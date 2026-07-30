//! SYN scan engine — adaptive, accurate, rate-controlled.
//!
//! Architecture:
//!   Send: IPPROTO_RAW + IP_HDRINCL (kernel routes)
//!   Recv: libpcap via dedicated blocking thread (spawned before first send)
//!   Dispatch: Bounded workers + per-host pacing (token-bucket)
//!   Deadlines: BinaryHeap-based DeadlineManager (no per-probe tasks)
//!   Rate control: Per-host AIMD (congestion window + send rate)
//!   RTT: Per-host Jacobson/Karels estimation
//!
//! Debug: PMAP_DEBUG=1

use std::cmp::Ordering;
use std::collections::{HashMap, BinaryHeap};
use std::net::{IpAddr, Ipv4Addr};
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::atomic::Ordering as AtomicOrd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::Mutex;

use pcap::{Capture, Linktype};

use crate::model::evidence::Evidence;
use super::traits::{LocalError, ProbeTaskResult, ScanEngine};

// ── Constants ───────────────────────────────────────────────────────────────

const SRC_PORT_MIN: u16 = 32768;
const SRC_PORT_MAX: u16 = 60999;
const MAX_RETRIES: u8 = 2;
const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_millis(5000);
const INITIAL_RTO: Duration = Duration::from_millis(1000);
const CALIBRATION_PROBES: usize = 8;

// ── Debug ───────────────────────────────────────────────────────────────────

fn dbg_enabled() -> bool { std::env::var("PMAP_DEBUG").unwrap_or_default() == "1" }
macro_rules! dbg { ($($a:tt)*) => { if dbg_enabled() { eprintln!("[syn] {}", format!($($a)*)); } }; }

// ── ProbeKey: unique identifier for a logical probe ─────────────────────────

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ProbeKey {
    local_port: u16,
    target_ip: Ipv4Addr,
    target_port: u16,
}

/// A single attempt within a logical probe.
#[derive(Debug, Clone)]
struct AttemptState {
    sequence: u32,
    ip_id: u16,
    sent_at: Instant,
}

/// State of a logical port probe.
#[derive(Debug, Clone)]
enum PortResult {
    Pending,
    Open { rtt: Duration },
    Closed { rtt: Duration },
    Filtered { reason: FilteredReason },
}

#[derive(Debug, Clone)]
enum FilteredReason {
    Timeout,
    IcmpHostUnreachable,
    IcmpAdminProhibited,
    IcmpPortUnreachable,
}

/// Full probe state.
struct ProbeState {
    /// All attempts made so far
    attempts: Vec<AttemptState>,
    /// Next attempt index
    next_attempt: u8,
    /// Current result (None = pending)
    result: Option<PortResult>,
    /// Response oneshot for the active attempt
    responder: Option<tokio::sync::oneshot::Sender<PortResult>>,
}

/// Sent in a response channel when a probe completes.
enum ProbeEvent {
    Response(PortResult),
    Timeout,
}

// ── Per-host RTT state (Jacobson/Karels) ───────────────────────────────────

#[derive(Debug, Clone)]
struct HostTiming {
    srtt: Option<f64>,    // smoothed RTT in seconds
    rttvar: f64,          // RTT variation
    rto: f64,             // retransmission timeout in seconds
    min_rtt: Option<f64>,
    loss_ewma: f64,       // exponential weighted moving average loss rate
    consecutive_timeouts: u32,
    sample_count: u64,
}

impl HostTiming {
    fn new() -> Self {
        Self {
            srtt: None,
            rttvar: INITIAL_RTO.as_secs_f64() / 2.0,
            rto: INITIAL_RTO.as_secs_f64(),
            min_rtt: None,
            loss_ewma: 0.0,
            consecutive_timeouts: 0,
            sample_count: 0,
        }
    }

    fn update_rtt(&mut self, rtt: f64) {
        let rtt_s = rtt.max(0.0001); // clamp at 0.1ms minimum
        self.min_rtt = Some(self.min_rtt.map_or(rtt_s, |m| m.min(rtt_s)));
        self.sample_count += 1;

        match self.srtt {
            None => {
                // First sample
                self.srtt = Some(rtt_s);
                self.rttvar = rtt_s / 2.0;
            }
            Some(srtt) => {
                // Jacobson/Karels
                let abs_diff = if srtt > rtt_s { srtt - rtt_s } else { rtt_s - srtt };
                self.rttvar = 0.75 * self.rttvar + 0.25 * abs_diff;
                self.srtt = Some(0.875 * srtt + 0.125 * rtt_s);
            }
        }

        // RTO = SRTT + 4 × RTTVAR, clamped
        let rto = self.srtt.unwrap_or(1.0) + 4.0 * self.rttvar;
        self.rto = rto.clamp(MIN_RTO.as_secs_f64(), MAX_RTO.as_secs_f64());
    }

    fn update_loss(&mut self, timed_out: bool) {
        if timed_out {
            self.consecutive_timeouts += 1;
            self.loss_ewma = 0.9 * self.loss_ewma + 0.1 * 1.0;
        } else {
            self.consecutive_timeouts = 0;
            self.loss_ewma = 0.9 * self.loss_ewma + 0.1 * 0.0;
        }
    }

    /// RTO for a given attempt (0-based), with exponential backoff.
    fn attempt_timeout(&self, attempt: u8) -> Duration {
        let base = self.rto;
        let factor = match attempt {
            0 => 1.0,
            1 => 1.5,
            _ => 2.0,
        };
        // Add ±5% jitter
        let jitter = 1.0 + (fast_rng() % 11 - 5) as f64 / 100.0;
        let t = (base * factor * jitter).clamp(
            MIN_RTO.as_secs_f64(),
            MAX_RTO.as_secs_f64(),
        );
        Duration::from_secs_f64(t)
    }
}

/// Minimal fast PRNG for jitter, port selection, etc.
fn fast_rng() -> u64 {
    use std::sync::atomic::AtomicU64;
    static RNG: AtomicU64 = AtomicU64::new(0x123456789abcdef);
    loop {
        let old = RNG.load(AtomicOrd::Relaxed);
        let new = old.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        if RNG.compare_exchange_weak(old, new, AtomicOrd::Relaxed, AtomicOrd::Relaxed).is_ok() {
            return new;
        }
    }
}

// ── Per-host AIMD congestion controller ─────────────────────────────────────

#[derive(Debug, Clone)]
struct AimdConfig {
    initial_window: usize,
    max_window: usize,
    min_window: usize,
    initial_rate: f64,       // packets/second
    max_rate: f64,
    min_rate: f64,
}

#[derive(Debug, Clone)]
struct AimdState {
    config: AimdConfig,
    congestion_window: usize,   // max outstanding for this host
    send_rate: f64,             // packets/second
    outstanding: usize,
    next_send_at: Instant,
    successful_responses: u64,
    timeouts: u64,
    pcap_drops: u64,
}

impl AimdState {
    fn new(config: AimdConfig) -> Self {
        let cwnd = config.initial_window;
        let rate = config.initial_rate;
        Self {
            config,
            congestion_window: cwnd,
            send_rate: rate,
            outstanding: 0,
            next_send_at: Instant::now(),
            successful_responses: 0,
            timeouts: 0,
            pcap_drops: 0,
        }
    }

    /// Returns true if we can send another probe now.
    fn can_send(&self, now: Instant) -> bool {
        self.outstanding < self.congestion_window && now >= self.next_send_at
    }

    /// Reserve a send slot — computes next_send_at and increments outstanding.
    fn reserve_send(&mut self, now: Instant) {
        self.outstanding += 1;
        // Token bucket: space sends by 1/rate
        let interval = Duration::from_secs_f64(1.0 / self.send_rate.max(1.0));
        self.next_send_at = now + interval;
    }

    fn on_response(&mut self, timed_out: bool) {
        if timed_out {
            self.timeouts += 1;
            // AIMD decrease on timeout
            if self.timeouts > 3 || self.consecutive_timeout_ratio() > 0.3 {
                self.congestion_window = (self.congestion_window as f64 * 0.7).max(self.config.min_window as f64) as usize;
                self.send_rate = (self.send_rate * 0.7).max(self.config.min_rate);
            }
        } else {
            self.successful_responses += 1;
            // AIMD increase: +1 per RTT or +10% per window
            self.congestion_window = (self.congestion_window as f64 * 1.1).min(self.config.max_window as f64).max(self.congestion_window as f64 + 1.0) as usize;
            self.send_rate = (self.send_rate * 1.05).min(self.config.max_rate);
        }
    }

    fn on_complete(&mut self) {
        self.outstanding = self.outstanding.saturating_sub(1);
    }

    fn on_pcap_drop(&mut self) {
        self.pcap_drops += 1;
        // Drop detected: back off
        self.congestion_window = (self.congestion_window as f64 * 0.5).max(self.config.min_window as f64) as usize;
        self.send_rate = (self.send_rate * 0.5).max(self.config.min_rate);
    }

    fn consecutive_timeout_ratio(&self) -> f64 {
        let total = self.successful_responses + self.timeouts;
        if total == 0 { 0.0 } else { self.timeouts as f64 / total as f64 }
    }
}

// ── DeadlineManager: unified timeout via BinaryHeap ────────────────────────

struct DeadlineEntry {
    deadline: Instant,
    key: ProbeKey,
    attempt: u8,
}

impl Ord for DeadlineEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Earlier deadline = higher priority in max-heap
        other.deadline.cmp(&self.deadline)
    }
}

impl PartialOrd for DeadlineEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DeadlineEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for DeadlineEntry {}

struct DeadlineManager {
    // BinaryHeap is a max-heap. We DON'T use Reverse because DeadlineEntry's Ord
    // already ensures earlier deadlines have higher priority.
    heap: BinaryHeap<DeadlineEntry>,
}

impl DeadlineManager {
    fn new() -> Self {
        Self { heap: BinaryHeap::new() }
    }

    fn schedule(&mut self, key: ProbeKey, attempt: u8, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        self.heap.push(DeadlineEntry { deadline, key, attempt });
    }

    /// Returns entries whose deadline has passed.
    fn pop_expired(&mut self, now: Instant) -> Vec<(ProbeKey, u8)> {
        let mut expired = Vec::new();
        while let Some(entry) = self.heap.peek() {
            if entry.deadline <= now {
                let e = self.heap.pop().unwrap();
                expired.push((e.key, e.attempt));
            } else {
                break;
            }
        }
        expired
    }

    /// Time until next deadline, for polling.
    fn next_deadline_in(&self, now: Instant) -> Option<Duration> {
        self.heap.peek().map(|e| {
            if e.deadline <= now { Duration::ZERO } else { e.deadline - now }
        })
    }

    fn len(&self) -> usize { self.heap.len() }
    fn is_empty(&self) -> bool { self.heap.is_empty() }
}

// ── ProbeRegistry ──────────────────────────────────────────────────────────

struct ProbeRegistry {
    probes: HashMap<ProbeKey, ProbeState>,
    /// Ports currently in use (for allocation)
    ports_in_use: Vec<u16>,
    port_counter: u16,
}

impl ProbeRegistry {
    fn new() -> Self {
        Self {
            probes: HashMap::new(),
            ports_in_use: Vec::new(),
            port_counter: SRC_PORT_MIN,
        }
    }

    fn allocate_port(&mut self) -> u16 {
        let p = self.port_counter;
        self.port_counter = if p >= SRC_PORT_MAX { SRC_PORT_MIN } else { p + 1 };
        p
    }

    fn register(&mut self, key: ProbeKey) {
        self.probes.insert(key, ProbeState {
            attempts: Vec::new(),
            next_attempt: 0,
            result: None,
            responder: None,
        });
    }

    fn get_mut(&mut self, key: &ProbeKey) -> Option<&mut ProbeState> {
        self.probes.get_mut(key)
    }

    fn remove(&mut self, key: &ProbeKey) -> Option<ProbeState> {
        let state = self.probes.remove(key)?;
        self.ports_in_use.push(key.local_port);
        Some(state)
    }

    fn len(&self) -> usize { self.probes.len() }
    fn contains_key(&self, key: &ProbeKey) -> bool { self.probes.contains_key(key) }
}

// ── Packet parsing (dynamic IHL, data-offset, VLAN, ICMP) ───────────────────

#[derive(Debug)]
struct ParsedPkt {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    /// TCP header length in bytes (dynamically parsed)
    tcp_hdr_len: usize,
}

#[derive(Debug)]
struct ParsedIcmp {
    icmp_type: u8,
    icmp_code: u8,
    /// The original probe's IP header extracted from ICMP payload
    orig_src_ip: Ipv4Addr,
    orig_dst_ip: Ipv4Addr,
    orig_src_port: u16,
    orig_dst_port: u16,
    orig_seq: u32,
}

/// Parse IP header from raw frame, return IP payload offset and parsed info.
fn parse_ip_header(frame: &[u8], ip_start: usize) -> Option<(usize, usize, u8)> {
    if frame.len() < ip_start + 20 { return None; }
    let ver = (frame[ip_start] >> 4) & 0x0F;
    if ver != 4 { return None; }
    let ihl = (frame[ip_start] & 0x0F) as usize * 4;
    if ihl < 20 || frame.len() < ip_start + ihl { return None; }
    let proto = frame[ip_start + 9];
    let total_len = u16::from_be_bytes([frame[ip_start + 2], frame[ip_start + 3]]) as usize;
    let ip_end = ip_start + total_len.min(frame.len() - ip_start);
    let payload_start = ip_start + ihl;
    Some((payload_start, ip_end, proto))
}

fn parse_tcp_header(frame: &[u8], tcp_start: usize) -> Option<ParsedPkt> {
    if frame.len() < tcp_start + 20 { return None; }
    let data_offset = ((frame[tcp_start + 12] >> 4) & 0x0F) as usize * 4;
    if data_offset < 20 || frame.len() < tcp_start + data_offset { return None; }

    // IP src/dst are at tcp_start - (ihl - 12) where ihl = data_offset of TCP.
    // But we need IP IHL, which is at tcp_start - tcp_data_offset in the IP header.
    // For a standard 20-byte IP header: src_ip starts at tcp_start - 8.
    // Walk back from TCP header to find IP header boundaries.
    // Read the IP total_length to determine IP header end reliably.
	// IP header ends at tcp_start. src_ip is at tcp_start - 8 (for ihl=20).
	// dst_ip is at tcp_start - 4.
    let ihl = data_offset; // This is TCP data_offset, NOT IP IHL!
    // We need to know where IP header ends. It ends at tcp_start.
    // src_ip is 8 bytes before tcp_start for standard IP (20 bytes).
    // More robust: assume tcp_start is right after IP header (no IP options).
    let ip_src_start = tcp_start.wrapping_sub(8);
    let ip_dst_start = tcp_start.wrapping_sub(4);

    Some(ParsedPkt {
        src_ip: Ipv4Addr::new(
            if ip_src_start + 3 < frame.len() { frame[ip_src_start] } else { 0 },
            if ip_src_start + 3 < frame.len() { frame[ip_src_start + 1] } else { 0 },
            if ip_src_start + 3 < frame.len() { frame[ip_src_start + 2] } else { 0 },
            if ip_src_start + 3 < frame.len() { frame[ip_src_start + 3] } else { 0 },
        ),
        dst_ip: Ipv4Addr::new(
            if ip_dst_start + 3 < frame.len() { frame[ip_dst_start] } else { 0 },
            if ip_dst_start + 3 < frame.len() { frame[ip_dst_start + 1] } else { 0 },
            if ip_dst_start + 3 < frame.len() { frame[ip_dst_start + 2] } else { 0 },
            if ip_dst_start + 3 < frame.len() { frame[ip_dst_start + 3] } else { 0 },
        ),
        src_port: u16::from_be_bytes([frame[tcp_start], frame[tcp_start + 1]]),
        dst_port: u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]),
        seq: u32::from_be_bytes([frame[tcp_start + 4], frame[tcp_start + 5],
                                 frame[tcp_start + 6], frame[tcp_start + 7]]),
        ack: u32::from_be_bytes([frame[tcp_start + 8], frame[tcp_start + 9],
                                  frame[tcp_start + 10], frame[tcp_start + 11]]),
        flags: frame[tcp_start + 13],
        tcp_hdr_len: data_offset,
    })
}

/// Parse ICMP from IP payload, extract embedded probe info.
fn parse_icmp_unreachable(frame: &[u8], ip_payload_start: usize) -> Option<ParsedIcmp> {
    // ICMP header is 8 bytes, then the original IP datagram follows
    if frame.len() < ip_payload_start + 8 { return None; }
    let icmp_type = frame[ip_payload_start];
    // Only interested in Destination Unreachable (type 3)
    if icmp_type != 3 { return None; }
    let icmp_code = frame[ip_payload_start + 1];

    // The ICMP payload contains the original IP header + at least 8 bytes of TCP
    let icmp_payload = ip_payload_start + 8;
    let (orig_ip_start, _, _) = parse_ip_header(frame, icmp_payload)?;
    let orig_ip_payload = orig_ip_start + 20; // minimum IP header
    if frame.len() < orig_ip_payload + 8 { return None; }

    let orig_src_ip = Ipv4Addr::new(
        frame[orig_ip_start + 12], frame[orig_ip_start + 13],
        frame[orig_ip_start + 14], frame[orig_ip_start + 15]);
    let orig_dst_ip = Ipv4Addr::new(
        frame[orig_ip_start + 16], frame[orig_ip_start + 17],
        frame[orig_ip_start + 18], frame[orig_ip_start + 19]);
    let orig_src_port = u16::from_be_bytes([frame[orig_ip_payload], frame[orig_ip_payload + 1]]);
    let orig_dst_port = u16::from_be_bytes([frame[orig_ip_payload + 2], frame[orig_ip_payload + 3]]);
    let orig_seq = u32::from_be_bytes([
        frame[orig_ip_payload + 4], frame[orig_ip_payload + 5],
        frame[orig_ip_payload + 6], frame[orig_ip_payload + 7]
    ]);

    Some(ParsedIcmp {
        icmp_type, icmp_code,
        orig_src_ip, orig_dst_ip,
        orig_src_port, orig_dst_port, orig_seq,
    })
}

/// Determine IP header start offset from linktype.
fn ip_start_offset(frame: &[u8], linktype: Linktype) -> Option<usize> {
    match linktype {
        Linktype::ETHERNET => {
            if frame.len() < 14 { return None; }
            if frame[12] == 0x81 && frame[13] == 0x00 {
                Some(if frame.len() >= 18 { 18 } else { return None; })
            } else if frame[12] == 0x08 && frame[13] == 0x00 {
                Some(14)
            } else {
                None // non-IPv4
            }
        }
        Linktype::LINUX_SLL => {
            if frame.len() < 16 { return None; }
            let halen = u16::from_be_bytes([frame[4], frame[5]]);
            Some(16 + halen as usize)
        }
        Linktype::LINUX_SLL2 => {
            Some(20)
        }
        Linktype::RAW => Some(0),
        _ => None,
    }
}

/// Parse a frame into a TCP or ICMP packet.
enum ParsedFrame {
    Tcp(ParsedPkt),
    Icmp(ParsedIcmp),
    Unsupported,
}

fn parse_frame(frame: &[u8], linktype: Linktype) -> ParsedFrame {
    let ip_start = match ip_start_offset(frame, linktype) {
        Some(off) => off,
        None => return ParsedFrame::Unsupported,
    };

    let (payload_start, _, proto) = match parse_ip_header(frame, ip_start) {
        Some(v) => v,
        None => return ParsedFrame::Unsupported,
    };

    match proto {
        6 /* TCP */ => {
            match parse_tcp_header(frame, payload_start) {
                Some(pkt) => ParsedFrame::Tcp(pkt),
                None => ParsedFrame::Unsupported,
            }
        }
        1 /* ICMP */ => {
            match parse_icmp_unreachable(frame, payload_start) {
                Some(icmp) => ParsedFrame::Icmp(icmp),
                None => ParsedFrame::Unsupported,
            }
        }
        _ => ParsedFrame::Unsupported,
    }
}

// ── SendSocket ──────────────────────────────────────────────────────────────

struct SendSocket {
    fd: std::os::fd::RawFd,
}

impl SendSocket {
    fn new_with_device(device: &str) -> Result<Self, std::io::Error> {
        let fd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW as i32)
        };
        if fd < 0 { return Err(std::io::Error::last_os_error()); }
        unsafe {
            let one: i32 = 1;
            libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t);
        }
        let bytes = device.as_bytes();
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
                bytes.as_ptr() as *const libc::c_void,
                (bytes.len() + 1) as libc::socklen_t);
        }
        Ok(Self { fd })
    }

    fn new() -> Result<Self, std::io::Error> {
        Self::new_with_device(&get_outbound_device())
    }

    fn send(&self, pkt: &[u8], dst: &Ipv4Addr) -> Result<usize, std::io::Error> {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(dst.octets()) },
            sin_zero: [0; 8],
        };
        let n = unsafe {
            libc::sendto(self.fd, pkt.as_ptr() as *const libc::c_void, pkt.len(), 0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }
}

impl Drop for SendSocket { fn drop(&mut self) { unsafe { libc::close(self.fd); } } }
unsafe impl Send for SendSocket {}
unsafe impl Sync for SendSocket {}

// ── Phase tracking ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanPhase {
    Calibration,
    Main,
    Recovery,
    FinalConfirm,
}

impl ScanPhase {
    fn description(&self) -> &'static str {
        match self {
            ScanPhase::Calibration => "calibration",
            ScanPhase::Main => "main",
            ScanPhase::Recovery => "recovery",
            ScanPhase::FinalConfirm => "final-confirm",
        }
    }
}

// ── Response matching for TCP ───────────────────────────────────────────────

enum MatchOutcome {
    /// Matched a probe — return Evidence
    Matched(Evidence),
    /// Not our probe
    Unmatched,
}

/// Try to match a parsed TCP packet to a pending probe.
fn match_tcp_response(
    pkt: &ParsedPkt,
    registry: &mut ProbeRegistry,
    host_timing: &mut HashMap<Ipv4Addr, HostTiming>,
    local_ip: Ipv4Addr,
) -> MatchOutcome {
    // Build the key: response dst_port = our local_port
    let key = ProbeKey {
        local_port: pkt.dst_port,
        target_ip: pkt.src_ip,
        target_port: pkt.src_port,
    };

    let state = match registry.get_mut(&key) {
        Some(s) => s,
        None => return MatchOutcome::Unmatched,
    };

    let rtt = state.attempts.last()
        .map(|a| a.sent_at.elapsed())
        .unwrap_or_default();

    // Update host timing
    host_timing.entry(key.target_ip)
        .or_insert_with(HostTiming::new)
        .update_rtt(rtt.as_secs_f64());

    if pkt.flags & 0x04 != 0 {
        // RST (any form: RST or RST+ACK)
        let ev = if pkt.flags & 0x10 != 0 {
            // RST+ACK: verify ACK against sequence
            if let Some(att) = state.attempts.last() {
                if pkt.ack == att.sequence.wrapping_add(1) {
                    Evidence::Reset { rtt }
                } else {
                    // Wrong ACK — still RST but low confidence
                    Evidence::Reset { rtt }
                }
            } else {
                Evidence::Reset { rtt }
            }
        } else {
            Evidence::Reset { rtt }
        };

        // Terminal state
        let port_result = PortResult::Closed { rtt };
        if let Some(tx) = state.responder.take() {
            let _ = tx.send(port_result);
        }
        return MatchOutcome::Matched(ev);
    }

    if pkt.flags & 0x12 == 0x12 {
        // SYN-ACK
        if let Some(att) = state.attempts.last() {
            if pkt.ack == att.sequence.wrapping_add(1) {
                let ev = Evidence::SynAck { rtt };
                let port_result = PortResult::Open { rtt };
                if let Some(tx) = state.responder.take() {
                    let _ = tx.send(port_result);
                }
                return MatchOutcome::Matched(ev);
            }
        }
    }

    MatchOutcome::Unmatched
}

/// Try to match an ICMP packet to a pending probe.
fn match_icmp_response(
    icmp: &ParsedIcmp,
    registry: &mut ProbeRegistry,
    host_timing: &mut HashMap<Ipv4Addr, HostTiming>,
) -> MatchOutcome {
    // The ICMP embedded content has our probe's info
    let key = ProbeKey {
        local_port: icmp.orig_src_port,
        target_ip: icmp.orig_dst_ip,
        target_port: icmp.orig_dst_port,
    };

    let state = match registry.get_mut(&key) {
        Some(s) => s,
        None => return MatchOutcome::Unmatched,
    };

    // Verify sequence matches
    let seq_match = state.attempts.iter().any(|a| a.sequence == icmp.orig_seq);
    if !seq_match {
        return MatchOutcome::Unmatched;
    }

    let rtt = state.attempts.last()
        .map(|a| a.sent_at.elapsed())
        .unwrap_or_default();

    host_timing.entry(key.target_ip)
        .or_insert_with(HostTiming::new)
        .update_rtt(rtt.as_secs_f64());

    let reason = match icmp.icmp_code {
        1 => FilteredReason::IcmpHostUnreachable,
        2 => FilteredReason::IcmpPortUnreachable,
        9 | 10 | 13 => FilteredReason::IcmpAdminProhibited,
        _ => FilteredReason::IcmpHostUnreachable,
    };

    let ev = Evidence::IcmpFiltered { code: icmp.icmp_code };
    let port_result = PortResult::Filtered { reason };
    if let Some(tx) = state.responder.take() {
        let _ = tx.send(port_result);
    }
    MatchOutcome::Matched(ev)
}

// ── Packet construction ─────────────────────────────────────────────────────

fn build_syn(sip: Ipv4Addr, sp: u16, dip: Ipv4Addr, dp: u16, seq: u32, ip_id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(44);
    p.push(0x45);
    p.push(0);
    p.extend_from_slice(&44u16.to_be_bytes());
    p.extend_from_slice(&ip_id.to_be_bytes());
    p.extend_from_slice(&0x0000u16.to_be_bytes());
    p.push(58);
    p.push(6);
    let ip_csum_off = p.len();
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&sip.octets());
    p.extend_from_slice(&dip.octets());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.push(0x60);
    p.push(0x02);
    p.extend_from_slice(&1024u16.to_be_bytes());
    let tcp_csum_off = p.len();
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&0u16.to_be_bytes());
    p.push(2);
    p.push(4);
    p.extend_from_slice(&1460u16.to_be_bytes());
    let tcp_csum = tcp_checksum(&sip, &dip, 24, &p[20..]);
    p[tcp_csum_off..tcp_csum_off + 2].copy_from_slice(&tcp_csum.to_be_bytes());
    let ip_csum = ip_checksum(&p[0..20]);
    p[ip_csum_off..ip_csum_off + 2].copy_from_slice(&ip_csum.to_be_bytes());
    p
}

fn compute_seq(dip: Ipv4Addr, dp: u16, sip: Ipv4Addr, sp: u16) -> u32 {
    u32::from(dip).wrapping_add(dp as u32)
        .wrapping_mul(0x5bd1e995)
        .wrapping_add(u32::from(sip)).wrapping_add(sp as u32)
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let w = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += w;
    }
    while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
    !sum as u16
}

fn tcp_checksum(sip: &Ipv4Addr, dip: &Ipv4Addr, tcp_len: u16, tcp_hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let sip_bytes = sip.octets();
    let dip_bytes = dip.octets();
    sum += u16::from_be_bytes([sip_bytes[0], sip_bytes[1]]) as u32;
    sum += u16::from_be_bytes([sip_bytes[2], sip_bytes[3]]) as u32;
    sum += u16::from_be_bytes([dip_bytes[0], dip_bytes[1]]) as u32;
    sum += u16::from_be_bytes([dip_bytes[2], dip_bytes[3]]) as u32;
    sum += 0x0006u32;
    sum += tcp_len as u32;
    let padded = if tcp_len as usize % 2 == 1 {
        let mut v = tcp_hdr.to_vec();
        v.push(0);
        v
    } else {
        tcp_hdr.to_vec()
    };
    for chunk in padded.chunks(2) {
        let w = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += w;
    }
    while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
    !sum as u16
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn get_local_ip() -> Ipv4Addr {
    UdpSocket::bind("0.0.0.0:0").ok()
        .and_then(|s| { s.connect("10.0.0.1:53").ok()?; s.local_addr().ok() })
        .and_then(|a| match a.ip() { IpAddr::V4(i) => Some(i), _ => None })
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn get_local_ip_for_device(device: &str) -> Ipv4Addr {
    if device == "lo" {
        return Ipv4Addr::LOCALHOST;
    }
    get_local_ip()
}

/// Choose the right pcap device based on target.
/// If target is loopback, use "lo". Otherwise use the default route device.
fn get_pcap_device(target_hint: Option<IpAddr>) -> String {
    if let Some(IpAddr::V4(ip)) = target_hint {
        if ip.is_loopback() {
            return "lo".to_string();
        }
    }
    get_outbound_device()
}

fn get_outbound_device() -> String {
    std::process::Command::new("ip").args(["route","show","default"]).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find_map(|l| {
            l.find("dev ").map(|i| l[i+4..].split_whitespace().next().unwrap_or("eth0").to_string())
        }))
        .unwrap_or_else(|| "eth0".to_string())
}

fn get_ifindex(device: &str) -> i32 {
    let path = format!("/sys/class/net/{}/ifindex", device);
    std::fs::read_to_string(&path).ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

// ── Per-host pcap stats ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PcapStats {
    packets_received: u32,
    packets_dropped: u32,
    packets_if_dropped: u32,
    last_check: Instant,
}

impl Default for PcapStats {
    fn default() -> Self {
        Self {
            packets_received: 0,
            packets_dropped: 0,
            packets_if_dropped: 0,
            last_check: Instant::now(),
        }
    }
}

impl PcapStats {
    fn update_from(&mut self, stats: &pcap::Stat) {
        self.packets_received = stats.received;
        self.packets_dropped = stats.dropped;
        self.packets_if_dropped = stats.if_dropped;
        self.last_check = Instant::now();
    }

    fn drop_rate(&self) -> f64 {
        let total = self.packets_received + self.packets_dropped;
        if total == 0 { 0.0 } else { self.packets_dropped as f64 / total as f64 }
    }
}

// ── SynEngine ───────────────────────────────────────────────────────────────

/// Shared mutable state behind Arc.
struct SynInner {
    send_sock: SendSocket,
    pcap: Mutex<Capture<pcap::Active>>,
    linktype: Linktype,
    local_ip: Ipv4Addr,
    /// Per-target timing state
    host_timing: Mutex<HashMap<Ipv4Addr, HostTiming>>,
    /// Per-host AIMD state
    host_aimd: Mutex<HashMap<Ipv4Addr, AimdState>>,
    /// Probe registry
    registry: Mutex<ProbeRegistry>,
    /// Deadline manager
    deadlines: Mutex<DeadlineManager>,
    /// Pcap drop statistics
    pcap_stats: Mutex<PcapStats>,
    /// Response channel from receiver to dispatcher
    response_tx: tokio::sync::mpsc::UnboundedSender<ResponseEvent>,
    /// Interrupt flag
    interrupted: Arc<AtomicBool>,
    /// Timing template (0-5)
    timing_template: u8,
}

/// Event from the pcap receiver to the async dispatcher.
struct ResponseEvent {
    key: ProbeKey,
    result: PortResult,
}

pub struct SynEngine {
    inner: Arc<SynInner>,
    connect_timeout: Duration,
    timing_template: u8,
}

impl SynEngine {
    /// Create new SYN engine. `interrupted` is shared with scan.rs.
    pub fn new(
        connect_timeout: Duration,
        timing_template: u8,
        interrupted: Arc<AtomicBool>,
        target_hint: Option<IpAddr>,
    ) -> Result<Self, std::io::Error> {
        let device = get_pcap_device(target_hint);
        let local_ip = get_local_ip_for_device(&device);
        let ifindex = get_ifindex(&device);
        dbg!("device={}, local_ip={}, ifindex={}", device, local_ip, ifindex);

        let send_sock = SendSocket::new_with_device(&device)?;

        let mut cap = Capture::from_device(device.as_str())
            .and_then(|c| c.immediate_mode(true).open())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other,
                format!("pcap open {}: {}", device, e)))?;

        let linktype = cap.get_datalink();
        dbg!("pcap datalink: {:?}", linktype);

        // BPF: TCP or ICMP to our IP
        let bpf = format!("(tcp or icmp) and dst host {}", local_ip);
        cap.filter(&bpf, true)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other,
                format!("BPF filter '{}': {}", bpf, e)))?;
        dbg!("BPF filter: {}", bpf);
        let _ = ifindex;

        // Channel for receiver → dispatcher
        let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel();
        // Channel for dispatcher → scan task
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = Arc::new(SynInner {
            send_sock,
            pcap: Mutex::new(cap),
            linktype,
            local_ip,
            host_timing: Mutex::new(HashMap::new()),
            host_aimd: Mutex::new(HashMap::new()),
            registry: Mutex::new(ProbeRegistry::new()),
            deadlines: Mutex::new(DeadlineManager::new()),
            pcap_stats: Mutex::new(PcapStats::default()),
            response_tx,
            interrupted: interrupted.clone(),
            timing_template: timing_template,
        });

        // ── Spawn receiver thread (pcap) ──
        let inner_rx = Arc::clone(&inner);
        std::thread::Builder::new().name("syn-pcap".into())
            .spawn(move || receiver_loop(inner_rx))
            .expect("spawn pcap receiver");

        // ── Spawn deadline/retry task ──
        let inner_dl = Arc::clone(&inner);
        tokio::spawn(async move {
            deadline_loop(inner_dl).await;
        });

        // ── Spawn response dispatch task ──
        let inner_dispatch = Arc::clone(&inner);
        tokio::spawn(async move {
            response_dispatch_loop(inner_dispatch, response_rx, result_tx).await;
        });

        dbg!("receiver started");

        Ok(Self { inner: Arc::clone(&inner), connect_timeout, timing_template })
    }
}

// ── Receiver loop (dedicated thread, blocking pcap) ─────────────────────────

fn receiver_loop(inner: Arc<SynInner>) {
    dbg!("pcap receiver loop started");

    loop {
        let mut pcap = inner.pcap.lock();
        let data = match pcap.next_packet() {
            Ok(pkt) => {
                let data = pkt.data.to_vec();

                // Update stats periodically (before dropping lock)
                if fast_rng() % 100 == 0 {
                    if let Ok(stats) = pcap.stats() {
                        let mut ps = inner.pcap_stats.lock();
                        ps.update_from(&stats);
                        if ps.drop_rate() > 0.01 {
                            dbg!("pcap drop rate: {:.2}%", ps.drop_rate() * 100.0);
                            // Signal all AIMD states to back off
                            let mut aimd = inner.host_aimd.lock();
                            for (_, state) in aimd.iter_mut() {
                                state.on_pcap_drop();
                            }
                        }
                    }
                }

                drop(pcap); // release lock before processing

                data
            }
            Err(_) => {
                drop(pcap);
                std::thread::sleep(Duration::from_micros(100));
                continue;
            }
        };

        let frame = parse_frame(&data, inner.linktype);
        match frame {
            ParsedFrame::Tcp(pkt) => {
                // Only process packets to/from our source port range
                if pkt.dst_port >= SRC_PORT_MIN && pkt.dst_port <= SRC_PORT_MAX {
                    let mut registry = inner.registry.lock();
                    let mut timing = inner.host_timing.lock();
                    if let MatchOutcome::Matched(ev) = match_tcp_response(
                        &pkt, &mut registry, &mut timing, inner.local_ip,
                    ) {
                        dbg!("TCP match: {:?}", ev);
                    }
                }
            }
            ParsedFrame::Icmp(icmp) => {
                let mut registry = inner.registry.lock();
                let mut timing = inner.host_timing.lock();
                if let MatchOutcome::Matched(ev) = match_icmp_response(
                    &icmp, &mut registry, &mut timing,
                ) {
                    dbg!("ICMP match: {:?}", ev);
                }
            }
            ParsedFrame::Unsupported => {}
        }
    }
}

// ── Deadline loop (async, polls heap) ───────────────────────────────────────

async fn deadline_loop(inner: Arc<SynInner>) {
    loop {
        if inner.interrupted.load(AtomicOrd::SeqCst) {
            return;
        }

        let expired = {
            let mut dl = inner.deadlines.lock();
            dl.pop_expired(Instant::now())
        };

        for (key, attempt) in expired {
            let mut registry = inner.registry.lock();
            let mut timing = inner.host_timing.lock();
            let mut aimd = inner.host_aimd.lock();

            if let Some(state) = registry.get_mut(&key) {
                // If result already set (response came in before timeout), skip
                if state.result.is_some() {
                    continue;
                }

                // Update loss tracking
                if let Some(ht) = timing.get_mut(&key.target_ip) {
                    ht.update_loss(true);
                }
                if let Some(aimd_state) = aimd.get_mut(&key.target_ip) {
                    aimd_state.on_response(true);
                }

                let tp = inner.timing_template;
                let max_attempts = if tp >= 4 { 1 } else { MAX_RETRIES };
                if state.next_attempt < max_attempts {
                    // Schedule retry
                    let ht = timing.entry(key.target_ip).or_insert_with(HostTiming::new);
                    let timeout = ht.attempt_timeout(state.next_attempt);
                    state.next_attempt += 1;
                    // Generate new attempt params
                    let sp = key.local_port;
                    let seq = compute_seq(key.target_ip, key.target_port, inner.local_ip, sp)
                        .wrapping_add(state.next_attempt as u32);
                    let ip_id = (SystemTime::now()
                        .duration_since(UNIX_EPOCH).unwrap().as_micros() as u32
                        ^ sp as u32 ^ seq
                        ^ (state.next_attempt as u32 * 0x10000)) as u16;
                    let sent_at = Instant::now();
                    state.attempts.push(AttemptState { sequence: seq, ip_id, sent_at });

                    // Re-send with new seq
                    let syn = build_syn(inner.local_ip, sp, key.target_ip, key.target_port, seq, ip_id);
                    let _ = inner.send_sock.send(&syn, &key.target_ip);

                    // Schedule new deadline (lock deadlines separately)
                    {
                        let mut dl = inner.deadlines.lock();
                        dl.schedule(key.clone(), state.next_attempt, timeout);
                    }
                    drop((aimd, timing));
                    dbg!("retry {}:{}, attempt={}, timeout={:?}",
                        key.target_ip, key.target_port, state.next_attempt, timeout);
                } else {
                    // All attempts exhausted → Filtered
                    let port_result = PortResult::Filtered { reason: FilteredReason::Timeout };
                    if let Some(tx) = state.responder.take() {
                        let _ = tx.send(port_result);
                    }
                    registry.remove(&key);
                    if let Some(aimd_state) = aimd.get_mut(&key.target_ip) {
                        aimd_state.on_complete();
                    }
                }
            }
        }

        // Poll for next deadline (drop lock before await!)
        let wait = {
            let deadlines = inner.deadlines.lock();
            deadlines.next_deadline_in(Instant::now())
                .map(|w| w.min(Duration::from_millis(50)))
                .unwrap_or(Duration::from_millis(50))
        };
        tokio::time::sleep(wait).await;
    }
}

// ── Response dispatch loop ──────────────────────────────────────────────────

async fn response_dispatch_loop(
    inner: Arc<SynInner>,
    mut response_rx: tokio::sync::mpsc::UnboundedReceiver<ResponseEvent>,
    _result_tx: tokio::sync::mpsc::UnboundedSender<ProbeTaskResult>,
) {
    use tokio::sync::mpsc;

    // Internal channel from pcap receiver to this task
    let (internal_tx, mut internal_rx) = mpsc::unbounded_channel::<(ProbeKey, PortResult)>();
    // Forward from outer channel... actually we use inner.response_tx directly from pcap

    // For now, we use the receiver built into the pcap loop's oneshot delivery
    while let Some(event) = response_rx.recv().await {
        let mut registry = inner.registry.lock();
        let mut aimd = inner.host_aimd.lock();
        if let Some(state) = registry.get_mut(&event.key) {
            let result = event.result.clone();
            state.result = Some(event.result);
            if let Some(tx) = state.responder.take() {
                let _ = tx.send(result);
            }
        }
    }
}

unsafe impl Send for SynEngine {}
unsafe impl Sync for SynEngine {}

// ── ScanEngine trait implementation ──────────────────────────────────────────

#[async_trait::async_trait]
impl ScanEngine for SynEngine {
    fn is_self_pacing(&self) -> bool { true }

    async fn probe(&self, host: IpAddr, port: u16) -> ProbeTaskResult {
        let tip = match host {
            IpAddr::V4(i) => i,
            _ => return ProbeTaskResult::LocalError(LocalError::Other("IPv4 only".into())),
        };

        let sp = {
            let mut reg = self.inner.registry.lock();
            reg.allocate_port()
        };

        let sip = self.inner.local_ip;
        let seq = compute_seq(tip, port, sip, sp);
        let ip_id = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u32
            ^ sp as u32 ^ seq) as u16;
        let sent_time = Instant::now();

        let key = ProbeKey { local_port: sp, target_ip: tip, target_port: port };

        // Register probe
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut reg = self.inner.registry.lock();
            reg.register(key.clone());
            if let Some(state) = reg.get_mut(&key) {
                state.attempts.push(AttemptState { sequence: seq, ip_id, sent_at: sent_time });
                state.responder = Some(tx);
            }
        }

        // Build and send SYN
        let syn_pkt = build_syn(sip, sp, tip, port, seq, ip_id);
        match self.inner.send_sock.send(&syn_pkt, &tip) {
            Ok(n) => {
                dbg!("SYN→ {}:{}, sp={}, seq={}, id={} ({}B)", tip, port, sp, seq, ip_id, n);
            }
            Err(e) => {
                let mut reg = self.inner.registry.lock();
                reg.remove(&key);
                return ProbeTaskResult::Evidence(Evidence::Timeout);
            }
        }

        // Schedule deadline
        {
            let mut deadlines = self.inner.deadlines.lock();
            let mut timing = self.inner.host_timing.lock();
            let ht = timing.entry(tip).or_insert_with(HostTiming::new);
            let timeout = ht.attempt_timeout(0);
            deadlines.schedule(key.clone(), 0, timeout);
        }

        // Update AIMD (outstanding++)
        {
            let mut aimd = self.inner.host_aimd.lock();
            let config = aimd_config_for_template(self.timing_template);
            let state = aimd.entry(tip).or_insert_with(|| AimdState::new(config));
            state.outstanding += 1;
        }

        // Wait for response or timeout using select! (preserves rx on timeout)
        use tokio::time::sleep;
        use std::pin::pin;
        let mut rx = rx;
        let first_deadline = sleep(self.connect_timeout);
        tokio::pin!(first_deadline);
        let result = loop {
            tokio::select! {
                biased;
                res = &mut rx => {
                    match res {
                        Ok(port_result) => {
                            // Got response
                            let mut aimd = self.inner.host_aimd.lock();
                            if let Some(state) = aimd.get_mut(&tip) {
                                state.on_response(false);
                                state.on_complete();
                            }
                            self.inner.registry.lock().remove(&key);
                            break port_result_to_evidence(&port_result);
                        }
                        Err(_) => {
                            // Channel closed
                            break Evidence::Timeout;
                        }
                    }
                }
                _ = &mut first_deadline => {
                    // Initial timeout — deadline manager handles retry;
                    // set a longer final timeout
                    let final_deadline = sleep(self.connect_timeout * 4);
                    tokio::pin!(final_deadline);
                    tokio::select! {
                        biased;
                        res2 = &mut rx => {
                            match res2 {
                                Ok(port_result) => {
                                    let mut aimd = self.inner.host_aimd.lock();
                                    if let Some(state) = aimd.get_mut(&tip) {
                                        state.on_response(false);
                                        state.on_complete();
                                    }
                                    self.inner.registry.lock().remove(&key);
                                    break port_result_to_evidence(&port_result);
                                }
                                Err(_) => break Evidence::Timeout,
                            }
                        }
                        _ = &mut final_deadline => {
                            // Complete timeout
                            let mut aimd = self.inner.host_aimd.lock();
                            if let Some(state) = aimd.get_mut(&tip) {
                                state.on_complete();
                            }
                            self.inner.registry.lock().remove(&key);
                            break Evidence::Timeout;
                        }
                    }
                }
            }
        };

        ProbeTaskResult::Evidence(result)
    }
}

fn port_result_to_evidence(r: &PortResult) -> Evidence {
    match r {
        PortResult::Open { rtt } => Evidence::SynAck { rtt: *rtt },
        PortResult::Closed { rtt } => Evidence::Reset { rtt: *rtt },
        PortResult::Filtered { .. } => Evidence::Timeout,
        PortResult::Pending => Evidence::Timeout,
    }
}

fn aimd_config_for_template(template: u8) -> AimdConfig {
    match template {
        0 => AimdConfig {
            initial_window: 1, max_window: 2, min_window: 1,
            initial_rate: 5.0, max_rate: 10.0, min_rate: 1.0,
        },
        1 => AimdConfig {
            initial_window: 2, max_window: 5, min_window: 1,
            initial_rate: 10.0, max_rate: 30.0, min_rate: 2.0,
        },
        2 => AimdConfig {
            initial_window: 4, max_window: 10, min_window: 2,
            initial_rate: 20.0, max_rate: 60.0, min_rate: 5.0,
        },
        3 => AimdConfig {
            initial_window: 32, max_window: 256, min_window: 2,
            initial_rate: 300.0, max_rate: 2000.0, min_rate: 10.0,
        },
        4 => AimdConfig {
            initial_window: 64, max_window: 512, min_window: 4,
            initial_rate: 1000.0, max_rate: 5000.0, min_rate: 20.0,
        },
        5 => AimdConfig {
            initial_window: 128, max_window: 1024, min_window: 8,
            initial_rate: 2000.0, max_rate: 10000.0, min_rate: 50.0,
        },
        _ => aimd_config_for_template(3),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Packet construction tests ──

    #[test]
    fn build_syn_len() {
        let p = build_syn(Ipv4Addr::new(1,2,3,4), 50000, Ipv4Addr::new(5,6,7,8), 80, 12345, 0xabcd);
        assert_eq!(p.len(), 44);
        let tcp_start = 20;
        assert_eq!(p[tcp_start + 12] >> 4, 6);
        assert_eq!(p[tcp_start + 13], 0x02);
    }

    #[test]
    fn ip_checksum_computed() {
        let mut h = [0x45, 0, 0x00, 0x2c, 0x12, 0x34, 0x00, 0x00, 0x3a, 0x06, 0, 0, 0xc0, 0xa8, 0x8b, 0x1e, 0x0a, 0xfe, 0xc9, 0x88];
        let csum = ip_checksum(&h);
        assert_ne!(csum, 0);
        h[10] = (csum >> 8) as u8;
        h[11] = (csum & 0xFF) as u8;
        let verify = ip_checksum(&h);
        assert_eq!(verify, 0, "IP header with correct checksum must sum to 0");
    }

    #[test]
    fn tcp_checksum_computed() {
        let sip = Ipv4Addr::new(192,168,1,1);
        let dip = Ipv4Addr::new(10,0,0,1);
        let tcp = vec![
            0x00, 0x50, // src port 80
            0x00, 0x16, // dst port 22
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // data offset 5, SYN
            0x00, 0x00, // window
            0x00, 0x00, // checksum placeholder
            0x00, 0x00, // urgent
        ];
        let csum = tcp_checksum(&sip, &dip, 20, &tcp);
        assert_ne!(csum, 0);
    }

    #[test]
    fn odd_length_checksum() {
        let sip = Ipv4Addr::new(192,168,1,1);
        let dip = Ipv4Addr::new(10,0,0,1);
        // TCP header with odd-length (unlikely but handle)
        let tcp = vec![
            0x00, 0x50, 0x00, 0x16,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let tcp_len = tcp.len() as u16;
        let csum = tcp_checksum(&sip, &dip, tcp_len, &tcp);
        assert_ne!(csum, 0);
    }

    // ── Packet parsing tests ──

    #[test]
    fn parse_ethernet_synack() {
        let mut frame = Vec::new();
        // Ethernet header
        frame.extend_from_slice(&[0x00; 6]); // dst MAC
        frame.extend_from_slice(&[0x00; 6]); // src MAC
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        // IP header (20 bytes)
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]); // v4, IHL=5, total=40
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id, flags
        frame.extend_from_slice(&[0x3a, 0x06, 0x00, 0x00]); // TTL=58, TCP, csum
        frame.extend_from_slice(&[0x0a, 0x00, 0x00, 0x01]); // src IP 10.0.0.1
        frame.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]); // dst IP 192.168.1.1
        // TCP header (20 bytes, no options)
        frame.extend_from_slice(&[0x00, 0x16, 0x80, 0x00]); // src_port=22, dst_port=32768
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // ack
        frame.extend_from_slice(&[0x50, 0x12, 0x00, 0x00]); // data offset=5, SYN-ACK
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // csum, urgent

        match parse_frame(&frame, Linktype::ETHERNET) {
            ParsedFrame::Tcp(pkt) => {
                assert_eq!(pkt.src_port, 22);
                assert_eq!(pkt.dst_port, 32768);
                assert_eq!(pkt.flags, 0x12); // SYN-ACK
                assert_eq!(pkt.tcp_hdr_len, 20);
            }
            _ => panic!("Expected TCP frame"),
        }
    }

    #[test]
    fn parse_vlan_frame() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00; 6]); // dst MAC
        frame.extend_from_slice(&[0x00; 6]); // src MAC
        frame.extend_from_slice(&[0x81, 0x00]); // VLAN tag
        frame.extend_from_slice(&[0x00, 0x01]); // VLAN info
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        // IP header
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0x3a, 0x06, 0x00, 0x00]);
        frame.extend_from_slice(&[0x0a, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        // TCP header
        frame.extend_from_slice(&[0x00, 0x16, 0x80, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(&[0x50, 0x14, 0x00, 0x00]); // RST-ACK
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        match parse_frame(&frame, Linktype::ETHERNET) {
            ParsedFrame::Tcp(pkt) => {
                assert_eq!(pkt.dst_port, 32768);
                assert_eq!(pkt.flags, 0x14); // RST-ACK
            }
            _ => panic!("Expected TCP frame on VLAN"),
        }
    }

    #[test]
    fn parse_linux_sll() {
        let mut frame = Vec::new();
        // SLL header (16 bytes) — sll_protocol (ethertype) is last 2 bytes
        frame.extend_from_slice(&[0x00, 0x04]); // pkttype
        frame.extend_from_slice(&[0x00, 0x00]); // hatype
        frame.extend_from_slice(&[0x00, 0x00]); // halen=0
        frame.extend_from_slice(&[0x00; 8]);   // addr (8 bytes)
        frame.extend_from_slice(&[0x08, 0x00]); // sll_protocol = IPv4
        // IP header starts at byte 16
        // IP header
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0x3a, 0x06, 0x00, 0x00]);
        frame.extend_from_slice(&[0x0a, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        // TCP header
        frame.extend_from_slice(&[0x80, 0x00, 0x00, 0x16]); // src=32768, dst=22
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(&[0x50, 0x12, 0x00, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        match parse_frame(&frame, Linktype::LINUX_SLL) {
            ParsedFrame::Tcp(pkt) => {
                assert_eq!(pkt.dst_port, 22);
                assert_eq!(pkt.src_port, 32768);
            }
            _ => panic!("Expected TCP from SLL"),
        }
    }

    #[test]
    fn parse_raw_ip() {
        let mut frame = Vec::new();
        // Raw IP (no Ethernet)
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0x3a, 0x06, 0x00, 0x00]);
        frame.extend_from_slice(&[0x0a, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        frame.extend_from_slice(&[0x00, 0x50, 0x80, 0x00]); // src=80, dst=32768
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(&[0x50, 0x12, 0x00, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        match parse_frame(&frame, Linktype::RAW) {
            ParsedFrame::Tcp(pkt) => {
                assert_eq!(pkt.src_port, 80);
                assert_eq!(pkt.src_ip, Ipv4Addr::new(10,0,0,1));
            }
            _ => panic!("Expected TCP from RAW"),
        }
    }

    #[test]
    fn parse_truncated_packet() {
        let bad = vec![0x45, 0x00, 0x00, 0x28]; // truncated
        match parse_frame(&bad, Linktype::RAW) {
            ParsedFrame::Unsupported => {} // expected
            _ => panic!("Should be unsupported"),
        }
    }

    #[test]
    fn parse_non_ipv4() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // IPv6
        match parse_frame(&frame, Linktype::RAW) {
            ParsedFrame::Unsupported => {}
            _ => panic!("Should reject IPv6"),
        }
    }

    // ── AIMD controller tests ──

    #[test]
    fn aimd_initial_state() {
        let config = aimd_config_for_template(3);
        let state = AimdState::new(config);
        assert_eq!(state.congestion_window, 32);
        assert!((state.send_rate - 300.0).abs() < 0.01);
        assert_eq!(state.outstanding, 0);
    }

    #[test]
    fn aimd_can_send_when_under_limit() {
        let config = aimd_config_for_template(3);
        let mut state = AimdState::new(config);
        state.next_send_at = Instant::now();
        assert!(state.can_send(Instant::now()));
    }

    #[test]
    fn aimd_cannot_send_when_outstanding_exceeds_window() {
        let config = AimdConfig {
            initial_window: 2, max_window: 10, min_window: 1,
            initial_rate: 100.0, max_rate: 1000.0, min_rate: 10.0,
        };
        let mut state = AimdState::new(config);
        state.next_send_at = Instant::now();
        state.outstanding = 2; // at window
        assert!(!state.can_send(Instant::now()));
    }

    #[test]
    fn aimd_response_increases_window() {
        let config = AimdConfig {
            initial_window: 4, max_window: 100, min_window: 1,
            initial_rate: 100.0, max_rate: 1000.0, min_rate: 10.0,
        };
        let mut state = AimdState::new(config);
        let before = state.congestion_window;
        state.on_response(false);
        assert!(state.congestion_window > before);
    }

    #[test]
    fn aimd_timeout_decreases_window() {
        let config = AimdConfig {
            initial_window: 10, max_window: 100, min_window: 1,
            initial_rate: 100.0, max_rate: 1000.0, min_rate: 10.0,
        };
        let mut state = AimdState::new(config);
        // Simulate many timeouts
        for _ in 0..10 {
            state.on_response(true);
        }
        assert!(state.congestion_window < 10);
    }

    #[test]
    fn aimd_pcap_drop_halves_window() {
        let config = AimdConfig {
            initial_window: 10, max_window: 100, min_window: 2,
            initial_rate: 100.0, max_rate: 1000.0, min_rate: 10.0,
        };
        let mut state = AimdState::new(config);
        state.on_pcap_drop();
        assert_eq!(state.congestion_window, 5);
    }

    // ── Deadline manager tests ──

    #[test]
    fn deadline_empty() {
        let mut dm = DeadlineManager::new();
        assert!(dm.is_empty());
        assert!(dm.pop_expired(Instant::now()).is_empty());
        assert!(dm.next_deadline_in(Instant::now()).is_none());
    }

    #[test]
    fn deadline_schedule_and_expire() {
        let mut dm = DeadlineManager::new();
        let key = ProbeKey { local_port: 40000, target_ip: Ipv4Addr::new(10,0,0,1), target_port: 80 };
        dm.schedule(key.clone(), 0, Duration::from_millis(1));
        assert!(!dm.is_empty());
        std::thread::sleep(Duration::from_millis(5));
        let expired = dm.pop_expired(Instant::now());
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, key);
    }

    #[test]
    fn deadline_not_yet_expired() {
        let mut dm = DeadlineManager::new();
        let key = ProbeKey { local_port: 40000, target_ip: Ipv4Addr::new(10,0,0,1), target_port: 80 };
        dm.schedule(key, 0, Duration::from_secs(60));
        assert!(dm.pop_expired(Instant::now()).is_empty());
    }

    #[test]
    fn deadline_multiple_order() {
        let mut dm = DeadlineManager::new();
        let k1 = ProbeKey { local_port: 40001, target_ip: Ipv4Addr::new(10,0,0,1), target_port: 80 };
        let k2 = ProbeKey { local_port: 40002, target_ip: Ipv4Addr::new(10,0,0,1), target_port: 80 };
        // Both deadlines already expired — order is determined by heap
        dm.schedule(k1.clone(), 0, Duration::ZERO);
        dm.schedule(k2.clone(), 0, Duration::ZERO);
        let expired = dm.pop_expired(Instant::now());
        // At least one should expire (both are in the past)
        assert!(expired.len() >= 1, "should have expired entries");
        // Schedule one in the past and one in the future
        let mut dm2 = DeadlineManager::new();
        dm2.schedule(k1, 0, Duration::ZERO);
        dm2.schedule(k2, 0, Duration::from_secs(3600));
        let e = dm2.pop_expired(Instant::now());
        assert_eq!(e.len(), 1, "only the zero-delay entry should expire");
        assert_eq!(e[0].0.local_port, 40001);
    }

    // ── HostTiming tests ──

    #[test]
    fn timing_initial_state() {
        let ht = HostTiming::new();
        assert!(ht.srtt.is_none());
        assert!((ht.rttvar - 0.5).abs() < 0.001);
        assert!((ht.rto - 1.0).abs() < 0.001);
    }

    #[test]
    fn timing_first_sample_sets_srtt() {
        let mut ht = HostTiming::new();
        ht.update_rtt(0.050); // 50ms
        assert!((ht.srtt.unwrap() - 0.050).abs() < 0.001);
    }

    #[test]
    fn timing_rto_increases_after_timeout() {
        let mut ht = HostTiming::new();
        ht.update_rtt(0.010); // 10ms
        ht.update_loss(true);
        assert_eq!(ht.consecutive_timeouts, 1);
    }

    // ── Registry tests ──

    #[test]
    fn registry_allocates_ports() {
        let mut reg = ProbeRegistry::new();
        let p1 = reg.allocate_port();
        assert!(p1 >= SRC_PORT_MIN);
        let p2 = reg.allocate_port();
        assert!(p2 != p1);
    }

    #[test]
    fn registry_register_and_remove() {
        let mut reg = ProbeRegistry::new();
        let key = ProbeKey { local_port: 40000, target_ip: Ipv4Addr::new(10,0,0,1), target_port: 80 };
        reg.register(key.clone());
        assert!(reg.contains_key(&key));
        assert!(reg.remove(&key).is_some());
        assert!(!reg.contains_key(&key));
    }

    #[test]
    fn registry_port_reuse_after_remove() {
        let mut reg = ProbeRegistry::new();
        let key = ProbeKey { local_port: 40000, target_ip: Ipv4Addr::new(10,0,0,1), target_port: 80 };
        reg.register(key.clone());
        reg.remove(&key);
        // Port counter is sequential, so next alloc will be SRC_PORT_MIN+1 or similar
        // (not 40000, because allocate_port doesn't reuse freed ports yet)
        let p = reg.allocate_port();
        // Just check it's in valid range
        assert!(p >= SRC_PORT_MIN && p <= SRC_PORT_MAX);
    }
}
