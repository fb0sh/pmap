//! SYN scan engine: IPPROTO_RAW send + libpcap receive.
//!
//! Architecture:
//! - Send: IPPROTO_RAW + IP_HDRINCL (kernel routes)
//! - Recv: libpcap on outbound interface (captured BEFORE send)
//! - ProbeRegistry: concurrent-safe map keyed by source_port
//! - Central receiver dispatches to pending probes via oneshot
//!
//! Debug: PMAP_DEBUG=1

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use parking_lot::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;
use pcap::{Capture, Linktype};

use crate::model::evidence::Evidence;
use super::traits::{LocalError, ProbeTaskResult, ScanEngine};

const SRC_PORT_MIN: u16 = 32768;
const SRC_PORT_MAX: u16 = 60999;

fn dbg_enabled() -> bool { std::env::var("PMAP_DEBUG").unwrap_or_default() == "1" }
macro_rules! dbg { ($($a:tt)*) => { if dbg_enabled() { eprintln!("[syn] {}", format!($($a)*)); } }; }

/// A probe waiting for a response, tracked by source_port.
struct PendingProbe {
    expected_ack: u32,
    send_time: Instant,
    sender: oneshot::Sender<Evidence>,
}

/// IPPROTO_RAW send socket with IP_HDRINCL.
/// Kernel handles routing, ARP, and Ethernet framing.
struct SendSocket {
    fd: std::os::fd::RawFd,
}

impl SendSocket {
    fn new() -> Result<Self, std::io::Error> {
        let fd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW as i32)
        };
        if fd < 0 { return Err(std::io::Error::last_os_error()); }
        // IP_HDRINCL: we provide the IP header
        unsafe {
            let one: i32 = 1;
            libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t);
        }

        // SO_BINDTODEVICE: bind to interface (nmap does this too)
        let dev = get_outbound_device();
        let bytes = dev.as_bytes();
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
                bytes.as_ptr() as *const libc::c_void,
                (bytes.len() + 1) as libc::socklen_t);
        }
        Ok(Self { fd })
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

/// Parsed IP+TCP header information.
#[derive(Debug)]
struct ParsedPkt {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    data_offset: usize, // TCP header length in bytes
}

/// Parse a raw Ethernet frame into IP+TCP fields.
/// Supports: DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_RAW
fn parse_frame(frame: &[u8], linktype: Linktype) -> Option<ParsedPkt> {
    // Determine IP header offset based on link type
    let ip_start = match linktype {
        Linktype::ETHERNET => {
            if frame.len() < 14 { return None; }
            // Check for VLAN tag
            if frame[12] == 0x81 && frame[13] == 0x00 {
                if frame.len() < 18 { return None; }
                18 // 14 Ethernet + 4 VLAN
            } else if frame[12] == 0x08 && frame[13] == 0x00 {
                14 // standard Ethernet
            } else {
                return None; // non-IPv4
            }
        }
        Linktype::LINUX_SLL => {
            if frame.len() < 16 { return None; }
            let pkttype = u16::from_be_bytes([frame[0], frame[1]]);
            let _hatype = u16::from_be_bytes([frame[2], frame[3]]);
            let halen = u16::from_be_bytes([frame[4], frame[5]]);
            let sll_payload_offset = 16 + halen as usize;
            iana_ethertype_to_offset(frame, 14, sll_payload_offset)
        }
        Linktype::LINUX_SLL2 => {
            // SLL2 header is 20 bytes
            if frame.len() < 20 { return None; }
            iana_ethertype_to_offset(frame, 16, 20)
        }
        Linktype::RAW => {
            0 // starts with IP header
        }
        _ => {
            // Unknown link type, try Ethernet heuristic
            if frame.len() >= 14 && frame[12] == 0x08 && frame[13] == 0x00 {
                14
            } else {
                return None
            }
        }
    };

    // Parse IP header (minimum 20 bytes)
    if frame.len() < ip_start + 20 { return None; }
    let ip_ver = (frame[ip_start] >> 4) & 0x0F;
    if ip_ver != 4 { return None; } // IPv4 only
    let ip_ihl = (frame[ip_start] & 0x0F) as usize * 4;
    if ip_ihl < 20 || frame.len() < ip_start + ip_ihl + 20 { return None; }
    let ip_proto = frame[ip_start + 9];
    if ip_proto != 6 { return None; } // TCP only

    let src_ip = Ipv4Addr::new(
        frame[ip_start + 12], frame[ip_start + 13],
        frame[ip_start + 14], frame[ip_start + 15]);
    let dst_ip = Ipv4Addr::new(
        frame[ip_start + 16], frame[ip_start + 17],
        frame[ip_start + 18], frame[ip_start + 19]);

    // Parse TCP header
    let tcp_start = ip_start + ip_ihl;
    if frame.len() < tcp_start + 20 { return None; }
    let src_port = u16::from_be_bytes([frame[tcp_start], frame[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]);
    let seq = u32::from_be_bytes([frame[tcp_start + 4], frame[tcp_start + 5], frame[tcp_start + 6], frame[tcp_start + 7]]);
    let ack = u32::from_be_bytes([frame[tcp_start + 8], frame[tcp_start + 9], frame[tcp_start + 10], frame[tcp_start + 11]]);
    let flags = frame[tcp_start + 13];
    let data_offset = ((frame[tcp_start + 12] >> 4) & 0x0F) as usize * 4;

    Some(ParsedPkt { src_ip, dst_ip, src_port, dst_port, seq, ack, flags, data_offset })
}

fn iana_ethertype_to_offset(frame: &[u8], sll_off: usize, payload_off: usize) -> usize {
    // Check for IEEE 802.2 LLC/SNAP after SLL header
    if frame.len() >= payload_off + 2 {
        let ethertype = u16::from_be_bytes([frame[payload_off], frame[payload_off + 1]]);
        if ethertype >= 1536 {
            return payload_off + 2; // Ethernet II after payload
        }
    }
    // Default: assume Ethernet II format, IP starts after payload
    payload_off
}

/// Result of matching a packet against pending probes.
enum MatchResult {
    Matched(Evidence),
    Unmatched,
    WrongAck(u32, u32), // expected, got
}

/// Try to match a parsed TCP packet to a pending probe.
fn match_response(pkt: &ParsedPkt, local_ip: Ipv4Addr, pending: &Mutex<HashMap<u16, PendingProbe>>) -> Option<Evidence> {
    // The response must be FROM the target, TO us
    // Response dst_port is our source_port
    let mut map = pending.lock();
    let probe = map.remove(&pkt.dst_port)?;
    let rtt = probe.send_time.elapsed();

    if pkt.flags & 0x04 != 0 {
        // RST
        let _ = probe.sender.send(Evidence::Reset { rtt });
        return Some(Evidence::Reset { rtt });
    }

    if pkt.flags & 0x12 == 0x12 && pkt.ack == probe.expected_ack {
        // SYN-ACK with correct ACK
        let _ = probe.sender.send(Evidence::SynAck { rtt });
        return Some(Evidence::SynAck { rtt });
    }

    // Didn't match — put probe back
    map.insert(pkt.dst_port, probe);
    None
}

// ── SynEngine ───────────────────────────────────────────────────────────────

pub struct SynEngine {
    send_sock: Arc<SendSocket>,
    pcap: Arc<Mutex<Capture<pcap::Active>>>,
    linktype: Linktype,
    local_ip: Ipv4Addr,
    connect_timeout: Duration,
    port_counter: AtomicU16,
    pending: Arc<Mutex<HashMap<u16, PendingProbe>>>,
}

impl SynEngine {
    pub fn new(connect_timeout: Duration, _interrupted: Arc<AtomicBool>) -> Result<Self, std::io::Error> {
        let device = get_outbound_device();
        let local_ip = get_local_ip();
        let ifindex = get_ifindex(&device);
        dbg!("device={}, local_ip={}, ifindex={}", device, local_ip, ifindex);

        let send_sock = Arc::new(SendSocket::new()?);

        // ── Open pcap BEFORE spawning receiver ──
        let mut cap = Capture::from_device(device.as_str())
            .and_then(|c| c.immediate_mode(true).open())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other,
                format!("pcap open {}: {}", device, e)))?;

        // Get datalink type before moving cap
        let linktype = cap.get_datalink();
        dbg!("pcap datalink: {:?}", linktype);

        // Broad BPF filter: TCP or ICMP to/from target
        // We match in userspace by source_port
        let bpf = "tcp or icmp";
        cap.filter(bpf, true)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other,
                format!("BPF filter '{}': {}", bpf, e)))?;
        dbg!("BPF filter: {}", bpf);

        let pcap = Arc::new(Mutex::new(cap));
        let pending = Arc::new(Mutex::new(HashMap::new()));

        // Start receiver thread with ready pcap handle
        let pcap_rx = Arc::clone(&pcap);
        let pending_rx = Arc::clone(&pending);
        let lt = linktype;
        let lip = local_ip;
        std::thread::Builder::new().name("syn-rx".into())
            .spawn(move || receiver_thread(pcap_rx, pending_rx, lt, lip))
            .expect("spawn receiver");

        dbg!("receiver started");

        Ok(Self { send_sock, pcap, linktype, local_ip, connect_timeout,
            port_counter: AtomicU16::new(SRC_PORT_MIN), pending })
    }

    fn next_port(&self) -> u16 {
        let p = self.port_counter.fetch_add(1, Ordering::Relaxed);
        if p >= SRC_PORT_MAX || p == 0 {
            self.port_counter.store(SRC_PORT_MIN, Ordering::Relaxed);
        }
        p
    }
}

unsafe impl Send for SynEngine {}
unsafe impl Sync for SynEngine {}

// ── Receiver thread ─────────────────────────────────────────────────────────

fn receiver_thread(
    pcap: Arc<Mutex<Capture<pcap::Active>>>,
    pending: Arc<Mutex<HashMap<u16, PendingProbe>>>,
    linktype: Linktype,
    local_ip: Ipv4Addr,
) {
    dbg!("receiver loop started");
    let mut rx_count: u64 = 0;
    let mut hit_count: u64 = 0;
    let mut parse_err: u64 = 0;

    loop {
        let mut guard = pcap.lock();
        let data = match guard.next_packet() {
            Ok(p) => Some(p.data.to_vec()),
            Err(_) => None,
        };
        match data {
            Some(d) => {
                rx_count += 1;
                let len = d.len();
                if let Some(parsed) = parse_frame(&d, linktype) {
                    if dbg_enabled() && rx_count <= 100 {
                        let f = format!("{}{}{}{}{}{}",
                            if parsed.flags & 0x01 != 0 { "F" } else { "" },
                            if parsed.flags & 0x02 != 0 { "S" } else { "" },
                            if parsed.flags & 0x04 != 0 { "R" } else { "" },
                            if parsed.flags & 0x08 != 0 { "P" } else { "" },
                            if parsed.flags & 0x10 != 0 { "A" } else { "" },
                            if parsed.flags & 0x20 != 0 { "U" } else { "" });
                        dbg!("[#{}] {}:{}→{}:{} [{}] len={}", rx_count,
                            parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port, f, len);
                    }

                    // Only match responses to our probes (TO our source port)
                    if parsed.dst_port >= SRC_PORT_MIN && parsed.dst_port <= SRC_PORT_MAX {
                        if let Some(ev) = match_response(&parsed, local_ip, &pending) {
                            hit_count += 1;
                            dbg!("HIT {:?} total={}", ev, hit_count);
                        }
                    }
                } else {
                    parse_err += 1;
                    if dbg_enabled() && parse_err <= 10 {
                        dbg!("parse error: {} bytes, linktype={:?}", d.as_slice().len(), linktype);
                    }
                }
            }
            None => {
                // No packet — continue
                std::thread::sleep(Duration::from_micros(100));
            }
        }
    }
}

// ── ScanEngine ──────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl ScanEngine for SynEngine {
    async fn probe(&self, host: IpAddr, port: u16) -> ProbeTaskResult {
        let tip = match host { IpAddr::V4(i) => i, _ => {
            return ProbeTaskResult::LocalError(LocalError::Other("IPv4 only".into()));
        }};

        let sp = self.next_port();
        let sip = self.local_ip;
        let seq = compute_seq(tip, port, sip, sp);
        let ip_id = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u32
            ^ sp as u32 ^ seq) as u16;

        // Register BEFORE sending
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(sp, PendingProbe {
            expected_ack: seq.wrapping_add(1),
            send_time: Instant::now(),
            sender: tx,
        });

        // Build IP+TCP SYN (44 bytes with MSS option)
        let syn_pkt = build_syn(sip, sp, tip, port, seq, ip_id);
        match self.send_sock.send(&syn_pkt, &tip) {
            Ok(n) => dbg!("SYN→ {}:{}, sp={}, seq={}, id={} ({}B)", tip, port, sp, seq, ip_id, n),
            Err(e) => {
                dbg!("send ERR: {}", e);
                self.pending.lock().remove(&sp);
                return ProbeTaskResult::Evidence(Evidence::Timeout);
            }
        }

        // Wait for response
        let result = tokio::time::timeout(self.connect_timeout, rx).await;
        self.pending.lock().remove(&sp);

        match result {
            Ok(Ok(ev)) => ProbeTaskResult::Evidence(ev),
            _ => ProbeTaskResult::Evidence(Evidence::Timeout),
        }
    }
}

// ── SYN packet builder (IP + TCP, no Ethernet) ──────────────────────────────

fn build_syn(sip: Ipv4Addr, sp: u16, dip: Ipv4Addr, dp: u16, seq: u32, ip_id: u16) -> Vec<u8> {
    // 20 IP + 24 TCP (with MSS option) = 44 bytes
    let mut p = Vec::with_capacity(44);

    // IP header
    p.push(0x45); // v4, IHL=5
    p.push(0);    // TOS
    p.extend_from_slice(&44u16.to_be_bytes()); // total length
    p.extend_from_slice(&ip_id.to_be_bytes()); // IP ID
    p.extend_from_slice(&0x0000u16.to_be_bytes()); // flags=0, no DF
    p.push(58);   // TTL (like nmap)
    p.push(6);    // TCP
    let ip_csum_off = p.len();
    p.extend_from_slice(&[0, 0]); // IP checksum placeholder
    p.extend_from_slice(&sip.octets());
    p.extend_from_slice(&dip.octets());

    // TCP header
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.push(0x60); // data offset = 6 (24 bytes)
    p.push(0x02); // SYN
    p.extend_from_slice(&1024u16.to_be_bytes()); // window = 1024
    let tcp_csum_off = p.len();
    p.extend_from_slice(&[0, 0]); // TCP checksum placeholder
    p.extend_from_slice(&0u16.to_be_bytes()); // urgent
    // TCP option: MSS = 1460
    p.push(2);    // kind
    p.push(4);    // length
    p.extend_from_slice(&1460u16.to_be_bytes());

    // Compute checksums
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

// ── Checksum ────────────────────────────────────────────────────────────────

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
    // Pseudo header — add as 16-bit words (big-endian)
    let sip_bytes = sip.octets();
    let dip_bytes = dip.octets();
    // Source IP
    sum += u16::from_be_bytes([sip_bytes[0], sip_bytes[1]]) as u32;
    sum += u16::from_be_bytes([sip_bytes[2], sip_bytes[3]]) as u32;
    // Dest IP
    sum += u16::from_be_bytes([dip_bytes[0], dip_bytes[1]]) as u32;
    sum += u16::from_be_bytes([dip_bytes[2], dip_bytes[3]]) as u32;
    // Zero + protocol + TCP length (one 32-bit word = 0x0006 | tcp_len)
    sum += 0x0006u32;
    sum += tcp_len as u32;
    // Pad odd length with zero
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
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0").ok()
        .and_then(|s| { s.connect("10.0.0.1:53").ok()?; s.local_addr().ok() })
        .and_then(|a| match a.ip() { IpAddr::V4(i) => Some(i), _ => None })
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_synack_pkt(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16, ack: u32) -> Vec<u8> {
        let mut f = vec![0u8; 54];
        // Ethernet
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        // IP
        f[14] = 0x45;
        f[23] = 6; // TCP
        f[26..30].copy_from_slice(&src_ip.octets());
        f[30..34].copy_from_slice(&dst_ip.octets());
        // TCP
        f[34..36].copy_from_slice(&src_port.to_be_bytes());
        f[36..38].copy_from_slice(&dst_port.to_be_bytes());
        f[42..46].copy_from_slice(&ack.to_be_bytes());
        f[47] = 0x12; // SYN|ACK
        f
    }

    fn make_rst_pkt(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut f = make_synack_pkt(src_ip, src_port, dst_ip, dst_port, 0);
        f[47] = 0x04; // RST
        f
    }

    #[test]
    fn build_syn_len() {
        let p = build_syn(Ipv4Addr::new(1,2,3,4), 50000, Ipv4Addr::new(5,6,7,8), 80, 12345, 0xabcd);
        assert_eq!(p.len(), 44);
        // byte 32 is TCP data offset (byte 12 of TCP header, which starts at offset 20)
        let tcp_start = 20;
        assert_eq!(p[tcp_start + 12] >> 4, 6); // data offset = 6 (24 bytes)
        assert_eq!(p[tcp_start + 13], 0x02); // SYN
    }

    #[test]
    fn parse_ethernet_synack() {
        let dip = Ipv4Addr::new(192,168,1,1);
        let sip = Ipv4Addr::new(10,0,0,1);
        let pkt = make_synack_pkt(sip, 80, dip, 50000, 100);
        let parsed = parse_frame(&pkt, Linktype::ETHERNET).unwrap();
        assert_eq!(parsed.src_ip, sip);
        assert_eq!(parsed.dst_ip, dip);
        assert_eq!(parsed.src_port, 80);
        assert_eq!(parsed.dst_port, 50000);
        assert_eq!(parsed.ack, 100);
        assert_eq!(parsed.flags, 0x12);
    }

    #[test]
    fn parse_ethernet_rst() {
        let dip = Ipv4Addr::new(192,168,1,1);
        let sip = Ipv4Addr::new(10,0,0,1);
        let pkt = make_rst_pkt(sip, 80, dip, 50000);
        let parsed = parse_frame(&pkt, Linktype::ETHERNET).unwrap();
        assert_eq!(parsed.flags, 0x04);
    }

    #[test]
    fn match_synack_success() {
        let local_ip = Ipv4Addr::new(192,168,1,1);
        let target_ip = Ipv4Addr::new(10,0,0,1);
        let seq = 100u32;
        let sp = 50000u16;

        let pkt = make_synack_pkt(target_ip, 22, local_ip, sp, seq.wrapping_add(1));

        let parsed = parse_frame(&pkt, Linktype::ETHERNET).unwrap();

        let (tx, _rx) = oneshot::channel();
        let mut m = HashMap::new();
        m.insert(sp, PendingProbe { expected_ack: seq.wrapping_add(1), send_time: Instant::now(), sender: tx });
        let pending = Mutex::new(m);

        let result = match_response(&parsed, local_ip, &pending);
        assert!(matches!(result, Some(Evidence::SynAck { .. })));
    }

    #[test]
    fn match_rst_success() {
        let local_ip = Ipv4Addr::new(192,168,1,1);
        let target_ip = Ipv4Addr::new(10,0,0,1);
        let sp = 50000u16;

        let pkt = make_rst_pkt(target_ip, 22, local_ip, sp);
        let parsed = parse_frame(&pkt, Linktype::ETHERNET).unwrap();

        let (tx, _rx) = oneshot::channel();
        let mut m = HashMap::new();
        m.insert(sp, PendingProbe { expected_ack: 0, send_time: Instant::now(), sender: tx });
        let pending = Mutex::new(m);

        let result = match_response(&parsed, local_ip, &pending);
        assert!(matches!(result, Some(Evidence::Reset { .. })));
    }

    #[test]
    fn match_wrong_ack_ignored() {
        let local_ip = Ipv4Addr::new(192,168,1,1);
        let target_ip = Ipv4Addr::new(10,0,0,1);
        let seq = 100u32;
        let sp = 50000u16;

        let pkt = make_synack_pkt(target_ip, 22, local_ip, sp, 999); // wrong ack
        let parsed = parse_frame(&pkt, Linktype::ETHERNET).unwrap();

        let (tx, _rx) = oneshot::channel();
        let mut m = HashMap::new();
        m.insert(sp, PendingProbe { expected_ack: seq.wrapping_add(1), send_time: Instant::now(), sender: tx });
        let pending = Mutex::new(m);

        // Probe should NOT be removed on wrong ACK
        let result = match_response(&parsed, local_ip, &pending);
        assert!(result.is_none());
        assert_eq!(pending.lock().len(), 1);
    }

    #[test]
    fn seq_deterministic() {
        let a = Ipv4Addr::new(10,0,0,1);
        assert_eq!(compute_seq(a,80,a,50000), compute_seq(a,80,a,50000));
        assert_ne!(compute_seq(a,80,a,50000), compute_seq(a,443,a,50000));
    }

    #[test]
    fn ip_checksum_computed() {
        // IP header without checksum (checksum field = 0)
        let mut h = [0x45, 0, 0x00, 0x2c, 0x12, 0x34, 0x00, 0x00, 0x3a, 0x06, 0, 0, 0xc0, 0xa8, 0x8b, 0x1e, 0x0a, 0xfe, 0xc9, 0x88];
        let csum = ip_checksum(&h);
        assert_ne!(csum, 0, "IP checksum must not be zero");
        // Verify: set checksum field and verify whole header has correct checksum
        h[10] = (csum >> 8) as u8;
        h[11] = (csum & 0xFF) as u8;
        let verify = ip_checksum(&h);
        assert_eq!(verify, 0, "IP header with correct checksum must sum to 0");
    }

    #[test]
    fn tcp_checksum_computed() {
        let sip = Ipv4Addr::new(192,168,1,1);
        let dip = Ipv4Addr::new(10,0,0,1);
        let tcp = [0x9c, 0x40, 0x00, 0x16, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0x60, 0x02, 0x04, 0x00, 0, 0, 0, 0, 0x02, 0x04, 0x05, 0xb4];
        let csum = tcp_checksum(&sip, &dip, 24, &tcp);
        assert_ne!(csum, 0);
    }
}
