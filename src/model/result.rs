use std::net::IpAddr;
use std::time::Duration;

use super::{Confidence, PortState};

/// A single probe's result for one Host:Port.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub host: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub confidence: Confidence,
    pub best_rtt: Option<Duration>,
}

/// Transport protocol. First version only supports TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
        }
    }
}

/// The complete scan result — all ProbeResults from a single Scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub results: Vec<ProbeResult>,
    pub unknown: Vec<UnknownEntry>,
    pub summary: Summary,
}

/// Compressed unknown port ranges for one host.
#[derive(Debug, Clone)]
pub struct UnknownEntry {
    pub host: IpAddr,
    pub protocol: Protocol,
    /// Sorted, non-overlapping [start, end] ranges (inclusive).
    pub ranges: Vec<(u16, u16)>,
}

/// Scan-level summary statistics.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub hosts_requested: u64,
    pub hosts_resolved: u64,
    pub hosts_failed: u64,
    pub ports_selected: u64,
    pub probes_planned: u64,
    pub probes_completed: u64,
    pub open: u64,
    pub closed: u64,
    pub filtered: u64,
    pub unreachable: u64,
    pub unknown: u64,
    pub not_scanned: u64,
    pub local_errors: u64,
    pub completed: bool,
    pub partial_failures: bool,
    pub elapsed_ms: u64,
}
