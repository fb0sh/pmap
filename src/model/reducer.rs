use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use super::{Confidence, PortState};
use super::evidence::Evidence;
use super::result::{ProbeResult, Protocol, ScanResult, Summary, UnknownEntry};

/// Per-port state tracked by the reducer.
#[derive(Debug, Clone)]
struct PortEntry {
    state: PortState,
    confidence: Confidence,
    best_rtt: Option<Duration>,
    last_rtt: Option<Duration>,
    has_conflict: bool,
    evidence_count: u32,
}

impl Default for PortEntry {
    fn default() -> Self {
        Self {
            state: PortState::Pending,
            confidence: Confidence::Low,
            best_rtt: None,
            last_rtt: None,
            has_conflict: false,
            evidence_count: 0,
        }
    }
}

/// The State Reducer — single source of truth for PortState + Confidence.
///
/// Consumes Evidence for individual Host:Port pairs and produces final ProbeResults.
#[derive(Debug)]
pub struct StateReducer {
    /// (host, port) → PortEntry
    ports: HashMap<(IpAddr, u16), PortEntry>,
    /// Per-host port lists for unknown range compression
    host_ports: HashMap<IpAddr, Vec<u16>>,
}

/// Returns the priority of a port state for comparison with evidence priority.
/// Uses the same scale as Evidence::priority() (1-5).
fn entry_priority(state: &PortState) -> u8 {
    match state {
        PortState::Open => 5,       // ConnectSuccess/SynAck level
        PortState::Closed => 3,     // ConnectRefused/Reset level
        PortState::Filtered => 2,   // ICMP level
        PortState::Unreachable => 2,
        PortState::Unknown => 1,    // Timeout level
        PortState::Pending => 0,
    }
}

impl StateReducer {
    pub fn new() -> Self {
        Self {
            ports: HashMap::new(),
            host_ports: HashMap::new(),
        }
    }

    /// Record a new piece of evidence for a host:port pair.
    pub fn apply_evidence(&mut self, host: IpAddr, port: u16, evidence: &Evidence) {
        let entry = self.ports.entry((host, port)).or_default();
        entry.evidence_count += 1;

        let (new_state, new_confidence) = evidence.to_state_confidence();

        // Timeout is weak — never overwrites existing stronger state
        if matches!(evidence, Evidence::Timeout) {
            if matches!(entry.state, PortState::Pending) {
                entry.state = new_state;
                entry.confidence = new_confidence;
            }
            // Always update last_rtt (though timeout has no RTT)
            return;
        }

        // Check for conflict: two non-Timeout evidence sources disagree on state
        let is_non_weak = evidence.priority() >= 2; // ICMP and above
        let has_prior = !matches!(entry.state, PortState::Pending | PortState::Unknown);
        let states_disagree = has_prior && entry.state != new_state;

        if states_disagree && is_non_weak {
            // Conflict: both sources are non-weak but disagree
            entry.has_conflict = true;
            // Keep the stronger state (higher evidence priority)
            if evidence.priority() > entry_priority(&entry.state) {
                entry.state = new_state;
                entry.confidence = new_confidence;
            }
        } else if !states_disagree {
            // No conflict — update state if new evidence is stronger
            let should_update = entry.state == PortState::Pending
                || new_confidence > entry.confidence
                || (new_confidence == entry.confidence && evidence.priority() > entry_priority(&entry.state));
            if should_update {
                entry.state = new_state;
                entry.confidence = new_confidence;
            }
        } else {
            // States disagree but new evidence is weak (Timeout) — don't update
        }

        // Update RTT
        if let Some(rtt) = evidence.rtt() {
            entry.last_rtt = Some(rtt);
            entry.best_rtt = Some(match entry.best_rtt {
                Some(best) => best.min(rtt),
                None => rtt,
            });
        }

        self.host_ports.entry(host).or_default().push(port);
    }

    /// Get the final ProbeResult for a specific host:port.
    pub fn get_result(&self, host: IpAddr, port: u16) -> Option<ProbeResult> {
        self.ports.get(&(host, port)).map(|entry| {
            let mut confidence = entry.confidence;
            if entry.has_conflict {
                // Downgrade to Medium on conflict
                confidence = Confidence::Medium;
            }

            ProbeResult {
                host,
                port,
                protocol: Protocol::Tcp,
                state: entry.state,
                confidence,
                best_rtt: entry.best_rtt,
            }
        })
    }

    /// Build the full ScanResult with sorted results and compressed unknowns.
    pub fn into_scan_result(self, summary: Summary) -> ScanResult {
        let mut results: Vec<ProbeResult> = self
            .ports
            .iter()
            .filter(|(_, entry)| !matches!(entry.state, PortState::Pending))
            .map(|((host, port), entry)| {
                let mut confidence = entry.confidence;
                if entry.has_conflict {
                    confidence = Confidence::Medium;
                }
                ProbeResult {
                    host: *host,
                    port: *port,
                    protocol: Protocol::Tcp,
                    state: entry.state,
                    confidence,
                    best_rtt: entry.best_rtt,
                }
            })
            .collect();

        // Sort by IP (numeric) then port
        results.sort_by(|a, b| {
            a.host
                .cmp(&b.host)
                .then(a.port.cmp(&b.port))
        });

        // Build unknown entries per host
        let mut unknown = Vec::new();
        for (host, ports) in &self.host_ports {
            let mut unknown_ports: Vec<u16> = ports
                .iter()
                .filter(|&&p| {
                    self.ports
                        .get(&(*host, p))
                        .map_or(false, |e| matches!(e.state, PortState::Unknown))
                })
                .copied()
                .collect();

            unknown_ports.sort_unstable();
            unknown_ports.dedup();

            if !unknown_ports.is_empty() {
                let ranges = compress_ranges(&unknown_ports);
                unknown.push(UnknownEntry {
                    host: *host,
                    protocol: Protocol::Tcp,
                    ranges,
                });
            }
        }

        unknown.sort_by_key(|u| u.host);

        ScanResult {
            results,
            unknown,
            summary,
        }
    }

    /// Number of ports tracked.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }
}

/// Compress a sorted list of ports into [start, end] ranges (inclusive).
fn compress_ranges(ports: &[u16]) -> Vec<(u16, u16)> {
    if ports.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut start = ports[0];
    let mut end = ports[0];

    for &p in &ports[1..] {
        if p == end + 1 {
            end = p;
        } else {
            ranges.push((start, end));
            start = p;
            end = p;
        }
    }
    ranges.push((start, end));
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_connect_success() {
        let mut reducer = StateReducer::new();
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            80,
            &Evidence::ConnectSuccess {
                rtt: Duration::from_millis(10),
            },
        );

        let result = reducer.get_result("192.168.1.1".parse().unwrap(), 80).unwrap();
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.confidence, Confidence::Confirmed);
        assert_eq!(result.best_rtt, Some(Duration::from_millis(10)));
    }

    #[test]
    fn single_syn_ack() {
        let mut reducer = StateReducer::new();
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            443,
            &Evidence::SynAck {
                rtt: Duration::from_millis(5),
            },
        );

        let result = reducer.get_result("192.168.1.1".parse().unwrap(), 443).unwrap();
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn timeout_does_not_override_open() {
        let mut reducer = StateReducer::new();
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            80,
            &Evidence::ConnectSuccess {
                rtt: Duration::from_millis(10),
            },
        );
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            80,
            &Evidence::Timeout,
        );

        let result = reducer.get_result("192.168.1.1".parse().unwrap(), 80).unwrap();
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.confidence, Confidence::Confirmed);
    }

    #[test]
    fn timeout_sets_unknown_when_no_prior_evidence() {
        let mut reducer = StateReducer::new();
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            9999,
            &Evidence::Timeout,
        );

        let result = reducer.get_result("192.168.1.1".parse().unwrap(), 9999).unwrap();
        assert_eq!(result.state, PortState::Unknown);
        assert_eq!(result.confidence, Confidence::Low);
    }

    #[test]
    fn conflict_downgrades_to_medium() {
        let mut reducer = StateReducer::new();
        let host: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        reducer.apply_evidence(
            host,
            80,
            &Evidence::SynAck {
                rtt: Duration::from_millis(5),
            },
        );
        reducer.apply_evidence(
            host,
            80,
            &Evidence::IcmpFiltered { code: 3 },
        );

        let result = reducer.get_result("192.168.1.1".parse().unwrap(), 80).unwrap();
        assert_eq!(result.state, PortState::Open); // stronger state kept
        assert_eq!(result.confidence, Confidence::Medium); // but downgraded
    }

    #[test]
    fn best_rtt_tracking() {
        let mut reducer = StateReducer::new();
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            80,
            &Evidence::ConnectSuccess {
                rtt: Duration::from_millis(20),
            },
        );
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            80,
            &Evidence::ConnectSuccess {
                rtt: Duration::from_millis(8),
            },
        );

        let result = reducer.get_result("192.168.1.1".parse().unwrap(), 80).unwrap();
        assert_eq!(result.best_rtt, Some(Duration::from_millis(8))); // min
    }

    #[test]
    fn ip_sorting_is_numeric() {
        let mut reducer = StateReducer::new();
        for ip in &["192.168.1.10", "192.168.1.2", "192.168.1.1"] {
            reducer.apply_evidence(
                ip.parse().unwrap(),
                80,
                &Evidence::ConnectSuccess {
                    rtt: Duration::from_millis(10),
                },
            );
        }

        let result = reducer.into_scan_result(Summary::default());
        let ips: Vec<IpAddr> = result.results.iter().map(|r| r.host).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::from([192, 168, 1, 1]),
                IpAddr::from([192, 168, 1, 2]),
                IpAddr::from([192, 168, 1, 10]),
            ]
        );
    }

    #[test]
    fn closed_does_not_override_open() {
        let mut reducer = StateReducer::new();
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            80,
            &Evidence::ConnectSuccess {
                rtt: Duration::from_millis(10),
            },
        );
        reducer.apply_evidence(
            "192.168.1.1".parse().unwrap(),
            80,
            &Evidence::Reset {
                rtt: Duration::from_millis(5),
            },
        );

        let result = reducer.get_result("192.168.1.1".parse().unwrap(), 80).unwrap();
        // ConnectSuccess (priority 5) > Reset (priority 3), so Open kept
        // But conflict → confidence downgraded to Medium
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.confidence, Confidence::Medium);
    }
}
