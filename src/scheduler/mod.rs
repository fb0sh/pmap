pub mod timing;

use std::net::IpAddr;

pub use timing::TimingPolicy;

/// A single probe task: one host:port pair to scan.
#[derive(Debug, Clone)]
pub struct ProbeTask {
    pub host: IpAddr,
    pub port: u16,
}

/// Round-robin scheduler that interleaves probes across hosts.
///
/// Generates probe tasks in host-interleaved order so that no single slow
/// host monopolises scanning. With H hosts and P ports, the order is:
///
/// ```text
/// h₀:p₀  h₁:p₀  h₂:p₀  …  h₀:p₁  h₁:p₁  …
/// ```
///
/// This ensures every host gets probed at roughly the same rate.
pub struct Scheduler {
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    /// Total number of probe tasks (hosts × ports).
    total: u64,
    /// How many tasks have been dispatched via `next_task()`.
    dispatched: u64,
    /// Current index into the ports slice.
    port_index: usize,
    /// Current index into the hosts slice (round-robin position).
    host_index: usize,
}

impl Scheduler {
    /// Create a new scheduler for the given hosts and ports.
    ///
    /// `hosts` and `ports` must be non-empty. Callers should validate beforehand.
    pub fn new(hosts: Vec<IpAddr>, ports: Vec<u16>) -> Self {
        let total = hosts.len() as u64 * ports.len() as u64;
        Self {
            hosts,
            ports,
            total,
            dispatched: 0,
            port_index: 0,
            host_index: 0,
        }
    }

    /// Return the next probe task, or `None` if all tasks have been dispatched.
    ///
    /// Tasks are emitted in round-robin host order: one port per host per round,
    /// cycling through all hosts before advancing to the next port.
    pub fn next_task(&mut self) -> Option<ProbeTask> {
        if self.is_done() {
            return None;
        }

        let host = self.hosts[self.host_index];
        let port = self.ports[self.port_index];

        // Advance round-robin position
        self.host_index += 1;
        if self.host_index >= self.hosts.len() {
            self.host_index = 0;
            self.port_index += 1;
        }

        self.dispatched += 1;
        Some(ProbeTask { host, port })
    }

    /// Returns `true` when all probe tasks have been dispatched.
    pub fn is_done(&self) -> bool {
        self.port_index >= self.ports.len()
    }

    /// Number of tasks that have been dispatched so far.
    pub fn dispatched_count(&self) -> u64 {
        self.dispatched
    }

    /// Number of probe tasks that were never dispatched (interrupted or not yet reached).
    pub fn not_scanned_count(&self) -> u64 {
        self.total.saturating_sub(self.dispatched)
    }

    /// Total number of probe tasks.
    pub fn total_probes(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse::<Ipv4Addr>().unwrap().into()
    }

    #[test]
    fn single_host_single_port() {
        let mut sched = Scheduler::new(vec![ip("10.0.0.1")], vec![80]);
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.1"));
        assert_eq!(t.port, 80);
        assert!(sched.next_task().is_none());
        assert!(sched.is_done());
    }

    #[test]
    fn round_robin_interleaves_hosts() {
        let hosts = vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")];
        let ports = vec![22, 80, 443];
        let mut sched = Scheduler::new(hosts, ports);

        // Round 1 (port 22)
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.1"));
        assert_eq!(t.port, 22);
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.2"));
        assert_eq!(t.port, 22);
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.3"));
        assert_eq!(t.port, 22);

        // Round 2 (port 80)
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.1"));
        assert_eq!(t.port, 80);
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.2"));
        assert_eq!(t.port, 80);
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.3"));
        assert_eq!(t.port, 80);

        // Round 3 (port 443)
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.1"));
        assert_eq!(t.port, 443);
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.2"));
        assert_eq!(t.port, 443);
        let t = sched.next_task().unwrap();
        assert_eq!(t.host, ip("10.0.0.3"));
        assert_eq!(t.port, 443);

        assert!(sched.next_task().is_none());
    }

    #[test]
    fn total_probes_matches() {
        let hosts = vec![ip("10.0.0.1"), ip("10.0.0.2")];
        let ports = vec![22, 80, 443, 8080];
        let mut sched = Scheduler::new(hosts, ports);
        assert_eq!(sched.total_probes(), 8);

        let mut count = 0;
        while sched.next_task().is_some() {
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[test]
    fn not_scanned_count_decreases() {
        let hosts = vec![ip("10.0.0.1"), ip("10.0.0.2")];
        let ports = vec![22, 80, 443];
        let mut sched = Scheduler::new(hosts, ports);
        assert_eq!(sched.not_scanned_count(), 6);

        sched.next_task();
        assert_eq!(sched.not_scanned_count(), 5);
        sched.next_task();
        assert_eq!(sched.not_scanned_count(), 4);

        // Dispatch all remaining
        while sched.next_task().is_some() {}
        assert_eq!(sched.not_scanned_count(), 0);
    }

    #[test]
    fn dispatched_count_increases() {
        let hosts = vec![ip("10.0.0.1")];
        let ports = vec![80, 443];
        let mut sched = Scheduler::new(hosts, ports);
        assert_eq!(sched.dispatched_count(), 0);

        sched.next_task();
        assert_eq!(sched.dispatched_count(), 1);
        sched.next_task();
        assert_eq!(sched.dispatched_count(), 2);
    }
}
