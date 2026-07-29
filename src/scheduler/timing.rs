use std::time::Duration;

/// Timing template controlling scan speed, concurrency, and delays.
///
/// Templates T0–T5 map to Nmap-inspired profiles:
/// - T0: paranoid   (slowest, stealthiest)
/// - T1: sneaky
/// - T2: polite
/// - T3: normal     (default)
/// - T4: aggressive
/// - T5: insane     (fastest)
#[derive(Debug, Clone)]
pub struct TimingPolicy {
    /// TCP connect timeout per probe.
    pub connect_timeout: Duration,
    /// Minimum delay between consecutive probes to the same host.
    pub inter_probe_delay: Duration,
    /// Maximum concurrent probes across all hosts.
    pub max_concurrent_global: usize,
    /// Maximum concurrent probes per individual host.
    pub max_concurrent_per_host: usize,
    /// Maximum hosts with in-flight probes simultaneously.
    pub max_active_hosts: usize,
}

impl TimingPolicy {
    /// Create a TimingPolicy from a template number (0–5).
    pub fn from_template(template: u8) -> Self {
        match template {
            0 => Self {
                connect_timeout: Duration::from_millis(5000),
                inter_probe_delay: Duration::from_millis(10000),
                max_concurrent_global: 1,
                max_concurrent_per_host: 1,
                max_active_hosts: 1,
            },
            1 => Self {
                connect_timeout: Duration::from_millis(3000),
                inter_probe_delay: Duration::from_millis(2000),
                max_concurrent_global: 5,
                max_concurrent_per_host: 1,
                max_active_hosts: 1,
            },
            2 => Self {
                connect_timeout: Duration::from_millis(1000),
                inter_probe_delay: Duration::from_millis(500),
                max_concurrent_global: 10,
                max_concurrent_per_host: 2,
                max_active_hosts: 2,
            },
            3 => Self {
                connect_timeout: Duration::from_millis(1000),
                inter_probe_delay: Duration::from_millis(100),
                max_concurrent_global: 50,
                max_concurrent_per_host: 5,
                max_active_hosts: 5,
            },
            4 => Self {
                connect_timeout: Duration::from_millis(500),
                inter_probe_delay: Duration::from_millis(50),
                max_concurrent_global: 100,
                max_concurrent_per_host: 10,
                max_active_hosts: 10,
            },
            5 => Self {
                connect_timeout: Duration::from_millis(250),
                inter_probe_delay: Duration::ZERO,
                max_concurrent_global: 500,
                max_concurrent_per_host: 100,
                max_active_hosts: 50,
            },
            _ => Self::from_template(3), // fallback to T3
        }
    }
}

impl Default for TimingPolicy {
    fn default() -> Self {
        Self::from_template(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_t0_is_slowest() {
        let t = TimingPolicy::from_template(0);
        assert_eq!(t.connect_timeout, Duration::from_millis(5000));
        assert_eq!(t.inter_probe_delay, Duration::from_millis(10000));
        assert_eq!(t.max_concurrent_global, 1);
        assert_eq!(t.max_concurrent_per_host, 1);
        assert_eq!(t.max_active_hosts, 1);
    }

    #[test]
    fn template_t3_is_default() {
        let t = TimingPolicy::from_template(3);
        assert_eq!(t.connect_timeout, Duration::from_millis(1000));
        assert_eq!(t.inter_probe_delay, Duration::from_millis(100));
        assert_eq!(t.max_concurrent_global, 50);
        assert_eq!(t.max_concurrent_per_host, 5);
        assert_eq!(t.max_active_hosts, 5);
    }

    #[test]
    fn template_t5_is_fastest() {
        let t = TimingPolicy::from_template(5);
        assert_eq!(t.connect_timeout, Duration::from_millis(250));
        assert_eq!(t.inter_probe_delay, Duration::ZERO);
        assert_eq!(t.max_concurrent_global, 500);
        assert_eq!(t.max_concurrent_per_host, 100);
        assert_eq!(t.max_active_hosts, 50);
    }

    #[test]
    fn default_is_t3() {
        let t = TimingPolicy::default();
        let t3 = TimingPolicy::from_template(3);
        assert_eq!(t.connect_timeout, t3.connect_timeout);
        assert_eq!(t.max_concurrent_global, t3.max_concurrent_global);
    }

    #[test]
    fn invalid_template_falls_back_to_t3() {
        let t = TimingPolicy::from_template(99);
        let t3 = TimingPolicy::from_template(3);
        assert_eq!(t.connect_timeout, t3.connect_timeout);
    }

    #[test]
    fn concurrency_increases_with_template() {
        for i in 0..5 {
            let lower = TimingPolicy::from_template(i);
            let upper = TimingPolicy::from_template(i + 1);
            assert!(upper.max_concurrent_global >= lower.max_concurrent_global);
            assert!(upper.max_concurrent_per_host >= lower.max_concurrent_per_host);
            assert!(upper.max_active_hosts >= lower.max_active_hosts);
        }
    }
}
