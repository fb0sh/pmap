use std::time::Duration;

/// A single observation from a probe that can inform port state.
#[derive(Debug, Clone)]
pub enum Evidence {
    /// Received SYN-ACK (SYN scan).
    SynAck { rtt: Duration },
    /// Received RST.
    Reset { rtt: Duration },
    /// TCP connection succeeded (Connect scan).
    ConnectSuccess { rtt: Duration },
    /// Connection refused.
    ConnectRefused { rtt: Duration },
    /// Explicit ICMP filtered response.
    IcmpFiltered { code: u8 },
    /// ICMP host unreachable.
    HostUnreachable,
    /// ICMP network unreachable.
    NetworkUnreachable,
    /// No response after retries.
    Timeout,
}

/// Priority order for merging evidence (highest first).
///
/// ConnectSuccess > SynAck > ConnectRefused / Reset > ICMP > Timeout
impl Evidence {
    /// Returns the priority level (higher = stronger evidence).
    pub fn priority(&self) -> u8 {
        match self {
            Evidence::ConnectSuccess { .. } => 5,
            Evidence::SynAck { .. } => 4,
            Evidence::ConnectRefused { .. } | Evidence::Reset { .. } => 3,
            Evidence::IcmpFiltered { .. }
            | Evidence::HostUnreachable
            | Evidence::NetworkUnreachable => 2,
            Evidence::Timeout => 1,
        }
    }

    /// Returns the RTT if available.
    pub fn rtt(&self) -> Option<Duration> {
        match self {
            Evidence::SynAck { rtt }
            | Evidence::Reset { rtt }
            | Evidence::ConnectSuccess { rtt }
            | Evidence::ConnectRefused { rtt } => Some(*rtt),
            _ => None,
        }
    }

    /// Maps this evidence to a (PortState, Confidence) pair.
    pub fn to_state_confidence(&self) -> (crate::model::PortState, crate::model::Confidence) {
        use crate::model::{Confidence, PortState};
        match self {
            Evidence::ConnectSuccess { .. } => (PortState::Open, Confidence::Confirmed),
            Evidence::SynAck { .. } => (PortState::Open, Confidence::High),
            Evidence::ConnectRefused { .. } => (PortState::Closed, Confidence::Confirmed),
            Evidence::Reset { .. } => (PortState::Closed, Confidence::High),
            Evidence::IcmpFiltered { .. } => (PortState::Filtered, Confidence::High),
            Evidence::HostUnreachable => (PortState::Unreachable, Confidence::High),
            Evidence::NetworkUnreachable => (PortState::Unreachable, Confidence::High),
            Evidence::Timeout => (PortState::Unknown, Confidence::Low),
        }
    }
}

/// The result of executing a probe task.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// Successfully collected evidence.
    Evidence(Evidence),
    /// Task was cancelled (Ctrl+C, scheduler shutdown, fatal error).
    /// Cancelled tasks do NOT enter the State Reducer.
    Cancelled(CancelReason),
}

/// Why a probe task was cancelled.
#[derive(Debug, Clone)]
pub enum CancelReason {
    /// User pressed Ctrl+C or sent termination signal.
    UserInterrupt,
    /// Scheduler shutdown (all work complete or fatal error).
    SchedulerShutdown,
    /// This host's tasks were cancelled after it finished early.
    HostCompleted,
}
