use std::net::IpAddr;

use crate::model::evidence::Evidence;

/// Result of a single probe execution.
#[derive(Debug)]
pub enum ProbeTaskResult {
    /// Successfully collected evidence.
    Evidence(Evidence),
    /// Task was cancelled (Ctrl+C, scheduler shutdown).
    Cancelled,
    /// Local resource error (not a port state).
    LocalError(LocalError),
}

/// Local resource errors that should NOT be mapped to port states.
#[derive(Debug)]
pub enum LocalError {
    /// File descriptor exhaustion, too many open files.
    ResourceExhausted,
    /// Permission denied (e.g. raw socket without privileges).
    PermissionDenied,
    /// Other local error.
    Other(String),
}

/// A scan engine that probes Host:Port pairs.
#[async_trait::async_trait]
pub trait ScanEngine: Send + Sync {
    /// Probe a single Host:Port and return the result.
    async fn probe(&self, host: IpAddr, port: u16) -> ProbeTaskResult;
}
