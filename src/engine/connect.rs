use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::evidence::Evidence;

use super::traits::{LocalError, ProbeTaskResult, ScanEngine};

/// TCP Connect scan engine.
///
/// Uses Tokio TcpStream to attempt connections.
/// Works on all platforms with normal user privileges.
#[derive(Clone, Copy)]
pub struct ConnectEngine {
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for ConnectEngine {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
        }
    }
}

#[async_trait::async_trait]
impl ScanEngine for ConnectEngine {
    async fn probe(&self, host: IpAddr, port: u16) -> ProbeTaskResult {
        let addr = format!("{host}:{port}");
        let start = Instant::now();

        match timeout(self.connect_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => {
                // Connection succeeded → Open
                let rtt = start.elapsed();
                // Immediately close — no application-layer communication
                drop(_stream);
                ProbeTaskResult::Evidence(Evidence::ConnectSuccess { rtt })
            }
            Ok(Err(e)) => {
                let rtt = start.elapsed();
                let err_str = e.to_string().to_lowercase();

                // Map OS-level errors
                if err_str.contains("connection refused") || err_str.contains("connection reset") {
                    ProbeTaskResult::Evidence(Evidence::ConnectRefused { rtt })
                } else if err_str.contains("host unreachable")
                    || err_str.contains("network unreachable")
                {
                    ProbeTaskResult::Evidence(Evidence::HostUnreachable)
                } else if err_str.contains("too many open files")
                    || err_str.contains("cannot assign requested address")
                    || err_str.contains("address already in use")
                    || err_str.contains("no buffer space available")
                {
                    ProbeTaskResult::LocalError(LocalError::ResourceExhausted)
                } else if err_str.contains("permission denied")
                    || err_str.contains("operation not permitted")
                {
                    ProbeTaskResult::LocalError(LocalError::PermissionDenied)
                } else {
                    // Other connection error — treat as unknown/unreachable
                    ProbeTaskResult::Evidence(Evidence::Timeout)
                }
            }
            Err(_timeout) => {
                // Timed out
                ProbeTaskResult::Evidence(Evidence::Timeout)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn probe_localhost_unlikely_port() {
        let engine = ConnectEngine {
            connect_timeout: Duration::from_millis(500),
        };
        // Port 1 is almost certainly closed on any system
        let result = engine.probe(IpAddr::V4(Ipv4Addr::LOCALHOST), 1).await;
        match result {
            ProbeTaskResult::Evidence(Evidence::ConnectRefused { rtt }) => {
                assert!(rtt < Duration::from_secs(1));
            }
            other => panic!("expected ConnectRefused, got {other:?}"),
        }
    }
}
