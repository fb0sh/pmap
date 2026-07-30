use std::fmt;

/// Errors from platform/privilege checks before SYN scan can proceed.
#[derive(Debug)]
pub enum SynError {
    /// Platform is not supported for SYN scan.
    UnsupportedPlatform(String),
    /// Insufficient privileges (not root, no CAP_NET_RAW).
    PermissionDenied(String),
    /// Failed to create test raw socket (fd limit, kernel config, etc.)
    SocketCreationFailed(String),
}

impl fmt::Display for SynError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SynError::UnsupportedPlatform(msg) => write!(f, "SYN scan: {msg}"),
            SynError::PermissionDenied(msg) => write!(f, "SYN scan: {msg}"),
            SynError::SocketCreationFailed(msg) => write!(f, "SYN scan: {msg}"),
        }
    }
}

impl std::error::Error for SynError {}

/// Check if SYN scan is possible on this platform with current privileges.
///
/// Returns Ok(()) if SYN scan can proceed, or a descriptive SynError.
pub fn check_syn_privilege() -> Result<(), SynError> {
    // ── Platform gate ──────────────────────────────────────────────────────
    #[cfg(not(target_os = "linux"))]
    {
        return Err(SynError::UnsupportedPlatform(
            "SYN scan is currently only supported on Linux. Use -sT for Connect scan.".into(),
        ));
    }

    // ── Linux: try creating a raw socket to verify privileges ───────────────
    #[cfg(target_os = "linux")]
    {
        use socket2::{Domain, Protocol, Socket, Type};

        // Test with IPPROTO_RAW — same as what SynEngine uses for sending
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).map_err(|e| {
            let errno = e.raw_os_error().unwrap_or(0);
            match errno {
                libc::EPERM | libc::EACCES => SynError::PermissionDenied(
                    "SYN scan requires root or CAP_NET_RAW. \
                     Try: sudo pmap -sS <target> \
                     or: setcap cap_net_raw+ep $(which pmap)"
                        .into(),
                ),
                libc::ENOBUFS | libc::ENOMEM => SynError::SocketCreationFailed(format!(
                    "failed to create raw socket: {e} (insufficient kernel resources)"
                )),
                _ => SynError::SocketCreationFailed(format!("failed to create raw socket: {e}")),
            }
        })?;

        // Socket created successfully — drop it (privilege confirmed).
        drop(sock);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let err = SynError::PermissionDenied("need root".into());
        assert!(err.to_string().contains("need root"));

        let err = SynError::UnsupportedPlatform("only Linux".into());
        assert!(err.to_string().contains("only Linux"));
    }
}
