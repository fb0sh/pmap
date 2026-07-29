use std::fmt;

/// A user-provided target before resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A literal IP address.
    Ip(String),
    /// A CIDR range (e.g. "192.168.1.0/24").
    Cidr(String),
    /// A hostname to resolve.
    Hostname(String),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(s) | Target::Cidr(s) | Target::Hostname(s) => write!(f, "{s}"),
        }
    }
}

/// Parse raw target strings into Target variants.
///
/// Rules:
/// - Contains "/" → Cidr
/// - Parses as IpAddr → Ip
/// - Otherwise → Hostname
pub fn parse_targets(raw: &[String]) -> Result<Vec<Target>, TargetError> {
    if raw.is_empty() {
        return Err(TargetError::NoTargets);
    }

    raw.iter()
        .map(|s| {
            if s.contains('/') {
                // Validate CIDR format
                let parts: Vec<&str> = s.split('/').collect();
                if parts.len() != 2 {
                    return Err(TargetError::InvalidCidr(s.clone()));
                }
                let _ip: std::net::Ipv4Addr = parts[0]
                    .parse()
                    .map_err(|_| TargetError::InvalidCidr(s.clone()))?;
                let _mask: u8 = parts[1]
                    .parse()
                    .map_err(|_| TargetError::InvalidCidr(s.clone()))?;
                if _mask > 32 {
                    return Err(TargetError::InvalidCidr(s.clone()));
                }
                Ok(Target::Cidr(s.clone()))
            } else if s.parse::<std::net::Ipv4Addr>().is_ok() {
                Ok(Target::Ip(s.clone()))
            } else {
                // Basic hostname validation: at least one dot, no spaces
                if s.contains(' ') || s.is_empty() {
                    return Err(TargetError::InvalidHostname(s.clone()));
                }
                Ok(Target::Hostname(s.clone()))
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    NoTargets,
    InvalidCidr(String),
    InvalidHostname(String),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::NoTargets => write!(f, "no targets specified"),
            TargetError::InvalidCidr(s) => write!(f, "invalid CIDR: {s}"),
            TargetError::InvalidHostname(s) => write!(f, "invalid hostname: {s}"),
        }
    }
}

impl std::error::Error for TargetError {}
