use std::fmt;

/// Parse a port specification string into a sorted, deduplicated list of ports.
///
/// Supports:
/// - Single port: "443"
/// - Comma-separated: "22,80,443"
/// - Range: "1-1024"
/// - Mixed: "22,80,443,8000-9000"
/// - All ports: "-"
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, PortError> {
    if spec.is_empty() {
        return Err(PortError::Empty);
    }

    if spec == "-" {
        return Ok((1..=65535).collect());
    }

    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(PortError::InvalidRange(part.to_string()));
            }

            let start: u16 = range_parts[0]
                .parse()
                .map_err(|_| PortError::InvalidPort(range_parts[0].to_string()))?;
            let end: u16 = range_parts[1]
                .parse()
                .map_err(|_| PortError::InvalidPort(range_parts[1].to_string()))?;

            if start == 0 || end == 0 {
                return Err(PortError::InvalidPort(part.to_string()));
            }
            if start > end {
                return Err(PortError::InvalidRange(part.to_string()));
            }

            for p in start..=end {
                ports.push(p);
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| PortError::InvalidPort(part.to_string()))?;
            if port == 0 {
                return Err(PortError::InvalidPort(part.to_string()));
            }
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err(PortError::Empty);
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    Empty,
    InvalidPort(String),
    InvalidRange(String),
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortError::Empty => write!(f, "empty port specification"),
            PortError::InvalidPort(s) => write!(f, "invalid port: {s}"),
            PortError::InvalidRange(s) => write!(f, "invalid port range: {s}"),
        }
    }
}

impl std::error::Error for PortError {}
