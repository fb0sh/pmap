mod parser;
mod resolver;

pub use parser::parse_targets;
pub use resolver::resolve_input_file;
pub use parser::Target;

use std::net::IpAddr;

/// A resolved host (concrete IP address).
pub type Host = IpAddr;
