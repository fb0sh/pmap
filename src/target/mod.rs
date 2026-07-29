mod parser;
mod resolver;

pub use parser::Target;
pub use parser::parse_targets;
pub use resolver::resolve_input_file;

use std::net::IpAddr;

/// A resolved host (concrete IP address).
pub type Host = IpAddr;
