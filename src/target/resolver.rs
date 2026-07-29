use super::parser::{Target, TargetError};

/// Parse a target file content into Target variants.
///
/// Skips empty lines, lines starting with '#', and trims whitespace.
pub fn resolve_input_file(content: &str) -> Result<Vec<Target>, TargetError> {
    let lines: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    parse_targets(&lines)
}

use super::parser::parse_targets;
