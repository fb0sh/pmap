use clap::Parser;

/// pmap - Cross-platform TCP port scanner
#[derive(Parser, Debug)]
#[command(name = "pmap", version, about = "TCP port scanner")]
pub struct Args {
    /// TCP SYN scan
    #[arg(long = "syn", conflicts_with = "connect_scan")]
    pub syn_scan: bool,

    /// TCP connect scan
    #[arg(long = "connect", conflicts_with = "syn_scan")]
    pub connect_scan: bool,

    /// Timing template (0-5), default 3
    #[arg(short = 'T', value_parser = parse_timing)]
    pub timing: Option<u8>,

    /// Target IPs, CIDRs, or hostnames
    pub targets: Vec<String>,

    /// Read targets from file
    #[arg(short = 'i', long = "input-file")]
    pub input_file: Option<String>,

    /// Port specification (e.g. 22,80,443 or 1-1024)
    #[arg(short = 'p', conflicts_with = "all_ports")]
    pub ports: Option<String>,

    /// Scan all 65535 ports
    #[arg(short = 'P', long = "all-ports")]
    pub all_ports: bool,

    /// Show only open results
    #[arg(long = "open")]
    pub open_only: bool,

    /// Normal text output file
    #[arg(short = 'o', long = "output-normal")]
    pub output_normal: Option<String>,

    /// JSON output file
    #[arg(short = 'j', long = "output-json")]
    pub output_json: Option<String>,

    /// JSON Lines output file
    #[arg(short = 'l', long = "output-jsonl")]
    pub output_jsonl: Option<String>,

    /// Output all formats with prefix
    #[arg(short = 'a', long = "output-all")]
    pub output_all: Option<String>,
}

fn parse_timing(s: &str) -> Result<u8, String> {
    s.parse::<u8>()
        .map_err(|_| format!("invalid timing template: {s} (must be 0-5)"))
        .and_then(|v| {
            if v <= 5 {
                Ok(v)
            } else {
                Err(format!("timing template must be 0-5, got {v}"))
            }
        })
}
