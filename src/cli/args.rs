use clap::Parser;

/// pmap - Cross-platform TCP port scanner
#[derive(Parser, Debug)]
#[command(name = "pmap", version, about = "TCP port scanner")]
pub struct Args {
    /// Scan type: -sS (SYN) or -sT (Connect)
    #[arg(short = 's', value_parser = parse_scan_type)]
    pub scan_type: Option<String>,

    /// Timing template (-T0 to -T5), default -T3
    #[arg(short = 'T', value_parser = parse_timing)]
    pub timing: Option<u8>,

    /// Target IPs, CIDRs, or hostnames
    pub targets: Vec<String>,

    /// Read targets from file (-iL)
    #[arg(short = 'i', long = "input-file")]
    pub input_file: Option<String>,

    /// Port specification (e.g. -p 22,80,443 or -p 1-1024 or -p-)
    #[arg(short = 'p')]
    pub ports: Option<String>,

    /// Never do DNS resolution (-n)
    #[arg(short = 'n')]
    pub no_dns: bool,

    /// Skip host discovery, scan all targets (-Pn)
    #[arg(short = 'P', long = "skip-discovery")]
    pub skip_discovery: bool,

    /// Show only open results (--open)
    #[arg(long = "open")]
    pub open_only: bool,

    /// Normal text output file (-oN)
    #[arg(short = 'N', long = "output-normal", alias = "oN")]
    pub output_normal: Option<String>,

    /// JSON output file (-oJ)
    #[arg(short = 'J', long = "output-json", alias = "oJ")]
    pub output_json: Option<String>,

    /// JSON Lines output file (--oJL)
    #[arg(long = "output-jsonl", alias = "oJL")]
    pub output_jsonl: Option<String>,

    /// Output all formats with prefix (-oA)
    #[arg(short = 'A', long = "output-all", alias = "oA")]
    pub output_all: Option<String>,
}

impl Args {
    /// Check if SYN scan was requested.
    pub fn is_syn_scan(&self) -> bool {
        self.scan_type.as_deref() == Some("S")
    }

    /// Check if Connect scan was requested.
    pub fn is_connect_scan(&self) -> bool {
        self.scan_type.as_deref() == Some("T")
    }
}

fn parse_scan_type(s: &str) -> Result<String, String> {
    match s {
        "S" => Ok("S".to_string()),
        "T" => Ok("T".to_string()),
        _ => Err(format!("invalid scan type: -s{s} (use -sS or -sT)")),
    }
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
