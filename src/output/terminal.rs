use std::io::Write;

use crate::model::result::ScanResult;

use super::filter::{FilterMode, filter_results};

/// Format RTT for display.
fn fmt_rtt(rtt: Option<std::time::Duration>) -> String {
    match rtt {
        None => "-".to_string(),
        Some(d) => {
            let ms = d.as_secs_f64() * 1000.0;
            if ms < 1.0 {
                format!("{:.1}ms", ms)
            } else if ms >= 1000.0 {
                format!("{:.2}s", ms / 1000.0)
            } else {
                format!("{}ms", ms as u64)
            }
        }
    }
}

/// Write a single probe result line to the writer.
fn write_line(w: &mut impl Write, ip: &str, port: u16, state: &str, confidence: &str, rtt: &str) {
    let _ = writeln!(
        w,
        "{ip:<15} {port:>5}/tcp   {state:<8} {confidence:<10} {rtt}"
    );
}

/// Write a prefixed probe result line (used for final output).
fn write_prefixed_line(
    w: &mut impl Write,
    prefix: &str,
    ip: &str,
    port: u16,
    state: &str,
    confidence: &str,
    rtt: &str,
) {
    let _ = writeln!(
        w,
        "{prefix}{ip:<15} {port:>5}/tcp   {state:<8} {confidence:<10} {rtt}"
    );
}

/// Write real-time output for a newly discovered open port.
pub fn write_realtime(w: &mut impl Write, result: &crate::model::result::ProbeResult, mode: &FilterMode) {
    if mode.includes(result.state) {
        write_line(
            w,
            &result.host.to_string(),
            result.port,
            &format!("{:?}", result.state).to_lowercase(),
            &format!("{:?}", result.confidence).to_lowercase(),
            &fmt_rtt(result.best_rtt),
        );
    }
}

/// Write the final sorted output to stdout.
pub fn write_final(w: &mut impl Write, scan_result: &ScanResult, mode: &FilterMode) {
    let filtered = filter_results(scan_result, mode);

    // Write summary header
    writeln!(w).unwrap();
    writeln!(w, "# complete results (sorted)").unwrap();
    writeln!(w).unwrap();

    // Write sorted detail lines with * prefix
    for r in &filtered {
        write_prefixed_line(
            w,
            "* ",
            &r.host.to_string(),
            r.port,
            &format!("{:?}", r.state).to_lowercase(),
            &format!("{:?}", r.confidence).to_lowercase(),
            &fmt_rtt(r.best_rtt),
        );
    }

    // Write unknown compressed ranges
    if mode.unknown {
        for entry in &scan_result.unknown {
            let ranges_str: Vec<String> = entry
                .ranges
                .iter()
                .map(|(start, end)| {
                    if start == end {
                        start.to_string()
                    } else {
                        format!("{start}-{end}")
                    }
                })
                .collect();
            if !ranges_str.is_empty() {
                writeln!(
                    w,
                    "* {:<15} unknown     {}",
                    entry.host,
                    ranges_str.join(",")
                )
                .unwrap();
            }
        }
    }

    // Write summary stats
    writeln!(w).unwrap();
    let s = &scan_result.summary;
    writeln!(w, "# hosts: {}", s.hosts_resolved).unwrap();
    writeln!(w, "# ports: {}", s.ports_selected).unwrap();
    writeln!(w, "# open: {}", s.open).unwrap();
    writeln!(w, "# closed: {}", s.closed).unwrap();
    writeln!(w, "# filtered: {}", s.filtered).unwrap();
    writeln!(w, "# unreachable: {}", s.unreachable).unwrap();
    writeln!(w, "# unknown: {}", s.unknown).unwrap();
    if s.not_scanned > 0 {
        writeln!(w, "# not_scanned: {}", s.not_scanned).unwrap();
    }
    writeln!(w, "# elapsed: {:.1}s", s.elapsed_ms as f64 / 1000.0).unwrap();
}
