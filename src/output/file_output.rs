use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;

use crate::model::result::ScanResult;
use crate::model::PortState;

use super::filter::{filter_results, FilterMode};

/// Format RTT for plain text output (no ANSI).
fn fmt_rtt(rtt: Option<Duration>) -> String {
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

/// State name for output.
fn state_name(state: PortState) -> &'static str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::Unreachable => "unreachable",
        PortState::Unknown => "unknown",
        PortState::Pending => "pending",
    }
}

/// Confidence name for output.
fn confidence_name(confidence: crate::model::Confidence) -> &'static str {
    match confidence {
        crate::model::Confidence::Confirmed => "confirmed",
        crate::model::Confidence::High => "high",
        crate::model::Confidence::Medium => "medium",
        crate::model::Confidence::Low => "low",
    }
}

// ─── -oN: Plain text output ────────────────────────────────────────────────

/// Write -oN plain text output: no ANSI, no `*` prefix, same filtering as terminal.
pub fn write_output_normal(
    path: &str,
    scan_result: &ScanResult,
    mode: FilterMode,
) -> anyhow::Result<()> {
    let filtered = filter_results(scan_result, mode);
    let mut f = std::fs::File::create(path)?;

    // Detail lines (no * prefix)
    for r in &filtered {
        writeln!(
            f,
            "{ip}\t{port}/tcp\t{state}\t{confidence}\t{rtt}",
            ip = r.host,
            port = r.port,
            state = state_name(r.state),
            confidence = confidence_name(r.confidence),
            rtt = fmt_rtt(r.best_rtt),
        )?;
    }

    // Unknown compressed ranges (no * prefix)
    if matches!(mode, FilterMode::Default) {
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
                writeln!(f, "{host}\tunknown\t{ranges}", host = entry.host, ranges = ranges_str.join(","))?;
            }
        }
    }

    // Summary (always complete, not filtered)
    writeln!(f)?;
    writeln!(f, "# complete results (sorted)")?;
    writeln!(f)?;
    let s = &scan_result.summary;
    writeln!(f, "# hosts: {}", s.hosts_resolved)?;
    writeln!(f, "# ports: {}", s.ports_selected)?;
    writeln!(f, "# open: {}", s.open)?;
    writeln!(f, "# closed: {}", s.closed)?;
    writeln!(f, "# filtered: {}", s.filtered)?;
    writeln!(f, "# unreachable: {}", s.unreachable)?;
    writeln!(f, "# unknown: {}", s.unknown)?;
    writeln!(f, "# elapsed: {:.1}s", s.elapsed_ms as f64 / 1000.0)?;

    Ok(())
}

// ─── -oJ: JSON output ──────────────────────────────────────────────────────

/// Port set info for JSON output.
#[derive(Debug, Clone)]
pub struct PortSetInfo {
    pub kind: &'static str, // "explicit" or "default"
    pub value: String,
}

/// Write -oJ JSON output with atomic temp→rename.
pub fn write_output_json(
    path: &str,
    scan_result: &ScanResult,
    mode: FilterMode,
    scan_type: &str,
    timing_template: u8,
    started_at: &str,
    completed_at: &str,
    port_set: &PortSetInfo,
) -> anyhow::Result<()> {
    let filtered = filter_results(scan_result, mode);

    // Build results array
    let results_json: Vec<serde_json::Value> = filtered
        .iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "ip": r.host.to_string(),
                "port": r.port,
                "protocol": "tcp",
                "state": state_name(r.state),
                "confidence": confidence_name(r.confidence),
            });
            if let Some(rtt) = r.best_rtt {
                obj["rtt_ms"] = serde_json::json!((rtt.as_secs_f64() * 1000.0).round() as u64);
            }
            obj
        })
        .collect();

    // Build unknown array
    let unknown_json: Vec<serde_json::Value> = scan_result
        .unknown
        .iter()
        .map(|u| {
            serde_json::json!({
                "ip": u.host.to_string(),
                "protocol": "tcp",
                "ranges": u.ranges,
            })
        })
        .collect();

    let s = &scan_result.summary;

    let json = serde_json::json!({
        "schema_version": 1,
        "scanner": {
            "name": "pmap",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "scan": {
            "type": scan_type,
            "timing_template": timing_template,
            "completed": s.completed,
            "partial_failures": s.partial_failures,
            "started_at": started_at,
            "completed_at": completed_at,
            "elapsed_ms": s.elapsed_ms,
            "open_only": matches!(mode, FilterMode::OpenOnly),
            "port_set": {
                "kind": port_set.kind,
                "value": port_set.value,
            },
        },
        "targets": {
            "requested": s.hosts_requested,
            "resolved": s.hosts_resolved,
            "failed": s.hosts_failed,
        },
        "results": results_json,
        "unknown": unknown_json,
        "summary": {
            "hosts_requested": s.hosts_requested,
            "hosts_resolved": s.hosts_resolved,
            "hosts_failed": s.hosts_failed,
            "ports_selected": s.ports_selected,
            "probes_planned": s.probes_planned,
            "probes_completed": s.probes_completed,
            "open": s.open,
            "closed": s.closed,
            "filtered": s.filtered,
            "unreachable": s.unreachable,
            "unknown": s.unknown,
            "not_scanned": s.not_scanned,
            "local_errors": s.local_errors,
        },
    });

    // Atomic write: temp → rename
    let temp_path = format!("{path}.tmp.{pid}", pid = std::process::id());
    {
        let mut f = std::fs::File::create(&temp_path)?;
        serde_json::to_writer_pretty(&mut f, &json)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&temp_path, path)?;

    Ok(())
}

// ─── -oJL: JSON Lines streaming output ─────────────────────────────────────

/// Write -oJL scan_started event.
pub fn write_jsonl_scan_started(
    w: &mut impl Write,
    scan_type: &str,
    timing_template: u8,
    started_at: &str,
    hosts: &[IpAddr],
    ports_count: usize,
    open_only: bool,
    port_set: &PortSetInfo,
) -> anyhow::Result<()> {
    let event = serde_json::json!({
        "type": "scan_started",
        "scan_type": scan_type,
        "timing_template": timing_template,
        "started_at": started_at,
        "hosts": hosts.len(),
        "ports": ports_count,
        "open_only": open_only,
        "port_set": {
            "kind": port_set.kind,
            "value": port_set.value,
        },
    });
    serde_json::to_writer(&mut *w, &event)?;
    writeln!(w)?;
    Ok(())
}

/// Write -oJL port_event line.
pub fn write_jsonl_port_event(
    w: &mut impl Write,
    result: &crate::model::result::ProbeResult,
) -> anyhow::Result<()> {
    let mut event = serde_json::json!({
        "type": "port_event",
        "ip": result.host.to_string(),
        "port": result.port,
        "protocol": "tcp",
        "state": state_name(result.state),
        "confidence": confidence_name(result.confidence),
    });
    if let Some(rtt) = result.best_rtt {
        event["rtt_ms"] = serde_json::json!((rtt.as_secs_f64() * 1000.0).round() as u64);
    }
    serde_json::to_writer(&mut *w, &event)?;
    writeln!(w)?;
    Ok(())
}

/// Write -oJL scan_completed event.
pub fn write_jsonl_scan_completed(
    w: &mut impl Write,
    scan_result: &ScanResult,
    completed_at: &str,
) -> anyhow::Result<()> {
    let s = &scan_result.summary;
    let event = serde_json::json!({
        "type": "scan_completed",
        "completed_at": completed_at,
        "elapsed_ms": s.elapsed_ms,
        "completed": s.completed,
        "hosts_resolved": s.hosts_resolved,
        "hosts_failed": s.hosts_failed,
        "ports_selected": s.ports_selected,
        "probes_completed": s.probes_completed,
        "open": s.open,
        "closed": s.closed,
        "filtered": s.filtered,
        "unreachable": s.unreachable,
        "unknown": s.unknown,
        "not_scanned": s.not_scanned,
        "local_errors": s.local_errors,
    });
    serde_json::to_writer(&mut *w, &event)?;
    writeln!(w)?;
    Ok(())
}

/// Write -oJL scan_completed to a file path (creates/truncates).
pub fn write_jsonl_scan_completed_to_file(
    path: &str,
    scan_result: &ScanResult,
    completed_at: &str,
) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(path)?;
    write_jsonl_scan_completed(&mut f, scan_result, completed_at)
}
