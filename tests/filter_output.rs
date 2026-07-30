use std::time::Duration;

use portmap::model::PortState;
use portmap::model::confidence::Confidence;
use portmap::model::result::{ProbeResult, Protocol, ScanResult, Summary, UnknownEntry};
use portmap::output::file_output;
use portmap::output::filter::{FilterMode, filter_results};

/// Helper to build a ScanResult fixture.
fn make_scan_result() -> ScanResult {
    let results = vec![
        ProbeResult {
            host: "192.168.1.1".parse().unwrap(),
            port: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            confidence: Confidence::Confirmed,
            best_rtt: Some(Duration::from_millis(5)),
        },
        ProbeResult {
            host: "192.168.1.1".parse().unwrap(),
            port: 80,
            protocol: Protocol::Tcp,
            state: PortState::Closed,
            confidence: Confidence::Confirmed,
            best_rtt: None,
        },
        ProbeResult {
            host: "192.168.1.1".parse().unwrap(),
            port: 443,
            protocol: Protocol::Tcp,
            state: PortState::Filtered,
            confidence: Confidence::High,
            best_rtt: None,
        },
        ProbeResult {
            host: "192.168.1.2".parse().unwrap(),
            port: 22,
            protocol: Protocol::Tcp,
            state: PortState::Unknown,
            confidence: Confidence::Low,
            best_rtt: None,
        },
        ProbeResult {
            host: "192.168.1.2".parse().unwrap(),
            port: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            confidence: Confidence::High,
            best_rtt: Some(Duration::from_millis(12)),
        },
        ProbeResult {
            host: "192.168.1.2".parse().unwrap(),
            port: 999,
            protocol: Protocol::Tcp,
            state: PortState::Unreachable,
            confidence: Confidence::High,
            best_rtt: None,
        },
    ];

    let unknown = vec![UnknownEntry {
        host: "192.168.1.3".parse().unwrap(),
        protocol: Protocol::Tcp,
        ranges: vec![(1, 21), (23, 79)],
    }];

    let summary = Summary {
        hosts_requested: 2,
        hosts_resolved: 2,
        hosts_failed: 0,
        ports_selected: 6,
        probes_planned: 12,
        probes_completed: 12,
        open: 2,
        closed: 1,
        filtered: 1,
        unreachable: 1,
        unknown: 1,
        not_scanned: 0,
        local_errors: 0,
        completed: true,
        partial_failures: false,
        elapsed_ms: 5000,
    };

    ScanResult {
        results,
        unknown,
        summary,
    }
}

// ─── Filter tests ──────────────────────────────────────────────────────────

#[test]
fn filter_default_shows_open_filtered_unknown() {
    let sr = make_scan_result();
    let filtered = filter_results(&sr, &FilterMode::default_filter());

    // Open (22@192.168.1.1, 80@192.168.1.2) + Filtered (443@192.168.1.1) + Unknown (22@192.168.1.2)
    assert_eq!(filtered.len(), 4);

    let states: Vec<PortState> = filtered.iter().map(|r| r.state).collect();
    assert!(states.contains(&PortState::Open));
    assert!(states.contains(&PortState::Filtered));
    assert!(states.contains(&PortState::Unknown));
    // Closed and Unreachable should NOT appear
    assert!(!states.contains(&PortState::Closed));
    assert!(!states.contains(&PortState::Unreachable));
}

#[test]
fn filter_open_only_shows_only_open() {
    let sr = make_scan_result();
    let filtered = filter_results(
        &sr,
        &FilterMode {
            open: true,
            closed: false,
            filtered: false,
            unknown: false,
        },
    );

    assert_eq!(filtered.len(), 2);
    for r in &filtered {
        assert_eq!(r.state, PortState::Open);
    }
}

#[test]
fn filter_open_only_excludes_filtered() {
    let sr = make_scan_result();
    let filtered = filter_results(
        &sr,
        &FilterMode {
            open: true,
            closed: false,
            filtered: false,
            unknown: false,
        },
    );
    assert!(!filtered.iter().any(|r| r.state == PortState::Filtered));
}

#[test]
fn filter_open_only_excludes_unknown() {
    let sr = make_scan_result();
    let filtered = filter_results(
        &sr,
        &FilterMode {
            open: true,
            closed: false,
            filtered: false,
            unknown: false,
        },
    );
    assert!(!filtered.iter().any(|r| r.state == PortState::Unknown));
}

#[test]
fn summary_always_complete_regardless_of_filter_mode() {
    let sr = make_scan_result();

    // Even with OpenOnly filter, summary counts remain unchanged
    let _ = filter_results(
        &sr,
        &FilterMode {
            open: true,
            closed: false,
            filtered: false,
            unknown: false,
        },
    );
    assert_eq!(sr.summary.open, 2);
    assert_eq!(sr.summary.closed, 1);
    assert_eq!(sr.summary.filtered, 1);
    assert_eq!(sr.summary.unreachable, 1);
    assert_eq!(sr.summary.unknown, 1);
    assert_eq!(sr.summary.hosts_resolved, 2);
    assert_eq!(sr.summary.ports_selected, 6);
}

// ─── -oN tests ─────────────────────────────────────────────────────────────

#[test]
fn output_normal_creates_valid_file() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_on");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.txt");

    file_output::write_output_normal(path.to_str().unwrap(), &sr, &FilterMode::default_filter())
        .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("192.168.1.1"));
    assert!(content.contains("22/tcp"));
    assert!(content.contains("open"));
    // Summary present
    assert!(content.contains("# complete results (sorted)"));
    assert!(content.contains("# open: 2"));
    assert!(content.contains("# closed: 1"));
    assert!(content.contains("# filtered: 1"));
    assert!(content.contains("# unreachable: 1"));
    assert!(content.contains("# unknown: 1"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_normal_open_only_filter() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_on_open");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.txt");

    file_output::write_output_normal(
        path.to_str().unwrap(),
        &sr,
        &FilterMode {
            open: true,
            closed: false,
            filtered: false,
            unknown: false,
        },
    )
    .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    // Only open ports in detail lines
    let lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    for line in &lines {
        assert!(line.contains("open"), "non-open in --open output: {line}");
    }
    // Summary still shows all counts
    assert!(content.contains("# closed: 1"));
    assert!(content.contains("# filtered: 1"));
    assert!(content.contains("# unreachable: 1"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_normal_no_ansi_no_prefix() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_on_clean");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.txt");

    file_output::write_output_normal(path.to_str().unwrap(), &sr, &FilterMode::default_filter())
        .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(!content.contains('\x1b'), "ANSI escape found in -oN output");
    // No * prefix
    for line in content.lines() {
        if !line.starts_with('#') && !line.is_empty() {
            assert!(
                !line.starts_with("* "),
                "unexpected * prefix in -oN: {line}"
            );
        }
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_normal_unknown_compression() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_on_unknown");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.txt");

    file_output::write_output_normal(path.to_str().unwrap(), &sr, &FilterMode::default_filter())
        .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("192.168.1.3"));
    assert!(content.contains("unknown"));
    assert!(content.contains("1-21"));
    assert!(content.contains("23-79"));

    std::fs::remove_dir_all(&dir).unwrap();
}

// ─── -oJ tests ─────────────────────────────────────────────────────────────

#[test]
fn output_json_creates_valid_json() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_oj");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.json");

    file_output::write_output_json(
        path.to_str().unwrap(),
        &sr,
        &FilterMode::default_filter(),
        "connect",
        3,
        "2025-01-01T00:00:00.000Z",
        "2025-01-01T00:00:05.000Z",
        &file_output::PortSetInfo {
            kind: "explicit",
            value: "22,80,443,999".to_string(),
        },
    )
    .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Schema version
    assert_eq!(json["schema_version"], 1);

    // Scanner info
    assert_eq!(json["scanner"]["name"], "pmap");

    // Scan metadata
    assert_eq!(json["scan"]["type"], "connect");
    assert_eq!(json["scan"]["timing_template"], 3);
    assert_eq!(json["scan"]["completed"], true);
    assert_eq!(json["scan"]["open_only"], false);

    // Targets
    assert_eq!(json["targets"]["requested"], 2);
    assert_eq!(json["targets"]["resolved"], 2);

    // Results
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 4); // open + filtered + unknown (not closed/unreachable)

    // Summary
    assert_eq!(json["summary"]["open"], 2);
    assert_eq!(json["summary"]["closed"], 1);
    assert_eq!(json["summary"]["filtered"], 1);
    assert_eq!(json["summary"]["unreachable"], 1);
    assert_eq!(json["summary"]["unknown"], 1);

    // Unknown
    let unknown = json["unknown"].as_array().unwrap();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0]["ip"], "192.168.1.3");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_json_open_only_filter() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_oj_open");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.json");

    file_output::write_output_json(
        path.to_str().unwrap(),
        &sr,
        &FilterMode {
            open: true,
            closed: false,
            filtered: false,
            unknown: false,
        },
        "connect",
        3,
        "2025-01-01T00:00:00.000Z",
        "2025-01-01T00:00:05.000Z",
        &file_output::PortSetInfo {
            kind: "explicit",
            value: "22,80".to_string(),
        },
    )
    .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["scan"]["open_only"], true);

    // Only open results
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    for r in results {
        assert_eq!(r["state"], "open");
    }

    // Summary still shows all counts
    assert_eq!(json["summary"]["closed"], 1);
    assert_eq!(json["summary"]["filtered"], 1);
    assert_eq!(json["summary"]["unreachable"], 1);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_json_atomic_write() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_oj_atomic");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.json");

    file_output::write_output_json(
        path.to_str().unwrap(),
        &sr,
        &FilterMode::default_filter(),
        "connect",
        3,
        "2025-01-01T00:00:00.000Z",
        "2025-01-01T00:00:05.000Z",
        &file_output::PortSetInfo {
            kind: "default",
            value: "default".to_string(),
        },
    )
    .unwrap();

    // No .tmp file should remain
    let temp_path = format!("{}.tmp", path.to_str().unwrap());
    assert!(!std::path::Path::new(&temp_path).exists());

    // File should be valid JSON
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&content).is_ok());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_json_has_rtt_ms() {
    let sr = make_scan_result();
    let dir = std::env::temp_dir().join("pmap_test_oj_rtt");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.json");

    file_output::write_output_json(
        path.to_str().unwrap(),
        &sr,
        &FilterMode::default_filter(),
        "connect",
        3,
        "2025-01-01T00:00:00.000Z",
        "2025-01-01T00:00:05.000Z",
        &file_output::PortSetInfo {
            kind: "default",
            value: "default".to_string(),
        },
    )
    .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Port 22@192.168.1.1 has rtt 5ms
    let r22 = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ip"] == "192.168.1.1" && r["port"] == 22)
        .unwrap();
    assert_eq!(r22["rtt_ms"], 5);

    std::fs::remove_dir_all(&dir).unwrap();
}
