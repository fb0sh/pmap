use clap::Parser;
use pmap::cli::Args;

#[test]
fn parse_help_short() {
    let result = Args::try_parse_from(["pmap", "-h"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn parse_version() {
    let result = Args::try_parse_from(["pmap", "-V"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn parse_single_target() {
    let args = Args::try_parse_from(["pmap", "192.168.1.1"]).unwrap();
    assert_eq!(args.targets, vec!["192.168.1.1"]);
}

#[test]
fn parse_multiple_targets() {
    let args = Args::try_parse_from(["pmap", "192.168.1.1", "192.168.1.2", "10.0.0.1"]).unwrap();
    assert_eq!(args.targets, vec!["192.168.1.1", "192.168.1.2", "10.0.0.1"]);
}

#[test]
fn parse_cidr_target() {
    let args = Args::try_parse_from(["pmap", "192.168.1.0/24"]).unwrap();
    assert_eq!(args.targets, vec!["192.168.1.0/24"]);
}

#[test]
fn parse_hostname_target() {
    let args = Args::try_parse_from(["pmap", "example.com"]).unwrap();
    assert_eq!(args.targets, vec!["example.com"]);
}

#[test]
fn parse_syn_scan() {
    let args = Args::try_parse_from(["pmap", "--syn", "192.168.1.1"]).unwrap();
    assert!(args.syn_scan);
    assert!(!args.connect_scan);
}

#[test]
fn parse_connect_scan() {
    let args = Args::try_parse_from(["pmap", "--connect", "192.168.1.1"]).unwrap();
    assert!(!args.syn_scan);
    assert!(args.connect_scan);
}

#[test]
fn parse_default_scan_type() {
    let args = Args::try_parse_from(["pmap", "192.168.1.1"]).unwrap();
    assert!(!args.syn_scan);
    assert!(!args.connect_scan);
}

#[test]
fn syn_and_connect_mutually_exclusive() {
    let result = Args::try_parse_from(["pmap", "--syn", "--connect", "192.168.1.1"]);
    assert!(result.is_err());
}

#[test]
fn parse_port_single() {
    let args = Args::try_parse_from(["pmap", "-p", "443", "192.168.1.1"]).unwrap();
    assert_eq!(args.ports, Some("443".to_string()));
}

#[test]
fn parse_port_multiple() {
    let args = Args::try_parse_from(["pmap", "-p", "22,80,443", "192.168.1.1"]).unwrap();
    assert_eq!(args.ports, Some("22,80,443".to_string()));
}

#[test]
fn parse_port_range() {
    let args = Args::try_parse_from(["pmap", "-p", "1-1024", "192.168.1.1"]).unwrap();
    assert_eq!(args.ports, Some("1-1024".to_string()));
}

#[test]
fn parse_port_all() {
    let args = Args::try_parse_from(["pmap", "-P", "192.168.1.1"]).unwrap();
    assert!(args.all_ports);
}

#[test]
fn parse_input_file() {
    let args = Args::try_parse_from(["pmap", "-i", "targets.txt", "192.168.1.1"]).unwrap();
    assert_eq!(args.input_file, Some("targets.txt".to_string()));
}

#[test]
fn parse_timing_template() {
    let args = Args::try_parse_from(["pmap", "-T", "5", "192.168.1.1"]).unwrap();
    assert_eq!(args.timing, Some(5));
}

#[test]
fn parse_default_timing() {
    let args = Args::try_parse_from(["pmap", "192.168.1.1"]).unwrap();
    assert_eq!(args.timing, None);
}

#[test]
fn parse_open_only() {
    let args = Args::try_parse_from(["pmap", "--open", "192.168.1.1"]).unwrap();
    assert!(args.open_only);
}

#[test]
fn parse_output_normal_long() {
    let args = Args::try_parse_from(["pmap", "--output-normal", "scan.txt", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_normal, Some("scan.txt".to_string()));
}

#[test]
fn parse_output_normal_alias() {
    let args = Args::try_parse_from(["pmap", "--oN", "scan.txt", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_normal, Some("scan.txt".to_string()));
}

#[test]
fn parse_output_json_long() {
    let args = Args::try_parse_from(["pmap", "--output-json", "scan.json", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_json, Some("scan.json".to_string()));
}

#[test]
fn parse_output_json_alias() {
    let args = Args::try_parse_from(["pmap", "--oJ", "scan.json", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_json, Some("scan.json".to_string()));
}

#[test]
fn parse_output_jsonl_long() {
    let args = Args::try_parse_from(["pmap", "--output-jsonl", "scan.jsonl", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_jsonl, Some("scan.jsonl".to_string()));
}

#[test]
fn parse_output_jsonl_alias() {
    let args = Args::try_parse_from(["pmap", "--oJL", "scan.jsonl", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_jsonl, Some("scan.jsonl".to_string()));
}

#[test]
fn parse_output_all_long() {
    let args = Args::try_parse_from(["pmap", "--output-all", "scan", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_all, Some("scan".to_string()));
}

#[test]
fn parse_output_all_alias() {
    let args = Args::try_parse_from(["pmap", "--oA", "scan", "192.168.1.1"]).unwrap();
    assert_eq!(args.output_all, Some("scan".to_string()));
}

#[test]
fn parse_combined_output() {
    let args = Args::try_parse_from([
        "pmap",
        "--output-normal", "scan.txt",
        "--output-json", "scan.json",
        "192.168.1.1",
    ]).unwrap();
    assert_eq!(args.output_normal, Some("scan.txt".to_string()));
    assert_eq!(args.output_json, Some("scan.json".to_string()));
}

// Note: clap allows zero targets (Vec<String>).
// Validation of "at least one target" belongs at a higher layer.
#[test]
fn missing_targets_is_allowed_by_clap() {
    let args = Args::try_parse_from(["pmap"]).unwrap();
    assert!(args.targets.is_empty());
}

#[test]
fn parse_mixed_targets_and_input_file() {
    let args = Args::try_parse_from(["pmap", "192.168.1.1", "-i", "targets.txt"]).unwrap();
    assert_eq!(args.targets, vec!["192.168.1.1"]);
    assert_eq!(args.input_file, Some("targets.txt".to_string()));
}
