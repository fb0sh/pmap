use portmap::target::{parse_targets, resolve_input_file, Target};

#[test]
fn parse_single_ip() {
    let targets = parse_targets(&["192.168.1.1".to_string()]).unwrap();
    assert_eq!(targets, vec![Target::Ip("192.168.1.1".to_string())]);
}

#[test]
fn parse_multiple_ips() {
    let targets = parse_targets(&[
        "192.168.1.1".to_string(),
        "10.0.0.1".to_string(),
    ]).unwrap();
    assert_eq!(targets.len(), 2);
}

#[test]
fn parse_cidr() {
    let targets = parse_targets(&["192.168.1.0/30".to_string()]).unwrap();
    assert_eq!(targets.len(), 1);
    assert!(matches!(&targets[0], Target::Cidr(c) if c == "192.168.1.0/30"));
}

#[test]
fn parse_hostname() {
    let targets = parse_targets(&["example.com".to_string()]).unwrap();
    assert_eq!(targets, vec![Target::Hostname("example.com".to_string())]);
}

#[test]
fn parse_mixed() {
    let targets = parse_targets(&[
        "192.168.1.1".to_string(),
        "10.0.0.0/28".to_string(),
        "example.com".to_string(),
    ]).unwrap();
    assert_eq!(targets.len(), 3);
}

#[test]
fn empty_input_errors() {
    let result = parse_targets(&[]);
    assert!(result.is_err());
}

#[test]
fn resolve_input_file_basic() {
    let content = "192.168.1.1\n10.0.0.1\n";
    let targets = resolve_input_file(content).unwrap();
    assert_eq!(targets.len(), 2);
}

#[test]
fn resolve_input_file_skips_empty_lines() {
    let content = "192.168.1.1\n\n\n10.0.0.1\n";
    let targets = resolve_input_file(content).unwrap();
    assert_eq!(targets.len(), 2);
}

#[test]
fn resolve_input_file_skips_comments() {
    let content = "# comment\n192.168.1.1\n# another comment\n10.0.0.1\n";
    let targets = resolve_input_file(content).unwrap();
    assert_eq!(targets.len(), 2);
}

#[test]
fn resolve_input_file_mixed() {
    let content = "192.168.1.1\n10.0.0.0/28\nexample.com\n";
    let targets = resolve_input_file(content).unwrap();
    assert_eq!(targets.len(), 3);
}

#[test]
fn resolve_input_file_trims_whitespace() {
    let content = "  192.168.1.1  \n  10.0.0.1  \n";
    let targets = resolve_input_file(content).unwrap();
    assert_eq!(targets.len(), 2);
}
