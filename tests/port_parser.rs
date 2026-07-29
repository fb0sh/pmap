use portmap::port::parse_ports;

#[test]
fn parse_single_port() {
    let ports = parse_ports("443").unwrap();
    assert_eq!(ports, vec![443]);
}

#[test]
fn parse_multiple_ports() {
    let ports = parse_ports("22,80,443").unwrap();
    assert_eq!(ports, vec![22, 80, 443]);
}

#[test]
fn parse_port_range() {
    let ports = parse_ports("1-5").unwrap();
    assert_eq!(ports, vec![1, 2, 3, 4, 5]);
}

#[test]
fn parse_mixed() {
    let ports = parse_ports("22,80,443,8000-8002").unwrap();
    assert_eq!(ports, vec![22, 80, 443, 8000, 8001, 8002]);
}

#[test]
fn parse_all_ports() {
    let ports = parse_ports("-").unwrap();
    assert_eq!(ports.len(), 65535);
    assert_eq!(ports[0], 1);
    assert_eq!(ports[65534], 65535);
}

#[test]
fn parse_deduplicates() {
    let ports = parse_ports("22,80,22,443,80").unwrap();
    assert_eq!(ports, vec![22, 80, 443]);
}

#[test]
fn parse_sorted() {
    let ports = parse_ports("443,22,80").unwrap();
    assert_eq!(ports, vec![22, 80, 443]);
}

#[test]
fn invalid_port_zero() {
    let result = parse_ports("0");
    assert!(result.is_err());
}

#[test]
fn invalid_port_too_high() {
    let result = parse_ports("65536");
    assert!(result.is_err());
}

#[test]
fn invalid_range() {
    let result = parse_ports("100-50");
    assert!(result.is_err());
}

#[test]
fn invalid_non_numeric() {
    let result = parse_ports("abc");
    assert!(result.is_err());
}

#[test]
fn empty_string() {
    let result = parse_ports("");
    assert!(result.is_err());
}
