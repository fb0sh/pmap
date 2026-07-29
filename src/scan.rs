use std::io::Write;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::cli::Args;
use crate::engine::connect::ConnectEngine;
use crate::engine::traits::{LocalError, ProbeTaskResult, ScanEngine};
use crate::model::reducer::StateReducer;
use crate::model::result::Summary;
use crate::model::PortState;
use crate::output::filter::FilterMode;
use crate::output::terminal;
use crate::port::parse_ports;
use crate::target::Target;

/// Run a scan based on CLI args.
pub async fn run_scan(args: &Args) -> anyhow::Result<()> {
    // 1. Parse targets
    let mut raw_targets: Vec<String> = args.targets.clone();
    if let Some(ref file) = args.input_file {
        let content = std::fs::read_to_string(file)?;
        let file_targets = crate::target::resolve_input_file(&content)?;
        for t in file_targets {
            raw_targets.push(t.to_string());
        }
    }

    if raw_targets.is_empty() {
        eprintln!("pmap: no targets specified");
        std::process::exit(1);
    }

    let targets = crate::target::parse_targets(&raw_targets)?;

    // 2. Resolve targets to hosts
    let mut hosts: Vec<IpAddr> = Vec::new();
    let mut hosts_failed = 0u64;
    for target in &targets {
        match target {
            Target::Ip(s) => {
                if let Ok(ip) = s.parse::<IpAddr>() {
                    hosts.push(ip);
                } else {
                    hosts_failed += 1;
                }
            }
            Target::Cidr(s) => {
                let parts: Vec<&str> = s.split('/').collect();
                let base: std::net::Ipv4Addr = parts[0].parse()?;
                let prefix: u8 = parts[1].parse()?;
                if prefix >= 24 {
                    let base_u32 = u32::from(base);
                    let host_bits = 32 - prefix;
                    let count = 1u32 << host_bits;
                    let mask = !0u32 << host_bits;
                    for i in 0..count {
                        let ip = base_u32 & mask | i;
                        hosts.push(IpAddr::V4(std::net::Ipv4Addr::from(ip)));
                    }
                } else {
                    let base_u32 = u32::from(base);
                    for i in 0..256u32 {
                        let ip = base_u32 & !0xFF | (i & 0xFF);
                        hosts.push(IpAddr::V4(std::net::Ipv4Addr::from(ip)));
                    }
                }
            }
            Target::Hostname(s) => {
                match tokio::net::lookup_host(format!("{s}:0")).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            hosts.push(addr.ip());
                        }
                    }
                    Err(_) => {
                        hosts_failed += 1;
                        eprintln!("pmap: failed to resolve {s}");
                    }
                }
            }
        }
    }

    // Deduplicate hosts
    hosts.sort();
    hosts.dedup();

    if hosts.is_empty() {
        eprintln!("pmap: no valid targets could be resolved");
        std::process::exit(2);
    }

    // 3. Parse ports
    let ports = if args.all_ports {
        (1..=65535u16).collect::<Vec<u16>>()
    } else if let Some(ref spec) = args.ports {
        parse_ports(spec)?
    } else {
        // Default: common ports
        vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
            3389, 5900, 8080, 8443,
        ]
    };

    // 4. Probe all host:port combinations
    let total_probes = hosts.len() as u64 * ports.len() as u64;
    let probe_limit: u64 = 100_000_000;
    if total_probes > probe_limit {
        eprintln!("pmap: too many probes ({total_probes}), limit is {probe_limit}");
        std::process::exit(1);
    }

    let engine = ConnectEngine {
        connect_timeout: Duration::from_secs(3),
    };

    let mut reducer = StateReducer::new();
    let mut _open_count = 0u64;
    let start = Instant::now();
    let mut completed = 0u64;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    eprintln!(
        "Scanning {} host(s) × {} port(s) = {} probes",
        hosts.len(),
        ports.len(),
        total_probes
    );

    for host in &hosts {
        for &port in &ports {
            let result = engine.probe(*host, port).await;

            match result {
                ProbeTaskResult::Evidence(evidence) => {
                    reducer.apply_evidence(*host, port, &evidence);

                    if let Some(pr) = reducer.get_result(*host, port) {
                        if matches!(pr.state, PortState::Open) {
                            _open_count += 1;
                            terminal::write_realtime(&mut out, &pr);
                            out.flush().unwrap();
                        }
                    }
                }
                ProbeTaskResult::LocalError(LocalError::ResourceExhausted) => {
                    eprintln!("pmap: local resource exhaustion, reducing concurrency");
                }
                ProbeTaskResult::LocalError(LocalError::PermissionDenied) => {
                    eprintln!("pmap: permission denied on {host}:{port}");
                }
                ProbeTaskResult::LocalError(LocalError::Other(msg)) => {
                    eprintln!("pmap: local error on {host}:{port}: {msg}");
                }
                ProbeTaskResult::Cancelled => {
                    break;
                }
            }

            completed += 1;
        }
    }

    let elapsed = start.elapsed();

    // 5. Build final results from reducer
    let mut summary = Summary::default();
    summary.hosts_requested = raw_targets.len() as u64;
    summary.hosts_resolved = hosts.len() as u64;
    summary.hosts_failed = hosts_failed;
    summary.ports_selected = ports.len() as u64;
    summary.probes_planned = total_probes;
    summary.probes_completed = completed;
    summary.completed = true;
    summary.elapsed_ms = elapsed.as_millis() as u64;

    // Count states from reducer
    for host in &hosts {
        for &port in &ports {
            if let Some(pr) = reducer.get_result(*host, port) {
                match pr.state {
                    PortState::Open => summary.open += 1,
                    PortState::Closed => summary.closed += 1,
                    PortState::Filtered => summary.filtered += 1,
                    PortState::Unreachable => summary.unreachable += 1,
                    PortState::Unknown => summary.unknown += 1,
                    PortState::Pending => {}
                }
            }
        }
    }

    let scan_result = reducer.into_scan_result(summary);

    // 6. Write final output
    writeln!(&mut out).unwrap();
    terminal::write_final(&mut out, &scan_result, FilterMode::Default);

    Ok(())
}
