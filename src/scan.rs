use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::cli::Args;
use crate::engine::connect::ConnectEngine;
use crate::engine::traits::{LocalError, ProbeTaskResult, ScanEngine};
use crate::model::reducer::StateReducer;
use crate::model::result::Summary;
use crate::model::PortState;
use crate::output::filter::FilterMode;
use crate::output::file_output::{self, PortSetInfo};
use crate::output::terminal;
use crate::port::parse_ports;
use crate::scheduler::{ProbeTask, Scheduler, TimingPolicy};
use crate::target::Target;

/// Run a scan based on CLI args.
pub async fn run_scan(args: &Args) -> anyhow::Result<()> {
    // ── 1. Parse targets ────────────────────────────────────────────────────
    let mut raw_targets: Vec<String> = args.targets.clone();
    if let Some(file) = &args.input_file {
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

    // ── 2. Resolve targets to hosts ─────────────────────────────────────────
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
                if args.no_dns {
                    eprintln!("pmap: DNS resolution disabled, skipping {s}");
                    hosts_failed += 1;
                } else {
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
    }

    hosts.sort();
    hosts.dedup();

    if hosts.is_empty() {
        eprintln!("pmap: no valid targets could be resolved");
        std::process::exit(2);
    }

    // ── 3. Parse ports ──────────────────────────────────────────────────────
    let (ports, port_set) = if let Some(spec) = &args.ports {
        if spec == "-" {
            let ports: Vec<u16> = (1..=65535u16).collect();
            (
                ports,
                PortSetInfo {
                    kind: "explicit",
                    value: "1-65535".to_string(),
                },
            )
        } else {
            let ports = parse_ports(spec)?;
            let value = spec.clone();
            (
                ports,
                PortSetInfo {
                    kind: "explicit",
                    value,
                },
            )
        }
    } else {
        let ports = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
            3389, 5900, 8080, 8443,
        ];
        (
            ports,
            PortSetInfo {
                kind: "default",
                value: "default-21".to_string(),
            },
        )
    };

    // ── 4. Timing & scheduling ──────────────────────────────────────────────
    let timing = TimingPolicy::from_template(args.timing.unwrap_or(3));
    let total_probes = hosts.len() as u64 * ports.len() as u64;
    let probe_limit: u64 = 100_000_000;
    if total_probes > probe_limit {
        eprintln!("pmap: too many probes ({total_probes}), limit is {probe_limit}");
        std::process::exit(1);
    }

    let engine = ConnectEngine {
        connect_timeout: timing.connect_timeout,
    };
    let mut scheduler = Scheduler::new(hosts.clone(), ports.clone());

    // ── 5. Shutdown signal ──────────────────────────────────────────────────
    let interrupted = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    {
        let flag = interrupted.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\npmap: interrupt received, finishing in-flight probes...");
            flag.store(true, Ordering::SeqCst);
            let _ = shutdown_tx.send(true);
        });
    }

    // ── 6. Concurrency semaphores ───────────────────────────────────────────
    let global_sem = Arc::new(Semaphore::new(timing.max_concurrent_global));
    let active_hosts_sem = Arc::new(Semaphore::new(timing.max_active_hosts));
    let per_host_sems: HashMap<IpAddr, Arc<Semaphore>> = hosts
        .iter()
        .map(|h| {
            (
                *h,
                Arc::new(Semaphore::new(timing.max_concurrent_per_host)),
            )
        })
        .collect();

    // Track per-host in-flight count for active-hosts semaphore management
    let mut host_in_flight: HashMap<IpAddr, usize> = HashMap::new();
    // Store active-hosts permits so they're released when last probe to host completes.
    // Using a plain Vec; permits are dropped (releasing the semaphore) on drop.
    let mut host_permits: Vec<(IpAddr, tokio::sync::OwnedSemaphorePermit)> = Vec::new();

    // ── 7. Execute scan ─────────────────────────────────────────────────────
    let mut reducer = StateReducer::new();
    let mut join_set: JoinSet<(ProbeTask, ProbeTaskResult)> = JoinSet::new();
    let mut probes_completed = 0u64;
    let mut local_errors = 0u64;
    let start = Instant::now();
    let started_at = chrono_now_iso();

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let filter_mode = if args.open_only {
        FilterMode::OpenOnly
    } else {
        FilterMode::Default
    };

    // Open JSONL file for streaming if requested
    let mut jsonl_writer: Option<std::io::BufWriter<std::fs::File>> = None;
    if let Some(path) = &args.output_jsonl {
        let f = std::fs::File::create(path)?;
        let mut w = std::io::BufWriter::new(f);
        file_output::write_jsonl_scan_started(
            &mut w,
            "connect",
            args.timing.unwrap_or(3),
            &started_at,
            &hosts,
            ports.len(),
            args.open_only,
            &port_set,
        )?;
        jsonl_writer = Some(w);
    }

    eprintln!(
        "Scanning {} host(s) × {} port(s) = {} probes",
        hosts.len(),
        ports.len(),
        total_probes
    );

    // Per-host last-dispatch time for inter-probe delay
    let mut last_dispatch: HashMap<IpAddr, Instant> = HashMap::new();

    // ── Main scan loop ──────────────────────────────────────────────────────
    loop {
        // Dispatch as many tasks as semaphores allow
        while !scheduler.is_done() {
            if interrupted.load(Ordering::SeqCst) {
                break;
            }

            let task = scheduler.next_task().unwrap();

            // Acquire global semaphore permit (blocks until available)
            let global_permit = tokio::select! {
                permit = global_sem.clone().acquire_owned() => permit.unwrap(),
                _ = shutdown_rx.changed() => {
                    interrupted.store(true, Ordering::SeqCst);
                    break;
                }
            };

            // Acquire per-host semaphore permit
            let host_permit = tokio::select! {
                permit = per_host_sems[&task.host].clone().acquire_owned() => permit.unwrap(),
                _ = shutdown_rx.changed() => {
                    drop(global_permit);
                    interrupted.store(true, Ordering::SeqCst);
                    break;
                }
            };

            // Acquire active-hosts permit (only for first probe to this host)
            let in_flight = host_in_flight.entry(task.host).or_insert(0);
            let active_permit = if *in_flight == 0 {
                let permit = tokio::select! {
                    p = active_hosts_sem.clone().acquire_owned() => p.unwrap(),
                    _ = shutdown_rx.changed() => {
                        drop(host_permit);
                        drop(global_permit);
                        interrupted.store(true, Ordering::SeqCst);
                        break;
                    }
                };
                Some(permit)
            } else {
                None
            };
            *in_flight += 1;

            // Store active-hosts permit if we acquired one
            if let Some(permit) = active_permit {
                host_permits.push((task.host, permit));
            }

            // Per-host inter-probe delay
            if timing.inter_probe_delay > Duration::ZERO {
                if let Some(last) = last_dispatch.get(&task.host) {
                    let elapsed = last.elapsed();
                    if elapsed < timing.inter_probe_delay {
                        let delay = timing.inter_probe_delay - elapsed;
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {}
                            _ = shutdown_rx.changed() => {
                                interrupted.store(true, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                }
            }
            last_dispatch.insert(task.host, Instant::now());

            // Spawn probe task
            join_set.spawn(async move {
                let result = engine.probe(task.host, task.port).await;
                (task, result)
            });
        }

        // If nothing left to dispatch and nothing in flight, we're done
        if scheduler.is_done() && join_set.is_empty() {
            break;
        }

        // If interrupted and nothing in flight, drain remaining
        if interrupted.load(Ordering::SeqCst) && join_set.is_empty() {
            break;
        }

        // Wait for the next probe to complete
        match join_set.join_next().await {
            Some(Ok((task, probe_result))) => {
                probes_completed += 1;

                // Release per-host and active-hosts tracking
                if let Some(count) = host_in_flight.get_mut(&task.host) {
                    *count -= 1;
                    if *count == 0 {
                        host_permits.retain(|(h, _)| *h != task.host);
                    }
                }

                match probe_result {
                    ProbeTaskResult::Evidence(evidence) => {
                        reducer.apply_evidence(task.host, task.port, &evidence);

                        if let Some(pr) = reducer.get_result(task.host, task.port) {
                            if matches!(pr.state, PortState::Open) {
                                terminal::write_realtime(&mut out, &pr);
                                out.flush().unwrap();
                            }
                            if let Some(w) = &mut jsonl_writer {
                                let _ = file_output::write_jsonl_port_event(w, &pr);
                            }
                        }
                    }
                    ProbeTaskResult::LocalError(LocalError::ResourceExhausted) => {
                        local_errors += 1;
                        eprintln!("pmap: local resource exhaustion, reducing concurrency");
                    }
                    ProbeTaskResult::LocalError(LocalError::PermissionDenied) => {
                        local_errors += 1;
                        eprintln!("pmap: permission denied on {host}:{port}",
                            host = task.host, port = task.port);
                    }
                    ProbeTaskResult::LocalError(LocalError::Other(msg)) => {
                        local_errors += 1;
                        eprintln!("pmap: local error on {host}:{port}: {msg}",
                            host = task.host, port = task.port);
                    }
                    ProbeTaskResult::Cancelled => {}
                }
            }
            Some(Err(_)) => {
                // Task panicked — shouldn't happen, but ignore
            }
            None => {
                // JoinSet is empty — shouldn't happen given the check above
                break;
            }
        }
    }

    // Drain any remaining in-flight tasks
    while let Some(result) = join_set.join_next().await {
        if let Ok((task, probe_result)) = result {
            probes_completed += 1;

            if let Some(count) = host_in_flight.get_mut(&task.host) {
                *count -= 1;
                if *count == 0 {
                    host_permits.retain(|(h, _)| *h != task.host);
                }
            }

            match probe_result {
                ProbeTaskResult::Evidence(evidence) => {
                    reducer.apply_evidence(task.host, task.port, &evidence);

                    if let Some(pr) = reducer.get_result(task.host, task.port) {
                        if matches!(pr.state, PortState::Open) {
                            terminal::write_realtime(&mut out, &pr);
                            out.flush().unwrap();
                        }
                        if let Some(w) = &mut jsonl_writer {
                            let _ = file_output::write_jsonl_port_event(w, &pr);
                        }
                    }
                }
                ProbeTaskResult::LocalError(LocalError::ResourceExhausted) => {
                    eprintln!("pmap: local resource exhaustion, reducing concurrency");
                }
                ProbeTaskResult::LocalError(LocalError::PermissionDenied) => {
                    eprintln!("pmap: permission denied on {host}:{port}",
                        host = task.host, port = task.port);
                }
                ProbeTaskResult::LocalError(LocalError::Other(msg)) => {
                    eprintln!("pmap: local error on {host}:{port}: {msg}",
                        host = task.host, port = task.port);
                }
                ProbeTaskResult::Cancelled => {}
            }
        }
    }

    let was_interrupted = interrupted.load(Ordering::SeqCst);
    let elapsed = start.elapsed();
    let completed_at = chrono_now_iso();

    // ── 8. Build final results ──────────────────────────────────────────────
    let mut summary = Summary::default();
    summary.hosts_requested = raw_targets.len() as u64;
    summary.hosts_resolved = hosts.len() as u64;
    summary.hosts_failed = hosts_failed;
    summary.ports_selected = ports.len() as u64;
    summary.probes_planned = total_probes;
    summary.probes_completed = probes_completed;
    summary.local_errors = local_errors;
    summary.not_scanned = scheduler.not_scanned_count();
    summary.completed = !was_interrupted;
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

    // ── 9. Write final terminal output ──────────────────────────────────────
    writeln!(&mut out).unwrap();
    terminal::write_final(&mut out, &scan_result, filter_mode);

    // ── 10. Write file outputs ──────────────────────────────────────────────
    if let Some(path) = &args.output_normal {
        file_output::write_output_normal(path, &scan_result, filter_mode)?;
        eprintln!("pmap: wrote normal output to {path}");
    }

    if let Some(path) = &args.output_json {
        file_output::write_output_json(
            path,
            &scan_result,
            filter_mode,
            "connect",
            args.timing.unwrap_or(3),
            &started_at,
            &completed_at,
            &port_set,
        )?;
        eprintln!("pmap: wrote JSON output to {path}");
    }

    if let Some(w) = &mut jsonl_writer {
        file_output::write_jsonl_scan_completed(w, &scan_result, &completed_at)?;
        w.flush()?;
        eprintln!(
            "pmap: wrote JSONL output to {}",
            args.output_jsonl.as_ref().unwrap()
        );
    }

    if let Some(prefix) = &args.output_all {
        let normal_path = format!("{prefix}.txt");
        let json_path = format!("{prefix}.json");
        let jsonl_path = format!("{prefix}.jsonl");

        file_output::write_output_normal(&normal_path, &scan_result, filter_mode)?;
        file_output::write_output_json(
            &json_path,
            &scan_result,
            filter_mode,
            "connect",
            args.timing.unwrap_or(3),
            &started_at,
            &completed_at,
            &port_set,
        )?;

        {
            let mut f = std::fs::File::create(&jsonl_path)?;
            file_output::write_jsonl_scan_started(
                &mut f,
                "connect",
                args.timing.unwrap_or(3),
                &started_at,
                &hosts,
                ports.len(),
                args.open_only,
                &port_set,
            )?;
            for r in &scan_result.results {
                file_output::write_jsonl_port_event(&mut f, r)?;
            }
            file_output::write_jsonl_scan_completed(&mut f, &scan_result, &completed_at)?;
            f.flush()?;
        }

        eprintln!("pmap: wrote all outputs with prefix {prefix} (.txt, .json, .jsonl)");
    }

    if was_interrupted {
        std::process::exit(130);
    }

    Ok(())
}

/// Get current time as ISO 8601 string.
fn chrono_now_iso() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z"
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
