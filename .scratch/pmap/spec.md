# pmap: Cross-Platform TCP Port Scanner

## Problem Statement

Network administrators and security engineers need to discover which TCP ports are open across multiple hosts. Existing tools either lack cross-platform consistency (different behavior on Windows vs Linux vs macOS), require elevated privileges forSYN scanning, or produce output that's hard to parse programmatically. There is no tool that prioritizes open port recall rate and result可信度 while maintaining a clean, stable CLI contract across all three major platforms.

## Solution

A Rust CLI tool (`pmap`) that performs TCP port scanning with two ScanType strategies:SYN scan (-sS) for speed on supported platforms, and Connect scan (-sT) for universal compatibility. The tool outputs results in real-time as open ports are discovered, then presents a sorted final summary. Output formats include terminal, plain text (-oN), JSON (-oJ), JSON Lines (-oJL), and all-at-once (-oA). Internal scheduling uses fair round-robin across hosts with adaptive timing, and the State Reducer centralizes all PortState + Confidence logic so that every output path shares identical semantics.

## User Stories

1. As a network administrator, I want to scan a single host for open ports, so that I can verify which services are running.
2. As a network administrator, I want to scan a CIDR range (e.g. 192.168.1.0/24), so that I can discover all active hosts and their open ports in one command.
3. As a security engineer, I want to scan multiple hosts specified on the command line, so that I can audit a set of servers simultaneously.
4. As a security engineer, I want to read targets from a file (-iL), so that I can scan large lists without shell escaping issues.
5. As a security engineer, I want to combine command-line targets and -iL files, so that I can incrementally build target lists.
6. As a user, I want to specify exact ports (-p 22,80,443), so that I can focus on services I care about.
7. As a user, I want to specify port ranges (-p 1-1024), so that I can scan a contiguous block.
8. As a user, I want to scan all ports (-p-), so that I can do a comprehensive audit.
9. As a user, I want mixed port specs (-p 22,80,443,8000-9000), so that I can combine precision and ranges.
10. As a user, I want a sensible default port set (top 1000 TCP ports) when I don't specify -p, so that I get useful results without memorizing port numbers.
11. As a user, I wantSYN scan (-sS) for faster results on Linux/macOS with privileges, so that I can scan quickly.
12. As a user, I want Connect scan (-sT) as the default, so that it works everywhere without special privileges.
13. As a user, if I request -sS but the system lacks capabilities, I want a clear error message instead of a silent fallback, so that I can trust the result semantics.
14. As a user, I want timing templates (-T0 to -T5) to control scan speed, so that I can balance speed vs stealth vs reliability.
15. As a user, I want -T3 as the default, so that I get balanced performance without thinking about it.
16. As a user, I want open ports to appear in real-time as they're discovered, so that I can act immediately on findings.
17. As a user, I want the final result sorted by IP then port, so that I can read it systematically.
18. As a user, I want closed and unreachable ports hidden from detail output but counted in summary, so that I can judge scan completeness without noise.
19. As a user, I want --open to filter all output to only open ports, so that I can get a clean list for scripting.
20. As a user, I want --open to still show full summary counts, so that I know the scan was comprehensive.
21. As a user, I want -oN to produce clean text output without ANSI colors, so that I can pipe it or include in reports.
22. As a user, I want -oJ to produce structured JSON with schema_version, so that I can parse it programmatically.
23. As a user, I want -oJL to stream results as they happen, so that I can feed them into a live dashboard.
24. As a user, I want -oA to generate all three formats at once, so that I don't have to run the scan multiple times.
25. As a user, I want unknown ports compressed into ranges in text and JSON output, so that the output stays manageable for large scans.
26. As a user, I want the summary to always show all state counts (open, closed, filtered, unreachable, unknown, not_scanned), so that I can assess scan completeness.
27. As a user, I want Ctrl+C to produce a valid partial result with completed=false, so that I don't lose data from an interrupted scan.
28. As a user, I want the exit code to be 130 on Ctrl+C, so that scripts can detect interruption.
29. As a user, I want progress reported to stderr, so that stdout remains clean for piping.
30. As a user, I want the tool to detect and report local resource errors (file descriptor exhaustion) without misclassifying them as target states, so that I can adjust concurrency or retry.
31. As a user, I want duplicate hosts automatically deduplicated, so that overlapping CIDRs or hostnames don't waste time.
32. As a user, I want hostnames that resolve to multiple IPs all scanned, so that I don't miss addresses.
33. As a user, I want a hostname resolution failure to not abort the entire scan, so that one bad entry doesn't block everything.
34. As a user, I want an error if all targets are invalid, so that I know immediately nothing was scanned.
35. As a user, I want a target count limit (65536 hosts, 100M total probes) to prevent accidental resource exhaustion, so that I don't accidentally scan the internet.
36. As a user, I wantSYN scan to use sequence cookies to match responses to requests, so that stale or unrelated packets don't corrupt results.
37. As a user, I want fair scheduling across hosts (round-robin), so that one slow host doesn't block discovery on others.
38. As a user, I want high-value ports (user-specified, then common ports, then 1-1024) probed first, so that I see important results early.
39. As a user, I want open port verification (SYN → Connect confirmation) for -sS, so that open/high can be upgraded to confirmed.
40. As a user, I want conflict review when evidence disagrees, so that ambiguous results get a second chance to converge.
41. As a user, I want RTT shown as best_rtt in terminal output, so that I see the most favorable measurement.
42. As a user, I want IP addresses sorted numerically (not lexicographically), so that 192.168.1.2 appears before 192.168.1.10.
43. As a user, I want theJSON schema_version固定为1 from the first release, so that parsers can rely on a stable contract.
44. As a user, I want theJSON scan object to record timing_template, scan type, started_at, completed_at, and elapsed_ms, so that I can reconstruct the scan context.
45. As a user, I want theJSON summary to include hosts_requested, hosts_resolved, hosts_failed, ports_selected, probes_planned, probes_completed, and local_errors, so that I can assess completeness programmatically.
46. As a user, I want Ctrl+C + --open to still only output open results, so that the filter is consistently applied.
47. As a user, I want the output task decoupled from the probe engine, so that I/O latency doesn't slow down scanning.
48. As a user, I want the State Reducer to be the single source of truth for PortState + Confidence, so that all output paths share identical semantics.
49. As a user, I wantSYN scan on Linux via AF_PACKET, macOS via BPF/libpcap, and Windows via Npcap, so that I get native performance on each platform.
50. As a user, I want Connect scan to work on all platforms with普通用户权限, so that I can use it anywhere without setup.

## Implementation Decisions

### Module Structure

The codebase is organized into these primary modules, each with a clear responsibility boundary:

- **cli** — Parses command-line arguments into a ScanConfig. Handles -sS/-sT, -p, -iL, -T0..5, --open, and output flags. Validates mutual exclusivity (e.g. -sS and -sT cannot coexist).
- **target** — Resolves Targets (IP, CIDR, hostname, -iL file) into a deduplicated list of Hosts. Handles CIDR expansion, DNS resolution, file reading, and the 65536 host limit.
- **port** — Parses port specifications into a sorted Vec<u16>. Handles -p, -p-, ranges, comma-separated values, deduplication, and the default top-1000 set.
- **model** — Core domain types: PortState, Confidence, Evidence, ProbeResult, ScanResult, Protocol. No business logic, just type definitions.
- **engine** — Probe execution. Connect engine uses Tokio TcpStream with timeout and error mapping. SYN engine uses platform-specific raw packet injection. Both produce ProbeEvidence.
- **scheduler** — Fair round-robin scheduling across Hosts with bounded queues, three-layer concurrency limits (global, per-host, active hosts), and priority ordering (high-value ports first).
- **state** — State Reducer: the single source of truth. Consumes Evidence, produces ProbeResult, handles conflict detection, RTT tracking, and summary aggregation.
- **output** — Decoupled output task. Consumes ScanResult, applies filtering (--open or default), formats for each target (terminal, -oN, -oJ, -oJL), handles unknown range compression, and manages BufWriter flushing.
- **platform** — Platform-specific capability detection: privilege checks, SYN backend availability, file descriptor limits.

### Key Architectural Decisions

1. **State Reducer is the single source of truth.** All PortState + Confidence logic lives here. The engine never decides final state — it only produces Evidence. This ensures all output paths (terminal, -oN, -oJ, -oJL) share identical semantics.

2. **Output task is decoupled from probe engine.** The engine writes Evidence to a bounded channel; the State Reducer consumes it and emits events to a bounded output channel; the Output Task consumes events and writes to stdout/files. No probe worker ever touches stdout.

3. **No silent ScanType fallback.** If the user specifies -sS but the system lacks capabilities, pmap exits with an error. The user must explicitly choose -sT. This preserves result semantics.

4. **Unknown ports are compressed, not enumerated.** Text output uses range notation (e.g. `unknown  1-21,23-79`). JSON uses `unknown_ranges: [[1,21],[23,79]]` per host. This keeps output manageable for large scans.

5. **not_scanned vs unknown.** Interrupted scans distinguish between ports that were probed but got no conclusion (unknown) and ports that were never probed (not_scanned). Both appear in summary.

6. **local_errors are independent.** LocalResourceExhausted and PermissionDenied never map to any PortState. They increment summary.local_errors and may cause completed=false.

7. **Fair scheduling via round-robin.** Hosts are polled in rotation, not scanned sequentially. This ensures multi-host discovery is uniform and slow hosts don't monopolize resources.

8. **High-value ports first.** User-specified ports (in user order) > built-in common ports > 1-1024 > rest. This ensures important results appear early in real-time output.

9. **RTT tracking: best_rtt + last_rtt.** Terminal shows best_rtt. JSON records both. Timeout never participates in RTT calculation.

10. **IP sorting is numeric, not lexicographic.** 192.168.1.2 must sort before 192.168.1.10.

11. **Atomic file writing for JSON.** JSON is written to a temp file, flushed, fsynced, then renamed. JSONL is appended line-by-line. Text is written after scan completion.

12. **Ctrl+C produces valid partial results.** The scan stops gracefully, in-flight probes are given a short convergence window, the State Reducer flushes completed evidence, and all output files remain valid (合法 JSON, complete JSONL lines, clean text). Exit code 130.

### Evidence Priority

The State Reducer applies this priority when merging Evidence for a single Host:Port:

```
ConnectSuccess > SynAck > ConnectRefused / Reset > ICMP > Timeout
```

Timeout is weak evidence — it never overwrites an existing stronger state. Two strong conflicting evidence sources (e.g. SYN-ACK vs ICMP Filtered) trigger Medium降级.

### ProbeEvidence Variants

```
SynAck { rtt }
Reset { rtt }
ConnectSuccess { rtt }
ConnectRefused { rtt }
IcmpFiltered { code }
HostUnreachable
NetworkUnreachable
Timeout
LocalResourceExhausted
PermissionDenied
```

LocalResourceExhausted and PermissionDenied are not port evidence — they are local error signals handled separately.

### Cancelled is not ProbeEvidence

Task cancellation (Ctrl+C, scheduler shutdown, fatal error) produces a ProbeOutcome::Cancelled, not a ProbeEvidence. Cancelled tasks do not enter the State Reducer.

### JSON Schema (v1)

```json
{
  "schema_version": 1,
  "scanner": { "name": "pmap", "version": "0.1.0" },
  "scan": {
    "type": "syn|connect",
    "timing_template": 3,
    "completed": true,
    "partial_failures": false,
    "started_at": "ISO-8601",
    "completed_at": "ISO-8601",
    "elapsed_ms": 38700,
    "open_only": false,
    "port_set": { "kind": "explicit|default", "value": "..." }
  },
  "targets": { "requested": 256, "resolved": 254, "failed": 2 },
  "results": [
    { "ip": "...", "port": 443, "protocol": "tcp", "state": "open", "confidence": "high", "rtt_ms": 31 }
  ],
  "unknown": [
    { "ip": "...", "protocol": "tcp", "ranges": [[1,21],[23,79]] }
  ],
  "summary": {
    "hosts_requested": 256,
    "hosts_resolved": 254,
    "hosts_failed": 2,
    "ports_selected": 65535,
    "probes_planned": 16645890,
    "probes_completed": 16645890,
    "open": 17,
    "closed": 312,
    "filtered": 104,
    "unreachable": 357,
    "unknown": 16645100,
    "not_scanned": 0,
    "local_errors": 0
  }
}
```

### Terminal Output Format

Real-time (during scan):
```
<IP>\t<PORT>/tcp\t<STATE>\t<CONFIDENCE>\t<RTT>
```

Final (after scan, with `*` prefix):
```
* <IP>\t<PORT>/tcp\t<STATE>\t<CONFIDENCE>\t<RTT>
```

Unknown compression in final output:
```
* <IP>\tunknown\t<PORT-RANGES>
```

### Output Filtering Matrix

| State       | Real-time | Final | -oN | -oJ | -oJL |
|-------------|:---------:|:-----:|:---:|:---:|:----:|
| open        | yes       | yes   | yes | yes | yes  |
| filtered    | no        | yes   | yes | yes | yes  |
| unknown     | no        | yes   | yes | yes | no   |
| closed      | no        | no    | no  | no  | no   |
| unreachable | no        | no    | no  | no  | no   |

With --open: only open details. Summary always shows all counts.

## Testing Decisions

### Seam Selection

The spec identifies these seams for testing, ordered from highest (most value) to lowest:

1. **CLI → ScanConfig** — Parse args, validate constraints. Tests: mutual exclusivity, missing targets, invalid ports, -p- expansion, -iL parsing.
2. **Target Resolution** — Input targets → deduplicated Hosts. Tests: IP, CIDR expansion, hostname resolution, -iL file, dedup, 65536 limit, partial DNS failure.
3. **Port Parsing** — Input specs → Vec<u16>. Tests: single port, range, comma-separated, -p-, dedup, invalid range error, default 1000.
4. **State Reducer** — Evidence stream → ProbeResult. Tests: evidence priority, conflict → Medium, RTT tracking (best/last), timeout doesn't override, LocalResourceExhausted not mapped.
5. **Output Filtering** — ScanResult + mode → filtered results. Tests: --open filters to open only, default shows open/filtered/unknown, summary always complete, not_scanned appears on interrupt.
6. **Output Formatting** — Filtered results → formatted output. Tests: terminal tab-separated, -oN no ANSI, -oJ valid JSON with schema_version, -oJL valid JSONL lines, -oA generates all three, unknown range compression.

### Test Philosophy

- Test external behavior, not internal implementation.
- Each test targets one seam.
- Use real (not mocked) transformations where the seam is pure.
- For the State Reducer, construct specific Evidence sequences and verify the resulting ProbeResult.
- For output formatting, construct ScanResult fixtures and verify exact output strings.
- Integration tests should exercise the full pipeline: CLI args → scan → output file → verify file contents.

### Prior Art

This is a new project with no existing test code. Tests will follow Rust conventions:
- Unit tests in each module file (#[cfg(test)])
- Integration tests in tests/ directory
- Benchmarks in benches/

## Out of Scope

- Service identification, version detection, banner grabbing
- UDP scanning
- Script/NSE engine
- IPv6 support (first version is IPv4 only)
- Service name resolution (http, https, etc.) in port specs
- User-configurable timeout, retries, rate, concurrency (managed internally by TimingPolicy)
- --show-closed, --show-filtered, --show-unknown, --no-progress, --no-color, --engine, --profile flags
- --force to bypass target limits
- Output colorization (plain text only, even on TTY)
- Progress bar or visual indicators (stderr text progress only)

## Further Notes

- The default port set (top 1000) is versioned with pmap and may change between releases. It lives in data/top_tcp_1000.txt and is embedded at build time.
- SYN scan sequence cookies use a keyed hash of (secret, target_ip, target_port, source_ip, source_port, scan_epoch) to match SYN-ACK responses to requests.
- The project follows a strict implementation order: CLI → target/port parsing → state model → output filtering → Connect engine → real-time output → final sorting → multi-host scheduling → timing → file outputs → unknown compression → cancellation → resource protection → Linux SYN → macOS/Windows SYN → performance.
- Cross-platform SYN backends share the same interface and Evidence model but differ in implementation (AF_PACKET on Linux, BPF on macOS, Npcap on Windows). The spec intentionally does not unify their low-level details.
