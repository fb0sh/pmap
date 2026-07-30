Status: ready-for-agent

# SYN Scan MVP

## Problem Statement

`pmap -sS` currently prints an error and exits. Users who need SYN scan speed must fall back to `-sT`, which completes a full TCP handshake and is slower on high-concurrency scans. There is no working SYN scan backend — the Evidence model (`SynAck`, `Reset`) and the State Reducer already handle SYN evidence correctly, but no engine produces it.

## Solution

Implement a Linux-only SYN scan backend (`SynEngine`) that produces `Evidence::SynAck` and `Evidence::Reset`, plugging directly into the existing `ScanEngine` trait and State Reducer pipeline. The engine uses a single raw socket per scan (shared via `Arc<Socket>`), constructs TCP SYN packets manually, and matches responses by four-tuple + ACK number. On non-Linux platforms or without privileges, `-sS` prints a clear error and exits.

## User Stories

1. As a user running `pmap -sS 10.0.0.1`, I want SYN-ACK responses from open ports to be identified as `open` (High confidence) and printed in real-time, so that I can quickly discover services.
2. As a user running `pmap -sS 10.0.0.1`, I want RST responses from closed ports to be identified as `closed` (High confidence) and counted in the summary, so that I can judge scan completeness.
3. As a user running `pmap -sS 10.0.0.1`, I want unresponsive ports to be identified as `unknown` (Low confidence) after the timeout, so that I know which ports gave no conclusion.
4. As a user running `pmap -sS` on Linux without root or `CAP_NET_RAW`, I want a clear error message ("SYN scan requires root or CAP_NET_RAW"), so that I know exactly what to do.
5. As a user running `pmap -sS` on macOS or Windows, I want a clear error message ("SYN scan is currently only supported on Linux"), so that I know to use `-sT` instead.
6. As a user, I want `-sS` to respect the same `-T` timing templates as `-sT`, so that I can control scan speed consistently across scan types.
7. As a user, I want `-sS` results to flow through the same State Reducer as `-sT`, so that the output format, filtering (`--open`), and summary statistics are identical.
8. As a user, I want `-sS` to work with all existing output flags (`-oN`, `-oJ`, `-oJL`, `-oA`), so that I don't need to change my workflow.
9. As a user, I want Ctrl+C during `-sS` to produce a valid partial result (exit code 130), so that I don't lose data from an interrupted scan.
10. As a user, I want `-sS` with multiple targets and `-p` to use round-robin scheduling like `-sT`, so that no single host monopolizes scanning.
11. As a user, I want the SYN source port selected from a high range (40000–60000) to avoid conflicts with well-known ports, so that responses are reliably matched.
12. As a user, I want sequence numbers used for SYN matching to be verifiable (ACK must equal sent_seq + 1), so that stale or unrelated packets don't corrupt results.
13. As a user, I want errors during raw socket creation (fd exhaustion, permission denied) to be reported as `LocalError` and counted in `summary.local_errors`, so that the scan can continue with reduced capacity rather than crashing.
14. As a user, I want the JSON output's `scan.type` field to be `"syn"` when `-sS` is active, so that parsers can distinguish scan types programmatically.
15. As a user, I want the JSONL streaming output to emit `scan_started` with `"type": "syn"` for `-sS` scans, so that live dashboards can display the scan type.
16. As a user, I want the `evidence_count` in the State Reducer to reflect the number of SYN probes sent (including retries within a single probe), so that the summary statistics remain accurate.
17. As a user, I want SYN scan on localhost to work correctly (or with a documented best-effort note), so that I can test the tool locally before scanning remote targets.
18. As a user, I want the raw socket to be set to non-blocking mode, so that recv timeouts are controlled by the probe logic rather than the kernel.
19. As a user, I want the SYN engine to accept the same `connect_timeout` from `TimingPolicy` as the Connect engine, so that timeout behavior is consistent.
20. As a user, I want each SYN probe to complete within the timing timeout, so that the overall scan duration is predictable.

## Implementation Decisions

### Module Structure

New and modified modules:

- **`engine/syn.rs`** (new) — `SynEngine` struct implementing `ScanEngine` trait. Holds shared raw socket (`Arc<Socket>`), timeout duration, and source port counter. Core logic: `probe()` sends a TCP SYN, enters a timed recv loop, matches SYN-ACK or RST by four-tuple + ACK number, returns `ProbeTaskResult`.

- **`engine/privilege.rs`** (new) — `check_syn_privilege() -> Result<(), SynError>` function. Checks platform (`#[cfg(not(target_os = "linux"))]` returns unsupported error). On Linux, attempts to create a test raw socket to verify `root` or `CAP_NET_RAW` capability. Returns a structured error with a user-facing message.

- **`engine/mod.rs`** (modified) — Re-export `SynEngine`. Add `pub mod syn; pub mod privilege;`.

- **`scan.rs`** (modified) — Replace the `exit(1)` branch at the engine creation point with: call `check_syn_privilege()`, construct `SynEngine`, wrap in `Arc`. The JSON output `scan_type` and JSONL `scan_started` must pass `"syn"` instead of hardcoded `"connect"`.

- **`cli/args.rs`** (no change) — `-sS`/`-sT` parsing already works. `is_syn_scan()` already returns `true` for `"S"`.

- **`Cargo.toml`** (modified) — Add `socket2 = "0.5"`.

### SynEngine Design

```
struct SynEngine {
    sock: Arc<Socket>,              // raw socket, shared across all probes
    connect_timeout: Duration,      // from TimingPolicy
    source_port_counter: AtomicU16, // wraps around 40000..60000
}
```

`probe()` flow:
1. Allocate source port (atomic increment, wrap at 60000 → reset to 40000)
2. Build TCP SYN packet (manual IP + TCP headers, src_port, dst_port, seq from simple hash)
3. Send via raw socket
4. Enter timed recv loop (`spawn_blocking` wrapping synchronous recv with deadline)
5. For each received packet: parse Ethernet/IP/TCP headers, check four-tuple match, verify ACK number
6. Match SYN-ACK → `Evidence::SynAck { rtt }`, RST → `Evidence::Reset { rtt }`, timeout → `Evidence::Timeout`
7. Return `ProbeTaskResult::Evidence(...)` or `ProbeTaskResult::LocalError(...)` on socket errors

### Async Integration

`probe()` is async but raw socket I/O is synchronous. Use `tokio::task::spawn_blocking` to wrap the recv loop. This avoids `AsyncFd` complexity. At T5 (500 concurrent), `spawn_blocking` thread pool (default 512) is sufficient. The `ScanEngine` trait remains unchanged.

### Sequence Number Verification

Sent seq = `(target_ip ^ target_port ^ source_ip ^ source_port) as u32` (simple XOR cookie). Response must have `ack_number == sent_seq + 1`. This prevents matching stale packets without complex crypto.

### Socket Configuration

- Domain: `AF_INET` (IPv4 only, documented limitation)
- Type: `SOCK_RAW`
- Protocol: `IPPROTO_TCP` (kernel provides IP header, we only build TCP header)
- Non-blocking: yes
- No BPF filter in MVP — user-side filtering on four-tuple + flags is sufficient at T3 concurrency (50 probes). BPF added as post-MVP optimization.

### Error Mapping

| Socket error | Maps to |
|---|---|
| Permission denied (raw socket creation) | Exit at startup with clear message |
| EMFILE / ENOBUFS / ENOMEM during probe | `LocalError::ResourceExhausted` |
| Sendto failure | `Evidence::Timeout` (probe-level) |
| Recv timeout | `Evidence::Timeout` |
| Task panic | Ignored by JoinSet (existing behavior) |

### Local RST Mitigation

After sending SYN, the local kernel may send RST for the SYN-ACK it sees. Mitigation: after the first recv returns SYN-ACK, do a second short recv (5ms window) to confirm it wasn't immediately RST'd. If the second recv shows RST for the same port, downgrade to `Evidence::Reset` (closed) — this is the correct conservative behavior. Documented limitation: localhost open ports may appear closed due to this race.

### Files Modified

| File | Change |
|---|---|
| `src/engine/syn.rs` | New: SynEngine implementation |
| `src/engine/privilege.rs` | New: platform + privilege check |
| `src/engine/mod.rs` | Add `pub mod syn; pub mod privilege;` |
| `src/scan.rs` | Replace exit(1) with SynEngine creation; pass scan type string to output functions |
| `Cargo.toml` | Add `socket2 = "0.5"` |

## Testing Decisions

### Test Philosophy

Test external behavior at the seams. Each test targets one observable contract. Use real (not mocked) network calls where the seam is a network boundary. For unit tests, construct raw byte buffers to verify packet parsing.

### Seam Tests

1. **Privilege check (unit)** — `check_syn_privilege()` returns correct error on non-Linux. Returns `Ok(())` when raw socket creation succeeds. Returns permission error when it fails. File: `src/engine/privilege.rs` (inline `#[cfg(test)]`).

2. **Packet construction (unit)** — Build a SYN packet, verify the TCP header bytes (flags, seq, src/dst port, checksum). File: `src/engine/syn.rs` (inline `#[cfg(test)]`).

3. **Response matching (unit)** — Parse a raw SYN-ACK byte buffer, verify four-tuple match and ACK number validation. Parse a RST buffer, verify match. Parse an unrelated packet, verify no match. File: `src/engine/syn.rs` (inline `#[cfg(test)]`).

4. **Source port allocation (unit)** — Verify counter starts at 40000, increments, wraps at 60000, skips 0. File: `src/engine/syn.rs` (inline `#[cfg(test)]`).

5. **SynEngine integration (integration)** — Scan `127.0.0.1:1` (closed) → expect `Reset` → `Closed`. Scan `127.0.0.1:22` (if sshd running) → expect `SynAck` → `Open`. File: `tests/syn_integration.rs`.

6. **SynEngine + State Reducer (integration)** — Feed `SynAck` and `Reset` evidence through the reducer, verify `ProbeResult` state and confidence. Confirm `ConnectSuccess` and `SynAck` coexist correctly (conflict → Medium). File: existing reducer tests, add SYN-specific cases.

7. **scan.rs integration (end-to-end)** — Run `pmap -sS 127.0.0.1 -p 1` as a subprocess, verify exit code 0, verify stdout contains sorted results, verify `-oJ` output has `"type": "syn"`.

8. **Error cases (integration)** — Run `pmap -sS` without root on a non-privileged user, verify exit code 1 and stderr contains "root or CAP_NET_RAW". Run on non-Linux, verify "only supported on Linux".

9. **Ctrl+C during SYN scan (integration)** — Start a SYN scan against a range, send SIGINT, verify partial results are valid and exit code is 130.

10. **Output compatibility (integration)** — Run `-sS -oN`, `-sS -oJ`, `-sS -oJL`, `-sS -oA`, verify output format matches Connect scan format (only `scan.type` differs).

### Prior Art

Existing tests in `tests/cli.rs`, `tests/port_parser.rs`, `tests/target_parser.rs`, `tests/filter_output.rs` provide the pattern: real I/O, assert on output. The new tests follow the same convention.

## Out of Scope

- macOS / Windows SYN scan (clear error message only)
- ICMP parsing (all unresponsive → Timeout)
- High-performance batch send/recv model (per-probe via `spawn_blocking` only)
- Complex sequence number cookie (simple XOR cookie only)
- BPF filter on raw socket (user-side four-tuple filtering in MVP)
- Retry / conflict review / HostProfile / adaptive rate limiting
- Auto-degradation from SYN to Connect
- Perfect local RST suppression (documented best-effort only)
- IPv6 support (IPv4 only, documented limitation)
- Open port verification (SYN → Connect confirmation for upgraded confidence)

## Further Notes

The existing `Evidence::SynAck`, `Evidence::Reset`, and their `to_state_confidence()` mappings are already correct and complete. The State Reducer's conflict detection (`has_conflict` → Medium downgrade) handles mixed SYN + Connect evidence without modification. The terminal real-time output (`write_realtime`) and final output (`write_final`) already display all PortState variants. This means the SYN MVP requires changes to exactly one pipeline seam: the engine layer. Everything downstream is already wired.
