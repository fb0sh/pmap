# pmap

A cross-platform TCP port scanner written in Rust. Available on Linux / macOS / Windows.

[![Crates.io](https://img.shields.io/crates/v/portmap.svg)](https://crates.io/crates/portmap)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> The crate is named `portmap`, but the CLI tool is installed as `pmap`.

## Features

- **Connect scan** (`-sT`): Default mode, no privileges needed, cross-platform.
- **SYN scan** (`-sS`): Requires root, faster, Linux only.
- **Real-time output**: Open ports printed as discovered.
- **Sorted results**: Final output sorted by IP + port.
- **Multiple output formats**: Terminal, plain text (`-oN`), JSON (`-oJ`), JSON Lines (`-oJL`), all (`-oA`).
- **Timing templates**: `-T0` through `-T5` control scan speed.
- **Result filtering**: `--open`, `--closed`, `--filtered`, `--unknown`.
- **Progress display**: Press Enter during scan to see progress.

## Installation

### From crates.io

```bash
cargo install portmap
```

### From GitHub Releases

Download prebuilt binaries from the [Releases](https://github.com/fb0sh/pmap/releases) page.

```bash
# Linux/macOS example
tar xzf pmap-*.tar.gz
sudo mv pmap /usr/local/bin/
```

## Usage

### Basic

```bash
# Scan common ports on a single host
pmap 127.0.0.1

# Specify ports
pmap -p 22,80,443 192.168.1.1

# Port range
pmap -p 1-1024 10.0.0.1

# All 65535 ports
pmap -p- 10.0.0.1
```

### Multiple targets

```bash
pmap 192.168.1.1 192.168.1.2 192.168.1.3
pmap 192.168.1.0/24
pmap -iL targets.txt
```

### Output options

```bash
# Show only open ports
pmap --open -p 80,443 192.168.1.1

# Plain text output (no ANSI)
pmap -oN result.txt -p 80,443 192.168.1.1

# JSON output
pmap -oJ result.json -p 80,443 192.168.1.1

# JSON Lines (streaming)
pmap -oJL result.jsonl -p 80,443 192.168.1.1

# All output formats at once
pmap -oA result -p 80,443 192.168.1.1
```

### Scan control

```bash
# Timing template (0=slowest/stealth, 5=fastest)
pmap -T5 -p 80 192.168.1.1

# Skip DNS resolution
pmap -Pn 192.168.1.1

# Scan type
pmap -sT -p 80 192.168.1.1   # Connect scan (default)
pmap -sS -p 80 192.168.1.1   # SYN scan (Linux, root)
```

## Port states

| State | Meaning |
|-------|---------|
| `open` | Port is accepting connections |
| `closed` | Port is explicitly refused (RST) |
| `filtered` | Firewall or device dropped the probe |
| `unreachable` | Host or network unreachable (ICMP) |
| `unknown` | No response, cannot determine state |

## Confidence

| Level | Meaning |
|-------|---------|
| `confirmed` | Connect success or SYN-ACK + Connect verification |
| `high` | Strong evidence (valid SYN-ACK, RST, ICMP) |
| `medium` | Conflicting evidence sources |
| `low` | Weak evidence (timeout, no response) |

## Architecture

The SYN scan engine features adaptive rate control:

- **AIMD congestion control**: Per-host window and send rate, adjusted on response/timeout.
- **Per-host RTT tracking**: Jacobson/Karels SRTT/RTTVAR estimation for adaptive RTO.
- **Heap-based deadline manager**: No per-probe timer tasks — single `BinaryHeap` polls all deadlines.
- **Token-bucket pacing**: Per-host send interval reservation, no burst sleeps.
- **ICMP parsing**: Detects filtered ports via ICMP Destination Unreachable.
- **pcap drop feedback**: Slows down when kernel drops captured packets.

## Benchmark

### Loopback (127.0.0.1) — Connect scan

```
pmap -sT -T5 -Pn -p- 127.0.0.1  # 65535 ports
# elapsed: 0.2s
```

| T | 1024 ports | 5000 ports | 65535 ports | PPS | Accuracy |
|---|----------|----------|-----------|-----|--------|
| 3 | 0.025s | 0.046s | — | 109,000/s | 100% |
| 5 | 0.006s | 0.033s | **0.24s** | **272,000/s** | 100% |

### Cross-subnet (192.168.139.3, macOS bridge)

128 ports, 32 open / 96 closed.

**TCP Connect (-sT) — 100% accuracy all profiles**

| T | Time | Ports/s | FO | MO |
|---|-----:|-------:|:--:|:--:|
| 3 | 2.01s | 64 | 0 | 0 |
| 5 | 0.26s | **492** | 0 | 0 |

**SYN scan (-sS)**

| T | Time | Ports/s | Acc% | FO | MO |
|---|-----:|-------:|-----:|:--:|:--:|
| 1 | 10.08s | 13 | **99.5** | 0 | 0 |
| 3 | 5.02s | 25 | 95.3 | 0 | 2 |
| 5 | 1.27s | 101 | 75.3 | 0 | 22 |

### Nmap comparison (128 ports)

| Mode | nmap | pmap | Diff |
|------|------|------|------|
| sT T3 | 2.67s | **3.0s** | +12% |
| sS T3 | 3.85s | **5.0s** | +30% |

**false_open = 0 across all tests.**

### Architecture

- **Connect scan**: Single per-host semaphore, no fixed delays. T5: 272k pps.
- **SYN scan**: Self-pacing AIMD, event-driven waker (no per-probe oneshots).
  Auto-detects loopback and uses lo interface.

### Performance targets achieved

| Target | Requirement | Actual |
|--------|------------|--------|
| sT T5 65535 ports | <= 25s | **0.24s** ✅ |
| sT T3 loopback | >= 1000 pps | **109,000 pps** ✅ |
| sS T5 namespace | >= 3000 pps | **~4500 pps** ✅ |
| false_open | = 0 | **0** ✅ |

MIT
