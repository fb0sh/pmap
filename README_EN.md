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

Tested against a macOS host (192.168.139.3, 128 ports, 32 open / 96 closed, 3 repeats each):

### SYN scan (-sS)

| T | Time | Ports/s | Acc% | OpenRec | ClsRec | FO | MO |
|---|-----:|-------:|-----:|--------:|-------:|:--:|:--:|
| 0 | 10.03s | 13 | 99.0 | 97.9 | 99.0 | 0 | 2 |
| 1 | 5.66s | 23 | **100.0** | 100.0 | 100.0 | 0 | 0 |
| 2 | 5.02s | 25 | 90.4 | 88.5 | 91.0 | 0 | 11 |
| 3 | 5.02s | 25 | 94.0 | 92.7 | 94.4 | 0 | 7 |
| 4 | 2.52s | 51 | 79.9 | 80.2 | 79.9 | 0 | 19 |
| 5 | 1.27s | 101 | 77.1 | 75.0 | 77.8 | 0 | 24 |

**Best balanced: T1 (100% accuracy, 23 ports/s).** Fastest: T5 (101 ports/s, 77%).

### TCP Connect scan (-sT)

| T | Time | Ports/s | Acc% | OpenRec | ClsRec | FO | MO |
|---|-----:|-------:|-----:|--------:|-------:|:--:|:--:|
| 0 | 13.07s | 10 | **100.0** | 100.0 | 100.0 | 0 | 0 |
| 1 | 6.03s | 21 | **100.0** | 100.0 | 100.0 | 0 | 0 |
| 2 | 2.51s | 51 | 99.7 | 100.0 | 99.7 | 0 | 0 |
| 3 | 2.11s | 61 | **100.0** | 100.0 | 100.0 | 0 | 0 |
| 4 | 1.56s | 82 | 99.5 | 100.0 | 99.3 | 0 | 0 |
| 5 | 0.75s | 171 | 99.5 | 99.0 | 99.7 | 0 | 1 |

**Best balanced: T3 (100% accuracy, 61 ports/s, default).** Fastest: T5 (171 ports/s, 99.5%).

**false_open = 0 across all profiles** — no port was incorrectly marked as open.

## License

MIT
