# pmap

跨平台 TCP 端口扫描器。用 Rust 编写，支持 Linux / macOS / Windows。

[![Crates.io](https://img.shields.io/crates/v/portmap.svg)](https://crates.io/crates/portmap)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Crate 名称是 `portmap`，但安装后命令行工具是 `pmap`。

## 功能

- **Connect 扫描** (`-sT`)：默认模式，无需特权，全平台可用
- **SYN 扫描** (`-sS`)：需要 root/管理员权限，速度更快（仅限 Linux）
- **实时输出**：开放端口发现后立即打印
- **排序结果**：扫描结束后按 IP 升序 + 端口升序输出完整结果
- **过滤结果**：`--open` / `--closed` / `--filtered` / `--unknown`
- **多种输出格式**：终端、纯文本 (`-oN`)、JSON (`-oJ`)、JSON Lines (`-oJL`)、全部 (`-oA`)
- **定时模板**：`-T0` ~ `-T5` 控制扫描速度
- **进度显示**：扫描过程中按回车查看进度

## 安装

### 从 crates.io 安装

```bash
cargo install portmap
```

### 从 GitHub Releases 下载预编译二进制

前往 [Releases](https://github.com/fb0sh/pmap/releases) 下载对应平台的二进制：

| 平台 | 文件 |
|------|------|
| Linux x86_64 | `pmap-x86_64-unknown-linux-gnu.tar.gz` |
| Linux i686 | `pmap-i686-unknown-linux-gnu.tar.gz` |
| macOS ARM (Apple Silicon) | `pmap-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `pmap-x86_64-pc-windows-msvc.zip` |
| Windows x86 | `pmap-i686-pc-windows-msvc.zip` |

```bash
# Linux/macOS 示例
tar xzf pmap-*.tar.gz
sudo mv pmap /usr/local/bin/
```

## 使用

### 基本用法

```bash
# 扫描单个主机的常用端口
pmap 127.0.0.1

# 指定端口
pmap -p 22,80,443 192.168.1.1

# 扫描端口范围
pmap -p 1-1024 10.0.0.1

# 扫描全部端口
pmap -p- 10.0.0.1
```

### 扫描多个目标

```bash
# 命令行指定多个主机
pmap 192.168.1.1 192.168.1.2 192.168.1.3

# CIDR 段
pmap 192.168.1.0/24

# 从文件读取目标
pmap -iL targets.txt

# 组合使用
pmap 192.168.1.1 -iL extra_hosts.txt
```

### 输出选项

```bash
# 只显示开放端口
pmap --open -p 80,443 192.168.1.1

# 输出到纯文本文件（无 ANSI 颜色）
pmap -oN result.txt -p 80,443 192.168.1.1

# 输出到 JSON 文件
pmap -oJ result.json -p 80,443 192.168.1.1

# 输出到 JSON Lines（流式）
pmap -oJL result.jsonl -p 80,443 192.168.1.1

# 同时生成所有格式
pmap -oA result -p 80,443 192.168.1.1
```

### 扫描控制

```bash
# 时序模板（0=最慢/隐蔽，5=最快）
pmap -T5 -p 80 192.168.1.1

# 不解析主机名
pmap -Pn 192.168.1.1

# 指定扫描类型
pmap -sT -p 80 192.168.1.1
```

## 目标文件格式

`-iL` 读取的目标文件支持 `#` 注释：

```
# 内网服务器
192.168.1.1
192.168.1.2

# DMZ 区域
10.0.0.0/24
```

## 输出格式

### 终端输出

扫描过程中实时显示发现的开放端口：

```
# pmap version 0.0.1 powered by fb0sh

127.0.0.1            80/tcp   open     confirmed  0.2ms
127.0.0.1           443/tcp   open     confirmed  0.3ms

# complete results (sorted)

* 127.0.0.1            80/tcp   open     confirmed  0.2ms
* 127.0.0.1           443/tcp   open     confirmed  0.3ms

# hosts: 1
# ports: 21
# open: 2
# closed: 19
# filtered: 0
# unreachable: 0
# unknown: 0
# elapsed: 0.1s
```

### JSON 输出

```json
{
  "schema_version": 1,
  "scanner": { "name": "pmap", "version": "1.1.0" },
  "scan": {
    "type": "connect",
    "timing_template": 3,
    "completed": true,
    "started_at": "2025-01-01T00:00:00.000Z",
    "completed_at": "2025-01-01T00:00:01.000Z",
    "elapsed_ms": 1000,
    "open_only": false,
    "port_set": { "kind": "explicit", "value": "80,443" }
  },
  "targets": { "requested": 1, "resolved": 1, "failed": 0 },
  "results": [
    { "ip": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "confidence": "confirmed", "rtt_ms": 0.2 }
  ],
  "summary": {
    "hosts_requested": 1,
    "hosts_resolved": 1,
    "hosts_failed": 0,
    "ports_selected": 2,
    "probes_planned": 2,
    "probes_completed": 2,
    "open": 1,
    "closed": 1,
    "filtered": 0,
    "unreachable": 0,
    "unknown": 0,
    "not_scanned": 0,
    "local_errors": 0
  }
}
```

## 端口状态

| 状态 | 含义 |
|------|------|
| `open` | 端口开放，有服务监听 |
| `closed` | 端口关闭，连接被拒绝 |
| `filtered` | 端口被防火墙过滤 |
| `unreachable` | 主机或网络不可达 |
| `unknown` | 无响应，无法确定状态 |

## 置信度

| 置信度 | 含义 |
|--------|------|
| `confirmed` | 最高置信度，Connect 扫描连接成功或 SYN + Connect 验证通过 |
| `high` | 高置信度 |
| `medium` | 中等置信度，存在证据冲突 |
| `low` | 低置信度 |

## 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 扫描正常完成 |
| `1` | 运行时错误 |
| `2` | 无法解析任何目标 |
| `130` | 用户按 Ctrl+C 中断 |

## 项目结构

```
src/
├── main.rs              # 入口
├── lib.rs               # 库根
├── scan.rs              # 扫描主流程
├── cli/                 # 命令行参数解析
├── target/              # 目标解析（IP、CIDR、主机名、文件）
├── port/                # 端口解析
├── model/               # 领域模型（PortState、Confidence、Evidence）
├── engine/              # 探测引擎（Connect、SYN）
├── scheduler/          # 调度器（轮询、时序策略）
└── output/              # 输出（终端、文件、JSON）
```

## 依赖

- `tokio` — 异步运行时
- `clap` — 命令行参数解析
- `serde` / `serde_json` — JSON 序列化
- `anyhow` — 错误处理
- `pcap` — 包捕获（SYN 扫描）
- `libc` / `socket2` — 原始套接字（SYN 扫描）
- `parking_lot` — 高效互斥锁

## SYN 扫描限制

- 需要 root 权限（原始套接字 + BPF）
- 仅限 Linux
- 跨子网扫描时目标必须返回正确的 TCP SYN-ACK（标准 TCP/IP 行为，无特殊限制）

**建议**：对于日常使用，推荐使用 `-sT`（Connect 扫描），无需特权且全平台可用。

## 调试

设置环境变量 `PMAP_DEBUG=1` 启用 SYN 扫描的详细诊断日志：

```bash
# 查看 SYN 扫描的收包/发包细节
PMAP_DEBUG=1 pmap -sS -T3 -p 80 192.168.1.1

# 用于排查 SYN 扫描无响应问题
sudo PMAP_DEBUG=1 pmap -sS -T3 -Pn -p 22,80,443 192.168.1.1
```

日志输出示例：
```
[syn] device=eth0, local_ip=192.168.1.100, ifindex=2
[syn] SYN→ 192.168.1.1:80, sp=40000, seq=3569752726, id=12345 (44B)
[syn] [#1] 192.168.1.1:80 → 192.168.1.100:40000 [SA] len=44
[syn] HIT Some(Open ...) total=1
```

日志含义：
- `device` / `local_ip` — 绑定网卡和源 IP
- `SYN→` — SYN 包已发出（目标、端口、序列号、IP ID、字节数）
- `[#N]` — 收到的第 N 个包（源:端口 → 目标:端口 [TCP flags] 长度）
- `HIT` — 响应已匹配到挂起的探测任务，返回端口状态

## 开发

```bash
# 构建
cargo build

# 运行测试
cargo test

# 发布构建
cargo build --release
```

## 许可证

MIT

## Network benchmark (192.168.139.3)
<!-- PMAP_LOCALHOST_BENCHMARK_START -->
*Target: 192.168.139.3 (macOS host, cross-subnet)*  
*Date: 2026-07-30*  
*Ports: 20000-20127 (128 ports, 32 open / 96 closed)*  
*Repeats: 3, seed=42, shuffled interleaved*  

### SYN scan (-sS)
| T | Time | Ports/s | Acc% | OpenRec | ClsRec | FO | MO | CPU ms/k | Mem KB |
|---|-----:|-------:|-----:|--------:|-------:|:--:|:--:|---------:|-------:|
| 0 | 10.03s | 13 | 99.0 | 97.9 | 99.0 | 0 | 2 | 286 | 8257 |
| 1 | 5.66s | 23 | 100.0 | 100.0 | 100.0 | 0 | 0 | 234 | 8241 |
| 2 | 5.02s | 25 | 90.4 | 88.5 | 91.0 | 0 | 11 | 156 | 8153 |
| 3 | 5.02s | 25 | 94.0 | 92.7 | 94.4 | 0 | 7 | 156 | 8241 |
| 4 | 2.52s | 51 | 79.9 | 80.2 | 79.9 | 0 | 19 | 104 | 8301 |
| 5 | 1.27s | 101 | 77.1 | 75.0 | 77.8 | 0 | 24 | 104 | 8284 |

**Best: T1 (100% accuracy, 23 ports/s, lowest profile with 100%).**  
**Fastest: T5 (101 ports/s, 77% accuracy — speed costs accuracy).**

### TCP Connect scan (-sT)
| T | Time | Ports/s | Acc% | OpenRec | ClsRec | FO | MO | CPU ms/k | Mem KB |
|---|-----:|-------:|-----:|--------:|-------:|:--:|:--:|---------:|-------:|
| 0 | 13.07s | 10 | 100.0 | 100.0 | 100.0 | 0 | 0 | 78 | 4139 |
| 1 | 6.03s | 21 | 100.0 | 100.0 | 100.0 | 0 | 0 | 78 | 4139 |
| 2 | 2.51s | 51 | 99.7 | 100.0 | 99.7 | 0 | 0 | 104 | 4207 |
| 3 | 2.11s | 61 | 100.0 | 100.0 | 100.0 | 0 | 0 | 26 | 4165 |
| 4 | 1.56s | 82 | 99.5 | 100.0 | 99.3 | 0 | 0 | 52 | 4172 |
| 5 | 0.75s | 171 | 99.5 | 99.0 | 99.7 | 0 | 1 | 104 | 4089 |

**Best: T0/T1/T3 (100% accuracy). T3 is 6x faster than T0 (61 vs 10 ports/s).**  
**Fastest: T5 (171 ports/s, 99.5% accuracy).**

### Recommendations
- **Most balanced SYN**: T1 (100% accuracy, 23 pps, no false opens)
- **Most balanced TCP**: T3 (100% accuracy, 61 pps, default profile)
- **Fastest accurate**: TCP T5 (171 pps, 99.5% accuracy)
- **SYN vs TCP**: TCP Connect is more accurate and faster on this network.
  SYN scan extra overhead (pcap + raw sockets) doesn't pay off on low-latency LAN.
- **false_open = 0 across all profiles**: no port was incorrectly marked as open.

### Limitations
- Cross-subnet LAN only (bridge100 → en5 via macOS routing).
- Includes open and closed ports; no true `filtered` ports.
- Results depend on CPU, kernel, and background load.
- SYN scan on 127.0.0.1 (loopback) does not work: pcap binds eth0, loopback
  traffic goes through lo — responses are never captured.
<!-- PMAP_LOCALHOST_BENCHMARK_END -->
