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

## Loopback benchmark (127.0.0.1)

### TCP Connect (-sT)

| T | 1024 ports | 5000 ports | 65535 ports | PPS (peak) |
|---|-----------|-----------|------------|-----------|
| 3 | 0.025s | 0.046s | — | 109,000/s |
| 5 | 0.006s | 0.033s | **0.24s** | **272,000/s** |

Accuracy: 100%, false_open=0 on all tests.

### SYN scan (-sS)

| T | 128 ports | 1024 ports | Accuracy |
|---|----------|-----------|----------|
| 3 | — | — | ~94% (routed) |
| 5 | 1.3s (69/128 open) | — | ~54% (loopback) |

SYN scan loopback accuracy limited by kernel RST race condition.
Use routed network for reliable SYN results.

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

## 性能基准测试

### Loopback (127.0.0.1) — Connect 扫描

```
pmap -sT -T5 -Pn -p- 127.0.0.1  # 65535 端口
# elapsed: 0.2s
```

| T | 1024 端口 | 5000 端口 | 65535 端口 | PPS | 准确率 |
|---|----------|----------|-----------|-----|--------|
| 3 | 0.025s | 0.046s | — | 109,000/s | 100% |
| 5 | 0.006s | 0.033s | **0.24s** | **272,000/s** | 100% |

### Loopback (127.0.0.1) — SYN 扫描

| T | 128 端口 | 准确率 |
|---|---------|--------|
| 5 | 0.03s | 100% (Linux namespace) |

### 跨子网 (192.168.139.3, macOS host over bridge)

128 ports, 32 open / 96 closed, 3 repeats.

**TCP Connect (-sT) — 全部 100% 准确率**

| T | 耗时 | 端口/秒 | 误报 | 漏报 |
|---|-----:|-------:|:----:|:----:|
| 0 | 5.11s | 25 | 0 | 0 |
| 1 | 5.11s | 25 | 0 | 0 |
| 2 | 3.02s | 42 | 0 | 0 |
| 3 | 2.01s | **64** | 0 | 0 |
| 4 | 1.01s | **127** | 0 | 0 |
| 5 | 0.26s | **492** | 0 | 0 |

**推荐: T3 (100% acc, 64 pps, 默认模板)**

**SYN 扫描 (-sS)**

| T | 耗时 | 端口/秒 | 准确率% | 误报 | 漏报 |
|---|-----:|-------:|--------:|:----:|:----:|
| 0 | 300s* | 0.4 | 57.8 | 0 | 64 |
| 1 | 10.08s | 13 | **99.5** | 0 | 0 |
| 2 | 5.02s | 25 | 88.5 | 0 | 16 |
| 3 | 5.02s | 25 | **95.3** | 0 | 2 |
| 4 | 2.52s | 51 | 70.3 | 0 | 46 |
| 5 | 1.27s | 101 | 75.3 | 0 | 22 |

*T0 受 300s timeout 截断

**推荐: T1 (99.5% acc, 13 pps, 最稳定 SYN)**

### Linux 命名空间网络 (10.210.2.2, 3 段路由)

128 ports, nftables DROP for filtered testing.

| 模式 | T | 耗时 | 准确率 | 开放 | 关闭 |
|------|---|-----:|-------|-----|------|
| sT | 3 | 0.018s | 100% | 32 | 96 |
| sT | 5 | **0.005s** | 100% | 32 | 96 |
| sS | 3 | 5.0s | 90% | 29 | 89 |
| sS | 5 | **0.028s** | 100% | 32 | 96 |

### Nmap 对比 (192.168.139.3, 128 ports)

| 模式 | nmap | pmap | 差异 |
|------|------|------|------|
| sT T3 | 2.67s | **3.0s** | +12% |
| sS T3 | 3.85s | **5.0s** | +30% (1 漏报) |

### 推荐使用场景

| 场景 | 推荐 | 理由 |
|------|------|------|
| 日常扫描 | **sT T3** | 100% acc, 跨平台, 无需 root |
| 快速扫描 | **sT T5** | 65535 端口 0.24s |
| 隐蔽扫描 | **sS T1** | 99.5% acc, 低速低流量 |
| 局域网全端口 | **sT T5** | 492 pps, 100% acc |
| 受控环境 | **sS T5** | 100% acc, namespace 0.028s |

### 架构说明

**Connect 扫描 (-sT)**: 单层 per-host semaphore 控制并发，去除固定延迟。
T3 并发=50, T5=500。65535 端口 ≈0.24s。

**SYN 扫描 (-sS)**: 引擎自 pacing (AIMD)，scan.rs 不介入调度。
Loopback 自动切换 lo 接口。Event-driven waker 替代 per-probe oneshot。

### 限制

- Loopback SYN 准确率受内核 RST 竞争影响，跨网络正常
- 跨子网结果依赖网络条件，仅供参考
- false_open = 0 全部测试（无端口被错误标记为开放）

<!-- PMAP_LOCALHOST_BENCHMARK_END -->
