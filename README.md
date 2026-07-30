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

## 网络基准测试 (192.168.139.3)
<!-- PMAP_LOCALHOST_BENCHMARK_START -->
*目标: 192.168.139.3 (macOS 宿主机, 跨子网)*  
*日期: 2026-07-30*  
*端口: 20000-20127 (128 个端口, 32 开放 / 96 关闭)*  
*重复: 3 次, seed=42, 交错随机顺序*  

### SYN 扫描 (-sS)
| T | 耗时 | 端口/秒 | 准确率% | 开放召回 | 关闭召回 | 误报 | 漏报 | CPU ms/k | 内存 KB |
|---|-----:|-------:|--------:|--------:|--------:|:----:|:----:|---------:|--------:|
| 0 | 10.03s | 13 | 99.0 | 97.9 | 99.0 | 0 | 2 | 286 | 8257 |
| 1 | 5.66s | 23 | **100.0** | 100.0 | 100.0 | 0 | 0 | 234 | 8241 |
| 2 | 5.02s | 25 | 90.4 | 88.5 | 91.0 | 0 | 11 | 156 | 8153 |
| 3 | 5.02s | 25 | 94.0 | 92.7 | 94.4 | 0 | 7 | 156 | 8241 |
| 4 | 2.52s | 51 | 79.9 | 80.2 | 79.9 | 0 | 19 | 104 | 8301 |
| 5 | 1.27s | 101 | 77.1 | 75.0 | 77.8 | 0 | 24 | 104 | 8284 |

**最平衡: T1 (100% 准确率, 23 端口/秒).**  
**最快: T5 (101 端口/秒, 77% 准确率 — 速度牺牲准确率).**

### TCP Connect 扫描 (-sT)
| T | 耗时 | 端口/秒 | 准确率% | 开放召回 | 关闭召回 | 误报 | 漏报 | CPU ms/k | 内存 KB |
|---|-----:|-------:|--------:|--------:|--------:|:----:|:----:|---------:|--------:|
| 0 | 13.07s | 10 | **100.0** | 100.0 | 100.0 | 0 | 0 | 78 | 4139 |
| 1 | 6.03s | 21 | **100.0** | 100.0 | 100.0 | 0 | 0 | 78 | 4139 |
| 2 | 2.51s | 51 | 99.7 | 100.0 | 99.7 | 0 | 0 | 104 | 4207 |
| 3 | 2.11s | 61 | **100.0** | 100.0 | 100.0 | 0 | 0 | 26 | 4165 |
| 4 | 1.56s | 82 | 99.5 | 100.0 | 99.3 | 0 | 0 | 52 | 4172 |
| 5 | 0.75s | 171 | 99.5 | 99.0 | 99.7 | 0 | 1 | 104 | 4089 |

**最平衡: T0/T1/T3 (100% 准确率). T3 比 T0 快 6 倍 (61 vs 10 端口/秒).**  
**最快: T5 (171 端口/秒, 99.5% 准确率).**

### 推荐
- **SYN 最平衡**: T1 (100% 准确率, 23 pps, 无误报)
- **TCP 最平衡**: T3 (100% 准确率, 61 pps, 默认模板)
- **最快且准确**: TCP T5 (171 pps, 99.5% 准确率)
- **SYN vs TCP**: 在此网络上 TCP Connect 更准确且更快。
  SYN 扫描的额外开销 (pcap + 原始套接字) 在低延迟局域网中没有优势。
- **所有 profile 误报率 = 0**: 没有端口被错误标记为开放。

### 限制
- 仅跨子网局域网 (bridge100 → en5 经 macOS 路由).
- 包含开放和关闭端口; 不含真实 filtered 端口。
- 结果取决于 CPU、内核和后台负载。
- SYN 扫描在 127.0.0.1 (loopback) 上不可用: pcap 绑定 eth0,
  loopback 走 lo——响应无法被捕获。
<!-- PMAP_LOCALHOST_BENCHMARK_END -->
