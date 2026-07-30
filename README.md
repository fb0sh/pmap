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
  "scanner": { "name": "pmap", "version": "0.1.0" },
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
├── scheduler/           # 调度器（轮询、时序策略）
└── output/              # 输出（终端、文件、JSON）
```

## 依赖

- `tokio` — 异步运行时
- `clap` — 命令行参数解析
- `serde` / `serde_json` — JSON 序列化
- `anyhow` — 错误处理

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
[syn-recv] send_socket fd=9, recv_socket fd=10
[syn-recv] receiver_loop: started, fd=10
[syn-recv] sent SYN to 192.168.1.1:80 src_port=40000 seq=3569752726 (40 bytes)
[syn-recv] [pkt#1] 192.168.1.1:80 → 192.168.1.100:40000 flags=SYNACK seq=123 ack=3569752727
[syn-recv] dispatched: SynAck { rtt: 1.2ms }
```

日志含义：
- `send_socket` / `recv_socket` — 发送和接收 socket 的文件描述符
- `sent SYN` — SYN 包已发送（目标、源端口、序列号、字节数）
- `[pkt#N]` — 收到的第 N 个网络包（源:端口 → 目标:端口 flags 序列号）
- `dispatched` — 响应已成功匹配并分发给对应的探测任务
- `recv WouldBlock` — 接收 socket 暂无数据（正常轮询）

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
