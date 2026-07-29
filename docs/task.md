# pmap 跨平台 TCP 端口扫描器开发 Plan

## 0. 项目目标

开发一个名为 `pmap` 的跨平台 Rust CLI 端口扫描器。

项目定位：

* 专注 TCP 端口发现
* 支持 Windows、Linux、macOS
* 支持多主机、多端口和 CIDR
* 扫描过程中实时输出发现结果
* 扫描结束后输出按 IP、端口排序的最终结果
* 输出简洁、稳定、文本解析友好
* 支持 SYN 扫描和 TCP Connect 扫描
* 优先保证开放端口召回率和结果可信度
* 不做服务识别、版本探测、漏洞扫描和 Banner 抓取

优先级：

```text
开放端口召回率
> 结果可信度
> 扫描速度
> 跨平台一致性
> 资源占用
```

仅用于用户拥有或明确获得授权的目标。

---

# 1. 必须固定的 CLI 契约

CLI 风格参考 Nmap，但不要复制 Nmap 的全部功能。

基本语法：

```bash
pmap [SCAN TYPE] [OPTIONS] <TARGETS>...
```

第一版只实现以下参数：

```text
SCAN TYPE:
  -sS                   TCP SYN scan
  -sT                   TCP connect scan

TARGET:
  <TARGETS>...          IP、CIDR 或主机名
  -iL <FILE>            从文件读取目标

PORT:
  -p <PORTS>            指定端口，例如 22,80,443 或 1-1024
  -p-                   扫描 1-65535

TIMING:
  -T0 .. -T5            扫描速度模板，默认 -T3

OUTPUT:
  --open                只显示并保存 open 结果
  -oN <FILE>            普通文本输出
  -oJ <FILE>            完整 JSON 输出
  -oJL <FILE>           实时 JSON Lines 输出
  -oA <PREFIX>          同时生成 .txt、.json、.jsonl

GENERAL:
  -h, --help
  -V, --version
```

不要加入以下参数：

```text
--timeout
--retries
--rate
--global-concurrency
--host-concurrency
--port-concurrency
--show-closed
--show-unreachable
--show-filtered
--no-progress
--no-color
--engine
--profile
```

这些全部由程序内部策略自动管理。

---

# 2. 扫描类型行为

## 2.1 `-sT`

TCP Connect 扫描。

必须支持：

* Windows
* Linux
* macOS
* 普通用户权限
* IPv4

状态证据：

```text
连接成功
→ open / confirmed

ConnectionRefused
→ closed / confirmed

明确 host/network unreachable
→ unreachable / high

超时或没有足够证据
→ unknown / low

本地资源错误
→ local error，不得归入 closed、unreachable 或 unknown
```

## 2.2 `-sS`

TCP SYN 半开扫描。

平台后端：

```text
Linux:
  AF_PACKET 或 raw socket

macOS:
  BPF 或 libpcap 后端

Windows:
  Npcap 后端
```

SYN 状态证据：

```text
有效 SYN-ACK
→ open / high

有效 RST
→ closed / high

明确过滤类 ICMP
→ filtered / high

明确 host/network unreachable ICMP
→ unreachable / high

重试后仍无响应
→ unknown / low
```

## 2.3 不允许静默改变扫描类型

用户明确指定：

```bash
pmap -sS ...
```

但当前系统缺少权限、Npcap 或后端能力时，必须直接报错：

```text
pmap: SYN scan is unavailable on this system
```

同时给出简短提示：

```text
try running with sufficient privileges or use -sT
```

禁止静默回退到 `-sT`，否则用户无法判断结果语义。

如果用户没有指定扫描类型，第一版默认：

```text
-sT
```

这样三平台默认行为一致、无需额外权限。

---

# 3. 目标解析

必须支持：

```bash
pmap 192.168.1.10
pmap 192.168.1.10 192.168.1.20
pmap 192.168.1.0/24
pmap example.com
pmap example.com 10.0.0.0/28
pmap -iL targets.txt
```

命令行目标和 `-iL` 可以同时使用：

```bash
pmap 192.168.1.10 -iL targets.txt
```

处理流程：

```text
读取位置参数
+
读取 -iL 文件
↓
忽略空行和 # 注释
↓
解析 IP、CIDR、主机名
↓
展开 CIDR
↓
解析主机名
↓
按照最终 IP 去重
```

目标文件示例：

```text
192.168.1.10
192.168.1.0/28
example.com

# internal servers
10.0.0.5
```

注意事项：

1. 一个主机名可能解析出多个 IP，必须全部扫描。
2. 不同主机名可能解析到同一 IP，必须去重。
3. 输入 IP 时不要做反向 DNS。
4. 单个主机名解析失败不能终止全部扫描。
5. 所有目标均无效时才返回参数或输入错误。
6. CIDR 过大时必须防止意外展开。

建议限制：

```text
默认最多展开 65536 个目标
超过时直接报错
```

第一版不需要增加 `--force`，避免继续扩展参数；错误信息中明确提示目标范围过大。

---

# 4. 端口解析

必须支持：

```bash
pmap 192.168.1.10 -p 443
pmap 192.168.1.10 -p 22,80,443
pmap 192.168.1.10 -p 1-1024
pmap 192.168.1.10 -p 22,80,443,8000-9000
pmap 192.168.1.10 -p-
```

规则：

```text
端口范围：1..=65535
逗号分隔
短横线表示范围
-p- 表示 1-65535
重复端口自动去重
非法范围直接报错
```

不指定 `-p` 时：

```text
扫描内置常见 1000 个 TCP 端口
```

第一版不支持：

```text
服务名端口，例如 http、https
T:80,443
U:53
--top-ports
-F
```

内部端口顺序：

```text
用户明确输入的顺序优先
全端口扫描时使用常见端口优先顺序
然后扫描其余端口
```

最终结果排序与扫描顺序无关。

---

# 5. 状态与置信度模型

## 5.1 状态

内部必须支持：

```rust
enum PortState {
    Pending,
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unknown,
}
```

用户可见的最终结果默认只展开：

```text
open
filtered
unknown
```

以下状态不显示明细：

```text
closed
unreachable
```

但必须进入统计：

```text
# closed: N
# unreachable: N
```

## 5.2 置信度

```rust
enum Confidence {
    Confirmed,
    High,
    Medium,
    Low,
}
```

推荐映射：

```text
Connect success
→ open / confirmed

SYN-ACK + Connect success
→ open / confirmed

有效 SYN-ACK
→ open / high

Connect refused
→ closed / confirmed

有效 RST
→ closed / high

明确 ICMP filtered
→ filtered / high

明确 unreachable
→ unreachable / high

重复超时
→ unknown / low

证据互相矛盾
→ 保留较强状态，并降低为 medium
```

## 5.3 证据优先级

必须实现：

```text
ConnectSuccess
>
SynAck
>
ConnectRefused / Reset
>
明确 ICMP
>
Timeout
```

超时不是强证据，不能覆盖已有状态：

```text
Open + Timeout
→ Open

Closed + Timeout
→ Closed

Filtered + Timeout
→ Filtered
```

新证据只能推动状态演化，不得无条件覆盖旧结果。

---

# 6. `--open` 的严格行为

`--open` 表示：

```text
终端实时输出只包含 open
终端最终结果只包含 open
-oN 只包含 open
-oJ results 数组只包含 open
-oJL 只写 open 端口事件和扫描生命周期事件
-oA 生成的所有结果文件均只包含 open 明细
```

即使启用了 `--open`，summary 仍然必须包含所有状态的数量：

```text
# open: 17
# closed: 312
# filtered: 104
# unreachable: 357
# unknown: 65100
```

这样用户既能获得纯开放端口列表，也能判断扫描完整度。

## 6.1 默认模式

未指定 `--open` 时，终端实时阶段仍然只输出 open。

扫描完成后的完整结果默认展开：

```text
open
filtered
unknown
```

不展开：

```text
closed
unreachable
```

原因：

* closed 数量通常极大
* unreachable 属于主机或路径结果，逐端口显示价值低
* 大量输出会严重拖慢扫描
* 用户主要关心开放端口和不确定结果

## 6.2 默认输出过滤表

| 状态          | 实时终端 | 最终终端 | `-oN` | `-oJ` | `-oJL` |
| ----------- | ---: | ---: | ----: | ----: | -----: |
| open        |    是 |    是 |     是 |     是 |      是 |
| filtered    |    否 |    是 |     是 |     是 |      是 |
| unknown     |    否 |    是 |  是或压缩 |  是或压缩 |      否 |
| closed      |    否 |    否 |     否 |     否 |      否 |
| unreachable |    否 |    否 |     否 |     否 |      否 |

启用 `--open` 后，只有 open 明细保留。

---

# 7. 终端实时输出

执行：

```bash
pmap -sS 192.0.2.0/24 -p-
```

实时输出：

```text
192.0.2.10	22/tcp	open	high	11ms
192.0.2.10	80/tcp	open	confirmed	8ms
192.0.2.15	443/tcp	open	high	27ms
192.0.2.18	3306/tcp	open	high	16ms
```

固定格式：

```text
<IP>\t<PORT>/tcp\t<STATE>\t<CONFIDENCE>\t<RTT>
```

必须使用 TAB 分隔。

禁止默认加入：

```text
[+]
图标
Emoji
服务名
时间戳
探测阶段
冗长说明
```

RTT 格式：

```text
小于 1ms：
  0.8ms

普通毫秒：
  11ms

超过 1 秒：
  1.24s

无 RTT：
  -
```

实时输出规则：

1. 一个端口首次进入 `open` 时立即打印。
2. 同一端口不得重复打印。
3. 后续从 `high` 升级为 `confirmed` 时，默认不再打印。
4. 最终结果显示最新状态、最高置信度和最佳 RTT。
5. 实时结果按发现顺序，不要求排序。
6. 输出必须通过单独输出任务处理，探测引擎不得直接写 stdout。

---

# 8. 最终终端输出

默认模式示例：

```text
192.0.2.10	22/tcp	open	high	11ms
192.0.2.10	80/tcp	open	confirmed	8ms
192.0.2.15	443/tcp	open	high	27ms

# complete results (sorted)
* 192.0.2.10	22/tcp	open	high	11ms
* 192.0.2.10	80/tcp	open	confirmed	8ms
* 192.0.2.15	443/tcp	open	high	27ms
* 192.0.2.20	443/tcp	filtered	high	31ms
* 192.0.2.21	8080/tcp	unknown	low	-

# summary
# hosts: 254
# ports: 16645890
# open: 17
# closed: 312
# filtered: 104
# unreachable: 357
# unknown: 16645100
# elapsed: 38.7s
```

使用 `--open`：

```bash
pmap -sS 192.0.2.0/24 -p- --open
```

输出：

```text
192.0.2.10	22/tcp	open	high	11ms
192.0.2.10	80/tcp	open	confirmed	8ms
192.0.2.15	443/tcp	open	high	27ms

# complete results (sorted)
* 192.0.2.10	22/tcp	open	high	11ms
* 192.0.2.10	80/tcp	open	confirmed	8ms
* 192.0.2.15	443/tcp	open	high	27ms

# summary
# hosts: 254
# ports: 16645890
# open: 17
# closed: 312
# filtered: 104
# unreachable: 357
# unknown: 16645100
# elapsed: 38.7s
```

排序规则：

```text
IP 数值升序
→ 端口数值升序
→ 协议
```

禁止使用字符串排序 IP。

---

# 9. 大量 unknown 的处理

这是必须重点处理的问题。

例如：

```text
254 hosts × 65535 ports
= 16,645,890 个端口
```

如果大部分端口是 unknown，逐条保存和打印会造成：

* 巨量内存使用
* 数 GB 输出文件
* 最终排序很慢
* 输出耗时可能超过扫描耗时
* JSON 文件极大

因此必须实现压缩策略。

## 9.1 内部状态存储

对每个主机建议使用位图或紧凑数组：

```text
open bitmap
closed bitmap
filtered bitmap
unreachable bitmap
unknown bitmap
```

或者：

```rust
Vec<CompactPortState>
```

不要为每个端口保存大型 `PortRecord`。

只有以下端口保存完整证据：

```text
open
filtered
有冲突的端口
具有 RTT 的明确响应
```

closed、unreachable 和普通 unknown 只需要紧凑状态和计数。

## 9.2 文本输出 unknown 压缩

默认最终终端和 `-oN` 中，unknown 应按范围压缩：

```text
* 192.0.2.10	1-21,23-79,81-442/tcp	unknown	low	-
```

但不要把 open 端口混入 unknown 范围。

更清晰的推荐格式：

```text
* 192.0.2.10	unknown	1-21,23-79,81-442,444-65535
```

最终固定使用后一种：

```text
* <IP>\tunknown\t<PORT-RANGES>
```

示例：

```text
* 192.0.2.10	unknown	1-21,23-79,81-442,444-65535
```

`--open` 模式不输出 unknown 范围。

## 9.3 JSON unknown 压缩

JSON 中不要逐条输出 unknown。

使用：

```json
{
  "ip": "192.0.2.10",
  "unknown_ranges": [
    [1, 21],
    [23, 79],
    [81, 442],
    [444, 65535]
  ]
}
```

`--open` 模式不写入 `unknown_ranges`。

---

# 10. 输出文件设计

## 10.1 `-oN`

命令：

```bash
pmap -sS 192.0.2.0/24 -p- -oN scan.txt
```

写入最终排序结果。

文件中不包含 ANSI 颜色和动态进度。

默认：

```text
# pmap 0.1.0
# completed: true

192.0.2.10	22/tcp	open	high	11ms
192.0.2.10	80/tcp	open	confirmed	8ms
192.0.2.20	443/tcp	filtered	high	31ms
192.0.2.21	unknown	1-21,23-79,81-65535

# hosts: 254
# ports: 16645890
# open: 17
# closed: 312
# filtered: 104
# unreachable: 357
# unknown: 16645100
# elapsed: 38.7s
```

使用 `--open`：

```text
192.0.2.10	22/tcp	open	high	11ms
192.0.2.10	80/tcp	open	confirmed	8ms
```

仍保留 summary。

## 10.2 `-oJ`

最终完整 JSON。

必须包含：

```json
{
  "schema_version": 1,
  "scanner": {},
  "scan": {},
  "targets": {},
  "results": [],
  "unknown": [],
  "summary": {}
}
```

默认 `results` 包含：

```text
open
filtered
```

不包含：

```text
closed
unreachable
```

unknown 使用范围压缩。

启用 `--open` 后：

```text
results 只包含 open
unknown 字段为空数组或省略
summary 仍保留全部计数
```

从第一版开始固定：

```text
schema_version: 1
```

## 10.3 `-oJL`

实时 JSON Lines 文件。

开始事件：

```json
{"type":"scan_started","hosts":254,"ports":16645890,"scan_type":"syn"}
```

开放端口事件：

```json
{"type":"port","ip":"192.0.2.10","port":22,"protocol":"tcp","state":"open","confidence":"high","rtt_ms":11}
```

filtered 事件：

```json
{"type":"port","ip":"192.0.2.20","port":443,"protocol":"tcp","state":"filtered","confidence":"high","rtt_ms":31}
```

结束事件：

```json
{"type":"scan_completed","completed":true,"hosts":254,"ports":16645890,"open":17,"closed":312,"filtered":104,"unreachable":357,"unknown":16645100,"elapsed_ms":38700}
```

默认 JSONL 写：

```text
scan_started
open 事件
filtered 事件
scan_completed
```

不写：

```text
closed
unreachable
每个 unknown
```

使用 `--open` 时：

```text
scan_started
open 事件
scan_completed
```

## 10.4 `-oA`

命令：

```bash
pmap -sS 192.0.2.0/24 -p- -oA scans/internal
```

生成：

```text
scans/internal.txt
scans/internal.json
scans/internal.jsonl
```

`--open` 必须同时影响三个文件：

```bash
pmap -sS 192.0.2.0/24 -p- --open -oA scans/internal
```

所有明细文件都只保存 open。

---

# 11. 扫描调度架构

禁止为每个目标端口一次性创建 Tokio Task。

错误方式：

```text
254 × 65535
= 16,645,890 个 Tokio Task
```

正确结构：

```text
Target Iterator
    ↓
Per-host Port Iterator
    ↓
Fair Scheduler
    ↓
Bounded Probe Queue
    ↓
Fixed Worker Pool / FuturesUnordered
```

必须有：

```text
全局活跃探测上限
单主机活跃探测上限
同时活跃主机上限
有界任务队列
有界证据队列
有界输出队列
```

## 11.1 多主机公平调度

采用轮询或加权轮询：

```text
Host A: port 22
Host B: port 22
Host C: port 22
Host A: port 80
Host B: port 80
Host C: port 80
```

不要先扫完一台主机再扫描下一台。

目标：

* 多主机都能尽早发现开放端口
* 慢主机不会占满全部资源
* 实时输出更均匀
* 单一过滤目标不会拖垮全部扫描

## 11.2 重试优先级

队列优先级：

```text
首次高价值端口
>
首次普通端口
>
开放端口验证
>
冲突复核
>
普通超时重试
```

但是为了开放端口召回率，最终必须确保超时端口能够进入补扫队列。

---

# 12. `-T0` 到 `-T5`

用户只选择扫描节奏，内部参数不暴露。

建议语义：

```text
-T0
极保守，低并发，长超时，多次重试

-T1
很慢，适合不稳定链路

-T2
低速、低资源占用

-T3
默认，平衡召回率和速度

-T4
高速，适合稳定局域网

-T5
极高速，可能增加 unknown 和漏报风险
```

内部策略结构：

```rust
struct TimingPolicy {
    global_concurrency: usize,
    active_hosts: usize,
    per_host_concurrency: usize,

    initial_timeout: Duration,
    max_timeout: Duration,
    retry_count: u8,

    retry_backoff: f32,
    overload_backoff: f32,
}
```

不要把 `-T` 直接映射成固定死参数。

运行时必须允许自适应：

```text
本地资源压力升高
→ 降低全局并发

单主机超时率升高
→ 降低该主机并发

RTT P95 上升
→ 增加该主机超时

网络恢复
→ 缓慢恢复速度
```

---

# 13. 状态中枢

采用单一状态归并任务：

```text
Probe Workers
    ↓
Evidence Channel
    ↓
State Reducer
    ├── Live Output Event
    ├── JSONL Event
    ├── Metrics
    └── Final Result Store
```

探测引擎只能产生证据：

```rust
enum ProbeEvidence {
    SynAck { rtt: Duration },
    Reset { rtt: Duration },
    ConnectSuccess { rtt: Duration },
    ConnectRefused { rtt: Duration },
    IcmpFiltered { code: u8 },
    HostUnreachable,
    NetworkUnreachable,
    Timeout,
    LocalResourceExhausted,
    PermissionDenied,
    Cancelled,
}
```

引擎不能直接决定最终状态。

状态中枢负责：

* 状态迁移
* 置信度计算
* RTT 更新
* 证据冲突处理
* 实时 open 去重
* 汇总计数
* 最终结果存储
* 输出过滤

---

# 14. SYN 响应关联

SYN 扫描必须避免把旧包或无关流量识别为扫描响应。

建议生成 sequence cookie：

```text
cookie = keyed_hash(
    secret,
    target_ip,
    target_port,
    source_ip,
    source_port,
    scan_epoch
)
```

收到 SYN-ACK 时验证：

```text
ack_number - 1 == cookie
```

同时验证：

* 响应源 IP
* 响应源端口
* 本地目标端口
* TCP flags
* 当前扫描批次
* 包长度
* IPv4/TCP 首部长度
* 校验和或抓包后端提供的校验状态

必须正确处理：

* 重复 SYN-ACK
* 乱序响应
* 旧扫描响应
* 无关网络流量
* 截断数据包
* TCP options

---

# 15. Connect 引擎资源保护

Connect 扫描在高并发下容易遇到：

* 文件描述符耗尽
* 本地临时端口耗尽
* `Too many open files`
* `Cannot assign requested address`
* Windows Socket 资源不足

这些错误绝不能被判为目标 closed 或 unknown。

处理方式：

```text
检测本地资源错误
→ 暂停产生新连接
→ 降低全局并发
→ 等待已有连接结束
→ 延迟后重试
→ 记录一次警告
```

必须限制：

```text
global active connections
per-host active connections
connection creation rate
```

Socket 建立成功后立即关闭，不进行应用层通信。

---

# 16. RTT 规则

每个端口记录：

```text
best_rtt
last_rtt
```

默认输出使用：

```text
best_rtt
```

原因：

* 重试可能受到瞬时拥塞影响
* 最佳有效响应更接近路径基础延迟
* 后续 Connect 验证可能比 SYN RTT 更稳定

但 JSON 中可以同时保留：

```json
{
  "rtt_ms": 8,
  "last_rtt_ms": 11
}
```

第一版终端只显示一个 RTT。

---

# 17. stdout 与 stderr

必须严格分离。

stdout：

```text
实时端口结果
最终排序结果
summary
```

stderr：

```text
动态进度
警告
权限错误
DNS 解析失败
输出文件错误
后端诊断
```

当 stdout 不是 TTY：

* 禁止 ANSI 颜色
* 保持 TAB 分隔
* 不输出动态控制字符

当 stderr 是 TTY：

```text
Scanning 18/254 hosts · 174021/16645890 ports · 2481/s · 12 open
```

动态进度最多每秒刷新 5 次。

不要提供进度参数，程序自动处理。

---

# 18. 输出性能

输出任务必须独立，禁止扫描 Worker 直接打印。

结构：

```text
State Reducer
    ↓
Bounded Output Channel
    ↓
Output Task
    ↓
BufWriter
```

实时输出刷新策略：

```text
最多积累 16 行
或最多等待 20ms
任一条件满足即 flush
```

这样兼顾实时性和系统调用开销。

若输出队列接近满：

```text
不得丢弃 open 事件
可以降低探测调度速度
```

开放端口结果优先级高于进度事件。

---

# 19. 中断处理

收到 Ctrl+C：

```text
停止生成新任务
→ 取消等待队列
→ 给在途任务短暂收敛
→ 状态中枢处理已完成证据
→ 写出合法的部分结果
→ completed = false
→ 输出部分 summary
→ 退出码 130
```

终端：

```text
# scan interrupted

# complete results (sorted)
* 192.0.2.10	22/tcp	open	high	11ms

# summary
# completed: false
# progress: 41.8%
# hosts: 254
# open: 1
# closed: 104
# filtered: 3
# unreachable: 2
# unknown: 78120
# elapsed: 12.4s
```

输出文件要求：

* `-oN` 必须是合法文本
* `-oJ` 必须是合法 JSON
* `-oJL` 必须保证已写行完整
* `completed` 必须为 `false`

---

# 20. 文件写入可靠性

## 20.1 JSON

不要扫描过程中直接写未闭合 JSON 数组。

正确流程：

```text
扫描期间维护紧凑状态
完成或中断时写 file.tmp
flush
尽可能 fsync
rename 到正式文件
```

## 20.2 JSONL

可以实时追加。

每一行必须完整有效。

开放端口事件应及时 flush。

## 20.3 文本

扫描结束后根据最终状态排序写入。

不要先写无序内容，再在同一文件中追加有序内容。

---

# 21. 推荐项目目录

```text
pmap/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── CHANGELOG.md
│
├── src/
│   ├── main.rs
│   ├── lib.rs
│   │
│   ├── cli/
│   │   ├── mod.rs
│   │   ├── args.rs
│   │   └── timing.rs
│   │
│   ├── config/
│   │   ├── mod.rs
│   │   └── scan_config.rs
│   │
│   ├── target/
│   │   ├── mod.rs
│   │   ├── parser.rs
│   │   ├── resolver.rs
│   │   └── input_file.rs
│   │
│   ├── port/
│   │   ├── mod.rs
│   │   ├── parser.rs
│   │   ├── common.rs
│   │   └── ranges.rs
│   │
│   ├── model/
│   │   ├── mod.rs
│   │   ├── endpoint.rs
│   │   ├── evidence.rs
│   │   ├── state.rs
│   │   ├── confidence.rs
│   │   ├── result.rs
│   │   └── summary.rs
│   │
│   ├── engine/
│   │   ├── mod.rs
│   │   ├── traits.rs
│   │   ├── connect/
│   │   │   ├── mod.rs
│   │   │   ├── engine.rs
│   │   │   └── error_map.rs
│   │   └── syn/
│   │       ├── mod.rs
│   │       ├── packet.rs
│   │       ├── checksum.rs
│   │       ├── cookie.rs
│   │       ├── linux.rs
│   │       ├── macos.rs
│   │       └── windows.rs
│   │
│   ├── scheduler/
│   │   ├── mod.rs
│   │   ├── scheduler.rs
│   │   ├── fair_queue.rs
│   │   ├── limiter.rs
│   │   └── retry.rs
│   │
│   ├── state/
│   │   ├── mod.rs
│   │   ├── reducer.rs
│   │   ├── store.rs
│   │   └── compact_ports.rs
│   │
│   ├── event/
│   │   ├── mod.rs
│   │   ├── scan_event.rs
│   │   └── bus.rs
│   │
│   ├── output/
│   │   ├── mod.rs
│   │   ├── terminal.rs
│   │   ├── normal.rs
│   │   ├── json.rs
│   │   ├── jsonl.rs
│   │   ├── filter.rs
│   │   └── progress.rs
│   │
│   └── platform/
│       ├── mod.rs
│       ├── privileges.rs
│       ├── limits.rs
│       └── terminal.rs
│
├── tests/
│   ├── cli.rs
│   ├── target_parser.rs
│   ├── port_parser.rs
│   ├── state_reducer.rs
│   ├── output_filter.rs
│   ├── output_sort.rs
│   ├── output_json.rs
│   ├── output_jsonl.rs
│   ├── connect_scan.rs
│   └── cancellation.rs
│
├── benches/
│   ├── scheduler.rs
│   ├── state_store.rs
│   ├── port_ranges.rs
│   └── output.rs
│
└── .github/
    └── workflows/
        ├── ci.yml
        └── release.yml
```

---

# 22. 开发阶段

## M0：项目骨架

完成：

* Cargo 项目
* CLI 骨架
* 错误模型
* tracing
* 三平台 CI
* README 基础说明

验收：

```bash
pmap --help
pmap --version
cargo test
```

## M1：目标与端口解析

完成：

* IP
* CIDR
* 主机名
* `-iL`
* `-p`
* `-p-`
* 去重
* 常见 1000 端口

重点测试边界输入。

## M2：状态模型与输出过滤

完成：

* PortState
* Confidence
* ProbeEvidence
* State Reducer
* `--open`
* closed/unreachable 不显示
* summary 统计完整

这一步必须在扫描引擎前完成，避免输出逻辑散落到各模块。

## M3：跨平台 Connect 引擎

完成：

* Tokio TcpStream
* 超时
* 重试
* 错误映射
* 本地资源保护
* 单主机扫描

验收：

* 开放端口实时输出
* 最终排序
* `--open` 正确
* closed/unreachable 不展开

## M4：多主机公平调度

完成：

* 流式任务生成
* 有界队列
* Round Robin
* 三层并发限制
* `-T0..5`

验收：

* 不一次创建全部任务
* 多主机公平推进
* 慢主机不阻塞其他主机

## M5：文本和结构化输出

完成：

* 默认终端
* `-oN`
* `-oJ`
* `-oJL`
* `-oA`
* unknown 范围压缩
* schema version
* 原子文件写入

## M6：取消、进度和稳定性

完成：

* Ctrl+C
* 部分结果
* completed=false
* stderr 进度
* TTY 自动判断
* 输出背压
* DNS 部分失败

## M7：Linux SYN 引擎

完成：

* 数据包构造
* checksum
* sequence cookie
* 发送
* 接收
* 响应关联
* RST/SYN-ACK/ICMP
* 权限检查

## M8：macOS 和 Windows SYN 后端

完成：

* macOS BPF/libpcap
* Windows Npcap
* 后端能力检查
* 安装和权限说明

不得影响 `-sT` 的跨平台稳定性。

## M9：性能与发布

完成：

* Benchmark
* 内存优化
* Release profile
* Windows/Linux/macOS 二进制
* Shell completion
* GitHub Release

---

# 23. 必须测试的行为

## CLI

```text
-sS 和 -sT 同时出现必须报错
缺少目标必须报错
-p- 正确展开
无效端口报错
-iL 不存在报错
-oA 路径冲突报错
```

## 状态

```text
ConnectSuccess → open confirmed
SynAck → open high
Timeout 不覆盖 open
Reset → closed high
unreachable 不显示但进入 summary
closed 不显示但进入 summary
```

## `--open`

必须分别测试：

```text
默认终端
-oN
-oJ
-oJL
-oA
Ctrl+C 部分结果
```

确认所有明细都只有 open，但 summary 仍完整。

## 排序

```text
192.0.2.2 必须排在 192.0.2.10 前
端口 80 必须排在 443 前
实时输出可以无序
最终输出必须有序
```

## 大规模扫描

验证：

```text
/24 × 65535
```

不能：

* 一次创建全部任务
* 为每个端口创建大型对象
* 为 closed 保存完整证据
* 为 unknown 逐条写 JSON
* 因输出阻塞扫描

## 中断

验证：

```text
终端结果合法
JSON 合法
JSONL 行完整
summary completed=false
退出码 130
```

---

# 24. 第一版验收标准

必须通过以下命令：

```bash
pmap 127.0.0.1
pmap -sT 127.0.0.1 -p 22,80,443
pmap -sT 192.168.1.0/24 -p-
pmap -sT -iL targets.txt -p 1-1024
pmap -sT 192.168.1.0/24 -p- --open
pmap -sT 192.168.1.0/24 -p- -oN scan.txt
pmap -sT 192.168.1.0/24 -p- -oJ scan.json
pmap -sT 192.168.1.0/24 -p- -oJL scan.jsonl
pmap -sT 192.168.1.0/24 -p- --open -oA scan
```

最终结果必须满足：

* 开放端口实时出现
* 每个开放端口实时只出现一次
* 最终按 IP、端口排序
* closed 不显示
* unreachable 不显示
* filtered 和 unknown 默认显示
* `--open` 后只显示 open
* summary 永远包含全部状态计数
* `-oN`、`-oJ`、`-oJL`、`-oA` 语义一致
* Windows、Linux、macOS 的 `-sT` 行为一致
* SYN 后端不可用时不静默回退
* 大规模扫描内存有界
* Ctrl+C 后仍输出合法部分结果

---

# 25. 实现时禁止做的事情

1. 不要一次性为所有目标端口创建 Tokio Task。
2. 不要让扫描 Worker 直接打印 stdout。
3. 不要将 Timeout 判断为 Closed。
4. 不要将本地 Socket 资源错误判断为目标状态。
5. 不要静默把 `-sS` 改成 `-sT`。
6. 不要默认显示 closed 和 unreachable 明细。
7. 不要在 `--open` 模式下把 filtered 或 unknown 写入任何输出文件。
8. 不要让 `--open` 删除 summary 中的其他状态数量。
9. 不要对 IP 地址进行字符串排序。
10. 不要逐条存储和输出数百万 unknown。
11. 不要让 JSON 文件在中断后变成非法 JSON。
12. 不要在实时结果中加入图标、服务名或非固定字段。
13. 不要让输出 I/O 阻塞数据包接收或连接调度。
14. 不要在第一版增加服务识别、UDP、脚本引擎等范围外功能。
15. 不要为了代码复用强行统一不同平台 SYN 后端的所有底层细节；统一的是接口和证据模型。

---

# 26. 推荐实现顺序

严格按照以下顺序：

```text
CLI 契约
→ 目标与端口解析
→ 状态和证据模型
→ 输出过滤与 --open
→ 单主机 Connect
→ 实时输出
→ 最终排序
→ 多主机公平调度
→ -T0..5
→ -oN
→ -oJ
→ -oJL
→ -oA
→ unknown 范围压缩
→ Ctrl+C
→ 资源保护
→ Linux SYN
→ macOS SYN
→ Windows SYN
→ 性能优化
```

不要先实现 SYN 发包，再补状态机和输出。状态中枢和输出契约必须先稳定，因为所有扫描后端最终都要服从同一套状态、过滤和输出规则。

