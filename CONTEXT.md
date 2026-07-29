# pmap

一个跨平台 TCP 端口扫描器，用于发现目标主机上开放的 TCP 端口。

## Language

### 端口状态

**PortState（端口状态）**：
端口探测后得出的结论。包含 Open、Closed、Filtered、Unreachable、Unknown 五个值。Pending 是纯内部值，不属于领域语言。
_Avoid_: Status, Result, Condition

**Open**：
目标端口接受了 TCP 连接（Connect 扫描）或回复了 SYN-ACK（SYN 扫描），表明有服务在监听。
_Avoid_: Listening, Active

**Closed**：
目标端口明确拒绝了连接（ConnectionRefused）或回复了 RST，表明没有服务在该端口监听。
_Avoid_: Refused, Denied

**Filtered**：
探测包被防火墙或中间设备丢弃，无法确定端口是开放还是关闭。
_Avoid_: Blocked, Dropped

**Unreachable**：
目标主机或网络不可达，通常是 ICMP host/network unreachable 响应。
_Avoid_: Down, Unavailable

**Unknown**：
重试后仍无响应，缺乏足够证据得出结论。
_Avoid_: Timeout, NoResponse

### 置信度

**Confidence（置信度）**：
对 PortState 判断的确信程度。包含 Confirmed、High、Medium、Low 四个值。
_Avoid_: Certainty, Reliability

**Confirmed**：
最高等级。Connect 扫描连接成功，或 SYN 扫描收到 SYN-ACK 且 Connect 验证通过。

**Medium（降级）**：
同一端口收到两个互相冲突的强证据（如 SYN-ACK vs ICMP Filtered），保留较强状态但降为 Medium。
_Avoid_: Conflicted, Degraded

### 扫描与探测

**Scan（扫描）**：
一次完整的 pmap 命令执行，从用户输入到结果输出。包含所有目标和所有端口。
_Avoid_: Run, Execution, Task

**Probe（探测）**：
对单个 Host:Port 的一次或多次发包和收包，用于收集 PortState 证据。
_Avoid_: Check, Ping, Sweep

**ScanType（扫描类型）**：
用户指定的探测策略，决定 Probe 如何与目标交互。包含 SYN scan（-sS）和 Connect scan（-sT），默认 -sT。缺少能力时报错，禁止静默回退。
_Avoid_: Mode, Method, Strategy

### 目标与主机

**Target（目标）**：
用户输入的原始值，可以是 IP 地址、CIDR 段或主机名。是解析前的概念。
_Avoid_: Input, Spec

**Host（主机）**：
Target 解析后的一个具体 IP 地址。是扫描和结果的基本单位。多个 Target 可以解析到同一个 Host（去重后只扫描一次）。
_Avoid_: IP, Endpoint, Address

### 证据与结果

**Evidence（证据）**：
一次 Probe 产生的、可用于推导端口状态的事实。例如 SYN-ACK、RST、连接成功或明确 ICMP。属于内部领域概念，用户文档中不直接暴露。
_Avoid_: Observation, Signal, Reading

**ProbeOutcome（探测结果类型）**：
Probe 的执行结果。包含 Evidence（成功收集到证据）或 Cancelled（任务被取消，不作为端口证据进入 Reducer）。
_Avoid_: ProbeResult

**ProbeResult（探测结果）**：
一次成功 Probe 的产出。包含 Host、Port、Protocol、PortState、Confidence、RTT。所有状态和置信度始终完整保留，不受输出过滤影响。
_Avoid_: PortResult, CheckResult

**ScanResult（扫描结果）**：
一次 Scan 的全部 ProbeResult 集合。按 Host、Port 排序后呈现。过滤（--open、默认只显示 open/filtered/unknown）是展示层行为，不影响 ScanResult 的完整性。
_Avoid_: Output, Report

### 协议

**Protocol（协议）**：
端点身份的一部分，与 IP + Port 共同构成端点标识。第一版仅支持 Tcp。
_Avoid_: L4, Transport

### RTT

**best_rtt**：
多次有效响应中的最小 RTT。用于终端和普通文本输出。Timeout 不参与 RTT 计算。

**last_rtt**：
最近一次有效响应的 RTT。仅供 JSON 和调试使用。

### 调度概念

**High-value port（高价值端口）**：
探测优先级较高的端口。优先级顺序：用户通过 -p 显式指定的端口 > 内置常见端口表中的高频端口 > 1–1024 > 其余端口。用户意图优先于内置列表。
_Avoid_: Important port, Priority port

**Open port verification（开放端口验证）**：
SYN 扫描发现 open/high 后，安排一次 Connect 验证以升至 confirmed。-sT 不需要额外验证。不要因验证拖慢首次开放端口发现。
_Avoid_: Recheck, Double-check

**Conflict review（冲突复核）**：
证据冲突后，重新探测该端口以尝试收敛。可更换源端口、使用新 sequence cookie、延迟后重发、执行 Connect 或降低速率。预算耗尽仍冲突则保留最强状态并标记 confidence=medium。
_Avoid_: Retry, Re-probe

### 输出概念

**not_scanned（未扫描）**：
因中断或错误未能执行的端口。与 Unknown（已扫描但无结论）不同。中断后的 summary 必须区分两者。
_Avoid_: Pending, Skipped

**local_errors（本地错误）**：
LocalResourceExhausted 或 PermissionDenied 导致的本地运行错误。不作为端口证据进入 Reducer，独立统计。严重时可使 completed=false。
_Avoid_: System error, Internal error

**partial_failures（部分失败）**：
非致命问题标志。例如 DNS 部分失败、部分主机不可达。completed 仍可为 true，但 partial_failures=true 提示用户结果不完整。
_Avoid_: Incomplete, Degraded

**completed（扫描完成状态）**：
Scan 的完成状态。true = 所有成功展开的目标端口已得到最终处理或正式收敛。false = Ctrl+C、致命本地资源错误、输出文件致命错误、后端崩溃、调度器异常退出。
_Avoid_: Done, Finished
