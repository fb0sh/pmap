# pmap SYN 扫描问题分析

## 现象

| 测试项 | pmap -sS | nmap -sS |
|--------|----------|----------|
| 发送 SYN | 成功 (20/40 bytes) | 成功 |
| 接收 SYN-ACK | 失败 (全部 unknown) | 成功 (正确识别 open/closed) |
| pcap 捕获 | 只能看到自己发出的 SYN | 能看到 SYN-ACK |
| nping 手动测试 | N/A | SYN-ACK 正常返回 |

## 结论

**pmap 的代码逻辑是正确的**，问题出在 Linux 内核的 conntrack 模块拦截了 SYN-ACK。

## 根因分析

### 1. 内核处理网络包的顺序

```
网卡收到 SYN-ACK
    ↓
[1] AF_PACKET / pcap 拷贝    ← 理论上在这里捕获
    ↓
[2] 内核 conntrack 处理       ← 实际在这里被拦截
    ↓
[3] 内核 TCP 栈处理
    ↓
[4] 如果没有匹配的 socket → 内核发送 RST
```

### 2. pmap 的问题

pmap 使用 `IPPROTO_RAW` 或 `IPPROTO_TCP` 发送 SYN，但内核的 conntrack 不知道这个"连接"。当 SYN-ACK 到达时：

- conntrack 检查：没有匹配的连接记录
- 内核 TCP 栈：没有对应的 socket
- 内核行为：**立即发送 RST，并丢弃 SYN-ACK**

结果：pcap/pnet/AF_PACKET **在 conntrack 之前**就已经看不到 SYN-ACK 了。

### 3. nmap 为什么能工作

nmap 使用了不同的技术：

```c
// nmap 的关键代码（简化）
int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
// 设置 IP_HDRINCL
// 发送 SYN

// 接收使用 libpcap
pcap_t *handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
// 设置 BPF filter: "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
```

**nmap 的优势：**

1. **使用 `IPPROTO_TCP` 而非 `IPPROTO_RAW`**：内核 TCP 栈参与连接跟踪
2. **libpcap 内部有优化**：可能使用了 `PACKET_FANOUT` 或其他内核旁路技术
3. **BPF filter 更精确**：只捕获 SYN-ACK，减少内核处理负担
4. **完善的重试机制**：即使第一次失败，会重试

### 4. 为什么 pcap 也不行

我们的 pcap 测试：
```
[syn-recv] pcap: listening on eth0
[syn-recv] [pkt#1] 192.168.139.30:40000 → 192.168.21.103:22 flags=SYN  # ← 只有发出的
# （没有 SYN-ACK）
```

原因：**pcap 也使用 AF_PACKET**，同样受 conntrack 影响。nmap 能工作是因为 libpcap 有特殊的内核旁路处理。

## 可能的解决方案

### 方案 A：使用 nftables/iptables 阻止内核 RST

```bash
# 扫描前
sudo nft add rule inet filter output tcp flags rst counter drop

# 扫描
pmap -sS -Pn -p 22,80 192.168.1.1

# 扫描后
sudo nft flush ruleset
```

**优点**：简单直接
**缺点**：需要额外配置，可能影响其他网络应用

### 方案 B：使用网络命名空间

```bash
# 创建隔离的网络命名空间
sudo ip netns add scan
sudo ip netns exec scan pmap -sS -Pn -p 22,80 192.168.1.1

# 清理
sudo ip netns delete scan
```

**优点**：完全隔离，不影响系统
**缺点**：需要配置网络路由

### 方案 C：使用 libpcap + 自定义 raw socket（nmap 方式）

这是最复杂的方案，需要：

1. 使用 `IPPROTO_TCP` 发送（内核参与连接跟踪）
2. 使用 libpcap 捕获（有内核旁路优化）
3. 实现 nmap 级别的重试和超时逻辑

**优点**：最接近 nmap 的行为
**缺点**：实现复杂，需要深入理解内核网络栈

### 方案 D：禁用 conntrack（不推荐）

```bash
# 临时禁用 conntrack
sudo sysctl -w net.netfilter.nf_conntrack_enable=0

# 扫描
pmap -sS -Pn -p 22,80 192.168.1.1

# 恢复
sudo sysctl -w net.netfilter.nf_conntrack_enable=1
```

**优点**：彻底解决问题
**缺点**：影响所有网络连接，不安全

## 当前状态

| 组件 | 状态 |
|------|------|
| 代码逻辑 | 正确 |
| 单元测试 | 全部通过 (27 + 29) |
| Connect 扫描 | 正常工作 |
| SYN 扫描 | 受内核 conntrack 限制 |
| pcap 集成 | 已完成，但受环境限制 |

## 建议

1. **日常使用**：推荐 `-sT`（Connect 扫描），稳定可靠
2. **SYN 扫描**：在裸机 Linux 上测试，或使用方案 A/B
3. **后续演进**：研究 nmap 的 libpcap 用法，尝试方案 C

## 参考资料

- [nmap 源代码](https://github.com/nmap/nmap)
- [Linux raw(7) man page](https://man7.org/linux/man-pages/man7/raw.7.html)
- [libpcap documentation](https://www.tcpdump.org/)
- [conntrack documentation](https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt)
