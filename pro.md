# pmap 领域模型问题

以下问题按主题分组，请逐一回答。

---

## A. 核心概念

### 1. Evidence 是领域概念吗？

计划里 `ProbeEvidence` 是探测引擎的产出（SynAck、Reset、ConnectSuccess 等），State Reducer 根据证据优先级规则合并成 PortState + Confidence。但用户看不到原始证据，只看到最终状态 + 置信度。

**Evidence 应该放进领域语言（CONTEXT.md）吗？** 还是它纯粹是实现层的概念，不属于用户需要理解的领域术语？

### 2. RTT 输出哪个值？

计划说每个端口记录 `best_rtt` 和 `last_rtt`，终端显示 `best_rtt`，JSON 可以同时有 `rtt_ms` 和 `last_rtt_ms`。

**终端是否永远只显示 best_rtt？** 即使重试多次，也只显示最快那次？

### 3. Protocol 是领域概念吗？

输出格式是 `<PORT>/tcp`，计划只支持 TCP。**"tcp" 是固定后缀还是领域概念？** 如果未来支持 UDP，是否需要在领域语言里定义 Protocol？

---

## B. 状态与置信度

### 4. LocalResourceExhausted 和 PermissionDenied 如何处理？

计划说"本地资源错误不得归入 closed、unreachable 或 unknown"。`ProbeEvidence` 里有 `LocalResourceExhausted` 和 `PermissionDenied`。

**它们在输出里怎么体现？** 是静默丢弃（不进入任何 PortState），还是在 summary 里单独统计？还是有专门的错误输出？

### 5. Cancelled 什么时候出现？

`ProbeEvidence` 里有 `Cancelled`。**只有 Ctrl+C 触发？** 还有其他情况（如目标全部完成后的清理取消）？

### 6. 证据矛盾 = 两个强证据冲突，还有其他场景吗？

之前确认"矛盾"= 两个强证据冲突（如 SYN-ACK vs ICMP Filtered）。**除了这种场景，还有其他情况需要触发 Medium 降级吗？** 比如：
- Connect 成功后又收到 Reset（理论上 TCP 不可能，但竞态下可能）
- 同一端口两次 Connect 成功但 RTT 差异巨大

---

## C. 调度与重试

### 7. "开放端口验证"是什么？

重试优先级里有"开放端口验证"：

```
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

**是发现 open 后再 probe 一次确认（升到 confirmed）？** 还是只是把已确认的 open 端口排在更高优先级做别的事？

### 8. "冲突复核"是什么？

重试优先级里有"冲突复核"。**是证据冲突后重试该端口？** 还是只是标记为 Medium 不再重试？

### 9. "高价值端口"怎么定义？

重试优先级里有"首次高价值端口"。**什么是高价值？** 是：
- 用户通过 `-p` 明确指定的端口？
- 常见端口列表里的端口（如 22, 80, 443）？
- 还是其他标准？

---

## D. 输出

### 10. unknown 范围是否排除 filtered 端口？

计划说 unknown 范围不能混入 open 端口。**filtered 端口呢？**

例如一个主机有 22/open、443/filtered、其余 unknown：
- 方案 A：`unknown  1-21,23-442,444-65535`（排除 22 和 443）
- 方案 B：`unknown  1-21,23-442,444-65535`（只排除 22，443 留在 unknown 范围里）

哪个对？

### 11. `# complete results (sorted)` 的 `*` 前缀

最终输出里每行有 `*` 前缀：

```
* 192.0.2.10	22/tcp	open	high	11ms
```

**这个 `*` 是固定格式吗？** 还是只是示例里的视觉标记？

### 12. 默认 1000 端口列表

计划说"不指定 -p 时扫描内置常见 1000 个 TCP 端口"。**这个列表是固定的（硬编码）？** 还是随版本更新？来源是什么（Nmap 的 top 1000？自己维护的列表？）

### 13. 端口扫描顺序 vs 输出排序

计划说：
- 扫描顺序：用户输入顺序优先 → 常见端口优先 → 其余
- 输出排序：IP 数值升序 → 端口数值升序

**所以扫描顺序只影响调度优先级，不影响输出顺序？** 输出永远按 IP + 端口数值排序？

### 14. 实时输出 vs 最终输出的过滤边界

实时输出只显示 open，最终输出显示 open + filtered + unknown。**这个边界是硬性的？** 还是用户可以通过参数调整（比如 `--show-filtered`）？计划说"不要加入以下参数"里有 `--show-filtered`，所以是硬性的？

### 15. completed 的语义

summary 里有 `completed: true/false`。**除了 Ctrl+C 导致 false，还有什么情况？** 比如：
- DNS 部分失败？（计划说"单个主机名解析失败不能终止全部扫描"）
- 部分主机不可达？
- 本地资源耗尽导致扫描提前终止？

---

## E. 边界场景

### 16. 主机无开放端口

如果一个主机所有端口都是 closed/unreachable/unknown，**它在最终输出里怎么出现？**

- 方案 A：不出现（只有 open/filtered/unknown 的端口才输出）
- 方案 B：出现 unknown 范围行（`* 192.0.2.10  unknown  1-65535`）
- 方案 C：出现但只在 summary 里统计

哪个对？

### 17. 所有主机不可达

如果所有目标都 unreachable，**输出是什么？**

- 有 summary 但没有结果行？
- 还是有特殊提示？

### 18. DNS 全部失败

如果 `-iL` 文件里全是无法解析的主机名，**输出是什么？**

- 报错退出？
- 还是空结果 + summary？

### 19. 总探测数过大

计划限制目标数 ≤ 65536。但如果用户 `pmap 192.168.1.0/24 -p-`，那是 254 × 65535 = 16M 探测。**是否有总探测数限制？** 还是只限制目标数，端口数不限？

### 20. Ctrl+C 后 --open 模式

中断后输出部分结果。**`--open` 模式下中断，是否也只输出 open？** summary 是否仍然包含所有状态计数？

---

## F. JSON 结构

### 21. JSON 里 unknown 的结构

计划说 JSON 里 unknown 用范围压缩：

```json
{
  "ip": "192.0.2.10",
  "unknown_ranges": [[1, 21], [23, 79]]
}
```

**这个结构是每个 host 一个对象？** 还是所有 host 的 unknown 合并在一个数组里？

### 22. JSON results 里 filtered 的结构

JSON results 包含 open 和 filtered。**filtered 的结构和 open 一样吗？** 都有 `ip`, `port`, `protocol`, `state`, `confidence`, `rtt_ms`？

### 23. JSON scan 对象里包含什么？

计划说 JSON 有 `scan: {}`。**里面具体包含什么字段？** 比如 `scan_type`、`timing_template`、`started_at`、`completed_at`？

---

请按编号回答，可以简短回答。
