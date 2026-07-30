# pmap localhost benchmark

Date: 2026-07-30T13:53:31.393354
Commit: 771dd69f1474c60a495b5395c6a1663278b22470

## Environment
```
benchmark_date: 2026-07-30T13:28:55+08:00
git_commit: 771dd69f1474c60a495b5395c6a1663278b22470
git_dirty: M  .gitignore
pmap_version: TCP port scanner
rustc_version: rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo_version: cargo 1.97.1 (c980f4866 2026-06-30)
kernel: Linux kali 7.0.11-orbstack-00360-gc9bc4d96ac70 #1 SMP PREEMPT Thu Jun  4 16:40:25 UTC 2026 aarch64 GNU/Linux
cpu: Model name:                              -
cpu_cores: 10
target: 127.0.0.1
port_range: 22000-22127
port_count: 128
open_ports: 32
closed_ports: 96
warmup_runs: 0
measured_runs: 5
seed: 42
```

## Results
|Mode|T|Time(median)|Ports/s|Acc%|CV%|CPUms/k|MemKB|A|S|St|C|M|O|
|---|---|---:|---:|---:|---:|---:|---:|:---:|:---:|:---:|:---:|:---:|:---:|
|sS|T0|15.020s|9|0.00|0.2|437.5|8222|-1|-3|-3|3|-3|-1|
|sS|T1|15.020s|9|0.00|0.0|328.1|8203|-1|-3|-3|3|-3|-1|
|sS|T2|5.020s|25|0.00|214.6|171.9|8232|-1|-1|3|-3|-3|0|
|sS|T3|5.020s|25|0.00|214.6|140.6|8202|-1|-1|3|-3|-3|0|
|sS|T4|2.520s|51|0.00|0.2|78.1|8217|-1|0|-3|-3|-3|-1|
|sS|T5|1.270s|101|0.00|0.7|62.5|8229|-1|3|-3|-3|-3|0|
|sT|T0|10.010s|13|75.00|0.1|46.9|4109|-1|-3|-3|-3|-3|-2|
|sT|T1|2.010s|64|75.00|0.2|62.5|4083|-1|-3|-3|-3|-3|-2|
|sT|T2|0.510s|251|75.00|1.1|31.2|4080|-1|-3|-3|-3|-3|-2|
|sT|T3|0.100s|1280|75.00|5.3|31.2|4110|-1|0|-3|-3|-3|-1|
|sT|T4|0.050s|2560|75.00|10.1|15.6|4109|-1|3|-3|-3|-3|0|
|sT|T5|0.000s|0|75.00|0.0|0.0|4108|-1|-3|-3|-3|-3|-2|

## Speed vs T3
|Mode|T|PPS|vs T3|
|---|---:|---:|
|sS|T0|9|-66.6%|
|sS|T1|9|-66.6%|
|sS|T2|25|+0.0%|
|sS|T3|25|+0.0%|
|sS|T4|51|+99.2%|
|sS|T5|101|+295.3%|
|sT|T0|13|-99.0%|
|sT|T1|64|-95.0%|
|sT|T2|251|-80.4%|
|sT|T3|1280|+0.0%|
|sT|T4|2560|+100.0%|
|sT|T5|0|-100.0%|

## SYN vs TCP
|T|SYN time|TCP time|Faster|Diff|
|---|---:|---:|----|---:|
|T0|15.020s|10.010s|TCP|33.4%|
|T1|15.020s|2.010s|TCP|86.6%|
|T2|5.020s|0.510s|TCP|89.8%|
|T3|5.020s|0.100s|TCP|98.0%|
|T4|2.520s|0.050s|TCP|98.0%|
|T5|1.270s|0.000s|TCP|100.0%|

## Grade matrix (numeric)
|Mode|T|Accuracy|Speed|Stability|CPU|Memory|Overall|
|---|---:|---:|---:|---:|---:|---:|---:|
|sS|T0|-1|-3|-3|3|-3|-1|
|sS|T1|-1|-3|-3|3|-3|-1|
|sS|T2|-1|-1|3|-3|-3|0|
|sS|T3|-1|-1|3|-3|-3|0|
|sS|T4|-1|0|-3|-3|-3|-1|
|sS|T5|-1|3|-3|-3|-3|0|
|sT|T0|-1|-3|-3|-3|-3|-2|
|sT|T1|-1|-3|-3|-3|-3|-2|
|sT|T2|-1|-3|-3|-3|-3|-2|
|sT|T3|-1|0|-3|-3|-3|-1|
|sT|T4|-1|3|-3|-3|-3|0|
|sT|T5|-1|-3|-3|-3|-3|-2|

## Per profile
### sS
- **T0**: acc=0.00% pps=9 cv=0.2% fo=0 mo=160 cpu=437.5ms/k mem=8222KB
- **T1**: acc=0.00% pps=9 cv=0.0% fo=0 mo=160 cpu=328.1ms/k mem=8203KB
- **T2**: acc=0.00% pps=25 cv=214.6% fo=0 mo=160 cpu=171.9ms/k mem=8232KB
- **T3**: acc=0.00% pps=25 cv=214.6% fo=0 mo=160 cpu=140.6ms/k mem=8202KB
- **T4**: acc=0.00% pps=51 cv=0.2% fo=0 mo=160 cpu=78.1ms/k mem=8217KB
- **T5**: acc=0.00% pps=101 cv=0.7% fo=0 mo=160 cpu=62.5ms/k mem=8229KB
### sT
- **T0**: acc=75.00% pps=13 cv=0.1% fo=0 mo=160 cpu=46.9ms/k mem=4109KB
- **T1**: acc=75.00% pps=64 cv=0.2% fo=0 mo=160 cpu=62.5ms/k mem=4083KB
- **T2**: acc=75.00% pps=251 cv=1.1% fo=0 mo=160 cpu=31.2ms/k mem=4080KB
- **T3**: acc=75.00% pps=1280 cv=5.3% fo=0 mo=160 cpu=31.2ms/k mem=4110KB
- **T4**: acc=75.00% pps=2560 cv=10.1% fo=0 mo=160 cpu=15.6ms/k mem=4109KB
- **T5**: acc=75.00% pps=0 cv=0.0% fo=0 mo=160 cpu=0.0ms/k mem=4108KB

## Limitations
Loopback only. Does not represent real network conditions.
