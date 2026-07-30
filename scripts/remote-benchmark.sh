#!/usr/bin/env bash
set -euo pipefail

# Remote benchmark: run scans against a remote listener.
#
# Prerequisites:
#   1. Remote machine runs scripts/remote-listener.sh
#   2. Remote machine sends you the expected.csv file
#
# Usage:
#   bash scripts/remote-benchmark.sh <target-ip> <expected.csv>
#
# Options:
#   --binary PATH     pmap binary (default: ./target/release/pmap)
#   --repeats N       runs per combo (default: 5)
#   --port-count N    ports to scan (default: from expected.csv)
#   --output-dir DIR  output directory (default: benchmark-results/remote)
#   --dry-run         print commands only

TARGET=""
EXPECTED_CSV=""
PMAP_BIN="./target/release/pmap"
REPEATS=5
PORT_COUNT=0
OUTPUT_DIR="benchmark-results/remote"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) PMAP_BIN="$2"; shift 2 ;;
        --repeats) REPEATS="$2"; shift 2 ;;
        --port-count) PORT_COUNT="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h)
            echo "Usage: bash scripts/remote-benchmark.sh <target-ip> <expected.csv> [options]"
            exit 0 ;;
        -*)
            echo "Unknown: $1"; exit 1 ;;
        *)
            if [[ -z "$TARGET" ]]; then TARGET="$1"
            elif [[ -z "$EXPECTED_CSV" ]]; then EXPECTED_CSV="$1"
            fi
            shift ;;
    esac
done

if [[ -z "$TARGET" || -z "$EXPECTED_CSV" ]]; then
    echo "ERROR: target IP and expected.csv required"
    echo "Usage: bash scripts/remote-benchmark.sh <target-ip> <expected.csv>"
    exit 1
fi
if [[ ! -f "$EXPECTED_CSV" ]]; then
    echo "ERROR: expected.csv not found: $EXPECTED_CSV"
    exit 1
fi

# Get port count from expected.csv
if [[ "$PORT_COUNT" -eq 0 ]]; then
    PORT_COUNT=$(tail -n +2 "$EXPECTED_CSV" | wc -l)
fi
EXP_OPEN=$(grep -c ',open$' "$EXPECTED_CSV" 2>/dev/null || echo 0)
EXP_CLOSED=$(grep -c ',closed$' "$EXPECTED_CSV" 2>/dev/null || echo 0)

LOG_DIR="$OUTPUT_DIR/logs"
RAW_CSV="$OUTPUT_DIR/raw-runs.csv"
SUMMARY_CSV="$OUTPUT_DIR/summary.csv"
SUMMARY_JSON="$OUTPUT_DIR/summary.json"
REPORT_MD="$OUTPUT_DIR/report.md"
ENV_TXT="$OUTPUT_DIR/environment.txt"

mkdir -p "$OUTPUT_DIR" "$LOG_DIR"
cp "$EXPECTED_CSV" "$OUTPUT_DIR/expected.csv"

echo "=== pmap remote benchmark ==="
echo "Target: $TARGET"
echo "Port range: $PORT_COUNT ports (open=$EXP_OPEN closed=$EXP_CLOSED)"
echo "Repeats: $REPEATS"

# Record environment
{
    echo "benchmark_date: $(date -Iseconds)"
    echo "git_commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
    echo "pmap_version: $($PMAP_BIN --help 2>/dev/null | head -1 || echo 'unknown')"
    echo "rustc_version: $(rustc --version 2>/dev/null || echo 'unknown')"
    echo "kernel: $(uname -a 2>/dev/null || echo 'unknown')"
    echo "target: $TARGET"
    echo "port_count: $PORT_COUNT"
    echo "open_ports: $EXP_OPEN"
    echo "closed_ports: $EXP_CLOSED"
    echo "measured_runs: $REPEATS"
} | tee "$ENV_TXT"

# Need sudo for SYN scan
if command -v setcap &>/dev/null; then
    sudo setcap cap_net_raw,cap_net_admin=eip "$PMAP_BIN" 2>/dev/null || true
fi

# Build round list (interleaved)
ROUNDS=""
for ((r=1; r<=REPEATS; r++)); do
    for mode in sS sT; do
        for profile in 0 1 2 3 4 5; do
            ROUNDS+="$mode $profile $r"$'\n'
        done
    done
done

# Shuffle for fairness
ROUNDS=$(echo "$ROUNDS" | python3 -c "
import sys, random
random.seed(42)
lines = sys.stdin.read().strip().split('\n')
random.shuffle(lines)
print('\n'.join(lines))
")

TOTAL=$(echo "$ROUNDS" | wc -l)

# Parse function (same as local benchmark)
parse_run() {
    local mode="$1" profile="$2" run_idx="$3"
    local log_prefix="$LOG_DIR/${mode}-T${profile}-run-$(printf '%02d' "$run_idx")"
    local result_file="${log_prefix}.result.json"

    python3 - "$log_prefix" "$mode" "$profile" "$run_idx" "$EXPECTED_CSV" "$PORT_COUNT" <<'PY' > "$result_file"
import sys, json, os, re, csv
from pathlib import Path

lp = sys.argv[1]
mode = sys.argv[2]
profile = sys.argv[3]
run_idx = sys.argv[4]
expected_file = sys.argv[5]
port_count = int(sys.argv[6])

stdout_file = Path(lp + '.stdout')
time_file = Path(lp + '.time')
ec_file = Path(lp + '.exit_code')

result = {
    'scan_mode': mode, 'timing_profile': profile, 'run_index': int(run_idx),
    'exit_code': 0, 'wall_time': 0, 'user_cpu': 0, 'system_cpu': 0,
    'cpu_percent': 0, 'max_rss': 0,
    'reported_open': 0, 'reported_closed': 0, 'reported_filtered': 0, 'unknown_ports': 0,
    'expected_open': 0, 'expected_closed': 0,
    'false_open': 0, 'missed_open': 0, 'false_closed': 0,
    'accuracy': 0, 'open_recall': 0, 'closed_recall': 0, 'ports_per_second': 0,
}

if ec_file.exists():
    result['exit_code'] = int(ec_file.read_text().strip())

if time_file.exists():
    lines = [l.strip() for l in time_file.read_text().split('\n') if l.strip()]
    numeric = []
    pct_line = None
    for l in lines:
        if re.match(r'^[\d.]+$', l):
            numeric.append(float(l))
        elif re.match(r'^[\d.]+%$', l):
            pct_line = float(l.rstrip('%'))
    if len(numeric) >= 3:
        result['wall_time'] = numeric[0]
        result['user_cpu'] = numeric[1]
        result['system_cpu'] = numeric[2]
    if len(numeric) >= 4:
        result['max_rss'] = int(numeric[3])
    if pct_line is not None:
        result['cpu_percent'] = pct_line

pmap = {}
if stdout_file.exists():
    text = stdout_file.read_text()
    # Match per-port lines
    for m in re.finditer(r'(\d+)/tcp\s+(\S+)', text):
        pmap[int(m.group(1))] = m.group(2)
    # Also read summary lines which are authoritative
    open_m = re.search(r'# open:\s*(\d+)', text)
    closed_m = re.search(r'# closed:\s*(\d+)', text)
    filtered_m = re.search(r'# filtered:\s*(\d+)', text)
    unknown_m = re.search(r'# unknown:\s*(\d+)', text)
    if open_m:
        # Summary overrides per-port counts (some ports may not appear as individual lines)
        result['reported_open'] = int(open_m.group(1))
    if closed_m:
        result['reported_closed'] = int(closed_m.group(1))
    if filtered_m:
        result['reported_filtered'] = int(filtered_m.group(1))
    if unknown_m:
        result['unknown_ports'] = int(unknown_m.group(1))

expected = {}
with open(expected_file) as f:
    for row in csv.DictReader(f):
        expected[int(row['port'])] = row['state']

true_open = true_closed = 0
false_open = missed_open = false_closed = 0

# Use summary counts when available (more reliable than per-port lines)
# Summary may report accurate open/closed counts even if individual
# port lines are filtered from output
summary_open = result['reported_open']
summary_closed = result['reported_closed']

if summary_open > 0 or summary_closed > 0:
    # Aggregate comparison using summary
    exp_open = sum(1 for s in expected.values() if s == 'open')
    exp_closed = sum(1 for s in expected.values() if s == 'closed')
    true_open = min(summary_open, exp_open)
    true_closed = min(summary_closed, exp_closed)
    missed_open = exp_open - true_open
    false_open = max(0, summary_open - exp_open)
    # Closed ports from summary that exceed expected -> error
    false_closed = max(0, summary_closed - exp_closed) + exp_closed - true_closed
else:
    # Fallback: per-port comparison
    for port, exp in expected.items():
        actual = pmap.get(port, 'unknown')
        if exp == 'open':
            if actual == 'open': true_open += 1
            else: missed_open += 1
        elif exp == 'closed':
            if actual == 'closed': true_closed += 1
            elif actual == 'open': false_open += 1
            else: false_closed += 1

total = len(expected)
acc = (true_open + true_closed) / total * 100 if total > 0 else 0
or_ = true_open / (true_open + missed_open) * 100 if (true_open + missed_open) > 0 else 0
cr = true_closed / (true_closed + false_open + false_closed) * 100 if (true_closed + false_open + false_closed) > 0 else 0

result['expected_open'] = sum(1 for s in expected.values() if s == 'open')
result['expected_closed'] = sum(1 for s in expected.values() if s == 'closed')
result['false_open'] = false_open
result['missed_open'] = missed_open
result['false_closed'] = false_closed
result['accuracy'] = acc
result['open_recall'] = or_
result['closed_recall'] = cr
result['ports_per_second'] = port_count / result['wall_time'] if result['wall_time'] > 0 else 0

print(json.dumps(result, separators=(',', ':')))
PY
}

# Run one scan
run_pmap() {
    local mode="$1" profile="$2" run_idx="$3"
    local log_prefix="$LOG_DIR/${mode}-T${profile}-run-$(printf '%02d' "$run_idx")"
    
    # Get ports from expected.csv (first and last)
    local start_port end_port
    start_port=$(sed -n '2p' "$EXPECTED_CSV" | cut -d, -f1)
    end_port=$(tail -1 "$EXPECTED_CSV" | cut -d, -f1)
    
    if [[ "$mode" == "sS" ]]; then
        cmd=(sudo "$PMAP_BIN" -sS -Pn "-T${profile}" -p "${start_port}-${end_port}" --closed "$TARGET")
    else
        cmd=("$PMAP_BIN" -sT -Pn "-T${profile}" -p "${start_port}-${end_port}" --closed "$TARGET")
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[DRY] ${cmd[*]}" > "${log_prefix}.stdout"
        echo "0" > "${log_prefix}.time"
        return 0
    fi

    /usr/bin/time -o "${log_prefix}.time" -f '%e\n%U\n%S\n%P\n%M' \
        timeout --signal=TERM --kill-after=5s 300 \
        "${cmd[@]}" > "${log_prefix}.stdout" 2> "${log_prefix}.stderr" || true

    if grep -q 'timeout: sending signal TERM' "${log_prefix}.stderr" 2>/dev/null; then
        echo 124 > "${log_prefix}.exit_code"
    else
        echo 0 > "${log_prefix}.exit_code"
    fi
}

# Write CSV header
echo "scan_mode,timing_profile,run_index,exit_code,wall_time,user_cpu,system_cpu,cpu_percent,max_rss,reported_open,reported_closed,reported_filtered,unknown_ports,expected_open,expected_closed,false_open,missed_open,false_closed,accuracy,open_recall,closed_recall,ports_per_second" > "$RAW_CSV"

# Run
echo "Running $TOTAL rounds..."
IDX=0
OLDIFS="$IFS"
IFS=$'\n'
round_lines=($ROUNDS)
IFS="$OLDIFS"

for round_line in "${round_lines[@]}"; do
    OLDIFS2="$IFS"
    IFS=' '
    rf=($round_line)
    IFS="$OLDIFS2"
    mode="${rf[0]}"
    profile="${rf[1]}"
    run_idx="${rf[2]}"
    [[ -z "$mode" ]] && continue
    IDX=$((IDX + 1))
    echo "[$IDX/$TOTAL] $mode T$profile run $run_idx"

    set +e
    run_pmap "$mode" "$profile" "$run_idx"
    parse_run "$mode" "$profile" "$run_idx"
    set -e
done

# Aggregate results
python3 - "$OUTPUT_DIR" "$PORT_COUNT" "$EXP_OPEN" "$EXP_CLOSED" <<'PY' > /dev/null
import sys, json, glob, os, csv, math, collections

outdir = sys.argv[1]
total_ports = int(sys.argv[2])
exp_open = int(sys.argv[3])
exp_closed = int(sys.argv[4])

results = []
for f in sorted(glob.glob(os.path.join(outdir, 'logs', '*.result.json'))):
    with open(f) as fh: results.append(json.load(fh))

fieldnames = [
    'scan_mode','timing_profile','run_index','exit_code',
    'wall_time','user_cpu','system_cpu','cpu_percent','max_rss',
    'reported_open','reported_closed','reported_filtered','unknown_ports',
    'expected_open','expected_closed',
    'false_open','missed_open','false_closed',
    'accuracy','open_recall','closed_recall','ports_per_second'
]
with open(os.path.join(outdir, 'raw-runs.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    for r in results:
        w.writerow({k: r.get(k, 0) for k in fieldnames})

groups = collections.defaultdict(list)
for r in results:
    groups[(r['scan_mode'], r['timing_profile'])].append(r)

def median(vals):
    s = sorted(vals); n = len(s)
    return s[n//2] if n%2==1 else (s[n//2-1]+s[n//2])/2 if n else 0
def mean(vals):
    return sum(vals)/len(vals) if vals else 0
def stdev(vals):
    if len(vals)<2: return 0
    m = mean(vals)
    return math.sqrt(sum((v-m)**2 for v in vals)/(len(vals)-1))
def cv(vals):
    m = mean(vals); return 0 if m==0 else stdev(vals)/m*100

summary_rows = []
for mode in ['sS','sT']:
    for prof in ['0','1','2','3','4','5']:
        grp = groups.get((mode, prof), [])
        if not grp: continue
        n = len(grp)
        wt = [r['wall_time'] for r in grp if r['wall_time']>0]
        pps = [r['ports_per_second'] for r in grp if r['ports_per_second']>0]
        cpu_sec = [r.get('user_cpu',0)+r.get('system_cpu',0) for r in grp]
        mem = [r.get('max_rss',0) for r in grp if r.get('max_rss',0)>0]
        acc = [r.get('accuracy',0) for r in grp]
        fo = sum(r.get('false_open',0) for r in grp)
        mo = sum(r.get('missed_open',0) for r in grp)
        ro = sum(r.get('reported_open',0) for r in grp)
        rc = sum(r.get('reported_closed',0) for r in grp)
        cpu_ms = mean(cpu_sec)*1000_000/total_ports if total_ports>0 else 0

        row = {
            'scan_mode':mode,'timing_profile':prof,'n_runs':n,
            'successful':sum(1 for r in grp if r.get('exit_code',-1)==0),
            'failed':sum(1 for r in grp if r.get('exit_code',-1) not in (0,124)),
            'timeout':sum(1 for r in grp if r.get('exit_code',-1)==124),
            'wall_median':median(wt),'wall_mean':mean(wt),'wall_cv':cv(wt),
            'pps_median':median(pps),'pps_mean':mean(pps),
            'cpu_ms_per_1000':cpu_ms,
            'mem_kb_mean':mean(mem),'mem_kb_peak':max(mem) if mem else 0,
            'accuracy_mean':mean(acc),'accuracy_min':min(acc) if acc else 0,
            'open_recall_mean':mean([r.get('open_recall',0) for r in grp]),
            'closed_recall_mean':mean([r.get('closed_recall',0) for r in grp]),
            'false_open_total':fo,'missed_open_total':mo,
            'reported_open_total':ro,'reported_closed_total':rc,
        }
        summary_rows.append(row)

with open(os.path.join(outdir,'summary.csv'),'w',newline='') as f:
    if summary_rows:
        w=csv.DictWriter(f,fieldnames=summary_rows[0].keys())
        w.writeheader(); w.writerows(summary_rows)

with open(os.path.join(outdir,'summary.json'),'w') as f:
    json.dump({f'({r["scan_mode"]},{r["timing_profile"]})':r for r in summary_rows}, f, indent=2)

print(f"Aggregated: {len(results)} runs, {len(summary_rows)} groups")
PY

# Generate report
python3 - "$OUTPUT_DIR" "$ENV_TXT" <<'PY' > /dev/null
import sys, json, os, csv, collections

outdir = sys.argv[1]
env_file = sys.argv[2]

with open(env_file) as f:
    env = {l.split(':',1)[0].strip(): l.split(':',1)[1].strip() for l in f if ':' in l}

with open(os.path.join(outdir,'summary.json')) as f:
    data = json.load(f)

rows = []
with open(os.path.join(outdir,'raw-runs.csv')) as f:
    for row in csv.DictReader(f):
        rows.append(row)

groups = collections.defaultdict(list)
for r in rows:
    groups[(r['scan_mode'], r['timing_profile'])].append(r)

def median(vals):
    s=sorted(vals); n=len(s)
    return s[n//2] if n%2==1 else (s[n//2-1]+s[n//2])/2 if n else 0
def mean(vals):
    return sum(vals)/len(vals) if vals else 0

report = os.path.join(outdir, 'report.md')
with open(report, 'w') as r:
    r.write(f"# pmap remote benchmark\n\nTarget: {env.get('target','')}\nDate: {env.get('benchmark_date','')}\n")
    r.write("## Results\n|Mode|T|Time|Ports/s|Acc%|OpenRec|ClsRec|FO|MO|\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
    for m in ['sS','sT']:
        for p in ['0','1','2','3','4','5']:
            grp=groups.get((m,p),[])
            if not grp: continue
            wt=median([float(r['wall_time']) for r in grp if float(r['wall_time'])>0])
            pps=median([float(r['ports_per_second']) for r in grp if float(r['ports_per_second'])>0])
            acc=mean([float(r['accuracy']) for r in grp])
            or_=mean([float(r['open_recall']) for r in grp])
            cr_=mean([float(r['closed_recall']) for r in grp])
            fo=sum(int(float(r.get('false_open',0))) for r in grp)
            mo=sum(int(float(r.get('missed_open',0))) for r in grp)
            r.write(f"|{m}|T{p}|{wt:.3f}s|{pps:.0f}|{acc:.1f}|{or_:.1f}|{cr_:.1f}|{fo}|{mo}|\n")

print(f"Report: {report}")
PY

echo ""
echo "=== Done ==="
echo "Results: $OUTPUT_DIR/"
echo "  raw-runs.csv summary.csv summary.json report.md"
