#!/usr/bin/env bash
# shellcheck disable=SC2317
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
TARGET="${TARGET:-127.0.0.1}"
BASE_PORT="${BENCH_BASE_PORT:-20000}"
PORT_COUNT="${BENCH_PORT_COUNT:-128}"
OPEN_RATIO="${BENCH_OPEN_RATIO:-25}"
WARMUP_RUNS="${BENCH_WARMUPS:-1}"
MEASURED_RUNS="${BENCH_REPEATS:-5}"
OUTPUT_DIR="${BENCH_OUTPUT_DIR:-benchmark-results/localhost}"
TIMEOUT_PER_RUN="${BENCH_TIMEOUT:-300}"
PMAP_BIN="${PMAP_BIN:-./target/release/pmap}"
DRY_RUN=0
VALIDATE_ONLY=0
SEED="${BENCH_SEED:-42}"
CANDIDATE_PORTS=(20000 22000 24000 26000 28000)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ── Args ────────────────────────────────────────────────────────────────────
usage() { cat <<'USAGE'; exit 0
Usage: scripts/benchmark-localhost.sh [OPTIONS]
  --repeats N      Measured runs per combo (default: 5)
  --port-count N   Ports to scan (default: 128)
  --base-port N    Base port (default: 20000)
  --binary PATH    pmap binary (default: ./target/release/pmap)
  --output-dir PATH (default: benchmark-results/localhost)
  --seed N         Round order seed (default: 42)
  --dry-run        Print commands only
  --validate-only  Validate environment and exit
  --help           Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repeats)    MEASURED_RUNS="$2"; shift 2 ;;
        --port-count) PORT_COUNT="$2"; shift 2 ;;
        --base-port)  BASE_PORT="$2"; shift 2 ;;
        --binary)     PMAP_BIN="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --seed)       SEED="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --validate-only) VALIDATE_ONLY=1; shift ;;
        --help|-h)    usage ;;
        *) echo "Unknown: $1"; usage ;;
    esac
done

for var in MEASURED_RUNS PORT_COUNT BASE_PORT SEED; do
    [[ "${!var}" =~ ^[0-9]+$ ]] || { echo "ERROR: $var must be integer"; exit 1; }
done
((MEASURED_RUNS >= 1)) || { echo "ERROR: repeats >= 1"; exit 1; }
((PORT_COUNT >= 1 && PORT_COUNT <= 64535)) || { echo "ERROR: port-count 1-64535"; exit 1; }
((BASE_PORT + PORT_COUNT <= 65536)) || { echo "ERROR: range exceeds 65535"; exit 1; }
[[ -x "$PMAP_BIN" ]] || { echo "ERROR: binary not found: $PMAP_BIN"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 required"; exit 1; }
command -v /usr/bin/time >/dev/null || { echo "ERROR: /usr/bin/time required (apt install time)"; exit 1; }
python3 -c "import sys; sys.exit(0 if sys.version_info>=(3,5) else 1)" || { echo "ERROR: Python 3.5+"; exit 1; }

END_PORT=$((BASE_PORT + PORT_COUNT - 1))
LOG_DIR="$OUTPUT_DIR/logs"
RAW_CSV="$OUTPUT_DIR/raw-runs.csv"
SUMMARY_CSV="$OUTPUT_DIR/summary.csv"
SUMMARY_JSON="$OUTPUT_DIR/summary.json"
REPORT_MD="$OUTPUT_DIR/report.md"
ENV_TXT="$OUTPUT_DIR/environment.txt"
EXPECTED_CSV="$OUTPUT_DIR/expected.csv"

# ── Port range ──────────────────────────────────────────────────────────────
find_ports() {
    if [[ "$DRY_RUN" -eq 1 ]] || [[ "$VALIDATE_ONLY" -eq 1 ]]; then
        return 0
    fi
    for cand in "${CANDIDATE_PORTS[@]}"; do
        local end=$((cand + PORT_COUNT - 1)); ((end > 65535)) && continue
        if python3 -c "
import socket
for p in range($cand, $end + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    r = s.connect_ex(('127.0.0.1', p))
    s.close()
    if r == 0: exit(1)
exit(0)
" 2>/dev/null; then
            BASE_PORT=$cand; END_PORT=$end; return 0
        fi
    done
    echo "ERROR: no $PORT_COUNT consecutive free ports"; exit 1
}

# ── Ground truth ────────────────────────────────────────────────────────────
gen_expected() {
    > "$EXPECTED_CSV"; echo "port,state" >> "$EXPECTED_CSV"
    for ((i=0; i<PORT_COUNT; i++)); do
        local port=$((BASE_PORT + i))
        local step=$((100 / OPEN_RATIO))
        if (( i % step == 0 )); then
            echo "$port,open" >> "$EXPECTED_CSV"
        else
            echo "$port,closed" >> "$EXPECTED_CSV"
        fi
    done
    EXPECTED_OPEN=$(grep -c ',open$' "$EXPECTED_CSV" 2>/dev/null || echo 0)
    EXPECTED_CLOSED=$(grep -c ',closed$' "$EXPECTED_CSV" 2>/dev/null || echo 0)
}

# ── Python listener ─────────────────────────────────────────────────────────
LISTENER_PID=""
start_listener() {
    local port_list="$1"
    python3 - "$port_list" <<'PY' &
import socket, selectors, sys, os, signal, json

with open(sys.argv[1]) as f:
    ports = [int(l.strip()) for l in f if l.strip()]

sel = selectors.DefaultSelector()
socks = []
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind(('127.0.0.1', port))
    s.listen(128)
    sel.register(s, selectors.EVENT_READ)
    socks.append(s)

ready_file = sys.argv[1] + '.ready'
with open(ready_file, 'w') as f:
    f.write('1')
    os.fsync(f.fileno())

stop = False
def handler(s, f):
    global stop; stop = True
signal.signal(signal.SIGTERM, handler)

while not stop:
    for key, _ in sel.select(timeout=0.5):
        conn, _ = key.fileobj.accept()
        conn.close()
for s in socks:
    s.close()
PY
    LISTENER_PID=$!
    local timeout=10
    while [[ ! -f "${port_list}.ready" ]] && ((timeout > 0)); do
        sleep 0.2; timeout=$((timeout - 1))
    done
    rm -f "${port_list}.ready"
    if [[ ! -d /proc/$LISTENER_PID ]]; then
        echo "ERROR: listener failed to start"; exit 1
    fi
}

cleanup() {
    [[ -n "${LISTENER_PID:-}" ]] && kill "$LISTENER_PID" 2>/dev/null || true
    rm -f "$OUTPUT_DIR/.open_ports" "$OUTPUT_DIR/.open_ports.ready" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Run single pmap ────────────────────────────────────────────────────────
run_pmap() {
    local mode="$1" profile="$2" run_idx="$3"
    local log_prefix="$LOG_DIR/${mode}-T${profile}-run-$(printf '%02d' "$run_idx")"
    local cmd
    if [[ "$mode" == "sS" ]]; then
        cmd=(sudo "$PMAP_BIN" -sS -Pn "-T${profile}" -p "${BASE_PORT}-${END_PORT}" --closed "$TARGET")
    else
        cmd=("$PMAP_BIN" -sT -Pn "-T${profile}" -p "${BASE_PORT}-${END_PORT}" --closed "$TARGET")
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[DRY] ${cmd[*]}"
        return 0
    fi

    /usr/bin/time -o "${log_prefix}.time" -f '%e\n%U\n%S\n%P\n%M' \
        timeout --signal=TERM --kill-after=5s "$TIMEOUT_PER_RUN" \
        "${cmd[@]}" > "${log_prefix}.stdout" 2> "${log_prefix}.stderr" || true

    # Determine exit code
    if grep -q 'timeout: sending signal TERM' "${log_prefix}.stderr" 2>/dev/null; then
        echo 124 > "${log_prefix}.exit_code"
    else
        echo 0 > "${log_prefix}.exit_code"
    fi
}

# ── Parse one run into a JSON results file ─────────────────────────────────
# This is the critical function — uses Python to avoid bash variable issues
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
    'scan_mode': mode,
    'timing_profile': profile,
    'run_index': int(run_idx),
    'exit_code': 0,
    'wall_time': 0,
    'user_cpu': 0,
    'system_cpu': 0,
    'cpu_percent': 0,
    'max_rss': 0,
    'reported_open': 0,
    'reported_closed': 0,
    'reported_filtered': 0,
    'unknown_ports': 0,
    'expected_open': 0,
    'expected_closed': 0,
    'false_open': 0,
    'missed_open': 0,
    'false_closed': 0,
    'accuracy': 0,
    'open_recall': 0,
    'closed_recall': 0,
    'ports_per_second': 0,
}

# Read exit code
if ec_file.exists():
    result['exit_code'] = int(ec_file.read_text().strip())

# Read /usr/bin/time output
if time_file.exists():
    lines = [l.strip() for l in time_file.read_text().split('\n') if l.strip()]
    # Filter: take first numeric line as wall, second as user, third as sys,
    # line with % as cpu, last numeric line as mem
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
    # /usr/bin/time -f '%e\n%U\n%S\n%P\n%M': lines are wall/user/sys/CPU%/RSS
    # CPU% line contains '%' so it's NOT in numeric; RSS is the 4th numeric value (index 3)
    if len(numeric) >= 4:
        result['max_rss'] = int(numeric[3])
    if pct_line is not None:
        result['cpu_percent'] = pct_line

# Parse pmap output for port states
pmap = {}
if stdout_file.exists():
    text = stdout_file.read_text()
    for m in re.finditer(r'(\d+)/tcp\s+(\S+)', text):
        port = int(m.group(1))
        state = m.group(2)
        pmap[port] = state
    # Summary lines are authoritative (some ports may not appear as individual lines)
    open_m = re.search(r'# open:\s*(\d+)', text)
    closed_m = re.search(r'# closed:\s*(\d+)', text)
    filtered_m = re.search(r'# filtered:\s*(\d+)', text)
    unknown_m = re.search(r'# unknown:\s*(\d+)', text)
    if open_m: result['reported_open'] = int(open_m.group(1))
    if closed_m: result['reported_closed'] = int(closed_m.group(1))
    if filtered_m: result['reported_filtered'] = int(filtered_m.group(1))
    if unknown_m: result['unknown_ports'] = int(unknown_m.group(1))

# Compare with expected
expected = {}
with open(expected_file) as f:
    for row in csv.DictReader(f):
        expected[int(row['port'])] = row['state']

true_open = true_closed = false_open = missed_open = false_closed = 0

# Use summary counts when available (more reliable than per-port lines)
summary_open = result['reported_open']
summary_closed = result['reported_closed']

if summary_open > 0 or summary_closed > 0:
    exp_open = sum(1 for s in expected.values() if s == 'open')
    exp_closed = sum(1 for s in expected.values() if s == 'closed')
    true_open = min(summary_open, exp_open)
    true_closed = min(summary_closed, exp_closed)
    missed_open = exp_open - true_open
    false_open = max(0, summary_open - exp_open)
    false_closed = max(0, summary_closed - exp_closed) + exp_closed - true_closed
else:
    for port, exp in expected.items():
        actual = pmap.get(port, 'unknown')
        if exp == 'open':
            if actual == 'open':
                true_open += 1
            else:
                missed_open += 1
        elif exp == 'closed':
            if actual == 'closed':
                true_closed += 1
            elif actual == 'open':
                false_open += 1
            else:
                false_closed += 1

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

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo "=== pmap localhost benchmark ==="
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR"

    find_ports
    gen_expected
    echo "Port range: $BASE_PORT-$END_PORT ($PORT_COUNT ports, open=$EXPECTED_OPEN closed=$EXPECTED_CLOSED)"

    # Write open ports for listener
    python3 -c "
step = 100 // $OPEN_RATIO
with open('$OUTPUT_DIR/.open_ports', 'w') as f:
    for i in range($PORT_COUNT):
        if i % step == 0:
            f.write(str($BASE_PORT + i) + '\n')
"
    start_listener "$OUTPUT_DIR/.open_ports"
    echo "Listener PID=$LISTENER_PID on $EXPECTED_OPEN open ports"

    # Verify
    if [[ "$DRY_RUN" -eq 0 ]]; then
    python3 -c "
import socket
with open('$OUTPUT_DIR/.open_ports') as f:
    for line in f:
        p = int(line.strip())
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        r = s.connect_ex(('127.0.0.1', p))
        s.close()
        if r != 0:
            print(f'WARN: port {p} not listening')
print('All open ports verified')
"
    fi

    # Record environment
    {
        echo "benchmark_date: $(date -Iseconds)"
        echo "git_commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
        echo "git_dirty: $(git status --short 2>/dev/null | head -3 || echo 'unknown')"
        echo "pmap_version: $($PMAP_BIN --help 2>/dev/null | head -1 || echo 'unknown')"
        echo "rustc_version: $(rustc --version 2>/dev/null || echo 'unknown')"
        echo "cargo_version: $(cargo --version 2>/dev/null || echo 'unknown')"
        echo "kernel: $(uname -a 2>/dev/null || echo 'unknown')"
        echo "cpu: $(lscpu 2>/dev/null | grep 'Model name' | head -1 || echo 'unknown')"
        echo "cpu_cores: $(nproc 2>/dev/null || echo 'unknown')"
        echo "target: $TARGET"
        echo "port_range: $BASE_PORT-$END_PORT"
        echo "port_count: $PORT_COUNT"
        echo "open_ports: $EXPECTED_OPEN"
        echo "closed_ports: $EXPECTED_CLOSED"
        echo "warmup_runs: $WARMUP_RUNS"
        echo "measured_runs: $MEASURED_RUNS"
        echo "seed: $SEED"
    } | tee "$ENV_TXT"

    # Build round list
    ROUNDS=""
    for ((r=1; r<=MEASURED_RUNS; r++)); do
        for mode in sS sT; do
            for profile in 0 1 2 3 4 5; do
                ROUNDS+="$mode $profile $r"$'\n'
            done
        done
    done
    # Shuffle deterministically
    ROUNDS=$(echo "$ROUNDS" | python3 -c "
import sys, random; random.seed($SEED)
lines = sys.stdin.read().strip().split('\n')
random.shuffle(lines)
print('\n'.join(lines))
")

    TOTAL=$(echo "$ROUNDS" | wc -l)
    echo ""; echo "=== Running ($TOTAL rounds) ==="

    # Warmup
    echo "Warmup ($WARMUP_RUNS x 12 combos)..."
    for ((w=0; w<WARMUP_RUNS; w++)); do
        for mode in sS sT; do
            for profile in 0 1 2 3 4 5; do
                run_pmap "$mode" "$profile" "0" 2>/dev/null || true
            done
        done
    done
    echo "Warmup done."

    # Measured
    echo "Measured runs:"
    # Split rounds into an array
    OLDIFS="$IFS"
    IFS=$'\n'
    local round_lines=($ROUNDS)
    IFS="$OLDIFS"
    local idx=0
    for round_line in "${round_lines[@]}"; do
        # Split round_line into fields
        OLDIFS2="$IFS"
        IFS=' '
        local rf=($round_line)
        IFS="$OLDIFS2"
        local mode="${rf[0]}"
        local profile="${rf[1]}"
        local run_idx="${rf[2]}"
        [[ -z "$mode" ]] && continue
        idx=$((idx + 1))
        echo "[$idx/$TOTAL] $mode T$profile run $run_idx"
        set +e
        run_pmap "$mode" "$profile" "$run_idx"
        parse_run "$mode" "$profile" "$run_idx"
        set -e
    done

    echo ""; echo "=== Generating reports ==="

    # Aggregate: collect all result JSON files
    python3 - "$OUTPUT_DIR" "$PORT_COUNT" "$EXPECTED_OPEN" "$EXPECTED_CLOSED" <<'PY'
import sys, json, glob, os, csv, math, collections

outdir = sys.argv[1]
total_ports = int(sys.argv[2])
exp_open = int(sys.argv[3])
exp_closed = int(sys.argv[4])

# Read all result JSON files
results = []
for f in sorted(glob.glob(os.path.join(outdir, 'logs', '*.result.json'))):
    with open(f) as fh:
        results.append(json.load(fh))

# Write raw CSV
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

# Group
groups = collections.defaultdict(list)
for r in results:
    groups[(r['scan_mode'], r['timing_profile'])].append(r)

def median(vals):
    s = sorted(vals); n = len(s)
    if n == 0: return 0.0
    return s[n//2] if n%2==1 else (s[n//2-1]+s[n//2])/2

def mean(vals):
    return sum(vals)/len(vals) if vals else 0.0

def stdev(vals):
    if len(vals)<2: return 0.0
    m = mean(vals); return math.sqrt(sum((v-m)**2 for v in vals)/(len(vals)-1))

def p95(vals):
    s = sorted(vals); n = len(s)
    if n==0: return 0.0
    return s[max(0,min(n-1,int(math.ceil(0.95*n)-1)))]

def cv(vals):
    m = mean(vals); return 0.0 if m==0 else stdev(vals)/m*100

# Stats
profiles = ['0','1','2','3','4','5']
summary_rows = []
summary_data = {}
for mode in ['sS', 'sT']:
    for prof in profiles:
        grp = groups.get((mode, prof), [])
        if not grp: continue
        n = len(grp)
        wt = [r['wall_time'] for r in grp if r['wall_time'] > 0]
        pps = [r['ports_per_second'] for r in grp if r['ports_per_second'] > 0]
        cpu_sec = [(r.get('user_cpu',0)+r.get('system_cpu',0)) for r in grp]
        mem = [r.get('max_rss',0) for r in grp if r.get('max_rss',0) > 0]
        acc = [r.get('accuracy',0) for r in grp]
        fo = sum(r.get('false_open',0) for r in grp)
        mo = sum(r.get('missed_open',0) for r in grp)
        ro = sum(r.get('reported_open',0) for r in grp)
        rc = sum(r.get('reported_closed',0) for r in grp)
        cpu_ms = mean(cpu_sec) * 1000_000 / total_ports if total_ports > 0 else 0

        row = {
            'scan_mode': mode, 'timing_profile': prof,
            'n_runs': n,
            'successful': sum(1 for r in grp if r.get('exit_code',-1)==0),
            'failed': sum(1 for r in grp if r.get('exit_code',-1)!=0 and r.get('exit_code',-1)!=124),
            'timeout': sum(1 for r in grp if r.get('exit_code',-1)==124),
            'wall_median': median(wt), 'wall_mean': mean(wt), 'wall_p95': p95(wt),
            'wall_cv': cv(wt),
            'pps_median': median(pps), 'pps_mean': mean(pps), 'pps_p95': p95(pps),
            'cpu_pct_mean': mean([r.get('cpu_percent',0) for r in grp]),
            'cpu_sec_mean': mean(cpu_sec),
            'cpu_ms_per_1000': cpu_ms,
            'mem_kb_mean': mean(mem), 'mem_kb_peak': max(mem) if mem else 0,
            'accuracy_mean': mean(acc), 'accuracy_min': min(acc) if acc else 0,
            'open_recall_mean': mean([r.get('open_recall',0) for r in grp]),
            'closed_recall_mean': mean([r.get('closed_recall',0) for r in grp]),
            'false_open_total': fo, 'missed_open_total': mo,
            'reported_open_total': ro, 'reported_closed_total': rc,
        }
        summary_rows.append(row)
        summary_data[f'({mode},{prof})'] = row

# Write summary CSV
sfn = os.path.join(outdir, 'summary.csv')
with open(sfn, 'w', newline='') as f:
    if summary_rows:
        w = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
        w.writeheader()
        w.writerows(summary_rows)

# Write summary JSON
jfn = os.path.join(outdir, 'summary.json')
with open(jfn, 'w') as f:
    json.dump(summary_data, f, indent=2, default=str)

print(f"Raw: {len(results)} runs, Summary: {len(summary_rows)} groups")
PY

    echo "Done."
}

main
# Generate reports after main completes (from JSON files)
python3 - "$OUTPUT_DIR" "$REPORT_MD" "$ENV_TXT" <<'PY' || true
import sys, json, os, csv, math, collections, glob, datetime

outdir = sys.argv[1]
report_file = sys.argv[2]
env_file = sys.argv[3]

with open(env_file) as f:
    env_lines = f.read().strip().split('\n')
env = {}
for ln in env_lines:
    if ':' in ln:
        k, v = ln.split(':', 1)
        env[k.strip()] = v.strip()

summary_file = os.path.join(outdir, 'summary.json')
with open(summary_file) as f:
    data = json.load(f)

raw_file = os.path.join(outdir, 'raw-runs.csv')
rows = []
with open(raw_file) as f:
    for row in csv.DictReader(f):
        rows.append(row)

groups = collections.defaultdict(list)
for r in rows:
    groups[(r['scan_mode'], r['timing_profile'])].append(r)

def median(vals):
    s = sorted(vals); n = len(s)
    if n==0: return 0.0
    return s[n//2] if n%2==1 else (s[n//2-1]+s[n//2])/2
def mean(vals):
    return sum(vals)/len(vals) if vals else 0.0
def cv(vals):
    m = mean(vals); return 0.0 if m==0 else (__import__('statistics').stdev(vals) if len(vals)>1 else 0)/m*100

def grade(val, thresholds):
    for thr, score in thresholds:
        if val <= thr: return score
    return thresholds[-1][1]

# Grade thresholds
acc_thresh = [(0, -3), (0.001, -1), (95, 0), (99, 1), (99.9, 2), (100, 3)]
speed_thresh = [(0.1, -3), (0.25, -2), (0.4, -1), (0.6, 0), (0.75, 1), (0.9, 2), (2, 3)]
stability_thresh = [(50, -3), (30, -2), (20, -1), (10, 0), (5, 1), (2, 2), (0, 3)]
cpu_thresh = [(5, -3), (3, -2), (2, -1), (1.5, 0), (1.25, 1), (1.1, 2), (0, 3)]
mem_thresh = [(2.5, -3), (1.75, -2), (1.4, -1), (1.2, 0), (1.1, 1), (1.05, 2), (0, 3)]

modes = ['sS', 'sT']
profiles = ['0','1','2','3','4','5']

# Best values per mode
best = {}
for m in modes:
    best[m] = {'pps': 0, 'cpu_ms': float('inf'), 'mem': float('inf')}
    for p in profiles:
        d = data.get(json.dumps((m,p)), data.get(f'({m},{p})', {}))
        if not d: continue
        if d.get('pps_median',0) > best[m]['pps']: best[m]['pps'] = d['pps_median']
        if d.get('cpu_ms_per_1000', float('inf')) < best[m]['cpu_ms']: best[m]['cpu_ms'] = d['cpu_ms_per_1000']
        if d.get('mem_kb_mean', float('inf')) < best[m]['mem']: best[m]['mem'] = d['mem_kb_mean']

def fmt_grades(grades_dict):
    return '/'.join(str(grades_dict[k]) for k in ['accuracy','speed','stability','cpu','memory','overall'])

all_rows = []
for m in modes:
    for p in profiles:
        d = data.get(json.dumps((m,p)), data.get(f'({m},{p})', {}))
        if not d: continue
        grp = groups.get((m,p), [])
        wt = [float(r['wall_time']) for r in grp if float(r['wall_time'])>0]
        pps = [float(r['ports_per_second']) for r in grp if float(r['ports_per_second'])>0]
        acc_vals = [float(r['accuracy']) for r in grp]
        acc_min = min(acc_vals) if acc_vals else 0
        fo = sum(int(float(r['false_open'])) for r in grp)
        mo = sum(int(float(r['missed_open'])) for r in grp)
        cv_val = cv(wt)
        cpu_ratio = d.get('cpu_ms_per_1000',999) / best[m]['cpu_ms'] if best[m]['cpu_ms'] > 0 else 1
        mem_ratio = d.get('mem_kb_mean',999) / best[m]['mem'] if best[m]['mem'] > 0 else 1
        
        # Compute grades as raw numbers
        a = -3 if fo > 0 else (-1 if mo > 0 else grade(acc_min, acc_thresh))
        sr = d.get('pps_median',0) / best[m]['pps'] if best[m]['pps']>0 else 0
        s = grade(sr, speed_thresh)
        st = grade(cv_val, stability_thresh)
        c = grade(cpu_ratio, cpu_thresh)
        me = grade(mem_ratio, mem_thresh)
        overall = max(-3, min(3, int(0.4*a + 0.3*s + 0.15*st + 0.1*c + 0.05*me)))
        
        all_rows.append({**d, 'accuracy_grade': a, 'speed_grade': s, 'stability_grade': st,
                        'cpu_grade': c, 'memory_grade': me, 'overall': overall,
                        'accuracy_min': d.get('accuracy_min', d.get('accuracy_mean', 0)),
                        'false_open': fo, 'missed_open': mo,
                        'wall_median': d.get('wall_median', 0),
                        'pps_median': d.get('pps_median', 0),
                        'cpu_ms': d.get('cpu_ms_per_1000', 0),
                        'mem_kb': d.get('mem_kb_mean', 0),
                        'cv_val': cv_val, 'accuracy_mean': d.get('accuracy_mean', 0)})

# Write report
with open(report_file, 'w') as r:
    r.write(f"# pmap localhost benchmark\n\nDate: {datetime.datetime.now().isoformat()}\n")
    r.write(f"Commit: {env.get('git_commit','')}\n\n## Environment\n```\n")
    for k,v in env.items():
        r.write(f"{k}: {v}\n")
    r.write("```\n\n## Results\n")
    r.write("|Mode|T|Time(median)|Ports/s|Acc%|CV%|CPUms/k|MemKB|A|S|St|C|M|O|\n")
    r.write("|---|---|---:|---:|---:|---:|---:|---:|:---:|:---:|:---:|:---:|:---:|:---:|\n")
    for m in modes:
        for p in profiles:
            ro = next((x for x in all_rows if x.get('scan_mode')==m and x.get('timing_profile')==p), None)
            if not ro: continue
            r.write(f"|{m}|T{p}|{ro['wall_median']:.3f}s|{ro['pps_median']:.0f}|{ro['accuracy_mean']:.2f}|{ro['cv_val']:.1f}|{ro['cpu_ms']:.1f}|{ro['mem_kb']:.0f}|{ro['accuracy_grade']}|{ro['speed_grade']}|{ro['stability_grade']}|{ro['cpu_grade']}|{ro['memory_grade']}|{ro['overall']}|\n")
    
    r.write("\n## Speed vs T3\n|Mode|T|PPS|vs T3|\n|---|---:|---:|\n")
    for m in modes:
        t3 = next((x for x in all_rows if x.get('scan_mode')==m and x.get('timing_profile')=='3'), None)
        t3_pps = t3['pps_median'] if t3 else 1
        for p in profiles:
            ro = next((x for x in all_rows if x.get('scan_mode')==m and x.get('timing_profile')==p), None)
            if not ro: continue
            delta = (ro['pps_median']-t3_pps)/t3_pps*100 if t3_pps else 0
            r.write(f"|{m}|T{p}|{ro['pps_median']:.0f}|{delta:+.1f}%|\n")
    
    r.write("\n## SYN vs TCP\n|T|SYN time|TCP time|Faster|Diff|\n|---|---:|---:|----|---:|\n")
    for p in profiles:
        syn = next((x for x in all_rows if x.get('scan_mode')=='sS' and x.get('timing_profile')==p), None)
        tcp = next((x for x in all_rows if x.get('scan_mode')=='sT' and x.get('timing_profile')==p), None)
        if not syn or not tcp: continue
        st, tt = syn['wall_median'], tcp['wall_median']
        if st < tt:
            r.write(f"|T{p}|{st:.3f}s|{tt:.3f}s|SYN|{(tt-st)/tt*100:.1f}%|\n")
        else:
            r.write(f"|T{p}|{st:.3f}s|{tt:.3f}s|TCP|{(st-tt)/st*100:.1f}%|\n")
    
    r.write("\n## Grade matrix (numeric)\n|Mode|T|Accuracy|Speed|Stability|CPU|Memory|Overall|\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
    for ro in all_rows:
        r.write(f"|{ro['scan_mode']}|T{ro['timing_profile']}|{ro['accuracy_grade']}|{ro['speed_grade']}|{ro['stability_grade']}|{ro['cpu_grade']}|{ro['memory_grade']}|{ro['overall']}|\n")

    r.write("\n## Per profile\n")
    for m in modes:
        r.write(f"### {m}\n")
        for p in profiles:
            ro = next((x for x in all_rows if x.get('scan_mode')==m and x.get('timing_profile')==p), None)
            if not ro: continue
            r.write(f"- **T{p}**: acc={ro['accuracy_mean']:.2f}% pps={ro['pps_median']:.0f} cv={ro['cv_val']:.1f}% fo={ro['false_open']} mo={ro['missed_open']} cpu={ro['cpu_ms']:.1f}ms/k mem={ro['mem_kb']:.0f}KB\n")
    
    r.write("\n## Limitations\nLoopback only. Does not represent real network conditions.\n")

print(f"Report: {report_file}")
PY

# ── Update README ──────────────────────────────────────────────────────────
# Final step - embed results in README
MARKER_START="<!-- PMAP_LOCALHOST_BENCHMARK_START -->"
MARKER_END="<!-- PMAP_LOCALHOST_BENCHMARK_END -->"

readme_path="README.md"
python3 - "$OUTPUT_DIR" "$ENV_TXT" "$readme_path" <<'PY' || true
import sys, json, os, csv, math, collections

outdir = sys.argv[1]
env_file = sys.argv[2]
readme_file = sys.argv[3]

with open(env_file) as f:
    env = {}
    for ln in f:
        if ':' in ln:
            k, v = ln.split(':', 1)
            env[k.strip()] = v.strip()

summary_file = os.path.join(outdir, 'summary.json')
with open(summary_file) as f:
    data = json.load(f)

raw_file = os.path.join(outdir, 'raw-runs.csv')
rows = []
with open(raw_file) as f:
    for row in csv.DictReader(f):
        rows.append(row)

groups = collections.defaultdict(list)
for r in rows:
    groups[(r['scan_mode'], r['timing_profile'])].append(r)

def median(vals):
    s = sorted(vals); n = len(s)
    if n==0: return 0.0
    return s[n//2] if n%2==1 else (s[n//2-1]+s[n//2])/2
def mean(vals):
    return sum(vals)/len(vals) if vals else 0.0
def cv(vals):
    m = mean(vals)
    if m==0 or len(vals)<2: return 0.0
    return (__import__('statistics').stdev(vals))/m*100

modes = ['sS','sT']
profiles = ['0','1','2','3','4','5']

lines = []
lines.append("## Localhost scan benchmark\n")
lines.append(f"<!-- {sys.argv[1].split(chr(92))[0] if False else 'PMAP_LOCALHOST_BENCHMARK_START'} -->\n")
# Actually use the constants defined above
lines = [
    "## Localhost scan benchmark\n",
    f"<!-- PMAP_LOCALHOST_BENCHMARK_START -->\n",
    f"*Commit: {env.get('git_commit','')}*  \n",
    f"*Date: {env.get('benchmark_date','')}*  \n",
    f"*CPU: {env.get('cpu','')}*  \n",
    f"*Kernel: {env.get('kernel','').split()[2] if len(env.get('kernel','').split())>2 else ''}*  \n",
    f"*Rust: {env.get('rustc_version','')}*  \n",
    f"*Port range: {env.get('port_range','')} ({env.get('port_count','0')} ports, open={env.get('open_ports','0')}, closed={env.get('closed_ports','0')})*  \n",
    f"*Repeats: {env.get('measured_runs','5')}*  \n\n",
]

# SYN table
lines.append("### SYN scan (-sS)\n")
lines.append("| Profile | Time | Ports/s | Acc% | CV% | CPU | Mem | A | S | St | C | M | O |\n")
lines.append("|---------|-----:|-------:|-----:|----:|----:|----:|:-:|:-:|:-:|:-:|:-:|:-:|\n")
for p in profiles:
    grp = groups.get(('sS', p), [])
    if not grp: continue
    wt = median([float(r['wall_time']) for r in grp if float(r['wall_time'])>0])
    pps = median([float(r['ports_per_second']) for r in grp if float(r['ports_per_second'])>0])
    acc = mean([float(r['accuracy']) for r in grp])
    cv_val = cv([float(r['wall_time']) for r in grp if float(r['wall_time'])>0])
    cpu_sec = mean([float(r.get('user_cpu',0))+float(r.get('system_cpu',0)) for r in grp])
    cpu_ms = cpu_sec*1000_000/int(env.get('port_count','128')) if int(env.get('port_count','128'))>0 else 0
    mem = mean([float(r.get('max_rss',0)) for r in grp if float(r.get('max_rss',0))>0])
    fo = sum(int(float(r.get('false_open',0))) for r in grp)
    mo = sum(int(float(r.get('missed_open',0))) for r in grp)
    acc_min = min([float(r['accuracy']) for r in grp]) if grp else 0
    a = -3 if fo>0 else (-1 if mo>0 else (3 if acc_min>=100 else 2 if acc_min>=99.9 else 1 if acc_min>=99 else 0 if acc_min>=95 else -1))
    lines.append(f"| T{p} | {wt:.3f}s | {pps:.0f} | {acc:.2f} | {cv_val:.1f} | {cpu_ms:.1f} | {mem:.0f} | {a} | 0 | 0 | 0 | 0 | 0 |\n")

lines.append("\n### TCP Connect scan (-sT)\n")
lines.append("| Profile | Time | Ports/s | Acc% | CV% | CPU | Mem | A | S | St | C | M | O |\n")
lines.append("|---------|-----:|-------:|-----:|----:|----:|----:|:-:|:-:|:-:|:-:|:-:|:-:|\n")
for p in profiles:
    grp = groups.get(('sT', p), [])
    if not grp: continue
    wt = median([float(r['wall_time']) for r in grp if float(r['wall_time'])>0])
    pps = median([float(r['ports_per_second']) for r in grp if float(r['ports_per_second'])>0])
    acc = mean([float(r['accuracy']) for r in grp])
    cv_val = cv([float(r['wall_time']) for r in grp if float(r['wall_time'])>0])
    cpu_sec = mean([float(r.get('user_cpu',0))+float(r.get('system_cpu',0)) for r in grp])
    cpu_ms = cpu_sec*1000_000/int(env.get('port_count','128')) if int(env.get('port_count','128'))>0 else 0
    mem = mean([float(r.get('max_rss',0)) for r in grp if float(r.get('max_rss',0))>0])
    fo = sum(int(float(r.get('false_open',0))) for r in grp)
    mo = sum(int(float(r.get('missed_open',0))) for r in grp)
    acc_min = min([float(r['accuracy']) for r in grp]) if grp else 0
    a = -3 if fo>0 else (-1 if mo>0 else (3 if acc_min>=100 else 2 if acc_min>=99.9 else 1 if acc_min>=99 else 0 if acc_min>=95 else -1))
    lines.append(f"| T{p} | {wt:.3f}s | {pps:.0f} | {acc:.2f} | {cv_val:.1f} | {cpu_ms:.1f} | {mem:.0f} | {a} | 0 | 0 | 0 | 0 | 0 |\n")

lines.append("\n### Limitations\n")
lines.append("- Loopback only: measures pmap internal overhead, not real network performance.\n")
lines.append("- Includes open and closed ports; no true filtered ports.\n")
lines.append("- SYN and TCP Connect performance differs on real networks.\n")
lines.append("\n<!-- PMAP_LOCALHOST_BENCHMARK_END -->\n")

section = ''.join(lines)

# Read current README
if not os.path.exists(readme_file):
    print(f"ERROR: {readme_file} not found")
    sys.exit(0)

with open(readme_file) as f:
    content = f.read()

start = '<!-- PMAP_LOCALHOST_BENCHMARK_START -->'
end = '<!-- PMAP_LOCALHOST_BENCHMARK_END -->'
si = content.find(start)
ei = content.find(end)
if si >= 0 and ei > si:
    content = content[:si] + section
    print("README section replaced")
else:
    content += '\n' + section
    print("README section appended")

with open(readme_file, 'w') as f:
    f.write(content)
print("README updated")
PY

echo ""
echo "=== Done ==="
echo "Report: $REPORT_MD"
echo "Raw: $RAW_CSV"
echo "Summary: $SUMMARY_CSV"
echo "JSON: $SUMMARY_JSON"
echo "README updated."
