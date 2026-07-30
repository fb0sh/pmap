#!/usr/bin/env bash
set -euo pipefail

# Remote listener for pmap benchmark.
# Run this on the target machine, then give the IP to the controller.
#
# Usage:
#   bash remote-listener.sh              # default: 20000-20127, 25% open
#   bash remote-listener.sh --base-port 30000 --port-count 256 --open-ratio 50

BASE_PORT=20000
PORT_COUNT=128
OPEN_RATIO=25  # percent

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-port) BASE_PORT="$2"; shift 2 ;;
        --port-count) PORT_COUNT="$2"; shift 2 ;;
        --open-ratio) OPEN_RATIO="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: bash remote-listener.sh [--base-port N] [--port-count N] [--open-ratio N]"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

END_PORT=$((BASE_PORT + PORT_COUNT - 1))
OPEN_COUNT=$((PORT_COUNT * OPEN_RATIO / 100))
CLOSED_COUNT=$((PORT_COUNT - OPEN_COUNT))

echo "=== pmap remote listener ==="
echo "Port range: $BASE_PORT-$END_PORT ($PORT_COUNT ports)"
echo "Open ratio: $OPEN_RATIO% (${OPEN_COUNT} open, ${CLOSED_COUNT} closed)"

# Generate expected.csv
EXPECTED_CSV="/tmp/pmap-expected-$$.csv"
echo "port,state" > "$EXPECTED_CSV"
for ((i=0; i<PORT_COUNT; i++)); do
    port=$((BASE_PORT + i))
    step=$((100 / OPEN_RATIO))
    if (( i % step == 0 )); then
        echo "$port,open" >> "$EXPECTED_CSV"
    else
        echo "$port,closed" >> "$EXPECTED_CSV"
    fi
done

# Write open ports list
OPEN_PORTS_FILE="/tmp/pmap-open-$$.txt"
awk -F',' '/,open$/ {print $1}' "$EXPECTED_CSV" > "$OPEN_PORTS_FILE"

cleanup() {
    echo ""
    echo "Shutting down listener..."
    [[ -n "${LISTENER_PID:-}" ]] && kill "$LISTENER_PID" 2>/dev/null || true
    rm -f "$EXPECTED_CSV" "$OPEN_PORTS_FILE" 2>/dev/null || true
    echo "Cleaned up."
}
trap cleanup EXIT INT TERM

# Start Python listener
echo "Starting listener on $OPEN_COUNT open ports..."
python3 - "$OPEN_PORTS_FILE" <<'PY' &
import socket, selectors, sys, os, signal

with open(sys.argv[1]) as f:
    ports = [int(l.strip()) for l in f if l.strip()]

sel = selectors.DefaultSelector()
socks = []
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    try:
        s.bind(('0.0.0.0', port))
        s.listen(128)
        sel.register(s, selectors.EVENT_READ)
        socks.append(s)
    except OSError as e:
        print(f"ERROR binding port {port}: {e}", file=sys.stderr)
        for sock in socks:
            sock.close()
        sys.exit(1)

# Signal readiness
ready_file = '/tmp/pmap-listener-ready'
try:
    with open(ready_file, 'w') as f:
        f.write('1')
        os.fsync(f.fileno())
except:
    pass

stop = False
def handler(s, f):
    global stop; stop = True
signal.signal(signal.SIGTERM, handler)

while not stop:
    for key, _ in sel.select(timeout=0.5):
        conn, addr = key.fileobj.accept()
        conn.close()

for s in socks:
    s.close()
PY
LISTENER_PID=$!

# Wait for ready
sleep 1
if [[ ! -f /tmp/pmap-listener-ready ]]; then
    echo "ERROR: listener failed to start"
    exit 1
fi
rm -f /tmp/pmap-listener-ready

echo "Listener PID=$LISTENER_PID"
echo ""
echo "============================================="
echo "  Give this IP to the benchmark controller:"
echo ""
HOST_IP=$(ip -4 addr show 2>/dev/null | grep -o 'inet [0-9.]*' | head -1 | cut -d' ' -f2 || ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}')
echo "    $HOST_IP"
echo ""
echo "  Expected CSV saved: $EXPECTED_CSV"
echo "  Range: $BASE_PORT-$END_PORT ($PORT_COUNT ports)"
echo "  Open: $OPEN_COUNT  Closed: $CLOSED_COUNT"
echo "============================================="
echo ""
echo "Press Ctrl+C to stop listener."

# Wait forever
while true; do
    sleep 60
done
