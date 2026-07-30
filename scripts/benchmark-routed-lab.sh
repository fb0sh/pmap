#!/usr/bin/env bash
set -euo pipefail

# pmap routed-lab benchmark
# Creates 3 namespaces: scanner → router → target
# Tests cross-subnet scanning with controlled network conditions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

SCANNER_NS="pmap-scanner"
ROUTER_NS="pmap-router"
TARGET_NS="pmap-target"

SCANNER_IP="10.210.1.2/24"
ROUTER_IP1="10.210.1.1/24"
ROUTER_IP2="10.210.2.1/24"
TARGET_IP="10.210.2.2/24"

cleanup() {
    echo "Cleaning up..."
    ip netns del "$TARGET_NS" 2>/dev/null || true
    ip netns del "$ROUTER_NS" 2>/dev/null || true
    ip netns del "$SCANNER_NS" 2>/dev/null || true
    ip link del veth-scanner 2>/dev/null || true
    ip link del veth-target 2>/dev/null || true
    nft delete table inet pmap_bench 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== pmap routed-lab benchmark ==="
cleanup 2>/dev/null

# ── Create namespaces and veth pairs ──
ip netns add "$SCANNER_NS"
ip netns add "$ROUTER_NS"
ip netns add "$TARGET_NS"

# Scanner ↔ Router
ip link add veth-scanner type veth peer name veth-router1
ip link set veth-scanner netns "$SCANNER_NS"
ip link set veth-router1 netns "$ROUTER_NS"

# Router ↔ Target
ip link add veth-target type veth peer name veth-router2
ip link set veth-target netns "$TARGET_NS"
ip link set veth-router2 netns "$ROUTER_NS"

# ── Configure IPs ──
ip netns exec "$SCANNER_NS" ip addr add "$SCANNER_IP" dev veth-scanner
ip netns exec "$SCANNER_NS" ip link set veth-scanner up
ip netns exec "$SCANNER_NS" ip route add default via 10.210.1.1

ip netns exec "$ROUTER_NS" ip addr add "$ROUTER_IP1" dev veth-router1
ip netns exec "$ROUTER_NS" ip link set veth-router1 up
ip netns exec "$ROUTER_NS" ip addr add "$ROUTER_IP2" dev veth-router2
ip netns exec "$ROUTER_NS" ip link set veth-router2 up
ip netns exec "$ROUTER_NS" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

ip netns exec "$TARGET_NS" ip addr add "$TARGET_IP" dev veth-target
ip netns exec "$TARGET_NS" ip link set veth-target up
ip netns exec "$TARGET_NS" ip route add default via 10.210.2.1

sleep 0.5

# Verify connectivity
echo "Testing connectivity..."
ip netns exec "$SCANNER_NS" ping -c 1 -W 1 10.210.2.2 >/dev/null 2>&1 && echo "  Scanner → Target: OK" || echo "  Scanner → Target: FAIL"

# ── Setup target ports ──
BASE_PORT=20000
PORT_COUNT=128
OPEN_RATIO=25

# Generate expected.csv
EXPECTED_CSV="/tmp/pmap-routed-expected.csv"
echo "port,state" > "$EXPECTED_CSV"
for ((i=0; i<PORT_COUNT; i++)); do
    port=$((BASE_PORT + i))
    if (( i % (100 / OPEN_RATIO) == 0 )); then
        echo "$port,open" >> "$EXPECTED_CSV"
    else
        echo "$port,closed" >> "$EXPECTED_CSV"
    fi
done
OPEN_PORTS=$(grep -c ',open$' "$EXPECTED_CSV")

# Start listener in target namespace
echo "Starting listener in $TARGET_NS ($OPEN_PORTS open ports)..."
ip netns exec "$TARGET_NS" python3 -c "
import socket, selectors, signal, os
ports = list(range($BASE_PORT, $BASE_PORT + $PORT_COUNT))
step = 100 // $OPEN_RATIO
open_ports = [p for i, p in enumerate(ports) if i % step == 0]
socks = []
sel = selectors.DefaultSelector()
for p in open_ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind(('0.0.0.0', p))
    s.listen(128)
    sel.register(s, selectors.EVENT_READ)
    socks.append(s)
with open('/tmp/pmap-routed-ready', 'w') as f: f.write('1')
signal.signal(signal.SIGTERM, lambda *a: exec('raise SystemExit(0)'))
try:
    while True:
        for key, _ in sel.select(timeout=0.5):
            conn, _ = key.fileobj.accept(); conn.close()
except: pass
for s in socks: s.close()
" &
LISTENER_PID=$!
sleep 1

# Add nftables DROP rule for filtered test
ip netns exec "$TARGET_NS" nft add table inet pmap_bench 2>/dev/null || true
ip netns exec "$TARGET_NS" nft add chain inet pmap_bench input { type filter hook input priority 0\; } 2>/dev/null || true
# Drop port 20002 for filtered testing
ip netns exec "$TARGET_NS" nft add rule inet pmap_bench input tcp dport 20002 drop 2>/dev/null || true
echo "  nftables DROP rule added for port 20002"

# ── Run benchmark ──
echo ""
echo "=== Running benchmark ==="
for mode in sT sS; do
    for profile in 3 5; do
        echo ""
        echo "--- $mode T$profile ---"
        if [[ "$mode" == "sS" ]]; then
            PREFIX="sudo"
        else
            PREFIX=""
        fi
        timeout 30 bash -c "time ip netns exec $SCANNER_NS $PREFIX $PROJECT_DIR/target/release/pmap -$mode -T$profile -Pn -p $BASE_PORT-$((BASE_PORT+PORT_COUNT-1)) --closed 10.210.2.2" 2>&1 | grep -E "open:|closed:|filtered:|elapsed|real|unknown"
    done
done

# ── Cleanup ──
kill $LISTENER_PID 2>/dev/null || true
echo ""
echo "=== Cleanup ==="
cleanup
echo "Done."
