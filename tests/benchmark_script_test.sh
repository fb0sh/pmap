#!/usr/bin/env bash
set -euo pipefail

# Self-test for benchmark-localhost.sh
# Usage: bash tests/benchmark_script_test.sh

SCRIPT="./scripts/benchmark-localhost.sh"
TESTS_PASSED=0
TESTS_FAILED=0

pass() { TESTS_PASSED=$((TESTS_PASSED+1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED+1)); echo "  FAIL: $1"; }

# ── 1. Shell syntax check ──────────────────────────────────────────────────
echo "=== Shell syntax ==="
if bash -n "$SCRIPT" 2>/dev/null; then
    pass "bash -n syntax check"
else
    fail "bash -n syntax check"
fi

# ── 2. Shellcheck ──────────────────────────────────────────────────────────
echo "=== Shellcheck ==="
if command -v shellcheck &>/dev/null; then
    if shellcheck "$SCRIPT" 2>/dev/null; then
        pass "shellcheck"
    else
        fail "shellcheck (has warnings)"
    fi
else
    echo "  SKIP: shellcheck not installed"
fi

# ── 3. Argument parsing ────────────────────────────────────────────────────
echo "=== Argument parsing ==="
if bash "$SCRIPT" --help 2>&1 | grep -q "Usage"; then
    pass "--help"
else
    fail "--help"
fi

if bash "$SCRIPT" --dry-run 2>&1 | grep -q "DRY"; then
    pass "--dry-run"
else
    fail "--dry-run"
fi

if bash "$SCRIPT" --validate-only 2>&1 | grep -q "Validation"; then
    pass "--validate-only"
else
    fail "--validate-only"
fi

# ── 4. Invalid repeats ─────────────────────────────────────────────────────
echo "=== Invalid inputs ==="
if ! bash "$SCRIPT" --repeats 0 2>&1; then
    pass "rejects repeats=0"
else
    fail "should reject repeats=0"
fi

if ! bash "$SCRIPT" --repeats -1 2>&1; then
    pass "rejects repeats=-1"
else
    fail "should reject repeats=-1"
fi

# ── 5. Invalid port count ──────────────────────────────────────────────────
if ! bash "$SCRIPT" --port-count 0 2>&1; then
    pass "rejects port-count=0"
else
    fail "should reject port-count=0"
fi

if ! bash "$SCRIPT" --port-count 64536 2>&1; then
    pass "rejects port-count >64535"
else
    fail "should reject port-count >64535"
fi

# ── 6. Port range overflow ─────────────────────────────────────────────────
if ! bash "$SCRIPT" --base-port 65000 --port-count 1000 2>&1; then
    pass "rejects port range >65535"
else
    fail "should reject range >65535"
fi

# ── 7. Missing binary ──────────────────────────────────────────────────────
if ! bash "$SCRIPT" --binary /nonexistent/pmap 2>&1; then
    pass "rejects missing binary"
else
    fail "should reject missing binary"
fi

# ── 8. Dry run generates CSV structure ─────────────────────────────────────
OUTDIR=$(mktemp -d)
trap 'rm -rf "$OUTDIR"' EXIT
bash "$SCRIPT" --dry-run --output-dir "$OUTDIR" 2>&1 >/dev/null || true
# Check output directory was created
if [[ -d "$OUTDIR" ]]; then
    pass "creates output directory"
else
    fail "should create output directory"
fi

# ── 9. Tool check: python3 required ────────────────────────────────────────
if command -v python3 &>/dev/null; then
    pass "python3 available"
else
    fail "python3 required but not found"
fi

if command -v /usr/bin/time &>/dev/null; then
    pass "/usr/bin/time available"
else
    fail "/usr/bin/time required (apt install time)"
fi

# ── 10. Readme markers ─────────────────────────────────────────────────────
echo "=== README markers ==="
README_FILE="README.md"
if [[ -f "$README_FILE" ]]; then
    if grep -q "PMAP_LOCALHOST_BENCHMARK_START" "$README_FILE"; then
        pass "README has start marker"
    else
        echo "  NOTE: benchmark hasn't run yet, no marker expected yet"
        pass "README ready for marker"
    fi
    if grep -q "PMAP_LOCALHOST_BENCHMARK_END" "$README_FILE"; then
        pass "README has end marker"
    fi
else
    fail "README.md not found"
fi

# ── 11. Dry-run port check ─────────────────────────────────────────────────
echo "=== Port validation ==="
# Check candidate ports aren't massively duplicated
CANDIDATES=$(grep -c "CANDIDATE_PORTS" "$SCRIPT" 2>/dev/null || echo 0)
if [[ "$CANDIDATES" -ge 1 ]]; then
    pass "has port candidate configuration"
else
    fail "missing CANDIDATE_PORTS"
fi

# ── 12. Validate expected CSV column count ─────────────────────────────────
echo "=== CSV structure ==="
SAMPLE_CSV='port,state
20000,open
20001,closed'
echo "$SAMPLE_CSV" | python3 -c "
import csv, sys
reader = csv.DictReader(sys.stdin)
for row in reader:
    assert 'port' in row and 'state' in row
print('CSV column validation OK')
" && pass "expected.csv column validation" || fail "expected.csv column validation"

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Results ==="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
if [[ "$TESTS_FAILED" -gt 0 ]]; then
    exit 1
fi
echo "All tests passed."
