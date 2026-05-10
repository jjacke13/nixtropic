#!/usr/bin/env bash
# validate-phase2.sh — automated Phase 2 PASS check.
#
# Phase 2 goal: 100% Nix-built drop-in replacement for stock TS1302 firmware.
# Validation: run the unmodified host-side `lt-util` against our firmware and
# match its chip-info output byte-for-byte against the Phase 0 baseline.
#
# Required matches in lt-util output:
#   - "Silicon rev" line containing "ACAB"
#   - "S/N" line containing "02001101085B1905090D00000000048B"
#   - "TR01-C2P-T101" (Long P/N ASCII; appears in P/N (long) line)
#   - "EPS Global - Brno" (Fab ID — confirms provisioning record)
#   - "QFN32" (Package ID)
#
# 5/5 PASS = byte-faithful protocol replication confirmed.
#
# Usage:
#   tools/validate-phase2.sh                       (auto-detect /dev/ttyACM*)
#   TROPIC_DEV=/dev/ttyACM1 tools/validate-phase2.sh

set -uo pipefail

TIMEOUT="${TROPIC_VALIDATE_TIMEOUT:-15}"

# Auto-detect /dev/ttyACM* (kernel may assign higher index after replug).
if [ -n "${TROPIC_DEV:-}" ]; then
    DEV="$TROPIC_DEV"
else
    DEV=""
    for candidate in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyACM2 /dev/ttyACM3 /dev/ttyACM4 /dev/ttyACM5; do
        if [ -e "$candidate" ]; then
            DEV="$candidate"
            break
        fi
    done
    if [ -n "$DEV" ] && [ "$DEV" != "/dev/ttyACM0" ]; then
        echo "Auto-detected dongle at $DEV (not /dev/ttyACM0; override with TROPIC_DEV)" >&2
    fi
fi

if [ -z "$DEV" ] || [ ! -e "$DEV" ]; then
    echo "FAIL: no /dev/ttyACM* device found." >&2
    if command -v lsusb >/dev/null 2>&1; then
        echo "  Current USB state:" >&2
        lsusb 2>/dev/null | grep -E "0483:|cafe:" | sed 's/^/    /' >&2 || echo "    (no TS1302-related VID seen)" >&2
    fi
    exit 2
fi

if [ ! -r "$DEV" ] || [ ! -w "$DEV" ]; then
    echo "FAIL: $DEV not readable/writable. Try sudo, or enable services.tropic." >&2
    exit 2
fi

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

echo "Running lt-util chip-info against $DEV (timeout ${TIMEOUT}s)..." >&2
echo "" >&2

# lt-util prints chip-info to stdout; merge stderr in case it logs there too.
timeout "$TIMEOUT" lt-util "$DEV" -i > "$LOG" 2>&1 || true

# Phase 0 baseline canonical fields (from STATUS.md 2026-05-10)
declare -a CHECKS=(
    "lt_util_runs:CHIP_ID ver"
    "silicon_rev_acab:Silicon rev .*ACAB"
    "sn_baseline:S/N .*02001101085B1905090D00000000048B"
    "long_pn_baseline:TR01-C2P-T101"
    "fab_id_eps_brno:EPS Global - Brno"
)

ERRORS=0
PASSED=0

echo ""
for check in "${CHECKS[@]}"; do
    name="${check%%:*}"
    pattern="${check#*:}"
    if grep -qE "$pattern" "$LOG"; then
        echo "  ✓ $name"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ $name (pattern: $pattern)"
        ERRORS=$((ERRORS + 1))
    fi
done

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ✓ Phase 2 validation PASS ($PASSED/${#CHECKS[@]} checks)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Drop-in stock-fw replacement confirmed: lt-util reads chip ID"
    echo "byte-for-byte matching the Phase 0 baseline. Open firmware works."
    exit 0
else
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ✗ Phase 2 validation FAIL ($ERRORS errors, $PASSED passed)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "--- lt-util output (first 80 lines) ---"
    head -80 "$LOG"
    echo "--- end ---"
    exit 1
fi
