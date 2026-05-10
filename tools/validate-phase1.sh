#!/usr/bin/env bash
# validate-phase1.sh — automated Phase 1 PASS check.
#
# Captures /dev/ttyACM0 output for a few seconds, then greps for the markers
# that prove a successful Phase 1 firmware boot:
#   - "[boot] nixtropic phase 1 — USB CDC up"   → USB CDC enumerated
#   - "[hal_rng]"                                → STM32 RNG works
#   - "[tropic] lt_init OK"                      → libtropic L1 link up
#   - "[chip_id]" with TR01-C2P-T101 ASCII bytes → chip ID matches Phase 0
#   - "[chip_id]" with S/N 02 00 11 01 ...        → S/N matches Phase 0
#   - "[tropic] L2 sweep PASS"                   → L2 round-trip clean
#   - "[boot] PHASE1 OK"                         → final marker
#
# Exits 0 on PASS, non-zero with diff on FAIL.
#
# Usage:
#   tools/validate-phase1.sh            (assumes /dev/ttyACM0)
#   TROPIC_DEV=/dev/ttyACM1 tools/validate-phase1.sh

set -uo pipefail

TIMEOUT="${TROPIC_VALIDATE_TIMEOUT:-8}"

# Auto-detect /dev/ttyACM* if TROPIC_DEV not explicitly set.
# Kernel may assign /dev/ttyACM1 (or higher) if /dev/ttyACM0 is held by
# a stale enumeration or another device. Prefer first existing node.
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
    echo "FAIL: no /dev/ttyACM* device found. Is the dongle plugged in and running custom firmware?" >&2
    echo "      (Stock firmware enumerates as 0483:5740, not our 0xCAFE:0x4001.)" >&2
    if command -v lsusb >/dev/null 2>&1; then
        echo "" >&2
        echo "  Current USB state for TS1302-related VIDs:" >&2
        lsusb 2>/dev/null | grep -E "0483:|cafe:" | sed 's/^/    /' >&2 || echo "    (no TS1302 device seen)" >&2
    fi
    exit 2
fi

if [ ! -r "$DEV" ]; then
    echo "FAIL: $DEV not readable as $USER. Try sudo, or add user to dialout group" >&2
    echo "      OR enable services.tropic in your NixOS config (nixosModules.tropic)." >&2
    exit 2
fi

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

echo "Capturing $DEV for ${TIMEOUT}s..." >&2
echo "" >&2
echo "NOTE: this script greps for boot markers (e.g. '[chip_id] ...', '[tropic]"  >&2
echo "      L2 sweep PASS') that emit ONCE at boot. If the dongle has already" >&2
echo "      been running for a while, those markers are no longer in the live" >&2
echo "      stream and validation will FAIL. To capture them, run:" >&2
echo "" >&2
echo "        sudo nix run .#flash-and-validate" >&2
echo "" >&2
echo "      ...which DFU-flashes the firmware and IMMEDIATELY captures the" >&2
echo "      fresh boot output. (Or do it manually: flash-firmware, then run" >&2
echo "      this script within ~5 seconds before the boot block scrolls off.)" >&2
echo "" >&2

timeout "$TIMEOUT" cat "$DEV" > "$LOG" 2>/dev/null || true

# Phase 0 baseline canonical bytes (from STATUS.md 2026-05-10)
LONG_PN_BYTES="54 52 30 31 2d 43 32 50 2d 54 31 30 31"  # "TR01-C2P-T101"
SN_BYTES="02 00 11 01 08 5b 19 05 09 0d 00 00 00 00 04 8b"  # full S/N
SILICON_REV="41 43 41 42"  # "ACAB"

declare -a CHECKS=(
    "boot_block:\\[boot\\] nixtropic phase 1"
    "hal_rng:\\[hal_rng\\]"
    "lt_init:\\[tropic\\] lt_init OK"
    "chip_id_present:\\[chip_id\\]"
    "chip_id_silicon_rev_acab:\\[chip_id\\].*${SILICON_REV}"
    "chip_id_long_pn_match:\\[chip_id\\].*${LONG_PN_BYTES}"
    "chip_id_sn_match:\\[chip_id\\].*${SN_BYTES}"
    "riscv_fw:\\[riscv_fw\\]"
    "spect_fw:\\[spect_fw\\]"
    "l2_sweep_pass:\\[tropic\\] L2 sweep PASS"
    "phase1_ok:PHASE1 OK"
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
    echo "  ✓ Phase 1 validation PASS ($PASSED/${#CHECKS[@]} checks)"
    echo "═══════════════════════════════════════════════════════════════"
    exit 0
else
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ✗ Phase 1 validation FAIL ($ERRORS errors, $PASSED passed)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "--- Captured output (first 50 lines) ---"
    head -50 "$LOG"
    echo "--- end ---"
    exit 1
fi
