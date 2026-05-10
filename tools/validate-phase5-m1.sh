#!/usr/bin/env bash
# Phase 5 M1 validation: exercises the TROPIC01-backed slot manager
# (firmware/src/fido_hid/slots.{h,c}) end-to-end via the lt-rpc debug
# commands (LT_RPC_CMD_SLOTS_*). Tests bitmap, alloc, erase, meta
# round-trip, and first-free allocation policy.
#
# This is the HW-in-the-loop checkpoint between M1 and M2 per
# docs/PHASE-5-PLAN.md §5.
#
# Exit code 0 = all 7 checks passed; non-zero = at least one failed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PY_CLIENT="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 5 M1 validation — TROPIC01 slot manager"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -e "$PY_CLIENT" ]; then
  echo "ERROR: $PY_CLIENT not found." >&2
  exit 2
fi

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated on USB." >&2
  echo "       Is the firmware flashed and the dongle plugged in?" >&2
  exit 3
fi

python3 "$PY_CLIENT" validate-m1
rc=$?

echo ""
if [ $rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 5 M1 validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "TROPIC01 R-mem-backed slot manager validated:"
  echo "  - First-boot detection + magic bytes"
  echo "  - Alloc + erase + first-free allocation"
  echo "  - rpIdHash and credential-ID nonce round-trip"
  echo "  - Factory reset wipes all state"
  echo ""
  echo "Next: M2 — wire credstore.c onto slots + lt_ecc_key_generate"
  echo "         (THE MIC-DROP — webauthn.io demo)"
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 5 M1 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi

exit $rc
