#!/usr/bin/env bash
# Phase 3 validation: runs `lt_rpc.py validate` against the currently
# connected nixtropic firmware. Wraps the Python client so the nix app
# can present a uniform pass/fail summary alongside validate-phase1 and
# validate-phase2.
#
# Exit code 0 = all checks passed; non-zero = at least one check failed.

set -uo pipefail

# Path to the Python lt-rpc client. The Nix app wrapper sets
# LT_RPC_PY explicitly so we don't depend on $0 (which resolves to a
# /nix/store/... path that no longer sits beside tools/lt_rpc.py).
# When run from the repo directly, fall back to the sibling file.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PY_CLIENT="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 3 validation — lt-rpc-over-HID (PING / RANDOM / CHIP_ID / SIGN)"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -e "$PY_CLIENT" ]; then
  echo "ERROR: $PY_CLIENT not found." >&2
  exit 2
fi

# Quick sanity: HID interface enumerated?
if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated on USB." >&2
  echo "       Is the firmware flashed and the dongle plugged in?" >&2
  exit 3
fi

python3 "$PY_CLIENT" validate
rc=$?

echo ""
if [ $rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 3 validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Composite USB (CDC + HID), lt-rpc framing, libtropic L1+L2 on chip,"
  echo "L3 secure session, and Ed25519 sign+verify all validated end-to-end."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 3 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi

exit $rc
