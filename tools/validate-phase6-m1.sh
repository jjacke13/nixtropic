#!/usr/bin/env bash
# Phase 6 M1 validation — SW1 user-presence + LED state machine.
#
# Interactive: tester is prompted to press SW1 (test 2) and then NOT press
# it (test 3, full 30 s timeout).  Total run time ~60 s.
#
# Pre-step: clears persisted state via lt-rpc slots-reset.  Without this,
# any PIN/credentials left over from prior Phase 5 testing make MakeCred
# fail at the PIN gate (CTAP2_ERR_PIN_REQUIRED = 0x36) BEFORE reaching
# the UP gate, masking M1's actual behaviour.
#
# Per docs/PHASE-6-PLAN.md §5 M1 HW checkpoint.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIDO2="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"
LT_RPC="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 6 M1 validation — SW1 + LED (interactive)"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -e "$FIDO2" ]; then
  echo "ERROR: $FIDO2 not found." >&2
  exit 2
fi

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated on USB." >&2
  echo "       Is the Phase 6 firmware flashed and the dongle plugged in?" >&2
  exit 3
fi

# Wipe persisted PIN + credentials + M&D state so MakeCred can reach
# the UP gate.  Requires root (lt-rpc HID interface is root-only per
# nixos/tropic.nix udev rule).  Tolerate failure here: an already-clean
# device will succeed on subsequent tests anyway.
echo "Pre-step: clearing persisted state via lt-rpc slots-reset..."
if [ -e "$LT_RPC" ]; then
  python3 "$LT_RPC" slots-reset || \
    echo "  (slots-reset returned non-zero; continuing — device may have been clean already)"
else
  echo "  (lt_rpc.py not found; skipping — make sure dongle is in factory state)"
fi
echo ""

python3 "$FIDO2" validate-phase6-m1
rc=$?

echo ""
if [ $rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 6 M1 validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Touch-to-confirm is real.  Each WebAuthn signing op now requires"
  echo "a fresh SW1 press; ignored prompts time out at 30 s."
  echo ""
  echo "Next: M2 — Force-UV vendor command + alwaysUv option."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 6 M1 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $rc
