#!/usr/bin/env bash
# Phase 6 M3 validation — authenticatorCredentialManagement (CTAP2 cmd 0x0A).
#
# Interactive: one SW1 press for the MakeCredential step.  Then ~11
# automated checks of the 5 credMgmt sub-commands we implement.  Total
# runtime: ~30 s.
#
# Pre-step: lt-rpc slots-reset to clean state.  Requires sudo.
#
# Per docs/PHASE-6-PLAN.md §5 M3 HW checkpoint.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIDO2="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"
LT_RPC="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 6 M3 validation — authenticatorCredentialManagement"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -e "$FIDO2" ]; then
  echo "ERROR: $FIDO2 not found." >&2
  exit 2
fi

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated on USB." >&2
  echo "       Is the Phase 6 M3 firmware flashed and the dongle plugged in?" >&2
  exit 3
fi

python3 "$FIDO2" validate-phase6-m3
rc=$?

echo ""
if [ $rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 6 M3 validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Credential enumeration + deletion work end-to-end.  fido2-token"
  echo "-L -r should now list discoverable credentials.  fido2-token -D"
  echo "should delete them.  Closes task #54."
  echo ""
  echo "Next: M4 — cpp-reviewer audit + validate-phase6 full chain + ship."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 6 M3 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $rc
