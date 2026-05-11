#!/usr/bin/env bash
# Phase 5 M3 validation — ClientPIN protocol v1.
#
# Step 1: reset slots + PIN (factory_reset wipes both, per slots_factory_reset)
# Step 2: run the M3 FIDO2 PIN suite (13 tests)
# Step 3: reset again at the end so the chip is left clean for further
#         testing (M3 set PIN to "5678" — without reset, every subsequent
#         MakeCred would require pinAuth)
#
# Exit 0 = pass.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LT_RPC="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"
FIDO2="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 5 M3 validation — ClientPIN (P-256 + AES-256-CBC + HMAC-SHA-256)"
echo "═══════════════════════════════════════════════════════════════"

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated." >&2
  exit 3
fi

echo ""
echo "Step 1/3: factory_reset (clean slot bitmap + PIN state)..."
python3 "$LT_RPC" slots-reset

echo ""
echo "Step 2/3: Phase 5 M3 ClientPIN suite..."
python3 "$FIDO2" validate-m3
rc=$?

echo ""
echo "Step 3/3: cleanup factory_reset (so the chip leaves M3 with no PIN)..."
python3 "$LT_RPC" slots-reset

echo ""
if [ $rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 5 M3 validation PASS — ClientPIN works"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Validated:"
  echo "  - GetKeyAgreement: P-256 pubkey returned in COSE_Key form"
  echo "  - SetPin: ECDH-derived shared key, AES-CBC PIN encryption, HMAC pinAuth"
  echo "  - GetPinToken: encrypted pinUvAuthToken decrypts to 32 B"
  echo "  - Wrong PIN: PIN_INVALID returned, retries decrements"
  echo "  - Correct PIN: retries restored to 8"
  echo "  - ChangePin: old hash verified, new PIN installed"
  echo "  - MakeCred without pinAuth (when PIN set): PIN_REQUIRED"
  echo "  - MakeCred WITH pinAuth: succeeds, UV flag set in authData"
  echo "  - GetAssertion WITH pinAuth: succeeds, UV flag set"
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 5 M3 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $rc
