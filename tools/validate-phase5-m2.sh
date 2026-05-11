#!/usr/bin/env bash
# Phase 5 M2 validation — THE MIC-DROP.
#
# Step 1: reset slot bitmap (lt-rpc SLOTS_RESET) so we start from a known
#         empty state. Otherwise leftover credentials from M1 testing
#         would mess up "first MakeCred lands in slot 0" assertions.
#
# Step 2: run the M2 FIDO2 suite — 8 tests covering:
#         - AAGUID Phase 5 marker (0x02 trailing byte)
#         - 3 distinct credentials, distinct pubkeys + credIds, sigs verify
#         - GetAssertion on each → real Ed25519 sigs verify with each pubkey
#         - Monotonic shared signCount strictly increases across all ops
#         - Forged credId → CTAP2_ERR_NO_CREDENTIALS (0x2E)
#
# Exit code 0 = all checks passed; non-zero = at least one failed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LT_RPC="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"
FIDO2="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 5 M2 validation — TROPIC01-backed FIDO2 (THE MIC-DROP)"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -e "$LT_RPC" ]; then
  echo "ERROR: $LT_RPC not found." >&2
  exit 2
fi
if [ ! -e "$FIDO2" ]; then
  echo "ERROR: $FIDO2 not found." >&2
  exit 2
fi

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated on USB." >&2
  echo "       Is the firmware flashed and the dongle plugged in?" >&2
  exit 3
fi

echo ""
echo "Step 1/2: factory_reset slot bitmap (clean starting state)..."
python3 "$LT_RPC" slots-reset
rc=$?
if [ $rc -ne 0 ]; then
  echo "✗ Slot reset failed (rc=$rc)" >&2
  exit $rc
fi
echo ""

echo "Step 2/2: Phase 5 M2 FIDO2 suite..."
python3 "$FIDO2" validate-m2
rc=$?

echo ""
if [ $rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 5 M2 validation PASS — THE MIC-DROP"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Real TROPIC01-backed FIDO2 working end-to-end:"
  echo "  - Per-credential Ed25519 keypairs generated on TROPIC01"
  echo "  - Signatures computed on TROPIC01, never leave the chip"
  echo "  - Host-side python-cryptography verifies all signatures"
  echo "  - Shared monotonic signCount strictly increases across ops"
  echo "  - Forged credentialIds rejected (CTAP2_ERR_NO_CREDENTIALS)"
  echo ""
  echo "Try it in a real browser:"
  echo "  1. Open https://webauthn.io in Firefox or Chrome"
  echo "  2. Click Register, give it any username"
  echo "  3. When prompted for security key, the dongle should respond"
  echo "  4. Log out, then click Login — same dongle authenticates"
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 5 M2 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi

exit $rc
