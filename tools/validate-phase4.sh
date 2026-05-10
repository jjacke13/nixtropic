#!/usr/bin/env bash
# Phase 4 validation: runs `fido2_test.py validate` against the currently
# connected nixtropic firmware. Exercises CTAPHID framing + CTAP2
# (GetInfo / MakeCredential / GetAssertion) on the FIDO HID interface,
# and verifies Ed25519 signatures host-side.
#
# Exit code 0 = all checks passed; non-zero = at least one check failed.

set -uo pipefail

# Path to the Python CTAP client. The Nix app wrapper sets FIDO2_PY
# explicitly so we don't depend on $0 (which resolves to a /nix/store/...
# path that no longer sits beside tools/fido2_test.py).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PY_CLIENT="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 4 validation — CTAPHID + CTAP2 stubs over HID"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -e "$PY_CLIENT" ]; then
  echo "ERROR: $PY_CLIENT not found." >&2
  exit 2
fi

# Quick sanity: dongle enumerated?
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
  echo "  ✓ Phase 4 validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "FIDO2 HID interface (usage page 0xF1D0), CTAPHID framing, CTAP2"
  echo "GetInfo / MakeCredential / GetAssertion stubs all validated."
  echo "Ed25519 self-attestation and assertion signatures verify host-side."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 4 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi

exit $rc
