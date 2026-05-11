#!/usr/bin/env bash
# Phase 6 M2 validation — Force-UV (auto-enable on first setPIN) + alwaysUv
# + lt-rpc force-uv-get/set toggle.
#
# Non-interactive: 10 automated tests using P-256 ECDH + AES-CBC on the
# host side.  Total runtime: ~5 s.
#
# Does NOT cover the H1 Reset-with-SW1 gating (interactive, requires the
# 10 s post-boot window — deferred to validate-phase6 full chain in M4).
#
# Per docs/PHASE-6-PLAN.md §5 M2 HW checkpoint.
# Requires sudo (lt-rpc HID interface is root-only per nixos/tropic.nix udev).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIDO2="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"
LT_RPC="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 6 M2 validation — Force-UV + alwaysUv + auto-enable"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -e "$FIDO2" ]; then
  echo "ERROR: $FIDO2 not found." >&2
  exit 2
fi

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated on USB." >&2
  echo "       Is the Phase 6 M2 firmware flashed and the dongle plugged in?" >&2
  exit 3
fi

python3 "$FIDO2" validate-phase6-m2
rc=$?

echo ""
if [ $rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 6 M2 validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Force-UV is now secure-by-default: setting a PIN automatically"
  echo "enforces alwaysUv.  Users can opt out via 'nix run .#force-uv-set 0'"
  echo "(PIN-gated)."
  echo ""
  echo "Next: M3 — authenticatorCredentialManagement (cmd 0x0A)."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 6 M2 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $rc
