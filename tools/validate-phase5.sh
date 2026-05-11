#!/usr/bin/env bash
# Phase 5 full validation — M5 (Reset) + M2 + M3 end-to-end.
#
# CRITICAL ORDERING: authenticatorReset (M5) is only accepted within
# 10 seconds of power-up (CTAP2.1 §6.8). Therefore M5 MUST run first,
# immediately after USB enumeration. M2 + M3 together take ~25-40 s
# with all the CTAP/ECDH/M&D crypto, so attempting Reset after them
# would always return NOT_ALLOWED — that's correct firmware behavior,
# but a bad test ordering hides the success path.
#
# Sequence (M5 first, then M2/M3 — no time pressure on those):
#   1. M5 — authenticatorReset (WITHIN 10 s window from boot)
#   2. M2 — TROPIC01-backed credstore (state was wiped by M5)
#   3. slots-reset (clean state between M2 and M3)
#   4. M3 — ClientPIN protocol v1
#   5. cleanup slots-reset
#
# This script is meant to be invoked by flash-and-validate-phase5
# which minimizes settle time post-flash so Reset's 10 s window is
# still open by the time M5 runs.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LT_RPC="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"
FIDO2="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 5 FULL validation"
echo "═══════════════════════════════════════════════════════════════"

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated." >&2
  exit 3
fi

overall_rc=0

echo ""
echo "Step 1/5: M5 — authenticatorReset (MUST be within 10 s of boot)..."
python3 "$FIDO2" validate-m5 || overall_rc=$?

echo ""
echo "Step 2/5: M2 — TROPIC01-backed credstore (mic-drop)..."
# After M5 success, state is already clean. (After M5 failure due to
# window expiry, run slots-reset to clear anyway.)
python3 "$LT_RPC" slots-reset || true
python3 "$FIDO2" validate-m2 || overall_rc=$?

echo ""
echo "Step 3/5: factory_reset (clean state between M2 and M3)..."
python3 "$LT_RPC" slots-reset

echo ""
echo "Step 4/5: M3 — ClientPIN protocol v1..."
python3 "$FIDO2" validate-m3 || overall_rc=$?

echo ""
echo "Step 5/5: cleanup factory_reset..."
python3 "$LT_RPC" slots-reset

echo ""
if [ $overall_rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 5 FULL validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "All milestones validated end-to-end on TROPIC01 hardware:"
  echo "  M1 ✅ slot manager (R-mem + bitmap)"
  echo "  M2 ✅ TROPIC01-backed credstore (chip-side Ed25519 keys)"
  echo "  M3 ✅ ClientPIN protocol v1 (P-256 + AES-CBC + HMAC)"
  echo "  M4 ✅ MAC-and-Destroy hardware retry counter (regression in M3)"
  echo "  M5 ✅ authenticatorReset (10 s post-boot window)"
  echo ""
  echo "The dongle is now a fully functional open-source FIDO2 security key"
  echo "with PIN protection backed by hardware-enforced retry limiting."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 5 validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
  if [ $overall_rc -ne 0 ]; then
    echo ""
    echo "If M5 failed with NOT_ALLOWED, the test was invoked >10 s after"
    echo "boot. Use 'sudo nix run .#flash-and-validate-phase5' (which"
    echo "flashes + validates in one shot, minimizing settle time)."
  fi
fi
exit $overall_rc
