#!/usr/bin/env bash
# Phase 6 FULL validation — M1 + M2 + M3 chain.
#
# Inlines the python sub-commands directly rather than chaining to the
# per-milestone .sh wrappers (those live in separate /nix/store paths
# under `nix run` so $SCRIPT_DIR-based discovery doesn't reach them).
#
# Ordering (per feedback_validation_temporal_constraints.md):
#   M1 first  — interactive: 1 SW1 press + 1 30 s timeout (~60 s)
#   M2 second — auto: Force-UV / alwaysUv / Reset-with-SW1 (~5 s)
#   M3 third  — interactive: 1 SW1 press + 11 auto-checks (~30 s)
#
# Total walltime: ~95 s + flash time (if called via flash-and-validate-phase6).
#
# All steps require sudo (lt-rpc HID is root-only per nixos/tropic.nix udev).
# Each step does its own slots-reset for state isolation between phases.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIDO2="${FIDO2_PY:-${SCRIPT_DIR}/fido2_test.py}"
LT_RPC="${LT_RPC_PY:-${SCRIPT_DIR}/lt_rpc.py}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 6 FULL validation — M1 + M2 + M3"
echo "═══════════════════════════════════════════════════════════════"

if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "ERROR: nixtropic dongle (cafe:4001) not enumerated on USB." >&2
  exit 3
fi

overall_rc=0

echo ""
echo "Step 1/3: M1 — SW1 user-presence + LED (interactive)..."
echo "(Pre-step: slots-reset for clean state)"
python3 "$LT_RPC" slots-reset 2>&1 | tail -5 || true
echo ""
echo "(One SW1 press, then one 30 s timeout — ~60 s total.)"
python3 "$FIDO2" validate-phase6-m1 || overall_rc=$?

echo ""
echo "Step 2/3: M2 — Force-UV + alwaysUv + auto-enable..."
python3 "$FIDO2" validate-phase6-m2 || overall_rc=$?

echo ""
echo "Step 3/3: M3 — authenticatorCredentialManagement (1 SW1 press)..."
python3 "$FIDO2" validate-phase6-m3 || overall_rc=$?

echo ""
if [ $overall_rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 6 FULL validation PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "All three milestones validated end-to-end on TROPIC01 hardware:"
  echo "  M1 ✅ SW1 user-presence + LED state machine"
  echo "  M2 ✅ Force-UV auto-enable + Reset-with-SW1 + R-mem v3 schema"
  echo "  M3 ✅ authenticatorCredentialManagement (CTAP2 cmd 0x0A)"
  echo ""
  echo "The dongle is now a daily-driver Yubikey-class FIDO2 security key:"
  echo "  - Real touch-to-confirm per signing op"
  echo "  - PIN auto-enforced after first setPIN (Force-UV default-on)"
  echo "  - Credential enumeration + deletion via standard tooling"
  echo "    (\`fido2-token -L -r\`, \`fido2-token -D -i\`)"
  echo "  - Reset requires SW1 press when state exists (anti-passive-physical)"
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 6 FULL validation FAIL"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $overall_rc
