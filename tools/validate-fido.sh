#!/usr/bin/env bash
# FIDO2 surface validation — quick regression check.
#
# Uses libfido2's `fido2-token` CLI so it works on any host without
# needing our python test helpers.  Five checks, no SW1 press needed:
#
#   1. cafe:4001 enumerated on USB
#   2. fido2-token -L finds the nixtropic device
#   3. fido2-token -I returns CTAP2 info (proves GetInfo works)
#   4. AAGUID in GetInfo matches our self-allocated 6e69...0003
#   5. pinUvAuthProtocols + options.alwaysUv visible (proves M3/M6 polish ships)
#
# For deeper FIDO testing (PIN flows, MakeCredential, GetAssertion with
# real touch consent) use `tools/fido2_test.py` — that's the development-
# time helper, not the CI-friendly check.

set -uo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  nixtropic — FIDO2 surface validation"
echo "═══════════════════════════════════════════════════════════════"

overall_rc=0

# --- 1. USB enumeration ---
echo ""
echo "1/5  USB enumeration..."
if lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "  ✓ cafe:4001 enumerated"
else
  echo "  ✗ cafe:4001 not found.  Is the dongle plugged in (app mode)?"
  exit 2
fi

# --- 2. fido2-token -L finds us ---
echo ""
echo "2/5  fido2-token -L finds nixtropic..."
if ! command -v fido2-token >/dev/null 2>&1; then
  echo "  ⚠ fido2-token not in PATH (install libfido2); skipping FIDO checks"
  exit 0
fi
LIST_OUT=$(fido2-token -L 2>&1 || true)
DEV_PATH=$(echo "$LIST_OUT" | grep -i "nixtropic" | awk -F: '{print $1}' | head -1)
if [ -z "$DEV_PATH" ]; then
  echo "  ✗ no nixtropic device in fido2-token -L output:"
  echo "$LIST_OUT" | sed 's/^/      /'
  exit 3
fi
echo "  ✓ found at $DEV_PATH"

# --- 3. fido2-token -I returns CTAP2 info ---
echo ""
echo "3/5  fido2-token -I returns CTAP2 GetInfo..."
INFO_OUT=$(fido2-token -I "$DEV_PATH" 2>&1 || true)
if echo "$INFO_OUT" | grep -q "version strings:"; then
  echo "  ✓ GetInfo response parsed"
else
  echo "  ✗ GetInfo did not return expected fields:"
  echo "$INFO_OUT" | sed 's/^/      /'
  overall_rc=4
fi

# --- 4. AAGUID check ---
echo ""
echo "4/5  AAGUID matches 6e697874726f70696300000000000003..."
# fido2-token -I prints AAGUID with hyphens; strip them for the compare.
AAGUID_GOT=$(echo "$INFO_OUT" | awk '/aaguid:/ {print $2}' | tr -d '-' | head -1)
AAGUID_EXPECT="6e697874726f70696300000000000003"
if [ "$AAGUID_GOT" = "$AAGUID_EXPECT" ]; then
  echo "  ✓ AAGUID = $AAGUID_GOT"
else
  echo "  ✗ AAGUID mismatch."
  echo "      expected: $AAGUID_EXPECT"
  echo "      got:      $AAGUID_GOT"
  overall_rc=5
fi

# --- 5. options.alwaysUv + pinUvAuthProtocols visible ---
echo ""
echo "5/5  Force-UV + PIN protocol surface..."
ALWAYS_UV_OK=0
PIN_PROTO_OK=0
if echo "$INFO_OUT" | grep -qE "alwaysUv"; then
  ALWAYS_UV_OK=1
fi
if echo "$INFO_OUT" | grep -qE "pin protocols:.*1|pinUvAuthProtocols.*1"; then
  PIN_PROTO_OK=1
fi
if [ $ALWAYS_UV_OK -eq 1 ] && [ $PIN_PROTO_OK -eq 1 ]; then
  echo "  ✓ alwaysUv option + pinProtocol v1 advertised"
else
  if [ $ALWAYS_UV_OK -eq 0 ]; then
    echo "  ✗ alwaysUv option not advertised in GetInfo"
  fi
  if [ $PIN_PROTO_OK -eq 0 ]; then
    echo "  ✗ pin protocol v1 not advertised"
  fi
  echo "$INFO_OUT" | sed 's/^/      /'
  overall_rc=6
fi

echo ""
if [ $overall_rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ FIDO2 surface PASS  (5/5)"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Quick checks only — no real credential operations were performed."
  echo "For the deep flow (register + authenticate with real SW1 touch):"
  echo "  - webauthn.io in Firefox (see README §Demo recipes)"
  echo "  - or python3 tools/fido2_test.py make-cred / assertion"
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ FIDO2 surface FAIL  (rc=$overall_rc)"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $overall_rc
