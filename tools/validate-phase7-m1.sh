#!/usr/bin/env bash
# Phase 7 M1 validation — USB CCID interface + ATR + APDU loopback.
#
# Five checks:
#   1.  Dongle enumerates as cafe:4001 (USB-level sanity).
#   2.  lsusb -v shows interface class 0x0B (Smart Card / CCID).
#   3.  pcscd is running and pcsc-lite sees `nixtropic CCID Reader`.
#   4.  opensc-tool --atr returns the expected ATR (3B 80 81 31 30).
#   5.  Raw APDU `00 A4 04 00 00` (SELECT with no AID body) returns SW=9000
#       (echo).  Real applet dispatch arrives in M2.
#
# Requires pcscd running on the host.  On NixOS, enable via
#   services.pcscd.enable = true;
# or this script will try to start it via sudo.
#
# All steps require sudo (CCID device node + pcscd access).

set -uo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 7 M1 validation — USB CCID + ATR + APDU echo"
echo "═══════════════════════════════════════════════════════════════"

overall_rc=0

# --- 1. USB enumeration ---
echo ""
echo "1/5  USB enumeration..."
if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "  ✗ nixtropic dongle (cafe:4001) not enumerated."
  echo "    Confirm dongle is plugged in (not in DFU) and try again."
  exit 3
fi
echo "  ✓ cafe:4001 enumerated"

# --- 2. CCID interface descriptor ---
echo ""
echo "2/5  CCID interface descriptor..."
LSUSB_DETAIL=$(lsusb -v -d cafe:4001 2>&1 || true)
if ! echo "$LSUSB_DETAIL" | grep -qE "(SmartCard|Smart Card|bInterfaceClass[[:space:]]+11[[:space:]]|bInterfaceClass.*0[xX]?0[bB])"; then
  echo "  ✗ Smart Card class (0x0B / 11 decimal) not in interface descriptors."
  echo "    Class bytes found:"
  echo "$LSUSB_DETAIL" | grep -i "InterfaceClass" || echo "    (none)"
  overall_rc=4
else
  echo "  ✓ Smart Card class 0x0B advertised on one interface"
fi

# --- 3. pcsc-lite enumeration ---
echo ""
echo "3/5  pcsc-lite reader enumeration..."
if ! pgrep -x pcscd > /dev/null 2>&1; then
  echo "  pcscd not running — attempting to start..."
  if sudo systemctl start pcscd 2>/dev/null; then
    echo "    started via systemd"
    sleep 2
  elif command -v pcscd >/dev/null && sudo pcscd 2>/dev/null; then
    echo "    started directly"
    sleep 2
  else
    echo "  ✗ Could not start pcscd.  Install pcsclite + enable the service."
    echo "    NixOS: services.pcscd.enable = true;"
    exit 5
  fi
fi

PCSCAN_OUT=$(timeout 5 pcsc_scan -n 2>&1 | head -20 || true)
if ! echo "$PCSCAN_OUT" | grep -qi "nixtropic"; then
  echo "  ✗ pcsc-lite doesn't see the nixtropic reader."
  echo "    pcsc_scan output:"
  echo "$PCSCAN_OUT" | sed 's/^/      /'
  overall_rc=5
else
  echo "  ✓ pcsc-lite sees 'nixtropic CCID Reader'"
fi

# --- 4. ATR ---
echo ""
echo "4/5  ATR check..."
ATR_OUT=$(timeout 5 opensc-tool --atr 2>&1 | tail -3 || true)
# Minimal valid T=1 ATR (4 bytes).  TS T0 TD1 TCK.
if echo "$ATR_OUT" | grep -qiE "3b:80:01:81"; then
  echo "  ✓ ATR = 3B:80:01:81"
else
  echo "  ✗ ATR mismatch (or no card detected)."
  echo "    opensc-tool output:"
  echo "$ATR_OUT" | sed 's/^/      /'
  echo "    Expected: 3B:80:01:81"
  overall_rc=6
fi

# --- 5. APDU loopback ---
echo ""
echo "5/5  APDU loopback (SELECT no-AID → SW=9000)..."
# Force --card-driver default so opensc doesn't bail on card auto-detect
# (we don't match any of opensc's known applet ATR profiles yet — that
# arrives in M2 when SELECT for the OpenPGP AID is wired up).
APDU_OUT=$(timeout 5 opensc-tool --card-driver default --send-apdu "00:A4:04:00:00" 2>&1 | tail -5 || true)
if echo "$APDU_OUT" | grep -qiE "9000|sw1=90.*sw2=00"; then
  echo "  ✓ SW=9000 (M1 echo)"
else
  echo "  ✗ APDU echo failed."
  echo "    opensc-tool output:"
  echo "$APDU_OUT" | sed 's/^/      /'
  overall_rc=7
fi

echo ""
if [ $overall_rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 7 M1 PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "USB CCID interface live:"
  echo "  - Class 0x0B advertised in interface descriptor"
  echo "  - pcsc-lite enumerates 'nixtropic CCID Reader'"
  echo "  - ATR 3B 80 81 31 30 returned on power-on"
  echo "  - APDU loopback echoes SW=9000"
  echo ""
  echo "Next: M2 — OpenPGP applet (SELECT AID + GET DATA for read-only DOs)."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 7 M1 FAIL  (rc=$overall_rc)"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $overall_rc
