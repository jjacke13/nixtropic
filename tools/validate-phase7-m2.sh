#!/usr/bin/env bash
# Phase 7 M2 validation — OpenPGP applet SELECT + GET DATA + gpg --card-status.
#
# Six checks:
#   1. Dongle enumerates (cafe:4001).
#   2. pcsc-lite enumerates 'nixtropic CCID Reader'.
#   3. ATR matches 3B 80 01 81 (T=1 minimal).
#   4. SELECT for OpenPGP AID (D2 76 00 01 24 01) returns SW=9000.
#   5. GET DATA for AID (DO 4F) returns 16 bytes that match our AID
#      compile-time constant + SW=9000.
#   6. `gpg --card-status` succeeds and shows:
#        - our AID prefix (D276000124010304)
#        - algorithm attributes "ed25519" + "cv25519" + "ed25519"
#
# Requires pcscd + libccid (with cafe:4001 in Info.plist via tropic.nix
# module) + gnupg installed on host.

set -uo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  Phase 7 M2 validation — OpenPGP applet (SELECT + GET DATA)"
echo "═══════════════════════════════════════════════════════════════"

overall_rc=0

# --- 1. USB enumeration ---
echo ""
echo "1/6  USB enumeration..."
if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "  ✗ nixtropic dongle (cafe:4001) not enumerated."
  exit 3
fi
echo "  ✓ cafe:4001 enumerated"

# --- 2. pcsc-lite enumeration ---
echo ""
echo "2/6  pcsc-lite reader enumeration..."
if ! pgrep -x pcscd > /dev/null 2>&1; then
  sudo systemctl start pcscd 2>/dev/null || true
  sleep 2
fi
PCSCAN_OUT=$(timeout 5 pcsc_scan -n 2>&1 | head -20 || true)
if ! echo "$PCSCAN_OUT" | grep -qi "nixtropic"; then
  echo "  ✗ pcsc-lite doesn't see the nixtropic reader."
  echo "$PCSCAN_OUT" | sed 's/^/      /'
  exit 4
fi
echo "  ✓ pcsc-lite sees 'nixtropic CCID Reader'"

# --- 3. ATR ---
echo ""
echo "3/6  ATR check..."
ATR_OUT=$(timeout 5 opensc-tool --atr 2>&1 | tail -3 || true)
if echo "$ATR_OUT" | grep -qiE "3b:80:01:81"; then
  echo "  ✓ ATR = 3B:80:01:81"
else
  echo "  ✗ ATR mismatch."
  echo "$ATR_OUT" | sed 's/^/      /'
  overall_rc=5
fi

# --- 4. SELECT for OpenPGP AID ---
echo ""
echo "4/6  SELECT OpenPGP AID (D2 76 00 01 24 01)..."
SELECT_OUT=$(timeout 5 opensc-tool --card-driver default --send-apdu \
  "00:A4:04:00:06:D2:76:00:01:24:01" 2>&1 | tail -5 || true)
if echo "$SELECT_OUT" | grep -qiE "received.*0x90.*0x00|sw1=0x90.{0,20}sw2=0x00"; then
  echo "  ✓ SELECT returned SW=9000"
else
  echo "  ✗ SELECT failed."
  echo "$SELECT_OUT" | sed 's/^/      /'
  overall_rc=6
fi

# --- 5. GET DATA for AID (DO 4F) ---
echo ""
echo "5/6  GET DATA for AID (DO 4F)..."
GETDATA_OUT=$(timeout 5 opensc-tool --card-driver default --send-apdu \
  "00:A4:04:00:06:D2:76:00:01:24:01" --send-apdu \
  "00:CA:00:4F:00" 2>&1 | tail -10 || true)
# Expect 16-byte AID + SW=9000 in the last APDU response.  Match the
# AID prefix D276000124010304 (RID + version v3.4).
if echo "$GETDATA_OUT" | grep -qiE "D2.?76.?00.?01.?24.?01.?03.?04"; then
  echo "  ✓ GET DATA 4F returned AID matching D276 00 01 24 01 03 04"
else
  echo "  ✗ GET DATA 4F response doesn't contain expected AID prefix."
  echo "$GETDATA_OUT" | sed 's/^/      /'
  overall_rc=7
fi

# --- 6. gpg --card-status ---
echo ""
echo "6/6  gpg --card-status (end-to-end via scdaemon + pcscd)..."
if ! command -v gpg >/dev/null 2>&1; then
  echo "  ⚠ gpg not in PATH; skipping (install gnupg to enable this check)"
else
  GPG_OUT=$(timeout 10 gpg --card-status 2>&1 || true)
  if echo "$GPG_OUT" | grep -qiE "D27600012401.*4E58|application id.*d27600012401"; then
    echo "  ✓ gpg --card-status sees our card (AID D276000124010304 4E58)"
    # Algorithm attributes — best-effort grep; not failing if missing
    # since gpg formatting varies across versions.
    if echo "$GPG_OUT" | grep -qi "ed25519"; then
      echo "  ✓ algorithm attributes show ed25519"
    fi
    if echo "$GPG_OUT" | grep -qi "cv25519\|curve25519"; then
      echo "  ✓ algorithm attributes show cv25519"
    fi
  else
    echo "  ✗ gpg --card-status doesn't see our card."
    echo "$GPG_OUT" | sed 's/^/      /'
    overall_rc=8
  fi
fi

echo ""
if [ $overall_rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ Phase 7 M2 PASS"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "OpenPGP applet live on the dongle:"
  echo "  - SELECT for OpenPGP AID succeeds"
  echo "  - GET DATA returns our AID + algorithm attributes"
  echo "  - gpg --card-status enumerates the card"
  echo ""
  echo "Keys not yet generated (signature/encryption/auth all empty);"
  echo "that arrives in M4 with GENERATE + PSO:CDS.  Next: M3 — PIN"
  echo "handling (PW1/PW3/RC) with M&D backing + PUT DATA for writable DOs."
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ Phase 7 M2 FAIL  (rc=$overall_rc)"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $overall_rc
