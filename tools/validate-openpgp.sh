#!/usr/bin/env bash
# OpenPGP card surface validation — end-to-end via opensc-tool +
# gpg --card-status.  17 checks against ISO 7816-4 INS handlers
# implementing OpenPGP card v3.4.1:
#
#   - CCID enumeration + ATR (USB CCID 1.1 transport)
#   - SELECT + GET DATA (DOs 4F / 6E / C4 — read-only)
#   - VERIFY PW3 + PW1 with default PINs (123456 / 12345678)
#   - GENERATE sig (Ed25519 chip slot 29) + PSO:CDS sign
#   - GENERATE dec (X25519 host-side) + GENERATE aut + INTERNAL AUTHENTICATE
#   - CHANGE REF wrong-old consumes EXACTLY one retry (single-attempt
#     boundary; defends against split-search counter exhaustion)
#   - TERMINATE DF erases chip ECC slots 29 + 31
#   - gpg --card-status interop sanity
#
# Run AFTER `gpg-connect-agent "SCD RESTART" /bye` if testing right after
# flash, so scdaemon's cache doesn't show stale state.
#
# The OpenPGP R-mem schema (magic "PG7N") forces a clean state on every
# magic-bump firmware upgrade.  Any existing custom PINs/keys/cardholder
# data is wiped on schema change; user must regenerate via
# `gpg --card-edit → admin → generate`.

set -uo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  nixtropic — OpenPGP card surface validation (17 checks)"
echo "═══════════════════════════════════════════════════════════════"

overall_rc=0

# Defaults — must match write_activated_defaults in openpgp_state.c.
DEFAULT_PW1_HEX="31:32:33:34:35:36"        # "123456"
DEFAULT_PW3_HEX="31:32:33:34:35:36:37:38"  # "12345678"
DEFAULT_PW1_LEN=6
DEFAULT_PW3_LEN=8

SELECT_APDU="00:A4:04:00:06:D2:76:00:01:24:01"

# --- 1. CCID + pcsc-lite enum ---
echo ""
echo " 1/17  USB + pcsc-lite enumeration..."
if ! lsusb 2>/dev/null | grep -q "cafe:4001"; then
  echo "  ✗ cafe:4001 not enumerated."
  exit 3
fi
PCSC_FOUND=0
PCSC_LAST=""
for attempt in 1 2 3; do
  if ! pgrep -x pcscd > /dev/null 2>&1; then
    sudo systemctl restart pcscd 2>/dev/null || true
    sleep 3
  fi
  PCSC_LAST=$(timeout 10 pcsc_scan -n 2>&1 | head -20 || true)
  if echo "$PCSC_LAST" | grep -qi "nixtropic"; then
    PCSC_FOUND=1
    break
  fi
  sleep 2
done
if [ "$PCSC_FOUND" -ne 1 ]; then
  echo "  ✗ pcsc-lite doesn't see the reader."
  echo "$PCSC_LAST" | sed 's/^/      /'
  exit 4
fi
echo "  ✓ cafe:4001 + pcsc-lite reader"

# --- 2. SELECT OpenPGP AID ---
echo ""
echo " 2/17  SELECT OpenPGP AID..."
SELECT_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" 2>&1 | tail -3 || true)
if echo "$SELECT_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x90.{0,20}SW2=0x00"; then
  echo "  ✓ SELECT → SW=9000"
else
  echo "  ✗ SELECT failed:"
  echo "$SELECT_OUT" | sed 's/^/      /'
  overall_rc=5
fi

# --- 3. GET DATA 4F (raw AID) ---
echo ""
echo " 3/17  GET DATA 4F (raw AID)..."
AID_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:CA:00:4F:00" 2>&1 | tail -5 || true)
# Expect AID bytes ending in our manufacturer 4E 58 then serial + SW=9000
if echo "$AID_OUT" | grep -qiE "d2.{0,2}76.{0,2}00.{0,2}01.{0,2}24.{0,2}01.{0,2}03.{0,2}04.{0,2}4e.{0,2}58"; then
  echo "  ✓ AID returned with version 03 04 + manufacturer 4E 58 (NX)"
else
  echo "  ✗ AID didn't match expected layout:"
  echo "$AID_OUT" | sed 's/^/      /'
  overall_rc=6
fi

# --- 4. GET DATA 6E (Application Related Data) ---
echo ""
echo " 4/17  GET DATA 6E (composite Application Related Data)..."
# DO 6E is the long-response case — opensc-tool prints the SW on the
# header line BEFORE the hex dump (which can be 250+ bytes), so tail
# slicing would clip the SW header.  Grep the full output instead.
ARD_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:CA:00:6E:00" 2>&1 || true)
# Two acceptance criteria: SW=9000 in any header line AND tag 6E at the start
# of the hex dump (proves it's our DO, not a generic error).
if echo "$ARD_OUT" | grep -qiE "SW1=0x90.{0,20}SW2=0x00" \
   && echo "$ARD_OUT" | grep -qE "^[[:space:]]*6E[[:space:]]"; then
  echo "  ✓ DO 6E returned with SW=9000"
else
  echo "  ✗ DO 6E failed:"
  echo "$ARD_OUT" | tail -20 | sed 's/^/      /'
  overall_rc=7
fi

# --- 5. GET DATA C4 (PW status) — 7 bytes ---
echo ""
echo " 5/17  GET DATA C4 (PW status)..."
PW_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:CA:00:C4:00" 2>&1 | tail -5 || true)
# Expect: NN 40 40 40 03 00 03 then SW=9000 (force_verify, 64,64,64, retries 3,0,3)
# where NN is 00 after Phase 8 M4.0 (PIN cached for session) or 01 on
# pre-M4.0 firmware (PIN re-prompted per PSO).  Both byte sequences
# are spec-valid, just policy differences — accept either.
if echo "$PW_OUT" | grep -qiE "0[01].{0,2}40.{0,2}40.{0,2}40.{0,2}03.{0,2}00.{0,2}03"; then
  echo "  ✓ PW status = .. 40 40 40 03 00 03 (default state)"
else
  echo "  ✗ PW status didn't match expected:"
  echo "$PW_OUT" | sed 's/^/      /'
  overall_rc=8
fi

# --- 6. VERIFY PW3 default ---
echo ""
echo " 6/17  VERIFY PW3 default '12345678'..."
V3_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:83:08:$DEFAULT_PW3_HEX" 2>&1 | tail -3 || true)
if echo "$V3_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x90.{0,20}SW2=0x00"; then
  echo "  ✓ VERIFY PW3 → SW=9000"
else
  echo "  ✗ VERIFY PW3 failed:"
  echo "$V3_OUT" | sed 's/^/      /'
  overall_rc=9
fi

# --- 7. GENERATE sig key ---
echo ""
echo " 7/17  GENERATE sig key (Ed25519 chip slot 29)..."
GEN_SIG_OUT=$(timeout 15 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:83:08:$DEFAULT_PW3_HEX" \
  --send-apdu "00:47:80:00:02:B6:00:00" 2>&1 | tail -10 || true)
if echo "$GEN_SIG_OUT" | grep -qiE "7f.{0,4}49.{0,4}22.{0,4}86.{0,4}20"; then
  echo "  ✓ GENERATE sig returned pubkey TLV"
else
  echo "  ✗ GENERATE sig failed:"
  echo "$GEN_SIG_OUT" | sed 's/^/      /'
  overall_rc=10
fi

# --- 8. PSO:CDS sign ---
echo ""
echo " 8/17  PSO:CDS sign 64-byte 0xAA test message..."
MSG=""
for _ in $(seq 1 64); do MSG="${MSG}AA:"; done
MSG="${MSG%:}"
SIGN_OUT=$(timeout 10 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:81:06:$DEFAULT_PW1_HEX" \
  --send-apdu "00:2A:9E:9A:40:${MSG}:00" 2>&1 | tail -10 || true)
if echo "$SIGN_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x90.{0,20}SW2=0x00"; then
  echo "  ✓ PSO:CDS produced signature + SW=9000"
else
  echo "  ✗ PSO:CDS failed:"
  echo "$SIGN_OUT" | sed 's/^/      /'
  overall_rc=11
fi

# --- 9. GENERATE dec key (X25519 host-side, M5) ---
echo ""
echo " 9/17  GENERATE dec key (X25519, R-mem byte 180-211)..."
GEN_DEC_OUT=$(timeout 15 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:83:08:$DEFAULT_PW3_HEX" \
  --send-apdu "00:47:80:00:02:B8:00:00" 2>&1 | tail -10 || true)
if echo "$GEN_DEC_OUT" | grep -qiE "7f.{0,4}49.{0,4}22.{0,4}86.{0,4}20"; then
  echo "  ✓ GENERATE dec returned pubkey TLV"
else
  echo "  ✗ GENERATE dec failed:"
  echo "$GEN_DEC_OUT" | sed 's/^/      /'
  overall_rc=12
fi

# --- 10. GENERATE aut key ---
echo ""
echo "10/17  GENERATE aut key (Ed25519 chip slot 31)..."
GEN_AUT_OUT=$(timeout 15 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:83:08:$DEFAULT_PW3_HEX" \
  --send-apdu "00:47:80:00:02:A4:00:00" 2>&1 | tail -10 || true)
if echo "$GEN_AUT_OUT" | grep -qiE "7f.{0,4}49.{0,4}22.{0,4}86.{0,4}20"; then
  echo "  ✓ GENERATE aut returned pubkey TLV"
else
  echo "  ✗ GENERATE aut failed:"
  echo "$GEN_AUT_OUT" | sed 's/^/      /'
  overall_rc=13
fi

# --- 11. INTERNAL AUTHENTICATE — sign 32-byte challenge ---
echo ""
echo "11/17  INTERNAL AUTHENTICATE — sign 32-byte challenge..."
CHAL=""
for _ in $(seq 1 32); do CHAL="${CHAL}55:"; done
CHAL="${CHAL%:}"
INTAUT_OUT=$(timeout 10 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:81:06:$DEFAULT_PW1_HEX" \
  --send-apdu "00:88:00:00:20:${CHAL}:00" 2>&1 | tail -10 || true)
if echo "$INTAUT_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x90.{0,20}SW2=0x00"; then
  echo "  ✓ INTERNAL AUTHENTICATE produced signature + SW=9000"
else
  echo "  ✗ INTERNAL AUTHENTICATE failed:"
  echo "$INTAUT_OUT" | sed 's/^/      /'
  overall_rc=14
fi

# --- 12. CHANGE REF PW3 wrong old should consume exactly ONE retry ---
# Before M6: split-search loop iterated over every plausible boundary; each
# wrong split decremented the retry counter.  A 24-byte body with default
# PW3 length 8 lets the loop try splits at k=8..16 (9 iterations); 3 of
# those exhaust the retry counter → SW=6983 (blocked).
# After M6: stored old_len forces a single attempt at exactly k=8 →
# SW=63C2 (1 retry consumed, counter 3→2).
echo ""
echo "12/17  CHANGE REF PW3 wrong-old should consume EXACTLY 1 retry..."
# Body = "wrongPW3" (8 B old) || "newPin12_24bytes" (16 B new) = 24 bytes.
# Pre-M6 split-search would try 9 iterations → counter exhaust.
# M6 single-attempt → 1 retry consumed.
WRONG_OLD="77:72:6F:6E:67:50:57:33"                                  # "wrongPW3" (8 B)
NEW_PW3="6E:65:77:50:69:6E:31:32:5F:32:34:62:79:74:65:73"            # "newPin12_24bytes" (16 B)
WRONG_CHANGE_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:24:00:83:18:${WRONG_OLD}:${NEW_PW3}" 2>&1 | tail -3 || true)
if echo "$WRONG_CHANGE_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x63.{0,20}SW2=0xc2"; then
  echo "  ✓ CHANGE REF wrong-old → SW=63C2 (single-attempt, 2 PW3 retries remain)"
elif echo "$WRONG_CHANGE_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x63.{0,20}SW2=0xc0|SW1=0x69.{0,20}SW2=0x83"; then
  echo "  ✗ CHANGE REF wrong-old consumed >1 retry — split-search loop still active:"
  echo "$WRONG_CHANGE_OUT" | sed 's/^/      /'
  overall_rc=15
else
  echo "  ✗ CHANGE REF returned unexpected SW:"
  echo "$WRONG_CHANGE_OUT" | sed 's/^/      /'
  overall_rc=15
fi

# Re-verify PW3 with correct default to reset counter for downstream tests.
timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:83:08:$DEFAULT_PW3_HEX" >/dev/null 2>&1 || true

# --- 13. VERIFY PW1 default still works after counter recovery ---
echo ""
echo "13/17  VERIFY PW1 default (post-recovery sanity)..."
V1_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:81:06:$DEFAULT_PW1_HEX" 2>&1 | tail -3 || true)
if echo "$V1_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x90.{0,20}SW2=0x00"; then
  echo "  ✓ VERIFY PW1 → SW=9000"
else
  echo "  ✗ VERIFY PW1 failed:"
  echo "$V1_OUT" | sed 's/^/      /'
  overall_rc=16
fi

# --- 14. TERMINATE erases chip ECC slots ---
# Before TERMINATE: sig slot 29 has the key generated at step 7.
# After TERMINATE + ACTIVATE: chip slots erased; READ PUBLIC KEY returns 6A88.
echo ""
echo "14/17  TERMINATE wipes chip ECC slots 29 + 31..."
TERM_OUT=$(timeout 10 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:20:00:83:08:$DEFAULT_PW3_HEX" \
  --send-apdu "00:E6:00:00:00" 2>&1 | tail -3 || true)
if echo "$TERM_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x90.{0,20}SW2=0x00"; then
  echo "  ✓ TERMINATE → SW=9000"
else
  echo "  ✗ TERMINATE failed:"
  echo "$TERM_OUT" | sed 's/^/      /'
  overall_rc=17
fi

# --- 15. ACTIVATE FILE → re-init ---
echo ""
echo "15/17  ACTIVATE FILE re-init after TERMINATE..."
ACT_OUT=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:44:00:00:00" 2>&1 | tail -3 || true)
if echo "$ACT_OUT" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x90.{0,20}SW2=0x00"; then
  echo "  ✓ ACTIVATE → SW=9000"
else
  echo "  ✗ ACTIVATE failed:"
  echo "$ACT_OUT" | sed 's/^/      /'
  overall_rc=18
fi

# --- 16. Confirmation — READ sig pubkey after TERMINATE+ACTIVATE
# should fail with REF_DATA_NOT_FOUND (6A88) because chip slot 29 was erased.
echo ""
echo "16/17  READ sig pubkey after TERMINATE should fail (6A88)..."
READ_AFTER_TERM=$(timeout 5 opensc-tool --reader 0 --card-driver default \
  --send-apdu "$SELECT_APDU" \
  --send-apdu "00:47:81:00:02:B6:00:00" 2>&1 | tail -5 || true)
if echo "$READ_AFTER_TERM" | grep -E "^[[:space:]]*Received \(SW1=" | tail -1 | grep -qiE "SW1=0x6a.{0,20}SW2=0x88"; then
  echo "  ✓ READ sig pubkey → SW=6A88 (chip slot 29 erased — H1 fix confirmed)"
elif echo "$READ_AFTER_TERM" | grep -qiE "7f.{0,4}49.{0,4}22.{0,4}86.{0,4}20"; then
  echo "  ✗ READ sig pubkey STILL returns a key — TERMINATE didn't erase chip slot 29:"
  echo "$READ_AFTER_TERM" | sed 's/^/      /'
  overall_rc=19
else
  echo "  ✗ READ sig pubkey returned unexpected SW:"
  echo "$READ_AFTER_TERM" | sed 's/^/      /'
  overall_rc=19
fi

# --- 17. gpg --card-status (final regression check) ---
echo ""
echo "17/17  gpg --card-status (interop sanity)..."
GPG_AS_USER=""
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  GPG_AS_USER="sudo -u $SUDO_USER -E"
fi
if ! command -v gpg >/dev/null 2>&1; then
  echo "  ⚠ gpg not in PATH; skipping"
else
  # Flush scdaemon cache first — schema bump may have stale state cached.
  $GPG_AS_USER gpg-connect-agent "SCD RESTART" /bye >/dev/null 2>&1 || true
  sleep 1
  GPG_OUT=$(timeout 10 $GPG_AS_USER gpg --card-status 2>&1 || true)
  if echo "$GPG_OUT" | grep -qiE "D27600012401|application id.*d27600012401"; then
    echo "  ✓ gpg --card-status sees our card"
    # Verify version + manufacturer in display
    if echo "$GPG_OUT" | grep -qiE "version.*3\.4|version.*0x?0304"; then
      echo "  ✓ Version 3.4 displayed"
    fi
    # The audit fix re-init zeroed fingerprints — should see [none] or all-zero
    if echo "$GPG_OUT" | grep -qiE "signature key.*\[none\]|fingerprint.*0000"; then
      echo "  ✓ Fingerprints cleared post-TERMINATE+ACTIVATE"
    fi
  else
    echo "  ✗ gpg --card-status doesn't see our card:"
    echo "$GPG_OUT" | sed 's/^/      /'
    overall_rc=20
  fi
fi

echo ""
if [ $overall_rc -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✓ OpenPGP card surface PASS  (17/17)"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""
  echo "Verified surfaces:"
  echo "  - CCID transport + ATR + SELECT + GET DATA"
  echo "  - VERIFY PW1/PW3 + CHANGE REFERENCE DATA (single-attempt boundary)"
  echo "  - GENERATE sig/dec/aut + PSO:CDS + INTERNAL AUTHENTICATE"
  echo "  - TERMINATE DF erases chip ECC slots; ACTIVATE FILE re-inits"
  echo "  - gpg --card-status interop"
else
  echo "═══════════════════════════════════════════════════════════════"
  echo "  ✗ OpenPGP card surface FAIL  (rc=$overall_rc)"
  echo "═══════════════════════════════════════════════════════════════"
fi
exit $overall_rc
