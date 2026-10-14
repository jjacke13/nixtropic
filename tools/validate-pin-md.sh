#!/usr/bin/env bash
# Destructive validation: confirm the M&D-backed PIN retry counter
# actually consumes chip slots and locks the dongle after the
# configured number of wrong attempts (default 3).
#
# Phase 8 M4.F; Phase 9 M0: fixture PINs + establish the M&D binding first.
#
# WHY THIS LIVES OUTSIDE validate-openpgp.sh
# ===========================================
# Running this test wipes the user's PW1, PW3 (and forces a
# TERMINATE+ACTIVATE recovery flow at the end).  After it finishes
# the dongle is back to factory defaults; the user must re-run
# `gpg --card-edit > admin > generate` to bind keys before any
# real cryptographic operations work again.
#
# MUTATES the card: PW1 changed to NIXTROPIC_PW1_MD_TEST (this sets up its
# M&D binding: M&D slots re-initialised, R-mem state rewritten), one correct
# VERIFY, three wrong VERIFYs (three M&D slots destroyed, PW1 locked), then
# PW3 VERIFY + TERMINATE + ACTIVATE (all OpenPGP keys erased, factory PINs).
#
# PINs come from tools/fixture.env (see tools/fixture.env.example); the
# script never guesses one.  Why the PIN change first: on a fresh card PW1
# has no M&D binding yet and the software counter answers instead, so the
# lockout below would prove nothing about the chip.  The firmware does not
# report which path answered (until Phase 9 M4 removes the software path),
# so binding first is the only way to know the chip counter is the one tested.
#
# Run with:
#
#   bash tools/validate-pin-md.sh --destroy-my-pin
#
# Anything less than the explicit --destroy-my-pin argument is
# refused.

set -uo pipefail

if [ "${1:-}" != "--destroy-my-pin" ]; then
  cat <<'EOF'
Refusing to run.

This script DESTROYS the dongle's current PIN state via the
MAC-and-Destroy hardware retry counter.  After running, you must
re-init with `gpg --card-edit > admin > passwd > generate`.

If you accept that and want to proceed, re-run with:
    bash tools/validate-pin-md.sh --destroy-my-pin
EOF
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib-fixture.sh
. "$SCRIPT_DIR/lib-fixture.sh"
fixture_load
if [ -z "${NIXTROPIC_PW1_MD_TEST:-}" ]; then
  echo "✗ fixture: NIXTROPIC_PW1_MD_TEST is required by this script" >&2
  exit 2
fi
# A wrong PIN that cannot collide with any fixture PIN.
PW1_WRONG="wrong-${NIXTROPIC_PW1_MD_TEST}-x"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

blue "═══════════════════════════════════════════════════════════════"
blue "  nixtropic — M&D PIN retry-counter validation (DESTRUCTIVE)"
blue "═══════════════════════════════════════════════════════════════"

# Sanity check: dongle plugged + card-status reachable.
if ! lsusb | grep -q "cafe:4001"; then
  red "✗ cafe:4001 not on USB.  Plug the open firmware dongle first."
  exit 1
fi
gpgconf --kill scdaemon >/dev/null 2>&1 || true
sleep 1
if ! gpg --card-status >/dev/null 2>&1; then
  red "✗ gpg --card-status failed.  Check README §5 bring-up sequence."
  exit 1
fi
green "✓ Dongle visible to gpg-agent"

# Send one APDU through scdaemon (no gpg PIN cache / pinentry involved)
# and print its status word = the last two response bytes.  The reply is a
# hexdump: "D[0000]  00 40 40 40 03 00 03 90  00   .@@@....."; only the
# byte columns are read (the offset and the ASCII column can look like hex).
# The old `grep -oE '[0-9A-F]{4}' | tail -1` picked the offset "0000".
# No D line (scdaemon error) → empty status → the caller fails.
apdu_sw() {
  gpg-connect-agent --hex "SCD APDU $*" /bye 2>&1 | awk '
    /^D\[[0-9A-Fa-f]+\]/ {
      n = split(substr($0, 10, 49), f, " ")
      for (i = 1; i <= n; i++) if (f[i] ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) b[c++] = toupper(f[i])
    }
    END { if (c >= 2) print b[c-2] b[c-1] }'
}
verify_pw1() { apdu_sw "00 20 00 81 $(pin_lc "$1") $(pin_hex "$1" '')"; }
verify_pw3() { apdu_sw "00 20 00 83 $(pin_lc "$1") $(pin_hex "$1" '')"; }

# "PIN retry counter : 3 0 3" → PW1 and PW3 counters.  Read-only.
retries() {
  gpg --card-status 2>&1 | sed -nE 's/^PIN retry counter +\.*: +([0-9]+) +([0-9]+) +([0-9]+).*$/\1 \3/p' | head -1
}

# Preflight: both counters full before ANY PIN use.
read -r PRE_PW1 PRE_PW3 <<<"$(retries)"
echo "  retry counters before test: PW1=${PRE_PW1:-?} PW3=${PRE_PW3:-?}"
if [ "${PRE_PW1:-}" != "3" ] || [ "${PRE_PW3:-}" != "3" ]; then
  red "✗ Counters not at 3.  Recover with gpg --card-edit first; this"
  red "  script will not spend attempts on a card in an unknown state."
  exit 1
fi

# Step 1: bind PW1 to M&D by changing it (fixture PW1 → MD test PIN).
blue "── bind PW1 to M&D: CHANGE REFERENCE DATA PW1 ──"
OLD_HEX="$(pin_hex "$NIXTROPIC_PW1" '')"
NEW_HEX="$(pin_hex "$NIXTROPIC_PW1_MD_TEST" '')"
LC="$(printf '%02X' $(( 0x$(pin_lc "$NIXTROPIC_PW1") + 0x$(pin_lc "$NIXTROPIC_PW1_MD_TEST") )))"
SW="$(apdu_sw "00 24 00 81 ${LC} ${OLD_HEX}${NEW_HEX}")"
echo "  SW = ${SW}"
if [ "${SW}" != "9000" ]; then
  red "  ✗ PIN change failed — is NIXTROPIC_PW1 in tools/fixture.env right?"
  red "    Stopped after one attempt."
  exit 1
fi
green "  ✓ PW1 changed; M&D binding set up"

# Step 2: the bound PIN verifies (spends one M&D slot, then re-inits all).
blue "── correct VERIFY on the bound PIN ──"
SW="$(verify_pw1 "${NIXTROPIC_PW1_MD_TEST}")"
echo "  SW = ${SW}"
if [ "${SW}" != "9000" ]; then
  red "  ✗ correct PIN refused after binding — bug"; exit 1
fi
green "  ✓ bound PIN verifies"

# Step 3: three wrong PINs.
for i in 1 2 3; do
  blue "── wrong attempt ${i}/3 ──"
  SW="$(verify_pw1 "${PW1_WRONG}")"
  echo "  SW = ${SW}"
  case "${SW}" in
    63C0|6983)
      if [ "${i}" -lt 3 ]; then
        red "  ✗ Counter dropped to 0 too early"; exit 1
      fi
      green "  ✓ blocked (expected on attempt ${i})"
      ;;
    63C[1-3])
      green "  ✓ wrong-PIN counter decremented"
      ;;
    9000)
      red "  ✗ verify succeeded with WRONG PIN — bug"; exit 1
      ;;
    *)
      red "  ✗ unexpected SW ${SW}"; exit 1
      ;;
  esac
done

blue "── 4th attempt (should be HW-locked) ──"
SW="$(verify_pw1 "${PW1_WRONG}")"
case "${SW}" in
  63C0|6983)
    green "  ✓ HW lockout enforced — chip-side M&D slots consumed"
    ;;
  *)
    red "  ✗ expected SW=63C0 / 6983, got ${SW}"
    exit 1
    ;;
esac

blue "── recover via TERMINATE+ACTIVATE ──"
# Verify PW3 first (TERMINATE requires PW3 verified).
SW_PW3="$(verify_pw3 "${NIXTROPIC_PW3}")"
if [ "${SW_PW3}" != "9000" ]; then
  red "  ✗ PW3 verify failed (SW=${SW_PW3}).  Is NIXTROPIC_PW3 in the fixture right?"
  exit 1
fi
SW_TERM="$(apdu_sw "00 E6 00 00")"
SW_ACT="$(apdu_sw "00 44 00 00")"
if [ "${SW_TERM}" = "9000" ] && [ "${SW_ACT}" = "9000" ]; then
  green "  ✓ TERMINATE + ACTIVATE round-trip cleared the lockout"
else
  red "  ✗ recovery failed (TERM=${SW_TERM}, ACT=${SW_ACT})"
  exit 1
fi

blue "═══════════════════════════════════════════════════════════════"
green "  ✓ M&D PIN retry counter validates: 3-wrong locks, T+A recovers"
blue "═══════════════════════════════════════════════════════════════"
echo
echo "The card is at factory defaults now (PINs 123456 / 12345678, no keys)."
echo "Set tools/fixture.env back to those if it differed.  To use the card:"
echo "    gpg --card-edit"
echo "    > admin"
echo "    > passwd"
echo "    > name"
echo "    > generate"
