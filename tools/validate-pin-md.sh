#!/usr/bin/env bash
# Destructive validation: confirm the M&D-backed PIN retry counter
# actually consumes chip slots and locks the dongle after the
# configured number of wrong attempts (default 3).
#
# Phase 8 M4.F.
#
# WHY THIS LIVES OUTSIDE validate-openpgp.sh
# ===========================================
# Running this test wipes the user's PW1, PW3 (and forces a
# TERMINATE+ACTIVATE recovery flow at the end).  After it finishes
# the dongle is back to factory defaults; the user must re-run
# `gpg --card-edit > admin > generate` to bind keys before any
# real cryptographic operations work again.
#
# Required env (override per run as needed):
#
#   PW3_GOOD   default 12345678  — admin PIN, must be correct
#   PW1_WRONG  default wrongPin99 — what we feed as wrong attempts
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

PW3_GOOD="${PW3_GOOD:-12345678}"
PW1_WRONG="${PW1_WRONG:-wrongPin99}"

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

# Helper: send a VERIFY-PW1 APDU directly and capture SW.
# We hand-craft so we don't depend on gpg's PIN cache / pinentry.
verify_pw1() {
  local pin="$1"
  local hex="$(printf '%s' "$pin" | od -An -tx1 | tr -d ' \n')"
  local len="$(printf '%02x' $((${#hex} / 2)))"
  gpg-connect-agent --hex \
    "SCD APDU 00 20 00 81 ${len} ${hex}" /bye 2>&1 \
    | grep -oE '[0-9A-F]{4}' | tail -1
}

# Pre-fly: confirm PW1 retry counter is 3 (fresh state).
PRE_RETRY="$(gpg --card-status 2>&1 | sed -nE 's/^PIN retry counter +\.+: +([0-9]).*$/\1/p' | head -1)"
echo "  PW1 retry counter before test: ${PRE_RETRY}"
if [ "${PRE_RETRY}" != "3" ]; then
  red "✗ PW1 counter not at 3.  Run gpg --card-edit > admin > verify"
  red "  to recover before running this destructive test."
  exit 1
fi

# Feed 3 wrong PINs.
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
HEX_PW3="$(printf '%s' "${PW3_GOOD}" | od -An -tx1 | tr -d ' \n')"
LEN_PW3="$(printf '%02x' $((${#HEX_PW3} / 2)))"
SW_PW3="$(gpg-connect-agent --hex \
  "SCD APDU 00 20 00 83 ${LEN_PW3} ${HEX_PW3}" /bye 2>&1 \
  | grep -oE '[0-9A-F]{4}' | tail -1)"

if [ "${SW_PW3}" != "9000" ]; then
  red "  ✗ PW3 verify failed (SW=${SW_PW3}).  Set PW3_GOOD env."
  exit 1
fi

SW_TERM="$(gpg-connect-agent --hex "SCD APDU 00 E6 00 00" /bye 2>&1 \
  | grep -oE '[0-9A-F]{4}' | tail -1)"
SW_ACT="$(gpg-connect-agent --hex "SCD APDU 00 44 00 00" /bye 2>&1 \
  | grep -oE '[0-9A-F]{4}' | tail -1)"

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
echo "Now run to restore keys:"
echo "    gpg --card-edit"
echo "    > admin"
echo "    > passwd"
echo "    > name"
echo "    > generate"
