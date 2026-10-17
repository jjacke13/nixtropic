#!/usr/bin/env bash
# Phase 9 M4 hardware check of the OpenPGP PIN semantics (design §7):
# PW1.81 vs PW1.82, DO C4 00 (one signature per VERIFY), CHANGE split by the
# stored length, RC set + RESET RETRY COUNTER, and the time of a VERIFY.
# Phase 9 M5: the DEC key is wrapped under the PW1 KEK — GENERATE dec needs
# PW3 and a verified PW1 (81 or 82), PSO:DEC 82, a PW1 change keeps the key,
# a RESET RETRY COUNTER destroys it (after its preflight).
#
# DESTRUCTIVE: expects the factory PINs (123456 / 12345678), generates a new
# signature and decryption key, ends with TERMINATE + ACTIVATE (all OpenPGP keys erased,
# factory PINs).  Needs opensc-tool (dev shell); stops scdaemon first.
set -euo pipefail

hex() { printf '%s' "$1" | od -An -tx1 | tr -s ' \n' ':' | sed 's/^://; s/:$//'; }
lc() { printf '%02X' "${#1}"; }
apdu_pin() { echo "00:$1:00:$2:$(lc "$3"):$(hex "$3")"; }
two() { local b="$3$4"; echo "00:$1:$2:81:$(printf '%02X' "${#b}"):$(hex "$b")"; }

SEL=00:A4:04:00:06:D2:76:00:01:24:01
MSG=$(printf '11:%.0s' $(seq 1 32)); MSG=${MSG%:}
DEC="00:2A:80:86:27:A6:25:7F:49:22:86:20:$(printf '09:%.0s' $(seq 1 32))"; DEC=${DEC%:}

steps=(
  "$SEL|9000|SELECT"
  "$(apdu_pin 20 83 12345678)|9000|VERIFY PW3"
  "00:47:80:00:02:B6:00|9000|GENERATE sig key"
  "00:47:80:00:02:B8:00|6982|GENERATE dec key refused with PW3 only (M5: no KEK)"
  "00:47:81:00:02:B8:00|6A88|no dec key yet"
  "$(apdu_pin 20 81 123456)|9000|VERIFY 81 (what gpg sends on a fresh card)"
  "00:47:80:00:02:B8:00|9000|GENERATE dec key (PW3 + 81)"
  "00:DA:00:D6:02:00:20|9000|UIF off (no touch needed here)"
  "00:DA:00:C4:01:00|9000|C4 byte 0 := 00"
  "$(apdu_pin 20 81 123456)|9000|VERIFY 81"
  "$DEC|6982|PSO:DEC refused with 81 only"
  "00:2A:9E:9A:20:$MSG|9000|CDS (81)"
  "00:2A:9E:9A:20:$MSG|6982|second CDS refused (C4 00)"
  "$(apdu_pin 20 81 123456)|9000|VERIFY 81 again"
  "00:2A:9E:9A:20:$MSG|9000|CDS again"
  "00:DA:00:C4:01:01|9000|C4 byte 0 := 01"
  "$(apdu_pin 20 82 123456)|9000|VERIFY 82"
  "$DEC|9000|PSO:DEC with 82 (wrapped key unwrapped)"
  "$(two 24 00 123456 654321)|9000|CHANGE PW1"
  "$(apdu_pin 20 81 123456)|63C2|old PW1 refused"
  "$(apdu_pin 20 81 654321)|9000|new PW1"
  "$(apdu_pin 20 82 654321)|9000|VERIFY 82, new PW1"
  "$DEC|9000|PSO:DEC after the change (same key, M5 E7)"
  "00:DA:00:D3:08:$(hex rcrcrcrc)|9000|set RC"
  "$(apdu_pin 20 81 000000)|63C2|wrong PW1 1"
  "$(apdu_pin 20 81 000000)|63C1|wrong PW1 2"
  "$(apdu_pin 20 81 000000)|63C0|wrong PW1 3"
  "$(apdu_pin 20 81 654321)|6983|PW1 blocked"
  "$(two 2C 00 rcrcrcrc 12345)|6700|RESET RETRY COUNTER, PW1 too short (no RC attempt)"
  "00:47:81:00:02:B8:00|9000|dec key still there"
  "$(two 2C 00 xxxxxxxx 123456)|63C2|RESET RETRY COUNTER, wrong RC"
  "00:47:81:00:02:B8:00|9000|dec key still there"
  "$(two 2C 00 rcrcrcrc 123456)|9000|RESET RETRY COUNTER by RC"
  "00:47:81:00:02:B8:00|6A88|dec key destroyed by the reset (M5 E8)"
  "$(apdu_pin 20 82 123456)|9000|PW1 after the reset (82)"
  "$DEC|6A88|PSO:DEC: no key"
  "00:47:80:00:02:B8:00|9000|GENERATE dec key again (PW3 + 82)"
  "$DEC|9000|PSO:DEC with the new key"
  "00:DA:00:D3:00|9000|clear RC"
  "00:CA:00:C4:00|9000|C4"
  "00:E6:00:00|9000|TERMINATE (PW3 verified)"
  "00:44:00:00|9000|ACTIVATE"
)

gpgconf --kill scdaemon 2>/dev/null || true
args=(); for s in "${steps[@]}"; do args+=(-s "${s%%|*}"); done
out=$(opensc-tool --reader 0 --card-driver default "${args[@]}" 2>&1)
mapfile -t got < <(echo "$out" | sed -n 's/.*Received (SW1=0x\(..\), SW2=0x\(..\)).*/\1\2/p' | tr a-f A-F)
fail=0
for i in "${!steps[@]}"; do
  IFS='|' read -r _ want name <<<"${steps[$i]}"
  if [ "${got[$i]:-none}" = "$want" ]; then echo "  ✓ $name ($want)"; else echo "  ✗ $name: want $want, got ${got[$i]:-none}"; fail=1; fi
done
echo "$out" | grep -A1 "00 CA 00 C4" | tail -1 | sed 's/^/  C4 after: /'
# One VERIFY, timed (SELECT alone subtracted).
t0=$(date +%s%N); opensc-tool --reader 0 -s "$SEL" >/dev/null 2>&1; t1=$(date +%s%N)
opensc-tool --reader 0 -s "$SEL" -s "$(apdu_pin 20 81 123456)" >/dev/null 2>&1; t2=$(date +%s%N)
echo "  VERIFY 81 ≈ $(( ((t2 - t1) - (t1 - t0)) / 1000000 )) ms"
[ $fail = 0 ] && echo "M4 OpenPGP hardware check: PASS" || { echo "M4 OpenPGP hardware check: FAIL"; exit 1; }
