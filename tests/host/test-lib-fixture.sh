#!/usr/bin/env bash
# Host test for tools/lib-fixture.sh: PIN encodings and fixture validation.
# No hardware.  Run: bash tests/host/test-lib-fixture.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../tools/lib-fixture.sh
. "$HERE/../../tools/lib-fixture.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fails=0
eq() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got [$2] want [$3]"; fails=$((fails+1)); fi; }

eq "pin_hex default sep"   "$(pin_hex 123456)"       "31:32:33:34:35:36"
eq "pin_hex empty sep"     "$(pin_hex 123456 '')"    "313233343536"
eq "pin_hex space sep"     "$(pin_hex 12 ' ')"       "31 32"
eq "pin_hex 20 bytes"      "$(pin_hex aaaaaaaaaaaaaaaaaaaa '')" "6161616161616161616161616161616161616161"
eq "pin_lc 6"              "$(pin_lc 123456)"        "06"
eq "pin_lc 16"             "$(pin_lc 0123456789abcdef)" "10"

load() { ( NIXTROPIC_FIXTURE="$TMP/f.env"; fixture_load ) >/dev/null 2>&1; echo $?; }
printf 'NIXTROPIC_PW1=123456\nNIXTROPIC_PW3=12345678\nNIXTROPIC_PW1_MD_TEST=246813\n' > "$TMP/f.env"
eq "valid fixture loads"    "$(load)" 0
printf 'NIXTROPIC_PW1=12345\nNIXTROPIC_PW3=12345678\n' > "$TMP/f.env"
eq "short PW1 rejected"     "$(load)" 2
printf 'NIXTROPIC_PW1=123456\nNIXTROPIC_PW3=1234567\n' > "$TMP/f.env"
eq "short PW3 rejected"     "$(load)" 2
printf 'NIXTROPIC_PW1=123456\nNIXTROPIC_PW3=12345678\nNIXTROPIC_PW1_MD_TEST=123456\n' > "$TMP/f.env"
eq "MD test PIN == PW1 rejected" "$(load)" 2
rm -f "$TMP/f.env"
eq "missing fixture rejected" "$(load)" 2

[ "$fails" -eq 0 ] && echo "lib-fixture: all passed" || { echo "lib-fixture: $fails failed"; exit 1; }
