#!/usr/bin/env bash
# Host test for tools/dfu-flash.sh: feeds it fake dfu-util runs and checks
# the verdict.  No hardware.  Run: bash tests/host/test-dfu-flash.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FLASH="$HERE/../../tools/dfu-flash.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
touch "$TMP/fw.bin"
fails=0

# case <name> <expected exit> <fake exit> <fake output lines...>
case_() {
  local name="$1" want="$2" code="$3"; shift 3
  { echo '#!/usr/bin/env bash'
    for l in "$@"; do printf 'echo %q\n' "$l"; done
    echo "exit $code"; } > "$TMP/dfu-util"
  chmod +x "$TMP/dfu-util"
  DFU_UTIL="$TMP/dfu-util" bash "$FLASH" "$TMP/fw.bin" >/dev/null 2>&1
  local got=$?
  if [ "$got" -eq "$want" ]; then echo "ok   $name"; else echo "FAIL $name (exit $got, want $want)"; fails=$((fails+1)); fi
}

case_ "clean exit 0"                     0 0  "Download done." "File downloaded successfully"
case_ "benign leave get_status"          0 74 "File downloaded successfully" "Submitting leave request..." "dfu-util: Error during download get_status"
case_ "get_status error mid-download"    1 74 "Downloading element to address = 0x08000000, size = 1" "dfu-util: Error during download get_status"
case_ "leave sent, other error"          1 74 "File downloaded successfully" "Submitting leave request..." "dfu-util: Error during download"
case_ "no device"                        1 74 "dfu-util: No DFU capable USB device available"
case_ "benign text but exit 1"           1 1  "File downloaded successfully" "Submitting leave request..." "dfu-util: Error during download get_status"
case_ "leave before success marker"      1 74 "Submitting leave request..." "File downloaded successfully" "dfu-util: Error during download get_status"

# Missing image never reaches dfu-util.
DFU_UTIL=/bin/false bash "$FLASH" "$TMP/missing.bin" >/dev/null 2>&1 && { echo "FAIL missing image"; fails=$((fails+1)); } || echo "ok   missing image"

[ "$fails" -eq 0 ] && echo "dfu-flash: all passed" || { echo "dfu-flash: $fails failed"; exit 1; }
