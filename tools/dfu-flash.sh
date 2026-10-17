#!/usr/bin/env bash
# dfu-flash.sh <firmware.bin> — flash the STM32U535 over its ROM DFU bootloader
# and report the truth about it.  Used by every flash app in nix/apps.nix.
#
# Exit 0 only when:
#   - dfu-util exits 0, or
#   - dfu-util hits the ONE known-benign failure of `:leave`: the download
#     completed ("File downloaded successfully"), the leave request was sent
#     ("Submitting leave request..."), the device jumped to the new firmware
#     and so never answered the final get_status, and dfu-util exited
#     EX_IOERR (74) with exactly "Error during download get_status" as its
#     last line.  (dfu-util 0.11, src/dfuse.c dfuse_do_leave →
#     dfuse_dnload_chunk.)
# Anything else is a failed flash.  The dongle then usually still sits in DFU
# mode and the flash can simply be retried.
#
# Phase 9 M0: the old inline check ran `dfu-util … | tee … || true` and then
# read PIPESTATUS, which by then described `true`, so every flash "succeeded".
#
# DFU_UTIL overrides the dfu-util binary (tests/host/test-dfu-flash.sh).
set -uo pipefail

FW_BIN="${1:?usage: dfu-flash.sh <firmware.bin>}"
DFU_UTIL="${DFU_UTIL:-dfu-util}"

if [ ! -f "$FW_BIN" ]; then
  echo "✗ firmware image not found: $FW_BIN" >&2
  exit 1
fi

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

"$DFU_UTIL" -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$LOG"
rc="${PIPESTATUS[0]}"

echo ""
if [ "$rc" -eq 0 ]; then
  echo "✓ Flash complete (dfu-util exit 0)."
  exit 0
fi

# Known-benign leave failure: markers in this order, and the error is the
# very last line of output.
if [ "$rc" -eq 74 ] && awk '
    /^File downloaded successfully$/                 { done = NR }
    /^Submitting leave request\.\.\.$/ && done        { leave = NR }
    END {
      if (!done || !leave) exit 1
      if ($0 != "dfu-util: Error during download get_status") exit 1
    }' "$LOG"; then
  echo "✓ Flash complete.  (dfu-util exit 74 after :leave = the device left"
  echo "  DFU before answering get_status; expected on the STM32 ROM loader.)"
  exit 0
fi

echo "✗ Flash FAILED (dfu-util exit $rc).  The dongle is most likely still in"
echo "  DFU mode; it is safe to retry.  See docs/recovery.md."
exit 1
