{ pkgs, stockFirmware, openFirmware ? null, libtropicUtil ? null }:

# Backwards-compat alias — many internal references still use `firmware`.
let firmware = openFirmware; in

# Flake apps for `nix run .#<app>`.
#
# Phase 0 set:
#   flash-stock     — DFU-flashes stock firmware (recovery / factory reset)
#   identify        — Runs lt-util chip-info command (against stock firmware)
#   check-dongle    — Diagnostic: lsusb + udev permission check
# Phase 1 set:
#   flash-firmware  — DFU-flashes our custom Phase 1 firmware. Same DFU
#                     mechanic as flash-stock, different binary. Per
#                     plan decision P1.23 (no rename of flash-stock).
#   read            — Open USB CDC console (/dev/ttyACM*) via screen.
#                     Uses screen instead of picocom — picocom's tcsetattr
#                     races with TinyUSB CDC SET_LINE_CODING and hangs
#                     intermittently (task #27 follow-up).
#   validate-phase1 — Captures CDC output for ~8s, greps for the markers
#                     proving Phase 1 PASS: chip_id matches Phase 0 baseline
#                     byte-for-byte, L2 sweep PASS, PHASE1 OK marker.
#
# These apps are deliberately thin wrappers around dfu-util + lt-util. They
# do not do anything destructive without user input — flash-stock and
# flash-firmware only write to the STM32U535's flash (not the TROPIC01
# chip — chip is unaffected).

let
  inherit (pkgs) writeShellApplication dfu-util usbutils screen coreutils gnugrep;

  flash-stock = writeShellApplication {
    name = "nixtropic-flash-stock";
    runtimeInputs = [ dfu-util usbutils ];
    text = ''
      set -euo pipefail

      FW_BIN="${stockFirmware}/firmware.bin"

      echo "═══════════════════════════════════════════════════════════════"
      echo "  Flashing stock TS1302 firmware (recovery / factory reset)"
      echo "═══════════════════════════════════════════════════════════════"
      echo ""
      echo "Stock firmware: $FW_BIN"
      echo ""
      echo "Checking for TS1302 in DFU mode (USB ID 0483:df11)..."
      if ! lsusb | grep -q "0483:df11"; then
        echo ""
        echo "ERROR: Dongle is NOT in DFU mode."
        echo ""
        echo "To enter DFU mode:"
        echo "  1. Unplug the TS1302 dongle"
        echo "  2. Hold the SW1 button (the only button) DOWN"
        echo "  3. While holding SW1, plug the dongle in"
        echo "  4. Release SW1 after USB enumeration"
        echo "  5. Verify: lsusb | grep 0483:df11"
        echo ""
        echo "Then re-run this command."
        echo ""
        echo "If lsusb shows '0483:5740' instead, the dongle is in normal app"
        echo "mode — that's a working dongle, not in need of recovery."
        exit 1
      fi

      echo "✓ DFU mode detected"
      echo ""
      echo "Flashing... (this writes to STM32U535 flash at 0x08000000;"
      echo "TROPIC01 chip is NOT touched by this operation)"
      echo ""

      # dfu-util exits non-zero after a successful :leave because the device
      # disconnects from USB to jump to user firmware before dfu-util can read
      # final get_status. This is a known benign quirk affecting every STM32 +
      # dfu-util combo. Detect by parsing for the "File downloaded successfully"
      # marker rather than relying on exit code alone.
      DFU_LOG=$(mktemp)
      trap 'rm -f "$DFU_LOG"' EXIT

      dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" || true
      DFU_EXIT="''${PIPESTATUS[0]}"

      echo ""
      if [ "$DFU_EXIT" -eq 0 ]; then
        echo "✓ Flash complete (clean dfu-util exit)."
      elif grep -q "File downloaded successfully" "$DFU_LOG"; then
        echo "✓ Flash complete."
        echo "  ('Error during download get_status' after the :leave is a benign"
        echo "  dfu-util quirk — STM32 jumped to user firmware before dfu-util"
        echo "  could read the final status. Flash itself succeeded per the"
        echo "  'File downloaded successfully' line above.)"
      else
        echo "✗ Flash FAILED — dfu-util exit $DFU_EXIT and no"
        echo "  'File downloaded successfully' marker in output. The dongle is"
        echo "  likely still in DFU mode; safe to retry. If retries fail, see"
        echo "  docs/RECOVERY.md."
        exit 1
      fi

      echo ""
      echo "  The dongle should restart in app mode automatically."
      echo "  Wait ~2 seconds, then run: nix run .#identify"
    '';
  };

  identify =
    if libtropicUtil == null then
      writeShellApplication {
        name = "nixtropic-identify-placeholder";
        text = ''
          echo "lt-util not yet packaged in this flake."
          echo "Phase 0 placeholder; will be wired up after libtropic-util pkg added."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-identify";
        runtimeInputs = [ libtropicUtil usbutils ];
        text = ''
          set -euo pipefail

          echo "Checking for TS1302 in app mode..."
          echo "  Acceptable VID/PID: 0483:5740 (stock) OR cafe:4001 (nixtropic open)"
          if ! lsusb | grep -qE "0483:5740|cafe:4001"; then
            echo ""
            echo "ERROR: Dongle is not in app mode."
            echo ""
            if lsusb | grep -q "0483:df11"; then
              echo "Dongle is in DFU mode — flash firmware first:"
              echo "  sudo nix run .#flash-stock           # restore stock"
              echo "  sudo nix run .#flash-firmware        # load nixtropic open"
            else
              echo "Dongle not detected. Check the USB cable and lsusb output."
            fi
            exit 1
          fi

          DEV="''${TROPIC_DEV:-/dev/ttyACM0}"
          if lsusb | grep -q "cafe:4001"; then
            echo "✓ App mode detected — nixtropic open firmware (cafe:4001)"
          else
            echo "✓ App mode detected — stock firmware (0483:5740)"
          fi
          echo ""
          echo "Querying chip on $DEV..."
          echo ""

          # Read chip info via lt-util.
          # Override device path with TROPIC_DEV=/dev/ttyACM1 etc. if needed.
          lt-util "$DEV" -i || {
            echo ""
            echo "ERROR: lt-util failed. Possible causes:"
            echo "  - Permission denied: install nixosModules.tropic on this host,"
            echo "    OR add yourself to the dialout group, OR run with sudo"
            echo "  - Wrong device: try TROPIC_DEV=/dev/ttyACM1 nix run .#identify"
            echo "  - Pairing key mismatch: TS1302 ships eng-sample chips, ensure"
            echo "    libtropic was built with the matching key set"
            exit 1
          }
        '';
      };

  # Phase 1 — flash-firmware (decision P1.23): mirror flash-stock with
  # different binary path. Same DFU dance, same benign-tail-error handling.
  flash-firmware =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-firmware-placeholder";
        text = ''
          echo "Custom firmware not yet built in this flake."
          echo "Phase 0 placeholder; will be wired up after firmware pkg added."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-firmware";
        runtimeInputs = [ dfu-util usbutils ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Flashing nixtropic Phase 1 firmware"
          echo "═══════════════════════════════════════════════════════════════"
          echo ""
          echo "Firmware: $FW_BIN"
          echo ""
          echo "Checking for TS1302 in DFU mode (USB ID 0483:df11)..."
          if ! lsusb | grep -q "0483:df11"; then
            echo ""
            echo "ERROR: Dongle is NOT in DFU mode."
            echo ""
            echo "To enter DFU mode:"
            echo "  1. Unplug the TS1302 dongle"
            echo "  2. Hold the SW1 button (the only button) DOWN"
            echo "  3. While holding SW1, plug the dongle in"
            echo "  4. Release SW1 after USB enumeration"
            echo "  5. Verify: lsusb | grep 0483:df11"
            echo ""
            echo "Then re-run this command."
            echo ""
            echo "If lsusb shows '0483:5740' instead, the dongle is running"
            echo "the stock firmware. Recovery from custom-fw is the same DFU"
            echo "dance — there's no risk."
            exit 1
          fi

          echo "✓ DFU mode detected"
          echo ""
          echo "Flashing custom firmware... (writes STM32U535 flash at 0x08000000;"
          echo "TROPIC01 chip is NOT touched by this operation)"
          echo ""

          # Same benign-tail-error handling as flash-stock — see comment there.
          DFU_LOG=$(mktemp)
          trap 'rm -f "$DFU_LOG"' EXIT

          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" || true
          DFU_EXIT="''${PIPESTATUS[0]}"

          echo ""
          if [ "$DFU_EXIT" -eq 0 ]; then
            echo "✓ Flash complete (clean dfu-util exit)."
          elif grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✓ Flash complete."
            echo "  ('Error during download get_status' after the :leave is a benign"
            echo "  dfu-util quirk — STM32 jumped to user firmware before dfu-util"
            echo "  could read final status.)"
          else
            echo "✗ Flash FAILED — dfu-util exit $DFU_EXIT and no"
            echo "  'File downloaded successfully' marker. Dongle is likely still"
            echo "  in DFU mode; safe to retry. If retries fail, fall back to"
            echo "  flash-stock for known-good recovery (docs/RECOVERY.md)."
            exit 1
          fi

          echo ""
          echo "  Phase 1 firmware should now be running. PA9 LED should pulse"
          echo "  at ~1 Hz (heartbeat). USB CDC enumeration comes in Group C."
        '';
      };

  # Phase 1 — read: open USB CDC console via screen.
  # Why screen and not picocom: picocom calls tcsetattr at open which
  # generates a USB CDC SET_LINE_CODING control transfer. TinyUSB's
  # default response timing races with picocom's expectation, causing
  # picocom to hang intermittently (verified by user 2026-05-10).
  # screen takes a different code path that's more tolerant.
  read = writeShellApplication {
    name = "nixtropic-read";
    runtimeInputs = [ screen usbutils ];
    text = ''
      set -euo pipefail

      DEV="''${TROPIC_DEV:-/dev/ttyACM0}"

      if [ ! -e "$DEV" ]; then
        echo "ERROR: $DEV not found." >&2
        echo "" >&2
        echo "If the dongle is plugged in:" >&2
        if lsusb | grep -qi "cafe:4001"; then
          echo "  USB is enumerated as nixtropic Phase 1 (cafe:4001) but the" >&2
          echo "  TTY device node is at a different path. Try TROPIC_DEV=/dev/ttyACM1" >&2
        elif lsusb | grep -q "0483:5740"; then
          echo "  USB shows stock firmware (0483:5740). Custom Phase 1 firmware" >&2
          echo "  is not currently flashed. Run: sudo nix run .#flash-firmware" >&2
        elif lsusb | grep -q "0483:df11"; then
          echo "  USB shows DFU mode (0483:df11). The dongle is not running" >&2
          echo "  any application firmware. Run: sudo nix run .#flash-firmware" >&2
        else
          echo "  USB doesn't show any TS1302-related VID. Check cable + plug." >&2
        fi
        exit 1
      fi

      echo "Opening $DEV via screen at 115200 baud."
      echo "  Exit: Ctrl-A k  (then 'y' to confirm)"
      echo ""
      exec screen "$DEV" 115200
    '';
  };

  validate-phase1 = writeShellApplication {
    name = "nixtropic-validate-phase1";
    runtimeInputs = [ coreutils gnugrep ];
    text = ''
      set -uo pipefail
      exec ${../tools/validate-phase1.sh} "$@"
    '';
  };

  # Phase 2 — validate-phase2: runs lt-util against our open firmware and
  # matches its chip-info output against the Phase 0 baseline. 5/5 PASS
  # confirms byte-faithful drop-in stock-fw replacement.
  validate-phase2 =
    if libtropicUtil == null then
      writeShellApplication {
        name = "nixtropic-validate-phase2-placeholder";
        text = ''
          echo "lt-util not yet packaged in this flake; cannot run Phase 2 validation."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-validate-phase2";
        runtimeInputs = [ libtropicUtil usbutils coreutils gnugrep ];
        text = ''
          set -uo pipefail
          exec ${../tools/validate-phase2.sh} "$@"
        '';
      };

  # Phase 1 — flash-and-validate: orchestrates DFU flash + immediate validate.
  # Solves the "boot markers emit only once" gotcha: after flash, the
  # firmware re-boots fresh and emits its boot block; the validator captures
  # that within the same script run.
  flash-and-validate =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-placeholder";
        text = ''
          echo "Custom firmware not available in this flake."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 1: flash-and-validate (one-shot regression test)"
          echo "═══════════════════════════════════════════════════════════════"
          echo ""

          # Step 1: confirm dongle in DFU mode
          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle is not in DFU mode (0483:df11)." >&2
            echo "" >&2
            echo "To enter DFU mode:" >&2
            echo "  1. Unplug the TS1302 dongle" >&2
            echo "  2. Hold SW1 (the only button) DOWN" >&2
            echo "  3. While holding SW1, plug the dongle back in" >&2
            echo "  4. Release SW1 after USB enumeration" >&2
            echo "  5. Verify: lsusb | grep 0483:df11" >&2
            echo "" >&2
            echo "Then re-run this command." >&2
            exit 1
          fi

          # Step 2: flash via DFU (same logic as flash-firmware)
          echo "Step 1/2: DFU flash..."
          DFU_LOG=$(mktemp)
          trap 'rm -f "$DFU_LOG"' EXIT

          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"

          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED. See $DFU_LOG for full output."
            exit 1
          fi

          echo "✓ Flash complete. Waiting up to 12 s for USB re-enumeration..."

          # Poll for /dev/ttyACM* — our dongle's enumeration sometimes
          # retries 2-3 times (kernel error -71 then success), totaling
          # ~3-4 seconds. Plus cdc_acm attach + udev rule processing.
          DETECTED_DEV=""
          for _ in $(seq 1 24); do
            sleep 0.5
            for candidate in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyACM2 /dev/ttyACM3; do
              if [ -e "$candidate" ]; then
                DETECTED_DEV="$candidate"
                break 2
              fi
            done
          done

          if [ -z "$DETECTED_DEV" ]; then
            echo "✗ No /dev/ttyACM* appeared after 12 s. Possible causes:" >&2
            echo "    - Firmware crashed before USB init (run nix run .#read after manual replug" >&2
            echo "      to see if device responds at all)" >&2
            echo "    - Host USB port had a state issue — try unplug + replug (no SW1) and" >&2
            echo "      run nix run .#validate-phase1 manually within 5 s of replug" >&2
            echo "" >&2
            echo "  Current USB state:" >&2
            lsusb | grep -E "0483:|cafe:" >&2 || echo "    (no TS1302-related VID seen)" >&2
            exit 1
          fi

          echo "✓ Detected at $DETECTED_DEV"
          echo ""
          echo "Step 2/2: capture + validate boot output..."
          echo ""

          export TROPIC_DEV="$DETECTED_DEV"
          export TROPIC_VALIDATE_TIMEOUT=10
          exec ${../tools/validate-phase1.sh}
        '';
      };

  # Phase 2 — flash-and-validate-phase2: DFU flash + lt-util chip-info check.
  # Single-shot regression test for the open firmware: flashes Phase 2,
  # waits for /dev/ttyACM*, runs validate-phase2.sh which exercises the
  # full host→firmware→TROPIC01 path via lt-util.
  flash-and-validate-phase2 =
    if firmware == null || libtropicUtil == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase2-placeholder";
        text = ''
          echo "Custom firmware or lt-util not available in this flake."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase2";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep libtropicUtil ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 2: flash-and-validate (one-shot regression test)"
          echo "═══════════════════════════════════════════════════════════════"
          echo ""

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            echo "Hold SW1 + replug, then re-run." >&2
            exit 1
          fi

          echo "Step 1/2: DFU flash..."
          DFU_LOG=$(mktemp)
          trap 'rm -f "$DFU_LOG"' EXIT

          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"

          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."
            exit 1
          fi

          echo "✓ Flash complete. Waiting up to 12 s for USB re-enumeration..."

          DETECTED_DEV=""
          for _ in $(seq 1 24); do
            sleep 0.5
            for candidate in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyACM2 /dev/ttyACM3; do
              if [ -e "$candidate" ]; then
                DETECTED_DEV="$candidate"
                break 2
              fi
            done
          done

          if [ -z "$DETECTED_DEV" ]; then
            echo "✗ No /dev/ttyACM* appeared after 12 s." >&2
            lsusb | grep -E "0483:|cafe:" >&2 || echo "    (no TS1302 VID seen)" >&2
            exit 1
          fi

          echo "✓ Detected at $DETECTED_DEV"
          echo ""
          echo "Step 2/2: lt-util chip-info validation..."
          echo ""

          export TROPIC_DEV="$DETECTED_DEV"
          export TROPIC_VALIDATE_TIMEOUT=15
          exec ${../tools/validate-phase2.sh}
        '';
      };

  check-dongle = writeShellApplication {
    name = "nixtropic-check-dongle";
    runtimeInputs = [ usbutils ];
    text = ''
      set -euo pipefail

      echo "═══════════════════════════════════════════════════════════════"
      echo "  TS1302 dongle diagnostic"
      echo "═══════════════════════════════════════════════════════════════"
      echo ""

      echo "─── lsusb output (filtered to STM 0483: VID) ───────────────────"
      if lsusb | grep -E "ID 0483:" || true; then
        echo ""
      fi

      if lsusb | grep -q "0483:5740"; then
        echo "✓ Dongle present in APP MODE (0483:5740 — TropicSquare SPI iface)"
        DEV="/dev/ttyACM0"
        if [ -e "$DEV" ]; then
          echo "  Device node: $DEV exists"
          if [ -r "$DEV" ] && [ -w "$DEV" ]; then
            echo "  Permissions: ✓ readable + writable"
          else
            echo "  Permissions: ✗ NOT readable/writable as current user"
            echo "  Fix: enable nixosModules.tropic on this host OR add yourself to dialout"
          fi
        else
          echo "  ✗ $DEV does not exist (try /dev/ttyACM1, /dev/ttyACM2)"
        fi
      elif lsusb | grep -q "0483:df11"; then
        echo "⚠ Dongle present in DFU MODE (0483:df11)"
        echo "  Run: nix run .#flash-stock  to recover to app mode"
      else
        echo "✗ Dongle not detected. Check USB cable / port."
      fi
      echo ""
    '';
  };

in
{
  flash-stock = {
    type = "app";
    program = "${flash-stock}/bin/nixtropic-flash-stock";
    meta.description = "DFU-flash the stock TS1302 firmware (recovery)";
  };

  flash-open = {
    type = "app";
    program =
      if firmware == null then
        "${flash-firmware}/bin/nixtropic-flash-firmware-placeholder"
      else
        "${flash-firmware}/bin/nixtropic-flash-firmware";
    meta.description = "DFU-flash nixtropic open firmware (Phase 2)";
  };

  read = {
    type = "app";
    program = "${read}/bin/nixtropic-read";
    meta.description = "Open USB CDC console (/dev/ttyACM*) via screen";
  };

  validate-phase1 = {
    type = "app";
    program = "${validate-phase1}/bin/nixtropic-validate-phase1";
    meta.description = "Automated Phase 1 PASS check (chip ID + L2 sweep) — run RIGHT AFTER flash";
  };

  validate-phase2 = {
    type = "app";
    program =
      if libtropicUtil == null then
        "${validate-phase2}/bin/nixtropic-validate-phase2-placeholder"
      else
        "${validate-phase2}/bin/nixtropic-validate-phase2";
    meta.description = "Automated Phase 2 PASS check via lt-util chip-info";
  };

  flash-and-validate-phase1 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate}/bin/nixtropic-flash-and-validate-placeholder"
      else
        "${flash-and-validate}/bin/nixtropic-flash-and-validate";
    meta.description = "DFU-flash open firmware + Phase 1 validate (chip_id + L2 sweep)";
  };

  flash-and-validate-phase2 = {
    type = "app";
    program =
      if firmware == null || libtropicUtil == null then
        "${flash-and-validate-phase2}/bin/nixtropic-flash-and-validate-phase2-placeholder"
      else
        "${flash-and-validate-phase2}/bin/nixtropic-flash-and-validate-phase2";
    meta.description = "DFU-flash open firmware + immediately validate via lt-util";
  };

  identify = {
    type = "app";
    program =
      if libtropicUtil == null then
        "${identify}/bin/nixtropic-identify-placeholder"
      else
        "${identify}/bin/nixtropic-identify";
    meta.description = "Read TROPIC01 chip info via lt-util";
  };

  check-dongle = {
    type = "app";
    program = "${check-dongle}/bin/nixtropic-check-dongle";
    meta.description = "Diagnose TS1302 USB enumeration and permissions";
  };
}
