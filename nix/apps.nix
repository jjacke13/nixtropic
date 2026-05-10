{ pkgs, stockFirmware, libtropicUtil ? null }:

# Flake apps for `nix run .#<app>`.
#
# Phase 0 set:
#   flash-stock  — DFU-flashes the stock firmware to the dongle. Requires the
#                  dongle to be in DFU mode (hold SW1/BOOT0 at power-on).
#                  See docs/RECOVERY.md for the physical procedure.
#   identify     — Runs lt-util chip-info command. Requires the dongle to be
#                  in normal app mode (stock or custom firmware running).
#   check-dongle — Diagnostic: lsusb + udev permission check.
#
# These apps are deliberately thin wrappers around dfu-util + lt-util. They
# do not do anything destructive without user input — except flash-stock,
# which the user must explicitly invoke and which only writes to the
# STM32U535's flash (not the TROPIC01 chip — chip is unaffected).

let
  inherit (pkgs) writeShellApplication dfu-util usbutils;

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

          echo "Checking for TS1302 in app mode (USB ID 0483:5740)..."
          if ! lsusb | grep -q "0483:5740"; then
            echo ""
            echo "ERROR: Dongle is not in app mode."
            echo ""
            if lsusb | grep -q "0483:df11"; then
              echo "Dongle is in DFU mode — flash firmware first:"
              echo "  nix run .#flash-stock"
            else
              echo "Dongle not detected. Check the USB cable and lsusb output."
            fi
            exit 1
          fi

          DEV="''${TROPIC_DEV:-/dev/ttyACM0}"
          echo "✓ App mode detected"
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
