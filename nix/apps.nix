{ pkgs, stockFirmware, openFirmware ? null, libtropicUtil ? null, fwUpdateChip ? null }:

# Backwards-compat alias used by internal references.
let firmware = openFirmware; in

# Flake apps for `nix run .#<app>`.
#
# All apps in this file are thin wrappers around `dfu-util`, `lt-util`,
# `opensc-tool`, `fido2-token`, and the validate scripts under tools/.
# Apps that flash the dongle (flash-stock, flash-open, flash-and-validate,
# fw-update-chip) only write to the STM32U535 (firmware app slot
# 0x08000000) — never directly to the TROPIC01 chip's R-config or other
# brick-vulnerable surfaces.

let
  inherit (pkgs) writeShellApplication dfu-util usbutils coreutils gnugrep;

  # ===== Flashing =====

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
        echo "  2. Hold the SW1 button DOWN"
        echo "  3. While holding SW1, plug the dongle in"
        echo "  4. Release SW1 after USB enumeration"
        echo "  5. Verify: lsusb | grep 0483:df11"
        echo ""
        echo "Then re-run this command."
        exit 1
      fi

      echo "✓ DFU mode detected"
      echo ""
      echo "Flashing... (writes to STM32U535 flash at 0x08000000; TROPIC01"
      echo "chip is NOT touched by this operation)"
      echo ""

      # dfu-util exits non-zero after a successful :leave because the
      # device disconnects from USB to jump to user firmware before
      # dfu-util can read the final get_status — known benign quirk on
      # every STM32 + dfu-util combo.  Detect via the "File downloaded
      # successfully" marker rather than exit code.
      DFU_LOG=$(mktemp)
      trap 'rm -f "$DFU_LOG"' EXIT

      dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" || true
      DFU_EXIT="''${PIPESTATUS[0]}"

      echo ""
      if [ "$DFU_EXIT" -eq 0 ]; then
        echo "✓ Flash complete (clean dfu-util exit)."
      elif grep -q "File downloaded successfully" "$DFU_LOG"; then
        echo "✓ Flash complete."
        echo "  ('Error during download get_status' after :leave is a benign"
        echo "  dfu-util quirk — flash itself succeeded.)"
      else
        echo "✗ Flash FAILED — dfu-util exit $DFU_EXIT and no"
        echo "  'File downloaded successfully' marker.  Dongle is likely"
        echo "  still in DFU mode; safe to retry.  See docs/RECOVERY.md."
        exit 1
      fi
    '';
  };

  flash-open =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-open-placeholder";
        text = ''echo "Custom firmware not built in this flake."; exit 1'';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-open";
        runtimeInputs = [ dfu-util usbutils ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Flashing nixtropic open firmware"
          echo "═══════════════════════════════════════════════════════════════"
          echo ""
          echo "Firmware: $FW_BIN"
          echo ""
          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: Dongle is NOT in DFU mode (USB ID 0483:df11)."
            echo "       Hold SW1 while plugging USB to enter DFU mode."
            exit 1
          fi
          echo "✓ DFU mode detected; flashing..."
          echo ""

          DFU_LOG=$(mktemp)
          trap 'rm -f "$DFU_LOG"' EXIT
          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" || true
          DFU_EXIT="''${PIPESTATUS[0]}"

          echo ""
          if [ "$DFU_EXIT" -eq 0 ] || grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✓ Flash complete."
            echo "  Run \`nix run .#validate\` to confirm both surfaces work."
          else
            echo "✗ Flash FAILED.  Safe to retry.  Fall back to flash-stock"
            echo "  for known-good recovery (see docs/RECOVERY.md)."
            exit 1
          fi
        '';
      };

  # ===== Diagnostic + identity =====

  identify =
    if libtropicUtil == null then
      writeShellApplication {
        name = "nixtropic-identify-placeholder";
        text = ''echo "lt-util not built in this flake."; exit 1'';
      }
    else
      writeShellApplication {
        name = "nixtropic-identify";
        runtimeInputs = [ libtropicUtil usbutils ];
        text = ''
          set -euo pipefail

          echo "Checking for TS1302 in app mode..."
          echo "  Acceptable VID/PID: 0483:5740 (stock) OR cafe:4001 (open)"
          if ! lsusb | grep -qE "0483:5740|cafe:4001"; then
            echo ""
            echo "ERROR: Dongle is not in app mode."
            if lsusb | grep -q "0483:df11"; then
              echo "Dongle is in DFU mode — flash firmware first:"
              echo "  sudo nix run .#flash-stock           # restore stock"
              echo "  sudo nix run .#flash-open            # load nixtropic open"
            fi
            exit 1
          fi

          DEV="''${TROPIC_DEV:-/dev/ttyACM0}"
          if lsusb | grep -q "cafe:4001"; then
            echo "✓ App mode — nixtropic open firmware (cafe:4001)"
          else
            echo "✓ App mode — stock firmware (0483:5740)"
          fi
          echo ""
          echo "Querying chip on $DEV..."
          echo ""

          # NB: lt-util's CDC chip-info path works only against stock
          # firmware (which exposes a CDC SPI passthrough).  Our open
          # firmware exposes the chip via the lt-rpc HID interface
          # instead — see tools/lt_rpc.py for that path.
          lt-util "$DEV" -i || {
            echo ""
            echo "ERROR: lt-util failed.  Possible causes:"
            echo "  - Permission denied: install nixosModules.tropic OR"
            echo "    add yourself to the dialout group OR run with sudo"
            echo "  - Wrong device: try TROPIC_DEV=/dev/ttyACM1 nix run .#identify"
            echo "  - Open firmware doesn't expose CDC chip-info — that's"
            echo "    by design (composite device with FIDO + OpenPGP instead)"
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

      echo "─── USB enumeration ────────────────────────────────────────────"
      lsusb | grep -E "ID (0483:|cafe:4001)" || echo "  (no TS1302-related VID seen)"
      echo ""

      if lsusb | grep -q "cafe:4001"; then
        echo "✓ Dongle in APP MODE — nixtropic open firmware (cafe:4001)"
        echo "  Composite device: CDC + HID×2 (lt-rpc + FIDO) + CCID"
        echo "  Run: nix run .#validate    # full FIDO + OpenPGP sanity"
      elif lsusb | grep -q "0483:5740"; then
        echo "✓ Dongle in APP MODE — stock firmware (0483:5740)"
        echo "  USB CDC SPI passthrough"
        echo "  Run: nix run .#identify    # lt-util chip info"
      elif lsusb | grep -q "0483:df11"; then
        echo "⚠ Dongle in DFU MODE (0483:df11)"
        echo "  Ready for re-flash via:"
        echo "    nix run .#flash-stock    # recover to stock"
        echo "    nix run .#flash-open     # install nixtropic open"
      else
        echo "✗ Dongle not detected.  Check USB cable / port."
      fi
      echo ""
    '';
  };

  # ===== Validation suites =====

  validate-fido = writeShellApplication {
    name = "nixtropic-validate-fido";
    runtimeInputs = [ usbutils coreutils gnugrep pkgs.libfido2 ];
    text = ''
      set -uo pipefail
      exec ${../tools/validate-fido.sh} "$@"
    '';
  };

  validate-openpgp = writeShellApplication {
    name = "nixtropic-validate-openpgp";
    runtimeInputs = [ usbutils coreutils gnugrep pkgs.opensc pkgs.pcsc-tools pkgs.pcsclite pkgs.gnupg ];
    text = ''
      set -uo pipefail
      exec ${../tools/validate-openpgp.sh} "$@"
    '';
  };

  validate = writeShellApplication {
    name = "nixtropic-validate";
    runtimeInputs = [
      usbutils coreutils gnugrep
      pkgs.libfido2
      pkgs.opensc pkgs.pcsc-tools pkgs.pcsclite pkgs.gnupg
    ];
    text = ''
      set -uo pipefail
      # validate.sh dispatches to validate-fido.sh + validate-openpgp.sh
      # via $SCRIPT_DIR; we re-execute the top-level wrapper directly so
      # the same env reaches both sub-suites.
      exec ${../tools/validate.sh} "$@"
    '';
  };

  flash-and-validate =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-placeholder";
        text = ''echo "Custom firmware not built in this flake."; exit 1'';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate";
        runtimeInputs = [
          dfu-util usbutils coreutils gnugrep
          pkgs.libfido2
          pkgs.opensc pkgs.pcsc-tools pkgs.pcsclite pkgs.gnupg
        ];
        text = ''
          set -euo pipefail
          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  nixtropic — flash open firmware + full validate"
          echo "═══════════════════════════════════════════════════════════════"

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            echo "       Hold SW1 while plugging USB to enter DFU." >&2
            exit 1
          fi

          DFU_LOG=$(mktemp)
          trap 'rm -f "$DFU_LOG"' EXIT
          echo "Step 1/2: DFU flash..."
          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"
          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."
            exit 1
          fi

          echo "✓ Flash complete.  Waiting for enumeration..."
          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then break; fi
          done
          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ Enumeration failed." >&2
            exit 1
          fi
          echo "✓ Enumerated.  Settling 3 s..."
          sleep 3

          sudo systemctl restart pcscd 2>/dev/null || true
          sleep 2

          echo ""
          echo "Step 2/2: full validation (FIDO + OpenPGP)..."
          exec ${../tools/validate.sh}
        '';
      };

  # ===== Maintenance / quality =====

  lint = writeShellApplication {
    name = "nixtropic-lint";
    runtimeInputs = [ pkgs.cppcheck coreutils ];
    text = ''
      set -uo pipefail
      FIRMWARE_SRC="$PWD/firmware/src"
      if [ ! -d "$FIRMWARE_SRC" ]; then
        echo "ERROR: run from the nixtropic repo root (firmware/src not found)." >&2
        exit 2
      fi

      echo "═══════════════════════════════════════════════════════════════"
      echo "  cppcheck — static analysis of nixtropic firmware source"
      echo "═══════════════════════════════════════════════════════════════"
      echo ""
      echo "Scope: hid_rpc/, fido_hid/, ccid/, openpgp/, tropic/, cdc_protocol/,"
      echo "       usb glue, platform/ wrappers, main.c."
      echo "Vendor code (libtropic, trezor_crypto, TinyUSB, HAL, CMSIS) excluded."
      echo ""

      cppcheck \
        --enable=warning,style,performance,portability \
        --check-level=exhaustive \
        --std=c11 \
        --platform=unix32 \
        --inline-suppr \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=unmatchedSuppression \
        --suppress=checkersReport \
        --error-exitcode=1 \
        -I "$FIRMWARE_SRC" \
        -I "$FIRMWARE_SRC/platform" \
        -I "$FIRMWARE_SRC/usb" \
        "$FIRMWARE_SRC/hid_rpc/" \
        "$FIRMWARE_SRC/fido_hid/" \
        "$FIRMWARE_SRC/ccid/" \
        "$FIRMWARE_SRC/openpgp/" \
        "$FIRMWARE_SRC/tropic/" \
        "$FIRMWARE_SRC/cdc_protocol/" \
        "$FIRMWARE_SRC/usb/usb_descriptors.c" \
        "$FIRMWARE_SRC/usb/usb.c" \
        "$FIRMWARE_SRC/usb/cdc_io.c" \
        "$FIRMWARE_SRC/usb/usb_ccid.c" \
        "$FIRMWARE_SRC/platform/spi.c" \
        "$FIRMWARE_SRC/platform/clock.c" \
        "$FIRMWARE_SRC/platform/gpio.c" \
        "$FIRMWARE_SRC/platform/blink.c" \
        "$FIRMWARE_SRC/platform/led.c" \
        "$FIRMWARE_SRC/platform/rng.c" \
        "$FIRMWARE_SRC/main.c" \
        2>&1
      rc=$?
      echo ""
      if [ $rc -eq 0 ]; then
        echo "✓ cppcheck clean — no warnings or errors"
      else
        echo "⚠ cppcheck found issues (exit $rc).  Review above."
      fi
      exit $rc
    '';
  };

in
{
  # ===== Flashing =====

  flash-stock = {
    type = "app";
    program = "${flash-stock}/bin/nixtropic-flash-stock";
    meta.description = "DFU-flash the stock TS1302 firmware (recovery)";
  };

  flash-open = {
    type = "app";
    program =
      if firmware == null then
        "${flash-open}/bin/nixtropic-flash-open-placeholder"
      else
        "${flash-open}/bin/nixtropic-flash-open";
    meta.description = "DFU-flash the nixtropic open firmware";
  };

  flash-and-validate = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate}/bin/nixtropic-flash-and-validate-placeholder"
      else
        "${flash-and-validate}/bin/nixtropic-flash-and-validate";
    meta.description = "DFU-flash open firmware + run full FIDO + OpenPGP validation";
  };

  # ===== Validation =====

  validate = {
    type = "app";
    program = "${validate}/bin/nixtropic-validate";
    meta.description = "Run the full FIDO + OpenPGP card validation suite";
  };

  validate-fido = {
    type = "app";
    program = "${validate-fido}/bin/nixtropic-validate-fido";
    meta.description = "FIDO2 surface validation (5 non-interactive checks)";
  };

  validate-openpgp = {
    type = "app";
    program = "${validate-openpgp}/bin/nixtropic-validate-openpgp";
    meta.description = "OpenPGP card surface validation (17 APDU checks)";
  };

  # ===== Diagnostic / identity =====

  identify = {
    type = "app";
    program =
      if libtropicUtil == null then
        "${identify}/bin/nixtropic-identify-placeholder"
      else
        "${identify}/bin/nixtropic-identify";
    meta.description = "Read TROPIC01 chip info via lt-util (against stock firmware)";
  };

  check-dongle = {
    type = "app";
    program = "${check-dongle}/bin/nixtropic-check-dongle";
    meta.description = "Diagnose TS1302 USB enumeration + permissions";
  };

  # ===== TROPIC01 chip-firmware updater =====
  # Auto-picks the first /dev/ttyACM* unless the user passes one explicitly.

  fw-update-chip = {
    type = "app";
    program =
      let wrapper = pkgs.writeShellApplication {
        name = "nixtropic-fw-update-chip";
        runtimeInputs = [ pkgs.coreutils ] ++ pkgs.lib.optionals (fwUpdateChip != null) [ fwUpdateChip ];
        text =
          if fwUpdateChip == null then
            ''echo "fw-update-chip not built in this flake."; exit 1''
          else ''
            set -euo pipefail
            DEV="''${1:-}"
            if [ -z "$DEV" ]; then
              # Auto-detect: lowest-numbered /dev/ttyACM*.
              DEV="$(find /dev -maxdepth 1 -name 'ttyACM*' 2>/dev/null | sort | head -n1)"
            fi
            if [ -z "$DEV" ] || [ ! -e "$DEV" ]; then
              echo "ERROR: no /dev/ttyACM* found.  Plug in the dongle first." >&2
              exit 1
            fi
            echo "Using device: $DEV"
            echo ""
            echo "⚠ Chip rejects FW downgrade after success — the upgrade is one-way."
            echo "⚠ Brick risk is low (chip Maintenance Mode is recoverable), but:"
            echo "   1. Make sure the dongle is on a stable USB port."
            echo "   2. Don't unplug it during the update."
            echo "   3. After success, our open-firmware should still work."
            echo ""
            exec ${fwUpdateChip}/bin/fw-update-chip "$DEV"
          '';
      };
      in "${wrapper}/bin/nixtropic-fw-update-chip";
    meta.description = "Update TROPIC01 chip firmware (CPU + SPECT) to App FW 2.0.0";
  };

  # ===== Maintenance =====

  lint = {
    type = "app";
    program = "${lint}/bin/nixtropic-lint";
    meta.description = "cppcheck static analysis over original firmware source";
  };
}
