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

  # Python with hidapi + cryptography for Phase 3 HID lt-rpc client.
  py = pkgs.python3.withPackages (p: [ p.hid p.cryptography ]);

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

  # Phase 3 — validate-phase3: runs lt-rpc-over-HID test suite (PING, RANDOM,
  # CHIP_ID, ECC sign+verify) against the currently-running firmware.
  # validate-phase3.sh is a thin wrapper that calls lt_rpc.py.
  validate-phase3 = writeShellApplication {
    name = "nixtropic-validate-phase3";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      # Both scripts are copied into the Nix store individually; pass the
      # python client's path explicitly so the shell wrapper can find it.
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      exec ${../tools/validate-phase3.sh} "$@"
    '';
  };

  # Phase 4 — validate-phase4: runs CTAPHID + CTAP2 test suite (INIT, PING,
  # MSG, GetInfo, MakeCredential, GetAssertion) with host-side Ed25519
  # signature verification. Same Nix-store path indirection as phase 3.
  validate-phase4 = writeShellApplication {
    name = "nixtropic-validate-phase4";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export FIDO2_PY="${../tools/fido2_test.py}"
      exec ${../tools/validate-phase4.sh} "$@"
    '';
  };

  # Phase 5 M1 — validate-phase5-m1: exercises the TROPIC01-backed slot
  # manager (slots.{h,c}) end-to-end via the LT_RPC_CMD_SLOTS_* debug
  # commands. This is the HW-in-the-loop checkpoint between M1 and M2
  # per docs/PHASE-5-PLAN.md §5.
  validate-phase5-m1 = writeShellApplication {
    name = "nixtropic-validate-phase5-m1";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      exec ${../tools/validate-phase5-m1.sh} "$@"
    '';
  };

  # Phase 5 M2 — validate-phase5-m2 (THE MIC-DROP): real TROPIC01-backed
  # FIDO2 keys. Resets slot bitmap, runs MakeCred×3 on distinct rpIds,
  # GetAssertion×3 against each, monotonic counter check, forged-credId
  # negative test. Per docs/PHASE-5-PLAN.md §5 + §2 ("THE MIC-DROP").
  validate-phase5-m2 = writeShellApplication {
    name = "nixtropic-validate-phase5-m2";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      export FIDO2_PY="${../tools/fido2_test.py}"
      exec ${../tools/validate-phase5-m2.sh} "$@"
    '';
  };

  # Phase 5 M3 — ClientPIN v1 validation. Exercises CTAP2 §5.5.4
  # end-to-end (key agreement, setPin, getPinToken, changePin, retry
  # counter, PIN-gated MakeCred/GetAssertion with UV bit verification).
  validate-phase5-m3 = writeShellApplication {
    name = "nixtropic-validate-phase5-m3";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      export FIDO2_PY="${../tools/fido2_test.py}"
      exec ${../tools/validate-phase5-m3.sh} "$@"
    '';
  };

  # Phase 5 M4 — MAC-and-Destroy-backed PIN retry counter. M4 is
  # internal hardening (TROPIC01 hardware enforces 8-attempt limit
  # via M&D slot consumption). CTAP2 surface unchanged; validate-m4
  # runs validate-m3 as regression + stress-tests re-setPin.
  validate-phase5-m4 = writeShellApplication {
    name = "nixtropic-validate-phase5-m4";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      export FIDO2_PY="${../tools/fido2_test.py}"
      exec ${../tools/validate-phase5-m4.sh} "$@"
    '';
  };

  # Phase 5 FULL — M2 + M3 + M5 (Reset) end-to-end. M5 has the 10 s
  # post-boot window for authenticatorReset, so flash-and-validate
  # is the most reliable invocation (flash immediately → tests within
  # window).
  validate-phase5 = writeShellApplication {
    name = "nixtropic-validate-phase5";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      export FIDO2_PY="${../tools/fido2_test.py}"
      exec ${../tools/validate-phase5.sh} "$@"
    '';
  };

  # Phase 6 M1 — SW1 user-presence button + LED state machine.
  # Interactive: tester presses SW1 on cue (test 2), then ignores
  # the prompt for the full 30 s timeout (test 3).  Pre-step wipes
  # leftover Phase 5 PIN/credstore state via lt-rpc slots-reset.
  # See docs/PHASE-6-PLAN.md §5 M1 HW checkpoint.
  validate-phase6-m1 = writeShellApplication {
    name = "nixtropic-validate-phase6-m1";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export FIDO2_PY="${../tools/fido2_test.py}"
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      exec ${../tools/validate-phase6-m1.sh} "$@"
    '';
  };

  # Phase 6 M2 — Force-UV vendor command + alwaysUv GetInfo option.
  # 10 automated tests covering auto-enable on first setPIN, PIN-gated
  # toggle, GetInfo reflection.  Non-interactive but requires sudo
  # (lt-rpc HID is root-only).  See docs/PHASE-6-PLAN.md §5 M2 HW checkpoint.
  validate-phase6-m2 = writeShellApplication {
    name = "nixtropic-validate-phase6-m2";
    runtimeInputs = [ py usbutils coreutils gnugrep ];
    text = ''
      set -uo pipefail
      export FIDO2_PY="${../tools/fido2_test.py}"
      export LT_RPC_PY="${../tools/lt_rpc.py}"
      exec ${../tools/validate-phase6-m2.sh} "$@"
    '';
  };

  # Phase 6 M2 — direct vendor commands for the Force-UV flag.
  # `force-uv-get` reads (unauthenticated).
  # `force-uv-set <0|1>` writes (requires active PIN session on device).
  force-uv-get = writeShellApplication {
    name = "nixtropic-force-uv-get";
    runtimeInputs = [ py usbutils coreutils ];
    text = ''
      set -uo pipefail
      exec ${py}/bin/python3 ${../tools/lt_rpc.py} force-uv-get "$@"
    '';
  };

  force-uv-set = writeShellApplication {
    name = "nixtropic-force-uv-set";
    runtimeInputs = [ py usbutils coreutils ];
    text = ''
      set -uo pipefail
      exec ${py}/bin/python3 ${../tools/lt_rpc.py} force-uv-set "$@"
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
          # Post-detection settle delay. /dev/ttyACMN can appear before the
          # kernel finishes cdc_acm probe, before TinyUSB completes SET_CONFIG,
          # AND before TROPIC01's filter cap fully discharges from its DFU-mode
          # power state — our firmware's 20ms power-off may not be enough on
          # top of a hot DFU :leave transition. The split test (flash-open
          # then manual replug + validate-phase2) hides this gap because the
          # user's USB unplug fully discharges everything. Give 3 s here so
          # the one-shot mirrors that.
          echo "Settling for 3 s..."
          sleep 3
          echo ""
          echo "Step 2/2: lt-util chip-info validation..."
          echo ""

          export TROPIC_DEV="$DETECTED_DEV"
          export TROPIC_VALIDATE_TIMEOUT=15
          exec ${../tools/validate-phase2.sh}
        '';
      };

  # Phase 3 — flash-and-validate-phase3: DFU flash + immediate Phase 3 validate.
  # Same shape as flash-and-validate-phase2; the validation step exercises the
  # HID lt-rpc transport rather than the CDC ASCII protocol.
  flash-and-validate-phase3 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase3-placeholder";
        text = ''
          echo "Custom firmware not available in this flake."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase3";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 3: flash-and-validate (one-shot regression test)"
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

          # Phase 3 device exposes /dev/hidraw* (interface 2). Wait for both
          # the CDC node (/dev/ttyACM*) and the HID node — the latter takes
          # slightly longer to appear because cdc_acm probes first.
          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then
              break
            fi
          done

          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ nixtropic open firmware (cafe:4001) not enumerated after 12 s." >&2
            lsusb | grep -E "0483:|cafe:" >&2 || echo "    (no TS1302 VID seen)" >&2
            exit 1
          fi

          echo "✓ nixtropic firmware enumerated."
          echo ""
          # Same 3 s settle as flash-and-validate-phase2 — gives the L3
          # session setup time to complete before host-side queries hit it.
          echo "Settling for 3 s..."
          sleep 3
          echo ""
          echo "Step 2/2: HID lt-rpc validation..."
          echo ""
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          exec ${../tools/validate-phase3.sh}
        '';
      };

  # Phase 5 FULL — flash-and-validate-phase5: DFU flash + full suite.
  # Critical: runs validate-phase5 immediately after flash so the
  # authenticatorReset 10s post-boot window is open.
  flash-and-validate-phase5 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-placeholder";
        text = ''echo "Custom firmware not available in this flake."; exit 1'';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail
          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 5 FULL: flash-and-validate"
          echo "═══════════════════════════════════════════════════════════════"

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            exit 1
          fi

          DFU_LOG=$(mktemp); trap 'rm -f "$DFU_LOG"' EXIT
          echo "Step 1/2: DFU flash..."
          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"
          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."; exit 1
          fi

          echo "✓ Flash complete. Waiting..."
          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then break; fi
          done
          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ Enumeration failed." >&2; exit 1
          fi
          echo "✓ Enumerated. Settling 2 s (keeping within 10 s Reset window)..."
          sleep 2

          echo ""
          echo "Step 2/2: Phase 5 full suite..."
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          export FIDO2_PY="${../tools/fido2_test.py}"
          exec ${../tools/validate-phase5.sh}
        '';
      };

  # Phase 6 M2 — flash-and-validate-phase6-m2: DFU flash + M2 auto-test.
  # Fast (~10 s incl. flash + enum).  No timing pressure.
  flash-and-validate-phase6-m2 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase6-m2-placeholder";
        text = ''echo "Custom firmware not available in this flake."; exit 1'';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase6-m2";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail
          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 6 M2: flash-and-validate (Force-UV + alwaysUv)"
          echo "═══════════════════════════════════════════════════════════════"

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            echo "       Hold SW1 while plugging USB to enter DFU." >&2
            exit 1
          fi

          DFU_LOG=$(mktemp); trap 'rm -f "$DFU_LOG"' EXIT
          echo "Step 1/2: DFU flash..."
          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"
          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."; exit 1
          fi

          echo "✓ Flash complete. Waiting for enumeration..."
          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then break; fi
          done
          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ Enumeration failed." >&2; exit 1
          fi
          echo "✓ Enumerated. Settling 3 s..."
          sleep 3

          echo ""
          echo "Step 2/2: M2 validation..."
          export FIDO2_PY="${../tools/fido2_test.py}"
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          exec ${../tools/validate-phase6-m2.sh}
        '';
      };

  # Phase 6 M1 — flash-and-validate-phase6-m1: DFU flash + interactive
  # SW1 + LED validation.  No timing pressure (no 10 s window like
  # Reset has) so the tester can take their time pressing / not-pressing.
  flash-and-validate-phase6-m1 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase6-m1-placeholder";
        text = ''echo "Custom firmware not available in this flake."; exit 1'';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase6-m1";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail
          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 6 M1: flash-and-validate (SW1 + LED, interactive)"
          echo "═══════════════════════════════════════════════════════════════"

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            echo "       Hold SW1 while plugging USB to enter DFU." >&2
            exit 1
          fi

          DFU_LOG=$(mktemp); trap 'rm -f "$DFU_LOG"' EXIT
          echo "Step 1/2: DFU flash..."
          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"
          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."; exit 1
          fi

          echo "✓ Flash complete. Waiting for enumeration..."
          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then break; fi
          done
          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ Enumeration failed." >&2; exit 1
          fi
          echo "✓ Enumerated. Settling 3 s..."
          sleep 3

          echo ""
          echo "Step 2/2: M1 validation (interactive)..."
          export FIDO2_PY="${../tools/fido2_test.py}"
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          exec ${../tools/validate-phase6-m1.sh}
        '';
      };

  # Phase 5 M4 — flash-and-validate-phase5-m4: DFU flash + M4 regression suite.
  flash-and-validate-phase5-m4 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m4-placeholder";
        text = ''echo "Custom firmware not available in this flake."; exit 1'';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m4";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail
          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 5 M4: flash-and-validate (M&D retry counter)"
          echo "═══════════════════════════════════════════════════════════════"

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            exit 1
          fi

          DFU_LOG=$(mktemp); trap 'rm -f "$DFU_LOG"' EXIT
          echo "Step 1/2: DFU flash..."
          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"
          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."; exit 1
          fi

          echo "✓ Flash complete. Waiting..."
          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then break; fi
          done
          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ Enumeration failed." >&2; exit 1
          fi
          echo "✓ Enumerated. Settling 3 s..."
          sleep 3

          echo ""
          echo "Step 2/2: M4 regression suite..."
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          export FIDO2_PY="${../tools/fido2_test.py}"
          exec ${../tools/validate-phase5-m4.sh}
        '';
      };

  # Phase 5 M3 — flash-and-validate-phase5-m3: DFU flash + M3 ClientPIN suite.
  flash-and-validate-phase5-m3 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m3-placeholder";
        text = ''
          echo "Custom firmware not available in this flake."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m3";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail
          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 5 M3: flash-and-validate (ClientPIN)"
          echo "═══════════════════════════════════════════════════════════════"

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            echo "Hold SW1 + replug, then re-run." >&2
            exit 1
          fi

          echo "Step 1/2: DFU flash..."
          DFU_LOG=$(mktemp); trap 'rm -f "$DFU_LOG"' EXIT
          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"
          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."; exit 1
          fi

          echo "✓ Flash complete. Waiting up to 12 s..."
          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then break; fi
          done
          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ nixtropic firmware (cafe:4001) not enumerated." >&2
            exit 1
          fi
          echo "✓ Enumerated. Settling 3 s..."
          sleep 3

          echo ""
          echo "Step 2/2: ClientPIN suite..."
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          export FIDO2_PY="${../tools/fido2_test.py}"
          exec ${../tools/validate-phase5-m3.sh}
        '';
      };

  # Phase 5 M2 — flash-and-validate-phase5-m2: DFU flash + M2 mic-drop.
  flash-and-validate-phase5-m2 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m2-placeholder";
        text = ''
          echo "Custom firmware not available in this flake."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m2";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 5 M2: flash-and-validate (THE MIC-DROP)"
          echo "═══════════════════════════════════════════════════════════════"
          echo ""

          if ! lsusb | grep -q "0483:df11"; then
            echo "ERROR: dongle not in DFU mode (0483:df11)." >&2
            echo "Hold SW1 + replug, then re-run." >&2
            exit 1
          fi

          echo "Step 1/3: DFU flash..."
          DFU_LOG=$(mktemp)
          trap 'rm -f "$DFU_LOG"' EXIT

          dfu-util -a 0 -s 0x08000000:leave -D "$FW_BIN" 2>&1 | tee "$DFU_LOG" >/dev/null || true
          DFU_EXIT="''${PIPESTATUS[0]}"

          if [ "$DFU_EXIT" -ne 0 ] && ! grep -q "File downloaded successfully" "$DFU_LOG"; then
            echo "✗ DFU flash FAILED."
            exit 1
          fi

          echo "✓ Flash complete. Waiting up to 12 s for USB re-enumeration..."

          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then
              break
            fi
          done

          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ nixtropic open firmware (cafe:4001) not enumerated after 12 s." >&2
            lsusb | grep -E "0483:|cafe:" >&2 || echo "    (no TS1302 VID seen)" >&2
            exit 1
          fi

          echo "✓ nixtropic firmware enumerated."
          echo ""
          echo "Settling for 3 s..."
          sleep 3
          echo ""
          echo "Steps 2-3/3: factory_reset + Phase 5 M2 FIDO2 mic-drop suite..."
          echo ""
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          export FIDO2_PY="${../tools/fido2_test.py}"
          exec ${../tools/validate-phase5-m2.sh}
        '';
      };

  # Phase 5 M1 — flash-and-validate-phase5-m1: DFU flash + immediate M1
  # checkpoint. Same shape as flash-and-validate-phase4.
  flash-and-validate-phase5-m1 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m1-placeholder";
        text = ''
          echo "Custom firmware not available in this flake."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase5-m1";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 5 M1: flash-and-validate (TROPIC01 slot manager)"
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

          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then
              break
            fi
          done

          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ nixtropic open firmware (cafe:4001) not enumerated after 12 s." >&2
            lsusb | grep -E "0483:|cafe:" >&2 || echo "    (no TS1302 VID seen)" >&2
            exit 1
          fi

          echo "✓ nixtropic firmware enumerated."
          echo ""
          echo "Settling for 3 s..."
          sleep 3
          echo ""
          echo "Step 2/2: Phase 5 M1 slot manager validation..."
          echo ""
          export LT_RPC_PY="${../tools/lt_rpc.py}"
          exec ${../tools/validate-phase5-m1.sh}
        '';
      };

  # Phase 4 — flash-and-validate-phase4: DFU flash + immediate Phase 4 validate.
  flash-and-validate-phase4 =
    if firmware == null then
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase4-placeholder";
        text = ''
          echo "Custom firmware not available in this flake."
          exit 1
        '';
      }
    else
      writeShellApplication {
        name = "nixtropic-flash-and-validate-phase4";
        runtimeInputs = [ dfu-util usbutils coreutils gnugrep py ];
        text = ''
          set -euo pipefail

          FW_BIN="${firmware}/firmware.bin"

          echo "═══════════════════════════════════════════════════════════════"
          echo "  Phase 4: flash-and-validate (one-shot regression test)"
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

          for _ in $(seq 1 24); do
            sleep 0.5
            if lsusb | grep -q "cafe:4001"; then
              break
            fi
          done

          if ! lsusb | grep -q "cafe:4001"; then
            echo "✗ nixtropic open firmware (cafe:4001) not enumerated after 12 s." >&2
            lsusb | grep -E "0483:|cafe:" >&2 || echo "    (no TS1302 VID seen)" >&2
            exit 1
          fi

          echo "✓ nixtropic firmware enumerated."
          echo ""
          echo "Settling for 3 s..."
          sleep 3
          echo ""
          echo "Step 2/2: CTAPHID + CTAP2 validation..."
          echo ""
          export FIDO2_PY="${../tools/fido2_test.py}"
          exec ${../tools/validate-phase4.sh}
        '';
      };

  # Lint: cppcheck pass over OUR original firmware code (hid_rpc/, tropic/,
  # cdc_protocol/, our usb/ glue, our platform/ wrappers). Vendor sources
  # (libtropic, trezor_crypto, TinyUSB, ST HAL, CMSIS) deliberately excluded —
  # they're already audited upstream and finding issues there is not our job.
  #
  # Exit code reflects findings: 0 = clean, non-zero = issues found.
  # Use as a checkpoint before committing security-relevant changes.
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
      echo "  cppcheck — static analysis of nixtropic original code"
      echo "═══════════════════════════════════════════════════════════════"
      echo ""
      echo "Scope: hid_rpc/, tropic/, cdc_protocol/, usb/ glue, platform/ wrappers."
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
        "$FIRMWARE_SRC/tropic/" \
        "$FIRMWARE_SRC/cdc_protocol/" \
        "$FIRMWARE_SRC/usb/usb_descriptors.c" \
        "$FIRMWARE_SRC/usb/usb.c" \
        "$FIRMWARE_SRC/usb/cdc_io.c" \
        "$FIRMWARE_SRC/platform/spi.c" \
        "$FIRMWARE_SRC/platform/clock.c" \
        "$FIRMWARE_SRC/platform/gpio.c" \
        "$FIRMWARE_SRC/platform/blink.c" \
        "$FIRMWARE_SRC/platform/rng.c" \
        "$FIRMWARE_SRC/main.c" \
        2>&1
      rc=$?
      echo ""
      if [ $rc -eq 0 ]; then
        echo "✓ cppcheck clean — no warnings or errors"
      else
        echo "⚠ cppcheck found issues (exit $rc). Review above."
      fi
      exit $rc
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

  validate-phase3 = {
    type = "app";
    program = "${validate-phase3}/bin/nixtropic-validate-phase3";
    meta.description = "Phase 3 lt-rpc-over-HID validation (PING + RANDOM + CHIP_ID + Ed25519 sign+verify)";
  };

  flash-and-validate-phase3 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase3}/bin/nixtropic-flash-and-validate-phase3-placeholder"
      else
        "${flash-and-validate-phase3}/bin/nixtropic-flash-and-validate-phase3";
    meta.description = "DFU-flash open firmware + immediately run Phase 3 HID validation";
  };

  validate-phase4 = {
    type = "app";
    program = "${validate-phase4}/bin/nixtropic-validate-phase4";
    meta.description = "Phase 4 CTAPHID + CTAP2 validation (INIT/PING/MSG/GetInfo/MakeCred/GetAssertion + Ed25519 verify)";
  };

  flash-and-validate-phase4 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase4}/bin/nixtropic-flash-and-validate-phase4-placeholder"
      else
        "${flash-and-validate-phase4}/bin/nixtropic-flash-and-validate-phase4";
    meta.description = "DFU-flash open firmware + immediately run Phase 4 FIDO2 stub validation";
  };

  validate-phase5-m1 = {
    type = "app";
    program = "${validate-phase5-m1}/bin/nixtropic-validate-phase5-m1";
    meta.description = "Phase 5 M1 — TROPIC01 slot manager validation (alloc/erase/meta round-trip)";
  };

  flash-and-validate-phase5-m1 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase5-m1}/bin/nixtropic-flash-and-validate-phase5-m1-placeholder"
      else
        "${flash-and-validate-phase5-m1}/bin/nixtropic-flash-and-validate-phase5-m1";
    meta.description = "DFU-flash open firmware + Phase 5 M1 slot manager validation";
  };

  validate-phase5-m2 = {
    type = "app";
    program = "${validate-phase5-m2}/bin/nixtropic-validate-phase5-m2";
    meta.description = "Phase 5 M2 — TROPIC01-backed FIDO2 multi-credential validation (THE MIC-DROP)";
  };

  flash-and-validate-phase5-m2 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase5-m2}/bin/nixtropic-flash-and-validate-phase5-m2-placeholder"
      else
        "${flash-and-validate-phase5-m2}/bin/nixtropic-flash-and-validate-phase5-m2";
    meta.description = "DFU-flash open firmware + Phase 5 M2 FIDO2 mic-drop validation";
  };

  validate-phase5-m3 = {
    type = "app";
    program = "${validate-phase5-m3}/bin/nixtropic-validate-phase5-m3";
    meta.description = "Phase 5 M3 — ClientPIN protocol v1 validation (13-test suite)";
  };

  flash-and-validate-phase5-m3 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase5-m3}/bin/nixtropic-flash-and-validate-phase5-m3-placeholder"
      else
        "${flash-and-validate-phase5-m3}/bin/nixtropic-flash-and-validate-phase5-m3";
    meta.description = "DFU-flash open firmware + Phase 5 M3 ClientPIN validation";
  };

  validate-phase5-m4 = {
    type = "app";
    program = "${validate-phase5-m4}/bin/nixtropic-validate-phase5-m4";
    meta.description = "Phase 5 M4 — MAC-and-Destroy PIN retry counter regression";
  };

  flash-and-validate-phase5-m4 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase5-m4}/bin/nixtropic-flash-and-validate-phase5-m4-placeholder"
      else
        "${flash-and-validate-phase5-m4}/bin/nixtropic-flash-and-validate-phase5-m4";
    meta.description = "DFU-flash open firmware + Phase 5 M4 regression validation";
  };

  validate-phase5 = {
    type = "app";
    program = "${validate-phase5}/bin/nixtropic-validate-phase5";
    meta.description = "Phase 5 FULL — M2 + M3 + M5 (Reset) end-to-end";
  };

  flash-and-validate-phase5 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase5}/bin/nixtropic-flash-and-validate-phase5-placeholder"
      else
        "${flash-and-validate-phase5}/bin/nixtropic-flash-and-validate-phase5";
    meta.description = "DFU-flash open firmware + Phase 5 FULL validation";
  };

  validate-phase6-m1 = {
    type = "app";
    program = "${validate-phase6-m1}/bin/nixtropic-validate-phase6-m1";
    meta.description = "Phase 6 M1 — SW1 user-presence + LED (interactive)";
  };

  flash-and-validate-phase6-m1 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase6-m1}/bin/nixtropic-flash-and-validate-phase6-m1-placeholder"
      else
        "${flash-and-validate-phase6-m1}/bin/nixtropic-flash-and-validate-phase6-m1";
    meta.description = "DFU-flash open firmware + Phase 6 M1 SW1/LED validation";
  };

  validate-phase6-m2 = {
    type = "app";
    program = "${validate-phase6-m2}/bin/nixtropic-validate-phase6-m2";
    meta.description = "Phase 6 M2 — Force-UV + alwaysUv + auto-enable (10 tests)";
  };

  flash-and-validate-phase6-m2 = {
    type = "app";
    program =
      if firmware == null then
        "${flash-and-validate-phase6-m2}/bin/nixtropic-flash-and-validate-phase6-m2-placeholder"
      else
        "${flash-and-validate-phase6-m2}/bin/nixtropic-flash-and-validate-phase6-m2";
    meta.description = "DFU-flash open firmware + Phase 6 M2 Force-UV validation";
  };

  force-uv-get = {
    type = "app";
    program = "${force-uv-get}/bin/nixtropic-force-uv-get";
    meta.description = "Read the Force-UV flag (Phase 6 M2)";
  };

  force-uv-set = {
    type = "app";
    program = "${force-uv-set}/bin/nixtropic-force-uv-set";
    meta.description = "Set / clear the Force-UV flag, PIN-gated (Phase 6 M2)";
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

  lint = {
    type = "app";
    program = "${lint}/bin/nixtropic-lint";
    meta.description = "Static analysis (cppcheck) over original firmware code";
  };
}
