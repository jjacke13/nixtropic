{ pkgs }:

# Development shell for nixtropic firmware work.
#
# Provides:
#   - ARM bare-metal toolchain (gcc-arm-embedded-13) — pinned to LTS for
#     reproducibility with the stock firmware build
#   - dfu-util for flashing the dongle via STM32 factory bootloader
#   - openocd + stlink for SWD-level debugging (used from Phase 1 onward)
#   - picocom for UART debug console (needed in Phase 1 to read libtropic
#     output from the STM32 before USB stack is added)
#   - cmake + make for the build system (Phase 0 uses make from upstream;
#     our future custom firmware uses cmake)
#   - libtropic, lt-util on PATH for host-side TROPIC01 interaction
#   - Standard utilities: usbutils (lsusb), pkg-config, jq, gnumake

pkgs.mkShell {
  name = "nixtropic-dev";

  packages = with pkgs; [
    # Embedded toolchain
    gcc-arm-embedded-13   # arm-none-eabi-{gcc,as,ld,objcopy,size,gdb}
    dfu-util              # USB DFU class flasher
    openocd               # On-chip debugger / SWD bridge
    stlink                # ST-Link CLI tools

    # Build system
    cmake
    gnumake
    pkg-config
    ninja

    # Debugging / development
    picocom               # Serial console for UART debug from STM32
    minicom               # Backup serial console
    usbutils              # lsusb to verify dongle enumeration
    gdb                   # Host gdb (use arm-none-eabi-gdb for the dongle)

    # Scripting / automation
    jq
    bash

    # libtropic host tooling (built from our flake — see packages output)
    # NOTE: these get added at the flake.nix level, not here, because they
    # depend on the calling system's package set wiring.
  ];

  # Friendly shell hook explaining the environment
  shellHook = ''
    cat <<EOF
    ╔═══════════════════════════════════════════════════════════════╗
    ║  nixtropic dev shell — TROPIC01 + STM32U535 firmware project  ║
    ╚═══════════════════════════════════════════════════════════════╝

    Phase 0 toolchain ready:
      arm-none-eabi-gcc  $(arm-none-eabi-gcc -dumpversion 2>/dev/null || echo "?")
      dfu-util           $(dfu-util --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "?")
      openocd            $(openocd --version 2>&1 | head -1 | awk '{print $4}' || echo "?")
      cmake              $(cmake --version 2>/dev/null | head -1 | awk '{print $3}' || echo "?")

    Useful commands:
      nix build .#stock-firmware     Build stock TS1302 firmware
      nix run .#identify             Read TROPIC01 chip info (needs dongle)
      nix run .#flash-stock          Flash stock fw via DFU (needs dongle in DFU mode)
      lsusb | grep -E '0483:5740|0483:df11'   Check dongle connection

    Read PROJECT.md for the full plan. See docs/RECOVERY.md for DFU procedure.
    EOF
  '';
}
