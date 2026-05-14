{ pkgs }:

# Development shell for nixtropic firmware work.
#
# Provides:
#   - ARM bare-metal toolchain (gcc-arm-embedded-13) — pinned to LTS for
#     reproducibility with the stock firmware build
#   - dfu-util for flashing the dongle via STM32 factory bootloader
#   - openocd + stlink for SWD-level debugging
#   - picocom + minicom for serial console / debug
#   - cmake + ninja + make for the build system
#   - Python with hidapi + cryptography for lt-rpc + FIDO2 test helpers
#   - Standard utilities: usbutils (lsusb), pkg-config, jq

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

    # Python with hidapi for lt-rpc client tests + cryptography for
    # Ed25519 verify (tools/fido2_test.py, tools/lt_rpc.py).
    (python3.withPackages (p: [ p.hid p.cryptography ]))

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

    Toolchain ready:
      arm-none-eabi-gcc  $(arm-none-eabi-gcc -dumpversion 2>/dev/null || echo "?")
      dfu-util           $(dfu-util --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "?")
      openocd            $(openocd --version 2>&1 | head -1 | awk '{print $4}' || echo "?")
      cmake              $(cmake --version 2>/dev/null | head -1 | awk '{print $3}' || echo "?")

    Useful commands:
      nix build .#open-firmware            Build the nixtropic open firmware
      nix run  .#flash-and-validate        DFU-flash + full FIDO + OpenPGP validation
      nix run  .#validate                  Run the validation suite against a flashed dongle
      nix run  .#check-dongle              Diagnose USB enumeration / permissions

    Read README.md for the daily-driver recipe.  See docs/RECOVERY.md for DFU procedure.
    EOF
  '';
}
