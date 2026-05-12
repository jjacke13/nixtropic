{
  description = ''
    nixtropic — Nix flake for Tropic Square TROPIC01 + TS1302 USB devkit work.

    Phase 0 deliverables:
      packages.stock-firmware     Reproducibly-built unmodified TS1302 firmware
                                  (the recovery / factory-reset image)
      packages.libtropic          The official C SDK as a Nix package
      packages.lt-util            The official lt-util CLI for chip access
      devShells.default           ARM toolchain + flashing/debug utilities
      apps.flash-stock            DFU-flash the stock firmware
      apps.identify               Read TROPIC01 chip info via lt-util
      apps.check-dongle           Diagnose USB enumeration and permissions
      nixosModules.tropic         udev rules + group for non-sudo dongle access

    Read PROJECT.md for the full project plan and phase roadmap.
  '';

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";

    systems.url = "github:nix-systems/default-linux";

    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };

    # Stock TS1302 firmware source — pinned to master @ 36a40ba (2025-08-27).
    # Source for our `stock-firmware` derivation. Has a single git submodule
    # (STM32U5xx_HAL_Driver from STMicroelectronics) which `flake = false`
    # input doesn't fetch automatically; we use fetchSubmodules in a
    # separate fetchFromGitHub call inside the derivation. See note below.
    ts1302-stock-fw-src = {
      url = "github:tropicsquare/tropic01-stm32u5-usb-devkit-fw/36a40baa802cf226e07296604afea24780fd09d1";
      flake = false;
    };

    # libtropic — official C SDK. Pinned to v3.2.1 (latest stable as of 2026-05-10).
    libtropic = {
      url = "github:tropicsquare/libtropic/6d058a36c7db9e55549a5e79ed4f9a83def80c0a";
      flake = false;
    };

    # lt-util CLI — pinned to master HEAD as of 2026-05-10.
    libtropic-util = {
      url = "github:tropicsquare/libtropic-util/cbc30f5ac37e7d0874df6b989d4b4be7d01d93e8";
      flake = false;
    };

    # PKCS#11 module — pinned to main HEAD as of 2026-05-10.
    libtropic-pkcs11 = {
      url = "github:tropicsquare/libtropic-pkcs11/37406ec5180fffb56f16e4d720188ef20fdd31b5";
      flake = false;
    };

    # ===== Phase 1 inputs (custom firmware) =====
    # All four pinned to specific commits for reproducibility. None have
    # submodules (verified 2026-05-10).

    # CMSIS Core — pinned to master @ Release 6.3.0 (2026-03-16).
    # ST's tagged release at v5.9.0_20250520 is older; master at this commit
    # carries the labeled "Release 6.3.0" so we treat it as a stable rev.
    cmsis-core = {
      url = "github:STMicroelectronics/cmsis-core/2327f7224ff212b2436e5a4cadda3288143fd041";
      flake = false;
    };

    # CMSIS Device U5 — v1.4.2 (latest stable tag as of 2026-05-10).
    # Ships startup_stm32u535xx.s and system_stm32u5xx.c we reuse directly.
    cmsis-device-u5 = {
      url = "github:STMicroelectronics/cmsis-device-u5/6e67187dec98035893692ab2923914cb5f4e0117";
      flake = false;
    };

    # STM32U5xx HAL driver — v1.6.2 (latest stable tag as of 2026-05-10).
    # libtropic's stm32u5xx HAL port is HAL-based, so we pull this in.
    stm32u5xx-hal-driver = {
      url = "github:STMicroelectronics/stm32u5xx-hal-driver/2c5e2568fbdb1900a13ca3b2901fdd302cac3444";
      flake = false;
    };

    # TinyUSB — 0.20.0 release tag (per Phase 1 plan decision P1.25).
    # We adapt the U545 BSP to U535 inside firmware/third_party_overlay/.
    tinyusb = {
      url = "github:hathach/tinyusb/3af1bec1a9161ee8dec29487831f7ac7ade9e189";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, ts1302-stock-fw-src, libtropic, libtropic-util, libtropic-pkcs11
            , cmsis-core, cmsis-device-u5, stm32u5xx-hal-driver, tinyusb
            , ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Stock firmware needs git submodules. The flake input mechanism
        # doesn't fetch submodules, so we re-fetch via fetchFromGitHub with
        # fetchSubmodules = true. The flake input still provides the URL and
        # rev pinning; we just refetch the tree with submodules included.
        stockFwSrc = pkgs.fetchFromGitHub {
          owner = "tropicsquare";
          repo = "tropic01-stm32u5-usb-devkit-fw";
          rev = "36a40baa802cf226e07296604afea24780fd09d1";
          fetchSubmodules = true;
          hash = "sha256-tjdEFE31EigzR683JQr8rcw8ULZbg6NvVx1eK8/gT1U=";
        };

        stockFirmware = pkgs.callPackage ./nix/stock-firmware.nix {
          src = stockFwSrc;
        };

        # Build lt-util as a Nix package.
        # Note: we keep this small and Phase-0-shaped. The CMake build of
        # libtropic-util pulls libtropic in as a submodule normally, so we
        # mirror that pattern.
        ltUtilSrc = pkgs.fetchFromGitHub {
          owner = "tropicsquare";
          repo = "libtropic-util";
          rev = "cbc30f5ac37e7d0874df6b989d4b4be7d01d93e8";
          fetchSubmodules = true;
          hash = "sha256-P4+VEaed40qKPLNLFwOdTCCCJ5PbjNk3JvJhOVedyAc=";
        };

        lt-util = pkgs.stdenv.mkDerivation {
          pname = "lt-util";
          version = "master-cbc30f5-patched-loop";
          src = ltUtilSrc;

          # Fix off-by-one in lt-util's bundled libtropic v1.0.0 host adapter
          # (hal/port/unix/lt_port_unix_usb_dongle.c). The readback loop
          # iterates 2*tx_data_length times instead of tx_data_length: for
          # chip_id (130-byte transfer) it walks 260 iterations past the
          # 512-byte buffered_chars[] and writes past s2->buff[257],
          # corrupting state and yielding LT_L1_SPI_ERROR on subsequent calls.
          # Fixed in libtropic >= v3.x; lt-util upstream is dormant and still
          # pins libtropic v1.0.0. Symptom: mode poll (1 byte) and riscv_fw
          # (4 bytes) work; chip_id (130 bytes) fails. Verified 2026-05-10
          # by manual replication of the lt-util sequence end-to-end against
          # our Phase 2 firmware (nix run .#read + printf chip_id sequence
          # → 294 bytes returned correctly with byte-exact Phase 0 baseline).
          postPatch = ''
            substituteInPlace libtropic/hal/port/unix/lt_port_unix_usb_dongle.c \
              --replace-fail 'count < 2 * tx_data_length' 'count < tx_data_length'
          '';

          nativeBuildInputs = with pkgs; [ cmake pkg-config ];
          cmakeFlags = [ "-DUSB_DONGLE_TS1302=1" ];
          installPhase = ''
            mkdir -p $out/bin
            cp ./lt-util $out/bin/lt-util
          '';
          meta = with pkgs.lib; {
            description = "CLI for interfacing with TROPIC01 chip via TS1302 USB devkit";
            homepage = "https://github.com/tropicsquare/libtropic-util";
            license = licenses.bsd3;
            platforms = platforms.linux;
          };
        };

        # Open firmware — custom STM32U535 firmware that's a byte-faithful
        # drop-in replacement for the stock TS1302 firmware (Phase 2 deliverable
        # per PROJECT.md §6). 100% Nix-built, MIT-licensed USB stack (TinyUSB),
        # libtropic kept as a flake input for host-side use only. Built on
        # any host with an arm-none-eabi cross toolchain via gcc-arm-embedded.
        open-firmware = pkgs.callPackage ./nix/firmware.nix {
          libtropicSrc = libtropic;
          cmsisCoreSrc = cmsis-core;
          cmsisDeviceU5Src = cmsis-device-u5;
          stm32u5xxHalDriverSrc = stm32u5xx-hal-driver;
          tinyusbSrc = tinyusb;
        };

        # TROPIC01 chip-firmware updater (host tool, Linux x86_64/aarch64).
        # Builds against pinned libtropic + OpenSSL CAL.  See nix/fw-update-chip.nix
        # + tools/fw-update-chip-main.c.
        fw-update-chip = pkgs.callPackage ./nix/fw-update-chip.nix {
          libtropicSrc = libtropic;
        };

        apps = import ./nix/apps.nix {
          inherit pkgs;
          inherit stockFirmware;
          openFirmware = open-firmware;
          libtropicUtil = lt-util;
          fwUpdateChip = fw-update-chip;
        };

        devShell = import ./nix/dev-shell.nix { inherit pkgs; };

      in
      {
        packages = {
          inherit stockFirmware lt-util;
          stock-firmware = stockFirmware;  # convenience alias
          inherit open-firmware;
          inherit fw-update-chip;
          default = stockFirmware;
        };

        devShells.default = devShell;

        inherit apps;

        # Convenience: nix run with no arg → identify
        # (commented out for now since identify needs the dongle plugged in)
        # apps.default = apps.identify;
      }
    ) // {
      # NixOS module — system-agnostic, lives outside eachDefaultSystem.
      nixosModules = {
        tropic = import ./nixos/tropic.nix;
        default = import ./nixos/tropic.nix;
      };
    };
}
