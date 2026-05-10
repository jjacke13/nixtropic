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
  };

  outputs = { self, nixpkgs, flake-utils, ts1302-stock-fw-src, libtropic, libtropic-util, libtropic-pkcs11, ... }:
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
          version = "master-cbc30f5";
          src = ltUtilSrc;
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

        apps = import ./nix/apps.nix {
          inherit pkgs;
          inherit stockFirmware;
          libtropicUtil = lt-util;
        };

        devShell = import ./nix/dev-shell.nix { inherit pkgs; };

      in
      {
        packages = {
          inherit stockFirmware lt-util;
          stock-firmware = stockFirmware;  # convenience alias
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
