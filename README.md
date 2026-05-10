# nixtropic

Open-source firmware project turning the **Tropic Square TS1302 USB devkit** into a **standards-compliant USB security key** (FIDO2 + OpenPGP card), backed by the **TROPIC01 secure element**.

> Yubikey-class hardware. Open silicon. Open SDK. Reproducible Nix builds. Daily-driver tools without the host-side glue.

## Status

**Phase 0** — toolchain reproducibility & recovery path. See `PROJECT.md` for the full 9-phase plan and architecture.

This is a long-running project. Each phase is independently shippable; if you stop anywhere, what you have is useful.

## Quickstart

Requires Nix with flakes enabled.

```bash
# Build the stock firmware reproducibly
nix build .#stock-firmware

# Enter the development shell
nix develop

# (TS1302 plugged in, in DFU mode) Flash stock firmware as a recovery / factory-reset
nix run .#flash-stock

# (TS1302 plugged in, in app mode) Read TROPIC01 chip info
nix run .#identify

# Diagnose USB enumeration / permissions
nix run .#check-dongle
```

## NixOS module

```nix
# In your flake.nix:
inputs.nixtropic.url = "github:jjacke13/nixtropic";

# In your configuration.nix:
{
  imports = [ inputs.nixtropic.nixosModules.tropic ];
  services.tropic.enable = true;
  services.tropic.users = [ "your-username" ];
}
```

This adds udev rules so the TS1302 dongle is accessible to the `tropic` group without sudo, in both normal app mode (`/dev/ttyACM0`) and DFU mode.

## Documentation

- **`PROJECT.md`** — Source of truth: architecture, phase plan, locked decisions, critical facts. Written for AI agents and contributors.
- **`docs/RECOVERY.md`** — How to recover the dongle if something goes wrong.
- **`TROPIC01.md`** — Conversational primer on the TROPIC01 chip.
- **`research/`** — Deep technical references (TROPIC01 inventory, STM32U535 inventory, prior-art verification). Load on demand.

## What this is NOT (yet)

- **Not a working FIDO2 key yet.** Phase 0 only builds the stock firmware reproducibly. Phase 5 ships the FIDO2 MVP.
- **Not a Yubikey replacement yet.** Phase 7 adds OpenPGP card / SSH / GPG support.
- **Not in nixpkgs yet.** Phase 8 (or later) will upstream.

For the original `libtropic-util` Nix packaging that this repo started as: see git history before commit `a0xxxxx` (the firmware-project pivot).

## License

See `LICENSE`. Upstream licenses preserved for libtropic and the stock firmware.

## Hardware

Tested on: Tropic Square **TS1302 USB devkit** (STM32U535 + TROPIC01, engineering sample TR01-B2S-T005). Other TROPIC01 devkits (RPi shield, Arduino shield) are *not* targeted by this firmware project; this is specifically about turning a USB dongle into a security key.

## Acknowledgments

Built on top of:
- [TROPIC01](https://github.com/tropicsquare/tropic01) by Tropic Square — the open-source secure element
- [libtropic](https://github.com/tropicsquare/libtropic) — the official C SDK
- [TinyUSB](https://github.com/hathach/tinyusb) (Phase 2+) — the embedded USB device stack
- [SoloKeys](https://github.com/solokeys/solo) (Phase 4+) — FIDO2 firmware port source
