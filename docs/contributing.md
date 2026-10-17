# Contributing

Issues and pull requests are welcome at
[github.com/jjacke13/nixtropic](https://github.com/jjacke13/nixtropic). Security
issues: see [SECURITY.md](https://github.com/jjacke13/nixtropic/blob/main/SECURITY.md),
not public issues.

## Build and test

```bash
nix develop                     # Arm toolchain, dfu-util, gpg, opensc, python tools
nix build .#open-firmware       # release firmware → result/firmware.bin
nix build .#open-firmware-debug # debug firmware
nix flake check                 # host tests, release-surface check, strict docs build
nix run .#lint                  # cppcheck over the firmware sources
```

Docs preview:

```bash
nix shell nixpkgs#python3Packages.mkdocs-material -c mkdocs serve
```

## Repository layout

| Path | Content |
|---|---|
| `firmware/` | the STM32 firmware (CMake); `src/` modules described in [architecture](architecture.md#firmware-modules) |
| `tests/host/` | host tests and the simulated TROPIC01 |
| `tools/` | flashing and validation scripts, chip firmware tools |
| `nix/` | firmware, stock firmware, host tests, dev shell, apps |
| `nixos/` | the NixOS module |
| `docs/` | this documentation; `docs/history/` is the frozen record |

## Rules for changes

**Never in normal firmware or scripts:** writes to the TROPIC01 configuration
(R-config, I-config), pairing-key writes or invalidation, chip firmware updates,
STM32 option-byte, RDP or TrustZone changes. These are irreversible or can brick the
chip; they need a reviewed design of their own ([roadmap](roadmap.md)).

**Firmware code:**

| Rule | |
|---|---|
| Warnings | `-Wall -Wextra -Wconversion -Wshadow -Wundef -Wcast-align -Wstrict-prototypes` |
| Memory | no dynamic allocation after init; static buffers sized at compile time |
| Parsers | every protocol parser bounds-checks every byte |
| Secrets | wiped after use (`memzero`) |
| Chip calls | only through `firmware/src/tropic/`; never retried ([decision 17](design.md#decisions)) |
| USB | callbacks store or assemble only; requests run from the main loop ([decision 18](design.md#decisions)) |
| Size | functions under 50 lines, files under 800 where possible |
| Comments | explain why, not what; file headers describe the module |

**Process for anything that touches the chip or stored state:** a short design
document first, reviewed against the vendor documentation; tests written first and
seen failing; mutants to prove the tests; a run on hardware on both builds;
[status](status.md) and the [changelog](changelog.md) updated.

**Hardware validation** uses the PINs in `tools/fixture.env` (from
`tools/fixture.env.example`); scripts never guess a PIN. Flashing someone's dongle
always needs their explicit go.

## Licenses

nixtropic is MIT licensed. Third-party code keeps its own license:

| Component | License | Used for |
|---|---|---|
| [libtropic](https://github.com/tropicsquare/libtropic) | Clear BSD | TROPIC01 SDK |
| [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/main/crypto) (via libtropic) | MIT | software cryptography |
| [TinyUSB](https://github.com/hathach/tinyusb) | MIT | USB device stack |
| [STM32U5 HAL](https://github.com/STMicroelectronics/stm32u5xx-hal-driver) | BSD-3-Clause | peripheral drivers |
| [CMSIS](https://github.com/STMicroelectronics/cmsis-core), [CMSIS device U5](https://github.com/STMicroelectronics/cmsis-device-u5) | Apache-2.0 | core and device headers |
| [TS1302 stock firmware](https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw) | Clear BSD | recovery image (`.#stock-firmware`) |

The FIDO2 and OpenPGP card code is written against the specifications; SoloKeys and
CanoKey served as cross-references, and no code from them is vendored.
