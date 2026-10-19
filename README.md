# nixtropic

[![Docs](https://img.shields.io/badge/docs-jjacke13.github.io%2Fnixtropic-26a69a)](https://jjacke13.github.io/nixtropic/)
[![Release](https://img.shields.io/github/v/tag/jjacke13/nixtropic?label=release)](https://github.com/jjacke13/nixtropic/tags)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Open-source firmware that turns the **Tropic Square TS1302 USB devkit** into a USB
security key — **FIDO2 / WebAuthn** and **OpenPGP card** — with keys held in the
**TROPIC01** secure element. Built reproducibly with Nix.

> [!WARNING]
> **Development release, not a production security key.** The board uses Tropic
> Square's **public development pairing key**: anyone holding the dongle can make it
> sign. v0.3.0 fixes the known host-side attack paths of v0.2 and stores no readable
> secrets on the chip; it does not defend against physical attacks. Read the [security model](https://jjacke13.github.io/nixtropic/security/)
> first.

> [!CAUTION]
> **Upgrading from v0.2 erases all FIDO2 credentials and OpenPGP keys** (the storage
> layout changed; no migration). See the
> [changelog](https://jjacke13.github.io/nixtropic/changelog/#upgrading) before flashing.

## Features

- **FIDO2 / WebAuthn** — passkeys and security-key logins; EdDSA and ES256 keys
  generated and used inside TROPIC01; PIN, `alwaysUv`, credential management
- **OpenPGP card** — `gpg` signing, decryption and SSH through `gpg-agent`; Ed25519
  keys inside TROPIC01, the X25519 decryption key sealed under the user PIN
- **Chip-enforced PIN limits** — TROPIC01 MAC-and-Destroy; no PIN hash stored anywhere
- **Fault-tolerant state** — settings and PINs stored as mirrored, read-back record
  pairs; one power cut or damaged slot never grants access or undoes a completed change
  ([limits](https://jjacke13.github.io/nixtropic/security/#persistent-state-under-faults))
- **User presence** — button SW1 and LED; touch policy per the OpenPGP card spec
- **Reproducible** — every input pinned; `nix build` gives the same firmware

## Quick start

```bash
# 1. Dongle in DFU mode: hold SW1 while plugging it in. Then:
nix run github:jjacke13/nixtropic#flash-open

# 2. Host (NixOS): imports = [ nixtropic.nixosModules.tropic ];
#    services.tropic.enable = true;
#    plus two lines in ~/.gnupg/scdaemon.conf: disable-ccid, pcsc-shared

# 3. Check
fido2-token -L && gpg --card-status
```

Needs TROPIC01 chip firmware 2.0.0. Full steps, including building without Nix and
setup on other distributions:

| Guide | |
|---|---|
| [Flashing](https://jjacke13.github.io/nixtropic/flashing/) | chip firmware check, DFU, Nix and non-Nix builds |
| [Linux setup](https://jjacke13.github.io/nixtropic/linux-setup/) | pcscd, scdaemon, udev, the libccid patch |
| [Windows](https://jjacke13.github.io/nixtropic/windows/) | Gpg4win / Kleopatra; FIDO2 with a PIN (v0.3.1) |
| [Card setup](https://jjacke13.github.io/nixtropic/card-setup/) | PINs, touch policy, key generation, resets |
| [Recovery](https://jjacke13.github.io/nixtropic/recovery/) | what each reset changes; DFU recovery |

## Documentation

**[jjacke13.github.io/nixtropic](https://jjacke13.github.io/nixtropic/)** — built from
[`docs/`](docs/): [architecture](docs/architecture.md), [hardware](docs/hardware.md),
[design decisions](docs/design.md), [security model](docs/security.md),
[testing](docs/testing.md), [status](docs/status.md), [roadmap](docs/roadmap.md).
Plans, design reviews and the milestone log of every phase are in
[`docs/history/`](docs/history/).

## Hardware

Tropic Square TS1302: STM32U535 microcontroller + TROPIC01 secure element
(`TR01-C2P-T101`), USB-C, one button, one LED. Other TROPIC01 boards are not supported.

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Third-party components keep their licenses
([list](docs/contributing.md#licenses)). Built on
[TROPIC01](https://github.com/tropicsquare/tropic01) and
[libtropic](https://github.com/tropicsquare/libtropic) by Tropic Square,
[TinyUSB](https://github.com/hathach/tinyusb) and
[trezor-crypto](https://github.com/trezor/trezor-firmware/tree/main/crypto).
