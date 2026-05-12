# nixtropic

Open-source firmware project turning the **Tropic Square TS1302 USB devkit** into a **standards-compliant USB security key** — both **FIDO2 / WebAuthn** and **OpenPGP card** — backed by the **TROPIC01** secure element.

> Yubikey-class hardware. Open silicon. Open SDK. Reproducible Nix builds. Daily-driver-tested.

## Status — Phase 7 ✅ COMPLETE (2026-05-12)

The full daily-driver feature set works end-to-end on real hardware:

- 🔐 **FIDO2 / WebAuthn** — register + login via `webauthn.io` in Firefox; hardware PIN protection; user-presence button (SW1) gates every operation
- ✍️ **GPG signing** — `git commit -S` works; private key never leaves the TROPIC01 chip
- 🔓 **GPG decryption** — `gpg --encrypt -r self … | gpg --decrypt` round-trip works
- 🔑 **SSH via gpg-agent** — push to GitHub with the dongle's auth key
- 🛡️ **Hardware-backed PIN** — FIDO PIN uses MAC-and-Destroy chip slots (8-attempt physical lockout); 9 wrong PINs and the slots are gone at the silicon level
- 🟢 **Reset-with-SW1** — factory wipe by holding the button during the first 10 seconds of boot; no host software needed
- 🔄 **Force-UV** — `alwaysUv` option per CTAP2.1; user verification required for every credential use
- 📦 **Reproducible Nix builds** — one `nix build` command from clean checkout to flashable firmware

A 17-check end-to-end validation suite (`nix run .#flash-and-validate-phase7-m6`) confirms each surface stays green after every change.

## Quickstart — daily-driver setup (NixOS)

Requires Nix with flakes enabled. The dongle must be a Tropic Square TS1302 (STM32U535 + TROPIC01).

### 1. Add nixtropic to your system flake

```nix
{
  inputs.nixtropic.url = "github:jjacke13/nixtropic";

  # In your configuration.nix:
  imports = [ inputs.nixtropic.nixosModules.tropic ];
  services.tropic.enable = true;
  services.tropic.users = [ "your-username" ];
}
```

This sets up udev rules for both **app mode** (`cafe:4001`) and **DFU mode** (`0483:df11`), enables `pcsc-lite`, and patches `libccid`'s `Info.plist` so the reader is recognized (without this, gpg's smartcard daemon won't see the device).

### 2. Update the TROPIC01 chip firmware (one-time, if needed)

The dongle ships with chip firmware 0.3.1 (Deprecated). nixtropic needs chip firmware ≥ 2.0.0.

```bash
sudo nix run github:jjacke13/nixtropic#fw-update-chip
```

### 3. Enter DFU mode and flash the latest firmware

Hold SW1 (the button on the back of the dongle) while plugging USB. The dongle enumerates as `STMicroelectronics ST32 BOOTLOADER` (0483:df11).

```bash
sudo nix run github:jjacke13/nixtropic#flash-and-validate-phase7-m6
```

The 17-check validation suite runs immediately after flash and confirms FIDO2 + OpenPGP + audit fixes all work.

### 4. Configure GnuPG for the OpenPGP card

```
# ~/.gnupg/scdaemon.conf  (create or edit)
disable-ccid
pcsc-shared
```

```
# ~/.gnupg/gpg-agent.conf  (create or edit)
enable-ssh-support
```

Then reload:

```bash
gpgconf --kill scdaemon
gpgconf --reload scdaemon
gpg-connect-agent updatestartuptty /bye
```

### 5. Initialize keys on the card

```bash
gpg --card-edit
> admin
> passwd          # IMMEDIATELY change PW1 (default '123456') + PW3 (default '12345678')
> name            # set cardholder name
> generate        # generate sig + dec + aut keys directly on the chip
> quit

gpg --card-status   # verify keys are bound
```

### 6. Use it daily

```bash
# Sign a git commit with the dongle (touch SW1 when LED blinks)
git commit -S -m "..."

# Encrypt + decrypt
echo "secret" | gpg --encrypt -r self | gpg --decrypt

# SSH via the dongle's auth key
ssh-add -L                       # print the auth key
# (add it to GitHub/GitLab/your server's authorized_keys)
ssh -T git@github.com            # touch SW1 when prompted
```

## Demo recipes

### FIDO2 / WebAuthn — register + login on webauthn.io

1. Plug in the dongle. The LED should be steady (idle).
2. Open https://webauthn.io in Firefox/Linux. Enter any username.
3. Click **Register**. The LED starts blinking (user-presence required).
4. Press **SW1** within 30 seconds.
5. Optionally set a PIN.
6. Click **Authenticate**. Press SW1 again. You're logged in.

The credential lives in a TROPIC01 ECC slot, signed on-chip with Ed25519. The host never sees the private key.

### Factory reset (panic button)

If the card is locked out, PINs are forgotten, or anything else goes wrong:

1. Unplug the dongle.
2. Plug it back in **while holding SW1** (or press SW1 within the first 10 seconds of boot).
3. The LED blinks the reset pattern (fast triple-flash).
4. All credentials, PINs, and the OpenPGP applet state are wiped. The card returns to factory defaults.

Chip-side ECC keys (slots 29 + 31) are erased; software state in R-mem is wiped. Only the chip firmware itself survives.

### `git commit -S` end-to-end

After the daily-driver setup above:

```bash
$ cd ~/some/repo
$ git commit -S -m "test signed commit"
# pinentry prompts for PW1 (first time per session)
# LED blinks → press SW1
$ git log --show-signature -1
commit abc123... (HEAD -> main)
gpg: Signature made ... using EDDSA key ...
gpg: Good signature from "..." [ultimate]
```

## Hardware

Tested on: Tropic Square **TS1302 USB devkit** (STM32U535 + TROPIC01, engineering sample TR01-B2S-T005). Other TROPIC01 boards (RPi shield, Arduino shield) are *not* targeted by this project.

The dongle:

- USB-C, ~$50 from Tropic Square
- STM32U535CCTx host MCU (256 KB flash, 96 KB RAM, ARM Cortex-M33)
- TROPIC01 secure element (signing + true RNG + persistent storage)
- SW1 user-presence button
- 1× user LED

Pre-built firmware lands at ~82.8% of the STM32's 256 KB flash budget. Future Phase 8 hardening (M&D PIN counters etc.) has comfortable headroom.

## What this is NOT (yet)

- **Not Yubikey-equivalent for every flow.** RSA is out of scope (ECC-only, see [`docs/PHASE-7-PLAN.md §0`](docs/PHASE-7-PLAN.md)). PIV is deferred to Phase 7b. Chromium / Brave WebAuthn detection on Linux still flaky (Firefox works fine — see [`docs/WEBAUTHN-NOTES.md §8`](docs/WEBAUTHN-NOTES.md)).
- **Not on Windows / macOS.** Linux/NixOS first. Other platforms should work but haven't been validated.
- **Not yet in nixpkgs.** Phase 8 (or later) will upstream.
- **AAGUID is self-allocated** (`6e697874726f70696300000000000003` = ASCII `"nixtropic\x00\x00\x00\x00\x00\x00\x03"`). Not FIDO MDS registered ($25k/year not viable for an open-source project). RPs will display "unknown manufacturer" — this is by design. See [`docs/WEBAUTHN-NOTES.md §3`](docs/WEBAUTHN-NOTES.md).

## Documentation

| Doc | What it is |
| --- | --- |
| [`PROJECT.md`](PROJECT.md) | Source of truth — architecture, phase plan, locked decisions, critical facts. Written for AI agents and contributors. |
| [`STATUS.md`](STATUS.md) | Append-only project log; latest at top. |
| [`docs/PHASE-{1..7}-PLAN.md`](docs/) | Per-phase design documents. |
| [`docs/PHASE-8-BACKLOG.md`](docs/PHASE-8-BACKLOG.md) | Open items deferred to the next phase (M&D for OpenPGP PINs, credProps, configurable policies, etc). |
| [`docs/RECOVERY.md`](docs/RECOVERY.md) | What to do if the dongle is bricked. |
| [`docs/WEBAUTHN-NOTES.md`](docs/WEBAUTHN-NOTES.md) | Browser quirks, AAGUID policy, credential ID format. |
| [`TROPIC01.md`](TROPIC01.md) | Conversational primer on the secure element. |
| [`research/`](research/) | Deep technical references (TROPIC01 inventory, STM32U535 inventory, prior-art verification). Load on demand. |

## Building from source

```bash
# Clone + enter dev shell
git clone https://github.com/jjacke13/nixtropic
cd nixtropic
nix develop

# Reproducibly build the firmware
nix build .#open-firmware
ls result/firmware.bin

# Or build the stock firmware (factory recovery image)
nix build .#stock-firmware
nix run .#flash-stock
```

The flake exposes per-phase validation apps (`validate-phase1` through `validate-phase7-m6`) plus their `flash-and-validate-…` counterparts that DFU-flash before validating.

## License + Acknowledgments

See [`LICENSE`](LICENSE). Upstream licenses preserved for libtropic and the stock firmware.

Built on top of:

- [TROPIC01](https://github.com/tropicsquare/tropic01) — Tropic Square's open-source secure element
- [libtropic](https://github.com/tropicsquare/libtropic) — official C SDK
- [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/main/crypto) — Ed25519 / X25519 / SHA / HMAC primitives
- [TinyUSB](https://github.com/hathach/tinyusb) — embedded USB device stack
- [SoloKeys](https://github.com/solokeys/solo) (Phase 4 source for CTAP2) — open FIDO2 firmware
