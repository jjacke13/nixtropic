# Status

**Current release: v0.3.1** (October 2026), a development release: v0.3.0 plus the
Windows FIDO2 fix (CTAPHID KEEPALIVE).

## What v0.3 is

- A working FIDO2 / WebAuthn authenticator and OpenPGP card on the TS1302 devkit, in
  daily use by its author.
- Hardened against attacks from the host it is plugged into, and against reading
  secrets out of chip storage (Phase 9, see [changelog](changelog.md)).
- Built reproducibly from pinned sources, with host tests, mutation testing and
  hardware-in-the-loop validation on every milestone ([testing](testing.md)).

## What v0.3 is not

- **Not a production security key.** It uses Tropic Square's public development
  pairing key; someone holding the dongle can make it sign. See the
  [security model](security.md).
- Not certified (FIDO Alliance, OpenPGP), not independently audited.
- Not protected against physical attacks on the STM32 (no read-out protection, no
  secure boot) or on the chip (see the laser fault-injection advisory).
- Not a finished FIDO 2.1 authenticator: it reports `FIDO_2_0`.

## Compatibility

| Area | Tested | Notes |
|---|---|---|
| Board | TS1302 with TROPIC01 `TR01-C2P-T101` (ACAB), chip application FW 2.0.0 / SPECT 1.0.0 | other boards unsupported; older chip FW must be updated |
| Host OS | NixOS (nixos-26.05) | Debian/Ubuntu steps documented, not CI-tested |
| Host stack | GnuPG 2.4, pcsc-lite + patched libccid, OpenSSH via gpg-agent, libfido2 | `scdaemon` with `disable-ccid` + `pcsc-shared` |
| Browsers | Firefox, Brave (Linux) | Chrome expected to work; macOS untested |
| Windows 11 | OpenPGP card with Gpg4win/Kleopatra; FIDO2 with a PIN in Brave and Settings (v0.3.1) | FIDO2 with a PIN fails in v0.3.0 (no KEEPALIVE); see [Windows](windows.md) |
| Sites | webauthn.io, webauthn.me (v0.3); Proton account 2FA (v0.2) | attestation `none` |
| FIDO2 | CTAP 2.0 + CTAP 2.1 credential management, authenticatorConfig, permission tokens | EdDSA and ES256; no hmac-secret, credProtect, PIN protocol 2 |
| OpenPGP card | 3.4.1 subset: Ed25519 sign/auth, Cv25519 decrypt, PINs, UIF, forcesig | no RSA, no key import, no KDF-DO |
| Capacity | 29 FIDO credentials, 3 OpenPGP keys | every FIDO credential uses a chip slot |

## Validation of v0.3.1

Hardware runs on 19 October 2026, on the project's dongle: release `firmware.bin` sha256
`8bea9a51…` and debug `1fe4eb65…`, the binaries tagged v0.3.1. The author's runs, not
independent ones.

| Suite | Release | Debug |
|---|---|---|
| Host tests (17 programs and 2 script tests, sanitizers on), `nix flake check` | pass | — |
| FIDO2 suite `validate_fido_m3.py` | 60/60 | 60/60 |
| OpenPGP APDU suite `validate-openpgp-m4.sh` | 42/42 | 42/42 ¹ |
| OpenPGP suite `validate-openpgp` | 16/16 | 16/16 ¹ |
| gpg end to end | 7/7 | 7/7 ¹ |
| Windows 11: FIDO2 registration, login, slow touch, Cancel, PIN change in Settings, with USB captures | pass | — |

¹ On the debug build one commit earlier; the last commit changed only two FIDO2 PIN
code paths, which the FIDO2 suite covers on both builds.

## Validation of v0.3.0

Final acceptance on 18 October 2026, on the project’s dongle, both builds: release
`firmware.bin` sha256 `467a2b87…` and debug `1a8b7997…`, the binaries tagged v0.3.0.
These are the author’s hardware-in-the-loop runs, not independent test runs.

| Suite | Release | Debug |
|---|---|---|
| Host tests against the simulated chip (15 programs, sanitizers on), `nix flake check` | pass | — |
| FIDO2 suite `validate_fido_m3.py` | 60/60 | 60/60 |
| OpenPGP APDU suite `validate-openpgp-m4.sh` (PIN separation, C4, change, Reset Code, decryption-key lifecycle) | 42/42 | 42/42 |
| OpenPGP suite `validate-openpgp` | 16/16 | 16/16 |
| gpg end to end: generate on a fresh card, sign and verify, wrong PIN refused, decrypt, SSH key via gpg-agent | 7/7 | 7/7 |
| Release surface (no debug symbols in the release image) | pass | — |

Gap: a raw dump of chip data memory on hardware was not done (the release build has no
interface for it); the host tests scan every simulated data slot for keys and PINs
instead.

## Phase history

| Phase | Result |
|---|---|
| 1–3 | TROPIC01 from the STM32; USB stack; composite device |
| 4–6 | FIDO2 / WebAuthn on the chip; ClientPIN with MAC-and-Destroy; SW1, Force-UV, credential management |
| 7–8 | OpenPGP card over CCID; gpg signing, decryption, SSH; RP compatibility fixes (v0.2) |
| 9 | Hardening for v0.3.0: release/debug split, chip-call error handling, FIDO2 fixes, fault-tolerant state and chip-enforced PINs, sealed decryption key |
| 10 | [Roadmap](roadmap.md): PIN-bound signing, own pairing key, STM32 protection |

The day-by-day record is the
[milestone log](https://github.com/jjacke13/nixtropic/blob/main/docs/history/STATUS-log.md).
