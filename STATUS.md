# Project Status

Top-level milestone log.  Full per-phase progression with day-by-day
HW-validation logs lives on the `archive/phases-1-7` branch
(`STATUS.md` there).

---

## 2026-05-12 — ship state ✅

Daily-driver feature set live on hardware:

- **FIDO2 / WebAuthn** — register + login via `webauthn.io` in Firefox/Linux
- **OpenPGP card** — `git commit -S`, `gpg --encrypt/--decrypt`, SSH via
  gpg-agent all working end-to-end
- **Hardware-backed FIDO PIN** — chip-enforced MAC-and-Destroy retry
  counter: 8 wrong PINs mutate 8 chip slots' state past reconstruction;
  only a correct PIN re-initialises them, so a firmware-reflash
  attacker cannot bypass
- **User-presence button** — SW1 (PH3) gates every credential
  operation; anti-passive-attack reset gating
- **Reproducible Nix builds** — one `nix build` from clean checkout to
  flashable firmware

`firmware.bin` = 217 096 B / 256 KB (82.81 %).  ~40 KB headroom for the
items in `docs/BACKLOG.md`.

Verification command (non-interactive):

    nix run .#validate            # 22 checks across FIDO + OpenPGP

The development history that got us here (incremental phases 1-7 with
per-milestone HW checkpoints, three rounds of cpp-reviewer audits,
12-day timeline) is preserved at the `archive/phases-1-7` branch.

---

## 2026-05-21 — Phase 8 polish + RP-compat ✅

Phase 8 backlog items landed and broader real-world RP compatibility
proven on Brave / Firefox / Proton Account 2FA.

**New features:**

- **MAC-and-Destroy-backed OpenPGP PIN counters** (PW1 / PW3 / RC).
  Generic `pin_md_kernel` extracted from FIDO; OpenPGP wrappers on
  M&D slots 8..16 + R-mem slots 50/51/52.  Wrong PIN now burns chip
  slots silicon-permanent for OpenPGP as well as FIDO.  Schema
  PG7K → PG7R; bootstrap path wipes stale M&D state to avoid PIN
  brick on bump.
- **OpenPGP global touch policy** — runtime on/off (`docs/BACKLOG.md`
  §3.4 partial).  Per-slot touch (Yubikey-style) still TODO.
- **credProps WebAuthn extension** — fixes "unknown discoverability"
  label in RP UIs.
- **hidraw udev rule** — `nixos/tropic.nix` installs the rule so
  `libfido2` / browsers see the dongle without manual setup.
- **Slot-33 collision fix** — earlier-Phase-7 bug where FIDO
  per-credential R-mem could overwrite OpenPGP primary state.
- **credstore_factory_reset bounded to FIDO range** — CTAP2
  authenticatorReset no longer wipes OpenPGP keys at ECC slots
  29/30/31.

**RP-compat fixes (this commit cluster):**

- **AAGUID emitted as 16 zero bytes** in MakeCredential authData
  (CTAP2.1 self-attestation rule).  GetInfo still reports the
  branded nixtropic AAGUID.
- **PIN-gate respects Force-UV setting** — RPs requesting
  `userVerification: "discouraged"` no longer get `CTAP2_ERR_PIN_REQUIRED`
  when Force-UV is off.
- **Attestation `fmt: "none"`** (was `"packed"` self-attest with
  Ed25519 sig).  Sidesteps server-lib coverage gaps for Ed25519 in
  packed attestation; universal RP compat.  Sig path still active
  for assertion (login) operations.

**Host-side daily-driver doc:**

- README §4 spells out `disable-ccid` + `pcsc-shared` as required on
  every Linux distro (not just NixOS), with a non-NixOS libccid
  Info.plist patch recipe.  Documents the composite-USB / scdaemon
  libusb wedge that hits anyone running both FIDO + OpenPGP on the
  same device.

**Verified end-to-end on hardware:**

- webauthn.io register + authenticate (Firefox, Brave)
- Proton Account 2FA Add Security Key (Firefox, Brave)
- `gpg --card-status` + `gpg --decrypt` + `git commit -S` + SSH via gpg-agent
- `gpg --card-status` cycling without scdaemon claim wedging post-WebAuthn

`firmware.elf` text = 218 856 B / 256 KB (83.5 %).  ~37 KB headroom.

The development history of Phase 8 lives in `docs/PHASE-8-PLAN.md`.
