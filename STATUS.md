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

---

## 2026-10-14 — Phase 9 M0 baseline ✅

Test harness made trustworthy before the Phase 9 hardening
(`docs/PHASE-9-PLAN.md`), then a baseline on the one dongle.

**Harness:**

- Flash apps report failed flashes (`tools/dfu-flash.sh`).  The old check
  turned every dfu-util failure into success.  On hardware the flash ended
  with exactly the one accepted benign error (`:leave` get_status, exit 74).
- PIN fixture (`tools/fixture.env`, from `fixture.env.example`): the
  validate scripts never guess a PIN and stop at the first failure.
- `validate-pin-md.sh` binds PW1 to MAC-and-Destroy before its wrong-PIN
  attempts.  Its status-word parser read the hexdump offset instead of the
  status bytes, so the script could not pass; fixed.
- `nix build .#host-tests` (also `nix flake check`): CBOR and the M&D
  kernel against a mock TROPIC01 with fault injection, plus the script
  tests, under ASan/UBSan.

**Baseline, firmware at `e5d72da` (= `firmware/` unchanged since `36f972b`):**

| Check | Result |
|---|---|
| `nix run .#flash-open` (DFU) | ✓ flashed, benign leave error recognised |
| `nix run .#validate` | ✓ FIDO2 5/5, OpenPGP 16/16 |
| `validate-pin-md.sh --destroy-my-pin` | ✓ bound PW1: 63C2, 63C1, 6983, locked; T+A recovers |
| `nix build .#host-tests` | ✓ |

Host: GnuPG 2.4.9, OpenSC 0.27.1, nixpkgs nixos-25.11 (pinned).
No SW1 touch was requested during the suites (touch policy off).

`firmware.elf` text = 218 760 B, data = 140 B (`firmware.bin` 218 904 B /
256 KB, 83.5 %); bss = 37 912 B.

**nixpkgs → nixos-26.05 (same day, only input bumped):** toolchain
Arm GNU 14.3.Rel1 → 15.2.Rel1.  Same 25 build warnings.  `firmware.elf`
text 218 760 → 219 980 B (`firmware.bin` 220 120 B, 84.0 %).  Reflashed;
`validate` FIDO2 5/5 + OpenPGP 16/16 and `validate-pin-md` pass again;
host tests pass.

---
## 2026-10-14 — Phase 9 M1 release / debug split ✅

`docs/PHASE-9-PLAN.md §3`.  Commits `bf085cc`..`15f8f6b`.

**Release build (`.#open-firmware`, default):** the dongle exposes only
HID-FIDO2 (IF 0) and CCID-OpenPGP (IF 1); device class 0, product
"nixtropic", no `/dev/ttyACM*`.  **Debug build (`.#open-firmware-debug`,
`-DNIXTROPIC_DEBUG=ON`):** adds the CDC log console (printf only) and the
lt-rpc vendor HID, in the Phase 4–8 layout; product "nixtropic debug".
The debug code is compiled out of release (no cdc/rpc symbols in the ELF).

- HID report routing moved to `usb/usb.c`; HID instances named.
- LED: heartbeat until boot is done and USB is configured, then off; the
  dead CDC-keyed cue and `platform/blink.c` removed.
- **CDC SPI passthrough removed** (also from debug).  A request-ID
  allowlist was built first; Jan (TROPIC01 docs reviewer) showed from the
  chip's app-2.0.0 source that the chip accepts a new request header while
  CSN is still low, so a first-byte filter cannot hold.  Owner decision:
  remove the passthrough.  Nothing in our tooling used it on the open
  firmware; chip FW update still goes through the stock firmware.
- Review: cpp-reviewer (no blocker; LED/CS findings fixed in `f63ff0a`),
  Jan (passthrough blocker → removal; M1 approved on source review).
- Force-UV can no longer be toggled on a release build (it was lt-rpc
  only); M3 adds `authenticatorConfig`.

**Hardware (one dongle):**

| Build | Check | Result |
|---|---|---|
| release | `lsusb -v` | ✓ class 0, 2 interfaces, wTotalLength 118 |
| release | `validate` | ✓ FIDO2 5/5, OpenPGP 16/16 |
| release | webauthn.io register + login (SW1) | ✓ |
| release | new card key + `git commit -S` + `verify-commit` | ✓ Good signature |
| release | LED: boot heartbeat → off; fast blink on touch wait | ✓ (owner) |
| debug | `lsusb -v`, check-dongle | ✓ 5 interfaces, "DEBUG build" |
| debug | `validate` / `lt_rpc.py validate` / `validate-pin-md` | ✓ 5/5 + 16/16 / 5/5 / 63C2, 63C1, 6983, T+A recovers |
| debug | CDC console on replug | ✓ init log (the `#` banner is lost: written before SET_CONFIGURATION) |

The final release binary (`firmware.bin` sha256 `2dd98d5e…`) is the one
validated above and left on the dongle.

Sizes (Arm GNU 15.2): release text 209 380 B (`firmware.bin` 209 524 B,
79.9 %), RAM 30 KB; debug `firmware.bin` 215 232 B, RAM 35 KB.  Same
compiler warnings as before the split.

## 2026-10-15 — Phase 9 M2 chip-wrapper foundation ✅

`docs/PHASE-9-PLAN.md §4`.  Commits `5af902f`..`d084f31` (the last three are
the fixes from Jan's review), plus a test-tool fix found on hardware.

- **Erase results (M2.1).**  `tropic_ecc_erase` / `tropic_rmem_erase`
  return the chip's result.  The old "an empty slot returns an error"
  claim was wrong: the chip answers OK for an empty slot (TROPIC01 app
  v2.0.0 source, checked by Jan).  Every non-rollback caller propagates
  it; both factory resets keep erasing past a failure and report it.
- **L3 session (M2.2).**  libtropic's own `session_status` is the only
  session state.  Every L3 wrapper returns through `l3_done()`: a result
  the chip returned inside the session keeps it (explicit list,
  `tropic/l3_result.h`); anything else aborts it on the host side and the
  next call re-handshakes.  The original error is returned and nothing is
  retried (guard rail 5; PROJECT.md decision 17).  Before: one transport
  error broke every chip call until a replug.  The debug `printf` no
  longer pumps `tud_task()` (it could dispatch a nested FIDO/CCID request
  in the middle of a chip operation); the unused Phase 1 L2 sweep is gone.
- **Entropy (M2.3).**  trezor-crypto's `random32()` (P-256 blinding in
  ClientPIN ECDH) was a fixed-seed LCG (`USE_INSECURE_PRNG`).  Now the
  STM32 TRNG (`platform/trezor_rng.c`); a TRNG failure stops the device
  at that call (system reset), never a substitute value.
- **Bounds (M2.4).**  EdDSA messages over 4096 B are refused before the
  `uint16_t` narrowing; a public key that does not fit is an error, not a
  truncation.
- **`chip-fw-version` (M2.5)** documented as rebooting the chip (it sends
  no write command; the chip's own boot may repair internal flash state).
- Host tests: `test_l3_result` (keep/drop list + `l3_result_finish`) and
  `test_trezor_rng` (stop on failure, no value returned), each red with a
  mutant.  Debug-only check: `lt_rpc.py session-recovery`.
- Review: cpp-reviewer approved (the `l3_done` host seam came from it).
  Jan: changes required (printf re-entry, RNG substitute, reboot wording)
  → fixed → approved.  Still open, by plan: signCount/reset counter errors
  (M3 item 5), FIDO/CCID interleaving during a touch wait (BACKLOG 6.6,
  M3), guard rails 7/8 (M4).

**Hardware (one dongle).**  Round 1 = first implementation, round 2 =
final code after Jan's fixes.

| Build | Check | Result |
|---|---|---|
| debug, **without** the abort (throw-away) | `lt_rpc.py session-recovery` | ✗ as intended: stuck after the fault, even step 1 fails on a rerun |
| debug (1, 2) | `lt_rpc.py session-recovery` | ✓ fault → `LT_L2_TAG_ERR` (35), session re-established, no replug |
| debug (1, 2) | CDC console on replug | ✓ no L3 error at boot; P-256 key ready |
| debug (1, 2) | `validate` / `lt_rpc.py validate` | ✓ 5/5 + 16/16 / 5/5 |
| debug (1) | `validate-pin-md` | ✓ 3 wrong lock, T+A recovers |
| debug (1) | `fido2_test.py validate-m5` (authenticatorReset + setPin) | ✓ 5/5 |
| release (1, 2) | `lsusb -v` | ✓ class 0, HID + CCID, wTotalLength 118 |
| release (1, 2) | `validate` | ✓ FIDO2 5/5, OpenPGP 16/16 |
| release (1) | `fido2-token -C` (changePIN over ECDH) | ✓ |
| release (1, 2) | webauthn.io (PIN + SW1) | ✓ register + login (1); (2) the round-1 credential fails (see notes), a new one registers + logs in ✓ (owner) |

Final binaries: release `firmware.bin` sha256 `c64e99b5…` (on the
dongle), debug `ed463efa…`.

Sizes (Arm GNU 15.2): release `firmware.bin` 209 396 B (79.9 %, −128 B vs
M1), RAM 30 KB; debug 215 136 B, RAM 35 KB.  Same compiler warnings as M1;
trezor's "NOT SUITABLE FOR PRODUCTION USE" pragma is gone.

Notes:
- An lt-rpc request sent within ~0.3 s of enumeration times out (2 s):
  boot init (chip power-up, session, credential store, P-256 key) runs
  before the main loop.  The boot sequence is the same as M1, so most
  likely not new (not re-checked on an M1 image).
- After a FIDO reset, the first setPIN auto-enables Force-UV (Phase 6
  design).  On a release build it can only be turned off again with M3's
  `authenticatorConfig`.
- `lt_rpc.py validate` used ECC slot 0 unconditionally (erase + generate),
  which replaced the key of the round-1 webauthn.io credential (slot 0 after
  the reset): login with it fails "could not verify signature", a fresh
  credential works.  Test-harness bug, not firmware: the key tests now use a
  free FIDO slot from the bitmap and erase it afterwards; `sign-test`
  refuses an occupied or OpenPGP slot.  First hardware run of the fixed tool:
  M3.
