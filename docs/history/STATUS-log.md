# Project Status

> **Historical record, frozen at v0.3.0.** Kept for the reasoning and the evidence it
> contains. Facts and procedures here may be outdated or wrong: do not follow
> instructions from this file. Current documentation: <https://jjacke13.github.io/nixtropic/>
> (known corrections: <https://jjacke13.github.io/nixtropic/hardware/#corrections-to-earlier-documentation>).

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

## 2026-10-15 — Phase 9 M3 FIDO2 fixes, permission tokens, authenticatorConfig ✅

`docs/PHASE-9-PLAN.md §5`; how and why: `docs/PHASE-9-M3-WORKPLAN.md` (reviewed by
Jan before code).  Commits `ca628dc`..`e6f8951`.

- **Requests are checked before parsing (M3.1).**  `cbor_validate()` runs once per
  CTAP2 request: one well-formed item, ≤ 4 nesting levels (CTAP §8), every length
  inside the buffer, no tags or indefinite lengths.  `cbor_reader_skip()` has its own
  recursion cap.  MakeCredential / GetAssertion parsing moved to chip-free
  `ctap2_parse.c` (every `pubKeyCredParams` entry checked, no int truncation of COSE
  ids, options as booleans, `user.id` ≤ 64 B, enterpriseAttestation refused).
- **Credentials are bound to their RP; discoverable credentials are real (M3.3).**
  GetAssertion walks the whole allowList and uses the first credential that exists
  **and** was made for this RP (before: the first entry, any RP).  `rk` is stored per
  credential; GetAssertion without an allowList returns the RP's discoverable
  credentials newest first (creation sequence in the slot metadata) with
  `numberOfCredentials`, `user.id` and GetNextAssertion.  excludeList is honoured;
  a new `rk` credential for the same RP + user replaces the old one in one bitmap
  write.  `credProps.rk` reports what was stored.
- **signCount (M3.4).**  Every assertion reserves its value first (counter Update,
  then Get) and signs it; errors fail the operation (before: a read error reported
  0, a write error was ignored).  The counter is initialised only on a genuine first
  boot (slot 0 and every credential slot read empty, once per boot) or by a reset
  whose key erases all succeeded; the reset now stops before touching PIN or bitmap
  if any key erase fails, and always asks for a touch.
- **Permission tokens (M3.5/6).**  `pin_token.c`: one token with permissions,
  permissions RP ID, 30 s to first use, 10 min life, spent by a touch-tested
  operation.  ClientPIN 0x09 (getPinUvAuthTokenUsingPinWithPermissions); 0x05 gives
  mc+ga only.  MakeCredential / GetAssertion / credMgmt / config each check their
  permission and RP; with a PIN set a discoverable credential needs a token
  (`makeCredUvNotRqd` = !alwaysUv); `up=false` is a silent pre-flight; zero-length
  pinUvAuthParam is the touch probe.
- **credMgmt (M3.7).**  `cm` permission and the per-subcommand RP rules; GetNextRP /
  GetNextCredential without pinUvAuthParam while the Begin's token lives — libfido2
  sends none there, so `fido2-token -L` stopped after the first RP or credential
  before.  Capacity from 29 slots.  Lists every credential, discoverable or not
  (each holds a chip slot; documented deviation).
- **authenticatorConfig 0x0D toggleAlwaysUv + honest GetInfo (M3.8).**  With a PIN,
  the toggle needs a token with `acfg`; without one it is open.  On a release build:
  `fido2-token -S -u` (on) / `-D -u` (off).  GetInfo: versions `FIDO_2_0` only
  (FIDO_2_1 needs hmac-secret, credProtect, protocol 2), new option IDs `authnrCfg`,
  `pinUvAuthToken`, `makeCredUvNotRqd`; `credentialMgmtPreview` and ES256 dropped
  (neither existed).  AAGUID trailing byte 03 → 04.
- **One request at a time during a touch wait (M3.9, BACKLOG 6.6).**  CCID APDUs and
  CTAPHID requests now run from the main loop, never inside a USB callback; a touch
  wait pumps USB but starts no other request (FIDO: CHANNEL_BUSY, CCID: answered after
  the wait, lt-rpc: BUSY); only one wait at a time.  CTAPHID_CANCEL ends the waiting
  request (KEEPALIVE_CANCEL) and is never answered (it was echoed).
- **Release surface check (M3.10):** flake check `release-surface` — the release ELF
  has no lt-rpc symbols, the debug ELF has them.
- Host tests: `test_cbor` (validate, depth, skip cap), `test_ctap2_parse`,
  `test_pin_token` (permissions, RP binding, timers, generation); mutants red.
  Hardware suite `tools/validate_fido_m3.py` (54 checks, destructive for FIDO only).
- Reviews: cpp-reviewer R1 changes required (CONT/INIT clobbering during a wait,
  RP re-check, fail-open getters, …) → R2 approve.  Jan: plan review (counter
  bootstrap, reset order, overwrite, creation sequence) + 4 code rounds (sticky
  bootstrap, CONT bypass, Reset gate, unreadable records, uncertain bitmap write,
  CCID bus reset, deferred-dispatch ownership) → approve at `e6f8951`, with host
  probes against the real sources.

**Found on hardware, invisible to every review:** TinyUSB re-arms the HID OUT
endpoint only after `tud_hid_set_report_cb` returns.  A CTAPHID request handled
inside that callback blocked every packet on the FIDO interface for its whole touch
wait, so CANCEL (and INIT/BUSY handling) never arrived (suite 51/53).  Fixed by
running requests from `fido_hid_task()` (`85009ee`, `e6f8951`).

**Hardware (one dongle).**

| Build | Check | Result |
|---|---|---|
| debug 2b9ffbb4 | `lt_rpc.py validate` / `sign-test` (M2 tool fix, first HW run) | ✓ 5/5 on a free slot / refuses occupied slot 0 |
| debug 2b9ffbb4, e6b4ee79 | `validate_fido_m3.py` | 51/53, 52/54 → CANCEL root cause above |
| debug fce3c528 (final) | `validate_fido_m3.py` (incl. CCID APDU during a FIDO wait) | ✓ 54/54 |
| debug fce3c528 | `validate-openpgp` / `validate-fido` | ✓ 16/16 / 5/5 |
| release c2cbb3e9 (final) | `validate_fido_m3.py` / `validate-openpgp` / `validate-fido` | ✓ 54/54 / 16/16 / 5/5 |
| release | `fido2-token -I` | ✓ options as implemented, EdDSA only, AAGUID …04 |
| release | `fido2-token -L -k webauthn.io` (2 creds via GetNext without auth), `-S -u` / `-D -u` | ✓ |
| release | webauthn.io discoverable register + usernameless login; non-discoverable register | ✓ (owner) |
| release | www.webauthn.me (EdDSA) register + authenticate with its credential ID | ✓ UP+UV, signCount 5 → 6 |

Final binaries: release `firmware.bin` sha256 `c2cbb3e9…` (on the dongle), debug
`fce3c528…`.  Sizes (Arm GNU 15.2): release 220 628 B (84.2 %, +11 232 B vs M2),
RAM 30.4 KB; debug 226 448 B, RAM 35.2 KB.  Same compiler warnings as M2.

Notes:
- Sites that offer only ES256/RS256 (webauthn.me's default) do not see the key: it
  announces EdDSA only now (before M3 it claimed ES256 and then refused it).  ES256
  support = BACKLOG 2.3.  webauthn.me's RP ID is `www.webauthn.me`.
- credMgmt shows RPs as the hex of their hash (only the hash is stored).
- A request in the first second after enumeration can be lost while the firmware
  boots; the suite retries INIT.
- `fido2_test.py validate-phase6-m2/m3` (lt-rpc Force-UV, legacy-token credMgmt,
  capacity 32) are superseded by `validate_fido_m3.py`.
- M4 inputs from the reviews: `slots_init` still rewrites slot 0 after a non-empty
  read error or a torn erase+write (PIN and alwaysUv lost); orphan scrub / record
  validation; other global-state writers do not mark an uncertain write; one-packet
  CTAPHID replies are dropped under IN backpressure.

## 2026-10-15 — Phase 9 M3b ES256 credentials + M4 design ✅

**ES256 (P-256 ECDSA) next to EdDSA** — commits 8b43157, 6ab113c, 790e630.
MakeCredential takes the first of EdDSA (-8) / ES256 (-7) in the site's
`pubKeyCredParams` order; RS256 stays unsupported (no RSA on the chip).  P-256 keys
are generated and used inside TROPIC01: SDK 3 hashes `authData ‖ clientDataHash` with
SHA-256 on the STM32, the chip signs the digest and returns raw `r ‖ s`, which
`cose.c` turns into DER.  `cose.c` also writes both COSE key formats (MakeCredential
and credMgmt).  The stored alg byte is minus the COSE id.  GetInfo lists both
algorithms.  Chip facts from Jan (`PHASE-9-M4-DESIGN.md` §9); cpp-reviewer APPROVE
(3 low, fixed in 6ab113c).

| Build | Test | Result |
|---|---|---|
| host | `test_cose` (key encodings, DER edge cases), `test_ctap2_parse` (host order, RS256, truncation) | ✓ red first, then green |
| debug 559c87ad | `validate_fido_m3.py` (new part 3b: EdDSA and ES256 chosen by order, both assertions verified; credMgmt keys = ES256 keys) | ✓ 60/60 |
| release c6385131 | `validate_fido_m3.py` | ✓ 60/60 (a first run 59/60: SW1 pressed during the CANCEL check) |
| release | www.webauthn.me, ES256 discoverable register + usernameless authenticate | ✓ (owner) |

Final binaries: release `firmware.bin` sha256 `c6385131…` (on the dongle), debug
`559c87ad…`.  Sizes: release 221 764 B (84.6 %, +1 136 B), debug 227 584 B.

Notes:
- webauthn.me's debugger defaults to RS256; pick ES256 or EdDSA.  Its Authenticate
  finds a non-discoverable credential only if the credential ID is uploaded; a
  discoverable one (Resident Key: required) works without.
- opensc joined the dev shell; without it the suite skipped the CCID check.

**M4 design** `docs/PHASE-9-M4-DESIGN.md`: approved by Jan at r3 (8f3a743; r1 and r2
CHANGES REQUIRED, mapped in §11/§12).  Implementation Fri 16 Oct.

## 2026-10-16 — Phase 9 M4 PIN + persistent-state integrity ✅

Design `docs/PHASE-9-M4-DESIGN.md` (approved before code; §13 = every implementation
decision and review).  Commits bf9b20b..4f98656.
- **Record pairs** (`tropic/rec_pair`): every persistent object in two R-mem slots, write
  proven by read-back, newer copy wins and repairs the other; an empty read never proves
  a fresh device (guards); an unproven write makes the object refuse until reboot.
- **M&D kernel v2** (`tropic/pin_md_kernel`): A/B slot ranges, commit = record, then the
  old range retired; k = HMAC(s, 2) out for M5; the binding is the only PIN state.
- **FIDO** (O1 0/40, O2 41/42, M&D 0–15): checked reset wipe (keys → metadata → PIN →
  fresh O1 → counter), dispatcher refuses all but GetInfo/Reset unless the state is
  known-good, changePin per CTAP 2.1.
- **OpenPGP** (O3 33/43, O4–O6 50–55, M&D 16–30): no software PIN check, PW1.81 /
  PW1.82 / PW3 apart, DO C4 byte 0 with spec meaning (default 01 = PIN once per
  plug-in), access cleared on card reset / other AID / PIN change, checked wipe before
  any factory PIN, ACTIVATE only from a clean TERMINATED, TERMINATE without PW3 only
  when PW3 itself is blocked or unreadable.  Legacy kernel and wrapper deleted.
- **No migration** (Vaios): the old layout reads damaged and fails closed.
- **Found on hardware, fixed:** USB now starts after the chip/FIDO boot (1ba7b86) and
  CCID listens again right after processing (f05e63b): a pcscd that gave up on a late
  answer (cold boot, or the FIDO reset at plug-in) had dropped the reader for good.

Reviews: cpp-reviewer APPROVE every step; Jan APPROVE every step (step 4 after one
CHANGES REQUIRED: TERMINATE waived PW3 on an unreadable O3; a torn ACTIVATE trapped the
card — both fixed, with an APDU-level fault sweep).  Host: 14 suites, single-fault sweeps
for every lifecycle path, ~130 mutants (all killed but equivalents).

| Build | Test | Result |
|---|---|---|
| host | `nix build .#host-tests` (rec_pair, pin_md_kernel, fido_state, fido_pin_cmd, openpgp_state, openpgp_applet, …) | ✓ 14/14 |
| release dc188e77 | old layout: GET DATA 6F00 → TERMINATE (no PW3) + ACTIVATE → factory | ✓ |
| release / debug | `validate_fido_m3.py` (FIDO reset at plug-in included) | ✓ 60/60 both |
| release / debug | `validate-openpgp` | ✓ 16/16 both |
| release / debug | `tools/validate-openpgp-m4.sh` (81/82, C4 00, CHANGE, RC + RESET RETRY COUNTER) | ✓ 29/29 both |
| release | `validate-pin-md.sh --destroy-my-pin` | ✓ |
| release | `gpg --card-status`: Signature PIN not forced, retries 3 0 3 | ✓ |

Measured: an OpenPGP VERIFY ≈ 1.4 s (3 rounds: two record-pair writes dominate).
Sizes: release 221 908 B, debug 227 792 B.

**Release note for v0.3.0 (must say):** after flashing, run a FIDO reset
(`fido2-token -R <dev>` within 10 s of plugging in, touch) and an OpenPGP factory reset
(tested raw: SELECT, `00 E6 00 00`, `00 44 00 00`, e.g. with `opensc-tool -s`; gpg's
`factory-reset` sends the same but was not tried against the old layout, where GET DATA
answers 6F00).
Until then FIDO answers only GetInfo/Reset and OpenPGP only SELECT / VERIFY 83 /
TERMINATE.  All FIDO credentials, OpenPGP keys and PINs are lost (no migration).

## 2026-10-17 — Phase 9 M5 OpenPGP decryption key wrapped under the PIN ✅

Design `docs/PHASE-9-M5-DESIGN.md` (Jan: CHANGES REQUIRED at r1, APPROVE at r2, before
code; §10 = implementation and reviews).  Commits 3d14ea7..cc93d82.
- The X25519 DEC private key is no longer stored plain: O3 schema 2 holds the public key
  and the private key sealed with AES-256-GCM under KEK = HMAC(k, label), k = HMAC(s, 2)
  from the PW1 M&D binding; fresh TRNG nonce per seal; the AAD binds the public key.
  Unwrap checks the tag first (constant time) and decrypts only after a match.
- The KEK lives in RAM only while PW1.81 or PW1.82 is verified.  GENERATE DEC needs PW3
  and a verified PW1 (gpg verifies 81 on a fresh card); PSO:DEC needs 82.
- A PW1 change keeps the key (same s).  RESET RETRY COUNTER (RC or PW3) destroys it,
  checked, after every refusal of the reset and before the new PIN (fresh s).
- Format pinned by a golden record made outside the code (Python `cryptography`).

Reviews: Jan APPROVE (one LOW fixed); cpp-reviewer CHANGES REQUIRED (test gaps only:
nonce freshness, preflight vs PW1 ERROR, no outside vector, generate failure, a
mislabelled case, PIN scan) → APPROVE on cc93d82.  Mutants: 17 at 2583b6f (3
equivalent) + the reviewer's 6 survivors, all killed after cc93d82.

| Build | Test | Result |
|---|---|---|
| host | `nix build .#host-tests` (+ new `pgp_dec`: GCM KAT, golden record, ECDH vs reference, tamper, faults, no key / PIN / SHA-256(PIN) in any R-mem window) | ✓ 15/15 |
| debug 1a8b7997 | M4 layout (schema 1): GET DATA 6F00 → VERIFY 83 + TERMINATE + ACTIVATE → factory | ✓ |
| release 467a2b87 / debug 1a8b7997 | `tools/validate-openpgp-m4.sh` (M5 fixture: GENERATE dec refused with PW3 only, ok after VERIFY 81; PSO:DEC after CHANGE; RC reset destroys) | ✓ 42/42 both |
| release / debug | `validate-openpgp` | ✓ 16/16 both |
| release | `validate_fido_m3.py` | ✓ 60/60 |
| release / debug | gpg (throwaway GNUPGHOME): `--card-edit generate` on a fresh card, decrypt fails with a wrong PIN, works with PW1; works after a PW1 change; after RESET RETRY COUNTER (RC on debug, PW3 on release) `--card-status` shows Encryption key [none], SIG + AUT kept | ✓ both |

Not done on hardware: the R-mem dump scan (design §5) — the debug build has no raw R-mem
read RPC; the host tests scan every R-mem window instead.
Measured: VERIFY 81 ≈ 1.4 s (unchanged from M4).  Sizes: release 223 188 B, debug 229 072 B.

**Release note for v0.3.0 (add):** the OpenPGP layout changed again (O3 schema 2): an
M4-era card reads damaged until TERMINATE + ACTIVATE.  Resetting PW1 with the Reset Code
or the Admin PIN destroys the decryption key (a change keeps it).  Tools that generate the
decryption key after verifying only PW3 now get 6982; gpg verifies PW1 first and works.

## 2026-10-18 — Phase 9 M6 documentation + final acceptance ✅

Documentation restructured into one `docs/` tree that GitHub shows and MkDocs Material
publishes (`nix build .#docs`, strict link and anchor validation; workflow
`.github/workflows/docs.yml`). Plans, design documents, this log, `PROJECT.md`,
`TROPIC01.md` and `research/` moved to `docs/history/` with a banner and inline
corrections. Jan reviewed the outline (approve with additions), the drafts (J1–J10,
all applied) and, at Vaios's request, verified every pairing-key statement twice more
against Tropic Square's documents (second pass P1–P12; third, fresh pass: core model
matches, two overstatements fixed, project-specific claims given source citations).
Code comments only point at the new paths; firmware bytes unchanged.

Final acceptance on the M5 binaries (release `467a2b87`, debug `1a8b7997`):

| Suite | Release | Debug |
|---|---|---|
| `validate-openpgp-m4.sh` | 42/42 (second run; the first started on a card the gpg run had left keyed — precondition "no dec key yet" failed, all else passed) | 42/42 |
| `validate-openpgp` | 16/16 | 16/16 |
| `validate_fido_m3.py` | 60/60 | 60/60 |
| gpg end to end (generate, sign+verify, wrong PIN, decrypt, ssh-add -L) | 7/7 | 7/7 |
| `nix flake check` (host tests, release surface, docs) | pass | |
