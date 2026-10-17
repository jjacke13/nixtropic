# Phase 9 — Plan (v2)

> **Historical record, frozen at v0.3.0.** Kept for the reasoning and the evidence it
> contains. Facts and procedures here may be outdated or wrong: do not follow
> instructions from this file. Current documentation: <https://jjacke13.github.io/nixtropic/>
> (known corrections: <https://jjacke13.github.io/nixtropic/hardware/#corrections-to-earlier-documentation>).

Status: in progress — M0 and M1 done (2026-10-14), M2 and M3 done (2026-10-15); see STATUS.md. v1 (98cbfde,
2026-10-14) was reviewed against the official TROPIC01 documentation the same evening;
verdict "changes required, direction supported". v2 folds that review in. This
document is the contract.

Phase 9 hardens the firmware for a **v0.3.0 release** that ships before FOSSCOMM 2026
(Athens, 31 Oct – 1 Nov). Like v0.2, v0.3.0 is a development release: it does **not**
claim to be a production security key.

**Hard deadline: Thursday 29 Oct 2026.** By then the repository, the release and the
nixtropic FOSSCOMM material are done. 30 Oct is buffer only.

Milestone format as in Phases 5–8: **plan → implementation → hardware-in-the-loop
validation → review → STATUS / PROJECT / BACKLOG / memory updates.** Review =
`cpp-reviewer` for the C code + the TROPIC01 documentation reviewer for anything that
touches the chip. Milestones with a design step (M4, M5) get a short design doc
reviewed **before** code, like `history/PHASE-5-M4-DESIGN.md`.

---

## 0. Guard rails (READ FIRST every time)

This list **replaces** `PHASE-8-PLAN.md §0` for Phase 9. Several Phase 8 rules were
wrong (the session-lifetime, slot-consumption and temperature rules); do not rely on
them. Document references: DS = datasheet, API = User API, PIN = M&D PIN application
note, CONFIG = configuration application note, PAIR = pairing-key application note,
CAT = catalogue/part listing, UPDATE = firmware-update application note.

1. **No irreversible lifecycle operation in Phase 9.** No pairing-key write or
   invalidation (one-way, DS §7.5.3), no I-config write (OTP, CONFIG §1), no R-config
   write, no chip firmware update (anti-downgrade, UPDATE §1.1), no STM32
   option-byte / RDP / TrustZone change. Mutable application operations (ECC
   erase/generate, R-mem erase/write, M&D, counters) are allowed; they are destructive
   and every validation step names which ones it uses. One dongle exists: a bricked chip
   means no demo.
2. **R-config procedure (Phase 10 material).** The SDK v3 whole-write helper does not
   erase. The official procedure: read and keep the full mirror first (factory sensor
   settings live there, CAT §5.2), explicit checked erase, write, apply, read back
   (CONFIG §4.2). The brick erratum `OI_TR01_ERR_2026010800` body is not fully verified,
   so no R-config operation is approved.
3. **Permanent failures.** Normal Alarm Mode clears on a power cycle (DS §6.5). Permanent
   failures are separate: the R-config erratum above, and fatal I-config failure
   (API Table 22).
4. **L3 sessions end** on reset, sleep, abort and several error classes (DS §7.4). Code
   must treat the session as invalid after those, and reopen. The L3 handshake is
   `Noise_KK1_25519_AESGCM_SHA256` (DS §7.4.1).
5. **M&D attempts.** A slot is consumed when the chip executes `MAC_And_Destroy`. A
   request rejected before dispatch need not consume one; a lost response leaves it
   unknown. Treat ambiguous outcomes conservatively (count the attempt) and **never
   replay blindly** (API Table 37; PIN §3.5).
6. **R-memory.** User payload max 444 B on older FW, 475 B on FW ≥ 2.0.0 (API Tables
   24–26). Every payload fits 444 B, and every reader validates the full length and
   schema it got. Rewrite = erase then write (DS §7.6), so there is no atomic in-place
   update.
7. **Read error ≠ empty slot.** Only the documented `SLOT_EMPTY` result triggers
   first-boot initialisation (API Table 25). Any other error fails closed. Corrupt
   records are not silently reset; supported migrations are explicit.
8. **OpenPGP state and keys move together.** R33 state and ECC slots 29/31 are separate
   objects. A reset of PINs must erase or re-bind the keys in the same checked sequence
   (crash-safe), never leave keys under reset PINs.
9. **Validation may be destructive** (owner decision, 2026-10-14: no keys on the dongle
   need keeping). This is not permission for lifecycle operations (rule 1). Tests use a
   **known fixture**: PINs known to the runner, stop if unknown, never probe PINs.
   Fault injection runs on the host mock, never on the chip.

---

## 1. Order and why

Remote first (host software), then the shared chip-wrapper fixes that everything else
stands on, then FIDO, then PIN and state integrity, then secrets at rest. Binding chip
signing to a correct PIN (pairing keys + access rights) is **Phase 10**: it needs
irreversible operations whose official procedures are not fully verified. M4 produces
the PIN-derived key Phase 10 builds on, so nothing here is in its way.

| M | What | Dates | Depends on |
|---|---|---|---|
| M0 | Test harness + fixture + host mock + baseline | ✅ Wed 14 Oct (planned Thu 15) | — |
| M1 | Release / debug build split | ✅ Wed 14 Oct (planned Fri 16) | M0 |
| M2 | Chip-wrapper foundation (errors, sessions, entropy) | ✅ Thu 15 Oct (planned Sat 17) | M1 |
| M3 | FIDO2 fixes + CTAP2.1 permission tokens + `authenticatorConfig` | ✅ Thu 15 Oct (planned Sat 17 – Sun 18) | M2 |
| M3b | ES256 (P-256) credentials (added 15 Oct) | ✅ Thu 15 Oct | M3 |
| M4 | PIN + persistent-state integrity | ✅ Fri 16 Oct (STATUS.md; design §13) | M2 |
| M5 ✅ | No secrets in readable R-memory: DEC key wrapped under k (PIN hashes already gone in M4) — done Sat 17 Oct (design, code, HIL) | Sat 17 18:00 (quota reset) – Sun 18 Oct | M4 ✅ green Fri 16 |
| M6 | Docs + CARD-SETUP (+ v0.3.0 release note) | Sun 18 Oct (moved up 17 Oct: M5 done a day early) | M1–M5 |
| — | Tag v0.3.0 (Vaios decides the push) + buffer | Mon 19 Oct (moved up 17 Oct) | — |
| — | FOSSCOMM material (slides, demo, refresher, rehearsal) | Tue 20 – Wed 28 Oct | v0.3.0 |
| — | **Everything ready** | **Thu 29 Oct** | — |

Re-planned 2026-10-15 (Vaios): M0–M3 took 1.5 days instead of 4, so M4–M6 move up and
the FOSSCOMM material gets 9 days instead of 4.  The 29 Oct deadline is unchanged.

The M4 and M5 design docs are written ahead (M4: Sun 18, M5: Tue 20) so review never
waits on code. Refresher sessions run in the evenings and finish by Sat 24 Oct.

---

## 2. M0 — Test harness + fixture + baseline (Thu 15 Oct)

1. `nix/apps.nix`: the flash step loses dfu-util's exit status (`tee … || true`, then
   `PIPESTATUS`). Fail on a real error; whitelist only the known benign "leave" error,
   narrowly.
2. **Fixture:** a `tools/fixture.env` (gitignored, example committed) with the PINs the
   runner knows. Scripts refuse to run when the card's state does not match the fixture,
   never by trying a PIN. `validate-openpgp.sh` and `validate-pin-md.sh` take it as
   input. `validate-pin-md.sh` first establishes an active M&D binding, then tests.
   Every script prints which objects it mutates.
3. **Host tests** (`nix build .#host-tests`, native gcc): pure-logic modules (CBOR first)
   plus a **mock chip transport** (in-memory R-mem / ECC / M&D with fault injection:
   errors, lost responses, power cut between calls). M2–M5 add their tests here.
4. **Baseline** on hardware: flash the current firmware, run the full suite with the
   fixture, record results and flash size (text ≈ 219 KB / 256 KB) in STATUS.md. Keep a
   known-good firmware image for recovery.

**Done when:** the harness catches a failure injected on the host mock and a failing
`dfu-util` (simulated), and the baseline is recorded.

## 3. M1 — Release / debug build split (Fri 16 Oct)

**Goal:** a release build exposes only HID-FIDO2 and CCID-OpenPGP. The CDC serial
interface and the lt-rpc vendor HID interface exist only in a debug build
(`NIXTROPIC_DEBUG=1`, default **off**). Their handlers and execution paths are compiled
out, not only removed from the descriptors.

Refactors needed first:
1. Move `tud_hid_set_report_cb` out of `hid_rpc/rpc.c` into the USB layer; FIDO2 input
   currently depends on it.
2. Replace the hard-coded FIDO HID instance `1` (`ctaphid.c`, `usb_descriptors.c`) with
   a named constant that follows the build.
3. `printf` → CDC (`usb/cdc_io.c`): a no-op in release.
4. LED state: keyed on "USB configured", not "CDC connected".
5. `main.c`, descriptors, `CONFIG_TOTAL_LEN`, string table, endpoints, CMake sources
   (`cdc_device.c`, `cdc_protocol/*`, `hid_rpc/*`) follow the flag.
6. Nix: `.#open-firmware` = release, `.#open-firmware-debug` = debug. Scripts that need
   lt-rpc say so and refuse on a release build.
7. ~~Even in debug, the raw passthrough gets an allowlist that excludes lifecycle commands
   (rule 1).~~  **Changed 2026-10-14:** the passthrough was **removed** from both builds.
   An allowlist was built, but the chip accepts a new request header while CSN stays
   low (TROPIC01 app-2.0.0 source), so a first-byte filter cannot keep lifecycle
   requests out.  The debug CDC is a printf log console only.  See STATUS.md.

**Done 2026-10-14** (a day early): all validation below passed on hardware for both
builds; reviews by cpp-reviewer and the TROPIC01 docs reviewer.  STATUS.md has the
record.

**Validation (Vaios):** release → `lsusb -v` shows only HID + CCID; webauthn.io
register + login; `gpg --card-status`, signed commit; `validate-fido.sh`. Debug → full
suite with the fixture.

## 4. M2 — Chip-wrapper foundation (Sat 17 Oct)

Shared fixes that M3–M5 rely on, so they come first.
1. ECC and R-mem erase wrappers return the chip's real result (today they report
   success on failure). Callers propagate it.
2. L3 session: invalidated on the error classes and events of rule 4 and on chip power
   changes; reopened on next use; ambiguous results reconciled, not replayed.
3. Entropy: the software P-256 code gets real randomness (TRNG) for its blinding instead
   of the fixed-seed stub; entropy failure fails closed.
4. Bounds: EdDSA message length checked against the API maximum before narrowing;
   P-256 public-key output length validated.
5. `chip-fw-version` documented as what it does (init + reboot), not "read-only".

**Validation:** host mock fault tests; full suite on both builds; a forced session
error recovers without a replug.

**Done 2026-10-15** (two days early): all of the above on hardware, plus a
throw-away image without the fix that stayed stuck (the check goes red).  Item 1:
the chip answers OK for an empty slot, so every erase error is real.  Item 2: no
retry anywhere, not even on `NO_SESSION` (SDK3 does not CRC-check error statuses).
Reviews: cpp-reviewer, Jan.  STATUS.md has the record.

## 5. M3 — FIDO2 fixes + `authenticatorConfig` (Sat 17 – Sun 18 Oct)

1. GetAssertion uses a credential only for the RP it was created for (stored RP hash,
   CTAP §6.2.2 step 7).
2. CBOR parser: nesting-depth limit, bounds checks on all lengths; host unit tests.
3. Algorithm selection walks `pubKeyCredParams` for the first supported algorithm
   (Ed25519). GetInfo stops advertising ES256 until it is implemented. Discoverable-
   credential (rk) claims match what assertion without an allowList actually does, or
   are fixed.
4. credMgmt reports capacity from the 29 FIDO ECC slots, not 32.
5. Counter and reset errors are reported (signCount never silently resets; factory
   reset reports partial failure) and reset clears PIN-token RAM.
6. **Permission tokens:** `getPinUvAuthTokenUsingPinWithPermissions` (0x09) with
   permission, RP-scope, lifetime and revocation state. The legacy token (0x05) keeps
   only mc/ga rights.
7. **`authenticatorConfig` (0x0D) `toggleAlwaysUv`**, authenticated with
   `pinUvAuthParam` over the command message and requiring the `acfg` permission
   (CTAP §6.11). GetInfo advertises `authnrCfg` and only the versions/options really
   implemented.
8. lt-rpc policy setters remain debug-only.
9. Dispatch policy while a request waits for touch (FIDO and OpenPGP both ways,
   nested waits, shared consent state, debug lt-rpc): BACKLOG 6.6, from the M2 review.

**Validation:** unit + mock tests; `fido2_test.py validate`; webauthn.io; credential of
site A refused for site B; alwaysUv matrix: PIN configured (toggle needs a
0x09 token with acfg; refused with a legacy token or none) and PIN not configured
(the spec's bootstrap behaviour). Rerun after M4/M5.

**Done 2026-10-15** (three days early): all of the above on hardware, release and
debug (`tools/validate_fido_m3.py` 54/54, OpenPGP 16/16, webauthn.io and
www.webauthn.me).  How and why: `PHASE-9-M3-WORKPLAN.md`.  The touch-wait policy
also had to move CTAPHID requests out of the USB callback (TinyUSB re-arms HID OUT
only after it returns; found on hardware).  Reviews: cpp-reviewer, Jan (plan + 4
rounds).  STATUS.md has the record; PROJECT.md decisions 18 and 19.

**Inputs for M4 from the M3 reviews:** `slots_init` still rewrites slot 0 after a
non-empty read error or a torn erase+write (PIN and alwaysUv lost, credentials
kept); orphan scrub / full record validation; the other global-state writers do not
mark an uncertain write the way `slots_alloc` / `slots_erase` do.

## 6. M4 — PIN + persistent-state integrity (Mon 19 – Wed 21 Oct)

**Design doc first** (`docs/PHASE-9-M4-DESIGN.md`, written Sun 18 Oct, reviewed before
code). It must cover:

1. **Kernel output.** `k = HMAC-SHA256(key=s, msg=0x02)` (PIN §3.4–3.5) returned on
   **setup and on verify**, only after the tag matches **and** restore/bookkeeping is
   committed. Caller-owned 32-byte buffer, wiped on every failure path. s, u, k_i stay
   internal. Tag comparison constant-time.
2. **Staged bindings (A/B).** Today setup overwrites the live M&D slots before the new
   record is saved, so a failure can lose the old binding. Each PIN gets two M&D slot
   ranges and two R-mem records with a generation number (plenty free: 17 of 128 M&D
   slots and ~36 of 512 R-mem slots used). New binding → inactive range + inactive
   record (gen+1) → commit = the valid record with the highest generation. The old
   binding stays usable until the commit. Old records cannot restore spent attempts.
   Behaviour defined at every commit boundary, tested on the host mock with power cuts.
3. **Ordinary PIN change keeps s.** Verify old PIN → recover s → set up the new PIN
   with the same s (PIN §3.4 optional supplied s) → k is unchanged, so data wrapped
   under k (M5) survives a PIN change.
4. **Bootstrap.** Who creates the PW1/PW3 bindings on a fresh card and when (factory
   PINs bound at first boot); a failed bootstrap is retried safely; FIDO "PIN not set"
   and "RC not set" stay valid, distinct states, never a broken binding.
5. **No software fallback.** A read error is not "M&D inactive"; every setup result is
   checked. The legacy software PIN path (check-then-count) is removed.
6. **Init only on `SLOT_EMPTY`** (rule 7) for FIDO R0 and OpenPGP R33; full-length
   validation of both records; explicit, tested migrations; a release that supports one
   layout uses one explicit destructive migration (rule 8).
7. **OpenPGP PIN semantics.** Separate PW1.81 (sign) and PW1.82 (decrypt/auth) states.
   All cleared on card reset / power-off / different-DF select (PGP §4.3). DO C4 governs
   CDS only: `00` = one signature per verify, `01` = until reset; new default `01`
   (PIN once per plug-in).

**Validation:** host mock tests for interrupted setup/change/commit, read/erase errors,
old/short/future records; then hardware with the fixture: `validate-pin-md.sh
--destroy-my-pin` on a bound PIN, PIN change, RC and PW3 resets, forcesig `00`/`01`,
card-reset APDUs, separate 81/82 behaviour.

## 7. M5 — No secrets in readable R-memory (Thu 22 – Fri 23 Oct)

**Gate:** M4 validated on hardware by **Wed 21 Oct evening**; otherwise M5 moves to
Phase 10 and the docs and slides say that readable secrets remain. **Design doc**
(`docs/PHASE-9-M5-DESIGN.md`) is written Tue 20 Oct and reviewed in parallel with M4.

1. **PIN verifiers.** Stop storing the independent PIN hashes (FIDO R0, OpenPGP). The
   M&D tag (with the encrypted s values, attempts, metadata) is the PIN check; syntax,
   authorization, lockout and storage errors are still enforced.
2. **Decryption key wrap.** KEK = domain-separated derivation from k. AES-KW (RFC 3394
   / NIST SP 800-38F) or AES-GCM via the existing crypto library; wrap bound to schema
   and object id; tampered or stale wraps fail closed and never fill the cache. The DEC
   public key is stored separately, so reading it needs no unwrap.
3. **Lifecycle, one rule per event:** generation (needs PW3 **and** a PW1.82 session to
   get k; otherwise refused, never plaintext at rest); ordinary PW1 change (s kept, wrap
   still valid); PW3 / RC reset (no old k: the DEC key is destroyed and must be
   regenerated; documented, no promise of recovering encrypted data); lockout,
   TERMINATE/ACTIVATE, schema reset (key destroyed); interrupted transitions (A/B
   commit from M4).
4. **Cache.** Unwrapped key + k/KEK in RAM only after PW1.82, cleared on card/USB reset,
   power-off, VERIFY reset, different-DF select, PIN change/reset, TERMINATE/ACTIVATE,
   key replacement and any failure. RAM exposure while unlocked is a stated residual.
5. Docs that say all OpenPGP private keys stay on the chip (`docs/UBUNTU.md` §10) are
   corrected.

**Validation:** host tests (wrong/tampered wraps, lifecycle events, cache
invalidation); hardware: `gpg --decrypt` works after the PIN and fails before it; PIN
change keeps decryption; PW3 reset destroys the key as documented; a debug-build dump of
R0, R33 and R50–R52 against the known fixture PINs and key bytes shows no plaintext
verifier, PIN or private key.

## 8. M6 — Docs + release (Fri 23 Oct, or Sat 24 if M5 ran)

1. Correct the docs found inaccurate: Noise variant, Alarm Mode, sessions, R-mem
   sizes, monotonic counters (they decrement and can be re-initialised), M&D behaviour,
   the R-config procedure, `NIXTROPIC_ENG_KEYS` (not implemented), `docs/RECOVERY.md`
   trust boundary, `research/stm32u535-inventory.md` (RDP regression, BHK), LFI dates.
2. State plainly: our part `TR01-C2P-T101` is listed DEPRECATED upstream; erratum
   `OI_TR01_ERR_2026090100` (RNGTEST_DIS) applicability is unresolved; no config
   change is made for it in Phase 9.
3. New `docs/CARD-SETUP.md`: the application-level commands that configure the dongle
   (gpg PINs, forcesig, uif, generate; FIDO PIN, alwaysUv). Never config, pairing,
   updater or MCU-protection commands. Reused in the FOSSCOMM slides.
4. README + STATUS: what v0.3.0 is and is not (development release, public dev pairing
   key, not a production security key, residual risks incl. M5 status), Phase 10 roadmap.
5. Final acceptance: both builds, full fixture suite, then flash the release and set up
   the demo state last. Tag `v0.3.0` locally; Vaios pushes.

---

## 9. Phase 10 (after FOSSCOMM, not dated)

- Bind chip signing to a correct PIN: own pairing keys whose use requires k, access
  rights per the official R-config procedure (rule 2), then SH0 invalidation. Needs the
  full erratum texts and its own reviewed design.
- Protecting the pairing private key on the STM32: RDP level / TrustZone (HDP needs
  TrustZone) / keeping the long-term secret in or wrapped by TROPIC01; signed update
  path if DFU is closed.
- Device identity: verify the chip certificate chain; runtime minimum chip-FW check.
- libtropic v4 + chip FW 2.1/2.2 with the controlled update procedure (both banks,
  start/final version checks, maintenance disable per the LFI advisory); check
  RNGTEST_DIS applicability first.
- Per-device pairing keys; non-resident
  (wrapped) credentials.
- **DEC key that survives a PIN reset** (Vaios, 2026-10-17): M5 locks the decryption key
  under the PW1 KEK because, with the public dev pairing key, the PIN is the only secret
  an attacker lacks — so a RESET RETRY COUNTER (RC or PW3) must destroy it, unlike a
  YubiKey.  With our own pairing key, lock it with a chip-held secret instead (keeping
  the PIN gate in front), so an admin reset keeps the key.  Chip facts (Jan, 2026-10-17):
  no user-slot ECDH in any public app FW (1.0.0–2.2.0) or SDK 3/4; R-mem reads can be
  limited to chosen pairing slots by UAP, but per 128-slot group (O3 shares group 0–127
  with FIDO) — needs a separate region; an authorized read still exports to STM32 RAM.
- **OpenPGP key import (gpg `keytocard`)**: not implemented today — gpg sends PUT DATA
  odd (`DB 3F FF`, extended header list `4D`), the applet answers `6D00`.  SIG/AUT via
  ECC_Key_Store (Ed25519 seed or P-256 scalar into an empty slot; ECC_Key_Read reports
  origin generated vs stored — API 1.4 Tables 29–30), DEC wrapped as in M5.  Gives an off-card backup of the
  decryption key; trade-off: an imported key is not chip-generated (BACKLOG 4.5).
- **PIN-bound signing design (C2), two parts decided for Phase 10** (Vaios, 2026-10-17):
  the chip's sign command checks only which pairing key opened the session (by design,
  every public app FW 1.0.0–2.2.0), so signing becomes PIN-bound indirectly: SH1 gets
  the signing rights, SH0 loses them, SH1's private key is wrapped under the PW1 KEK.
  (a) While a signature runs, the unwrapped SH1 key sits in STM32 RAM — protect it with
  RDP / TrustZone.  (b) A PIN reset must not burn the 4 write-once pairing-key slots
  (fresh s would orphan a wrapped SH1 key) — needs its own design and Jan's review.
- **libtropic 4.2.0** (Vaios, 2026-10-17): look into moving the firmware from libtropic
  3.2.1 to 4.2.0 (renamed APIs, e.g. `lt_sh0*`, `TR01_KEY_GENERATED/STORED`; the fw-update
  tool reworked for `lt_do_mutable_fw_update`).  Separate from the chip FW update.
- **Chip firmware: latest version + compatibility** (Vaios, 2026-10-17): (a) check whether
  our TROPIC01 can move to the latest public app FW (2.2.0 as of Jan's check, 17 Oct;
  re-check then) — one-way, only with the controlled update procedure above; the dongle
  runs 2.0.0 today (`nix run .#chip-fw-version`).  (b) Find and write down which chip FW
  versions our firmware works with (each libtropic version supports a range; our code
  uses app FW 2.x behaviour) — the basis for the runtime minimum chip-FW check under
  "Device identity".
