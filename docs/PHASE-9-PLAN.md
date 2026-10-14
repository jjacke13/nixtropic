# Phase 9 — Plan

Status: planning (2026-10-14). No code shipped yet. This document is the contract.

Phase 9 hardens the firmware for a **v0.3.0 release** that ships before FOSSCOMM 2026
(Athens, 31 Oct – 1 Nov). Like v0.2, v0.3.0 is a development release: it does **not**
claim to be a production security key. The work comes from an internal review of the
firmware against the official TROPIC01 documentation (2026-10-14).

**Hard deadline: Thursday 29 Oct 2026.** By then the repository, the release and all
FOSSCOMM material for nixtropic are done. 30 Oct is buffer only.

Milestone format as in Phases 5–8: every item goes
**plan → implementation → hardware-in-the-loop validation → review → STATUS / PROJECT /
BACKLOG / memory updates.** Review = `cpp-reviewer` for the C code, plus the TROPIC01
documentation reviewer for anything that touches the chip.

---

## 0. Guard rails (READ FIRST every time)

All of `PHASE-8-PLAN.md §0` still applies. Phase 9 adds, or corrects:

1. **No irreversible chip operation in Phase 9.** No R-config / I-config writes, no
   pairing-key write or invalidation, no chip firmware update. Those belong to Phase 10,
   after FOSSCOMM. One dongle exists. A bricked chip means no demo.
2. **R-config whole write does NOT erase first.** The SDK v3 helper only writes. The
   official procedure is an explicit, checked erase, then the whole write, then reboot
   and read back. Phase 10 material; listed so nobody relies on the old wording.
3. **Normal Alarm Mode clears on a power cycle.** The permanent alarm is the R-config
   erratum (`OI_TR01_ERR_2026010800`), a separate hazard. `PHASE-8-PLAN §0.7` overstated it.
4. **The L3 handshake is `Noise_KK1_25519_AESGCM_SHA256`**, not Noise IK.
5. **R-memory user slots are 444 B (older FW) / 475 B (FW ≥ 2.0.0).** Every payload must
   fit 444 B, and every reader must check the length it actually got.
6. **Read error ≠ empty slot.** Only the documented SLOT_EMPTY result may trigger
   first-boot initialisation. Any other error fails closed.
7. **Schema bumps wipe OpenPGP state, but not ECC slots 29/31.** A migration that resets
   PINs must also erase or re-bind the keys. Never leave keys under reset PINs.
8. **Validation may now be destructive.** Vaios has no keys on the dongle that need
   keeping (2026-10-14). Every validation step still names what it mutates.

---

## 1. Order and why

Remote first (host software), then PIN and state integrity, then secrets at rest. The
big architectural item, binding chip signing to a correct PIN through pairing keys and
access rights, goes to **Phase 10**. It needs irreversible chip operations, and their
official procedures are not fully verified yet. Nothing in Phase 9 gets in its way: M4
adds the PIN-derived key that Phase 10 builds on.

| M | What | Dates | Gate |
|---|---|---|---|
| M0 | Test harness you can trust + baseline | Thu 15 Oct | — |
| M1 | Release / debug build split | Fri 16 Oct | M0 |
| M2 | CTAP2.1 `authenticatorConfig` | Sat 17 Oct | M1 |
| M3 | FIDO2 correctness fixes | Sat 17 – Sun 18 Oct | M1 |
| M4 | PIN + persistent-state integrity, PIN-derived key | Mon 19 – Tue 20 Oct | M1 |
| M5 | No secrets in readable R-memory | Wed 21 – Thu 22 Oct | M4 green by Tue 20 Oct evening, else moved to Phase 10 |
| M6 | Chip-wrapper robustness | Thu 22 Oct | M1 |
| M7 | Docs corrections + card-setup guide + v0.3.0 | Fri 23 Oct | M1–M6 |
| — | Buffer for slips | Sat 24 Oct | — |
| — | FOSSCOMM material (slides, demo, rehearsal) | Sun 25 – Wed 28 Oct | v0.3.0 |
| — | **Everything ready** | **Thu 29 Oct** | — |

The refresher sessions (Vaios relearning the project) run in the evenings alongside,
and finish by Sat 24 Oct.

---

## 2. M0 — Test harness + baseline (Thu 15 Oct)

**Why first:** every later milestone is judged by these scripts, and some of them can
report success that didn't happen.

1. `nix/apps.nix`: the flash step loses dfu-util's exit status (`tee … || true`, then
   `PIPESTATUS`). Fix it so a failed flash fails the app.
2. `validate-pin-md.sh`: first establish an active MAC-and-Destroy binding (set a PIN),
   then run the wrong-PIN tests. Otherwise a fresh device passes through the software path.
3. `validate-openpgp.sh`: check its PIN preconditions up front. If the admin PIN is not
   the default, stop instead of burning retries.
4. Host unit-test target (`nix build .#host-tests`, native gcc) for pure-logic modules,
   starting with the CBOR parser. It stays small: one test file per module touched in
   Phase 9.
5. Baseline on hardware: flash the current firmware, run the full suite, record the
   results and the flash size (text ≈ 219 KB / 256 KB).

**Done when:** the harness fails when it should (shown by breaking one thing on purpose)
and the baseline is recorded in STATUS.md.

## 3. M1 — Release / debug build split (Fri 16 Oct)

**Goal:** a release build exposes only HID-FIDO2 and CCID-OpenPGP. The CDC serial
interface and the lt-rpc vendor HID interface exist only in a debug build
(`NIXTROPIC_DEBUG=1`, default **off**). Their handlers and execution paths are compiled
out, not just hidden from the descriptors.

Refactors needed first (found in review):
1. Move `tud_hid_set_report_cb` out of `hid_rpc/rpc.c` into the USB layer; FIDO2 input
   currently depends on it.
2. Replace the hard-coded FIDO HID instance `1` (`ctaphid.c`, `usb_descriptors.c`) with
   a named constant that follows the build.
3. `printf` → CDC (`usb/cdc_io.c`): a no-op in release.
4. LED state (`cdc_protocol/protocol.c`): key it on "USB configured", not "CDC connected".
5. `main.c`, descriptors, `CONFIG_TOTAL_LEN`, string table, endpoint numbers, and the
   CMake sources (`cdc_device.c`, `cdc_protocol/*`, `hid_rpc/*`) follow the flag.
6. Nix: `.#open-firmware` = release, `.#open-firmware-debug` = debug. Validate scripts
   that need lt-rpc state that they need the debug build.

**Validation (Vaios):** flash release → `lsusb -v` shows exactly 2 interface classes
(HID, CCID); webauthn.io register + login; `gpg --card-status`, signed commit,
`validate-fido.sh`. Flash debug → full suite as in M0.

## 4. M2 — CTAP2.1 `authenticatorConfig` (Sat 17 Oct)

1. Command `0x0D`, subcommand `toggleAlwaysUv`, authenticated with `pinUvAuthParam`
   and the `acfg` permission, as the spec requires.
2. GetInfo advertises `authnrCfg`. Review which version strings and options GetInfo may
   honestly claim (today it says `FIDO_2_0`).
3. The policy setters in lt-rpc stay in the debug build only.
4. Touch policy and forcesig keep working through gpg (`uif`, `forcesig`); document
   both in the card-setup guide (M7).

**Validation:** `fido2-token -S -u` toggles alwaysUv on and off with the PIN, and is
refused without it; GetInfo reflects the state.

## 5. M3 — FIDO2 correctness (Sat 17 – Sun 18 Oct)

1. GetAssertion: a credential is used only for the RP it was created for (check the
   stored RP hash on lookup, CTAP §6.2.2 step 7).
2. CBOR parser: a nesting-depth limit and bounds checks on all lengths; host unit tests.
3. Algorithm selection: walk `pubKeyCredParams` for the first algorithm we actually
   support (Ed25519) instead of failing on the first entry.
4. credMgmt: report remaining capacity from the 29 FIDO ECC slots, not 32.
5. Errors propagate: failed erases, counter reads and counter updates are reported, not
   turned into success; factory reset reports partial failure.

**Validation:** unit tests; `fido2_test.py validate`; webauthn.io; a register on site A
followed by an assertion for site B with A's credential ID must be refused.

## 6. M4 — PIN + persistent-state integrity (Mon 19 – Tue 20 Oct)

1. MAC-and-Destroy kernel: also return the vendor scheme's PIN-derived key
   `k = KDF(s, 0x02)` after a successful verify (PIN application note §3.4–3.5), zeroised
   after use. M5 and Phase 10 use it.
2. No silent software fallback: a read error is not "M&D inactive"; setup failures are
   checked; a PIN change is atomic from the caller's view (old binding until the new one
   is complete).
3. Initialisation only on SLOT_EMPTY (guard rail 6), for FIDO slot 0 and OpenPGP slot 33.
4. OpenPGP record: full length and field validation, explicit supported migrations, and
   fail closed otherwise.
5. OpenPGP PIN semantics: PW1 state cleared on card reset / power-off; DO C4 honoured
   (`00` = one signature per verify, `01` = valid until reset). New default `01`
   (PIN once per plug-in, the intended behaviour).
6. Legacy software PIN path: removed. Every PIN is M&D-backed, so the
   check-then-count pattern disappears with it.
7. Schema bump (expected: OpenPGP state + keys 29/31 erased together, guard rail 7).

**Validation:** destructive `validate-pin-md.sh --destroy-my-pin` on a bound PIN;
forcesig on/off behaviour in gpg; unplug/replug clears PW1; wrong-PIN lockout and
reset-code recovery.

## 7. M5 — No secrets in readable R-memory (Wed 21 – Thu 22 Oct)

Gate: M4 validated by Tue 20 Oct evening. Otherwise M5 moves to Phase 10 and the slides
say so.

1. Stop storing PIN verifiers (FIDO and OpenPGP). The M&D tag is the only PIN check.
2. The OpenPGP decryption key (X25519, used on the MCU) is stored wrapped under a key
   derived from `k` (M4.1) and unwrapped only after a successful PW1 (82) verify; kept in
   RAM for the session, zeroised on reset (BACKLOG §1.2).
3. Schema bump; the docs that say all OpenPGP private keys stay on the chip
   (`docs/UBUNTU.md` §10) are corrected to describe the decryption key exactly.

**Validation:** `gpg --decrypt` works after the PIN and fails before it; a debug-build
dump of R-mem slots 0 and 33 shows no PIN-derived material and no plain key.

## 8. M6 — Chip-wrapper robustness (Thu 22 Oct)

1. L3 session: invalidate on the error classes the SDK treats as session-ending, and on
   chip power changes; reopen on next use.
2. EdDSA message length checked against the API maximum before narrowing.
3. The software P-256 code gets real randomness for its blinding (TRNG), instead of the
   fixed-seed PRNG stub.
4. `chip-fw-version` is documented as what it is (init + reboot), not "read-only".

**Validation:** full suite on release + debug; a forced session error recovers without
replug.

## 9. M7 — Docs + release (Fri 23 Oct)

1. Correct the docs that the review found inaccurate: Noise variant, Alarm Mode, R-mem
   sizes, monotonic counters, M&D behaviour, the R-config procedure, `NIXTROPIC_ENG_KEYS`
   (not implemented), `docs/RECOVERY.md` trust-boundary wording,
   `research/stm32u535-inventory.md` (RDP regression, BHK), LFI dates.
2. New `docs/CARD-SETUP.md`: every command that configures the dongle (gpg PINs,
   forcesig, uif, generate; FIDO PIN, alwaysUv), reused in the FOSSCOMM slides.
3. README + STATUS: what v0.3.0 is and is not. Development release, dev pairing keys,
   not a production security key; Phase 10 roadmap.
4. Tag `v0.3.0` locally. Vaios pushes.

---

## 10. Phase 10 (after FOSSCOMM, not dated)

- Bind chip signing to a correct PIN: own pairing keys whose use requires `k`, R-config
  access rights per the official erase → write → reboot → read-back procedure, then SH0
  invalidation. Needs the full erratum texts first.
- Protecting the pairing private key on the STM32: RDP level / TrustZone / keeping the
  long-term secret in or wrapped by TROPIC01; signed update path if DFU is closed.
- Device identity: verify the chip certificate chain, not only extract STPUB.
- libtropic v4 + chip FW 2.1/2.2, using the controlled update procedure (both banks,
  start/final version checks, maintenance disable per the LFI advisory). Check erratum
  `OI_TR01_ERR_2026090100` (RNGTEST_DIS) against our part first.
- Per-device pairing keys, ES256 support, credential-wrapping (non-resident) mode.
