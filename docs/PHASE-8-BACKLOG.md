# Phase 8 Backlog

**Status:** Open. Gathered at Phase 7 close (2026-05-12).

Phase 7 shipped the daily-driver feature set: FIDO2 + OpenPGP card both
working end-to-end, hardware-validated, audit-passed. Phase 8 is the
"polish + harden + publish" milestone. Items below are everything we
deferred during Phases 5–7 that we still want to deliver, organized by
theme.

The order within each section is rough priority (highest first), not
implementation order. Many items are independent and can ship in any
order.

---

## 1. Audit-driven hardening (highest priority)

These were deferred from Phase 7 M3 / M6 because the threat model didn't
make them blocking, but they're real defense-in-depth wins.

### 1.1 M&D-backed PIN counters for OpenPGP PW1 / PW3 / RC

**Status:** Deferred from M6.B per `phase7_m3_h6_deferral.md` + this M6
close decision.

Phase 7 ships software-only PIN retry counters (R-mem cache + SHA-256
hash, decremented in firmware). A firmware-reflash attacker can bypass
the counter and brute-force PINs offline.

Phase 8 adds MAC-and-Destroy-backed retries — wrong PIN attempts
physically consume TROPIC01 chip slots; after N wrong attempts the
slots are gone at the silicon level and PIN entry is permanently
blocked until factory reset.

**Implementation sketch (~600 LOC):**

- Extract `pin_md_kernel` from existing `firmware/src/fido_hid/pin_md.c`
  (Phase 5). Parameterize on (M&D slot base, ROUNDS, R-mem accessor
  callbacks). Phase 5's existing FIDO PIN scheme becomes a thin wrapper.
- New `firmware/src/openpgp/openpgp_pin_md.c` with 3 PIN-specific
  wrappers using M&D slots 8-16 (3 slots × 3 PINs).
- New R-mem slot 2 schema for the M&D state (~390 B total).
- Integrate into `pgp_pin.c`: VERIFY calls M&D first, then software
  counter (M&D wins on lockout decision).
- HW-in-the-loop validation cycle: confirm wrong PINs consume chip
  slots (`slots-debug` tool).

**Acceptance:** wrong PW3 nine times → all 9 chip slots gone → only
TERMINATE+ACTIVATE+re-init recovers. Hand-validate via `slots-debug`.

### 1.2 M&D-KEK wrap for X25519 dec priv key

**Status:** Deferred from M6.C per M6 close decision.

The X25519 dec key for `gpg --decrypt` lives in R-mem slot 1 byte
180-211 (Trezor Safe 7 pattern). Anyone with SH0 + L3 session can read
it. Phase 8 wraps it with a PW1-derived KEK released only via M&D —
mirrors Trezor's PIN-encrypted-seed design.

**Implementation sketch (~200 LOC + shared M&D framework with §1.1):**

- KEK = HMAC(PW1-hash, M&D-derived-secret)
- Stored ciphertext = AES-GCM(dec_priv, KEK)
- On `PSO:DEC`: verify PW1 (consumes M&D slot via §1.1), derive KEK,
  decrypt priv, perform ECDH, zeroize all on return.

Shares M&D framework with §1.1 — implement them together.

### 1.3 Phase 6 cpp-reviewer deferred MEDIUMs

Per `project_phase6_done.md`: "2 MEDIUMs deferred to Phase 8". Re-read
the Phase 6 audit report from STATUS.md, address what still applies.

---

## 2. WebAuthn / FIDO2 polish

### 2.1 credProps extension (~30 LOC)

Fixes the "unknown discoverability" label in RP UIs (webauthn.io shows
`device-bound credential of unknown discoverability`). See
`docs/WEBAUTHN-NOTES.md §5`. Already documented + scoped.

### 2.2 Brave / Chromium / Linux WebAuthn detection

Brave's WebAuthn modal greys out our device on Linux even though
libfido2 + Firefox work fine. Chromium does its own FIDO HID detection
that differs from libfido2's. See `docs/WEBAUTHN-NOTES.md §8`.

Investigation pending — likely needs a Chromium-side patch OR a HID
descriptor tweak. Lower priority since Firefox works.

### 2.3 hidraw udev rule for FIDO

Per `docs/WEBAUTHN-NOTES.md §7`: udev's auto-rule sometimes doesn't tag
our FIDO HID interface with `security-device`. Permanent fix = add the
rule to `nixos/tropic.nix`.

---

## 3. Configurable policies (Yubikey-class)

Captured in `project_configurable_pin_touch_policies.md` memory note.

### 3.1 authenticatorConfig (CTAP2.1 command 0x0D)

Runtime toggles for Force-UV / alwaysUv / etc. Currently all options
are compile-time. CTAP2.1 §6.11 spec. Requires PIN auth.

### 3.2 credProtect per-credential UV

Per-credential UV requirement (CTAP2.1 §11.1.2). Some RPs (Google,
Microsoft) request `credProtect: 3` for high-value credentials.

### 3.3 PIN protocol v2 token permissions

Scope-limited PIN tokens — token authorizes only specific operations
(e.g. credential management read but not delete). CTAP2.1 §6.5.5.7.

### 3.4 OpenPGP per-slot touch policy

Yubikey-style: per-key "always require touch on sig", "always require
touch on dec", "cached (1 touch per session)", "off". Maps to OpenPGP
DOs D6/D7/D8.

---

## 4. OpenPGP card polish

### 4.1 gpg --card-status display anomaly verification

Per `phase7_m6_d_display_anomalies.md`: post-M6-flash, run
`gpg-connect-agent "SCD RESTART"` then `gpg --debug 0x0009
--card-status` to capture the trace. Confirm whether "Max. PIN
lengths: 0 0 0" and "PIN retry: 0 0 0" actually resolved post-flash
(expected: yes, because the schema bump forced clean defaults).

If anomalies persist, file an upstream gnupg bug with the captured
trace. Otherwise mark issue closed.

### 4.2 AID manufacturer ID cosmetic

`gpg --card-status` shows "Manufacturer: unknown" because `0x4E58`
("NX") isn't in gnupg's hardcoded table. Options:

1. Keep `0x4E58` — accept cosmetic display
2. Swap to `0xFF02` for spec-defined "unmanaged S/N range" label
3. Patch upstream gnupg to recognize `0x4E58` as "nixtropic"

Option 2 is one-line change; would invalidate any user's existing
state and require re-init via TERMINATE+ACTIVATE.

### 4.3 Default language pref

`write_activated_defaults` zeroes `OFF_LANG`. Could optionally write
`'e' 'n'` so `gpg --card-status` shows "Language: en" out of the box.
Trivial.

### 4.4 PIV applet (Phase 7b)

PROJECT.md §6 lists "Phase 7b: PIV (alongside or instead of OpenPGP
card)" as a future option. Decision: ship after Phase 7 uptake data.
Would add `pkcs11` + Windows smartcard logon use cases.

`firmware/src/ccid/apdu_dispatch.c` already has the comment "When
Phase 7b adds PIV, the dispatcher will route on the SELECT'd applet's
AID; for now there's only one applet" — code is structured to accept
a second applet.

### 4.5 Phase 7 close documentation

- `docs/PHASE-7-RECOVERY.md` — daily-driver setup guide from
  `phase7_readme_source_material.md` memory note.
- Update `STATUS.md` with Phase 7 close entry.
- Update `PROJECT.md` §2 (decision log) with final Phase 7 architecture.

---

## 5. Publishing / Nixpkgs upstreaming

### 5.1 Nixpkgs upstream PR

Per PROJECT.md "Future": "Phase 8 (or later) will upstream". Package
metadata: firmware as fixed-output, lt-util as a library, NixOS module.

### 5.2 pid.codes VID:PID allocation

Currently using `cafe:4001` (TinyUSB demo VID:PID). For public release
get a pid.codes allocation (free for open hardware). Then submit
upstream PR to libccid to add the new VID:PID to its known-readers
list — eliminates the runtime Info.plist patch.

### 5.3 TROPIC01 TRNG SP 800-90B compliance

Per PROJECT.md §13 open question: before any public production /
security claims, verify TRNG entropy against SP 800-90B. Tropic Square
App Note `ODN_TR01_app_008` documents the chip's TRNG architecture.

### 5.4 Phase 8 polish: Nix flake / NixOS module / CLI

Per PROJECT.md §6 Phase 8 scope. Includes a Rust CLI for direct
dongle control (separate from `lt-util`). Currently `nixtropic/` is
mentioned as the planned location.

---

## 6. Bug followups + maintenance

### 6.1 picocom termios hang on TinyUSB CDC

Per task #27 — SET_LINE_CODING race when picocom opens our CDC
interface. Workaround documented; underlying fix in TinyUSB
upstream pending.

### 6.2 Validate scripts: substring matching for `--reader`

Per `feedback_atr_must_match_declared_interface_bytes.md` lesson —
older opensc-tool versions don't support substring matching on
`--reader nixtropic`; current scripts pin `--reader 0` to avoid this.
Phase 8: detect opensc-tool version + fall back to substring when
supported.

---

## 7. Performance / flash budget

Phase 7 M6 close: firmware.bin = 217096 B / 256 KB (82.81%).

Headroom: ~40 KB. Easily fits §1.1 + §1.2 M&D additions (~5-8 KB
together). PIV applet (§4.4) is the budget-aware addition; would add
~15-25 KB.

If we exceed budget post-Phase 8, options:

- Drop `USE_PRECOMPUTED_CP=0` (P-256 base point caching) — current
  setting saves 74 KB at the cost of ECDH speed; could trade some back.
- Move trezor_crypto's `nist256p1.c` precomputed table to flash-stored
  blob with on-demand access (would slow + complicate ECDH).
- Strip unused libtropic functions via LTO + `-fdata-sections`.

---

## Out of scope for Phase 8

These came up but explicitly belong elsewhere:

- **Other TROPIC01 dev kits** (RPi shield, Arduino shield) — this
  project is TS1302-specific.
- **RSA support** — locked out per `project_phase7_ecc_only_lock.md`
  (flash budget). Users who need RSA have other devices.
- **FIDO Alliance AAGUID registration** — `$25k/year` not viable for
  open-source per `project_aaguid_policy.md`.

---

**This document is the Phase 8 plan kernel.** Before starting Phase 8
in earnest, draft `docs/PHASE-8-PLAN.md` from this backlog (priority +
ordering + HW checkpoint plan). Items here may be redistributed across
multiple Phase 8 milestones or split off into Phase 9.
