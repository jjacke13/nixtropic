# Backlog

Open work items beyond the current ship state.  Items are grouped by
theme; ordering within a section is rough priority (highest first) but
most items are independent.

---

## 1. Audit-driven hardening (highest priority)

Real defense-in-depth wins deferred because the original threat model
didn't make them blocking.

### 1.1 M&D-backed PIN counters for OpenPGP PW1 / PW3 / RC

OpenPGP currently ships software-only PIN retry counters (R-mem cache
+ SHA-256 hash, decremented in firmware).  A firmware-reflash attacker
can bypass the counter and brute-force PINs offline.

Add MAC-and-Destroy-backed retries: wrong PIN attempts physically
consume TROPIC01 chip slots; after N wrong attempts the slots are
gone at the silicon level and PIN entry is permanently blocked until
factory reset.

**Implementation sketch (~600 LOC):**

- Extract `pin_md_kernel` from existing `firmware/src/fido_hid/pin_md.c`.
  Parameterize on (M&D slot base, ROUNDS, R-mem accessor callbacks).
  Existing FIDO PIN scheme becomes a thin wrapper.
- New `firmware/src/openpgp/openpgp_pin_md.c` with 3 PIN-specific
  wrappers using M&D slots 8-16 (3 slots × 3 PINs).
- New R-mem slot 2 schema for the M&D state (~390 B total).
- Integrate into `pgp_pin.c`: VERIFY calls M&D first, then software
  counter (M&D wins on lockout decision).
- HW-in-the-loop validation: confirm wrong PINs consume chip slots.

**Acceptance:** wrong PW3 nine times → all 9 chip slots gone → only
TERMINATE+ACTIVATE+re-init recovers.

### 1.2 M&D-KEK wrap for X25519 dec priv key

The X25519 dec key for `gpg --decrypt` lives in R-mem slot 1 byte
180-211 (Trezor Safe 7 pattern).  Anyone with SH0 + L3 session can
read it.  Wrap it with a PW1-derived KEK released only via M&D —
mirrors Trezor's PIN-encrypted-seed design.

**Implementation sketch (~200 LOC + shared M&D framework with §1.1):**

- KEK = HMAC(PW1-hash, M&D-derived-secret)
- Stored ciphertext = AES-GCM(dec_priv, KEK)
- On `PSO:DEC`: verify PW1 (consumes M&D slot via §1.1), derive KEK,
  decrypt priv, perform ECDH, zeroize all on return.

Shares M&D framework with §1.1 — implement them together.

### 1.3 cpp-reviewer audit followups

The Phase 6 cpp-reviewer audit caught 2 MEDIUMs that were tagged as
deferred.  Re-read the audit report (in `archive/phases-1-7` branch
STATUS.md entry) and address what still applies post-Phase-7.

---

## 2. WebAuthn / FIDO2 polish

### 2.1 credProps extension (~30 LOC)

Fixes the "unknown discoverability" label in RP UIs (webauthn.io
shows `device-bound credential of unknown discoverability`).  See
`docs/WEBAUTHN-NOTES.md §5`.

### 2.2 Brave / Chromium / Linux WebAuthn detection

Brave's WebAuthn modal greys out our device on Linux even though
libfido2 + Firefox work fine.  Chromium does its own FIDO HID
detection that differs from libfido2's.  See
`docs/WEBAUTHN-NOTES.md §8`.  Likely needs a Chromium-side patch OR
a HID descriptor tweak.  Lower priority since Firefox works.

### 2.3 hidraw udev rule for FIDO

Per `docs/WEBAUTHN-NOTES.md §7`: udev's auto-rule sometimes doesn't
tag our FIDO HID interface with `security-device`.  Permanent fix =
add the rule to `nixos/tropic.nix`.

---

## 3. Configurable policies (Yubikey-class)

### 3.1 authenticatorConfig (CTAP2.1 command 0x0D)

Runtime toggles for Force-UV / alwaysUv / etc.  Currently all options
are compile-time.  CTAP2.1 §6.11.  Requires PIN auth.

### 3.2 credProtect per-credential UV

Per-credential UV requirement (CTAP2.1 §11.1.2).  Some RPs (Google,
Microsoft) request `credProtect: 3` for high-value credentials.

### 3.3 PIN protocol v2 token permissions

Scope-limited PIN tokens — token authorizes only specific operations
(e.g. credential management read but not delete).  CTAP2.1 §6.5.5.7.

### 3.4 OpenPGP per-slot touch policy

Yubikey-style: per-key "always require touch on sig", "always require
touch on dec", "cached (1 touch per session)", "off".  Maps to OpenPGP
DOs D6/D7/D8.

---

## 4. OpenPGP card polish

### 4.1 gpg --card-status display anomaly verification

Post-flash, run `gpg-connect-agent "SCD RESTART"` then
`gpg --debug 0x0009 --card-status` to capture the trace.  Confirm
whether "Max. PIN lengths: 0 0 0" and "PIN retry: 0 0 0" actually
resolved post-flash (expected: yes, because the schema bump forced
clean defaults).  If anomalies persist, file an upstream gnupg bug
with the captured trace.

### 4.2 AID manufacturer ID cosmetic

`gpg --card-status` shows "Manufacturer: unknown" because `0x4E58`
("NX") isn't in gnupg's hardcoded table.  Options:

1. Keep `0x4E58` — accept cosmetic display
2. Swap to `0xFF02` for spec-defined "unmanaged S/N range" label
3. Patch upstream gnupg to recognize `0x4E58` as "nixtropic"

Option 2 is one-line change but invalidates existing card state and
requires TERMINATE+ACTIVATE.

### 4.3 Default language pref

`write_activated_defaults` zeroes `OFF_LANG`.  Could optionally write
`'e' 'n'` so `gpg --card-status` shows "Language: en" out of the box.
Trivial.

### 4.4 PIV applet

A second smartcard applet (alongside OpenPGP) adding `pkcs11` +
Windows smartcard logon use cases.  `firmware/src/ccid/apdu_dispatch.c`
is structured to accept a second applet — just needs AID-based
routing wired in.

---

## 5. Publishing / Nixpkgs upstreaming

### 5.1 Nixpkgs upstream PR

Package metadata: firmware as fixed-output, lt-util as a library,
NixOS module.

### 5.2 pid.codes VID:PID allocation

Currently using `cafe:4001` (TinyUSB demo VID:PID).  For public
release get a pid.codes allocation (free for open hardware), then
submit upstream PR to libccid to add the new VID:PID to its
known-readers list — eliminates the runtime Info.plist patch.

### 5.3 TROPIC01 TRNG SP 800-90B compliance

Before any public production / security claims, verify TRNG entropy
against SP 800-90B.  Tropic Square App Note `ODN_TR01_app_008`
documents the chip's TRNG architecture.

### 5.4 Rust CLI

Direct dongle control beyond what `lt-util` provides — credential
enumeration, FIDO reset, OpenPGP card init, validate orchestration.

---

## 6. Bug followups + maintenance

### 6.1 picocom termios hang on TinyUSB CDC

SET_LINE_CODING race when picocom opens our CDC interface.
Workaround documented; underlying fix in TinyUSB upstream pending.

### 6.2 Validate scripts: substring matching for `--reader`

Older `opensc-tool` versions don't support substring matching on
`--reader nixtropic`; current scripts pin `--reader 0` to avoid this.
Detect opensc-tool version + fall back to substring when supported.

---

## 7. Performance / flash budget

Current `firmware.bin` = 217096 B / 256 KB (82.81%).  ~40 KB headroom.

§1.1 + §1.2 M&D additions: ~5-8 KB together (fits comfortably).
PIV applet (§4.4): ~15-25 KB (also fits).

If we exceed budget:

- Drop `USE_PRECOMPUTED_CP=0` (P-256 base point caching) — current
  setting saves 74 KB at the cost of ECDH speed; could trade some back.
- Move trezor_crypto's `nist256p1.c` precomputed table to flash-stored
  blob with on-demand access (slower + more complex ECDH).
- Strip unused libtropic functions via LTO + `-fdata-sections`.

---

## Out of scope

These come up regularly but belong elsewhere:

- **Other TROPIC01 dev kits** (RPi shield, Arduino shield) — this
  project is TS1302-specific.
- **RSA support** — locked out by flash budget.  Users who need RSA
  have other devices.
- **FIDO Alliance AAGUID registration** — $25k/year not viable for
  an open-source project.
