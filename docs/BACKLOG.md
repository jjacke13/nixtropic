# Backlog

Open work items beyond the current ship state.  Items are grouped by
theme; ordering within a section is rough priority (highest first) but
most items are independent.

---

## 1. Audit-driven hardening (highest priority)

Real defense-in-depth wins deferred because the original threat model
didn't make them blocking.

### 1.1 M&D-backed PIN counters for OpenPGP PW1 / PW3 / RC — ✅ DONE (Phase 8 M4)

Landed in commits leading up to `561e040` (schema PG7R).  `pin_md_kernel`
extracted to `firmware/src/tropic/pin_md_kernel.{c,h}`; OpenPGP wrappers
live in `firmware/src/openpgp/openpgp_pin_md.{c,h}` using M&D slots 8-16
and R-mem slots 50/51/52 (per-PIN state).  `pgp_pin.c` VERIFY routes
through M&D first.  Bootstrap path wipes M&D state on schema bump to
avoid PIN brick.  Acceptance verified by `tools/validate-pin-md.sh`.

### 1.2 M&D-KEK wrap for X25519 dec priv key

The X25519 dec key for `gpg --decrypt` lives in R-mem slot 1 byte
180-211 (Trezor Safe 7 pattern).  Anyone with SH0 + L3 session can
read it.  Wrap it with a PW1-derived KEK released only via M&D —
mirrors Trezor's PIN-encrypted-seed design.

**Implementation sketch (~200 LOC, reuses landed M&D framework):**

- KEK = HMAC(PW1-hash, M&D-derived-secret) — `pin_md_kernel` already
  exposes the M&D-derived-secret hook needed for this.
- Stored ciphertext = AES-GCM(dec_priv, KEK)
- On `PSO:DEC`: verify PW1 (consumes M&D slot via §1.1's landed
  wrappers), derive KEK, decrypt priv, perform ECDH, zeroize all on
  return.

§1.1's framework already landed in Phase 8 M4, so this is unblocked.

### 1.3 cpp-reviewer audit followups

The Phase 6 cpp-reviewer audit caught 2 MEDIUMs that were tagged as
deferred.  Re-read the audit report (in `archive/phases-1-7` branch
STATUS.md entry) and address what still applies post-Phase-7.

---

## 2. WebAuthn / FIDO2 polish

### 2.1 credProps extension — ✅ DONE (Phase 8 M2)

Landed in commit `bcff8fb`.  CTAP2 MakeCredential now parses incoming
`extensions.credProps` request and emits the `rk` flag in the
attestation extension map.  webauthn.io shows
`device-bound credential of unknown discoverability` no more.

### 2.2 hidraw udev rule for FIDO — ✅ DONE (Phase 8 M1)

Landed in commit `bcff8fb`.  `nixos/tropic.nix` now installs a udev
rule tagging `cafe:4001` with `ID_SECURITY_TOKEN=1` + group access
to `plugdev`, so libfido2 / browsers see the dongle without a
manual rule.

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

### 3.4 OpenPGP touch policy — ✅ PARTIAL (Phase 8 M3, GLOBAL only)

Landed in commit `98486f4` + `bcff8fb`.  Global on/off touch toggle
implemented and enforced in PSO:CDS, PSO:DEC, INTERNAL_AUTHENTICATE.
Defaults to ON (user-presence required for every signing op).

**Still TODO — per-slot policy + cached mode:** Yubikey-style
per-key granularity (sig / dec / aut independent) and the "cached
(1 touch per session)" mode.  Maps to OpenPGP DOs D6/D7/D8 properly.
Current impl is one boolean for all 3 slots.

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

### 4.5 OpenPGP attestation slot (Yubikey-compat)

Yubikey 5.2.3+ adds a vendor extension: an extra "attestation" key
slot beyond the standard 3 (sig/dec/aut).  Verified at runtime by
`ykman openpgp keys attest <slot>` — the device signs a statement
that the user-facing key was generated on-device (not imported), and
the resulting X.509 attestation is rooted in a Yubico-issued CA cert.
Useful for compliance scenarios that must distinguish HW-generated
keys from imported ones.

What it needs on our side:
- One more TROPIC01 ECC slot (we have headroom — slot 28 or repurpose
  one FIDO slot, since 29 FIDO creds is generous).
- An on-device-burned attestation CA (Ed25519 key + cert), or
  per-device unique attestation key signed at provisioning.
- Vendor APDU INS 0xF1 (Yubikey-compat) returning the X.509 cert
  chain.
- `ykman` / `gpg --card-edit` interop testing.

References:
- https://developers.yubico.com/PGP/Attestation.html
- Yubikey docs:
  https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps.html

Cost: ~1 KB flash + 1 ECC slot + one-time provisioning step.

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

### 6.3 Windows compatibility pass

Runtime use (FIDO2, OpenPGP, CDC) should auto-bind via in-box Win10/11
class drivers.  Needs: scdaemon.conf docs (same `disable-ccid + pcsc-shared`
as Linux, via Gpg4win), DFU flashing recipe (Zadig + dfu-util OR
STM32CubeProgrammer), README "Windows setup" section, HW-in-the-loop
verification on Win10 22H2 + Win11.  No firmware changes expected.

---

## 7. Performance / flash budget

Current `firmware.elf` text = 218856 B / 256 KB (83.5%) post-Phase-8
(M&D PIN counters + global touch + credProps + udev rule landed).
~37 KB headroom.

§1.2 M&D-KEK wrap for X25519 dec priv key: ~3-5 KB (shares framework
with the already-landed §1.1 wrappers).
PIV applet (§4.4): ~15-25 KB (also fits).
Attestation slot (§4.5): ~1 KB.

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
