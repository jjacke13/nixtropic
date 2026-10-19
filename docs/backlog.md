# Backlog

Open work items beyond the current release.  Items are grouped by
theme; ordering within a section is rough priority (highest first) but
most items are independent.  The larger Phase 10 themes are on the
[roadmap](roadmap.md).  Section numbers are referenced from code comments,
so they stay stable; finished items stay with their outcome.

---

## 1. Audit-driven hardening (highest priority)

Real defense-in-depth wins deferred because the original threat model
didn't make them blocking.

### 1.1 M&D-backed PIN counters for OpenPGP PW1 / PW3 / RC — ✅ DONE (Phase 8 M4)

Phase 8 moved the OpenPGP PIN counters onto MAC-and-Destroy (`561e040`). Phase 9 M4
replaced that layout: all PINs are now M&D kernel v2 bindings in mirrored record pairs,
with no software PIN check (current layout in
[architecture](architecture.md#persistent-state)). Hardware check:
`tools/validate-pin-md.sh`.

### 1.2 M&D-KEK wrap for X25519 dec priv key — ✅ DONE (Phase 9 M5)

Done differently from the sketch below: KEK = HMAC(k, label), k from the PW1 M&D
binding; AES-256-GCM; KEK cached while PW1 is verified.  See
[security model](security.md#the-openpgp-decryption-key).  Original note (historical):

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


### 2.3 ES256 (P-256) credentials — DONE (Phase 9 M3b, 2026-10-15)

Done: GetInfo lists EdDSA and ES256, and MakeCredential takes the first the site
offers. P-256 keys are generated and used inside TROPIC01 (COSE EC2 keys, DER
signatures, the algorithm stored in the slot metadata, one shared 29-credential cap).
RS256 stays unsupported.

### 2.4 Claim FIDO_2_1

Needs hmac-secret, credProtect (3.2) and PIN/UV auth protocol 2 (HKDF,
AES-CBC with random IV, full HMAC) — CTAP 2.1 §9.

### 2.5 Store the RP ID text

credMgmt shows each RP as the hex of its hash: only rpIdHash is stored.

---

## 3. Configurable policies (Yubikey-class)

### 3.1 authenticatorConfig (CTAP2.1 command 0x0D) — ✅ DONE (Phase 9 M3, toggleAlwaysUv)

`fido2-token -S -u` / `-D -u`.  Not implemented: setMinPINLength,
enableEnterpriseAttestation (both optional).

### 3.2 credProtect per-credential UV

Per-credential UV requirement (CTAP2.1 §11.1.2).  Some RPs (Google,
Microsoft) request `credProtect: 3` for high-value credentials.

### 3.3 Token permissions — ✅ DONE (Phase 9 M3)

getPinUvAuthTokenUsingPinWithPermissions (0x09), `pin_token.c`.  PIN/UV
auth protocol 2 is still open (see 2.4).

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

### 5.3 TROPIC01 TRNG SP 800-90B compliance — vendor claim found (v0.3.0)

The datasheet and `ODN_TR01_app_008` state NIST SP 800-90B and AIS 31
compliance for the chip's two TRNGs.  That is a vendor claim, not a
certification of this device or of nixtropic's entropy path; reopen only
for an independent assessment.  The RNGTEST_DIS erratum (2026-09-10) is
unresolved, see the [security model](security.md#part-status-and-errata).

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
Phase 9 M1 changed the release layout (HID + CCID only, device class 0,
no IAD). Re-verified 18 Oct 2026 on Windows 11: enumeration and the OpenPGP card
work; FIDO2 with a PIN needs 6.7.

### 6.4 Debug console loses the boot banner (Phase 9 M1)

The three `#` banner lines are printed before the host configures the
device; TinyUSB clears the CDC TX FIFO when the interface opens, so only
the later init log reaches `/dev/ttyACM0`.  Debug build only.  Fix if
ever needed: print the banner from `tud_mount_cb`, or after boot.

### 6.5 README / docs still describe the v0.2 composite layout — ✅ DONE (v0.3.0)

README and docs/UBUNTU.md mentioned the CDC + lt-rpc interfaces as if always
present, and Force-UV was toggled with `lt_rpc.py`, which the release build
no longer has (M3: `fido2-token -S -u` / `-D -u`).  Fixed: the documentation
was rewritten for v0.3.0 ([card setup](card-setup.md), [flashing](flashing.md)).

### 6.6 Requests interleave during a touch wait — ✅ DONE (Phase 9 M3, design decision 18)

`user_presence_check()` pumps `tud_task()` while it waits for SW1.  CTAPHID
refuses other FIDO requests then, but a CCID APDU is processed right away,
so OpenPGP chip operations can run between the chip calls of a waiting FIDO
request, and FIDO between OpenPGP's (`openpgp_applet.c` also waits for
touch).  Not inside a libtropic call, so the L3 session logic (M2) is not
affected.  Define a dispatch policy covering both directions, nested touch
waits, the shared consent state, and the debug lt-rpc.  Found by Jan in the
M2 review; plan it with the M3 FIDO work.

Fixed: requests run from the main loop, never inside a USB callback; one
request and one touch wait at a time.

### 6.7 CTAPHID KEEPALIVE and reply backpressure — ✅ DONE (v0.3.1)

Windows abandoned silent requests (getPinUvAuthToken after 2.6 s, changePIN after
6.6 s; usbmon, 18 Oct 2026). v0.3.1 sends KEEPALIVE from a progress function called
before every chip call and in the touch-wait loop, answers INIT resync and CANCEL during
a request, queues one-packet replies when the IN endpoint is busy, and holds the debug
lt-rpc while FIDO2 runs. Design: `docs/history/V0.3.1-KEEPALIVE-DESIGN.md`. Verified on
Windows 11 with captures (19 Oct 2026; longest silence 240 ms) and in the
[testing](testing.md#keepalive-timing) timings. Left over: the PIN operations and Reset
reach ~250 ms because the software P-256 steps cannot be interrupted (CTAP's SHOULD is
100 ms). The precomputed P-256 table would speed them up but needs about 74 KB of flash,
more than the headroom (§7). The `alwaysUv` question is 6.10. The
Protocols section is in [references](references.md#protocols).

### 6.8 Retire superseded test suites

`fido2_test.py validate-phase6-m2/m3` assume lt-rpc Force-UV, legacy-token
credMgmt and 32 slots; `tools/validate_fido_m3.py` replaces them (M6 cleanup).

---

### 6.9 Phase 9 M4 follow-ups

- A host that never reads a stale CCID answer still stalls CCID (Jan, f05e63b); libccid
  does read it.  Revisit if another PC/SC stack shows it.
- FIDO boot after a transient chip error: FIDO refuses until power-up (OpenPGP retries
  its boot up to 3 times per power cycle).
- OpenPGP VERIFY ≈ 1.4 s: record-pair writes dominate.  Moving the signature counter to
  a chip monotonic counter removes one O3 write per signature.
- `validate-openpgp.sh` needs `pcsc_scan`: run it as `nix run .#validate-openpgp` (the
  dev shell lacks it).

### 6.10 alwaysUv after the first PIN — decision open

Setting the first FIDO2 PIN after a reset also turns on alwaysUv (`fido_pin_set` →
`slots_set_pin_bound(1, 1)`, Phase 6 design). That is why GetInfo reported alwaysUv on
after the 18 Oct Windows session: Windows Settings reset the key and set a new PIN.
Options: keep it (documented in [Windows](windows.md#fido2-with-a-pin)), or leave
alwaysUv alone on the first PIN so the site decides. A security-behaviour change, so not
in a bug-fix release; the owner decides.

## 7. Performance / flash budget

v0.3.1 release `firmware.bin` = 223 364 B / 256 KB (85 %), about 38 KB of headroom
(the M5 decryption-key wrap cost about 1.3 KB; v0.3.1 KEEPALIVE about 0.2 KB).

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
