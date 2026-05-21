# Phase 8 — Plan

Status: planning.  No code shipped yet.  This document is the contract.

The intent of Phase 8 is to clear the [`docs/BACKLOG.md`](BACKLOG.md)
items in dependency order, lowest-risk first, with explicit TROPIC01
brick-avoidance rules called out for every item that goes near chip
state.

The Phase 5 / 6 / 7 milestone format is preserved: each item carries
plan → implementation → HW-in-the-loop validation → cpp-reviewer audit
→ STATUS / PROJECT / memory updates.  Two items have already been
closed during the Phase 8 ramp-up (see "Already shipped" below); the
rest are sequenced here.

---

## 0. Chip-side guard rails (READ FIRST every time)

Every item below MUST honour these rules.  Most of them came out of
PROJECT.md §5 and `research/tropic01-inventory.md` §10 — re-derived
here so a fresh contributor doesn't re-discover them the hard way.

1. **NEVER call `lt_r_config_write` without first calling
   `lt_r_config_erase`.**  Erratum `OI_TR01_ERR_2026010800` (2026-01-08)
   permanently puts the chip into Alarm Mode = brick.  No recovery.
   Use `lt_write_whole_R_config` if you have to touch R-config at all.
   *We currently do not touch R-config from firmware* — only the
   factory provisioner does.  Keep it that way for Phase 8.

2. **NEVER call `lt_pairing_key_invalidate` until SH1 is set up.**
   Invalidation is one-way.  Today only SH0 (default key) is in use;
   invalidating it bricks the dongle from gpg's standpoint.

3. **R-mem slot size = 475 B on App FW ≥ 2.0.0** (we are on App FW
   2.0.0 since the `chip-fw-version` / `fw-update-chip` rollout).  All
   current uses pack into 256 B for backward compatibility — Phase 8
   M&D state is on the edge and will use the full 475 B if needed.

4. **MAC-and-Destroy slots are consumed on every call**, success or
   failure.  A correct PIN consumes one slot AND must re-init the
   slot it consumed (and any slots consumed by prior wrong attempts);
   see `firmware/src/fido_hid/pin_md.c::pin_md_verify` for the
   canonical state machine.

5. **Operating temperature for I-Memory writes is -20 to +85 °C
   only.**  FW ≥ 2.0.0 returns an error outside that range.  Pairing
   keys, I-config, and FW updates all hit I-Memory.  R-Memory is the
   full industrial range so all Phase 8 work that only touches R-mem
   is fine.

6. **Schema bumps wipe all PGP state.**  The bump pattern is
   `PG7N → PG7O → PG7P → …`; existing state cleared, PINs reset to
   defaults (`123456` / `12345678`), dec privkey gone (re-generate
   via `gpg --card-edit > admin > generate`).  This costs us a
   minute of `card-edit` after every firmware bump — acceptable
   since there is exactly one dongle in the world.

7. **Alarm Mode = brick.**  Trigger conditions: R-config write
   without prior erase, any active sensor in `CFG_SENSORS` firing
   (we never disable them), I-Memory write errors.  Detect via
   `lt_get_tr01_mode` returning `LT_TR01_ALARM`; treat as terminal.

8. **AES-GCM nonce overflow = restart session.**  `LT_NONCE_OVERFLOW`
   = 46 surfaces after `2³²` packets per L3 session.  Our session
   stays up across the entire dongle lifetime, so in principle we
   could hit it after ~136 years at 1 op/sec.  Not an immediate
   concern, but flagged here for completeness.

---

## 1. Already shipped during Phase 8 ramp-up

Two items from `docs/BACKLOG.md §4` landed before this plan was
written.  Both are pure-cosmetic gpg-side fixes — no chip-state
changes, no new R-mem schema (other than the lang default schema
bump).

### 1.1 ✅ `gpg --card-status` display anomaly (BACKLOG §4.1)

**Commit `74720a5`** — DOs `5E` (LOGIN-DATA) and `5F50` (PUBKEY-URL)
were returning `SW=6A88` (Reference data not found).  scdaemon's
`do_learn_status` chains `do_getattr` with `if (!err)`, so the
`GPG_ERR_NO_OBJ` propagated by `iso7816_get_data` aborted the whole
chain — KEY-FPR / KEY-TIME / CA-FPR / CHV-STATUS / SIG-COUNTER were
never queried.  `gpg --card-status` then displayed defaults
(`[none]` for keys, `0 0 0` for PINs).  Fix: return `SW=9000` with
empty body for both DOs.

### 1.2 ✅ Default Language pref (BACKLOG §4.3)

**Commit `48763f2`** — `write_activated_defaults` zeroed `OFF_LANG`,
so `gpg --card-status` showed `\xff\xff`.  Now writes ASCII `"en"`
into bytes 54..55 on init.  Required a schema bump
PG7N → PG7O / v2 → v3 because the new default only fires on
magic-mismatch.  Existing dongles lose state on first boot of the
new firmware — fine for our single-dongle world.

### 1.3 ✅ Validate-script discovery in nix-store (BACKLOG §6.2 adjacent)

**Commit `fb1e260`** — `nix run .#flash-and-validate` was importing
each script via `${../tools/validate.sh}`, which materialised as a
sibling-less file in `/nix/store/`.  The dispatcher's
`SCRIPT_DIR/validate-fido.sh` lookup failed.  Fix: import the entire
`tools/` directory as one path (`${../tools}/validate.sh`), so the
dispatcher's siblings are reachable.

### 1.4 ✅ Smart-card session bring-up docs

**Commit `24aabc5`** — README now documents the precise daemon
sequence after a flash / replug.  Resolves a long-standing user
confusion about why the first replug often fails and what to do
about it.  No code change.

---

## 2. M1 — `hidraw` udev rule for FIDO (BACKLOG §2.2)

**Tier**: tiny.  No firmware change.  ~10 LOC in `nixos/tropic.nix`.
**Risk**: zero — udev rule is additive.
**Why first**: clears a footgun that surfaces on Wayland sessions
where the systemd `security-device` tag doesn't get applied to our
HID interface.

### Plan

1. Add to `nixos/tropic.nix::services.udev.extraRules`:

   ```
   SUBSYSTEM=="hidraw", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", \
     GROUP="${cfg.groupName}", MODE="0660", TAG+="uaccess"
   ```

2. Verify with `udevadm info /dev/hidrawN | grep TAGS` after replug
   — should include `uaccess` (logind ACL).

3. Test FIDO2 register/auth on Firefox + Chromium (if any).

### Validation

Add a check to `tools/validate-fido.sh`: `udevadm info` on the FIDO
HID device reports `TAGS=...:uaccess:...`.

### Out-of-scope

(none — Chromium/Brave previously suspected as broken was a
host-side scdaemon-libusb claim wedge, not a Chromium FIDO HID
detection bug; closed once `disable-ccid` + `pcsc-shared` landed in
README §4.)

---

## 3. M2 — `credProps` extension (BACKLOG §2.1)

**Tier**: small.  ~30 LOC in `firmware/src/fido_hid/ctap2_creds.c`.
**Risk**: low — pure CBOR-encode additions, no state.
**Why next**: removes the "unknown discoverability" label that
appears on every webauthn.io demo (and similar RPs) since v0.1.

### Plan

1. In `MakeCredential` request parse, decode `extensions: {credProps:
   true}` if present.  Set a local `req_credProps = true` flag.

2. After credential creation, if `req_credProps`, append the
   extension result to the response CBOR:

   ```
   extensions: {
     credProps: { rk: <true if resident, else false> }
   }
   ```

   For our authenticator every credential is resident (we don't
   support non-discoverable creds because all credentials live in
   TROPIC01 R-mem with a stable index — there is no "memoryless"
   credential type).  So `rk` is always `true` for the moment.

3. Same handling in `GetAssertion` if the RP passes it (rare;
   spec-allowed).

4. Add a test to `tools/fido2_test.py` that requests `credProps` and
   asserts `rk: true` in the response.

### Validation

`tools/validate-fido.sh` is non-interactive — adding an interactive
test path here is acceptable since the existing FIDO suite already
uses real-touch in `fido2_test.py`.

### Notes

- `credProps` is a CLIENT extension per WebAuthn L3 §10.4 — the user
  agent (browser) is responsible for interpreting and surfacing it.
  But CTAP2.1 §11 requires authenticators that support discoverable
  credentials to surface the `rk` value back so the browser doesn't
  have to guess.  Browsers fall back to "unknown" when the
  authenticator stays silent.

- No flash impact (CBOR encode is already linked).

---

## 4. M3 — OpenPGP per-slot touch policy (BACKLOG §3.4)

**Tier**: medium.  ~80 LOC across `openpgp_state.c`, `openpgp_applet.c`.
**Risk**: low — adds three bytes to slot 1, schema bump.
**Why next**: Yubikey-class polish.  Lets the user pin the
authentication key to "always touch" while keeping `dec` cached
for `git commit -S` ergonomics, or vice versa.

### Plan

1. R-mem slot 1 currently has a single `touch_required` byte at
   offset 11.  Split into three:

   ```
   offset 11: touch_required_sig   (UIF DO D6)
   offset 12: touch_required_dec   (UIF DO D7)
   offset 13: touch_required_aut   (UIF DO D8)
   ```

   Three bytes.  Free space exists at offset 215..255 (41 B), so
   reusing 11..13 (currently 11 = touch_required, 12..13 reserved)
   needs no growth.

2. `openpgp_state_touch_required_get(slot_idx)` — takes 0/1/2 for
   sig/dec/aut.  Update `pgp_keys.c` and `ctaphid.c` callers.

3. PUT DATA C7 / C8 / C9 already write into per-key slots; add PUT
   DATA D6 / D7 / D8 to the dispatcher.  Each writes one byte
   `0x00` = off, `0x01` = on, `0x02` = fixed (we honour `fixed` =
   permanent on; can't be cleared without TERMINATE).

4. GET DATA D6 / D7 / D8 already routed; have it return the
   per-key value (2-byte response: `<value> 0x20`).

5. Schema bump PG7O → PG7P / v3 → v4.

### Validation

Manual: `gpg --card-edit > admin > toggle 1` flips D6 (sig).
`gpg --card-status` shows `UIF setting ...: Sign=on Decrypt=off
Auth=on`.  `git commit -S` then prompts SW1 every time; `gpg --
decrypt` cached.

Automated: extend `tools/validate-openpgp.sh` with PUT DATA D6 +
GET DATA D6 round-trip.

---

## 5. M4 — M&D-backed PIN counters for OpenPGP (BACKLOG §1.1)

**Tier**: large.  Estimated 600 LOC + R-mem schema bump.
**Risk**: medium — touches M&D state machine, which is
chip-destructive.  Each verify consumes an M&D slot whether the PIN
is right or wrong.
**Why this point in the sequence**: requires the FIDO `pin_md`
kernel to be extracted and parameterised (M4.A below).  Smaller
items above (M1..M3) don't need that refactor and ship first as
quick wins.

### M4.A — extract `pin_md_kernel`

Move the four core operations out of `firmware/src/fido_hid/pin_md.c`
into a new module `firmware/src/tropic/pin_md_kernel.{c,h}`:

```c
typedef struct pin_md_layout_t {
    uint8_t md_slot_base;        /* first TROPIC01 M&D slot */
    uint8_t rounds;              /* number of slots per PIN */
    /* R-mem accessors — caller-supplied */
    int (*read_state) (uint8_t  *active, uint8_t *next,
                       uint8_t   tag[32], uint8_t *ci);
    int (*write_state)(uint8_t   active, uint8_t  next,
                       const uint8_t tag[32], const uint8_t *ci);
    int (*advance)    (uint8_t  *out_new);
} pin_md_layout_t;

int pin_md_kernel_setup (const pin_md_layout_t *L,
                         const uint8_t pin_material[32]);
int pin_md_kernel_verify(const pin_md_layout_t *L,
                         const uint8_t pin_material[32],
                         int *out_correct);
int pin_md_kernel_factory_reset(const pin_md_layout_t *L);
```

FIDO `pin_md.c` becomes a thin wrapper that fills in a layout with
`md_slot_base=0, rounds=8` and the existing R-mem slot 0 accessors.

Acceptance: FIDO validation suite passes unchanged.

### M4.B — OpenPGP PIN-MD wrappers

New module `firmware/src/openpgp/openpgp_pin_md.{c,h}`:

```c
enum pgp_pin_idx { PGP_PIN_PW1 = 0, PGP_PIN_PW3, PGP_PIN_RC };

int pgp_pin_md_setup(enum pgp_pin_idx, const uint8_t hash[16]);
int pgp_pin_md_verify(enum pgp_pin_idx, const uint8_t hash[16],
                      int *out_correct);
int pgp_pin_md_factory_reset_all(void);
```

Slot allocation (`firmware/src/openpgp/openpgp_pin_md.h`):

```c
#define PGP_PIN_MD_SLOT_BASE_PW1   8u   /* M&D slots 8..10  */
#define PGP_PIN_MD_SLOT_BASE_PW3  11u   /* M&D slots 11..13 */
#define PGP_PIN_MD_SLOT_BASE_RC   14u   /* M&D slots 14..16 */
#define PGP_PIN_MD_ROUNDS          3u
```

Total M&D slots used so far:
- FIDO PIN: 0..7 (8 slots)
- OpenPGP PW1: 8..10
- OpenPGP PW3: 11..13
- OpenPGP RC : 14..16

Used / 128 available = 17 / 128.  Plenty of room.

### M4.C — R-mem slot 2 schema

New R-mem slot 2 ("PGP-MD") for the M&D state.  Layout (475 B
target, ~150 B used):

```
0..3      magic "PGM0"
4..5      schema_version = 1
6         pw1_md_active
7         pw1_md_next_slot
8..39     pw1_md_tag (32 B)
40..135   pw1_md_ci[ROUNDS=3] (3 × 32 = 96 B)
136..167  pw1_md_kek_blob — see M5 (32 B encrypted dec_priv KEK seed)
168..301  pw3_md_state (active + next + tag + ci) = 134 B
302..473  rc_md_state = 134 B
474..475  reserved
```

(Exact offsets fixed in implementation; the above is a sketch.)

Accessors mirror `slots_global_md_*` from FIDO side.

### M4.D — `pgp_pin.c` integration

Current `pgp_pin_verify` flow:

```
verify(pin, idx):
  1. compute hash = SHA-256(pin)[:16]
  2. read stored hash, retry counter from R-mem slot 1
  3. compare; on match → reset counter, return OK
  4. on miss → decrement counter, return BAD
```

New flow (PIN-MD-first):

```
verify(pin, idx):
  1. compute hash = SHA-256(pin)[:16]
  2. call pgp_pin_md_verify(idx, hash, &correct)
     - returns -2 if all M&D slots consumed (HW lockout)
     - returns 0 with correct=0/1 otherwise
  3. if HW lockout: SW=63C0 (no retries), return BLOCKED
  4. if correct=1: reset software counter, return OK
  5. if correct=0: decrement software counter, return BAD
```

The software counter (R-mem slot 1 offsets 7..9) stays as a quick
display-side counter; the M&D is the authoritative lockout.

### M4.E — Acceptance test

`tools/validate-openpgp.sh` extended:

- Enter wrong PW3 three times.  After third attempt, scdaemon reports
  PIN blocked at SW=63C0.
- Confirm chip side: read R-mem slot 2 PW3 `next_slot` == 3 (all
  three slots consumed).
- TERMINATE+ACTIVATE.  Confirm `pgp_pin_md_factory_reset_all` runs
  and slots re-init to fresh secrets.
- Set fresh PW3, enter correctly — slot 0 consumed, then re-init
  triggered by correct-PIN path; `next_slot` back to 0.

### Flash impact

PIN-MD kernel: shared with FIDO, marginal extra code.
PGP wrappers + state slot accessors: ~2-3 KB compressed.
Total: ~3-4 KB.  Comfortable.

### Schema bump

PG7O → PG7P (slot 1), no migration needed (PIN state stays the same
shape; existing software hashes still valid as `setup_pin_material`
input).  Slot 2 introduces "PGM0" magic; defaults to all-zero on
fresh init.

---

## 6. M5 — M&D-KEK wrap for X25519 dec privkey (BACKLOG §1.2)

**Tier**: medium.  ~200 LOC riding the M4 framework.
**Risk**: medium — incorrect wrap loses dec capability without
recovery path.
**Why now**: directly mitigates the firmware-reflash attack we
discussed.  Reflashing without the user's PW1 yields an attacker an
encrypted-and-useless dec privkey blob.

### Plan

1. On `setPin(PW1)` AND on `keygen(dec)`:
   - Derive `KEK = HMAC(PW1-hash, M&D-derived-secret-PW1)`.
   - `enc_dec_priv = AES-GCM(dec_priv, KEK)` (12 B IV + 16 B tag).
   - Store `enc_dec_priv` in R-mem slot 2 at `pw1_md_kek_blob`
     (M4.C above) — 32 + 12 + 16 = 60 B.  Adjust schema to fit.

2. On `PSO:DEC`:
   - Run `pgp_pin_md_verify(PW1)` — consumes an M&D slot, returns
     a copy of the M&D-derived secret.
   - Derive `KEK`, decrypt `dec_priv`, perform ECDH, zeroize.

3. On `changePIN(PW1)`:
   - Verify old PW1 → recover dec_priv → re-encrypt with new KEK
     from new PW1 + fresh M&D-derived secret → re-store.

### Acceptance

- Flash a stock-known-PIN dongle, then re-flash with fresh schema:
  PIN resets to defaults, dec privkey blob is in R-mem but
  attacker-supplied firmware can't decrypt it without the old PW1.
- `gpg --decrypt` round-trip works after user enters PW1.

---

## 7. M6 — `authenticatorConfig` (BACKLOG §3.1)

**Tier**: medium.  ~200 LOC in `ctap2.c`.
**Risk**: low — only modifies the R-mem flag we already store.
**Depends on**: PIN-protocol-v1 token (already implemented).

### Plan

1. Add CTAP2.1 cmd `0x0D authenticatorConfig` dispatch.  Subcommands:
   - `0x01 enableEnterpriseAttestation` — return CTAP2_ERR_UNSUPPORTED.
   - `0x02 toggleAlwaysUv` — flip `slots_force_uv_get/set`.
   - `0x03 setMinPINLength` — write a new minimum PIN length into
     R-mem slot 0 (new field at offset 32 — bump schema NX7K → NX8K
     to migrate FIDO state).

2. All subcmds require `pinUvAuthToken` with `authenticatorConfig`
   permission.

3. Add `setMinPINLength` to GetInfo response so RP can read current
   minimum.

### Acceptance

`fido2-token -c -m 6` (set min PIN length 6) succeeds with valid
pinUvAuthToken; subsequent `setPin` rejects 4-char PINs.

### Flash impact

CBOR dispatch + R-mem accessor: ~1 KB.

### Schema bump

NX7K → NX8K (FIDO global, R-mem slot 0).  Existing FIDO credentials
preserved (per-cred slots untouched); PIN state preserved (offsets
10..30 unchanged); only `min_pin_length` added at offset 32.  Wait
— schema bump still wipes state via the magic-mismatch path.  May
need to write an in-place migration (read PG7N state, copy fields
into PG7O layout) to preserve PIN.  Decide at implementation time.

---

## 8. M7 — `credProtect` per-credential UV (BACKLOG §3.2)

**Tier**: medium.  ~150 LOC.
**Risk**: low — adds a 2-bit field to per-credential R-mem entries.
**Depends on**: nothing.

### Plan

1. Add `credProtect` byte to `slot_meta_t` (currently in
   `firmware/src/fido_hid/slots.h`).  Values 1/2/3 per CTAP2.1
   §11.1.2; default 1 (`userVerificationOptional`).

2. `MakeCredential` parses the `credProtect` extension in the
   request; validates against advertised `minCredProtectLevel`;
   stores in per-credential R-mem entry.

3. `GetAssertion` reads `credProtect`; if level 3, requires UV
   regardless of RP request.  If level 2, requires UV unless the
   request supplies the credential ID directly.

4. Bump per-credential R-mem schema (currently "NXCR").  Schema
   migration: existing creds without credProtect default to level 1.

### Acceptance

webauthn.io advanced settings → `credProtect: 3` → register +
authenticate works with PIN; without PIN authenticate fails.

---

## 9. M8 — PIV applet (BACKLOG §4.4)

**Tier**: very large.  ~600-800 LOC + new R-mem slot for PIV state.
**Risk**: medium — second smartcard applet; AID dispatch wiring
must not break OpenPGP path.
**Depends on**: nothing.
**Why this point**: unlocks pkcs11 + Windows smartcard logon use
cases.  Big value, but isolated from FIDO + OpenPGP so we can defer
without blocking others.

### Plan

1. New module `firmware/src/piv/` with submodules mirroring
   `openpgp/`:
   - `piv_aid.{c,h}` — AID `A0 00 00 03 08 00 00 10 00 01 00`.
   - `piv_state.{c,h}` — R-mem slot 3 ("PIV0").
   - `piv_applet.{c,h}` — APDU handlers.

2. Wire AID-based routing in `firmware/src/ccid/apdu_dispatch.c`.
   The current dispatcher is hard-coded to OpenPGP; replace with
   table-driven dispatch on SELECT AID.

3. PIV slots map to TROPIC01 ECC slots:
   - `9A` PIV Authentication → ECC slot 24
   - `9C` Digital Signature → ECC slot 25
   - `9D` Key Management → ECC slot 26
   - `9E` Card Authentication → ECC slot 27

   (Slots 24..27 currently in the FIDO range 0..28; reserve via
   `FIDO_SLOTS_MAX` cap drop to 24.)

4. Implement:
   - SELECT AID
   - VERIFY (PIN)
   - CHANGE REFERENCE DATA
   - GET DATA (CHUID, CCC, X.509 certs per slot)
   - PUT DATA (admin)
   - GENERAL AUTHENTICATE (challenge/response signing)
   - GENERATE ASYMMETRIC KEY PAIR

5. Add PIN-MD wrappers (mirror OpenPGP from M4) for PIV PIN +
   PUK + Reset Code.  Three more M&D slot ranges:
   - PIV PIN: 17..19
   - PIV PUK: 20..22
   - PIV Reset Code: 23..25

   M&D slot usage total after PIV: 26 / 128.  Still fine.

### Acceptance

`piv-tool --list-readers` sees the dongle.  `piv-tool -g 9A`
generates a key.  `piv-tool -s 9A` signs.  Windows-side test
deferred until we have a Windows VM.

### Flash impact

~15-25 KB.  Within the ~40 KB headroom but tight.  If we hit the
limit, prune `--gc-sections` cruft from trezor-crypto (groestl,
blake2*, ripemd160 still in for hasher.c symbols even though we
never use them).

---

## 10. M9 — PIN protocol v2 token permissions (BACKLOG §3.3)

**Tier**: large.  ~400 LOC.
**Risk**: low — additive.
**Depends on**: nothing.
**Why deferred**: PIN protocol v1 covers every browser we care
about today; v2 is a polish item.

### Plan

1. Add PIN protocol v2 to GetInfo `pinUvAuthProtocols` (currently
   only v1).

2. Implement the v2 key-agreement variant (HKDF-SHA-256 instead of
   v1's SHA-256-then-AES-CBC).

3. Add per-token permissions bitmap (`mc`, `ga`, `cm`, `bio`,
   `lbw`, `acfg`).  Each ClientPIN GetPinUvAuthToken request
   asserts a permissions bitmap; the token authorizes only those
   ops.

4. Update `MakeCredential`, `GetAssertion`, `credentialManagement`,
   `authenticatorConfig` to check permissions on the pinUvAuthToken.

### Acceptance

`fido2-token` v2 token flow round-trips.  Standard CTAP2.1 test
vectors pass.

---

## 11. M11 — AID manufacturer ID (BACKLOG §4.2)

**Tier**: small.  No firmware work; upstream gnupg PR.

Submit a patch to `gnupg/scd/app-openpgp.c::get_manufacturer()` that
maps `0x4E58` → `"nixtropic"`.  Wait for upstream merge + release
into Debian, NixOS, Arch.  Until then, "Manufacturer: unknown" is
cosmetic.

Option 2 (swap to `0xFF02`) was considered and rejected — loses
our brand identity in `gpg --card-status` and invalidates state.

---

## 12. M12 — TROPIC01 TRNG SP 800-90B compliance (BACKLOG §5.3)

**Tier**: documentation + audit.

Read `ODN_TR01_app_008_sec_arch_1v0.pdf`.  Document TRNG
architecture, health tests, and entropy claims in
`docs/WEBAUTHN-NOTES.md` + a new `docs/SECURITY-CLAIMS.md`.
Required before any "production-grade" marketing.

---

## 13. M13 — pid.codes VID:PID allocation + libccid PR (BACKLOG §5.2)

**Tier**: small + slow.

1. Apply at https://pid.codes/ for a free allocation.
2. Patch firmware USB descriptors with the new VID:PID.
3. Update NixOS module to drop the `awk` Info.plist patch.
4. Submit libccid upstream PR adding the new entry.

Once merged + released, drop the patch from `nixos/tropic.nix`.

---

## 14. M14 — picocom termios hang on TinyUSB CDC (BACKLOG §6.1)

**Tier**: defer-to-upstream.  Workaround documented.

TinyUSB issue: SET_LINE_CODING race when picocom opens CDC.
Watch upstream; pick up the fix when merged.  Currently bypassed
in our flow via `stty -echo -icanon raw` workaround documented in
README.

---

## 15. M15 — Validate-script reader substring (BACKLOG §6.2)

**Tier**: tiny.  ~20 LOC in `tools/validate-openpgp.sh`.

Detect `opensc-tool --reader-info` flag availability; on new
versions, switch from `--reader 0` to `--reader nixtropic` (matches
by friendly name).  Failover keeps current behaviour.

---

## 16. M16 — Rust CLI (BACKLOG §5.4)

**Tier**: out of scope for Phase 8.

New top-level project under `tools/nixtropic-rs/`.  Targets:
- Credential enumeration (currently only via `fido2-token -L` +
  custom CTAP2 cmd 0x0A walk).
- FIDO reset orchestration (10 s window + SW1 confirm).
- OpenPGP card init walkthrough.
- Validate-suite orchestration with structured JSON output.

Defer until Phase 9 or post-1.0.

---

## 17. M17 — Nixpkgs upstreaming (BACKLOG §5.1)

**Tier**: out of scope until items above are done.

When ready:
- Submit `firmware/`, `lt-util/`, `fw-update-chip/` as fixed-output
  derivations under `pkgs/by-name/ni/nixtropic/`.
- Submit NixOS module.
- pid.codes allocation (M13) is a prerequisite — nixpkgs doesn't
  accept TinyUSB-demo VID:PIDs in production packages.

---

## 18. Flash budget tracking

Current `firmware.bin`: 217 128 B / 256 KB (82.81%).  ~38 KB headroom.

Per-milestone projection:

| Milestone | Delta (KB) | Cumulative | % |
|---|---|---|---|
| M1 udev rule       | 0      | 217128 | 82.81 |
| M2 credProps       | ~0.1   | 217228 | 82.85 |
| M3 per-slot touch  | ~0.3   | 217528 | 82.96 |
| M4 OpenPGP M&D     | ~3.5   | 221028 | 84.30 |
| M5 M&D-KEK wrap    | ~1.5   | 222528 | 84.87 |
| M6 authConfig      | ~1.0   | 223528 | 85.25 |
| M7 credProtect     | ~1.5   | 225028 | 85.83 |
| M8 PIV applet      | ~22.0  | 247028 | 94.21 |
| M9 PIN proto v2    | ~3.0   | 250028 | 95.35 |

M8 PIV is the budget-buster.  If we hit overflow before PIV, the
escape hatches in BACKLOG §7 apply:

1. Drop `USE_PRECOMPUTED_CP=0` and lose the precomputed P-256 table
   instead (saves ~74 KB, costs ~50 ms per ECDH).
2. Move `nist256p1.c` precomputed table to flash-stored blob with
   on-demand access (slower, more code complexity).
3. Strip unused trezor-crypto symbols (groestl, blake2*, ripemd160).
   ~3-5 KB easy win.

---

## 19. Cpp-reviewer audit gates

Every milestone that touches the OpenPGP / FIDO / PIN state machine
ships AFTER a `cpp-reviewer` agent pass on the new code (per the
Phase 7 M6 audit precedent — three rounds of HIGH/MEDIUM findings
were caught and fixed there).  Scope per audit: new files + the
specific old files that the new code calls into.

Pattern:
1. Land code in branch.
2. Run `cpp-reviewer` with threat model: "physical attacker can
   reflash firmware AND read R-mem AND replay APDU sequences".
3. Fix HIGH findings before merging.  Decision-log MEDIUMs in the
   commit body.

---

## 20. Validation suite expansion

Each milestone adds at least one non-interactive check to
`tools/validate-fido.sh` or `tools/validate-openpgp.sh`.  Current
count: 22 checks.  Phase 8 target post-M9: ≥30 checks.

Interactive (touch-required) checks stay in `tools/fido2_test.py`
or `tools/openpgp_e2e.py` (new — to be created in M4 if needed for
M&D wrong-PIN-counter behaviour).

---

## 21. Ordering summary

Concrete sequence to follow (after writing this plan, the order is
locked unless we hit a blocker):

```
M1  udev rule              [tiny]    ─┐
M2  credProps              [small]    │  RP-visible polish, no risk
M3  per-slot touch         [medium]   │  Yubikey-class polish
                                      ├─ Phase 8 first ship
M4  OpenPGP PIN M&D        [large]   ─┘  Security hardening core
M5  M&D-KEK dec wrap       [medium]  ─┐  Closes reflash attack
                                      │
M6  authenticatorConfig    [medium]   │  CTAP2.1 polish
M7  credProtect            [medium]   │  RP-requested security level
                                      ├─ Phase 8 second ship
M8  PIV applet             [very large]
M9  PIN protocol v2        [large]
```

Non-firmware items run in parallel:
- M11 gnupg upstream PR.
- M12 SP 800-90B documentation.
- M13 pid.codes + libccid PR (block: external).
- M15 validate-script reader substring.

---

## 22. Open questions

1. Should PIV's PIN tie into the same M&D framework, or get its own
   isolated slots?  Current sketch in M8 says isolated; happy to
   revisit if reviewer prefers a single PIN-MD facade.

2. After M5 lands, the M&D-protected dec privkey requires PW1 even
   for non-interactive `gpg --decrypt` flows where the user hasn't
   pre-cached PW1.  This is a *correctness* feature but a UX
   regression.  Need to confirm gpg-agent's cache-aware behaviour
   plays nicely with the M&D verify-on-each-decrypt cost (each
   verify consumes one of 3 M&D slots; 3 decrypts in 30 s exhausts
   the counter).  May need to extend PGP_PIN_MD_ROUNDS to 8+ for
   PW1.

3. PIV (M8) wants 4 ECC slots + various PIN-related M&D slots.
   Re-confirm that the slot accounting (FIDO 0..23, OpenPGP 24..27,
   PIV 28..31 — wait, PIV in plan above used 24..27 conflicting
   with OpenPGP).  Re-check before M8.  TROPIC01 only has 32 ECC
   slots total — running tight.

---

End of plan.  Open a Phase 8 tracking issue and reference this doc
from STATUS.md when M1 lands.
