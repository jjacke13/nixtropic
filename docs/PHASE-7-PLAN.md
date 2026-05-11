# Phase 7 — CCID OpenPGP card (ECC-only, single build)

> **Status:** Draft — awaiting user sign-off before M1 implementation.
> **Started:** 2026-05-11 (immediately after Phase 6 sign-off; pushed to origin at 38 commits).
> **Amended:** 2026-05-11 (same day) — original draft proposed two build variants (`firmware-fido` + `firmware-combo`); collapsed to single build after slot-count verification showed the trade-off was trivial. See §1.
> **Goal:** Daily-driver GnuPG + SSH via gpg-agent. Single firmware: FIDO + OpenPGP card together.
> **Audience:** AI agents + future code reviewers (Yubico-class scrutiny).

---

## 0. Why this phase exists, and what it's NOT

Phase 6 closed with a daily-driver Yubikey-class FIDO2 key. The user's actual daily workflow is **GnuPG** (QtPass + signed commits) and **SSH via gpg-agent's `enable-ssh-support`**. Phase 7 brings the dongle into that workflow: `gpg --card-status` recognises it, `gpg --sign` works, `ssh git@github.com` works.

This is a NEW USB interface class (CCID — Chip Card Interface Device) plus a NEW protocol stack (ISO 7816 APDU layer + OpenPGP card v3.4.1 applet). Coexists with Phase 6's CDC + 2× HID interfaces.

**What this phase is NOT:**

- **NOT adding RSA.** ECC-only is locked. TROPIC01 has no RSA hardware support (verified via sub-agent 2026-05-11). Ed25519 (sig/aut) + Cv25519 (dec) covers the GnuPG ECC smartcard fully. RSA would also blow the flash budget (~40 KB cost on the host).
- **NOT adding PKCS#11.** That's host-side (existing `libtropic-pkcs11` or scd-agent); not firmware.
- **NOT adding PIV.** Phase 7b if the user wants it; the CCID dispatcher is designed to allow a second AID/applet later.
- **NOT two variants.** Original draft proposed `firmware-fido` + `firmware-combo`; that's been collapsed (see §1). Single firmware ships FIDO + OpenPGP together.
- **NOT redesigning Phase 6's R-mem schema.** We extend past v3 with one schema bump (`NX6K` → `NX7K`); same downgrade-safe machinery from Phase 6 H4.

---

## 1. §2 amendments + §6 update in this plan-doc commit

This plan-doc commit also amends `PROJECT.md`. Per the discipline from Phase 6 (`feedback_dont_silently_drift_locked_decisions.md`):

**§2 locked decisions:**

| # | Decision | Rationale | Date |
|---|---|---|---|
| **12** | **Phase 7 = ECC-only.** Ed25519 (sig), Cv25519 (dec), Ed25519 (aut). No RSA. | Verified 2026-05-11 (sub-agent): TROPIC01 has zero RSA hardware support; the asymmetric primitives are Ed25519, ECDSA P-256, X25519 only. RSA would also overrun flash budget (~40 KB host-side software cost). GnuPG ECC smartcard fully covered. | 2026-05-11 |
| **13** | **Phase 7 single build** (was two-variant; amended same-day 2026-05-11). | Original draft justified two-variant by "preserve FIDO capacity — combo would shrink it 8→5." Sub-agent verification on the same day showed TROPIC01 has 32 ECC slots (not 8); the actual trade-off is 32→29 — trivial. Single build is simpler to ship, test, audit, document. Users who don't want CCID can ignore the interface (it enumerates but only responds to OpenPGP AID SELECT). | 2026-05-11 |
| **14** | **TROPIC01 ECC slot allocation:** slots 0..28 for FIDO credentials (`FIDO_SLOTS_MAX=29`), slots 29/30/31 reserved for OpenPGP sig/dec/aut. | 32 total slots verified by sub-agent (`research/tropic01-inventory.md` + libtropic enum `TR01_ECC_SLOT_0..31` + `firmware/src/fido_hid/slots.h:40 #define SLOTS_MAX 32u`). Compile-time constants — no runtime "which slot is claimed" state machine. FIDO slot allocator refuses indices ≥ 29. | 2026-05-11 |

**§6 Phase 7 entry rewritten** in this commit — previous text mentioned "Port source: CanoKey's `applets/openpgp/`"; that's struck per user direction (2026-05-11). Implement clean-room against the canonical OpenPGP Card v3.4.1 specification (https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf). No Gnuk / CanoKey code referenced.

---

## 2. Pass criterion

**Primary mic-drop test (the daily-driver moment):**

```
$ gpg --card-status
Reader ...........: nixtropic (CCID)
Application ID ...: D27600012401nixtropicXXXX
Version ..........: 3.4
Manufacturer .....: self-allocated
Signature key ....: ED25519
Encryption key ...: Cv25519
Authentication key: ED25519

$ git commit -S -m "phase 7 signed commit"
[main XXXX] phase 7 signed commit (signed)

$ ssh-add -L
ssh-ed25519 AAAAC3Nz... cardno:nixtropic-XXXX

$ ssh git@github.com
Hi jjacke13! You've successfully authenticated...
```

**Secondary criteria:**

- `gpg --card-edit` walks all menus: admin, name/lang/sex, url, change PIN, generate keys.
- `gpg --decrypt` round-trips on a 4 KB ciphertext encrypted to the card's encryption subkey.
- Per-slot UIF (touch policy) per-spec: DO D6/D7/D8 default = `0x01` (enabled), every PSO requires SW1 press within 30 s. PW3 can toggle to `0x00`.
- `gpg --card-edit` → `factory-reset` (TERMINATE DF + ACTIVATE FILE) clears all PGP DOs and erases chip slots 29/30/31. FIDO surface unaffected.
- M&D-backed PIN retry counters: 3 wrong PW1 attempts → PW1 blocked; wrong PW3 → blocked; RC unblocks PW1.
- All Phase 6 validation chains still pass (FIDO regression test green); FIDO capacity drops from 32 to 29 — documented but unlikely to bite any user.

**Downgrade test (H4 machinery reuse):**

- Flash Phase 7 firmware → register a FIDO cred + set a PIN + generate PGP keys.
- Flash Phase 6 firmware on the same dongle → Phase 6 sees magic `NX7K`, doesn't recognise, init path forces factory_reset. Loud failure; no silent state corruption.

---

## 3. Threat model (delta over Phase 6)

Phase 6 shipped 22 rows (C1, H1–H5, M1–M4, L1–L2 + originals). Phase 7 adds new attack surface (CCID class + OpenPGP applet) and re-applies several Phase 6 defenses to the new code paths.

Numbering continues from Phase 6.

| # | Severity | Attack | Defense in Phase 7 | Validated at |
|---|---|---|---|---|
| H6 | **HIGH** | PIN brute force on PW1 / PW3 / RC — software counter alone is bypassable via firmware reflash (the same threat that drove Phase 5 M4 for FIDO PIN) | M&D-backed retry counter per PIN. 3 chip slots PW1 + 3 PW3 + 3 RC = 9 total (chip slot indices 8..16, on top of Phase 5's slots 0..7 for FIDO PIN; 17/128 used). Reuses Phase 5 `pin_md.c` primitive verbatim. | M3 |
| H7 | **HIGH** | PSO:CDS / PSO:DEC / INTERNAL AUTHENTICATE without consent — host malware sends APDU without user interaction | Every PSO + INT_AUT requires `user_presence_check(30000) == UP_OK` when the corresponding UIF is enabled (default ON). Reuses Phase 6 C1 fresh-consent gate, H5 sign-canary enum, M3 dispatcher reentrancy lock. | M4 + M5 |
| H8 | **HIGH** | PW3 (admin) compromise → key replacement attack — attacker who learns admin PIN runs GENERATE ASYMMETRIC KEY PAIR and silently replaces the user's keys | (a) GENERATE requires PW3 AND SW1 press (defense-in-depth beyond PIN). (b) Key fingerprints (DO C7/C8/C9) change on regeneration; host gpg-agent will report "different key on card" on next operation — visible signal. (c) Per-slot generation timestamp (DO CE/CF/D0) gives forensic trail. | M4 |
| H9 | **HIGH** | INTERNAL AUTHENTICATE replay — attacker submits chosen challenge to get signature usable elsewhere | INT_AUT response binds to challenge bytes — no separable "nonce" — but the wider concern is that the host application's chosen challenge format binds the signature to context. Spec-compliant. SSH binds challenge to session_id + hostkey; out-of-scope for firmware to verify. | (spec-compliance) |
| H10 | **HIGH** | APDU length-field confusion (CLA / Lc / Le parsing) — malformed Lc reads past command buffer | ISO 7816 parser bounds-checks every byte; T=1 chaining reassembled into bounded buffer; extended-length Lc (3-byte form) capped at 4096 B (matches TROPIC01 L3 ciphertext max). Reject any APDU whose declared Lc exceeds remaining buffer. | M1 + M6 audit |
| M5 | MEDIUM | TERMINATE DF without admin auth wipes the card | TERMINATE DF (00 E6) requires PW3 verified per spec §7.2.16. ACTIVATE FILE (00 44) likewise requires PW3 (re-init must be authenticated). | M3 |
| M6 | MEDIUM | PUT DATA on algorithm attributes (DO C1/C2/C3) — attacker switches curve, then GENERATE writes keys to attacker-controlled algorithm | PUT DATA C1/C2/C3 allowed ONLY when (a) the corresponding slot is uninitialised (no key generated yet) AND (b) PW3 verified. Once a key exists in slot, PUT DATA returns 0x6985 (Conditions of use not satisfied). | M4 |
| M7 | MEDIUM | LED covert channel (Phase 6 M2 analog) regresses in PGP code paths — webcam-adjacent attacker correlates LED state with PSO operations | LED writes forbidden in PSO:CDS / PSO:DEC / INT_AUT / VERIFY / GENERATE paths. cpp-reviewer M6 audit scans for any `led_set_state` call inside `pgp_pso.c` / `pgp_pin.c` / `pgp_keys.c`. None should exist. | M6 audit |
| M8 | MEDIUM | CCID dispatcher reentrancy during PSO touch wait (Phase 6 M3 analog) — CCID APDU on the slot's buffer while `user_presence_check` is awaiting → buffer overwrite | Same `s_dispatcher_busy` flag pattern from Phase 6 M3. CCID dispatcher returns ICC-busy (CCID PC_to_RDR error response) while a UP wait or admin operation is in progress. | M4 |
| M9 | MEDIUM | Algorithm attribute downgrade — user / attacker sets DO C1 to a weaker curve and re-generates | We support ONLY Ed25519 (sig/aut) and Cv25519 (dec). PUT DATA with any other OID returns 0x6A80 (Incorrect parameters in data field). Closes downgrade path. | M4 |
| M10 | MEDIUM | T=1 EDC (LRC checksum) bypass — malformed checksum accepted | LRC computed per ISO 7816-3 §11.3.2 over every received block; mismatch → R-block with retry. Three retry failures → drop block. | M1 + M6 audit |
| L3 | LOW | Default PIN UX — spec / convention defaults are `123456` (PW1) and `12345678` (PW3); attacker tries these first | Documented loudly in README that user MUST change PINs immediately. `gpg --card-status` parse will show default-PIN warning. Decision: ship spec-conventional defaults so `gpg --card-edit` → `passwd` flow works out of the box. | M3 + M6 docs |
| L4 | LOW | Generation timestamp (DO CE/CF/D0) source — STM32U535 has RTC but we may not wire it for M4 | M4 stubs to `0` (Unix epoch); M6 wires HAL RTC if budget allows. GnuPG accepts 0 (shows "1970-01-01"). Cosmetic. | M4 → M6 |
| L5 | LOW | UIF "permanent" (`0x02`) lock — once set, cannot be toggled even by PW3; user shoots own foot | We accept 0x00 / 0x01 by default; 0x02 only via explicit vendor lt-rpc command (similar to Force-UV vendor cmd). Defends accidental-permanent. Phase 8 polish surfaces it normally. | M3 |
| L6 | LOW | FIDO slot capacity drops from 32 to 29 | Documented; impossible to exceed 29 FIDO creds in real daily-driver use. README notes the 29-credential cap for the FIDO+OpenPGP build. | docs |
| I1 | INFO | Phase 7b PIV alongside OpenPGP would force CCID multi-applet dispatch | CCID applet dispatcher takes AID at SELECT; adding PIV applet later is "add a second AID branch, ~5 KB." Architecture doesn't preclude. | future |
| I2 | INFO | gpg-agent must run with `enable-ssh-support` on Linux for SSH-via-card to work | NixOS module addition (Phase 8) or README documentation. Phase 7 assumes user has this configured. | M5 docs |

---

## 4. Architecture

### 4.1 USB CCID class (TinyUSB integration)

TinyUSB upstream has no CCID class driver. Implementation: **TinyUSB vendor-class endpoints + manual ICCD descriptor + manual T=1 parsing.** A CCID device on the wire is just a USB vendor-class with a specific class descriptor + bulk-in/bulk-out + interrupt-in endpoints. pcsc-lite, scdaemon, gpg-agent, opensc-tool all speak the wire protocol — they don't care whose driver moved the bytes.

**File layout (new):**

- `firmware/src/usb/usb_ccid.c` — vendor-class endpoint pump; ICCD class descriptor; control-endpoint handling for PC_to_RDR / RDR_to_PC messages (`IccPowerOn`, `IccPowerOff`, `GetSlotStatus`, `XfrBlock`).
- `firmware/src/ccid/t1_framing.c` — T=1 IBlock / RBlock / SBlock reassembly; LRC checksum (1-byte EDC); 64 B max EP packet reassembled into 256 B (short APDU) or 4096 B (extended) command buffer.
- `firmware/src/ccid/apdu_dispatch.c` — ISO 7816 CLA/INS/P1/P2/Lc/Le parsing; bounds-checks; dispatches to applet.
- `firmware/src/openpgp/openpgp_applet.c` — receives parsed APDU; dispatcher table by INS byte; returns response + SW1/SW2.

**ICCD descriptor:**

- Class: 0x0B (CCID)
- 1 bulk-in EP (64 B), 1 bulk-out EP (64 B), 1 interrupt-in EP (8 B, optional)
- Class-specific descriptor: protocol T=1, max APDU 4096 B, max IFSD 254, BWI/CWI defaults
- Strings: "nixtropic CCID Reader"

**USB endpoint budget:**

| EP | Direction | Size | Used by |
|---|---|---|---|
| EP0 | bidir | 64 B | Control (USB standard + class control) |
| EP1 IN | IN | 64 B | CDC notify |
| EP2 IN | IN | 64 B | CDC data |
| EP2 OUT | OUT | 64 B | CDC data |
| EP3 IN | IN | 64 B | HID lt-rpc |
| EP3 OUT | OUT | 64 B | HID lt-rpc |
| EP4 IN | IN | 64 B | HID FIDO |
| EP4 OUT | OUT | 64 B | HID FIDO |
| EP5 IN | IN | 64 B | CCID bulk-in |
| EP5 OUT | OUT | 64 B | CCID bulk-out |
| EP6 IN | IN | 8 B | CCID interrupt-in (optional) |

STM32U535 USB FS controller has 8 bidir EPs. We use 7 (or 6 if we drop CCID interrupt-in — confirm at M1 from RM0456 §USB).

### 4.2 ISO 7816 APDU layer

Per ISO 7816-4 + OpenPGP card spec §7.

**Short APDU format:** `CLA INS P1 P2 [Lc data...] [Le]`
**Extended-length APDU** (spec §7.1 — capability flagged in DO C0): Lc/Le are 3 bytes (`00 + 2-byte BE length`); max 65535 B; we cap at 4096 B (matches TROPIC01 L3 max).

**Standard status words (subset):**

| SW | Meaning |
|---|---|
| `0x9000` | OK |
| `0x6982` | Security condition not satisfied (PIN required) |
| `0x6983` | Auth method blocked (retry counter == 0) |
| `0x6985` | Conditions of use not satisfied (wrong key state, touch timeout) |
| `0x6A80` | Incorrect parameters in data field |
| `0x6A82` | File or application not found (wrong SELECT) |
| `0x6A86` | Incorrect P1/P2 |
| `0x6A88` | Referenced data not found |
| `0x6D00` | INS not supported |
| `0x6E00` | CLA not supported |

CLA byte: we accept `0x00` (standard) and `0x10` (chaining flag set per ISO 7816-4 §5.1). Reject anything else with `0x6E00`.

### 4.3 OpenPGP applet (AID + DOs + commands)

**AID (Application Identifier) per spec §4.2.1:**

```
D2 76 00 01 24 01   RID (FSFE-allocated OpenPGP application)
03 04               Version 3.4
XX XX               Manufacturer (self-allocated; see §8 Open Q before M2)
XX XX XX XX         Serial number (derived from TROPIC01 chip ID, lower 32 bits)
00 00               RFU
```

Full AID is 16 bytes. Compile-time constants in `firmware/src/openpgp/openpgp_aid.h`.

**Standard Data Objects (per spec §4.4):**

| Tag | Read | Write | Source / Notes |
|---|---|---|---|
| `5E` | always | PW3 | Login data — R-mem |
| `5F50` | always | PW3 | URL pointing to pubkey — R-mem |
| `5B` | always | PW3 | Cardholder Name — R-mem |
| `5F2D` | always | PW3 | Language (ISO 639) — R-mem |
| `5F35` | always | PW3 | Sex (ISO 5218) — R-mem |
| `65` | always | (composite) | Cardholder Related Data template |
| `6E` | always | (composite) | Application Related Data |
| `7A` | always | (composite) | Security Support Template |
| `93` | always | n/a | Signature counter (3 B BCD) — R-mem |
| `C0` | always | n/a | Extended capabilities — compile-time constant |
| `C1` | always | PW3 (no key) | Algorithm attributes for sig key — Ed25519 OID |
| `C2` | always | PW3 (no key) | Algorithm attributes for dec key — Cv25519 OID |
| `C3` | always | PW3 (no key) | Algorithm attributes for aut key — Ed25519 OID |
| `C4` | always | PW3 | PW status bytes |
| `C7` | always | (auto) | Fingerprint of sig key — SHA-1, 20 B — R-mem |
| `C8` | always | (auto) | Fingerprint of dec key — R-mem |
| `C9` | always | (auto) | Fingerprint of aut key — R-mem |
| `CE` | always | (auto) | Generation timestamp of sig key — R-mem |
| `CF` | always | (auto) | Generation timestamp of dec key — R-mem |
| `D0` | always | (auto) | Generation timestamp of aut key — R-mem |
| `D6` | always | PW3 | UIF for sig (`0x00`/`0x01`/`0x02`) — R-mem |
| `D7` | always | PW3 | UIF for dec — R-mem |
| `D8` | always | PW3 | UIF for aut — R-mem |

**Algorithm attribute encoding** (DO C1/C2/C3 per spec §4.4.3.7):

| Curve | Bytes (length-prefixed OID) |
|---|---|
| Ed25519 (sig/aut) | `16 22 2B 06 01 04 01 DA 47 0F 01` (OID 1.3.6.1.4.1.11591.15.1) |
| Cv25519 (dec) | spec-encoded OID (exact bytes verified at M4 against spec §4.4.3.7 table) |

**Standard APDU command set:**

| INS | Name | CLA | P1 | P2 | Notes |
|---|---|---|---|---|---|
| 0xA4 | SELECT | 00 | 04 | 00 | SELECT by AID |
| 0x20 | VERIFY | 00 | 00 | 81/82/83 | P2: 81=PW1 sign, 82=PW1 dec/auth, 83=PW3 admin |
| 0x24 | CHANGE REFERENCE DATA | 00 | 00 | 81/82/83 | Change PIN |
| 0x2C | RESET RETRY COUNTER | 00 | 00/02 | 81 | P1: 0=use RC, 2=use PW3 |
| 0xCA | GET DATA | 00 | tag-hi | tag-lo | |
| 0xDA | PUT DATA | 00 | tag-hi | tag-lo | |
| 0x47 | GENERATE ASYMMETRIC KEY PAIR | 00 | 80 | 00 | Key reference in data: B6=sig, B8=dec, A4=aut |
| 0x2A | PSO | 00 | 9E | 9A | PSO:CDS (Compute Digital Signature) |
| 0x2A | PSO | 00 | 80 | 86 | PSO:DEC (Decipher) |
| 0x88 | INTERNAL AUTHENTICATE | 00 | 00 | 00 | Sign challenge with aut key |
| 0x84 | GET CHALLENGE | 00 | 00 | 00 | TROPIC01 TRNG passthrough |
| 0xE6 | TERMINATE DF | 00 | 00 | 00 | Wipe applet state — PW3 required |
| 0x44 | ACTIVATE FILE | 00 | 00 | 00 | Re-init after TERMINATE — PW3 required |

**Deferred to Phase 8:** DO F9 (KDF — GnuPG-specific PIN-hashing), DO 7F21 (Cardholder certificate), Algorithm-attribute history extension.

### 4.4 PIN handling (PW1 / PW3 / RC) with M&D backing

Spec defaults at first-init:

- PW1 = `"123456"` (6 bytes, ASCII)
- PW3 = `"12345678"` (8 bytes, ASCII)
- RC = unset (PUT DATA D3 by PW3 to set)
- Retries: 3 each

**PW1.81 (sign) and PW1.82 (dec/auth) share the same PIN counter** per spec §7.2.2.

**M&D slot allocation:**

```
TROPIC01 M&D slot indices:
  0..7   — Phase 5 FIDO PIN retry counter (8 retries)
  8..10  — PW1 retry counter (3 retries)
  11..13 — PW3 retry counter (3 retries)
  14..16 — RC retry counter (3 retries)
  17..127 — reserved / free
```

Total: 17/128. Compile-time constants `MD_SLOT_PW1_BASE=8`, `MD_SLOT_PW3_BASE=11`, `MD_SLOT_RC_BASE=14` in `firmware/src/fido_hid/slots.h`.

**Force-verify byte (DO C4 bit 0):** when set, every PSO:CDS requires fresh VERIFY of PW1.81. **Default ON.** User can disable via PUT DATA C4 + PW3.

**Bootstrapping:** Phase 7 first-boot (combined FIDO+OpenPGP, magic `NX7K`) sets PW1=`"123456"` / PW3=`"12345678"` per convention. `gpg --card-status` parse will detect default-PIN state and display a warning. User MUST change via `gpg --card-edit` → `passwd`. Documented loudly in README (L3 defense).

### 4.5 Key generation + persistence (TROPIC01 slots 29/30/31)

GENERATE ASYMMETRIC KEY PAIR (APDU `00 47 80 00`) + key reference template in data:

| Key ref | Curve | TROPIC01 slot | Purpose |
|---|---|---|---|
| `B6` | Ed25519 | 29 | Signature |
| `B8` | Curve25519 (X25519) | 30 | Decryption |
| `A4` | Ed25519 | 31 | Authentication |

**Required:** PW3 verified + SW1 press (H8 defense). 30 s touch timeout.

**Flow:**

1. Parse APDU; extract key reference byte.
2. Check PW3 verified (else 0x6982).
3. Call `user_presence_check(30000)` (else 0x6985 on UP_FAIL).
4. Call `lt_ecc_key_generate(handle, slot, curve)` — chip generates the keypair; private half never leaves the chip.
5. Call `lt_ecc_key_read(handle, slot, pubkey)` — read 32 B public key.
6. Compute fingerprint per RFC 4880 §12.2: SHA-1(`0x99 ‖ 2-byte length ‖ packet body including pubkey`). Store in DO C7/C8/C9.
7. Set generation time (current Unix timestamp from HAL RTC if wired, else 0 — L4 defense; M4 ships with 0, M6 wires RTC if budget) in DO CE/CF/D0.
8. Return 0x9000 + key-pair template per spec §7.2.14.

**Persistence:** keys live on TROPIC01 indefinitely until `lt_ecc_key_erase` (called from TERMINATE DF).

### 4.6 PSO operations (sign / decrypt / auth)

All three require:

1. Corresponding PIN verified (PW1.81 for CDS; PW1.82 for DEC / INT_AUT).
2. If UIF for slot is `0x01` (default), `user_presence_check(30000) == UP_OK`.

**PSO:CDS (00 2A 9E 9A)** — sig key (slot 29). VERIFY PW1.81. If force-verify (DO C4 bit 0) ON: PW1.81 must be verified in THIS APDU sequence (cleared after operation). UIF D6 → UP required. Output: 64 B Ed25519 signature. DO 93 (sig counter) increments by 1.

**PSO:DEC (00 2A 80 86)** — dec key (slot 30, Cv25519). VERIFY PW1.82. UIF D7 → UP required. Input: encrypted ephemeral pubkey wrapped in spec ASN.1 template. Operation: chip-side X25519 KX via `lt_ecc_ecdh_kx` using slot 30. Output: 32 B shared secret.

**INTERNAL AUTHENTICATE (00 88 00 00)** — aut key (slot 31, Ed25519). VERIFY PW1.82. UIF D8 → UP required. Input: challenge ≤4096 B. Output: 64 B Ed25519 signature.

All three use the same TROPIC01 API as Phase 5 (`lt_ecc_eddsa_sign`, `lt_ecc_ecdh_kx`).

### 4.7 R-mem schema v3 → v4 (single magic NX7K)

**Schema v4** extends Phase 6 v3 with OpenPGP card state. Magic bumps once: `NX6K` → `NX7K`.

R-mem slot 0 stays FIDO global state (with bumped magic). R-mem slot 1 holds PGP primary state. R-mem slot 2 holds PGP free-form fields (login, URL).

**Slot 0 (FIDO global, v4):**

```
offset  size   field                                     since
------  ----   -----                                     -----
   0      4    magic "NX7K"                              v4
   4      2    schema_version = 4                        v4
   ...
  31    290    M&D state (unchanged from Phase 5)        v2
  321     1    force_uv flag (unchanged from Phase 6)    v3
  322   153    reserved                                  v4
```

**Slot 1 (PGP primary state, v4):**

```
offset  size   field
------  ----   -----
   0      4    magic "PG4K" (PGP magic; corresponds to PGP v4)
   4      2    schema_version = 1 (PGP state v1)
   6      1    pgp_state_present (1 if PGP initialised)
   7      1    PW1 retry counter cache (M&D-derived)
   8      1    PW3 retry counter cache
   9      1    RC retry counter cache (0xFF if unset)
  10      1    force_verify (DO C4 bit 0; default 1)
  11      3    UIF sig/dec/aut (D6/D7/D8; default 1/1/1)
  14     40    cardholder name (1 B len + 39 B data)
  54      2    language (ISO 639)
  56      1    sex
  57     20    fingerprint sig (DO C7)
  77     20    fingerprint dec (DO C8)
  97     20    fingerprint aut (DO C9)
 117      4    generation time sig (DO CE, BE u32)
 121      4    generation time dec (DO CF)
 125      4    generation time aut (DO D0)
 129      3    signature counter (DO 93, BCD)
 132    343    reserved
                                                        ----
total: 475 B (matches R-mem slot size on TROPIC01 FW ≥2.0.0)
```

**Slot 2 (PGP free-form):** length-prefixed records for DO 5E (login) + DO 5F50 (URL); up to 475 B combined.

**Migration matrix:**

| Reader \ State | NX6K (Phase 6) | NX7K (Phase 7) |
|---|---|---|
| **Phase 7 firmware** | migrate: preserve M&D + force_uv; bump magic; init PGP state defaults | use as-is |
| **Phase 6 firmware** | use as-is | mismatch → factory_reset (loud — H4 machinery from Phase 6) |

Downgrade test (Phase 7 → Phase 6) hits the existing H4 path: Phase 6 firmware doesn't know `NX7K`, init forces factory_reset. User sees the dongle wiped — loud failure, no silent corruption.

### 4.8 FIDO slot allocation cap

`firmware/src/fido_hid/slots.h` gets:

```c
#define SLOTS_MAX             32u   /* chip ECC slot count — unchanged from Phase 6 */
#define FIDO_SLOTS_MAX        29u   /* Phase 7: FIDO allocator refuses indices ≥ 29 */
#define OPENPGP_SLOT_SIG      29u   /* Ed25519 — DO C7 fingerprint */
#define OPENPGP_SLOT_DEC      30u   /* Cv25519 — DO C8 */
#define OPENPGP_SLOT_AUT      31u   /* Ed25519 — DO C9 */
```

`slots_alloc()` (FIDO) refuses indices ≥ `FIDO_SLOTS_MAX`. OpenPGP key generation paths bypass the FIDO allocator and write to the three fixed indices.

User-visible: FIDO maximum credentials drops 32 → 29. Documented in README; impossible to exceed 29 in practical use.

### 4.9 SSH via gpg-agent integration

Once Phase 7 ships, the user enables gpg-agent SSH support:

```bash
echo 'enable-ssh-support' >> ~/.gnupg/gpg-agent.conf
gpg-connect-agent updatestartuptty /bye
ssh-add -L   # prints aut key pubkey
```

**Auth flow on `ssh git@github.com`:**

1. `ssh` asks gpg-agent's SSH socket for available keys.
2. gpg-agent forwards via `scdaemon` → pcsc-lite → our CCID device.
3. SSH challenge → INTERNAL AUTHENTICATE APDU → chip-side Ed25519 sign → response.
4. User sees LED blink (SW1 prompt); presses; auth completes.

**Prerequisite:** user's GitHub account has the Ed25519 SSH pubkey added (one-time, from `ssh-add -L` output). NixOS `programs.gnupg.agent.enableSSHSupport = true;` or manual gpg-agent.conf.

### 4.10 Touch policy (per-slot UIF, default = enabled)

DO D6/D7/D8 control UIF for sig/dec/aut:

| Value | Meaning |
|---|---|
| `0x00` | Never — no touch required |
| `0x01` | Enabled — touch required, can be toggled by PW3 |
| `0x02` | Permanent — touch required, CANNOT be toggled even by PW3 |

**First-init default:** all three = `0x01`.

User can toggle via PUT DATA D6/D7/D8 + PW3 (same UX as `ykman openpgp keys set-touch`).

**`0x02` (permanent) requires a vendor lt-rpc command** (similar to Force-UV gate) — not PW3 alone. Defends accidental self-lockout (L5).

---

## 5. Milestones (each is one HW-validated commit)

### M1 — USB CCID interface + T=1 ATR + raw APDU loopback

**Deliverable:**

- `firmware/src/usb/usb_ccid.c` — vendor-class ICCD endpoint pump; class descriptor; `PC_to_RDR_IccPowerOn` → returns hardcoded ATR.
- `firmware/src/ccid/t1_framing.c` — T=1 IBlock / RBlock parsing + reassembly + LRC checksum + retry logic.
- `firmware/src/ccid/apdu_dispatch.c` — minimal APDU echo: parses CLA/INS/P1/P2, returns 0x9000 with no data; rejects unknown INS with 0x6D00.
- `firmware/src/usb/usb_descriptors.c` — add CCID interface to config descriptor.
- `firmware/src/fido_hid/slots.{h,c}` — add `FIDO_SLOTS_MAX=29` cap; magic bump `NX6K` → `NX7K` with v3→v4 migration on read (preserves Phase 6 M&D + force_uv).
- `firmware/CMakeLists.txt` — add new source files.
- `tools/openpgp_test.py` — host APDU sender via pyscard / python-smartcard.
- `nix run .#validate-phase7-m1` — boot firmware; pcsc-lite enumerates as ICCD; send SELECT for nonexistent AID, expect 0x6A82; `opensc-tool --reader nixtropic --atr` returns expected ATR.

**HW checkpoint:**

- `lsusb -v` shows CCID interface descriptor.
- `pcsc_scan` enumerates the reader.
- `opensc-tool --reader nixtropic --atr` returns expected ATR.
- Echo APDU `00 00 00 00` returns 0x9000.
- Schema migration: dongle with Phase 6 state (NX6K) flashed with Phase 7 → boots, FIDO state preserved (M&D + force_uv), magic now `NX7K`.
- Phase 6 validation chain still passes verbatim (FIDO regression test).

**Stop-here value:** USB CCID enumerates. pcsc-lite sees a reader. No applet yet.

---

### M2 — OpenPGP applet SELECT + GET DATA (read-only DOs) + PGP R-mem state

**Deliverable:**

- `firmware/src/openpgp/openpgp_applet.c` — SELECT by AID; AID compile-time constant in `openpgp_aid.h`; returns 0x9000 + FCI template per spec §7.2.1.
- GET DATA (00 CA P1 P2) for read-only DOs: AID (4F), historical bytes (5F52), application related data (6E), security support template (7A), PW status (C4 from R-mem retry counters), algorithm attributes (C1/C2/C3 hardcoded Ed25519 / Cv25519 OIDs), extended capabilities (C0).
- `firmware/src/openpgp/openpgp_state.{h,c}` — accessor wrapper around `slots.c` R-mem reads/writes for PGP DOs; R-mem slot 1 layout per §4.7.
- `nix run .#validate-phase7-m2` — `gpg --card-status` enumerates and prints algorithm attributes `ed25519/cv25519/ed25519`.

**HW checkpoint:**

- `gpg --card-status` shows the card with AID + algorithm attributes.
- All read-only DOs return spec-conformant TLV.
- R-mem slot 1 holds PGP defaults (pgp_state_present=0 until first GENERATE).

**Stop-here value:** GnuPG recognises the card. Read-only DO surface complete.

---

### M3 — PIN handling (PW1 / PW3 / RC) + PUT DATA + admin operations

**Deliverable:**

- `firmware/src/openpgp/pgp_pin.{h,c}` — PW1/PW3/RC state machines. VERIFY (00 20), CHANGE REFERENCE DATA (00 24), RESET RETRY COUNTER (00 2C). M&D-backed retry counters using Phase 5 `pin_md.c` primitive; 9 chip slots (8..16).
- PUT DATA (00 DA P1 P2) for writable DOs: cardholder name (5B), login data (5E), URL (5F50), language (5F2D), sex (5F35), PW status bytes (C4), UIF D6/D7/D8.
- TERMINATE DF (00 E6) — PW3 only — clears PGP state in R-mem + erases ECC slots 29/30/31 via `lt_ecc_key_erase`.
- ACTIVATE FILE (00 44) — PW3 only — re-initialises after TERMINATE DF; restores spec-default PW1/PW3 in M&D.
- `firmware/src/fido_hid/slots.h` — `MD_SLOT_*` constants for PGP PIN allocations.
- `nix run .#validate-phase7-m3` — `gpg --card-edit` → `admin` → `passwd` flow; wrong-PIN lockout test; TERMINATE/ACTIVATE round-trip.

**HW checkpoint:**

- `gpg --card-edit` admin menu walks all DOs.
- Wrong PW1 3× → blocked (0x6983); wrong PW3 3× → blocked; RC unblocks PW1.
- Touch policy DO D6/D7/D8 settable via PUT DATA + PW3.
- M&D slots 8..16 visibly consumed after wrong-PIN attempts.

**Stop-here value:** Admin operations work. M&D-backed retry counters live. No keys yet.

---

### M4 — Key generation + PSO:CDS (sign)

**Deliverable:**

- GENERATE ASYMMETRIC KEY PAIR (00 47 80 00) — keys on slots 29/30/31. PW3 + UP required (H8 defense). Fingerprint per RFC 4880 §12.2. Generation timestamp = 0 (L4 defense; M4 stubs, M6 wires RTC if budget).
- PSO:CDS (00 2A 9E 9A) — Ed25519 sign with slot 29. PW1.81 + force-verify-cleared-on-success + UIF-conditional UP required (H7 defense). Sig counter (DO 93) increments.
- `firmware/src/openpgp/pgp_keys.{h,c}` — generation + fingerprint + slot wiring.
- `firmware/src/openpgp/pgp_pso.c` — PSO dispatcher (CDS only; DEC + INT_AUT in M5).
- PUT DATA C1/C2/C3 — accepted only when slot uninitialised AND PW3 verified (M6/M9 defense).
- `nix run .#validate-phase7-m4` — `gpg --card-edit` → `admin` → `generate` (Ed25519); `gpg --sign` succeeds; `gpg --verify` confirms.

**HW checkpoint:**

- `gpg --card-edit` → `generate` produces Ed25519 sig key in slot 29.
- Sign 32 B challenge → verify with `gpg --verify`.
- Wrong PW1 → 0x6982. No touch within 30 s → 0x6985.
- Sig counter increments in DO 93.

**Stop-here value:** **`git commit -S` works.**

---

### M5 — PSO:DEC (decrypt) + INTERNAL AUTHENTICATE + gpg-agent SSH

**Deliverable:**

- GENERATE for dec key (slot 30, Cv25519) + aut key (slot 31, Ed25519).
- PSO:DEC (00 2A 80 86) — X25519 KX via `lt_ecc_ecdh_kx` using slot 30.
- INTERNAL AUTHENTICATE (00 88 00 00) — Ed25519 sign using slot 31.
- `firmware/src/openpgp/pgp_pso.c` — extend dispatcher for DEC + INT_AUT.
- README — gpg-agent.conf `enable-ssh-support` recipe + `ssh-add -L` flow.
- `nix run .#validate-phase7-m5` — full round-trip: generate all three keys; GPG encrypt 4 KB blob; `gpg --decrypt` succeeds; configure gpg-agent SSH; `ssh-add -L` prints aut key; `ssh -T git@github.com` authenticates.

**HW checkpoint:**

- `gpg --decrypt` on 4 KB ciphertext → plaintext.
- `gpg --card-status` shows all 3 keys with correct fingerprints.
- `ssh-add -L` prints aut Ed25519 pubkey.
- `ssh git@github.com` (pubkey added to GitHub) → auth success, LED blinks for SW1, press → complete.

**Stop-here value:** **THE DAILY-DRIVER GOAL.** GPG sign + decrypt + SSH auth all working from real GnuPG + real ssh.

---

### M6 — cpp-reviewer audit + validate-phase7 + ship

**Deliverable:**

- cpp-reviewer audit scoped to Phase 7 surface: `usb_ccid.c`, `t1_framing.c`, `apdu_dispatch.c`, `openpgp_applet.c`, `pgp_pin.c`, `pgp_keys.c`, `pgp_pso.c`, `openpgp_state.c`. Verification clauses:
  - **H6:** PW1/PW3/RC retry counter decrement atomic with M&D consumption; no "PIN OK" path without consuming M&D first.
  - **H7:** every PSO + INT_AUT calls `user_presence_check` with `UP_OK` compare; LED writes absent from PSO paths.
  - **H8:** GENERATE requires both PW3 AND `user_presence_check == UP_OK`.
  - **H10:** ISO 7816 parser bounds-checks; extended-length capped at 4096 B.
  - **M5:** TERMINATE DF requires PW3 verified.
  - **M6:** PUT DATA C1/C2/C3 refused when slot has a key.
  - **M7:** no `led_set_state` calls in PSO / VERIFY / GENERATE / PUT-DATA paths.
  - **M8:** `s_dispatcher_busy` flag prevents reentrancy during UP wait or admin op.
  - **M9:** PUT DATA C1/C2/C3 rejects non-Ed25519 / non-Cv25519 OIDs with 0x6A80.
  - **M10:** T=1 LRC checksum mismatch triggers retry; 3 retries → drop.
- `nix run .#validate-phase7` — chains M1+M2+M3+M4+M5 (interactive prompts).
- `nix run .#flash-and-validate-phase7`.
- **AAGUID bump:** `6e697874726f70696300000000000004` in `ctap2.c`. Documented in `docs/WEBAUTHN-NOTES.md §3`.
- README + `docs/RECOVERY.md` updated: default PINs, factory-reset flow, SSH-via-gpg-agent setup, 29-credential FIDO cap (L6).
- `STATUS.md` Phase 7 entry at top.
- `PROJECT.md` §6 Phase 7 marked ✅ COMPLETE.
- Memory: `project_phase7_done.md` + any new feedback / project notes.
- **THE MIC-DROP TEST:** plug dongle → `gpg --card-status` shows ed25519 keys → `git commit -S` → green signed commit → `ssh git@github.com` → "Hi jjacke13!" Record video for README demo.

**Stop-here value:** Phase 7 complete. Ready for Phase 8 (polish) or public demo.

---

## 6. Code-organisation rules (continuing Phase 5/6 discipline)

- Each new file ≤ 400 LOC. Split if exceeded.
- `usb_ccid.c` zero crypto, zero R-mem; pure USB endpoint plumbing.
- `t1_framing.c` bounded buffers; no malloc; LRC computed in ≤10 line function; bounds-checked every byte.
- `apdu_dispatch.c` parses CLA/INS/P1/P2/Lc/Le with explicit bounds; extended-length capped at 4096 B; CLA ≠ 0x00/0x10 → 0x6E00.
- `openpgp_applet.c` dispatcher uses `static const struct { uint8_t ins; status_t (*handler)(...); }` table.
- `pgp_pin.c` uses Phase 5's `pin_md.c` primitives verbatim — no new M&D code.
- Every PSO + INT_AUT + GENERATE call site uses Phase 6's `UP_OK` sign-canary compare.
- LED writes forbidden in PIN/PSO/VERIFY/GENERATE/PUT-DATA paths (M7 defense).
- No `printf` in PIN/PSO/VERIFY paths (timing channel).
- No new global variables outside file-scope statics.
- Every applet command implementation comments cite OpenPGP card v3.4.1 spec section.

---

## 7. Risk register

| ID | Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|---|
| R1 | STM32U535 USB FS endpoint budget — 8 EPs, we want 7 | M | M | Drop CCID interrupt-in EP (optional per CCID spec). Confirm at M1 via RM0456 §USB. |
| R2 | T=1 chaining wrong — NAD/PCB/EDC mis-layout breaks pcsc-lite | M | M | Test against `pcsc_scan` + `opensc-tool` at M1. Reference ISO 7816-3 §11. |
| R3 | Extended-length APDU spotty in pcsc-lite | L | L | Advertise short APDU support too. |
| R4 | RFC 4880 SHA-1 fingerprint off-by-one in packet body length encoding | M | L | Validate against GnuPG's own fingerprint output at M4 commit. |
| R5 | UIF semantics diverge from Yubikey convention | L | L | Test with `ykman openpgp keys set-touch`; document any deviation. |
| R6 | Schema v3→v4 migration corrupts Phase 6 R-mem | L | H | Magic bump (`NX6K` → `NX7K`) + magic-mismatch path → factory_reset on downgrade. Test Phase 7 flash on dongle with full Phase 6 state at M1. |
| R7 | M&D slots 8..16 collide with future FIDO PIN scheme | L | L | Document allocation in `slots.h` `MD_SLOT_*` constants. |
| R8 | TROPIC01 `lt_ecc_ecdh_kx` API differs from expectation | L | H | Verify at M5 start. Fallback: software X25519 via `trezor_crypto` (already linked). |
| R9 | gpg-agent's scdaemon doesn't speak T=1 cleanly | M | M | Test with `scd-agent` debug logs at M5. Fallback: T=0 (simpler). |
| R10 | Touch-required for every operation makes SSH miserable | H | L | UIF default = `0x01` (toggleable). Document `ykman`-style disable. User likely keeps touch on for SIG, off for AUT. |
| R11 | Default PINs (`123456` / `12345678`) ignored by lazy user | M | M | README warning + `gpg --card-status` flag. |
| R12 | RTC needed for generation timestamps; not wired | L | L | M4 stubs to 0. M6 wires HAL RTC if budget. |
| R13 | Flash hits ~232 KB — leaves ~24 KB for Phase 8 polish | M | M | Per-milestone budget tracking. If overrun: drop RESET RETRY COUNTER first. |
| R14 | CCID class descriptor errors → device fails to enumerate | M | M | Validate against pcsc-lite logs at M1. |
| R15 | M&D slot exhaustion if user repeatedly wipes (TERMINATE DF) | L | L | ACTIVATE FILE resets the counter cache in R-mem; M&D slots consumed only on wrong-PIN attempts. Confirm in M3 design. |
| R16 | 29-credential FIDO cap surprises a user with 30+ webauthn registrations | L | L | Documented in README + L6 threat row. Real-world unlikely (Yubikey 5 caps discoverable creds at 25). |

---

## 8. Open questions to resolve before each milestone

### Before M1

- [ ] Confirm STM32U535 USB FS endpoint budget supports 7 EPs simultaneously (read RM0456 §USB EP table).
- [ ] Decide CCID protocol: T=1 (standard) vs T=0 (simpler). **Default: T=1.**
- [ ] Pick ICCD ATR bytes — minimal valid per ISO 7816-3 §8.

### Before M2

- [ ] Self-allocate 2-byte manufacturer ID in AID; document in `openpgp_aid.h`.
- [ ] Confirm R-mem slot 1 layout fits 475 B.
- [ ] Cv25519 OID byte encoding — verify against spec §4.4.3.7 table.

### Before M3

- [ ] M&D slot allocation `MD_SLOT_PW1_BASE=8`, `MD_SLOT_PW3_BASE=11`, `MD_SLOT_RC_BASE=14` — no clash with Phase 5 (0..7).
- [ ] Default PINs strategy: ship spec-conventional (`123456`/`12345678`) + loud README + `gpg --card-status` warning. **Default: yes.**
- [ ] Force-verify default: ON (every PSO requires fresh PW1.81 VERIFY).

### Before M4

- [ ] RFC 4880 §12.2 fingerprint format — verify packet body byte layout for Ed25519.
- [ ] Generation time = 0 — verify GnuPG handles gracefully.
- [ ] UIF default value: `0x01` (enabled). `0x02` only via vendor command.

### Before M5

- [ ] Verify `lt_ecc_ecdh_kx` exists with Curve25519 in libtropic ≥3.0. Fallback: software X25519.
- [ ] gpg-agent socket on NixOS — confirm `services.gnupg.agent` wires `enable-ssh-support`.

### Before M6

- [ ] cpp-reviewer prompt drafted; scope = §3 H6-L5 + new files.
- [ ] Recording setup: `git commit -S` + `ssh git@github.com` demo with dongle close-up.

---

## 9. Compile-time / runtime budgets

| Resource | Phase 6 | Phase 7 est. | Limit | Headroom |
|---|---|---|---|---|
| Flash (firmware.bin) | 206 KB | ~232 KB (+8 KB CCID + ~12 KB applet + ~3 KB pgp_pin + ~3 KB pgp_keys + ~2 KB pgp_pso) | 256 KB | 24 KB |
| RAM | 25.7 KB | ~28 KB (+1 KB CCID buffers + ~1 KB APDU buffer + state) | 192 KB | 164 KB |
| ECC slots | up to 32 (FIDO) | 29 FIDO max + 3 PGP fixed = 32 used | 32 | 0 at full load |
| R-mem slots | 1 | 3 (FIDO global + PGP state + PGP freeform) | 512 | 509 |
| M&D slots | 8 (FIDO PIN) | 17 (8 FIDO + 9 PGP) | 128 | 111 |
| USB FS endpoints | 5 | 7 (drop CCID interrupt-in if tight: 6) | 8 | 1-2 |
| Stack high-water | ~6 KB est. | +500 B APDU/T=1 frame | ~8 KB available | OK |

---

## 10. Stop-here value at each milestone

- **After M1:** USB CCID enumerates; pcsc-lite sees a reader. Foundational.
- **After M2:** GnuPG recognises the card. Read-only DO surface complete.
- **After M3:** Admin operations work. M&D-backed retry counters live.
- **After M4:** `git commit -S` works. First Yubikey-for-PGP-sign moment.
- **After M5:** **THE DAILY-DRIVER.** GPG sign + decrypt + SSH auth.
- **After M6:** Phase 7 complete; audit done.

---

## 11. Sign-off checklist (read before approving M1 start)

**Plan-doc bookkeeping done in this commit:**

- [ ] PROJECT.md §2 amended: row #12 (ECC-only lock), #13 (single build, was two-variant), #14 (slot allocation — 29 FIDO + 3 PGP).
- [ ] PROJECT.md §6 Phase 7 entry rewritten — no CanoKey reference; clean-room spec-driven; single build.
- [ ] PROJECT.md §13 — "Whether to also ship PIV (Phase 7b)" stays unresolved.
- [ ] `docs/PHASE-7-PLAN.md` (this file) committed alongside.

**Awaiting user sign-off:**

- [ ] §3 threat model delta (H6–I2) acceptable.
- [ ] §4.1 USB CCID via vendor-class endpoints + manual ICCD descriptor.
- [ ] §4.4 PIN handling: 9 M&D slots for PW1+PW3+RC; ship spec-default PINs + loud documentation; force-verify default ON.
- [ ] §4.5 GENERATE requires PW3 + SW1 press (H8).
- [ ] §4.6 PSO + INT_AUT require PIN + UIF-conditional SW1 press (H7).
- [ ] §4.7 R-mem schema v3 → v4; single magic NX7K; downgrade to Phase 6 triggers existing H4 factory_reset.
- [ ] §4.8 FIDO slot cap at 29; OpenPGP slots fixed at 29/30/31; 32 total chip slots verified by sub-agent.
- [ ] §4.10 UIF default = `0x01`; `0x02` only via vendor command.
- [ ] §9 flash budget acceptable: ~232 KB / 256 KB (24 KB headroom).
- [ ] M1-M6 milestone breakdown sensible; HW checkpoint between each.
- [ ] AAGUID bump to `...000004` acceptable (Phase 6 creds will not roam — same trade-off Yubikey makes across firmware versions).
- [ ] User explicitly OK with starting M1 (CCID + T=1 ATR + loopback + R-mem schema bump) before any OpenPGP applet code.

---

*End of PHASE-7-PLAN.md draft.*
