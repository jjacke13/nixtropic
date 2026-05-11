# Phase 7 — CCID OpenPGP card (ECC-only, two build variants)

> **Status:** Draft — awaiting user sign-off before M1 implementation.
> **Started:** 2026-05-11 (immediately after Phase 6 sign-off; 37 commits ahead of `origin/main` pending push).
> **Goal:** Daily-driver GnuPG + SSH via gpg-agent. Two build variants: `firmware-fido` (FIDO-only, no regression from Phase 6) and `firmware-combo` (FIDO + OpenPGP card).
> **Audience:** AI agents + future code reviewers (Yubico-class scrutiny).

---

## 0. Why this phase exists, and what it's NOT

Phase 6 closed with a daily-driver Yubikey-class FIDO2 key. The user's actual daily workflow is **GnuPG** (QtPass + signed commits) and **SSH via gpg-agent's `enable-ssh-support`**. Phase 7 brings the dongle into that workflow: `gpg --card-status` recognises it, `gpg --sign` works, `ssh git@github.com` works.

This is a NEW USB interface class (CCID — Chip Card Interface Device) plus a NEW protocol stack (ISO 7816 APDU layer + OpenPGP card v3.4.1 applet). Both must coexist with Phase 6's CDC + 2× HID interfaces in the **combo** build variant.

**What this phase is NOT:**

- **NOT adding RSA.** ECC-only is locked (memory `project_phase7_ecc_only_lock.md`; flash budget). Ed25519 (sig/aut) + Cv25519 (dec) covers the GnuPG ECC smartcard fully. RSA would add ~40 KB and overrun the 256 KB STM32U535 flash ceiling.
- **NOT adding PKCS#11.** That's host-side (existing `libtropic-pkcs11` or scd-agent); not firmware.
- **NOT adding PIV.** Phase 7b if the user wants it; the CCID dispatcher is designed to allow a second AID/applet later.
- **NOT a single universal firmware.** Two compile-time variants:
  - `firmware-fido` — Phase 6 functionality, 8 FIDO credentials, **no CCID interface**. For users who don't want GPG.
  - `firmware-combo` — FIDO (5 credentials) + OpenPGP card (3 keys on slots 5/6/7) + CCID interface. The daily-driver build.
- **NOT redesigning Phase 6's R-mem schema.** Combo build extends past the existing v3 layout; each variant uses a distinct magic (`NX7F` fido-only / `NX7C` combo) so variant switching triggers the same loud-failure factory_reset path we built for Phase 6 H4.

---

## 1. §2 amendments + §6 update in this plan-doc commit

Per the discipline established in Phase 6 (`feedback_dont_silently_drift_locked_decisions.md`), this plan commit also amends `PROJECT.md`:

**New §2 locked decisions (three rows):**

| # | Decision | Rationale | Date |
|---|---|---|---|
| **12** | **Phase 7 = ECC-only.** Ed25519 (sig), Cv25519 (dec), Ed25519 (aut). No RSA. | Flash budget: 256 KB ceiling; Phase 6 lands ~206 KB; ECC adds ~26 KB → ~232 KB combo total. RSA would add ~40 KB and overrun. GnuPG ECC smartcard fully covered. Users who need RSA have other devices. | 2026-05-11 |
| **13** | **Two-variant build:** `firmware-fido` (Phase 6 functionality, 8 FIDO creds, no CCID) and `firmware-combo` (5 FIDO creds + 3 OpenPGP slots, CCID added). | FIDO-only users keep full Phase 6 capability with no regression. Combo users opt in to the slot-allocation trade-off. Compile-time `NIXTROPIC_OPENPGP` flag; CCID + applet + ISO 7816 layer entirely preprocessor-excluded from fido-only build. Default `nix build .#firmware` resolves to combo (the headline feature). | 2026-05-11 |
| **14** | **TROPIC01 slot allocation policy (Option A — hard split).** Combo build: slots 0..4 for FIDO credentials (`SLOTS_MAX=5`), slots 5/6/7 reserved for OpenPGP sig/dec/aut. FIDO-only build: slots 0..7 for FIDO (`SLOTS_MAX=8`). | Compile-time constants — no runtime "which slot is GPG-claimed" state machine. Variant switching is loud (R-mem magic mismatch → factory_reset). Simplest mental model for the user. | 2026-05-11 |

**§6 Phase 7 entry rewritten in this commit.** Previous wording in PROJECT.md mentioned "Port source: CanoKey's `applets/openpgp/`". That's **struck** per user direction 2026-05-11: implement clean-room against the canonical OpenPGP Card v3.4.1 specification (https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf). No CanoKey / Gnuk code referenced. New entry text in §6 notes two variants per Decision #13.

---

## 2. Pass criterion

**Primary mic-drop test (the daily-driver moment):**

```
$ gpg --card-status
Reader ...........: nixtropic-combo (CCID)
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

**Secondary criteria (combo build complete):**

- `gpg --card-edit` walks all menus: admin, name/lang/sex, url, change PIN, generate keys.
- `gpg --decrypt` round-trips on a 4 KB ciphertext encrypted to the card's encryption subkey.
- Per-slot UIF (touch policy) is per-spec: DO D6/D7/D8 default = `0x01` (enabled), every PSO requires SW1 press within 30 s. PW3 + spec command can toggle to `0x00`.
- `gpg --card-edit` → `factory-reset` (TERMINATE DF + ACTIVATE FILE) clears all PGP DOs and erases chip slots 5/6/7. FIDO surface unaffected.
- All Phase 6 validation chains pass on the combo build (FIDO regression test green).
- M&D-backed retry counters: 3 wrong PW1 attempts → PW1 blocked; wrong PW3 → blocked; RC unblocks PW1.

**FIDO-only build criterion:**

- `nix build .#firmware-fido` produces a firmware.bin that boots and passes `nix run .#validate-phase6` verbatim — zero regression.
- `lsusb` shows CDC + 2× HID interfaces only (no CCID).
- AAGUID stays at `...0003` (Phase 6 compat) — existing Phase 6 credentials roam unchanged.
- Flash size unchanged from Phase 6 (~206 KB).

**Variant-switch test (H7 defense, see §3):**

- Flash fido-only → register 7 FIDO creds on webauthn.io (uses slots 0..6).
- Flash combo → boot detects magic `NX7F` and FIDO state in slot 5/6 → loud factory_reset (clears all FIDO state) → boots into combo with empty slots 5/6/7 for OpenPGP.
- User sees the "magic mismatch — wiping" path. Documented in README.

---

## 3. Threat model (delta over Phase 6)

Phase 6 shipped 22 rows (C1, H1–H5, M1–M4, L1–L2 + originals). Phase 7 adds new attack surface (CCID + OpenPGP applet + variant-switch + slot-split) and re-applies several Phase 6 defenses to the new code paths.

Numbering continues from Phase 6: next is C2, H6, M5, L3, I1.

| # | Severity | Attack | Defense in Phase 7 | Validated at |
|---|---|---|---|---|
| H6 | **HIGH** | PIN brute force on PW1/PW3/RC — software counter alone is bypassable via firmware reflash (the same threat that drove Phase 5 M4 for FIDO PIN) | M&D-backed retry counter per PIN. 3 chip slots PW1 + 3 PW3 + 3 RC = 9 total (chip slot indices 8..16, on top of Phase 5's slots 0..7 for FIDO PIN; 17/128 used). Reuses Phase 5 `pin_md.c` primitive verbatim. | M3 |
| H7 | **HIGH** | Variant-switch silent state corruption — flashing combo on a fido-only dongle with credentials in slots 5/6/7 collides with OpenPGP key generation | R-mem magic per variant: fido-only = `"NX7F"`, combo = `"NX7C"`. Combo firmware reading `NX7F` R-mem → magic mismatch → loud factory_reset (same H4 machinery from Phase 6). Migration only succeeds if slots 5..7 are FIDO-empty; otherwise the wipe is mandatory. | M1 + M6 |
| H8 | **HIGH** | PSO:CDS / PSO:DEC / INTERNAL AUTHENTICATE without consent — host malware sends APDU without user interaction | Every PSO + INT_AUT requires `user_presence_check(30000) == UP_OK` when the corresponding UIF is enabled (default ON). Reuses Phase 6 C1 fresh-consent gate, H5 sign-canary enum, M3 dispatcher reentrancy lock. | M4 + M5 |
| H9 | **HIGH** | PW3 (admin) compromise → key replacement attack — attacker who learns admin PIN runs GENERATE ASYMMETRIC KEY PAIR and silently replaces the user's keys | (a) GENERATE requires PW3 AND SW1 press (defense-in-depth beyond PIN). (b) Key fingerprints (DO C7/C8/C9) change on regeneration; host gpg-agent will report "different key on card" on next operation — visible signal. (c) Per-slot generation timestamp (DO CE/CF/D0) gives forensic trail. | M4 |
| H10 | **HIGH** | INTERNAL AUTHENTICATE replay — attacker submits chosen challenge to get signature usable elsewhere (e.g., SSH key reuse against a colluding server) | INT_AUT response binds to challenge bytes — no separable "nonce" — but the wider concern is that the host application's chosen challenge format binds the signature to context. Spec-compliant. SSH binds challenge to session_id + hostkey; out-of-scope for firmware to verify. | (spec-compliance) |
| H11 | **HIGH** | APDU length-field confusion (CLA/Lc/Le parsing) — malformed Lc reads past command buffer | ISO 7816 parser bounds-checks every byte; T=1 chaining reassembled into bounded buffer; extended-length Lc (3-byte form) capped at 4096 B (matches TROPIC01 L3 ciphertext max). Reject any APDU whose declared Lc exceeds remaining buffer. | M1 + M6 audit |
| M5 | MEDIUM | TERMINATE DF without admin auth wipes the card | TERMINATE DF (00 E6) requires PW3 verified per spec §7.2.16. ACTIVATE FILE (00 44) likewise requires PW3 (re-init must be authenticated). | M3 |
| M6 | MEDIUM | PUT DATA on algorithm attributes (DO C1/C2/C3) — attacker switches curve, then GENERATE writes keys to attacker-controlled algorithm | PUT DATA C1/C2/C3 allowed ONLY when (a) the corresponding slot is uninitialised (no key generated yet) AND (b) PW3 verified. Once a key exists in slot, PUT DATA returns 0x6985 (Conditions of use not satisfied). | M4 |
| M7 | MEDIUM | LED covert channel (Phase 6 M2 analog) regresses in PGP code paths — webcam-adjacent attacker correlates LED state with PSO operations | LED writes forbidden in PSO:CDS / PSO:DEC / INT_AUT / VERIFY / GENERATE paths. cpp-reviewer M6 audit scans for any `led_set_state` call inside `pgp_pso.c` / `pgp_pin.c` / `pgp_keys.c`. None should exist. | M6 audit |
| M8 | MEDIUM | CCID dispatcher reentrancy during PSO touch wait (Phase 6 M3 analog) — CCID APDU on the slot's buffer while `user_presence_check` is awaiting → buffer overwrite | Same `s_dispatcher_busy` flag pattern from Phase 6 M3. CCID dispatcher returns ICC-busy (CCID PC_to_RDR error response) while a UP wait or admin operation is in progress. | M4 |
| M9 | MEDIUM | Algorithm attribute downgrade — user / attacker sets DO C1 to a weaker curve and re-generates | We support ONLY Ed25519 (sig/aut) and Cv25519 (dec). PUT DATA with any other OID returns 0x6A80 (Incorrect parameters in data field). Closes downgrade path. | M4 |
| M10 | MEDIUM | T=1 EDC (LRC checksum) bypass — malformed checksum accepted | LRC computed per ISO 7816-3 §11.3.2 over every received block; mismatch → R-block with retry. Three retry failures → drop block. | M1 + M6 audit |
| L3 | LOW | Default PIN UX — spec / convention defaults are `123456` (PW1) and `12345678` (PW3); attacker tries these first | Documented loudly in README that user MUST change PINs immediately. `gpg --card-status` parse will show default-PIN warning. Decision: ship spec-conventional defaults so `gpg --card-edit` → `passwd` flow works out of the box (alternative — ship blocked PINs — breaks GnuPG's first-use wizard). | M3 + M6 docs |
| L4 | LOW | Generation timestamp (DO CE/CF/D0) source — STM32U535 has RTC but we may not wire it for M4 | M4 stubs to `0` (Unix epoch); M6 wires HAL RTC if budget allows. GnuPG accepts 0 (shows "1970-01-01"). Cosmetic. | M4 → M6 |
| L5 | LOW | UIF "permanent" (`0x02`) lock — once set, cannot be toggled even by PW3; user shoots own foot | We accept 0x00 / 0x01 by default; 0x02 only via explicit vendor lt-rpc command (similar to Force-UV vendor cmd). Defends accidental-permanent. Phase 8 polish surfaces it normally. | M3 |
| I1 | INFO | Phase 7b PIV alongside OpenPGP would force CCID multi-applet dispatch | CCID applet dispatcher takes AID at SELECT; adding PIV applet later is "add a second AID branch, ~5 KB." Architecture doesn't preclude. | future |
| I2 | INFO | gpg-agent must run with `enable-ssh-support` on Linux for SSH-via-card to work | NixOS module addition (Phase 8) or README documentation. Phase 7 assumes user has this configured. | M5 docs |

---

## 4. Architecture

### 4.1 USB CCID class (TinyUSB integration)

TinyUSB upstream has no CCID class driver. Options considered:

- **A) TinyUSB vendor-class endpoints + manual ICCD descriptor + manual T=1 parsing.** Pure firmware code, ~1500 LOC.
- **B) Adapt a third-party port (CanoKey).** Rejected per user direction (clean-room spec-driven, no port references).
- **C) Submit a proper CCID class addition to TinyUSB upstream.** Out of scope; PR-style work for a future contribution.

**Decision: A.** A CCID device on the wire is just a USB vendor-class device with a specific class descriptor + bulk-in/bulk-out + interrupt-in endpoints. pcsc-lite, scd-agent, gpg-agent, opensc-tool all speak the wire protocol — they don't care whose driver moved the bytes.

**File layout (new, combo-only — all `#ifdef NIXTROPIC_OPENPGP`):**

- `firmware/src/usb/usb_ccid.c` — vendor-class endpoint pump; ICCD class descriptor; control-endpoint handling for PC_to_RDR / RDR_to_PC messages (`IccPowerOn`, `IccPowerOff`, `GetSlotStatus`, `XfrBlock`).
- `firmware/src/ccid/t1_framing.c` — T=1 IBlock / RBlock / SBlock reassembly; LRC checksum (1-byte EDC); 64 B max EP packet reassembled into 256 B (short APDU) or 4096 B (extended) command buffer.
- `firmware/src/ccid/apdu_dispatch.c` — ISO 7816 CLA/INS/P1/P2/Lc/Le parsing; bounds-checks; dispatches to applet.
- `firmware/src/openpgp/openpgp_applet.c` — receives parsed APDU; dispatcher table by INS byte; returns response + SW1/SW2.

**ICCD descriptor (combo build only):**

- Class: 0x0B (CCID)
- 1 bulk-in EP (64 B), 1 bulk-out EP (64 B), 1 interrupt-in EP (8 B, optional)
- Class-specific descriptor: protocol T=1, max APDU 4096 B, max IFSD 254, BWI/CWI defaults
- Strings: "nixtropic CCID Reader"

**USB endpoint budget (combo build):**

| Endpoint | Direction | Size | Used by |
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

STM32U535 USB FS controller has 8 bidir EPs. We use 7 (or 6 if we drop CCID interrupt-in). Confirm at M1 — RM0456 §USB.

### 4.2 ISO 7816 APDU layer

Per ISO 7816-4 + OpenPGP card spec §7.

**Short APDU format:**
- Command: `CLA INS P1 P2 [Lc data...] [Le]`
- Response: `data... SW1 SW2`

**Extended-length APDU format** (spec §7.1 — capability flagged in DO C0):
- Lc/Le are 3 bytes: `00 + 2-byte BE length`
- Max payload 65535 B; we cap at 4096 B (matches TROPIC01 L3 ciphertext max — covers all OpenPGP operations including large encrypted blobs)
- Combo build advertises ext-len in DO C0

**Standard status words (subset):**

| SW | Meaning |
|---|---|
| `0x9000` | OK |
| `0x6982` | Security condition not satisfied (PIN required) |
| `0x6983` | Auth method blocked (retry counter == 0) |
| `0x6985` | Conditions of use not satisfied (e.g. wrong key state, touch timeout) |
| `0x6A80` | Incorrect parameters in data field |
| `0x6A82` | File or application not found (wrong SELECT) |
| `0x6A86` | Incorrect P1/P2 |
| `0x6A88` | Referenced data not found (no such DO) |
| `0x6D00` | Instruction (INS) not supported |
| `0x6E00` | Class (CLA) not supported |

CLA byte: we accept `0x00` (standard) and `0x10` (chaining flag set per ISO 7816-4 §5.1). Reject anything else with `0x6E00`.

### 4.3 OpenPGP applet (AID + DOs + commands)

**AID (Application Identifier) per spec §4.2.1:**

```
D2 76 00 01 24 01   RID (FSFE-allocated OpenPGP application)
03 04               Version 3.4
XX XX               Manufacturer (self-allocated, see §8 Open Q before M2)
XX XX XX XX         Serial number (derived from TROPIC01 chip ID, lower 32 bits)
00 00               RFU
```

The full AID is 16 bytes. Compile-time constants in `firmware/src/openpgp/openpgp_aid.h`.

**Standard Data Objects we implement (per spec §4.4):**

| Tag | Read | Write (PUT DATA) | Source / Notes |
|---|---|---|---|
| `5E` | always | PW3 | Login data (free-form, e.g. `"user@host"`) — R-mem |
| `5F50` | always | PW3 | URL pointing to pubkey — R-mem |
| `5B` | always | PW3 | Cardholder Name — R-mem |
| `5F2D` | always | PW3 | Language (ISO 639) — R-mem |
| `5F35` | always | PW3 | Sex (ISO 5218) — R-mem |
| `65` | always | (composite via children) | Cardholder Related Data template |
| `6E` | always | (composite via children) | Application Related Data — AID + history + algo attrs + fingerprints |
| `7A` | always | (composite via children) | Security Support Template — signature counter |
| `93` | always | n/a | Signature counter (3 B BCD) — increments on every PSO:CDS — R-mem |
| `C0` | always | n/a | Extended capabilities — compile-time constant (ext-len YES, max APDU 4096, KDF NO) |
| `C1` | always | PW3 (only when no key) | Algorithm attributes for sig key — Ed25519 OID |
| `C2` | always | PW3 (only when no key) | Algorithm attributes for dec key — Cv25519 OID |
| `C3` | always | PW3 (only when no key) | Algorithm attributes for aut key — Ed25519 OID |
| `C4` | always | PW3 | PW status bytes — `[PW1_len, force_verify, PW1_retries, PW3_retries, RC_retries]` |
| `C7` | always | (auto on key gen) | Fingerprint of sig key — SHA-1, 20 B — R-mem |
| `C8` | always | (auto on key gen) | Fingerprint of dec key — R-mem |
| `C9` | always | (auto on key gen) | Fingerprint of aut key — R-mem |
| `CE` | always | (auto on key gen) | Generation timestamp of sig key (4 B BE Unix epoch) — R-mem |
| `CF` | always | (auto on key gen) | Generation timestamp of dec key — R-mem |
| `D0` | always | (auto on key gen) | Generation timestamp of aut key — R-mem |
| `D6` | always | PW3 | UIF for sig — `{0x00 never, 0x01 enabled, 0x02 permanent}` — R-mem |
| `D7` | always | PW3 | UIF for dec — R-mem |
| `D8` | always | PW3 | UIF for aut — R-mem |

**Algorithm attribute encoding** (DO C1/C2/C3 per spec §4.4.3.7):

| Curve | Bytes (length-prefixed OID) |
|---|---|
| Ed25519 (sig/aut) | `16 22 2B 06 01 04 01 DA 47 0F 01` (OID 1.3.6.1.4.1.11591.15.1) |
| Cv25519 (dec) | `12 2A 86 48 CE 3D 02 01 ...` (Curve25519 OID — exact bytes TBD M4, verify against spec §4.4.3.7 table) |

(Byte values cited here are spec-recall; M4 implementation will fetch the spec table to confirm before commit.)

**Standard APDU command set:**

| INS | Name | CLA | P1 | P2 | Notes |
|---|---|---|---|---|---|
| 0xA4 | SELECT | 00 | 04 | 00 | SELECT by AID — Lc=16 (our AID) |
| 0x20 | VERIFY | 00 | 00 | 81/82/83 | P2: 81=PW1 sign-mode, 82=PW1 dec/auth-mode, 83=PW3 admin |
| 0x24 | CHANGE REFERENCE DATA | 00 | 00 | 81/82/83 | Change PIN |
| 0x2C | RESET RETRY COUNTER | 00 | 00/02 | 81 | P1: 0=use RC, 2=use PW3 |
| 0xCA | GET DATA | 00 | tag-hi | tag-lo | Tag in P1P2 |
| 0xDA | PUT DATA | 00 | tag-hi | tag-lo | Tag in P1P2 |
| 0x47 | GENERATE ASYMMETRIC KEY PAIR | 00 | 80 | 00 | Key reference in data: B6=sig, B8=dec, A4=aut |
| 0x2A | PERFORM SECURITY OPERATION | 00 | 9E | 9A | PSO:CDS (Compute Digital Signature) |
| 0x2A | PERFORM SECURITY OPERATION | 00 | 80 | 86 | PSO:DEC (Decipher) |
| 0x88 | INTERNAL AUTHENTICATE | 00 | 00 | 00 | Sign challenge with aut key |
| 0x84 | GET CHALLENGE | 00 | 00 | 00 | TROPIC01 TRNG passthrough |
| 0xE6 | TERMINATE DF | 00 | 00 | 00 | Wipe applet state — PW3 required |
| 0x44 | ACTIVATE FILE | 00 | 00 | 00 | Re-init after TERMINATE — PW3 required |

**We DEFER to Phase 8:**

- DO F9 (KDF) — GnuPG-specific PIN-hashing scheme. Default-off; opt-in later.
- DO 7F21 (Cardholder certificate) — large blob, not on critical path.
- Algorithm-attribute history extension.

### 4.4 PIN handling (PW1 / PW3 / RC) with M&D backing

Spec defaults at first-init (combo build factory state):

- PW1 = `"123456"` (6 bytes, ASCII)
- PW3 = `"12345678"` (8 bytes, ASCII)
- RC = unset (PUT DATA D3 by PW3 to set)
- Retries: 3 each

**PW1.81 (sign) and PW1.82 (dec/auth) share the same PIN counter** per spec §7.2.2 — many cards do this; we do too. One M&D set protects both modes.

**M&D slot allocation (combo build):**

```
TROPIC01 M&D slot indices:
  0..7   — Phase 5 FIDO PIN retry counter (8 retries)
  8..10  — PW1 retry counter (3 retries)
  11..13 — PW3 retry counter (3 retries)
  14..16 — RC retry counter (3 retries)
  17..127 — reserved / free
```

Total: 17/128. Compile-time constants `MD_SLOT_FIDO_BASE=0`, `MD_SLOT_PW1_BASE=8`, `MD_SLOT_PW3_BASE=11`, `MD_SLOT_RC_BASE=14` in `firmware/src/fido_hid/slots.h`. Combo-only (fido-only build doesn't compile these in).

**Force-verify byte (DO C4 bit 0):** when set, every PSO:CDS requires a fresh VERIFY of PW1.81. **Default ON for security** (defends sign-once-PIN-cached-forever path). User can disable via PUT DATA C4 + PW3.

**PIN length constraints:**
- PW1: 6-127 chars (spec mandate min 6)
- PW3: 8-127 chars (spec mandate min 8)
- RC: 8-127 chars

**Bootstrapping:** combo build first-boot (no PGP state, NX7C magic just installed) sets PW1=`"123456"` / PW3=`"12345678"` per spec convention. `gpg --card-status` parse will detect default-PIN state and display a warning. User MUST change via `gpg --card-edit` → `passwd`. Documented loudly in README (L3 defense).

### 4.5 Key generation + persistence (TROPIC01 slots 5/6/7)

GENERATE ASYMMETRIC KEY PAIR (APDU `00 47 80 00`) + key reference template in data:

| Key reference byte | Curve | TROPIC01 slot | Purpose |
|---|---|---|---|
| `B6` | Ed25519 | 5 | Signature |
| `B8` | Curve25519 (X25519) | 6 | Decryption |
| `A4` | Ed25519 | 7 | Authentication |

**Required:** PW3 verified + SW1 press (H9 defense). 30 s touch timeout.

**Flow:**

1. Parse APDU; extract key reference byte.
2. Check PW3 verified (else 0x6982).
3. Call `user_presence_check(30000)` (else 0x6985 on UP_FAIL).
4. Call `lt_ecc_key_generate(handle, slot, curve)` — chip generates the keypair; private half never leaves the chip.
5. Call `lt_ecc_key_read(handle, slot, pubkey)` — read 32 B public key.
6. Compute fingerprint per RFC 4880 §12.2: SHA-1(`0x99 ‖ 2-byte length ‖ packet body including pubkey`). Store in DO C7/C8/C9.
7. Set generation time (current Unix timestamp from HAL RTC if wired, else 0 — L4 defense, M4 ships with 0, M6 wires RTC if budget) in DO CE/CF/D0.
8. Increment PGP key-generation counter (DO 93 unchanged; this is sig-counter, separate).
9. Return 0x9000 + key-pair template per spec §7.2.14 with public key included.

**Persistence:** keys live on TROPIC01 indefinitely until `lt_ecc_key_erase` (called from TERMINATE DF). R-mem stores the DOs (fingerprint, generation time, UIF) but NOT the keys themselves.

### 4.6 PSO operations (sign / decrypt / auth)

All three operations require:

1. The corresponding PIN verified (PW1.81 for CDS; PW1.82 for DEC / INT_AUT).
2. If UIF for that slot is `0x01` (default), `user_presence_check(30000) == UP_OK`.

**PSO:CDS (00 2A 9E 9A)** — Compute Digital Signature using sig key (slot 5).

- VERIFY PW1.81 required.
- If force-verify (DO C4 bit 0) is ON (default): PW1.81 must be verified in THIS APDU sequence (not just previously); cleared after operation.
- UIF D6 == 01 → UP required (default).
- Input: hash to sign (typically 32 B for SHA-256; up to 4096 B raw — chip-side `lt_ecc_eddsa_sign` handles).
- Output: 64 B Ed25519 signature.
- Sig counter (DO 93) increments by 1.
- SW: 0x9000 success, 0x6982 (no PIN), 0x6985 (no touch).

**PSO:DEC (00 2A 80 86)** — Decipher using dec key (slot 6, Cv25519).

- VERIFY PW1.82 required.
- UIF D7 == 01 → UP required (default).
- Input: encrypted ephemeral public key wrapped in spec ASN.1 template (32 B X25519 pubkey + tag headers).
- Operation: chip-side X25519 KX via `lt_ecc_ecdh_kx` using slot 6 → 32 B shared secret.
- Output: 32 B shared secret (host derives session key from this via KDF).
- SW: 0x9000 success, 0x6982 (no PIN), 0x6985 (no touch).

**INTERNAL AUTHENTICATE (00 88 00 00)** — Sign challenge with aut key (slot 7, Ed25519).

- VERIFY PW1.82 required (same PW1.82 mode as DEC; spec §7.2.13).
- UIF D8 == 01 → UP required (default).
- Input: challenge bytes (up to 4096 B — SSH passes session_id-derived challenge here).
- Output: 64 B Ed25519 signature over challenge.
- SW: 0x9000 success, 0x6982 (no PIN), 0x6985 (no touch).

All three use the same TROPIC01 API surface as Phase 5 (`lt_ecc_eddsa_sign`, `lt_ecc_ecdh_kx`) — wire-up is mechanical.

### 4.7 R-mem schema v3 → v4 (combo build) + magic-per-variant migration

**Combo build** extends R-mem with OpenPGP card state. **FIDO-only build** stays at v3 layout but with bumped magic `NX7F` (for variant-switch detection).

Schema v4 layout (combo, R-mem slot 1 — slot 0 stays FIDO global state):

```
offset  size   field                                     schema since
------  ----   -----                                     ------------
   0      4    magic "NX7C" (0x4E,0x58,0x37,0x43)        v4 (combo)
   4      2    schema_version = 4                        v4
   6     32   reserved / future                          v4
  ...
  321     1    force_uv (FIDO Force-UV flag — inherited) v3
  322     1    pgp_state_present (1 if PGP initialised)  v4
  323     1    PW1 retry counter cache                   v4
  324     1    PW3 retry counter cache                   v4
  325     1    RC retry counter cache (0xFF = unset)     v4
  326     1    force_verify (DO C4 bit 0; default 1)     v4
  327     3    UIF sig/dec/aut (D6/D7/D8; default 1/1/1) v4
  330    40    cardholder name (1 B len + 39 B data)     v4 — DO 5B
  370     2    language (ISO 639)                        v4 — DO 5F2D
  372     1    sex                                       v4 — DO 5F35
  373    20    fingerprint sig (DO C7)                   v4
  393    20    fingerprint dec (DO C8)                   v4
  413    20    fingerprint aut (DO C9)                   v4
  433     4    generation time sig (DO CE)               v4
  437     4    generation time dec (DO CF)               v4
  441     4    generation time aut (DO D0)               v4
  445     3    signature counter (DO 93, BCD)            v4
  448    27    reserved / future                         v4
                                                        ------
total = 475 B (= R-mem slot size on TROPIC01 FW ≥2.0.0)
```

**Free-form fields** (login data DO 5E, URL DO 5F50) live in R-mem slot 2 with length-prefixed records. Up to 475 B combined.

**FIDO global state (slot 0)** stays at Phase 6 v3 layout — only the magic changes by variant: `NX6K` (Phase 6 firmware) → `NX7F` (Phase 7 fido-only) or `NX7C` (Phase 7 combo).

**Migration matrix:**

| Reader \ State | NX6K (Phase 6) | NX7F (Phase 7 fido) | NX7C (Phase 7 combo) |
|---|---|---|---|
| **fido-only Phase 7** | migrate → bump magic to NX7F | use as-is | mismatch → factory_reset (loud) |
| **combo Phase 7** | migrate → bump magic to NX7C, init PGP state slots | mismatch → factory_reset (only if slots 5/6/7 hold FIDO state); else just bump magic to NX7C | use as-is |

**Variant-switch UX:**

- fido-only → combo: combo firmware reads NX7F. If FIDO slots 5..7 are empty, just bumps magic to NX7C. If any of 5..7 hold a FIDO credential, **mandatory factory_reset** (user warned via README; LED enters error state briefly then normal boot).
- combo → fido-only: fido-only firmware reads NX7C. Magic mismatch → factory_reset (combo state was richer than fido-only schema can represent; wipe is the safe path).

Documented in README + a `nix run .#variant-switch` helper that prompts the user before flashing.

### 4.8 Two-variant build system

**CMake option** (in `firmware/CMakeLists.txt`):

```cmake
option(NIXTROPIC_OPENPGP "Build with OpenPGP card (CCID + applet)" ON)

if(NIXTROPIC_OPENPGP)
    target_sources(firmware PRIVATE
        src/usb/usb_ccid.c
        src/ccid/t1_framing.c
        src/ccid/apdu_dispatch.c
        src/openpgp/openpgp_applet.c
        src/openpgp/openpgp_state.c
        src/openpgp/pgp_pin.c
        src/openpgp/pgp_keys.c
        src/openpgp/pgp_pso.c
    )
    target_compile_definitions(firmware PRIVATE NIXTROPIC_OPENPGP=1)
endif()
```

**Header guards in shared files:**

- `firmware/src/fido_hid/slots.h`: `#ifdef NIXTROPIC_OPENPGP` → `SLOTS_MAX=5`, else 8.
- `firmware/src/fido_hid/ctap2.c`: AAGUID constant — `#ifdef NIXTROPIC_OPENPGP` → `0x04` last byte, else `0x03`.
- `firmware/src/fido_hid/slots.c`: R-mem magic constant — `NX7C` if combo, `NX7F` if fido-only.
- `firmware/src/usb/usb_descriptors.c`: CCID interface descriptor added to config descriptor only when `NIXTROPIC_OPENPGP`.

**Nix flake outputs (in `nix/firmware.nix`):**

```nix
firmware-combo = mkFirmware { withOpenpgp = true; };
firmware-fido  = mkFirmware { withOpenpgp = false; };
firmware       = firmware-combo;  # default
```

Both variants build in CI. `nix flake check` exercises both.

### 4.9 SSH via gpg-agent integration

Once Phase 7 ships, the user enables gpg-agent SSH support:

```bash
echo 'enable-ssh-support' >> ~/.gnupg/gpg-agent.conf
gpg-connect-agent updatestartuptty /bye
ssh-add -L   # prints aut key pubkey
```

**Authentication flow on `ssh git@github.com`:**

1. `ssh` asks gpg-agent's SSH socket for available keys.
2. gpg-agent forwards via `scdaemon` → pcsc-lite → our CCID device.
3. SSH challenge → INTERNAL AUTHENTICATE APDU → chip-side Ed25519 sign → response → gpg-agent → ssh.
4. User sees LED blink (SW1 prompt); presses; auth completes.

**Prerequisite (one-time, documented in README):**

- User's GitHub account needs the Ed25519 SSH pubkey added (from `ssh-add -L` output).
- NixOS `programs.gnupg.agent.enableSSHSupport = true;` (or manual gpg-agent.conf).

### 4.10 Touch policy (per-slot UIF, default = enabled)

DO D6/D7/D8 control UIF for sig/dec/aut. Spec values:

| Value | Meaning |
|---|---|
| `0x00` | Never — no touch required |
| `0x01` | Enabled — touch required, can be toggled by PW3 |
| `0x02` | Permanent — touch required, CANNOT be toggled even by PW3 |

**Combo build first-init default:** all three = `0x01` (enabled).

**User can toggle via `ykman openpgp keys set-touch <slot> on/off`-equivalent** (PUT DATA D6/D7/D8 + PW3). Same UX as Yubikey OpenPGP.

**0x02 (permanent) requires a vendor lt-rpc command** (similar to Force-UV gate) — not just PW3 alone. Defends accidental self-lockout (L5).

---

## 5. Milestones (each is one HW-validated commit)

### M1 — USB CCID interface + T=1 ATR + raw APDU loopback + two-variant build scaffold

**Deliverable:**

- `firmware/src/usb/usb_ccid.c` — vendor-class ICCD endpoint pump; class descriptor; `PC_to_RDR_IccPowerOn` → returns hardcoded ATR (spec-compliant: `3B DA 18 FF 81 B1 FE 75 1F 03 ...` — minimal ATR for nixtropic).
- `firmware/src/ccid/t1_framing.c` — T=1 IBlock / RBlock parsing + reassembly + LRC checksum + retry logic.
- `firmware/src/ccid/apdu_dispatch.c` — minimal APDU echo: parses CLA/INS/P1/P2, returns 0x9000 with no data; rejects unknown INS with 0x6D00.
- `firmware/src/usb/usb_descriptors.c` — add CCID interface to combo build config descriptor; guarded by `NIXTROPIC_OPENPGP`.
- `firmware/src/fido_hid/slots.{h,c}` — `SLOTS_MAX` conditional; R-mem magic conditional (`NX7F` vs `NX7C`); migration matrix per §4.7.
- `firmware/CMakeLists.txt` — `NIXTROPIC_OPENPGP` option + conditional sources.
- `nix/firmware.nix` — `firmware-combo` (default) + `firmware-fido` derivations.
- `tools/openpgp_test.py` — host APDU sender via pyscard / python-smartcard.
- `nix run .#validate-phase7-m1` — boot combo build; verify pcsc-lite enumerates as ICCD; send SELECT for nonexistent AID, expect 0x6A82; verify ATR via `opensc-tool --reader nixtropic --atr`.

**HW checkpoint:**

- **combo build:** `lsusb -v` shows CCID interface descriptor. `pcsc_scan` enumerates the reader. `opensc-tool --reader nixtropic --atr` returns expected ATR. `apdu_test.py` send-loop returns 0x9000 for echo APDU.
- **fido-only build:** `lsusb` does NOT show CCID interface. `validate-phase6` full chain still passes (zero FIDO regression).
- **Variant-switch test (rough version):** flash fido-only on dongle, register 1 FIDO cred in slot 0 (well below 5..7), flash combo → boots, FIDO cred still works, OpenPGP not initialised yet.

**Stop-here value:** USB CCID enumerates. pcsc-lite sees a reader. Two-variant build infrastructure proven. No applet yet.

---

### M2 — OpenPGP applet SELECT + GET DATA (read-only DOs) + R-mem schema v4

**Deliverable:**

- `firmware/src/openpgp/openpgp_applet.c` — SELECT by AID; AID compile-time constant in `openpgp_aid.h`; returns 0x9000 + FCI template per spec §7.2.1.
- GET DATA (00 CA P1 P2) for read-only DOs: AID (4F), historical bytes (5F52), application related data (6E), security support template (7A), PW status (C4 — from R-mem retry counters), algorithm attributes (C1/C2/C3 — hardcoded Ed25519 / Cv25519 OIDs), extended capabilities (C0).
- `firmware/src/openpgp/openpgp_state.{h,c}` — accessor wrapper around `slots.c` R-mem reads for PGP DOs.
- `firmware/src/fido_hid/slots.{h,c}` — schema v3→v4 migration (combo only); R-mem slot 1 layout per §4.7; preserve Phase 6 v3 layout for slot 0.
- `nix run .#validate-phase7-m2` — `gpg --card-status` enumerates and prints algorithm attributes `ed25519/cv25519/ed25519`. No PINs verified, no keys generated yet. Schema migration test: dongle with Phase 6 state (NX6K) flashed with combo → boots, FIDO state preserved, PGP state initialised to "not present".

**HW checkpoint:**

- `gpg --card-status` shows the card with our AID + algorithm attributes.
- All read-only DOs return spec-conformant TLV.
- Schema migration NX6K → NX7C preserves FIDO state; PGP state defaults applied.

**Stop-here value:** GnuPG recognises the card. Read-only DO surface complete. No keys yet — but visible.

---

### M3 — PIN handling (PW1 / PW3 / RC) + PUT DATA + admin operations

**Deliverable:**

- `firmware/src/openpgp/pgp_pin.{h,c}` — PW1 / PW3 / RC state machines. VERIFY (00 20), CHANGE REFERENCE DATA (00 24), RESET RETRY COUNTER (00 2C). M&D-backed retry counters using Phase 5 `pin_md.c` primitive; 9 chip slots (indices 8..16) reserved at compile-time (`MD_SLOT_PW1_BASE`, `MD_SLOT_PW3_BASE`, `MD_SLOT_RC_BASE`).
- PUT DATA (00 DA P1 P2) for writable DOs: cardholder name (5B), login data (5E), URL (5F50), language (5F2D), sex (5F35), PW status bytes (C4), UIF D6/D7/D8.
- TERMINATE DF (00 E6) — PW3-only — clears PGP state in R-mem + erases ECC slots 5/6/7 via `lt_ecc_key_erase`.
- ACTIVATE FILE (00 44) — PW3-only — re-initialises after TERMINATE DF; restores spec-default PW1/PW3 in M&D.
- `firmware/src/fido_hid/slots.h` — extend with `MD_SLOT_*` constants for PGP PIN allocations.
- `nix run .#validate-phase7-m3` — `gpg --card-edit` → `admin` → `passwd` flow. Set new PW1 + PW3. Verify with new PINs. Try wrong PW1 4× — 3rd wrong attempt blocks; correct entry from RC unblocks. TERMINATE DF + ACTIVATE FILE round-trip clears state.

**HW checkpoint:**

- `gpg --card-edit` admin menu walks all DOs.
- Wrong PW1 3× → blocked (0x6983); wrong PW3 3× → blocked; RC unblocks PW1.
- Touch policy DO D6/D7/D8 settable via PUT DATA + PW3.
- M&D slots 8..16 visibly consumed via `slots-debug` (debug app) after wrong-PIN attempts.

**Stop-here value:** All admin operations work. M&D-backed retry counters live. No keys yet.

---

### M4 — Key generation + PSO:CDS (sign)

**Deliverable:**

- GENERATE ASYMMETRIC KEY PAIR (00 47 80 00) — keys on TROPIC01 slots 5/6/7. PW3 + UP required (H9 defense). Fingerprint computed per RFC 4880 §12.2 (SHA-1 over `0x99 ‖ length ‖ pubkey-packet-body`); stored in R-mem DO C7/C8/C9. Generation timestamp (DO CE/CF/D0) = 0 for M4 (RTC wiring deferred to M6 if budget).
- PSO:CDS (00 2A 9E 9A) — Ed25519 sign with slot 5. PW1.81 + force-verify-cleared-on-success + UIF-conditional UP required (H8 defense). Sig counter (DO 93) increments per success.
- `firmware/src/openpgp/pgp_keys.{h,c}` — generation flow + fingerprint computation + slot wiring.
- `firmware/src/openpgp/pgp_pso.c` — PSO dispatcher (CDS only for now; DEC + INT_AUT in M5).
- PUT DATA C1/C2/C3 (algorithm attributes) — accepted only when slot uninitialised AND PW3 verified (M6/M9 defense). Once a key exists, returns 0x6985.
- `nix run .#validate-phase7-m4` — `gpg --card-edit` → `admin` → `generate` (Ed25519). `gpg --sign` succeeds; signature verifies with `gpg --verify`. GnuPG fingerprint matches DO C7.

**HW checkpoint:**

- `gpg --card-edit` → `generate` produces Ed25519 sig key in slot 5; pubkey readable via `gpg --card-status`.
- Sign a 32 B challenge → verify with `gpg --verify`.
- Wrong PW1 → 0x6982.
- No touch within 30 s → 0x6985.
- Sig counter increments visibly in DO 93.

**Stop-here value:** **`git commit -S` works.** First "Yubikey-for-PGP-sign" moment.

---

### M5 — PSO:DEC (decrypt) + INTERNAL AUTHENTICATE + gpg-agent SSH

**Deliverable:**

- GENERATE for dec key (slot 6, Cv25519) + aut key (slot 7, Ed25519).
- PSO:DEC (00 2A 80 86) — chip-side X25519 KX via `lt_ecc_ecdh_kx` using slot 6. Input: encrypted ephemeral pubkey wrapped in ASN.1 template. Output: 32 B shared secret.
- INTERNAL AUTHENTICATE (00 88 00 00) — chip-side Ed25519 sign using slot 7. Input: challenge ≤4096 B. Output: 64 B sig.
- `firmware/src/openpgp/pgp_pso.c` — extend dispatcher for DEC + INT_AUT.
- README — gpg-agent.conf `enable-ssh-support` recipe + `ssh-add -L` flow.
- `nix run .#validate-phase7-m5` — Full round-trip: generate all three keys, GPG encrypt a 4 KB blob to the card, `gpg --decrypt` succeeds. Configure gpg-agent SSH, `ssh-add -L` prints aut Ed25519 pubkey, `ssh -T git@github.com` (with key added to GitHub) authenticates.

**HW checkpoint:**

- `gpg --decrypt` on 4 KB ciphertext (encrypted to card's enc subkey) → plaintext.
- `gpg --card-status` shows all 3 keys present with correct fingerprints.
- `ssh-add -L` prints aut Ed25519 pubkey.
- `ssh git@github.com` (pubkey added to GitHub) → auth success, LED blinks for SW1, press → auth complete.

**Stop-here value:** **THE DAILY-DRIVER GOAL.** GPG signing + GPG decrypt + SSH auth all working from real GnuPG + real ssh.

---

### M6 — cpp-reviewer audit + variant switch HW test + validate-phase7 + ship

**Deliverable:**

- cpp-reviewer audit scoped to Phase 7 surface: `usb_ccid.c`, `t1_framing.c`, `apdu_dispatch.c`, `openpgp_applet.c`, `pgp_pin.c`, `pgp_keys.c`, `pgp_pso.c`, `openpgp_state.c`. Specific audit clauses for this phase:
  - **Verify H6:** PW1/PW3/RC retry counter decrement is atomic with M&D consumption; no path returns "PIN OK" without consuming the M&D slot first.
  - **Verify H7:** combo firmware reading NX7F R-mem with slots 5/6/7 occupied forces factory_reset; never silently overwrites.
  - **Verify H8:** every PSO + INT_AUT calls `user_presence_check` with `UP_OK` compare; LED writes absent from PSO paths.
  - **Verify H9:** GENERATE requires both PW3 AND `user_presence_check == UP_OK`.
  - **Verify H11:** ISO 7816 parser bounds-checks; extended-length APDU capped at 4096 B.
  - **Verify M5:** TERMINATE DF requires PW3 verified.
  - **Verify M6:** PUT DATA C1/C2/C3 refused when slot has a key.
  - **Verify M7:** no `led_set_state` calls in PSO / VERIFY / GENERATE / PUT-DATA paths.
  - **Verify M8:** `s_dispatcher_busy` flag prevents reentrancy during UP wait or admin op.
  - **Verify M9:** PUT DATA C1/C2/C3 rejects non-Ed25519 / non-Cv25519 OIDs with 0x6A80.
  - **Verify M10:** T=1 LRC checksum mismatch triggers retry (R-block with N=current); 3 retries → drop.
- Variant-switch HW round-trip: combo → fido → combo preserves no state (factory_reset triggered on each switch by magic mismatch). Documented.
- Both Nix flake outputs (`firmware-combo`, `firmware-fido`) build clean in CI.
- `nix run .#validate-phase7` — chains M1+M2+M3+M4+M5 (interactive prompts where needed).
- `nix run .#flash-and-validate-phase7-combo` + `.#flash-and-validate-phase7-fido`.
- **AAGUID bump:** combo = `6e697874726f70696300000000000004` in `ctap2.c`. fido-only stays at `...0003`. Documented in `docs/WEBAUTHN-NOTES.md §3`.
- README + `docs/RECOVERY.md` updated: choose variant, default PINs, factory-reset flow, SSH-via-gpg-agent setup, variant-switch warning.
- `STATUS.md` Phase 7 entry at top.
- `PROJECT.md` §6 Phase 7 marked ✅ COMPLETE.
- Memory: `project_phase7_done.md` + any new feedback / project notes.
- **THE MIC-DROP TEST:** plug combo dongle → `gpg --card-status` shows ed25519 keys → `git commit -S` → green signed commit → `ssh git@github.com` → "Hi jjacke13!" line. Record video for README demo.

**Stop-here value:** Phase 7 complete; both variants shipped; audit done. Ready for Phase 8 (polish) or public demo.

---

## 6. Code-organisation rules for Phase 7 (continuing Phase 5/6 discipline)

- Each new file ≤ 400 LOC. Split if exceeded.
- `usb_ccid.c` zero crypto, zero R-mem; pure USB endpoint plumbing.
- `t1_framing.c` bounded buffers; no malloc; LRC computed in ≤10 line function; bounds-checked every byte.
- `apdu_dispatch.c` parses CLA/INS/P1/P2/Lc/Le with explicit bounds; extended-length capped at 4096 B; CLA ≠ 0x00/0x10 → 0x6E00.
- `openpgp_applet.c` dispatcher uses `static const struct { uint8_t ins; status_t (*handler)(...); }` table for INS lookup.
- `pgp_pin.c` uses Phase 5's `pin_md.c` primitives verbatim — no new M&D code.
- Every PSO + INT_AUT + GENERATE call site uses Phase 6's `UP_OK` sign-canary compare pattern.
- LED writes forbidden in PIN/PSO/VERIFY/GENERATE/PUT-DATA paths (M7 defense). cpp-reviewer M6 audit scans.
- No `printf` in PIN/PSO/VERIFY paths (timing channel).
- No new global variables outside file-scope statics.
- Every applet command implementation comments cite the OpenPGP card v3.4.1 spec section.

---

## 7. Risk register (implementation risks; §3 is security threats)

| ID | Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|---|
| R1 | STM32U535 USB FS endpoint budget — 8 EPs, combo wants 7 | M | M | Drop CCID interrupt-in EP (optional per CCID spec). Confirm at M1 by reading RM0456 §USB. Worst case: drop one CDC EP in combo build (debug-only). |
| R2 | T=1 chaining wrong — NAD/PCB/EDC mis-layout breaks pcsc-lite | M | M | Test against `pcsc_scan` + `opensc-tool` at M1. Reference: ISO 7816-3 §11. |
| R3 | Extended-length APDU spotty in pcsc-lite client libs | L | L | Advertise short APDU support too (DO C0 advertises max APDU 4096; we accept short too). |
| R4 | RFC 4880 SHA-1 fingerprint off-by-one in packet body length encoding | M | L | Validate against GnuPG's own fingerprint output (`gpg --card-status` reports fp). At M4 commit, compare to gpg-side fingerprint. |
| R5 | UIF (touch policy) semantics diverge from Yubikey convention | L | L | Test with `ykman openpgp keys set-touch` semantics; document any deviation. |
| R6 | Schema v3→v4 migration corrupts Phase 6 R-mem | L | H | Per-variant magic (NX7F vs NX7C) + magic-mismatch path → factory_reset. Test combo flash on dongle with full Phase 6 state at M2. |
| R7 | M&D slots 8..16 collide with future FIDO PIN scheme | L | L | Document allocation in `firmware/src/fido_hid/slots.h` `MD_SLOT_*` constants. Phase 5 uses 0..7; we go 8..16. |
| R8 | TROPIC01 `lt_ecc_ecdh_kx` API surface differs from expectation | L | H | Verify at M5 start. Fallback: software X25519 via `trezor_crypto` (already linked). |
| R9 | gpg-agent's scdaemon doesn't speak T=1 cleanly with our reader | M | M | Test with `scd-agent` debug logs at M5. Fallback: implement T=0 (simpler; less common but supported). |
| R10 | Touch-required for every operation makes SSH miserable (every push = touch) | H | L | UIF default = `0x01` (configurable). Document `ykman`-style disable path. User will likely keep touch on for SIG, off for AUT. |
| R11 | Default PINs (`123456` / `12345678`) ignored by lazy user | M | M | `gpg --card-status` output + README warning. Phase 7b option: ship with PW1/PW3 cleared (forces immediate change at first use; breaks GnuPG wizard). |
| R12 | RTC needed for generation timestamps but not wired | L | L | M4 stubs to 0; M6 wires HAL RTC if budget. GnuPG accepts 0 (displays "1970-01-01"). |
| R13 | Variant switch confuses user — wrong variant flashed, FIDO state wiped | M | M | `nix run .#variant-switch` helper prompts. README + apps.nix output prominently warn. |
| R14 | Combo build flash hits ~232 KB — leaves only ~24 KB for Phase 8 polish | M | M | Per-milestone budget tracking. If overrun: drop RESET RETRY COUNTER first (less commonly used than core sign/dec/auth). |
| R15 | CCID class descriptor errors → device fails to enumerate | M | M | Validate against pcsc-lite logs at M1; compare against opensc-tool descriptor introspection. |
| R16 | M&D slot exhaustion if user repeatedly wipes (TERMINATE DF) — each ACTIVATE FILE consumes one M&D slot to "re-init" the counter | L | L | ACTIVATE FILE re-init resets the **counter cache** in R-mem but does NOT re-consume M&D. M&D slots are consumed only on wrong-PIN attempts. (Confirm in M3 design.) |

---

## 8. Open questions to resolve before each milestone

### Before M1

- [ ] Confirm STM32U535 USB FS endpoint budget supports 7 EPs simultaneously (read RM0456 §USB EP table).
- [ ] Decide CCID protocol: T=1 (standard for modern smartcards) vs T=0 (simpler). **Default: T=1.**
- [ ] Pick ICCD ATR bytes — minimal valid ATR per ISO 7816-3 §8. Suggested: `3B DA 18 FF 81 B1 FE 75 1F 03 00 31 C1 73 C0 01 00 90 00 21` (similar to Yubikey OpenPGP ATR style).

### Before M2

- [ ] Self-allocate 2-byte manufacturer ID in AID — pick value (suggested `0xFEED` or similar non-allocated) and document in `openpgp_aid.h`.
- [ ] Confirm R-mem schema v4 layout fits 475 B (slot 1 = primary state, slot 2 = freeform login/URL).
- [ ] Cv25519 OID byte encoding — verify against spec §4.4.3.7 table.

### Before M3

- [ ] M&D slot allocation: `MD_SLOT_PW1_BASE=8`, `MD_SLOT_PW3_BASE=11`, `MD_SLOT_RC_BASE=14` — no clash with Phase 5 (0..7). Document in `slots.h`.
- [ ] Default PINs strategy: ship spec-conventional (`123456` / `12345678`) + loud README + `gpg --card-status` warning. **Default: yes, spec defaults.**
- [ ] Force-verify default: ON (every PSO requires fresh VERIFY of PW1.81). User can disable via PUT DATA C4 + PW3.

### Before M4

- [ ] RFC 4880 §12.2 fingerprint format — verify packet body byte layout for Ed25519 OpenPGP keys.
- [ ] Generation time source: 0 (Unix epoch) — verify GnuPG displays "1970-01-01" gracefully.
- [ ] UIF default value: `0x01` (enabled). Permanent (`0x02`) requires explicit vendor command (L5 defense).

### Before M5

- [ ] Verify `lt_ecc_ecdh_kx` exists with Curve25519 in libtropic ≥3.0. Fallback path: software X25519 via trezor_crypto.
- [ ] gpg-agent socket setup on NixOS — confirm `services.gnupg.agent` module wires `enable-ssh-support`.

### Before M6

- [ ] cpp-reviewer prompt drafted; scope = §3 H6-L5 + new files (§5 M6 list).
- [ ] Recording setup for demo: `git commit -S` + `ssh git@github.com` end-to-end with dongle close-up + screen side-by-side.

---

## 9. Compile-time / runtime budgets

| Resource | Phase 6 | Phase 7 fido-only | Phase 7 combo (est.) | Limit | Combo headroom |
|---|---|---|---|---|---|
| Flash (firmware.bin) | 206 KB | ~206 KB (target: zero regression) | ~232 KB (+8 KB CCID + ~12 KB applet + ~3 KB pgp_pin + ~3 KB pgp_keys + ~2 KB pgp_pso) | 256 KB | 24 KB |
| RAM | 25.7 KB | ~25.7 KB | ~28 KB (+1 KB CCID buffers + ~1 KB APDU buffer + state) | 192 KB | 164 KB |
| ECC slots | up to 8 (FIDO) | up to 8 | 5 FIDO + 3 PGP fixed = 8 | 8 | 0 at full load |
| R-mem slots | 1 | 1 | 3 (FIDO global + PGP state + PGP freeform) | 512 | 509 |
| M&D slots | 8 (FIDO PIN) | 8 | 17 (8 FIDO + 9 PGP) | 128 | 111 |
| USB FS endpoints | 5 | 5 | 7 (drop CCID interrupt-in if tight: 6) | 8 | 1-2 |
| Stack high-water | ~6 KB est. | ~6 KB | +500 B APDU/T=1 frame | ~8 KB available | OK |

---

## 10. Stop-here value at each milestone

- **After M1:** USB CCID enumerates. pcsc-lite sees a reader. Two-variant build proven. Foundational.
- **After M2:** GnuPG recognises the card. Read-only DO surface complete. No keys.
- **After M3:** Admin operations work. PINs settable + changeable. M&D-backed retry counters live.
- **After M4:** `git commit -S` works. First Yubikey-for-PGP-sign moment.
- **After M5:** **THE DAILY-DRIVER.** GPG sign + decrypt + SSH auth all working.
- **After M6:** Phase 7 complete; audit done; both variants shipped.

---

## 11. Sign-off checklist (read before approving M1 start)

**Plan-doc bookkeeping done in this commit:**

- [ ] PROJECT.md §2 amended: row #12 (ECC-only lock), #13 (two-variant build), #14 (slot allocation Option A).
- [ ] PROJECT.md §6 Phase 7 entry rewritten — no CanoKey reference; spec-driven clean-room; two variants documented.
- [ ] PROJECT.md §13 — "Whether to also ship PIV (Phase 7b)" stays unresolved (revisit after Phase 7 ships).
- [ ] `docs/PHASE-7-PLAN.md` (this file) committed alongside §2/§6 edits.

**Awaiting user sign-off:**

- [ ] §3 threat model delta (H6–I2) acceptable as the security commitment for Phase 7.
- [ ] §4.1 USB CCID via vendor-class endpoints + manual ICCD descriptor (no TinyUSB CCID class driver).
- [ ] §4.4 PIN handling: 9 M&D slots for PW1+PW3+RC (chip slots 8..16); ship spec-default PINs (`123456`/`12345678`) + loud documentation; force-verify default ON.
- [ ] §4.5 GENERATE requires PW3 + SW1 press (H9 defense).
- [ ] §4.6 PSO + INT_AUT require PIN + UIF-conditional SW1 press (H8 defense).
- [ ] §4.7 R-mem schema v3 → v4 (combo); per-variant magics NX7F (fido-only) / NX7C (combo); migration matrix; variant-switch loud factory_reset when slots 5..7 conflict.
- [ ] §4.8 two-variant build: `NIXTROPIC_OPENPGP` CMake flag; `nix build .#firmware-combo` (default) vs `.#firmware-fido`.
- [ ] §4.10 UIF default = `0x01` (enabled, toggle-able by PW3); `0x02` (permanent) only via vendor lt-rpc command.
- [ ] §9 flash budget acceptable: ~232 KB / 256 KB combo (24 KB headroom); fido-only stays ~206 KB.
- [ ] M1-M6 milestone breakdown sensible; HW checkpoint between each.
- [ ] AAGUID policy: combo = `...0004`, fido-only stays `...0003`; combo creds will not roam to fido-only (and vice versa) — same trade-off Yubikey makes across firmware capability variants.
- [ ] User explicitly OK with starting M1 (CCID + T=1 ATR + loopback + variant scaffold) before any OpenPGP applet code.
- [ ] User explicitly OK with pushing the Phase 6 stack (37 commits) to origin BEFORE starting Phase 7 work (recommended — clean baseline; Phase 6 is a complete demo-ready feature on its own).

---

*End of PHASE-7-PLAN.md draft.*
