# Phase 6 — Production-grade UX (button + Force-UV + credentialManagement)

> **Status:** Draft — awaiting user sign-off before M1 implementation.
> **Started:** 2026-05-11 (immediately after Phase 5 sign-off; 30 commits ahead of origin/main pending push).
> **Goal:** Make the dongle a daily-driver Yubikey-class device. Real touch-to-confirm, always-PIN option, credential management.
> **Audience:** AI agents + future code reviewers (Yubico-class scrutiny).

---

## 0. Why this phase exists, and what it's NOT

Phase 5 produced a working FIDO2 security key with hardware-backed PIN. webauthn.io registers and logs in. PIN brute-force is hardware-impossible. **What Phase 5 does NOT have** that a real-world user notices:

1. **No touch confirmation.** `user_presence_check()` is a stub returning `true`. Any host process that can send a CTAPHID frame can sign without a human in the loop. This is the #1 thing a hostile reviewer will flag.
2. **No way to enforce "always PIN."** If the RP sends `userVerification: discouraged`, the browser happily signs without prompting. Yubikey exposes this via `ykman fido access enforce-pin`; we don't.
3. **No credential listing or deletion.** `fido2-token -L -r` returns `FIDO_ERR_NO_CREDENTIALS`. Users can't see what's stored on the device or revoke individual creds.

Phase 6 closes those three gaps. It is **not** a hardware-design phase (the daughter board option in the original §6 is obviated by the SW1 discovery — see §1).

**What this phase is NOT**:
- Not adding new crypto. M&D + ClientPIN already shipped.
- Not bumping to ClientPIN protocol v2 (still v1 — protocol v2 is a Phase 8 niceness).
- Not adding hmac-secret or other extensions (Phase 8).
- Not redesigning the credstore schema; we add **one byte** (force_uv flag) and bump schema version.

---

## 1. Decision drift — §2 #3 already amended

Per `feedback_dont_silently_drift_locked_decisions.md`, the original §2 row #3 ("TS1302 has no button — daughter board in Phase 6") was **wrong**: TS1302 has SW1, wired to PH3, which is also BOOT0.

**Amendment landed in this commit:** §2 row #3 now reads "TS1302 DOES have a button — SW1 on PH3 = BOOT0. Sampled by silicon only at reset; runtime-free as ordinary GPIO. No daughter board." The amendment line is dated `2026-05-10 / 2026-05-11`.

Also corrected in this commit:
- §6 Phase 6 entry rewritten with the M1-M4 scope.
- §9 build-system tree drops the `hardware/button-daughter/` directory.
- §13 open question "User-presence button hardware design (daughter board vs repurpose GPIO)" marked **Resolved 2026-05-11** with the SW1 outcome.

No further §2 amendments expected during Phase 6 unless a milestone reveals one.

---

## 2. Pass criterion

**Primary mic-drop test:**

1. Plug dongle into Linux. LED idle (off).
2. Open Firefox → `https://webauthn.io` → click "Register". LED begins slow blink.
3. Press SW1. LED goes solid for ~500 ms. Registration succeeds.
4. Log out. Click "Authenticate". LED blinks. Press SW1. Log in succeeds.
5. **No-touch path:** click Authenticate, wait 35 s without touching. Browser shows operation-cancelled / timed-out (CTAP2_ERR_OPERATION_DENIED). No signature was produced.

**Secondary criteria (Phase 6 complete):**

- `nix run .#force-uv-set 1` then webauthn.io with `userVerification: discouraged` — device still asks for PIN.
- `nix run .#force-uv-set 0` restores normal behaviour.
- `fido2-token -L -r /dev/hidrawN` lists every credential with its RP id and user handle.
- `fido2-token -D -i <credid> /dev/hidrawN` deletes that credential. Reboot dongle. The deleted credential is gone; remaining credentials still authenticate.
- Holding SW1 while plugging USB still enters DFU bootloader (recovery path preserved).
- All Phase 5 validations still pass (validate-phase5 chain green).

---

## 3. Threat model (delta over Phase 5)

Initial 10 rows ship with the draft. **Rows C1..L2 added 2026-05-11 after a Yubico-style red-team review** (independent agent run with full design-doc + Phase 5 source visibility). Severity tags follow the agent's call.

| # | Severity | Attack | Defense in Phase 6 | Validated at milestone |
|---|---|---|---|---|
| 1 | HIGH | Remote/malicious host forges a signature without user consent | `user_presence_check()` blocks signature path until SW1 is pressed within 30 s. Replaces stub-true. | M1 |
| 2 | MEDIUM | Malware on host scripts thousands of GetAssertion calls | Each call now requires a fresh button press. Side benefit: rate-limited by physical UX. | M1 |
| 3 | HIGH | RP sets `userVerification: discouraged` to silently exfil signatures | Force-UV refuses MakeCred / GetAssertion without `pinAuth` regardless of RP hints. CTAP2.1 §6.4 `alwaysUv` semantics. **Default-on after first `setPIN`** (see §4.4). | M2 |
| 4 | MEDIUM | User can't audit what creds are on the device | `authenticatorCredentialManagement` lists creds + RPs. Standard tooling (`fido2-token`, `ykman` analog) works. | M3 |
| 5 | MEDIUM | User can't revoke individual creds | `deleteCredential` sub-command (0x06). PIN-gated. | M3 |
| 6 | LOW | LED leaks crypto operations via timing (side channel) | LED state changes only on protocol-boundary events (start of UP prompt, end of UP prompt). No per-byte or per-block LED writes during AES/HMAC. | M1 (design) + M4 (audit) |
| 7 | LOW | SW1 polling steals cycles from USB / CTAP path | SW1 polling is timer-IRQ-driven, never blocks; LED PWM is via timer compare, no busy-wait. | M1 |
| 8 | INFO | User holds SW1 at plug-in expecting touch, lands in DFU | Documented in README + RECOVERY.md; LED stays dark in DFU mode (factory ROM doesn't drive PA9) so the user can tell. | M4 (docs) |
| C1 | **CRITICAL** | Held / taped / wedged SW1 satisfies every subsequent `user_presence_check()` — defeats the whole point of UP | `user_presence_check` requires a release→press transition from a confirmed-unpressed baseline at entry. Held button does not count as fresh consent — function returns false immediately if button is already pressed at entry. See §4.1. | M1 |
| H1 | **HIGH** | `authenticatorReset` bypasses Force-UV (and user consent generally) within 10 s power-on window — attacker with brief physical access unplugs/replugs → fresh 10 s → wipes PIN + creds + Force-UV silently | Once any state exists (PIN set OR ≥1 cred registered), Reset additionally requires a real SW1 press. 10 s window stays as the anti-host-software gate; SW1 is the anti-passive-physical gate. CTAP2 §6.7 allows this. See §4.7. | M2 |
| H2 | **HIGH** | `deleteCredential` mid-assertion race — credstore mutation between bitmap-write and ECC-erase could interleave with GetAssertion on the same slot → signed authData for a half-deleted credential | Serialize credstore mutations with `s_credmgmt_busy` flag. GetAssertion / MakeCred check it; conflicting concurrent ops return `CTAP2_ERR_CHANNEL_BUSY` (0x06). See §4.5. | M3 |
| H3 | **HIGH** | `pinUvAuthToken` cross-context replay — Phase 5 `pin_verify_pinauth(token, msg)` does not bind to the issuing CTAP command, so a captured `pinAuth` from one context could in principle be replayed against credMgmt sub-commands | Domain-separated HMAC input per CTAP2.1 §6.5.5.7: `HMAC(token, cmd_byte ‖ subcmd_byte ‖ params)[:16]`. Audit all callers of `pin_verify_pinauth` during M3. See §4.5. | M3 |
| H4 | **HIGH** | Force-UV downgrade via flashing older firmware — Phase 5 firmware (v2 schema reader) misreads `force_uv` byte on Phase 6 R-mem (v3) → silent Force-UV disable OR misinterprets it as part of `md_ci[]` → corruption | (a) Place `force_uv` past `GLOBAL_MD_END_OFF` (offset ≥ 321) so it falls outside the v2-known region. (b) Bump R-mem magic `"NX5K"` → `"NX6K"` so older firmware refuses to read v3 R-mem instead of misinterpreting it. See §4.3. | M2 |
| H5 | **HIGH** | Voltage-glitch single-instruction skip of `user_presence_check` return — `if (!user_presence_check()) return DENIED` is one branch; STM32U5 voltage-glitch attacks bypass single conditionals with one skip | Sign-canary return type — function returns `enum up_result { UP_OK = 0xA5C3, UP_FAIL = 0x3C5A }` (or two independent flags AND'd) and the caller compares against the magic value. One skipped instruction does not produce `UP_OK`. See §4.1. | M1 |
| M1 | MEDIUM | `excludeList` UP-skip required by spec (CTAP2.1 §6.1.2 step 3) — when excludeList lands, spec mandates returning `CREDENTIAL_EXCLUDED` *before* invoking UP; careless ordering exfils cred-presence via UP-prompt timing | Documented for the future implementation: excludeList check is pre-UP. Not in Phase 6 scope (deferred). | future |
| M2 | MEDIUM | LED is a covert protocol-boundary channel — webcam adjacent to dongle correlates `LED_AWAITING_TOUCH` with signing events; `LED_ERROR` reveals PIN_BLOCKED to line-of-sight observers | PIN paths leave LED in `LED_IDLE` — visually identical to "nothing happening." Only UP-prompt and explicit-error are visually distinguishable. See §4.2. | M1 design + M4 audit |
| M3 | MEDIUM | `tud_task()` reentrancy during 30 s SW1 wait — a CTAPHID command on a different CID dispatches while UP is awaited; `s_pin_token` and `s_eph_priv` (in `pin.c`) are file-statics and not reentrant | Dispatcher-busy flag: while `user_presence_check` is awaiting OR a credMgmt iterator is open, other-CID commands return CTAPHID `ERR_CHANNEL_BUSY` (0x06). | M1 |
| M4 | MEDIUM | DFU-at-plug-in is a write-arbitrary-firmware vector — attacker with brief physical access + reset flashes anything, bypassing all Phase 6 controls. Spec-allowed factory ROM affordance; not removable. | Tamper-evident seal; prominent README documentation. INFO category at audit. | M4 docs |
| L1 | LOW | AAGUID `…0003` invalidates Phase 5 creds with no deprecation window — RPs that pin AAGUID for high-assurance (enterprise SAML allow-lists) silently lose access | Changelog entry in `docs/WEBAUTHN-NOTES.md §3`. Acceptable trade-off per existing AAGUID policy. | M4 docs |
| L2 | LOW | TROPIC01 firmware version not verified at boot — a swapped or downgraded chip could expose pre-fixed vulnerabilities (M&D semantics, mcounter monotonicity, ECC key generation) | Boot-time check via `lt_get_info_fw_version`; `slots_init` refuses to run below a pinned min-version constant. Defines the "trust the chip" boundary explicitly. See §4.8. | M4 |

---

## 4. Architecture

### 4.1 SW1 / PH3 — hardware and firmware integration

**Pin facts (board.h:38-40):**
- `BOARD_BUTTON_PORT = GPIOH`, `BOARD_BUTTON_PIN = GPIO_PIN_3`.
- GPIOH clock is already enabled at boot (firmware/src/platform/gpio.c:15 — `__HAL_RCC_GPIOH_CLK_ENABLE()`).
- PH3 is currently configured as input pull-down (the BOOT0 sampler also wants pull-down for "boot from flash" default — matches our use).
- BOOT0 sampling is silicon-internal and happens only on rising edge of reset. After reset, PH3 is just an input.

**Debounce strategy:**
- Tactile switches typically bounce for <5 ms. We poll PH3 from a 1 ms SysTick callback.
- 10 ms "stable HIGH" window before declaring "pressed."
- 10 ms "stable LOW" window before declaring "released."
- No software interrupt on the line — polling is simpler and we're not power-constrained.

**Public API (`firmware/src/fido_hid/user_presence.h`):**

```c
/* Sign-canary return type — defends against single-instruction voltage-glitch
 * skip of the return-value check. Magic constants chosen far from 0/1. */
typedef enum {
    UP_OK   = 0xA5C3,
    UP_FAIL = 0x3C5A,
} up_result_t;

/* Block until a complete release→press transition on SW1, or timeout.
 * Returns UP_OK only on a fresh, observed-from-unpressed-baseline press.
 * Returns UP_FAIL on timeout OR on entry-while-already-pressed (defends C1). */
up_result_t user_presence_check(uint32_t timeout_ms);

/* Non-blocking: returns current debounced state. */
bool user_presence_is_pressed(void);

/* Called from SysTick (1 ms) to advance the debouncer. */
void user_presence_systick_tick(void);
```

Caller pattern (defends H5 voltage-glitch — single instruction skip cannot synthesize `UP_OK`):

```c
up_result_t up = user_presence_check(30000);
if (up != UP_OK) {
    return CTAP2_ERR_OPERATION_DENIED;  /* 0x27 */
}
```

Implementation notes:
- **C1 fresh-consent gate:** on entry, if `user_presence_is_pressed()` returns true, immediately return `UP_FAIL`. The function only succeeds on an observed release→press transition from a debounced-LOW baseline within the timeout. A held/taped/wedged button never counts.
- `user_presence_check` does not busy-wait. It loops calling `tud_task()` + 1 ms sleep so USB stays alive (the host expects responsiveness on its CTAPHID interface during the prompt). See M3 dispatcher-busy mechanism in §4.5 — other CIDs receive `ERR_CHANNEL_BUSY` while we're waiting.
- Default timeout per CTAP2 §6.1.2 is 30 s. Caller passes ms.
- `UP_FAIL` is returned on timeout AND on the C1 entry-already-pressed condition. Caller maps to `CTAP2_ERR_OPERATION_DENIED` (0x27) — same code Yubikey uses for ignored prompts.

### 4.2 LED state machine on PA9

The LED is already wired (BOARD_LED_PIN = PA9, active-high, blink module exists in `firmware/src/platform/blink.{h,c}`). Phase 6 reuses it, replacing the current "heartbeat" pattern with a state machine.

| State | LED behaviour | Trigger |
|---|---|---|
| `LED_IDLE` | Off | Boot, or after any operation completes |
| `LED_AWAITING_TOUCH` | 1 Hz blink, 50% duty | `user_presence_check()` entered |
| `LED_CONFIRMED` | Solid on for 500 ms | Touch detected |
| `LED_ERROR` | Rapid blink (5 Hz) for 2 s | UP timeout / PIN_BLOCKED / RESET |
| `LED_DFU_HINT` | n/a — factory ROM owns the pin in DFU mode | At-reset BOOT0 path |

State transitions are managed by a small driver in `firmware/src/platform/led.{h,c}` (new file). Internally uses a TIM timer compare for PWM-style brightness or just GPIO on/off — start with GPIO on/off, add PWM only if the blink looks janky.

**Covert-channel constraints (defends threat M2 in §3):**
- LED state **MUST NOT change** during PIN entry / PIN verification / pinUvAuthToken issuance / any AES or HMAC computation. Those code paths leave the LED in whatever state preceded them (typically `LED_IDLE`).
- Only protocol-boundary events drive LED transitions: enter-UP-wait → `LED_AWAITING_TOUCH`, leave-UP-wait → `LED_CONFIRMED` or `LED_ERROR`, then back to `LED_IDLE`.
- `LED_ERROR` (rapid blink) is reserved for spec-error conditions visible to the user (UP timeout, PIN_BLOCKED, Reset rejection). It does **NOT** fire on internal crypto errors — those return through the CTAP error code, no visual signal.
- M4 audit: cpp-reviewer scans for any `led_set_state(...)` call inside a PIN/AES/HMAC code path. None should exist.

### 4.3 R-mem slot 0 schema v2 → v3 (add force_uv) — downgrade-safe layout

Phase 5 M4 left slot 0 at schema v2 (384 B layout, magic `"NX5K"`, M&D state spans offsets 31..320 — see `slots.c` `GLOBAL_MD_END_OFF`). Phase 6 adds **one byte** for `force_uv`.

**H4 defense:** offset 64 is INSIDE the M&D `md_ci[]` block in v2 — placing `force_uv` there would either be silently lost if an older firmware is reflashed, OR worse, corrupt M&D state if the older firmware writes through the ci[] region. Both outcomes are unacceptable for a security-bearing flag. Two mitigations applied together:

1. **Place `force_uv` past the v2-known region**, at offset `GLOBAL_MD_END_OFF` (= 321). Older firmware doesn't read or write that range, so the byte is invisible (lost on downgrade) but not corrupting.
2. **Bump the magic** from `"NX5K"` → `"NX6K"`. Older Phase 5 firmware doesn't recognise the new magic and (per its existing init path) treats slot 0 as uninitialised → forces a factory_reset rather than misinterpreting v3 layout as v2. This converts a silent-data-corruption attack into a loud "you flashed older firmware on a configured device; please reconfigure" UX.

Proposed v3 layout (delta only):

```
offset  size   field                                            schema since
------  ----   -----                                            ------------
   0      4    magic "NX6K" (0x4E,0x58,0x36,0x4B)                v3 (was "NX5K")
   4      2    schema_version = 3 (uint16_BE)                    v3
   ...
  31     <34>  M&D state (active, next_slot, tag, ci[]) end @321 v2 (unchanged)
  321     1    force_uv (0 = honour RP hint, 1 = always require PIN)  v3
  322    ...   reserved, zero-filled
```

**Migration on boot read:**
- magic `"NX6K"` v3 → use directly.
- magic `"NX5K"` v2 → migrate in-RAM: copy known fields, set `force_uv = 0`, rewrite slot 0 with `"NX6K"` v3. Existing Phase 5 PIN + M&D state preserved.
- magic `"NX5K"` v1 (M3 era, no M&D) → force factory_reset (no resident creds expected at that schema).
- Any other magic / version → factory_reset.

**Migration on flash-downgrade** (Phase 5 firmware on v3 R-mem): Phase 5 reader sees `"NX6K"`, doesn't recognise → init path → factory_reset. User sees "your dongle was wiped." Loud failure; no security regression.

### 4.4 Force-UV semantics — secure-by-default after first setPIN

**Default policy:** when the user calls `setPIN` for the first time (transitioning from "no PIN" → "PIN set"), the firmware **automatically sets `force_uv = 1`**. The reasoning: a user who bothered to set a PIN is signalling "I want PIN required." Honouring that intent without making the user run a separate vendor command matches their mental model and is more secure than Yubikey's default-off Force-UV.

The user retains the ability to opt out via `force-uv-set 0` (PIN-gated, see below).

**When `force_uv == 1`:**
- `getInfo` response: `options.alwaysUv = true` (CTAP2.1 §6.4).
- `MakeCredential` and `GetAssertion`: if the request has no valid `pinAuth`, return `CTAP2_ERR_PIN_REQUIRED` (0x36) regardless of the RP's `userVerification` parameter. This forces the browser to call `getPinToken` first.
- `getInfo` keeps `options.uv = false` (we don't have biometric UV; PIN is UV).

**When `force_uv == 0`:**
- Behaviour unchanged from Phase 5 — RP's `userVerification` hint is honoured. Suitable for a user who wants the touch-only Phase 6 experience without the always-PIN constraint.

**User experience (the Yubikey-style flow, what the user gets after Phase 6 ships):**

```
   ┌── Plug dongle ──┐
   │                 │ Boot. LED idle. No PIN cached.
   │                 │
   │ First WebAuthn  │ → Browser sees alwaysUv=true → calls getPinToken
   │ op of session   │ → Device returns encrypted pinUvAuthToken (32 B, RAM only)
   │                 │ → User enters PIN ONCE in browser dialog.
   │                 │ → Browser caches token for the session.
   │                 │ → MakeCred/GetAssertion proceeds with pinAuth derived from token.
   │                 │ → LED blinks → user presses SW1 → operation completes.
   │                 │
   │ Every subsequent │ → Browser reuses cached token → no PIN prompt.
   │ op (same session)│ → LED blinks → user presses SW1 → operation completes.
   │                 │
   │ Unplug dongle   │ → Token RAM cleared.
   │                 │
   │ Replug dongle   │ → Next op needs PIN again (fresh getPinToken).
   └─────────────────┘
```

This is exactly what CTAP2 §6.5.5.7 specifies for `pinUvAuthToken` lifecycle. Phase 5 M3 already implements the token-RAM-only-until-power-cycle part. Phase 6 just makes sure the device actually demands `pinAuth` on every signing op so that the browser is forced to obtain (and cache) the token.

**Vendor lt-rpc commands** (new, in `firmware/src/hid_rpc/lt_rpc.c`):
- `force-uv-get` → returns one byte (0 or 1). Unauthenticated read (the state is already advertised in GetInfo, so this leaks no new information).
- `force-uv-set <0|1>` → writes the byte. **PIN-gated** in both directions (enable AND disable). Requires an active `pinUvAuthToken` session — i.e., the user must have entered PIN this boot.

**Why PIN-gated both ways:**
- Gating *disable* prevents an attacker with USB access from silently turning off the defense the user opted into.
- Gating *enable* prevents a misconfiguration vector: an attacker who can flip the bit to `1` without PIN could lock the user out (combined with subsequently-set PIN, even). Symmetric gating closes the gap.
- One exception: the **auto-enable on first setPIN** path is implicitly PIN-authed because the PIN being set right now is the PIN being committed — no replay risk.

**Bootstrapping problem (no PIN set yet):** `force-uv-set 1` is rejected by the PIN gate if no PIN has ever been set, because there's no `pinUvAuthToken` to authenticate the call. This is correct — you can't enforce a PIN you don't have. The auto-enable path on first `setPIN` is the supported way to bootstrap. Users who want Force-UV but no PIN are mis-configuring; not in scope.

### 4.5 authenticatorCredentialManagement (CTAP2 cmd 0x0A)

CTAP2.1 §6.8. Implementation in new file `firmware/src/fido_hid/credmgmt.{h,c}`.

Sub-commands we implement:

| Sub-cmd | Name | Action |
|---|---|---|
| 0x01 | getCredsMetadata | Return total existing + max remaining. Reads slot bitmap. |
| 0x02 | enumerateRPsBegin | Return first RP + total RP count. Walks slots, deduplicates by rpIdHash. |
| 0x03 | enumerateRPsGetNextRP | Iterator. State held in static struct; cleared on any other cmd. |
| 0x04 | enumerateCredentialsBegin (by rpIdHash) | Return first credential for given RP + total count for RP. |
| 0x05 | enumerateCredentialsGetNextCredential | Iterator. |
| 0x06 | deleteCredential | Call `credstore_erase(slot_idx)`. |

Sub-commands we DEFER to Phase 8:
- 0x07 updateUserInformation (CTAP2.1 addition; nice-to-have).

**pinUvAuthParam (H3 defense — domain-separated HMAC input):** every sub-command takes a `pinUvAuthParam` = `HMAC-SHA-256(pinUvAuthToken, 0x0a ‖ subCommand ‖ subCommandParams)[:16]`. The leading `0x0a` is the CTAP2 command byte for credMgmt — this binds the HMAC to *this command*, so a captured `pinAuth` from MakeCred (command `0x01`) cannot be replayed against credMgmt. Phase 5 M3's `pin_verify_pinauth(token, msg)` helper is **NOT directly reused** in M3 because it doesn't enforce a domain tag in the input; instead `credmgmt_verify_pin_auth(...)` constructs the domain-separated buffer `[0x0a, subCmd, params...]` and passes it through. Audit checkpoint at M3: confirm no caller of `pin_verify_pinauth` accepts attacker-controlled bytes without a command prefix; if any exists, add the prefix.

**RP enumeration:** walking the credstore looking for unique rpIdHash values. With 32 slots max and 32 B rpIdHash each, this is a 32-pass O(n²) scan. Fine.

**Storage impact:** zero new R-mem writes for read sub-commands. We already store everything needed (rpIdHash, user_handle, user name in slot N+1 metadata from Phase 5 M2). Phase 6 M3 is read-only over the credstore plus `credstore_erase` (already exists from Phase 5 authenticatorReset).

**H2 mutation serialization (deleteCredential race):**

`deleteCredential` invokes `credstore_erase(slot)` which performs two SPI round-trips: first clear the slot bitmap, then erase the ECC slot. Between those, a concurrent CTAPHID `GetAssertion` on the same `slot_idx` could read stale-but-bitmap-claimed-free metadata, or attempt to sign with an ECC key whose pubkey is about to be erased. Mitigation:

```c
/* file-static in credmgmt.c */
static volatile bool s_credstore_mutating = false;

/* deleteCredential and any future write op: */
s_credstore_mutating = true;
credstore_erase(slot);
s_credstore_mutating = false;

/* GetAssertion + MakeCred check at entry: */
if (s_credstore_mutating) {
    return CTAP2_ERR_CHANNEL_BUSY;  /* 0x06 — spec-defined for this exact case */
}
```

The flag is also raised during a credMgmt iterator (so a deleteCredential mid-enumerate doesn't desync the iterator state). Same lock interacts with the M3-flagged `tud_task()` reentrancy concern: a CTAPHID command on a different CID during `user_presence_check` or during a mutation gets `ERR_CHANNEL_BUSY` (0x06) at CTAPHID layer, before ever reaching the CBOR dispatcher.

**Iterator state machine:** any sub-command other than `enumerateRPsGetNextRP` resets the RP iterator. Same for the credential iterator. Strictly spec-conformant per CTAP2.1 §6.8.

### 4.6 ctap2.c GetInfo response changes

GetInfo CBOR map gets:
- Existing `options.up = true` — kept (we now genuinely have UP).
- New `options.alwaysUv` — set to `force_uv` (true/false).
- Existing `options.clientPin = (pin_is_set())` — kept.
- New `pinUvAuthProtocols = [1]` — already present from Phase 5 M3 (commit b95ff09).
- New top-level key `credentialMgmtPreview = true` — CTAP2.0 RPs see this; Phase 6 also adds `credMgmt = true` for CTAP2.1 RPs.
- AAGUID bumps from `...0002` to `...0003`.

AAGUID rationale per `docs/WEBAUTHN-NOTES.md §3` policy: "real UP + alwaysUv + credManagement" are behaviour-relevant changes that affect RP risk assessment. Existing creds bound to AAGUID `...0002` (the user's Phase 5 registrations) will NOT roam to a `...0003` firmware automatically — the user accepts this trade-off, as it's the same trade-off Yubikey makes when firmware versions change.

### 4.7 authenticatorReset gating — add SW1-press requirement (H1 defense)

Phase 5 gated `authenticatorReset` on a single check: `HAL_GetTick() > RESET_WINDOW_MS` (the 10 s post-power-up window from CTAP2.1 §6.8). That window protects against a malicious host process Reset-DoSing a configured dongle from any browser, since the device has been on for longer than 10 s by the time a hostile site loads. **It does NOT protect** against a passive physical attacker who unplugs and replugs your dongle while you're away from your desk: a fresh 10 s starts, and Reset wipes PIN + credentials + Force-UV with no consent.

**Phase 6 tightening:** Reset gates on **(window AND state) → also require SW1 press**.

```
if any state exists (pin_is_set() OR slots_count_used() > 0):
    if HAL_GetTick() > RESET_WINDOW_MS:
        return CTAP2_ERR_NOT_ALLOWED
    up = user_presence_check(10000)        /* 10 s prompt, fits inside the window */
    if up != UP_OK:
        return CTAP2_ERR_OPERATION_DENIED
    proceed with reset
else:  /* virgin device, no state to protect */
    if HAL_GetTick() > RESET_WINDOW_MS:
        return CTAP2_ERR_NOT_ALLOWED
    proceed with reset   /* no SW1 required — no state to wipe */
```

**Why the virgin-device exception:** a factory-fresh dongle (no PIN, no creds) has nothing to defend. Requiring SW1 there would mean the user can't bootstrap their device without first having pressed SW1 once — fine, but it's pointless friction. Skip it.

CTAP2.1 §6.7 explicitly allows requiring UP for Reset. The 10 s window is unchanged (still the spec's primary gate).

**Edge case — Reset within the 10 s window AFTER user already pressed SW1 for an earlier UP-required op:** the C1 rising-edge requirement means the user has to release-then-press again for Reset. This is correct: each consent is per-operation, not a global authorisation.

### 4.8 TROPIC01 firmware version pin at boot (L2 defense)

`slots_init()` runs at every boot. Phase 6 M4 adds a version check at the top of `slots_init`:

```c
struct lt_fw_ver_t fw;
if (lt_get_info_fw_version(&fw) != LT_OK) {
    /* chip not responding or version query unsupported — refuse */
    return SLOTS_ERR_CHIP_VERSION;
}
if (fw.major < NIXTROPIC_TROPIC01_MIN_FW_MAJOR ||
    (fw.major == NIXTROPIC_TROPIC01_MIN_FW_MAJOR &&
     fw.minor < NIXTROPIC_TROPIC01_MIN_FW_MINOR)) {
    return SLOTS_ERR_CHIP_VERSION;
}
```

`NIXTROPIC_TROPIC01_MIN_FW_*` constants are pinned at the version installed on the user's verified TS1302 (silicon `TR01-C2P-T101`, rev ACAB). This boundary is declarative — "we trust the chip's M&D semantics, mcounter monotonicity, and ECC key generation at this version or newer." A swapped/downgraded chip refuses to come up.

Failure UX: LED enters `LED_ERROR` (5 Hz blink, indefinite). USB enumerates the recovery CDC interface but FIDO HID does not start. User can re-flash firmware via DFU. Documented in README + `docs/RECOVERY.md`.

This also gives us a clean place to assert "TROPIC01 ACAB silicon assumption" — `lt_get_info_chip_id` returns the silicon revision; we can demand `ACAB` at boot. (Earlier silicon revisions had different M&D semantics. The Phase 5 design was validated only on ACAB.)

---

## 5. Milestones (each is one HW-validated commit)

### M1 — SW1 user-presence + LED state machine + dispatcher-busy lock

**Deliverable:**
- `firmware/src/fido_hid/user_presence.{h,c}` — debounced PH3 read; `up_result_t user_presence_check(uint32_t timeout_ms)` returning sign-canary enum (H5 defense); release→press transition requirement from confirmed-unpressed baseline (C1 defense); entry-already-pressed returns `UP_FAIL` immediately.
- `firmware/src/platform/led.{h,c}` — LED state machine. Replaces Phase 1 blink heartbeat. Covert-channel constraint enforced: no LED writes inside PIN / AES / HMAC code paths (M2 §3 defense).
- `firmware/src/fido_hid/ctap2_creds.c` — replace hardcoded `FLAG_UP` with conditional based on `user_presence_check()` return checked against `UP_OK`. On `UP_FAIL`, return `CTAP2_ERR_OPERATION_DENIED` (0x27) from MakeCred / GetAssertion. Use the sign-canary compare pattern in §4.1.
- `firmware/src/fido_hid/fido_hid.c` — dispatcher-busy lock: `s_dispatcher_busy` flag raised during `user_presence_check` wait; CTAPHID commands on other CIDs return `ERR_CHANNEL_BUSY` (0x06) (M3 §3 defense).
- `firmware/src/platform/gpio.c` — verify PH3 is configured input + pull-down (it is; double-check at boot).
- `firmware/src/main.c` — SysTick (1 ms) → `user_presence_systick_tick()` + `led_systick_tick()`.
- Update `ctap2.c` GetInfo: `options.up = true` stays (now real), `options.alwaysUv` not yet (M2).

**HW checkpoint** — `nix run .#validate-phase6-m1`:
- Step 1: `fido2-token -I /dev/hidrawN` — confirm `up` still advertised.
- Step 2 (manual / scripted with prompt): MakeCredential. Test prompts user to press SW1 within 30 s. Expect: LED blinks, user presses, success.
- Step 3 (manual): MakeCredential, do NOT press. Expect: 30 s timeout → `CTAP2_ERR_OPERATION_DENIED`.
- Step 4 (C1 regression): MakeCredential with SW1 *already held* at entry → expect immediate `CTAP2_ERR_OPERATION_DENIED` (no 30 s wait, no auth bypass).
- Step 5 (M3 regression): start MakeCredential on CID-A, while it's waiting send PING on CID-B → expect CTAPHID `ERR_CHANNEL_BUSY` from CID-B; CID-A still completes on press.
- Step 6: full validate-phase5 chain still passes (regression).
- Step 7: replug dongle while NOT holding SW1 → normal boot. Replug while HOLDING SW1 → DFU enumerates (1209:beba). Confirms BOOT0 path intact.

**Stop-here value:** real touch-to-confirm, with all three §3 defenses (C1 fresh-consent, H5 voltage-glitch, M3 reentrancy) already baked in. The biggest "this is a real security key" moment.

### M2 — Force-UV (auto-enable on first setPIN) + alwaysUv + Reset-with-SW1

**Deliverable:**
- `firmware/src/fido_hid/slots.{h,c}` — schema v2→v3 migration with magic bump `"NX5K"` → `"NX6K"` (H4 defense); `force_uv` byte placed at offset `GLOBAL_MD_END_OFF` (321) past the v2-known region; `slots_force_uv_get/set`; preserve existing Phase 5 PIN + M&D state through migration.
- `firmware/src/fido_hid/pin.c` — first-`setPIN` path: on the no-PIN → PIN-set transition, automatically write `force_uv = 1` (defends the "user set PIN, expected PIN to be required, RP sent uv:discouraged and bypassed it" gap from Phase 5 testing).
- `firmware/src/hid_rpc/lt_rpc.c` — new sub-commands `FORCE_UV_GET` (unauthenticated read — info is already in GetInfo), `FORCE_UV_SET` (PIN-gated in BOTH directions; refuses if no PIN ever set).
- `tools/lt_rpc.py` — Python wrapper functions `force_uv_get/set`.
- `firmware/src/fido_hid/ctap2.c` — GetInfo `options.alwaysUv` reflects flag; also gate `CTAP2_CMD_RESET` to require `user_presence_check(10000) == UP_OK` if `pin_is_set() || slots_count_used() > 0` (H1 defense, see §4.7). 10 s window unchanged.
- `firmware/src/fido_hid/ctap2_creds.c` — MakeCred + GetAssertion: when `force_uv` and no `pinAuth`, return `CTAP2_ERR_PIN_REQUIRED` (0x36).
- `nix run .#force-uv-get` / `force-uv-set` apps.

**HW checkpoint** — `nix run .#validate-phase6-m2`:
- Step 1 (auto-enable): factory-reset; `fido2-token -S` (set PIN); `force-uv-get` → expect `1` (auto-enabled on first setPIN).
- Step 2: `fido2-token -I` shows `alwaysUv: true`.
- Step 3: `fido2-cred -M` (no PIN provided) → expect `FIDO_ERR_PIN_REQUIRED`.
- Step 4: `fido2-cred -M -h ... -P pin` → expect success.
- Step 5: `force-uv-set 0` (PIN-gated) → succeeds with PIN. Confirm: same MakeCred with `uv: discouraged` now succeeds without PIN.
- Step 6: `force-uv-set 1` → succeeds with PIN. Confirm: alwaysUv=true again.
- Step 7 (browser test): webauthn.io login with browser's heuristic `userVerification: discouraged` → device demands PIN once for the session; cached afterward (PIN-once-per-cycle UX validated).
- Step 8 (H1 Reset gating): with force_uv=1 and a PIN set, unplug → replug within 10 s → send `authenticatorReset` immediately. Expect: LED blinks for SW1, do NOT press → expect `CTAP2_ERR_OPERATION_DENIED`. State preserved.
- Step 9 (H1 happy path): same setup, press SW1 when LED blinks during Reset prompt → Reset succeeds, state wiped, force_uv back to 0 (no PIN now).
- Step 10 (H4 downgrade): flash Phase 5 firmware on this Phase 6 R-mem → Phase 5 firmware sees magic `"NX6K"`, doesn't recognise, init path forces factory_reset. Confirm loud failure, no silent state corruption.

**Stop-here value:** PIN-once-per-cycle, touch-per-op UX is now the default. Defense-in-depth: passive physical attacker can't Reset without SW1. Closes task #53.

### M3 — authenticatorCredentialManagement (cmd 0x0A) + serialization + domain-separated pinAuth

**Deliverable:**
- `firmware/src/fido_hid/credmgmt.{h,c}` — sub-command dispatcher, iterator state, pinUvAuthParam verifier. **`credmgmt_verify_pin_auth(subCmd, params, pinAuth)` constructs domain-separated HMAC input `[0x0a, subCmd, params...]` (H3 defense).** Audit pass: confirm `pin_verify_pinauth(token, msg)` is NOT used directly with attacker-controlled bytes anywhere in credmgmt code; all paths go through the domain-separated helper.
- `firmware/src/fido_hid/credstore.{h,c}` — add `s_credstore_mutating` flag (file-static volatile). `deleteCredential` raises it before `credstore_erase`, lowers after. Export `credstore_is_mutating()` for callers. (H2 defense.)
- `firmware/src/fido_hid/ctap2_creds.c` — MakeCred + GetAssertion entry: check `credstore_is_mutating()` and `s_dispatcher_busy`; if either is set, return `CTAP2_ERR_CHANNEL_BUSY` (0x06). Tied to the M1 dispatcher-busy lock.
- `firmware/src/fido_hid/ctap2.c` — wire CTAP2_CMD_CREDENTIAL_MGMT (0x0A) into dispatcher.
- `firmware/src/fido_hid/credstore.{h,c}` — expose read helpers credmgmt.c needs (RP-by-index, cred-by-RP-and-index).
- `tools/fido2_test.py` — add `sub_validate_m3` (list + delete + relist + concurrent-delete-during-assertion race test).

**HW checkpoint** — `nix run .#validate-phase6-m3`:
- Register 3 creds on webauthn.io across 2 RP IDs.
- `fido2-token -L /dev/hidrawN` lists RPs — expect 2.
- `fido2-token -L -k <rpid> /dev/hidrawN` lists creds for one RP — expect 2 if registered there.
- `fido2-token -L -r /dev/hidrawN` lists all 3 with metadata.
- `fido2-token -D -i <credid> /dev/hidrawN` deletes one.
- Re-list — expect 2 remaining.
- GetAssertion for deleted cred → `CTAP2_ERR_NO_CREDENTIALS`.
- Reboot → state persists.

**Stop-here value:** users can audit and revoke. Closes task #54.

### M4 — TROPIC01 FW version pin + cpp-reviewer audit + validate-phase6 + ship

**Deliverable:**
- `firmware/src/fido_hid/slots.c` `slots_init()` — add boot-time TROPIC01 FW version check via `lt_get_info_fw_version`; refuse to init below `NIXTROPIC_TROPIC01_MIN_FW_*` constants (L2 defense, see §4.8). Also assert silicon revision `ACAB` via `lt_get_info_chip_id`. Failure UX: LED `LED_ERROR`, FIDO HID interface not started; CDC stays up for diagnostic.
- `firmware/src/tropic/tropic.h` — define `NIXTROPIC_TROPIC01_MIN_FW_MAJOR` / `_MINOR` constants pinned at the version installed on the user's verified ACAB chip.
- `nix run .#validate-phase6` — chains M1+M2+M3. Per `feedback_validation_temporal_constraints.md`, **M1 first** (touch path needs human; long-running CTAP/ECDH crypto would push other tests way out). Order: `validate-phase6-m1` (with prompt) → `validate-phase6-m2` → `validate-phase6-m3`. Also confirm Phase 5 chain still passes (regression).
- `nix run .#flash-and-validate-phase6`.
- **cpp-reviewer audit pass** scoped to: `user_presence.c`, `led.c`, `credmgmt.c`, force-UV gate diff in `ctap2_creds.c`, Reset gate diff in `ctap2.c`, schema-migration diff in `slots.c`. Specific audit prompt addenda for this phase:
  - Verify C1: no path through `user_presence_check` returns `UP_OK` from an entry-already-pressed state.
  - Verify H1: no path through `CTAP2_CMD_RESET` proceeds without `user_presence_check == UP_OK` when state exists.
  - Verify H2: no path through `credstore_erase` is concurrent with a GetAssertion / MakeCred without `CTAP2_ERR_CHANNEL_BUSY`.
  - Verify H3: no call site of `pin_verify_pinauth` accepts attacker-controlled bytes without a command-byte prefix.
  - Verify H4: `slots_init` rejects magic `"NX5K"` on Phase 6 firmware (or migrates only on the v2→v3 read path; never on the write path).
  - Verify H5: `user_presence_check` return type is `up_result_t` enum, never `bool`; all call sites compare to `UP_OK` not truthiness.
  - Verify M2: no `led_set_state(...)` invocation appears in any PIN, AES, or HMAC function.
  - Verify M3: dispatcher-busy flag prevents reentrancy through `tud_task()` during UP wait or credMgmt iterator.
  - Verify L2: `slots_init` performs version check before any other chip operation.
- `nix run .#lint` clean.
- AAGUID bumped to `6e697874726f70696300000000000003` in `ctap2.c` + `docs/WEBAUTHN-NOTES.md §3` history (L1 changelog entry).
- README + `docs/RECOVERY.md` updated with the SW1-at-plug-in DFU-mode caveat (M4 §3 doc).
- `STATUS.md` Phase 6 entry at top.
- `PROJECT.md` §6 Phase 6 marked ✅ COMPLETE.
- Memory: `project_phase6_done.md` + any new feedback entries.
- **THE FINAL TEST:** plug dongle → Firefox → webauthn.io register (LED blinks → press SW1 → success) → log out → log in (LED blinks → press SW1 → success). Record screen+dongle for README demo.

**Stop-here value:** Phase 6 done; ready for Phase 7 (CCID OpenPGP card) or a public demo.

---

## 6. Code-organization rules for Phase 6 (continuing Phase 5 discipline)

- Each new file ≤ 400 LOC. Split if exceeded.
- No new global variables outside file-scope statics.
- `user_presence.c` has zero crypto and no R-mem touch — pure HW driver. Easy to audit.
- `credmgmt.c` uses the new `credmgmt_verify_pin_auth(subCmd, params, pinAuth)` wrapper that constructs the domain-separated HMAC input. The wrapper reuses Phase 5's HMAC primitive but does NOT take attacker-controlled bytes through `pin_verify_pinauth` directly (H3 defense).
- LED writes never gated by secret data — only by protocol-state.
- No `printf` in PIN/UP paths (timing channel).
- No malloc anywhere.
- Every new CTAP2 sub-command has a comment block citing the CTAP2.1 §6.8 sub-section.

---

## 7. Risk register

Project / development risks (the §3 table is security threats; this is "things that might trip us during the implementation").

| ID | Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|---|
| R1 | SW1 debounce window too short → multiple presses register; too long → sluggish | M | L | Start with 10 ms stable-high + 10 ms stable-low. Tune from HW test. |
| R2 | User holds SW1 while plugging cable expecting touch → DFU bootloader | H | L | Document prominently (README + RECOVERY.md). LED-off in DFU is a tell. |
| R3 | LED blinking interferes with USB IRQ → CTAP latency spike | L | M | LED state changes only on protocol boundaries; SysTick (1 ms) is the heartbeat for both UP polling and LED ticks; both are fast. |
| R4 | Force-UV PIN-gating allows footgun (lose PIN = can't disable Force-UV) | M | L | authenticatorReset still works (10 s window + SW1 press) — clears Force-UV alongside PIN + creds. Lost-PIN recovery path is "factory reset then re-bootstrap." |
| R5 | credentialManagement iterator state desyncs if RP interleaves sub-commands | M | M | Strict state machine: any sub-command other than `enumerateRPsGetNextRP` resets the RP iterator. Same for cred iterator. CTAP2.1 §6.8 spec-conformant. |
| R6 | Schema migration v2→v3 silently corrupts existing creds on first boot of new firmware | L | H | H4 mitigations (magic bump + offset past `GLOBAL_MD_END_OFF`) close the silent-corruption path. Test: register on v2, flash v3, verify cred still authenticates. Test: register on v3, flash back v2, verify Phase 5 firmware forces factory_reset rather than misreading. |
| R7 | LED PA9 conflicts with another peripheral we forgot | L | L | PA9 was already LED in Phase 1 (blink.c). Nothing else uses it. |
| R8 | webauthn.io / Firefox / Chrome don't actually invoke UP for `discouraged` | M | M | We enforce UP for every signing operation regardless of RP hint — spec-compliant per CTAP2 §6.1.2. RPs that send `userPresence: false` are non-conformant and we reject. |
| R9 | tud_task() not pumped during 30 s wait → host treats device as hung | M | M | `user_presence_check()` loop calls `tud_task()` every 1 ms. Plus SW1 polling is in SysTick which fires regardless. M3 §3 dispatcher-busy lock returns `ERR_CHANNEL_BUSY` to other CIDs so they don't pile up. |
| R10 | Removing `LED_HEARTBEAT` confuses anyone debugging Phase 1-5 behaviour | L | L | Keep a `LED_HEARTBEAT` state for boot phase / pre-USB-enum. Switch to `LED_IDLE` once USB is up. |
| R11 | TROPIC01 FW version pin too aggressive — chip firmware update (legit) refuses to come up | L | M | Pin to **minimum**, not exact. Document the bump procedure (rebuild firmware with new `NIXTROPIC_TROPIC01_MIN_FW_*` constants). |
| R12 | H1 Reset-with-SW1 locks user out of recovery if dongle is bricked AND SW1 is damaged | L | L | DFU recovery path via BOOT0 strap is independent of firmware Reset. Pressing SW1 *at-reset* enters DFU (factory ROM); SW1 *at-runtime* gates Reset. Two independent paths. |
| R13 | Force-UV auto-enable surprises a user who didn't realise setPIN flips the bit | M | L | Communicate clearly in `lt-rpc` UX response ("PIN set; Force-UV automatically enabled — disable with `force-uv-set 0` if undesired"). README documents the policy. |
| R14 | C1 entry-already-pressed false-positive — user with shaky hands still touching SW1 from previous op | L | L | Debounce LOW window (10 ms) means a normal release-and-press cycle takes ≥20 ms — fast user can chain operations. We don't expect humans to chain UP-required ops faster than that. |
| R15 | H5 sign-canary `up_result_t` doesn't actually defend on real STM32U5 — voltage glitches can flip multi-byte returns | L | M | Two independent flag updates in `user_presence_check` AND a magic-value compare at call site. A single glitch must flip BOTH paths to forge `UP_OK`. Cheap defense; well-precedented in Yubico's open-source firmware. |

---

## 8. Open questions to resolve before each milestone

Questions resolved during red-team review (2026-05-11) are struck through and annotated.

### Before M1

- [ ] Confirm SysTick callback hook in `main.c` accepts a new `user_presence_systick_tick()` without breaking the existing `tud_task()` cadence.
- [ ] Confirm `tud_task()` is safe to call from within `user_presence_check()`'s wait loop (it is — TinyUSB is non-reentrant per-endpoint but `tud_task` from main context is fine; verify in Phase 1 main.c).
- [ ] Decide: LED blink 1 Hz or 2 Hz during wait? Yubikey uses 2 Hz. We match for muscle memory.
- [x] ~~Decide: should `user_presence_check` accept the current pressed state as a valid press (sticky-button), or require a rising edge?~~ **Resolved 2026-05-11 (C1 finding):** mandatory release→press transition from confirmed-unpressed baseline. Entry-already-pressed returns `UP_FAIL` immediately. See §4.1.
- [x] ~~Decide: return type for `user_presence_check`?~~ **Resolved 2026-05-11 (H5 finding):** `up_result_t` sign-canary enum, never bare bool. See §4.1.
- [ ] Decide: where to put the dispatcher-busy lock (M3 §3) — inside `fido_hid.c` CTAPHID dispatcher, or inside `ctap2.c` CBOR dispatcher? Probably CTAPHID layer so other-CID PINGs / INIT can still respond.

### Before M2

- [x] ~~Confirm available offset in R-mem slot 0 v2 layout for the new byte. If offset 64 is inside M&D block, put it past `GLOBAL_MD_END_OFF` (= 321).~~ **Resolved 2026-05-11 (H4 finding):** placed at offset 321 (past `GLOBAL_MD_END_OFF`). PLUS magic bump `"NX5K"` → `"NX6K"` so older firmware refuses to read v3 R-mem. See §4.3.
- [x] ~~Decide: gate `FORCE_UV_SET=0` (disable Force-UV) with PIN auth?~~ **Resolved 2026-05-11:** yes, both directions PIN-gated. See §4.4.
- [x] ~~Decide: what happens if Force-UV is set but `pin_is_set()` is false?~~ **Resolved 2026-05-11:** `force-uv-set 1` rejected without PIN; auto-enable on first `setPIN` is the supported bootstrap. See §4.4.
- [x] ~~Decide: should Force-UV be default-on or opt-in?~~ **Resolved 2026-05-11 (user direction):** auto-enable on first `setPIN`; user can opt out via PIN-gated vendor cmd. See §4.4.
- [x] ~~Decide: should `authenticatorReset` require SW1 press?~~ **Resolved 2026-05-11 (H1 finding):** yes, when state exists (PIN set OR ≥1 cred). 10 s window unchanged. See §4.7.

### Before M3

- [ ] CBOR encoding for credentialManagement responses — confirm key numbering matches CTAP2.1 §6.8.4. (Use canonical spec; libfido2 enforces strict.)
- [x] ~~Iterator timeout~~ **Resolved (spec-cited):** any non-enumerate sub-cmd resets the iterator. CTAP2.1 §6.8.
- [ ] Pre-check: `fido2-token -L -r` actually exercises the full enumerate flow on Linux + libfido2 current; can we test it without writing our own host harness? Yes — libfido2 in nixpkgs is current enough.
- [x] ~~pinUvAuthParam construction~~ **Resolved 2026-05-11 (H3 finding):** domain-separated input `[0x0a, subCmd, params...]`. See §4.5.
- [x] ~~deleteCredential mid-assertion race?~~ **Resolved 2026-05-11 (H2 finding):** `s_credstore_mutating` flag; conflicting ops get `CTAP2_ERR_CHANNEL_BUSY`. See §4.5.

### Before M4

- [ ] cpp-reviewer prompt drafted before M4 starts. Scope expanded by §3 additions: `user_presence.c`, `led.c`, `credmgmt.c`, force-UV gate diff in `ctap2_creds.c`, Reset gate diff in `ctap2.c`, schema-migration diff in `slots.c`. Specific C1/H1/H2/H3/H4/H5/M2/M3/L2 verification clauses listed in M4 deliverable.
- [ ] Screen-recording setup for demo (dongle close-up + browser side-by-side).
- [x] ~~`validate-phase6` interactive prompts?~~ **Decision: keep prompt in validate-m1; CI doesn't run this anyway.**
- [x] ~~TROPIC01 FW version pin?~~ **Resolved 2026-05-11 (L2 finding):** `slots_init` calls `lt_get_info_fw_version` + `lt_get_info_chip_id`; refuses below `NIXTROPIC_TROPIC01_MIN_FW_*` or non-ACAB silicon. See §4.8.

---

## 9. Compile-time / runtime budgets

Budgets updated 2026-05-11 to reflect §3 defenses (sign-canary return type, dispatcher-busy lock, schema magic bump, TROPIC01 FW version check, Reset SW1-gate).

| Resource | Phase 5 | Phase 6 estimate | Limit | Headroom |
|---|---|---|---|---|
| Flash (firmware.bin) | 202 KB | +20 KB (UP driver + sign-canary ~3 KB, LED FSM ~1 KB, credMgmt + domain-sep + busy lock ~13 KB, Force-UV + Reset-gate + schema-migrate ~2 KB, TROPIC01 FW pin ~1 KB) ≈ 222 KB | 256 KB | 34 KB |
| RAM | 25.6 KB | +1.5 KB (UP debounce state + entry-pressed tracker, LED FSM state, credMgmt iterator state, dispatcher-busy + credstore-mutating flags) ≈ 27.1 KB | 192 KB | 164 KB |
| ECC slots used | up to 32 | unchanged | 32 | 0 (at full credential load) |
| R-mem slot 0 fields | 384 B v2 | +1 B (force_uv past offset 321) → v3 | 475 B | 89 B |
| M&D slots used | 8 | unchanged | 128 | 120 |
| Stack high-water mark | TBD | +200 B credMgmt enumerator stackframe + ~100 B for sign-canary double-check locals | ~6 KB available | OK |

---

## 10. Stop-here value at each milestone

- **After M1:** "Real touch-to-confirm working." The single biggest UX upgrade. The dongle now feels like a Yubikey.
- **After M2:** "Always-PIN enforceable." Closes the `uv: discouraged` defensive gap. Closes task #53.
- **After M3:** "Users can audit and revoke creds." Standard tooling works. Closes task #54.
- **After M4:** "Phase 6 complete; ready for Phase 7 or public demo."

---

## 11. Sign-off checklist (read before approving M1 start)

Plan-doc bookkeeping done in this commit:

- [x] PROJECT.md §2 #3 amended.
- [x] PROJECT.md §6 Phase 6 entry updated.
- [x] PROJECT.md §9 `hardware/button-daughter/` directory removed.
- [x] PROJECT.md §13 open question marked Resolved.
- [x] §3 expanded with 12 red-team findings (C1, H1-H5, M1-M4, L1, L2) — 2026-05-11 commit.
- [x] §4.1-§4.8 updated with the defenses for each finding.
- [x] §4.4 rewritten for auto-enable-on-first-setPIN + PIN-once-per-cycle UX (per user direction).
- [x] §4.7 added (Reset-with-SW1 gating, H1).
- [x] §4.8 added (TROPIC01 FW version pin at boot, L2).
- [x] M1-M4 milestone deliverables updated with defenses baked in.
- [x] §7 risk register expanded (R11-R15).
- [x] §8 open questions resolved where the red-team review settled them.
- [x] §9 budgets updated.

Awaiting user sign-off:

- [ ] Threat-model delta (§3 22 rows) acceptable as the security commitment for Phase 6.
- [ ] Auto-enable Force-UV on first `setPIN` (more secure than Yubikey default) is the intended UX.
- [ ] R-mem slot 0 schema v2→v3 migration strategy acceptable: magic bump `"NX5K"` → `"NX6K"` + offset 321 placement.
- [ ] Reset-with-SW1 gating acceptable (10 s window unchanged; SW1 added when state exists).
- [ ] TROPIC01 FW version pin policy acceptable: minimum-version + ACAB-silicon requirement; below-minimum chip refuses to init FIDO.
- [ ] AAGUID bump to `...000003` acceptable (existing Phase 5 creds will not roam; same trade-off as Yubikey firmware versions).
- [ ] Milestone breakdown M1-M4 makes sense (HW checkpoint between each).
- [ ] User explicitly OK with starting M1 (SW1 + LED + dispatcher lock) before any Force-UV or credMgmt code.
- [ ] Memory + flash budget acceptable (~222 KB / 256 KB, 34 KB headroom).
- [ ] User explicitly OK with pushing the Phase 5 stack to origin BEFORE starting Phase 6 work (recommended — clean baseline).

---

*End of PHASE-6-PLAN.md draft.*
