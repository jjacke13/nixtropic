# Phase 9 M5 — Design: the DEC key wrapped under k

Contract: `docs/PHASE-9-PLAN.md` §7. Builds on `docs/PHASE-9-M4-DESIGN.md` (record pairs,
kernel v2, D4 "change keeps s", D8 "destruction before defaults"). PIN hashes are already
gone (M4 D6), so M5 is **only** the OpenPGP decryption key.

r2 (2026-10-17): Jan's r1 review (CHANGES REQUIRED, J1–J5) resolved — see §8.

## 0. What is wrong today (code facts)

| # | Fact | Where |
|---|---|---|
| F1 | The X25519 DEC private key is stored **plain** in O3 (payload offset 122, 32 B, both copies). | `openpgp_state.c:28`, `pgp_keys.c:107-134` |
| F2 | READ PUBLIC KEY (no PIN) derives the public key from that private key. | `pgp_keys.c:137-150` |
| F3 | The kernel already returns `k = HMAC(s, 0x02)` on setup / verify / change; `pgp_pin.c` passes `NULL`. | `pgp_pin.c:105,121,131` |
| F4 | Before on-card key generation gpg checks PW1 (`check_pin_for_key_operation` → `agent_scd_checkpin`). scdaemon 2.4.8 sends **VERIFY 81** when both DEC and AUT keys are absent (fresh card), **VERIFY 82** when a DEC key exists; GENERATE itself adds PW3 only (Jan J1, probed). | gnupg 2.4.8 `g10/card-util.c:1333`, `scd/app-openpgp.c:2851-2885, 5117` |
| F5 | RESET RETRY COUNTER via PW3 (P1 = 02) checks the new PIN's length only inside `pgp_pin_reset_pw1`. | `pgp_pin.c:138`, `openpgp_applet.c` `handle_reset_rc` |
| F6 | Gladman `gcm_decrypt_message` writes plaintext before checking the tag and compares with `memcmp`. | trezor `aes/aesgcm.c:538-542` |

## 1. Decisions

- **E1. Wrap = AES-256-GCM** (trezor `aes/aesgcm.c`, already linked for L3). AES-KW is
  not in the tree; GCM is allowed by PLAN §7.2. Nonce: 12 B fresh from the chip TRNG for
  every seal, full 128-bit tag. Budget: far below 2^32 seals per KEK (one per GENERATE
  DEC; NIST SP 800-38D §8.2.2 / §8.3). No O3 counter as nonce: R-mem can roll back (Jan).
- **E2. KEK = HMAC-SHA256(k, "nixtropic/openpgp/dec-kek/v1")**. Domain-separated from
  `t`, `u`, `k` (M4 §3.3) and from the FIDO binding (different s).
- **E3. AAD** = `"NXDW" | obj 3 | schema 2 | dec_pub[32]`. The wrap is bound to its own
  public key: swapping the wrap or the public key **alone** fails the tag. AAD
  authenticates, it does not prove freshness: a complete older `{pub, nonce, ct, tag}`
  sealed under the same KEK still opens (residual §6, J5).
- **E4. The public key is stored** next to the wrap. READ PUBLIC KEY needs no PIN and no
  unwrap (PLAN §7.2).
- **E5. RAM cache = the KEK only**, never the private key. PW1.81 and PW1.82 are the same
  PIN with the same s, so **either** verify yields the same k. The KEK is valid **iff**
  `AUTH_81` or `AUTH_82` is set; one helper keeps flags and KEK in step (§4). Every
  PSO:DEC unwraps into a stack buffer, uses it, wipes it.
- **E6. GENERATE DEC needs PW3 and a verified PW1 (81 or 82)** — needed because gpg on a
  fresh card verifies 81 only (F4). This revises PLAN §7.3 ("PW1.82 session"): the KEK
  is the same for both references, and no new right is given — **PSO:DEC still needs
  82**; 81 is never turned into 82. Without the KEK GENERATE DEC answers `6982` and
  writes nothing.
- **E7. PW1 change keeps s** (M4 D4) → k and the KEK are unchanged → the wrap stays
  valid. Nothing to do, also after an error that may have committed the new PIN
  (Jan's M4 step 2 lesson: k is the same either way). Same-s change matches TROPIC01
  PIN app note §3.4 Note p7 / §3.5 step 13 p10 (Jan).
- **E8. A PW1 reset (RESET RETRY COUNTER via RC, or via PW3) destroys the DEC key**,
  after every check that can refuse the reset has passed (preflight, J2) and before the
  new PW1 is bound with a fresh s (D8 order, §3). OpenPGP 3.4.1 §7.2.4 does **not**
  require this; it is our policy, owner-approved (Vaios: after a reset `gpg --decrypt`
  of old messages fails, after a change it works), and documented as data loss.
- **E9. Schema bump O3 1 → 2, no migration** (as in M4: the user resets once).
  A schema-1 O3 reads as damaged → ERROR → TERMINATE + ACTIVATE. Release note says so.
- **E10. Unwrap checks the tag first** (F6): GCM split API, pass 1 = header + ciphertext
  authentication → tag → **constant-time** compare; pass 2 (same nonce) decrypts only
  after a match. A failed tag never produces plaintext. All temporaries (k, KEK copies,
  the GCM context with its expanded key, the private key, the shared secret on failure)
  are wiped on **every** exit (single-exit functions).

## 2. O3 schema 2

Fields 0–121 unchanged. The plain key (122, 32 B) is replaced by:

| off | len | field |
|---|---|---|
| 122 | 32 | `dec_pub` — X25519 public key (all zero = no DEC key) |
| 154 | 12 | `dec_nonce` |
| 166 | 32 | `dec_ct` — wrapped private key |
| 198 | 16 | `dec_tag` |

`O3_LEN` 154 → 214 (≤ `REC_PAYLOAD_MAX` 424). A DEC key exists **iff** `dec_pub` is
non-zero; `fields_ok` rejects a non-zero `dec_pub` with an all-zero tag+ct, and a zero
`dec_pub` with non-zero wrap bytes (damage, not a state).

API change in `openpgp_state.h`: `dec_priv_get/set` go away; new
`openpgp_state_dec_get(pub, nonce, ct, tag)` (-1 = none / unusable),
`openpgp_state_dec_set(pub, nonce, ct, tag)` (writes nothing else), and
`openpgp_state_dec_destroy()` = **one** commit that zeroes `dec_pub`, the wrap, the DEC
fingerprint (C8) and its generation time (CF), so gpg sees "no key".

## 3. Lifecycle — one rule per event

Inherited from M4 and true for **every** row below (J4): a fault inside a correct
verify / change that uses the PIN's **last remaining slot** leaves that PIN BLOCKED (no
KEK); a failed pair write or repair leaves the object uncertain → ERROR until reboot;
damage at rest reads CORRUPT → ERROR, recovered by TERMINATE (M4 §1.1, §3.3 "Last
slot", §13; `rec_pair.c:98-108,141,154-160`). The chip gives no old/new atomicity of its
own; only the record pair does.

| Event | Sequence | One fault leaves |
|---|---|---|
| VERIFY 81 / 82 ok | kernel verify → k → KEK = E2 → wipe k → set the flag + KEK together | no flag, no KEK (attempt spent per M4); or flag + KEK |
| VERIFY 81 / 82 wrong | `auth_drop(81\|82)` (today's behaviour) | no flag, no KEK |
| VERIFY FF 81 / FF 82, CDS consuming 81 (C4 `00`) | `auth_drop(that flag)`; KEK wiped once neither 81 nor 82 is left | — |
| VERIFY 83 wrong / FF 83 | clears 83 only; the KEK belongs to PW1 and stays | — |
| Card reset, USB reset, SELECT other AID, TERMINATE, ACTIVATE | `auth_drop(all)` | — |
| PW1 change (ok, wrong, or error) | `auth_drop(81\|82)` first (today); s kept (E7) | M4 kernel rows; k unchanged either way |
| GENERATE DEC (PW3 + KEK) | TRNG priv → clamp → pub → TRNG nonce → seal → `dec_set` (one pair write) → wipe priv | old key, or new key; uncertain → ERROR |
| GENERATE DEC fails (TRNG, seal, write) | wipe temporaries → `auth_drop(81\|82)` | as above |
| PSO:DEC (82 + KEK + UIF touch) | `dec_get` → unwrap (E10) → ECDH → wipe priv | no write |
| PSO:DEC, no key | `6A88` (OpenPGP §7.6) | — |
| PSO:DEC, tag fails (damage) | `6F00`, output wiped, `auth_drop(81\|82)`, nothing rewritten | — |
| READ PUBLIC KEY | `dec_pub` | no write |
| PW1 reset (RC or PW3) | **preflight**: authorization (RC verified, or 83 set), new-PIN length, lifecycle OPERATIONAL, PW1 not ERROR — any refusal answers and touches nothing → `auth_drop(81\|82)` → if a DEC key exists: `dec_destroy` (checked; **failure stops here**, no reset) → `pgp_pin_reset_pw1` | old PIN + old key; old PIN + key destroyed (retry the reset); new PIN + key destroyed |
| PW1 blocked | nothing: s is unreachable, the wrap is cryptographically dead; a reset destroys it formally | — |
| TERMINATE / bootstrap | `pgp_wipe` already erases both O3 copies (M4 §5) | M4 rows |
| ACTIVATE | O3 OPERATIONAL defaults = no DEC key | M4 row |

The "old PIN + key destroyed" row is a permitted intermediate under D8: destruction ran
before the default; no access is gained. It is listed in §6.

**Key replacement does not drop the cache** (revises PLAN §7.4 "key replacement"): the
cache is the KEK, a function of s, not of the key; no unwrapped key is ever cached, so a
new key leaves nothing stale. Dropping 81 there would also break gpg, which signs the new
key's binding with PSO:CDS right after generating.

## 4. Applet changes (`openpgp_applet.c`)

- `static uint8_t s_kek[32]; static bool s_kek_ok;` next to `s_auth`.
- `auth_drop(mask)`: clears the bits; if neither `AUTH_81` nor `AUTH_82` is left,
  `memzero(s_kek)`, `s_kek_ok = false`. **Every** `s_auth &= ~…` and `s_auth = 0` site
  (lines 530, 583, 594, 617, 654, 973, 1019, 1037, 1099) goes through it. A host test
  greps the source: no direct `s_auth &=` / `s_auth = 0` outside the helper.
- `auth_grant(flag, k)`: derives the KEK, sets flag and KEK, wipes its copy of k. Called
  only from VERIFY 81 / 82 success.
- PSO:DEC checks `(s_auth & AUTH_82) && s_kek_ok`; GENERATE DEC checks
  `(s_auth & AUTH_83) && s_kek_ok`.
- `pgp_pin_verify` gains `uint8_t out_k[32]` (nullable), passed to the kernel.
- `pgp_pin_reset_pw1_check(pin, len)`: the refusals of `pgp_pin_reset_pw1` without side
  effects (length, lifecycle, PW1 state), for the preflight; the applet's PW3 path gets
  the same length check the RC path already has.

`pgp_keys.c`: `generate_dec(kek, pub_out)`, `read_dec_pubkey(pub_out)`,
`ecdh_dec(kek, peer, shared_out)`. Seal / open are two static functions there.

## 5. Validation

**Host** (`nix build .#host-tests`; link `aes/aesgcm` + `gf128mul`):
1. Round trip: VERIFY 82 → GENERATE → PSO:DEC = X25519 reference. Also the gpg fresh-card
   order: VERIFY 83 + **81 only** → GENERATE DEC ok → PSO:DEC `6982` → VERIFY 82 → ok.
2. No KEK: GENERATE DEC `6982` with PW3 only; PSO:DEC refused with 81 only; after each
   `auth_drop` event of §3 (one test per row); wrong / FF 83 keeps the KEK.
3. Tamper: flip one bit in each of `dec_pub`, nonce, ct, tag (both copies) → PSO:DEC
   `6F00`, output all zero, flags dropped, nothing rewritten.
4. Change keeps decryption; RC reset and PW3 reset destroy (READ PUBLIC KEY and
   PSO:DEC → `6A88`, C8/CF zero).
5. Preflight (J2): PW3-path reset with a 1-byte / 65-byte new PIN, without 83, wrong RC,
   lifecycle not OPERATIONAL → refused **and the DEC key is still there**.
6. Fault injection on the mock (cut / lost reply) at every chip call of VERIFY 81/82,
   CHANGE, GENERATE and the reset sequence → only the §3 states plus the inherited ones.
7. **No plaintext at rest:** after GENERATE, scan every R-mem slot of the mock for any
   32-byte window w with `X25519(clamp(w), 9) == dec_pub` → none. Same scan for the
   fixture PINs and SHA-256(PIN).
8. Schema-1 O3 → ERROR → TERMINATE + ACTIVATE works.
9. Replay (documents J5): restoring an older full wrap sealed under the same KEK opens —
   asserted, so the residual stays visible.
10. Mutants: drop the KEK wipe in `auth_drop`; KEK kept after 81+82 cleared; grant 82
    from 81; skip the destroy in reset; destroy before the preflight; drop the AAD
    pubkey; decrypt before the tag check; `memcmp` for the tag is not caught by a test
    (review item, not a mutant) — the others must each turn a test red.

**Hardware** (one dongle session, release + debug):
- `tools/validate-openpgp-m4.sh` updated (J1): GENERATE DEC with PW3 only → `6982`, then
  VERIFY 81 → GENERATE DEC ok; after RESET RETRY COUNTER, PSO:DEC → `6A88` (key
  destroyed), GENERATE again, PSO:DEC ok.
- gpg on a **fresh** card: `gpg --card-edit` → `generate` (gpg sends VERIFY 81), then
  `gpg --decrypt` fails before the PIN, works after; `passwd` change → still works;
  RC reset → key gone, decrypt fails.
- Debug build: dump R0, R33, R43, R50–R55 via lt-rpc and run the §5.7 window scan on
  the host against the card's `dec_pub`.

## 6. Residuals (stated in docs and slides)

- While PW1 is verified (81 or 82; default C4 `01`: until unplug) the KEK sits in STM32
  RAM; during each PSO:DEC the private key does too, for one X25519.
- Anyone who knows PW1 and has L3 access (the dev pairing key is public) can run the
  M&D verify themselves and unwrap. M5 removes the **offline** read, not the PIN.
- **Rollback:** someone with L3 access who saved an older O3 can write it back; an older
  DEC key sealed under the same PIN's s still opens. No anti-rollback in Phase 9.
- A reset interrupted after the destroy leaves the old PIN with no DEC key (§3).
- `docs/UBUNTU.md` §10 ("all private keys stay on the chip") is corrected: SIG and AUT
  are chip keys; DEC is wrapped in R-mem and computed on the STM32.

## 7. Answers to the r1 questions (Jan)

1. Random 96-bit nonces from the chip RNG are fine at this volume (E1).
2. VERIFY does not test-unwrap.
3. Invalid wrap → `6F00`; absent key → `6A88` (OpenPGP §7.6 p90).

## 8. Review r1 → r2 (Jan, 2026-10-17, CHANGES REQUIRED)

| # | Finding | Resolution |
|---|---|---|
| J1 HIGH | gpg on a fresh card verifies 81, not 82, before generating (F4). | E6: GENERATE DEC accepts a KEK from 81 or 82; PSO:DEC still needs 82; validate-openpgp-m4.sh fixtures updated; fresh-card gpg test. |
| J2 MED | Reset destroyed the key before the new-PIN checks. | Preflight before the destroy (§3, §4); host test 5. |
| J3 MED | Cache contract incomplete (replacement, failures, wipes). | §3 rows per event, replacement decision with reason, E10 wipes on every exit. |
| J4 MED | Fault column omitted inherited exceptions. | §3 preamble + VERIFY / CHANGE rows; host test 6 covers them. |
| J5 LOW | AAD does not prove freshness. | E3 narrowed, residual §6, host test 9. |
