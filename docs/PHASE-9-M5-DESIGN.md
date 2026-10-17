# Phase 9 M5 — Design: the DEC key wrapped under k

Contract: `docs/PHASE-9-PLAN.md` §7. Builds on `docs/PHASE-9-M4-DESIGN.md` (record pairs,
kernel v2, D4 "change keeps s", D8 "destruction before defaults"). PIN hashes are already
gone (M4 D6), so M5 is **only** the OpenPGP decryption key.

## 0. What is wrong today (code facts)

| # | Fact | Where |
|---|---|---|
| F1 | The X25519 DEC private key is stored **plain** in O3 (payload offset 122, 32 B, both copies). | `openpgp_state.c:28`, `pgp_keys.c:107-134` |
| F2 | READ PUBLIC KEY (no PIN) derives the public key from that private key. | `pgp_keys.c:137-150` |
| F3 | The kernel already returns `k = HMAC(s, 0x02)` on setup / verify / change; `pgp_pin.c` passes `NULL`. | `pgp_pin.c:105,121,131` |
| F4 | gpg verifies PW1 as CHV2 (= 82, which also sets 81) before every on-card key generation (`check_pin_for_key_operation` → `agent_scd_checkpin` → `verify_chv2`). | gnupg `g10/card-util.c:1333`, `scd/app-openpgp.c` `do_check_pin` |

## 1. Decisions

- **E1. Wrap = AES-256-GCM** (trezor `aes/aesgcm.c`, already linked for L3). AES-KW is
  not in the tree; GCM is allowed by PLAN §7.2. Nonce: 12 B from the chip TRNG per wrap
  (a KEK wraps a handful of keys in its life; random-nonce collision is negligible).
- **E2. KEK = HMAC-SHA256(k, "nixtropic/openpgp/dec-kek/v1")**. Domain-separated from
  `t`, `u`, `k` (M4 §3.3) and from the FIDO binding (different s).
- **E3. AAD** = `"NXDW" | obj 3 | schema 2 | dec_pub[32]`. The wrap is bound to its own
  public key: swapping either the wrap or the public key fails the tag.
- **E4. The public key is stored** next to the wrap. READ PUBLIC KEY needs no PIN and no
  unwrap (PLAN §7.2).
- **E5. RAM cache = the KEK only**, never the private key. The KEK is valid **iff**
  `AUTH_82` is set: one helper sets/clears both (§4). Every PSO:DEC unwraps into a
  stack buffer, uses it, wipes it. This keeps one cache, not two.
- **E6. GENERATE DEC needs PW3 and PW1.82** (PLAN §7.3). Without the KEK it answers
  `6982` and writes nothing. gpg already verifies 82 first (F4), so `gpg --card-edit`
  → `generate` works unchanged.
- **E7. PW1 change keeps s** (M4 D4) → k and the KEK are unchanged → the wrap stays
  valid. Nothing to do, also after an error that may have committed the new PIN
  (Jan's M4 step 2 lesson: k is the same either way).
- **E8. A PW1 reset (RESET RETRY COUNTER via RC, or via PW3) destroys the DEC key
  first**, then binds the new PW1 with a fresh s (D8 order, §3). Documented: after a
  reset, `gpg --decrypt` of old messages fails; after a change it works (Vaios).
- **E9. Schema bump O3 1 → 2, no migration** (as in M4: the user resets once).
  A schema-1 O3 reads as damaged → ERROR → TERMINATE + ACTIVATE. Release note says so.

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
`openpgp_state_dec_set(pub, nonce, ct, tag)` (also writes nothing else), and
`openpgp_state_dec_destroy()` = **one** commit that zeroes `dec_pub`, the wrap, the DEC
fingerprint (C8) and its generation time (CF), so gpg sees "no key".

## 3. Lifecycle — one rule per event

| Event | Sequence | One fault leaves |
|---|---|---|
| VERIFY 82 ok | kernel verify → k → KEK = E2 → wipe k → set `AUTH_82` + KEK together | before (no flag, no KEK) or after |
| VERIFY 81 ok | k discarded (81 grants no DEC) | — |
| VERIFY wrong / FF / card reset / USB reset / SELECT other AID / TERMINATE / ACTIVATE / PW1 change or reset | `auth_drop()` wipes the KEK with the flag | — |
| GENERATE DEC (PW3 + KEK) | TRNG priv → clamp → pub → TRNG nonce → GCM seal → `dec_set` (one pair write) → wipe priv | old key, or new key (record pair: before or after) |
| PSO:DEC (82 + KEK + UIF touch) | `dec_get` → GCM open (on failure **wipe the output buffer**: Gladman writes plaintext before the tag check) → ECDH → wipe priv | no write |
| READ PUBLIC KEY | `dec_pub` | no write |
| PW1 change | nothing (E7) | — |
| PW1 reset (RC or PW3) | `auth_drop(PW1)` → if a DEC key exists: `dec_destroy` (checked commit; **failure stops here**, no reset) → `pgp_pin_reset_pw1` | old PIN + old key; or old PIN + key destroyed (retry the reset); or new PIN + key destroyed |
| PW1 blocked | nothing: s is unreachable, the wrap is cryptographically dead; a reset destroys it formally | — |
| TERMINATE / bootstrap | `pgp_wipe` already erases both O3 copies (M4 §5) | M4 rows |
| ACTIVATE | O3 OPERATIONAL defaults = no DEC key | M4 row |
| Wrap fails the tag (damage, stale) | PSO:DEC answers `6F00`; nothing cached, nothing rewritten | — |

The "old PIN + key destroyed" row is a permitted intermediate under D8: destruction ran
before the default; no access is gained. It is listed in §6.

## 4. Applet changes (`openpgp_applet.c`)

- `static uint8_t s_kek[32]; static bool s_kek_ok;` next to `s_auth`.
- `auth_drop(mask)`: clears the bits; if `AUTH_82` is now clear, `memzero(s_kek)`,
  `s_kek_ok = false`. **Every** `s_auth &= ~…` and `s_auth = 0` site (lines 530, 583, 594,
  617, 654, 973, 1019, 1037, 1099) goes through it. A host test greps the source: no
  direct `s_auth &=` / `s_auth = 0` outside the helper (mutant guard).
- `auth_grant_82(k)`: derives the KEK, sets both. Called only from VERIFY 82 success.
- PSO:DEC and GENERATE DEC check `(s_auth & AUTH_82) && s_kek_ok`.
- `pgp_pin_verify` gains `uint8_t out_k[32]` (nullable), passed to the kernel.

`pgp_keys.c`: `generate_dec(kek, pub_out)`, `read_dec_pubkey(pub_out)`,
`ecdh_dec(kek, peer, shared_out)`. The wrap/unwrap is two static functions there.

## 5. Validation

**Host** (`nix build .#host-tests`; link `aes/aesgcm` + `gf128mul`):
1. Round trip: VERIFY 82 → GENERATE → PSO:DEC = X25519 reference.
2. No KEK: GENERATE and PSO:DEC refused before VERIFY 82, after VERIFY 81 only, after
   each `auth_drop` event in the §3 table (one test per event).
3. Tamper: flip one bit in each of `dec_pub`, nonce, ct, tag (both copies) → PSO:DEC
   `6F00`, output buffer all zero, nothing rewritten.
4. Change keeps decryption; RC reset and PW3 reset destroy (READ PUBLIC KEY → `6A88`,
   C8/CF zero).
5. Fault injection on the mock (cut / lost reply) at every chip call of GENERATE and of
   the reset sequence → only the states in the §3 "one fault" column.
6. **No plaintext at rest:** after GENERATE, scan every R-mem slot of the mock for any
   32-byte window w with `X25519(clamp(w), 9) == dec_pub` → none. Same scan for the
   fixture PINs and SHA-256(PIN).
7. Schema-1 O3 → ERROR → TERMINATE + ACTIVATE works.
8. Mutants: drop the KEK wipe in `auth_drop`; skip the destroy in reset; reorder destroy
   after reset; drop the AAD pubkey; skip the output wipe on tag failure — each must
   turn a test red.

**Hardware** (one dongle session, release + debug):
- `tools/validate-openpgp-m4.sh` stays green; extend it: GENERATE DEC without 82 → `6982`.
- gpg: generate keys on the card, `gpg --decrypt` fails before the PIN, works after;
  `passwd` change → still works; RC reset → key gone, decrypt fails.
- Debug build: dump R0, R33, R43, R50–R55 via lt-rpc and run the §5.6 window scan on
  the host against the card's `dec_pub`.

## 6. Residuals (stated in docs and slides)

- While PW1.82 is verified (default C4 `01`: until unplug) the KEK sits in STM32 RAM;
  during each PSO:DEC the private key does too, for one X25519.
- Anyone who knows PW1 and has L3 access (the dev pairing key is public) can run the
  M&D verify themselves and unwrap. M5 removes the **offline** read, not the PIN.
- A reset interrupted after the destroy leaves the old PIN with no DEC key (§3).
- `docs/UBUNTU.md` §10 ("all private keys stay on the chip") is corrected: SIG and AUT
  are chip keys; DEC is wrapped in R-mem and computed on the STM32.

## 7. Questions for review

1. GCM with a random 96-bit nonce under a KEK that lives for the PIN's whole life —
   acceptable, or derive the nonce (e.g. from a wrap counter in O3)?
2. Should VERIFY 82 test-unwrap (so a damaged wrap shows at VERIFY, not at DEC)? Current
   answer: no, keep VERIFY free of extra work.
3. Is `6F00` right for a failed unwrap, or `6A88` (key unusable)?
