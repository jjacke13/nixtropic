# Phase 9 M3 — work plan (FIDO2 fixes, permission tokens, authenticatorConfig)

> **Historical record, frozen at v0.3.0.** Kept for the reasoning and the evidence it
> contains. Facts and procedures here may be outdated or wrong: do not follow
> instructions from this file. Current documentation: <https://jjacke13.github.io/nixtropic/>
> (known corrections: <https://jjacke13.github.io/nixtropic/hardware/#corrections-to-earlier-documentation>).

Contract: `PHASE-9-PLAN.md` §5. Reviewed by Jan 2026-10-15 (changes folded in: decisions
3, 9, items 3, 4). This file says **how**, item by item, and records the
decisions taken while reading CTAP 2.1 (PS 2021-06-15, "CTAP" below) and the libfido2
1.17 client. Chip facts come from Jan's notes (`phase9-m3-counter-facts.md`).

## 0. Decisions

1. **GetInfo `versions` stays `["FIDO_2_0"]`.** `FIDO_2_1` requires hmac-secret,
   credProtect and PIN/UV protocol 2 (CTAP §9); we have none of them. The 2.1 pieces we
   do implement are announced through their own option IDs (`pinUvAuthToken`,
   `authnrCfg`, `credMgmt`, `alwaysUv`, `makeCredUvNotRqd`). libfido2 reads option IDs,
   not the version (dev.c), so it uses 0x09 tokens, 0x0A credMgmt and 0x0D config.
   `credentialMgmtPreview` is removed: it announces command 0x41, which does not exist.
   `algorithms` lists EdDSA only.
2. **Discoverable credentials become real** instead of dropping the `rk` claim.
   MakeCredential stores `rk` in the slot flags (CTAP §6.1.2 step 18: `rk` false MUST
   give a non-discoverable credential). GetAssertion without an allowList returns the
   discoverable credentials of the RP, newest first, with `numberOfCredentials` and
   GetNextAssertion. `credProps.rk` reports the stored flag.
3. **Creation order** = its own sequence: 1 + the highest order among the stored
   credentials (unreadable metadata counts as 0), stored in the slot metadata (new
   field, offset 121, 4 bytes, BE). Old credentials read 0; ties (legacy 0, or a
   saturated counter) fall back to the lower slot index. Not the signCount: two
   registrations without an assertion share one (Jan, M3 review 4).
4. **credMgmt lists every FIDO credential**, discoverable or not (CTAP lists only
   discoverable ones). Every credential occupies one of the 29 chip slots, so the user
   must be able to see and delete all of them. Documented deviation.
5. **MakeCredential UV policy follows CTAP §6.1.2 steps 6–8**, with
   `makeCredUvNotRqd = !alwaysUv`: with a PIN set, a non-discoverable credential may be
   made without a token (the Proton 2FA case keeps working), a discoverable one needs
   a token. Today any MakeCredential without a token passes when alwaysUv is off.
6. **No cached user presence.** Every operation that tests presence waits for a fresh
   SW1 press; a token's `userPresent` flag is never set. After such an operation the
   token loses its permissions (CTAP §6.5.5.7: one mc/ga use per token).
7. **Token timers:** 30 s to first use, 10 min maximum life (CTAP §6.5.2.1 USB
   defaults), no rolling timer. Tokens die on: a new token, setPIN/changePIN, reset,
   expiry, power cycle.
8. **alwaysUv stays auto-enabled on the first setPIN** (Phase 6 decision); the owner
   can now turn it off with `fido2-token -S -u <dev>` (authenticatorConfig).
9. **signCount (Jan, M3 Q1–Q4):** an assertion runs Update → Get → sign `MAX − v`. Any
   counter error fails the operation; nothing is retried. MakeCredential reads (Get)
   only. `COUNTER_INVALID` is not proof of a virgin counter (also corrupt or
   disabled), and the bitmap helpers report "empty" after read errors, so neither
   authorises an init (Jan, M3 review 1). The counter is (re)initialised only
   (a) by authenticatorReset after every key erase and the state wipe succeeded, or
   (b) on a genuine first boot: R-mem slot 0 read returned exactly `SLOT_EMPTY` and
   the fresh global state was written. Any other `COUNTER_INVALID` = FIDO fails
   closed. (The wider rule-7 fix for `slots_init`, which today also rewrites slot 0
   after a read error, is M4.)

## 1. Items and commits

| # | Commit | Contract |
|---|---|---|
| 1 | CBOR: `cbor_validate()` once per request at the dispatcher (well-formed, ≤ 4 nesting levels per CTAP §8, every length inside the buffer, no tags / indefinite length, nothing after the top-level item); `cbor_reader_skip` gets a hard recursion cap as a second line; host tests | 2 |
| 2 | MakeCredential / GetAssertion request parsing moves to `ctap2_parse.c` (no chip calls): every `pubKeyCredParams` entry validated, first supported alg chosen, `options` (`rk`/`up`/`uv`, booleans only), zero-length `pinUvAuthParam`, allowList / excludeList kept as validated byte ranges, `user.id` ≤ 64 B; host tests with valid and broken requests | 2, 3 |
| 3 | Credentials: lookup returns the slot metadata; GetAssertion walks the allowList and uses the first credential that exists **and** whose stored rpIdHash equals SHA-256(rpId); discoverable path + GetNextAssertion (30 s timer, state cleared by any other command and by reset); `user.id` in the response for discoverable credentials; MakeCredential excludeList (touch, then `CREDENTIAL_EXCLUDED`); same-account overwrite for `rk`: the new credential is generated and checked first, then ONE bitmap write adds the new bit and clears the old one (the old ID stops resolving in the same write), then the old key and metadata are erased best-effort (a free slot is erased again before reuse); store full → `KEY_STORE_FULL`, never delete the old one to make room; credId slot index must be < 29 | 1, 3 |
| 4 | signCount per decision 9; factory reset: erase ECC 0..28 first, and if any erase failed return the error BEFORE touching PIN, bitmap or metadata (Jan, M3 review 2); then wipe; then counter init; a later failure leaves the cached state invalid; reset clears PIN-token and assertion RAM | 5 |
| 5 | `pin_token.c`: token state (permissions, permissions RP ID hash, timers, uv flag) with host tests; ClientPIN 0x09 (permissions mandatory, 0 → INVALID_PARAMETER, be/lbw → UNAUTHORIZED_PERMISSION, optional rpId); 0x05 = mc+ga and refuses permissions/rpId; all checks in CTAP §6.5.5.7 order | 6 |
| 6 | MakeCredential / GetAssertion UV logic per CTAP §6.1.2 / §6.2.2 using the token (mc/ga permission, RP ID bind/match, uv flag, consume after the touch); `up=false` GetAssertion signs without touch and UP=0 | 6 |
| 7 | credMgmt: `cm` permission with the per-subcommand RP-ID rules (CTAP §6.8.2–6.8.5); GetNextRP / GetNextCredential need no `pinUvAuthParam` (libfido2 sends none — today a second RP or credential fails to list); capacity from 29 | 4, 6 |
| 8 | authenticatorConfig 0x0D `toggleAlwaysUv` (CTAP §6.11: no PIN set → no auth; PIN set → token with `acfg` over `32×0xFF ‖ 0x0D ‖ subCommand`); GetInfo per decision 1 | 7 |
| 9 | Touch-wait dispatch policy (below) | 9 |
| 10 | lt-rpc policy setters: confirm they exist only in the debug build (M1); add a check | 8 |
| 11 | `fido2_test.py validate-m3`: hardware suite for all of the above | validation |

## 2. Touch-wait dispatch policy (item 9, BACKLOG 6.6)

Only one application request runs at a time; the touch wait never starts a second one.

- **CCID:** the bulk-OUT callback only stores the message; the main loop processes it
  (`usb_ccid_task()`), and not while a touch wait is running. An APDU that arrives
  during a FIDO touch wait is answered after the wait. A CCID request cannot arrive
  during an OpenPGP touch wait (its RX endpoint is re-armed only after the response).
- **CTAPHID:** unchanged `CHANNEL_BUSY` for new requests during a wait (also during an
  OpenPGP wait). `CTAPHID_CANCEL` on the waiting CID ends the wait and the request
  answers `CTAP2_ERR_KEEPALIVE_CANCEL`; CANCEL is never answered itself (CTAP
  §11.2.9.1.5 — today it is echoed).
- **lt-rpc (debug):** refuses with a busy error during a wait.
- **Consent:** one wait at a time; a press counts only after a release seen inside the
  wait (unchanged C1 rule). Nested waits become impossible with the above.
- Not in M3: KEEPALIVE packets during the wait (CTAP SHOULD); clients work without.

## 3. Validation (hardware, destructive: FIDO reset, credentials wiped)

`fido2_test.py validate-m3` + existing suites + webauthn.io:
- site A credential refused for site B (allowList with A's credId, rpId B →
  NO_CREDENTIALS); unknown first allowList entry, known second → works.
- discoverable: two `rk` credentials for one RP → `numberOfCredentials` 2,
  GetNextAssertion returns the other, newest first; non-rk credential not discovered.
- tokens: legacy 0x05 token works for mc/ga and is refused for cm and acfg; 0x09 with
  cm only is refused for ga; RP-bound token refused for another RP; token unusable
  after one touch-tested use; expired after 30 s unused.
- alwaysUv matrix: PIN set → toggle needs a 0x09 token with acfg (refused with a
  legacy token or none); no PIN → toggle without auth; GetInfo follows; with alwaysUv
  on, GetAssertion without token → PUAT_REQUIRED.
- credMgmt via `fido2-token -L -r` / `-L -k` with ≥ 2 RPs; metadata shows 29 − used.
- signCount strictly increases across assertions.
- CANCEL during a touch wait → KEEPALIVE_CANCEL at once; CCID APDU during a FIDO wait
  answered after it.
- webauthn.io register + login (rk "discouraged" and "required"), `fido2-token -S -u`.
