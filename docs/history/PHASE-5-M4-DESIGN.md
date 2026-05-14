# Phase 5 M4 — MAC-and-Destroy-backed PIN retry counter

> **Goal:** Replace M3's RAM/R-mem-only retry counter with TROPIC01-
> hardware-enforced limit using MAC-and-Destroy slot consumption.
> Even firmware compromise cannot extend the 8-attempt limit because
> consumed M&D slots are physically destroyed at the silicon level.

## The TROPIC01 M&D primitive (research)

Confirmed via `libtropic/examples/model/mac_and_destroy/main.c` + tutorial
docs/tutorials/model/macandd.md + L3 cmd struct in `lt_l3_api_structs.h`.

`lt_mac_and_destroy(handle, slot, data_out, data_in)`:
- `data_out` = 32 B INPUT to chip
- `data_in`  = 32 B OUTPUT from chip
- Slot has internal stateful key K
- First call to a fresh slot: initializes K from input (output is junk)
- Second call: returns `MAC(K, input)` then DESTROYS K (slot permanently dead)
- Re-init requires another call (which destroys whatever was there)

**Therefore each PIN attempt requires the firmware to do an M&D call to
recover the per-attempt decrypt key.** Skipping M&D is impossible because
the firmware needs the M&D output to decrypt the stored secret.

## The scheme (canonical, from Tropic Square example)

Notation:
- `s` = master_secret (32 B random, generated at setPin time, NOT stored)
- `i` = attempts remaining (decremented per attempt, reset on success)
- `c_i[]` = N×32 B array of encrypted master_secrets (one per slot)
- `t` = SHA-256-based tag for verifying the recovered secret
- `u` = init value for M&D slots
- `v` = PIN-derived input to M&D probe

### setPin(PIN, master_secret)

```
1. tag t = HMAC(s, [0x00])                       // 32 B verification tag
2. u = HMAC(s, [0x01])                            // 32 B M&D init value
3. v = HMAC(0_32, PIN || A)                       // 32 B PIN-derived input
4. for slot i in 0..N-1:
     M&D(slot_i, u, ignore)                      // init slot with u
     M&D(slot_i, v, w_i)                          // compute MAC, slot consumed
     M&D(slot_i, u, ignore)                      // re-init slot fresh for later use
     k_i = HMAC(w_i, PIN || A)                    // derive encryption key
     c_i = XOR(s, k_i)                            // encrypt master_secret
5. store {i = N, t, c_i[]} in R-mem
6. final_key = HMAC(s, "2")                       // optional output to caller
```

### verify(PIN')

```
1. if i == 0: FAIL                                // attempts exhausted
2. i' = i - 1
3. write i' to R-mem (commit attempt before crypto so power-loss is safe)
4. v' = HMAC(0_32, PIN' || A)
5. w_i' = M&D(slot_{i'}, v', ...)                 // consume slot
6. k_i' = HMAC(w_i', PIN' || A)
7. s' = XOR(c_{i'}, k_i')
8. t' = HMAC(s', [0x00])
9. if t' != t: return PIN_INVALID                 // wrong PIN; slot was consumed
10. PIN was correct:
    u = HMAC(s', [0x01])
    for slot j in i'..N-1:
        M&D(slot_j, u, ignore)                   // re-init all unused slots
    write {i = N, t, c_i[]} to R-mem              // reset attempts
    final_key = HMAC(s', "2")                     // matches setPin's final_key
    return PIN_OK
```

### Security properties

| Attack | Defense |
|---|---|
| Firmware bypasses M&D, skips attempt count | Cannot recover decrypt key → cannot decrypt ci → cannot verify tag → PIN refuse |
| Firmware tries to call M&D twice on same slot | First call destroys slot; second call fails |
| Power-loss mid-attempt | i' was written to R-mem first; if power-loss before crypto completes, slot was still consumed but attempts already decremented — caller retries with i-1 remaining |
| Storage tampering: attacker rewrites R-mem with old attempts | tag mismatch on next verify because slots have been consumed since |
| Attacker captures M&D slot contents and replays | Slots are destroyed by M&D itself; chip-internal state |
| Brute force PIN | 8 wrong attempts → all 8 slots destroyed → re-init requires factory_reset |

## Adaptation to nixtropic Phase 5 M4

### What's different from the Tropic Square example

The reference example RECOVERS a `master_secret` after correct PIN, which
the caller uses as a high-entropy key. We don't have such a use case
directly. But we adapt:

- Our `master_secret` will be a random 32 B value generated at setPin.
- We don't expose `final_key` to anything; we ONLY use the M&D scheme to
  enforce "PIN was correct" — the recovered tag match is the signal.
- After successful verify, we keep generating fresh `pinUvAuthToken` per
  M3 (32 B from TRNG); M&D recovery doesn't change that flow.
- We still store `SHA-256(PIN)[:16]` in R-mem (M3 pin_hash) for fast PIN
  check during getPinToken. The M&D scheme is the HARDWARE backstop:
  even if firmware skips the M3 pin_hash check, the M&D layer rejects.

This is defense-in-depth — both layers must pass.

### R-mem slot 0 layout (M4 extension)

Bumping `SLOTS_RMEM_GLOBAL_SIZE` from 256 → 384 to fit M&D state. Below
the 475-byte TR01 R-mem-per-slot limit (FW ≥2.0.0).

```
offset   size   field                          when added
   0       4    magic "NX5K"                    M1
   4       2    schema_version (now = 2)        M1, bumped M4
   6       4    bitmap                          M1
  10       1    pin_set                         M3
  11      16    pin_hash[16] (SHA-256(PIN))     M3
  27       4    pin_retries (uint32_BE)         M3
  31       1    md_active                       M4
  32       1    md_next_slot (0..7)             M4
  33      32    md_tag                          M4
  65     256    md_ci[8 * 32]                   M4
 321      63    reserved                        M5+ (room for cred-mgmt extras)
 ───
 384 total
```

`schema_version` bumps to 2. On reading slot 0:
- schema = 1 (M3 firmware wrote it): factory_reset transparently to fresh M4 layout.
  This wipes the existing PIN, which is OK during Phase 5 development (user
  re-sets PIN after firmware update).
- schema = 2: read full M4 state.

### M&D slot allocation

Slots 0..7 (8 total) for PIN attempts. We use the existing
`TR01_MAC_AND_DESTROY_SLOT_0..7` enum values. Phase 6 might reserve
additional slots for OpenPGP card PIN attempts; we'd partition the 128
available slots accordingly later.

### Firmware module layout

New file: `firmware/src/fido_hid/pin_md.{h,c}`. Public surface:
```c
int  pin_md_setup(const uint8_t pin[], size_t pin_len);
int  pin_md_verify(const uint8_t pin[], size_t pin_len, int *out_correct);
int  pin_md_reset(void);            // factory reset
int  pin_md_is_active(void);
int  pin_md_attempts_remaining(void);
```

Wired into pin.c:
- `handle_set_pin` → after AES-CBC decrypt + PIN-length check, call
  `pin_md_setup` to create the M&D state. ALSO store the SHA-256(PIN)[:16]
  in R-mem per M3 (kept for fast-path check + backward compat).
- `handle_change_pin` → `pin_md_verify(old_pin)` first. If correct, then
  `pin_md_setup(new_pin)`.
- `handle_get_pin_token` → BOTH:
    1. M3 pin_hash check (fast)
    2. `pin_md_verify(submitted_pin)` (hardware-enforced)
  Both must pass. If only M3 passes (firmware bypass scenario), M&D
  catches it. If only M&D passes (shouldn't happen — implementation
  bug), we refuse and log.

### Behavior changes visible to RPs

None. The CTAP2 ClientPIN protocol surface is unchanged. The retries
counter reported via `getRetries` still ranges 0..8. The only change is
that even with firmware compromise, 8 wrong PINs permanently destroys
the slots and requires factory_reset.

### AAGUID decision

No bump. M4 adds an *internal* hardening layer but doesn't change any
RP-observable behavior (CTAP2 surface, options, algorithms, AAGUID
stays 0x02). Per `docs/WEBAUTHN-NOTES.md §3` rules.

## Risks

| Risk | Mitigation |
|---|---|
| M&D scheme implementation bug → PIN can't be verified after legitimate attempt | Implement with the canonical example as reference + extensive test suite |
| Power-loss during the 3-call init sequence per slot leaves slot in bad state | Re-init happens at end of `setPin` — if interrupted, next attempt fails cleanly, attempts decremented |
| First-boot migration from M3 schema=1 wipes existing PIN | Document; user re-sets via `fido2-token -S`. Acceptable for Phase 5 dev. |
| 256 B `md_ci[]` blob in R-mem grows R/W traffic | One R-mem write per setPin/verify-correct. Verify-wrong = 1 read + M&D. Acceptable. |
| trezor_crypto HMAC available but tagged as Bitcoin-specific | hmac_sha256 is generic; already used in Phase 5 M3 PIN protocol |
| ECC slots and M&D slots share an L3 session — concurrent op contention | Phase 5 design is single-threaded; no contention. |

## Test scenarios

`validate-phase5-m4`:
1. setPin '1234' → success; M&D state initialized
2. getRetries → 8
3. getPinToken correct → token
4. getRetries → 8 (reset on correct)
5. getPinToken wrong 7 times → each returns PIN_INVALID; retries decrements to 1
6. getRetries → 1
7. getPinToken correct → success, retries reset to 8 (slot reinit)
8. getPinToken wrong 8 times → PIN_BLOCKED on 8th
9. After PIN_BLOCKED: try getPinToken correct → PIN_BLOCKED (slots dead)
10. factory_reset → all slots wiped, can setPin fresh

## Token budget estimate

- Design (this doc): 5k ✓
- slots.h/c extensions: 10k
- pin_md.h/c: 30k
- pin.c integration: 15k
- Build + iterate: 20k
- Host test: 15k
- Commit: 5k
- **Total: ~100k tokens**

## Sign-off (self-assessment before implementing)

- [x] M&D primitive semantics understood
- [x] Canonical scheme from example understood
- [x] Defense-in-depth design (M3 hash + M4 M&D both must pass)
- [x] R-mem layout planned with migration
- [x] AAGUID policy adhered to (no bump)
- [x] No conflicts with M2 credstore (ECC slots vs M&D slots are different resources)

Going.
