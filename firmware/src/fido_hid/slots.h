/*
 * Phase 5 M1: TROPIC01-backed credential slot manager.
 *
 * Manages up to 32 FIDO2 credentials, each occupying:
 *   - TROPIC01 ECC slot (TR01_ECC_SLOT_0 + idx)        — private key, on chip
 *   - TROPIC01 R-mem slot (idx + 1)                    — metadata (256 B)
 *
 * R-mem slot 0 is the global state (allocation bitmap, schema magic,
 * later: PIN state, M&D bookkeeping). See docs/PHASE-5-PLAN.md §4.2.
 *
 * Persistence model:
 *   - R-mem is written/read over libtropic L3 — atomic per slot per spec.
 *   - First boot detection: read slot 0, check magic "NX5K".
 *     If missing or wrong, write fresh global state with bitmap=0.
 *   - Orphan-scrub: at boot, for every claimed bit in bitmap, verify the
 *     per-credential R-mem slot has matching "NXCR" magic. If not,
 *     clear the bit. Symmetric direction (ECC populated, bitmap empty)
 *     is harder to detect cheaply and is deferred to M2 when we wire
 *     credstore_make to lt_ecc_key_generate.
 *
 * Credential ID format (returned to relying party):
 *   [0]   version = 0x01
 *   [1]   slot_idx (0..31)
 *   [2..17] cred_id_nonce (random 16 B from TROPIC01 TRNG)
 *   total = 18 bytes
 *
 * The nonce protects against credential-ID forgery: an attacker who
 * guesses slot_idx still has to brute-force a 128-bit nonce that
 * matches the stored value before the device will sign with that
 * slot's key. The nonce is non-secret (it's in the credId on the wire)
 * but it's per-credential-unique random.
 */

#ifndef NIXTROPIC_FIDO_HID_SLOTS_H
#define NIXTROPIC_FIDO_HID_SLOTS_H

#include <stdint.h>
#include <stddef.h>

#define SLOTS_MAX                    32u
#define SLOTS_CRED_ID_LEN            18u
#define SLOTS_CRED_ID_NONCE_LEN      16u
#define SLOTS_RP_ID_HASH_LEN         32u
#define SLOTS_RMEM_GLOBAL_SLOT       0u
#define SLOTS_RMEM_PER_CRED_SIZE     256u
#define SLOTS_RMEM_GLOBAL_SIZE       256u

#define SLOTS_ALG_ED25519            8u

#define SLOTS_FLAG_RESIDENT          (1u << 0)

/* slot_idx → R-mem slot. Per-cred R-mem starts at slot 1 to keep
 * slot 0 reserved for global state. */
#define SLOTS_RMEM_SLOT_FOR(idx)     ((uint16_t)((idx) + 1u))

typedef struct {
    uint8_t  alg;                                       /* SLOTS_ALG_* */
    uint8_t  flags;                                     /* SLOTS_FLAG_* */
    uint8_t  rp_id_hash[SLOTS_RP_ID_HASH_LEN];
    uint8_t  cred_id_nonce[SLOTS_CRED_ID_NONCE_LEN];
} slot_meta_t;

/**
 * @brief First-boot init: open L3 session, read slot 0, detect magic.
 *        Idempotent — safe to call multiple times.
 *
 * @return 0 on success; negative on libtropic error.
 */
int slots_init(void);

/**
 * @brief Allocate the next free slot for a new credential.
 *
 *   1. Find first 0 bit in bitmap.
 *   2. Generate 16 B nonce from TROPIC01 TRNG.
 *   3. Write per-credential metadata to R-mem slot (idx + 1).
 *   4. Set bit in bitmap, write slot 0 back.
 *   5. Emit 18 B credential ID for relying party.
 *
 * Caller is responsible for the ECC key generation (slots layer doesn't
 * touch ECC slots in M1; credstore.c will in M2). On error, R-mem state
 * is left consistent — partial allocations are rolled back.
 *
 * @param  rp_id_hash     SHA-256 of rp.id (32 B); persisted in meta.
 * @param  alg            COSE alg id (only SLOTS_ALG_ED25519 in M1).
 * @param  out_cred_id    Caller buffer; 18 B written on success.
 * @param  out_slot_idx   Caller's slot index out (0..31).
 * @return 0 on success; -1 if full; -2 on TROPIC01 error.
 */
int slots_alloc(const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                uint8_t alg,
                uint8_t out_cred_id[SLOTS_CRED_ID_LEN],
                int *out_slot_idx);

/**
 * @brief Resolve a credential ID to a slot index.
 *
 *   1. Reject if cred_id_len != 18 or version byte != 0x01.
 *   2. Read slot_idx from byte[1]; reject if ≥ 32.
 *   3. Read per-credential R-mem; reject if magic mismatch.
 *   4. Constant-time compare nonce; reject on mismatch.
 *
 * @return 0 on success (out_slot_idx populated); -1 on not-found.
 */
int slots_lookup_by_credid(const uint8_t *cred_id, size_t cred_id_len,
                           int *out_slot_idx);

/**
 * @brief Erase a credential slot: clear bitmap bit, erase R-mem slot.
 *        Does NOT touch the ECC slot — that's credstore.c's job in M2
 *        because the slots module shouldn't know about chip keys.
 *
 * @return 0 on success; -1 on out-of-range; -2 on TROPIC01 error.
 */
int slots_erase(int slot_idx);

/**
 * @brief Return the current allocation bitmap (bit i = slot i used).
 *        Cached in RAM after slots_init() — no chip read.
 */
uint32_t slots_bitmap(void);

/**
 * @brief Popcount of the allocation bitmap.
 */
int slots_count_used(void);

/**
 * @brief Read per-credential metadata. Used for debug + lookup paths.
 *
 * @return 0 on success; -1 on out-of-range or unallocated slot;
 *         -2 on TROPIC01 read error.
 */
int slots_read_meta(int slot_idx, slot_meta_t *out);

/**
 * @brief WIPE EVERYTHING. Used by authenticatorReset (M5) and by the
 *        debug `nixtropic factory-reset` host command (M1).
 *        Erases bitmap, all per-credential R-mem entries (slots 1..32),
 *        and global slot 0. ECC slots untouched (credstore wipes those
 *        separately in M2+).
 *
 * @return 0 on success; -1 on TROPIC01 error.
 */
int slots_factory_reset(void);

/* ===== Phase 5 M3: PIN state on global R-mem slot 0 =====
 *
 * The PIN state is persisted alongside the credential bitmap in R-mem
 * slot 0, at offsets 10..30 per docs/PHASE-5-PLAN.md §4.2.
 *
 * On-disk layout (additive over M1; old schema=1 reads 0x00 at these
 * offsets, which correctly reports "no PIN set"):
 *   [10]      pin_set    (1 byte: 0=not set, 1=set)
 *   [11..26]  pin_hash   (16 bytes: LEFT(SHA-256(PIN), 16))
 *   [27..30]  pin_retries (uint32_BE)
 *
 * Wraps every R-mem touch in cached-then-write semantics (re-read after
 * write to confirm). All accessors require slots_init() already ran. */

#define SLOTS_PIN_HASH_LEN       16u
#define SLOTS_PIN_RETRIES_INITIAL 8u

/**
 * @brief Read PIN state from R-mem slot 0.
 * @param out_pin_set    1 if a PIN is currently set, 0 otherwise.
 * @param out_retries    current retries-remaining count (only meaningful when pin_set).
 * @param out_pin_hash   16 B; populated only when pin_set==1.
 * @return 0 on success; -1 on chip error.
 */
int slots_global_pin_get(int *out_pin_set,
                         uint32_t *out_retries,
                         uint8_t out_pin_hash[SLOTS_PIN_HASH_LEN]);

/**
 * @brief Set / replace the PIN. Stores hash, resets retries to 8,
 *        marks pin_set=1. Overwrites any previous PIN.
 * @return 0 on success; -1 on chip error.
 */
int slots_global_pin_set(const uint8_t pin_hash[SLOTS_PIN_HASH_LEN]);

/**
 * @brief Decrement PIN retries counter (after a wrong-PIN attempt).
 *        Floor at 0. Returns the new value via out_new.
 * @return 0 on success; -1 on chip error.
 */
int slots_global_pin_dec_retries(uint32_t *out_new);

/**
 * @brief Restore PIN retries to INITIAL (after a correct PIN).
 * @return 0 on success; -1 on chip error.
 */
int slots_global_pin_reset_retries(void);

/* ===== Phase 5 M4: MAC-and-Destroy state =====
 *
 * Layout in R-mem slot 0 (extends M3 PIN state). See
 * docs/PHASE-5-M4-DESIGN.md §"R-mem slot 0 layout (M4 extension)".
 *
 *   [31]      md_active (0 = not initialized, 1 = active)
 *   [32]      md_next_slot (0..7) — next slot index to consume
 *   [33..64]  md_tag (32 B) — verification tag
 *   [65..320] md_ci (8 * 32 B = 256 B) — encrypted master_secret per slot
 *
 * Schema version 2 (was 1 in M1/M3). Old schema=1 state is migrated by
 * factory_reset (acceptable in Phase 5 dev — user re-sets PIN). */

#define SLOTS_MD_ROUNDS              8u
#define SLOTS_MD_SLOT_SIZE          32u
#define SLOTS_MD_CI_LEN            (SLOTS_MD_ROUNDS * SLOTS_MD_SLOT_SIZE)
#define SLOTS_MD_TAG_LEN            32u

/**
 * @brief Read M&D state.
 *
 * @param out_active        1 = M&D slots are initialized (PIN set), 0 = not.
 * @param out_next_slot     Next slot to consume on attempt (0..ROUNDS).
 *                          When equal to ROUNDS, no slots remaining
 *                          (PIN exhausted at HW level — needs factory_reset).
 * @param out_tag           32 B verification tag.
 * @param out_ci            256 B encrypted secrets array.
 * @return 0 on success; -1 on chip error.
 */
int slots_global_md_get(int *out_active,
                        uint8_t *out_next_slot,
                        uint8_t out_tag[SLOTS_MD_TAG_LEN],
                        uint8_t out_ci[SLOTS_MD_CI_LEN]);

/**
 * @brief Persist M&D state to R-mem slot 0.
 *
 * @param active      1 = M&D active.
 * @param next_slot   Next slot pointer (0..ROUNDS).
 * @param tag         Verification tag.
 * @param ci          256 B encrypted secrets array.
 * @return 0 on success; -1 on chip error.
 */
int slots_global_md_set(int active,
                        uint8_t next_slot,
                        const uint8_t tag[SLOTS_MD_TAG_LEN],
                        const uint8_t ci[SLOTS_MD_CI_LEN]);

/**
 * @brief Advance the M&D next-slot pointer by one (commit attempt
 *        BEFORE doing the M&D op — power-loss-safe). Writes R-mem.
 *        Sets *out_new to the value AFTER increment.
 * @return 0 on success; -1 on chip error.
 */
int slots_global_md_advance(uint8_t *out_new);

#endif /* NIXTROPIC_FIDO_HID_SLOTS_H */
