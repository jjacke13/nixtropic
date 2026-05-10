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

#endif /* NIXTROPIC_FIDO_HID_SLOTS_H */
