/*
 * TROPIC01-backed credential slot manager.
 *
 * Manages up to 29 FIDO2 credentials (slots 0..28); slots 29..31 are
 * reserved for OpenPGP card sig/dec/aut keys (see firmware/src/
 * openpgp/pgp_keys.h §slot allocation).
 *
 * Each credential occupies:
 *   - TROPIC01 ECC slot (TR01_ECC_SLOT_0 + idx)        — private key, on chip
 *   - TROPIC01 R-mem slot (idx + 1)                    — metadata (256 B)
 *
 * FIDO global state = object O1, a mirrored record pair in R-mem slots 0
 * and 40 (Phase 9 M4, docs/history/PHASE-9-M4-DESIGN.md §2, §4): allocation
 * bitmap, Force-UV flag, and the `pin_bound` guard of the PIN binding O2.
 * No PIN state lives here any more (pin_md.c, kernel v2).
 *
 * Persistence model:
 *   - O1 changes only through rec_pair (both copies, read-back proven); a
 *     failed write leaves the pair uncertain and every slot operation is
 *     refused until the next boot.
 *   - slots_init never writes fresh state by itself: O1 ABSENT is the
 *     caller's cue for a checked FIDO wipe (fido_state.c), O1 damaged or
 *     unreadable is an error (FIDO refuses all but authenticatorReset).
 *   - Orphan-scrub: at boot a bitmap bit is cleared only when its metadata
 *     slot reads empty; a read error or bad content keeps the bit (the
 *     credential then fails to resolve).  The key is erased before a slot
 *     is reused (Phase 9 M3).
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
/* Phase 7 M1 — FIDO allocator cap.  TROPIC01 has 32 ECC slots total
 * (verified via libtropic enum TR01_ECC_SLOT_0..TR01_ECC_SLOT_31 and
 * docs/history/research/tropic01-inventory.md).  Phase 7 reserves slots 29/30/31
 * for OpenPGP sig/dec/aut keys; FIDO credential allocation refuses
 * indices ≥ FIDO_SLOTS_MAX. */
#define FIDO_SLOTS_MAX               29u
#define OPENPGP_SLOT_SIG             29u   /* Ed25519, DO C7 fingerprint */
#define OPENPGP_SLOT_DEC             30u   /* Cv25519, DO C8 */
#define OPENPGP_SLOT_AUT             31u   /* Ed25519, DO C9 */
#define SLOTS_CRED_ID_LEN            18u
#define SLOTS_CRED_ID_NONCE_LEN      16u
#define SLOTS_RP_ID_HASH_LEN         32u
#define SLOTS_RMEM_GLOBAL_SLOT       0u
#define SLOTS_RMEM_PER_CRED_SIZE     256u
#define SLOTS_RMEM_GLOBAL_SIZE       256u
/* Phase 6 M3 — user_handle storage in per-credential slot.  Up to 64 B
 * per WebAuthn spec (RP-supplied at MakeCred).  Stored in the 200 B
 * reserved area of the per-cred slot at offset 56..120.  Old creds
 * (Phase 5 schema) read all-zeros there, which decodes as
 * user_handle_len = 0 (i.e. "no user info"). */
#define SLOTS_USER_HANDLE_MAX        64u

/* Stored alg = minus the COSE algorithm id: 8 = EdDSA (-8), 7 = ES256 (-7). */
#define SLOTS_ALG_ED25519            8u
#define SLOTS_ALG_ES256              7u

#define SLOTS_FLAG_RESIDENT          (1u << 0)

/* slot_idx → R-mem slot. Per-cred R-mem starts at slot 1 to keep
 * slot 0 reserved for global state. */
#define SLOTS_RMEM_SLOT_FOR(idx)     ((uint16_t)((idx) + 1u))

typedef struct {
    uint8_t  alg;                                       /* SLOTS_ALG_* */
    uint8_t  flags;                                     /* SLOTS_FLAG_* */
    uint8_t  rp_id_hash[SLOTS_RP_ID_HASH_LEN];
    uint8_t  cred_id_nonce[SLOTS_CRED_ID_NONCE_LEN];
    /* Phase 6 M3 — user_handle from MakeCredential, used by
     * authenticatorCredentialManagement enumerateCredentials response.
     * Old (Phase 5) creds read user_handle_len=0 here. */
    uint8_t  user_handle_len;
    uint8_t  user_handle[SLOTS_USER_HANDLE_MAX];
    /* Phase 9 M3 — creation sequence (1 + highest at creation time), for
     * newest-first discovery.  Older credentials read 0. */
    uint32_t created;
} slot_meta_t;

/* slots_init results. */
#define SLOTS_INIT_OK       0
#define SLOTS_INIT_ABSENT   1    /* O1 never written or cleared: wipe, then slots_init_fresh */

/**
 * @brief Read O1 (repairing a pair whose copies differ) and orphan-scrub.
 *        Idempotent once it succeeded.
 *
 * @return SLOTS_INIT_OK; SLOTS_INIT_ABSENT; negative on a chip error or a
 *         damaged / uncertain O1 (FIDO must refuse all but Reset).
 */
int slots_init(void);

/**
 * @brief Write a fresh O1 (bitmap 0, Force-UV off, pin_bound 0): checked
 *        erase of both copies, then both written.  Only after a completed
 *        checked wipe of everything FIDO owns (fido_state.c).
 * @return 0 on success; -1 on chip error (O1 uncertain until reboot).
 */
int slots_init_fresh(void);

/**
 * @brief Checked erase of every FIDO metadata slot (R-mem 1..29): erase,
 *        then the slot must read empty.  Stops at the first failure.
 * @return 0 on success; -1 on chip error.
 */
int slots_wipe_meta(void);

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
 * @param  rp_id_hash       SHA-256 of rp.id (32 B); persisted in meta.
 * @param  alg              SLOTS_ALG_ED25519 or SLOTS_ALG_ES256.
 * @param  flags            SLOTS_FLAG_* (RESIDENT = discoverable, Phase 9 M3).
 * @param  user_handle      User handle from MakeCredential (optional;
 *                          may be NULL for Phase-5-style alloc).
 * @param  user_handle_len  0..SLOTS_USER_HANDLE_MAX.  Pass 0 to omit.
 * @param  created          Creation sequence stored in the metadata.
 * @param  replace_mask     Bitmap bits cleared by the SAME bitmap write that
 *                          adds the new credential (same-account overwrite,
 *                          Phase 9 M3): the old IDs stop resolving in one
 *                          step.  The caller erases their keys afterwards.
 * @param  out_cred_id      Caller buffer; 18 B written on success.
 * @param  out_slot_idx     Caller's slot index out (0..28).
 * @return 0 on success; -1 if full or invalid params; -2 on TROPIC01 error
 *         (nothing published); -3 if the bitmap write failed: the
 *         outcome is unknown, nothing is cleaned up, and allocation and
 *         erase are refused until the next boot (Phase 9 M3).
 */
int slots_alloc(const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                uint8_t alg, uint8_t flags,
                const uint8_t *user_handle, size_t user_handle_len,
                uint32_t created, uint32_t replace_mask,
                uint8_t out_cred_id[SLOTS_CRED_ID_LEN],
                int *out_slot_idx);

/**
 * @brief Resolve a credential ID to a slot index.
 *
 *   1. Reject if cred_id_len != 18 or version byte != 0x01.
 *   2. Read slot_idx from byte[1]; reject if ≥ FIDO_SLOTS_MAX (29).
 *   3. Read per-credential R-mem; reject if magic mismatch.
 *   4. Constant-time compare nonce; reject on mismatch.
 *
 * @param out_meta  optional (NULL): the credential's metadata.
 * @return 0 on success (out_slot_idx populated); -1 on not-found.
 */
int slots_lookup_by_credid(const uint8_t *cred_id, size_t cred_id_len,
                           int *out_slot_idx, slot_meta_t *out_meta);

/**
 * @brief 0 unless O1 was read (or freshly written) this boot and no O1
 *        write has failed since: then every slot operation (lookup,
 *        metadata, allocation, erase, global-state write) is refused and
 *        callers must not touch credential keys (Phase 9 M3/M4).
 */
int slots_usable(void);

/**
 * @brief The 18 B credential ID of a slot: [0x01, slot_idx, nonce(16)].
 */
void slots_make_cred_id(int slot_idx, const slot_meta_t *meta,
                        uint8_t out_cred_id[SLOTS_CRED_ID_LEN]);

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
 * @brief The `pin_bound` guard of the FIDO PIN binding (design §2.5):
 *        1 = a PIN binding was committed, 0 = none; -1 if O1 is unusable.
 */
int slots_pin_bound(void);

/**
 * @brief One O1 write: pin_bound := bound and, if `force_uv_on`, Force-UV
 *        on (the first-PIN auto-enable, Phase 6).
 * @return 0 on success; -1 on chip error (O1 uncertain until reboot).
 */
int slots_set_pin_bound(int bound, int force_uv_on);

/* ===== Phase 6 M2: Force-UV flag =====
 *
 * Persisted in O1 (Phase 9 M4).
 *
 * Semantics (docs/history/PHASE-6-PLAN.md §4.4):
 *   0 = honour RP's `userVerification` hint (Phase 5 behaviour).
 *   1 = always require pinAuth on MakeCred/GetAssertion, regardless
 *       of RP hint.  GetInfo also advertises `options.alwaysUv=true`
 *       so browsers proactively prompt for PIN.
 *
 * Auto-enabled on first `setPIN` (no-PIN → PIN-set transition).
 * User can opt out via the lt-rpc `force-uv-set 0` vendor command,
 * which is PIN-gated. */

/**
 * @brief Read the Force-UV flag.
 * @return 1 if Force-UV is enabled or O1 is unusable (the stricter
 *         policy), 0 otherwise.
 */
int slots_force_uv_get(void);

/**
 * @brief Set / clear the Force-UV flag and persist to R-mem.
 * @param value  1 = enable, 0 = disable.
 * @return 0 on success; -1 on chip error.
 */
int slots_force_uv_set(int value);

#ifdef NIXTROPIC_HOST_TEST
/* Host tests only: forget the RAM state, as a reboot does. */
void slots_test_reboot(void);
#endif

#endif /* NIXTROPIC_FIDO_HID_SLOTS_H */
