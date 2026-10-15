/*
 * Phase 5 M2 — credential store backed by TROPIC01 ECC slots + R-mem +
 * hardware monotonic counter. See credstore.h.
 *
 * No embedded keys. No software Ed25519. The chip generates, stores,
 * and signs.
 */

#include "credstore.h"
#include "slots.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "tropic/tropic.h"

/* COSE alg id 8 (which our slot layer stores in R-mem) corresponds to
 * the WebAuthn / FIDO `alg = -8` (EdDSA). credstore_make takes COSE 8
 * as the only supported value for M2; future ES256 support would add 7. */
#define CREDSTORE_ALG_ED25519   SLOTS_ALG_ED25519

/* TROPIC01 hw monotonic counter index used as the shared signCount source.
 * 0..15 available; we own counter 0 for Phase 5 FIDO2. Phase 7 (OpenPGP
 * card) may claim counter 1 for its key-use counter if needed. */
#define CREDSTORE_SIGNCOUNT_MCOUNTER  0u

/* Per TROPIC01 spec the mcounter init range is [0, TR01_MCOUNTER_VALUE_MAX].
 * Mirror the libtropic_common.h value here so we don't depend on its
 * private headers — defined as 0xFFFFFFFE (0xFFFFFFFF means "empty" and
 * is refused by the chip). */
#define CREDSTORE_MCOUNTER_MAX  0xFFFFFFFEu

/* libtropic ECC curve index for Ed25519, matching tropic_ecc_generate
 * 's curve parameter (0 = Ed25519, 1 = P-256). */
#define CREDSTORE_CURVE_ED25519   0u

static int s_initted;

/* Phase 6 M3 (H2 defense): true while credstore_make / credstore_erase_slot
 * is mid-flight.  MakeCred / GetAssertion check this and return BUSY to
 * the host — keeps the (slots → ECC → R-mem) write sequence atomic from
 * the FIDO surface's POV. */
static volatile int s_credstore_mutating;

/* ----- Init ----- */

/* Phase 9 M3 (Jan, M3 review): the counter is never initialised because
 * a read failed.  COUNTER_INVALID also means "corrupt" or "disabled", so
 * it starts a fresh counter only on a genuine first boot (slots_init saw
 * slot 0 reported empty by the chip: no credential can exist).  Any
 * other failure leaves FIDO failing closed; authenticatorReset is the
 * explicit way out. */
int credstore_init(void)
{
    if (s_initted) {
        return 0;
    }
    if (slots_init() != 0) {
        return -1;
    }

    uint32_t v;
    int rc = tropic_mcounter_get(CREDSTORE_SIGNCOUNT_MCOUNTER, &v);
    /* Taken (and so consumed) whatever the counter says: the bootstrap
     * right exists once, at the first init of a genuine first boot. */
    int fresh = slots_take_fresh_store();
    if (rc == TROPIC_ERR_COUNTER_INVALID && fresh) {
        if (tropic_mcounter_init(CREDSTORE_SIGNCOUNT_MCOUNTER,
                                 CREDSTORE_MCOUNTER_MAX) != 0) {
            printf("[credstore] mcounter init FAILED\n");
            return -2;
        }
        printf("[credstore] first boot: mcounter 0 initialized (signCount=0)\n");
    } else if (rc != 0) {
        printf("[credstore] mcounter 0 unreadable (%d): FIDO2 disabled until reset\n", rc);
        return -2;
    } else if (v > CREDSTORE_MCOUNTER_MAX) {
        printf("[credstore] mcounter 0 out of range\n");
        return -2;
    } else {
        printf("[credstore] mcounter 0 resumed at chip=%lu signCount=%lu\n",
               (unsigned long) v, (unsigned long)(CREDSTORE_MCOUNTER_MAX - v));
    }

    s_initted = 1;
    return 0;
}

/* ----- MakeCredential ----- */

int credstore_make(const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                   uint8_t alg, uint8_t flags,
                   const uint8_t *user_handle, size_t user_handle_len,
                   uint32_t created, uint32_t replace_mask,
                   uint8_t out_pubkey[CREDSTORE_PUBKEY_LEN],
                   uint8_t out_cred_id[CREDSTORE_CRED_ID_LEN],
                   credstore_handle_t *out_handle)
{
    if (!rp_id_hash || !out_pubkey || !out_cred_id || !out_handle) {
        return -1;
    }
    if (alg != CREDSTORE_ALG_ED25519) {
        /* M2 only supports Ed25519. P-256 deferred to later phase. */
        return -1;
    }
    /* No key operation while the slot bitmap may disagree with the chip:
     * a "free" slot could hold a possibly-published key (Jan, M3 round 2). */
    if (!slots_usable()) {
        return -2;
    }
    if (!s_initted) {
        int rc = credstore_init();
        if (rc != 0) return -2;
    }

    s_credstore_mutating = 1;

    /* Generate and check the key in a FREE slot before anything points
     * at it: allocation picks the slot without publishing it (the bitmap
     * bit is set last, by slots_alloc), so on failure the slot just stays
     * free.  Then slots_alloc writes the metadata and, in ONE bitmap
     * write, publishes the new credential and drops the replaced ones. */
    int slot_idx = -1;
    for (int i = 0; i < (int) FIDO_SLOTS_MAX; ++i) {
        if ((slots_bitmap() & (1u << i)) == 0u) {
            slot_idx = i;
            break;
        }
    }
    if (slot_idx < 0) {
        s_credstore_mutating = 0;
        return -1;              /* full: 29 FIDO credentials */
    }
    if (tropic_ecc_erase((uint8_t) slot_idx) != 0
        || tropic_ecc_generate((uint8_t) slot_idx, CREDSTORE_CURVE_ED25519) != 0
        || tropic_ecc_pubkey_read((uint8_t) slot_idx, out_pubkey,
                                  CREDSTORE_PUBKEY_LEN) != (int) CREDSTORE_PUBKEY_LEN) {
        (void) tropic_ecc_erase((uint8_t) slot_idx);
        s_credstore_mutating = 0;
        return -2;
    }

    uint8_t cred_id[CREDSTORE_CRED_ID_LEN];
    int got_idx = -1;
    int rc = slots_alloc(rp_id_hash, alg, flags, user_handle, user_handle_len,
                         created, replace_mask, cred_id, &got_idx);
    if (rc == -3) {
        /* Bitmap write failed: maybe published.  Keep the key; a free
         * slot holding it is erased again before reuse (Jan, M3 review). */
        s_credstore_mutating = 0;
        return -2;
    }
    if (rc != 0 || got_idx != slot_idx) {
        /* Not published (or, impossibly, a different slot): the key must
         * not outlive the failed registration. */
        (void) tropic_ecc_erase((uint8_t) slot_idx);
        if (rc == 0) (void) slots_erase(got_idx);
        s_credstore_mutating = 0;
        return (rc == -1) ? -1 : -2;
    }

    memcpy(out_cred_id, cred_id, CREDSTORE_CRED_ID_LEN);
    *out_handle = (credstore_handle_t) slot_idx;
    s_credstore_mutating = 0;
    return 0;
}

int credstore_get_pubkey(int slot_idx, uint8_t out_pubkey[CREDSTORE_PUBKEY_LEN])
{
    if (!out_pubkey || slot_idx < 0 || slot_idx >= (int) FIDO_SLOTS_MAX) {
        return -1;
    }
    int got = tropic_ecc_pubkey_read((uint8_t) slot_idx,
                                     out_pubkey, CREDSTORE_PUBKEY_LEN);
    return (got == (int) CREDSTORE_PUBKEY_LEN) ? 0 : -1;
}

int credstore_erase_slot(int slot_idx)
{
    if (slot_idx < 0 || slot_idx >= (int) FIDO_SLOTS_MAX) {
        return -1;
    }
    if (!slots_usable()) {
        return -2;              /* see credstore_make */
    }
    s_credstore_mutating = 1;
    /* ECC slot first (destroys the chip-side private key), then R-mem
     * metadata + bitmap clear (via slots_erase).  If the key erase fails
     * the credential stays registered and the caller sees the error
     * (Phase 9 M2); after an ambiguous failure the chip key may or may
     * not be gone. */
    if (tropic_ecc_erase((uint8_t) slot_idx) != 0) {
        s_credstore_mutating = 0;
        return -2;
    }
    int rc = slots_erase(slot_idx);
    s_credstore_mutating = 0;
    return (rc == 0) ? 0 : -2;
}

int credstore_is_mutating(void)
{
    return s_credstore_mutating ? 1 : 0;
}

/* ----- GetAssertion ----- */

int credstore_lookup(const uint8_t *cred_id, size_t cred_id_len,
                     credstore_handle_t *out_handle)
{
    if (!out_handle) return -1;
    if (!s_initted) {
        if (credstore_init() != 0) return -1;
    }
    int slot_idx = -1;
    if (slots_lookup_by_credid(cred_id, cred_id_len, &slot_idx, NULL) != 0) {
        return -1;
    }
    *out_handle = (credstore_handle_t) slot_idx;
    return 0;
}

int credstore_find(const uint8_t *cred_id, size_t cred_id_len,
                   const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                   credstore_handle_t *out_handle, slot_meta_t *out_meta)
{
    slot_meta_t meta;
    int slot_idx = -1;
    if (!out_handle || !rp_id_hash) return -1;
    if (!s_initted && credstore_init() != 0) return -1;
    if (slots_lookup_by_credid(cred_id, cred_id_len, &slot_idx, &meta) != 0) {
        return -1;
    }
    /* A credential is bound to the RP it was made for (CTAP §6.2.2
     * step 7.1).  rpIdHash is public, so memcmp is fine. */
    if (memcmp(meta.rp_id_hash, rp_id_hash, SLOTS_RP_ID_HASH_LEN) != 0) {
        return -1;
    }
    *out_handle = (credstore_handle_t) slot_idx;
    if (out_meta) *out_meta = meta;
    return 0;
}

int credstore_sign(credstore_handle_t h,
                   const uint8_t *msg, size_t msg_len,
                   uint8_t out_sig[CREDSTORE_SIG_LEN])
{
    if (!msg || !out_sig) return -1;
    if (h < 0 || h >= (int) FIDO_SLOTS_MAX) return -1;
    int got = tropic_ecc_eddsa_sign((uint8_t) h, msg, msg_len,
                                    out_sig, CREDSTORE_SIG_LEN);
    return (got == (int) CREDSTORE_SIG_LEN) ? 0 : -2;
}

/* ----- signCount (Phase 9 M3, Jan M3 Q1-Q4) ----- */

/* The chip counter counts down from MAX; WebAuthn's signCount counts up. */
static int read_signcount(uint32_t *out)
{
    uint32_t v = 0;
    if (tropic_mcounter_get(CREDSTORE_SIGNCOUNT_MCOUNTER, &v) != 0
        || v > CREDSTORE_MCOUNTER_MAX) {
        return -2;
    }
    *out = CREDSTORE_MCOUNTER_MAX - v;
    return 0;
}

int credstore_signcount_peek(uint32_t *out)
{
    if (!out) return -1;
    if (!s_initted && credstore_init() != 0) return -2;
    return read_signcount(out);
}

int credstore_signcount_next(uint32_t *out)
{
    if (!out) return -1;
    if (!s_initted && credstore_init() != 0) return -2;
    /* Reserve first, then read: whatever fails later leaves a gap, never
     * a repeated value.  No retry: a failed Update may have run. */
    if (tropic_mcounter_update(CREDSTORE_SIGNCOUNT_MCOUNTER) != 0) {
        return -2;
    }
    return read_signcount(out);
}

/* ----- Factory reset ----- */

/* Phase 9 M3 (Jan, M3 review 2): keys first, all or nothing.  If any FIDO
 * key erase fails, stop BEFORE the PIN, bitmap and metadata are wiped, so
 * no surviving key ends up with its protection reset.  Only after the
 * state wipe succeeded does the signature counter start again.  OpenPGP
 * slots 29..31 and its R-mem state are not touched. */
int credstore_factory_reset(void)
{
    int erase_failed = 0;
    for (uint8_t i = 0; i < FIDO_SLOTS_MAX; ++i) {
        if (tropic_ecc_erase(i) != 0) erase_failed = 1;
    }
    s_initted = 0;              /* re-check everything on next use */
    if (erase_failed) {
        return -1;
    }
    if (slots_factory_reset() != 0) {
        return -1;
    }
    /* cpp-reviewer audit 2026-05-11 M2: a post-reset credential must
     * start at signCount 0, not leak the old count. */
    if (tropic_mcounter_init(CREDSTORE_SIGNCOUNT_MCOUNTER,
                             CREDSTORE_MCOUNTER_MAX) != 0) {
        return -1;
    }
    return 0;
}
