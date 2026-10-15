/*
 * Phase 5 M2 — credential store backed by TROPIC01 ECC slots + R-mem +
 * hardware monotonic counter. See credstore.h.
 *
 * No embedded keys. No software Ed25519. The chip generates, stores,
 * and signs.
 */

#include "credstore.h"
#include "slots.h"
#include "fido_state.h"
#include "pin_md.h"
#include "cose.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "tropic/tropic.h"

/* TROPIC01 monotonic counter 0 = the shared signCount (fido_state.h owns
 * its index, start value and when it may be initialised). */
#define CREDSTORE_SIGNCOUNT_MCOUNTER  FIDO_SIGNCOUNT_MCOUNTER
#define CREDSTORE_MCOUNTER_MAX        FIDO_MCOUNTER_MAX

/* tropic_ecc_generate's curve parameter. */
#define CREDSTORE_CURVE_ED25519   0u
#define CREDSTORE_CURVE_P256      1u

/* Public key length for a stored alg (slots.h SLOTS_ALG_*), 0 if unknown.
 * The length is also how tropic_ecc_pubkey_read reports the slot's curve,
 * so a key of the wrong curve never passes as the stored alg. */
static size_t pubkey_len(uint8_t alg)
{
    switch (alg) {
    case SLOTS_ALG_ED25519: return 32u;
    case SLOTS_ALG_ES256:   return 64u;
    default:                return 0u;
    }
}

static int s_initted;

/* Phase 6 M3 (H2 defense): true while credstore_make / credstore_erase_slot
 * is mid-flight.  MakeCred / GetAssertion check this and return BUSY to
 * the host — keeps the (slots → ECC → R-mem) write sequence atomic from
 * the FIDO surface's POV. */
static volatile int s_credstore_mutating;

/* ----- Init ----- */

/* Boot rules and the counter policy live in fido_state.c (Phase 9 M4). */
int credstore_init(void)
{
    if (s_initted) {
        return 0;
    }
    int rc = fido_state_boot();
    if (rc != 0) {
        printf("[credstore] FIDO state unusable (%d): only authenticatorReset works\n", rc);
        return -1;
    }
    s_initted = 1;
    return 0;
}

/* ----- MakeCredential ----- */

int credstore_make(const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                   uint8_t alg, uint8_t flags,
                   const uint8_t *user_handle, size_t user_handle_len,
                   uint32_t created, uint32_t replace_mask,
                   uint8_t out_pubkey[CREDSTORE_PUBKEY_MAX],
                   uint8_t out_cred_id[CREDSTORE_CRED_ID_LEN],
                   credstore_handle_t *out_handle)
{
    if (!rp_id_hash || !out_pubkey || !out_cred_id || !out_handle) {
        return -1;
    }
    size_t want = pubkey_len(alg);
    if (want == 0u) {
        return -2;              /* the caller only passes supported algs */
    }
    uint8_t curve = (alg == SLOTS_ALG_ES256) ? CREDSTORE_CURVE_P256
                                             : CREDSTORE_CURVE_ED25519;
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
        || tropic_ecc_generate((uint8_t) slot_idx, curve) != 0
        || tropic_ecc_pubkey_read((uint8_t) slot_idx, out_pubkey,
                                  CREDSTORE_PUBKEY_MAX) != (int) want) {
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

int credstore_get_pubkey(int slot_idx, uint8_t alg,
                         uint8_t out_pubkey[CREDSTORE_PUBKEY_MAX])
{
    size_t want = pubkey_len(alg);
    if (!out_pubkey || want == 0u || slot_idx < 0 || slot_idx >= (int) FIDO_SLOTS_MAX) {
        return -1;
    }
    int got = tropic_ecc_pubkey_read((uint8_t) slot_idx,
                                     out_pubkey, CREDSTORE_PUBKEY_MAX);
    return (got == (int) want) ? (int) want : -1;
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

int credstore_sign(credstore_handle_t h, uint8_t alg,
                   const uint8_t *msg, size_t msg_len,
                   uint8_t out_sig[CREDSTORE_SIG_MAX])
{
    if (!msg || !out_sig) return -1;
    if (h < 0 || h >= (int) FIDO_SLOTS_MAX) return -1;
    if (alg == SLOTS_ALG_ED25519) {
        int got = tropic_ecc_eddsa_sign((uint8_t) h, msg, msg_len, out_sig, 64u);
        return (got == 64) ? 64 : -2;
    }
    if (alg == SLOTS_ALG_ES256) {
        uint8_t rs[64];
        int got = tropic_ecc_ecdsa_sign((uint8_t) h, msg, msg_len, rs, sizeof rs);
        int n = (got == 64) ? cose_es256_der(rs, out_sig, CREDSTORE_SIG_MAX) : -1;
        return (n > 0) ? n : -2;
    }
    return -1;
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

/* Design §4 / D8: keys, metadata, PIN binding, fresh O1, counter — each
 * step checked, any failure stops it (fido_state_wipe). */
int credstore_factory_reset(void)
{
    s_initted = 0;
    if (fido_state_wipe() != 0) return -1;
    s_initted = 1;              /* a completed wipe = a known fresh state */
    return 0;
}

int credstore_ready(void)
{
    /* O1 and the PIN binding O2: an ambiguous write to either ends
     * readiness until reboot or a completed reset (Jan, step 3 r2). */
    return s_initted && slots_usable() && fido_pin_usable();
}
