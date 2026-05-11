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
 * private headers — defined as 0xFFFFFFFE. */
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

int credstore_init(void)
{
    if (s_initted) {
        return 0;
    }
    if (slots_init() != 0) {
        return -1;
    }

    /* Try to read the mcounter. If it returns a sane value, leave it
     * alone (returning state from a previous boot). If the get fails
     * (counter never initialized), init it to MAX.
     *
     * Note: lt_mcounter_init() is safe to call on an already-initialized
     * counter — it resets to the new value. We only init when get fails
     * so we don't accidentally reset signCount across reboots. */
    uint32_t v;
    if (tropic_mcounter_get(CREDSTORE_SIGNCOUNT_MCOUNTER, &v) != 0) {
        if (tropic_mcounter_init(CREDSTORE_SIGNCOUNT_MCOUNTER,
                                 CREDSTORE_MCOUNTER_MAX) != 0) {
            printf("[credstore] mcounter init FAILED\n");
            return -2;
        }
        printf("[credstore] mcounter 0 initialized to MAX (signCount=0)\n");
    } else {
        uint32_t sc = CREDSTORE_MCOUNTER_MAX - v;
        printf("[credstore] mcounter 0 resumed at chip=%lu signCount=%lu\n",
               (unsigned long) v, (unsigned long) sc);
    }

    s_initted = 1;
    return 0;
}

/* ----- MakeCredential ----- */

int credstore_make(const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                   uint8_t alg,
                   const uint8_t *user_handle, size_t user_handle_len,
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
    if (!s_initted) {
        int rc = credstore_init();
        if (rc != 0) return rc;
    }

    s_credstore_mutating = 1;

    int slot_idx = -1;
    uint8_t cred_id[CREDSTORE_CRED_ID_LEN];
    if (slots_alloc(rp_id_hash, alg, user_handle, user_handle_len,
                    cred_id, &slot_idx) != 0) {
        s_credstore_mutating = 0;
        return -1;
    }

    /* Generate fresh Ed25519 keypair on the chip + read the pubkey.
     * If any step fails, roll back the slot allocation so the bitmap
     * stays clean. */
    if (tropic_ecc_erase((uint8_t) slot_idx) != 0) {
        (void) slots_erase(slot_idx);
        s_credstore_mutating = 0;
        return -2;
    }
    if (tropic_ecc_generate((uint8_t) slot_idx, CREDSTORE_CURVE_ED25519) != 0) {
        (void) slots_erase(slot_idx);
        s_credstore_mutating = 0;
        return -2;
    }
    int got = tropic_ecc_pubkey_read((uint8_t) slot_idx,
                                     out_pubkey, CREDSTORE_PUBKEY_LEN);
    if (got != (int) CREDSTORE_PUBKEY_LEN) {
        (void) tropic_ecc_erase((uint8_t) slot_idx);
        (void) slots_erase(slot_idx);
        s_credstore_mutating = 0;
        return -2;
    }

    memcpy(out_cred_id, cred_id, CREDSTORE_CRED_ID_LEN);
    *out_handle = (credstore_handle_t) slot_idx;
    s_credstore_mutating = 0;
    return 0;
}

int credstore_get_pubkey(int slot_idx, uint8_t out_pubkey[CREDSTORE_PUBKEY_LEN])
{
    if (!out_pubkey || slot_idx < 0 || slot_idx >= (int) SLOTS_MAX) {
        return -1;
    }
    int got = tropic_ecc_pubkey_read((uint8_t) slot_idx,
                                     out_pubkey, CREDSTORE_PUBKEY_LEN);
    return (got == (int) CREDSTORE_PUBKEY_LEN) ? 0 : -1;
}

int credstore_erase_slot(int slot_idx)
{
    if (slot_idx < 0 || slot_idx >= (int) SLOTS_MAX) {
        return -1;
    }
    s_credstore_mutating = 1;
    /* ECC slot first (destroys the chip-side private key), then R-mem
     * metadata + bitmap clear (via slots_erase). */
    (void) tropic_ecc_erase((uint8_t) slot_idx);
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
    if (slots_lookup_by_credid(cred_id, cred_id_len, &slot_idx) != 0) {
        return -1;
    }
    *out_handle = (credstore_handle_t) slot_idx;
    return 0;
}

int credstore_sign(credstore_handle_t h,
                   const uint8_t *msg, size_t msg_len,
                   uint8_t out_sig[CREDSTORE_SIG_LEN])
{
    if (!msg || !out_sig) return -1;
    if (h < 0 || h >= (int) SLOTS_MAX) return -1;
    int got = tropic_ecc_eddsa_sign((uint8_t) h, msg, msg_len,
                                    out_sig, CREDSTORE_SIG_LEN);
    return (got == (int) CREDSTORE_SIG_LEN) ? 0 : -2;
}

/* ----- signCount ----- */

uint32_t credstore_peek_signcount(void)
{
    if (!s_initted) {
        if (credstore_init() != 0) return 0;
    }
    uint32_t v = 0;
    if (tropic_mcounter_get(CREDSTORE_SIGNCOUNT_MCOUNTER, &v) != 0) {
        return 0;
    }
    /* Convert chip's decrementing value to WebAuthn's strictly-
     * increasing signCount. Chip starts at MAX, decrements; we
     * report MAX - v which starts at 0 and increments. */
    return CREDSTORE_MCOUNTER_MAX - v;
}

void credstore_commit_signcount(void)
{
    if (!s_initted) {
        if (credstore_init() != 0) return;
    }
    /* Update = decrement on TROPIC01. After this call,
     * credstore_peek_signcount returns one higher. */
    (void) tropic_mcounter_update(CREDSTORE_SIGNCOUNT_MCOUNTER);
}

/* ----- Factory reset ----- */

int credstore_factory_reset(void)
{
    /* Erase all 32 ECC slots — best-effort. Empty slots return error
     * but caller intent is "ensure this slot is empty". */
    for (uint8_t i = 0; i < SLOTS_MAX; ++i) {
        (void) tropic_ecc_erase(i);
    }
    /* Reset signCount source to MAX. cpp-reviewer audit 2026-05-11 M2:
     * without this, a post-reset credential registers with a non-zero
     * signCount which an RP may flag as a replay-detect sentinel and
     * also leaks how many assertions the device has performed since
     * its last init. */
    (void) tropic_mcounter_init(CREDSTORE_SIGNCOUNT_MCOUNTER,
                                CREDSTORE_MCOUNTER_MAX);
    /* Wipe R-mem bitmap + per-cred metadata + PIN state + M&D state. */
    int rc = slots_factory_reset();
    /* Force re-init on next credstore use so we re-detect mcounter etc. */
    s_initted = 0;
    return rc;
}
