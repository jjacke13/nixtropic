/*
 * The OpenPGP DEC key wrapped under the PW1 KEK.  See pgp_dec.h.
 */
#include "pgp_dec.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "aes/aesgcm.h"
#include "ed25519-donna/ed25519.h"   /* curve25519_scalarmult{,_basepoint} */
#include "hmac.h"
#include "memzero.h"
#include "openpgp_state.h"
#include "tropic/pin_md_kernel.h"
#include "tropic/tropic.h"

#define AAD_LEN  (4u + 2u + OPENPGP_DEC_PUB_LEN)

static const char KEK_LABEL[] = "nixtropic/openpgp/dec-kek/v1";

_Static_assert(OPENPGP_DEC_PUB_LEN == PGP_DEC_KEY_LEN && OPENPGP_DEC_CT_LEN == PGP_DEC_KEY_LEN
               && PIN_MD_KERNEL_K_LEN == PGP_DEC_KEY_LEN,
               "DEC record sizes");

void pgp_dec_kek(const uint8_t k[PGP_DEC_KEY_LEN], uint8_t kek[PGP_DEC_KEY_LEN])
{
    hmac_sha256(k, PGP_DEC_KEY_LEN, (const uint8_t *) KEK_LABEL, sizeof KEK_LABEL - 1u, kek);
}

/* E3: the wrap is bound to the object, the schema and its public key. */
static void aad_of(const uint8_t pub[OPENPGP_DEC_PUB_LEN], uint8_t aad[AAD_LEN])
{
    aad[0] = 'N';
    aad[1] = 'X';
    aad[2] = 'D';
    aad[3] = 'W';
    aad[4] = OPENPGP_STATE_O3_OBJ;
    aad[5] = OPENPGP_STATE_O3_SCHEMA;
    memcpy(&aad[6], pub, OPENPGP_DEC_PUB_LEN);
}

static bool tag_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= (uint8_t) (a[i] ^ b[i]);
    return d == 0u;
}

/* rec->pub set; fills nonce, ct, tag. */
static int seal(const uint8_t kek[PGP_DEC_KEY_LEN], const uint8_t priv[PGP_DEC_KEY_LEN],
                openpgp_dec_rec_t *rec)
{
    gcm_ctx ctx;
    uint8_t aad[AAD_LEN];
    int rc = PGP_DEC_ERR;
    aad_of(rec->pub, aad);
    memcpy(rec->ct, priv, OPENPGP_DEC_CT_LEN);
    if (tropic_random(rec->nonce, sizeof rec->nonce) == 0
        && gcm_init_and_key(kek, PGP_DEC_KEY_LEN, &ctx) == RETURN_GOOD
        && gcm_encrypt_message(rec->nonce, sizeof rec->nonce, aad, sizeof aad,
                               rec->ct, sizeof rec->ct, rec->tag, sizeof rec->tag,
                               &ctx) == RETURN_GOOD) {
        rc = PGP_DEC_OK;
    }
    memzero(&ctx, sizeof ctx);
    if (rc != PGP_DEC_OK) memzero(rec, sizeof *rec);
    return rc;
}

/* E10: pass 1 authenticates header + ciphertext only — gcm_compute_tag then
 * answers RETURN_WARN with a valid tag (no text was decrypted, Jan r2);
 * constant-time compare; pass 2 decrypts the same bytes with a fresh
 * message (CTR) initialisation, only after the match. */
static int open_wrap(const uint8_t kek[PGP_DEC_KEY_LEN], const openpgp_dec_rec_t *rec,
                     uint8_t priv[PGP_DEC_KEY_LEN])
{
    gcm_ctx ctx;
    uint8_t aad[AAD_LEN], tag[OPENPGP_DEC_TAG_LEN];
    int rc = PGP_DEC_ERR;
    ret_type t;
    memzero(priv, PGP_DEC_KEY_LEN);
    aad_of(rec->pub, aad);
    if (gcm_init_and_key(kek, PGP_DEC_KEY_LEN, &ctx) != RETURN_GOOD
        || gcm_init_message(rec->nonce, sizeof rec->nonce, &ctx) != RETURN_GOOD
        || gcm_auth_header(aad, sizeof aad, &ctx) != RETURN_GOOD
        || gcm_auth_data(rec->ct, sizeof rec->ct, &ctx) != RETURN_GOOD) {
        goto out;
    }
    t = gcm_compute_tag(tag, sizeof tag, &ctx);
    if (t != RETURN_WARN) goto out;              /* auth-only: the only valid answer */
    if (!tag_equal(tag, rec->tag, sizeof tag)) {
        rc = PGP_DEC_BAD_WRAP;
        goto out;
    }
    memcpy(priv, rec->ct, PGP_DEC_KEY_LEN);
    if (gcm_init_message(rec->nonce, sizeof rec->nonce, &ctx) == RETURN_GOOD
        && gcm_crypt_data(priv, PGP_DEC_KEY_LEN, &ctx) == RETURN_GOOD) {
        rc = PGP_DEC_OK;
    }
out:
    if (rc != PGP_DEC_OK) memzero(priv, PGP_DEC_KEY_LEN);
    memzero(&ctx, sizeof ctx);
    memzero(tag, sizeof tag);
    return rc;
}

int pgp_dec_generate(const uint8_t kek[PGP_DEC_KEY_LEN], uint8_t pub_out[PGP_DEC_KEY_LEN])
{
    uint8_t priv[PGP_DEC_KEY_LEN];
    openpgp_dec_rec_t rec;
    int rc = PGP_DEC_ERR;
    if (kek == NULL || pub_out == NULL) return PGP_DEC_BAD_PARAM;
    memzero(pub_out, PGP_DEC_KEY_LEN);
    if (tropic_random(priv, sizeof priv) == 0) {
        priv[0] &= 248u;              /* RFC 7748 §5 clamping */
        priv[31] &= 127u;
        priv[31] |= 64u;
        curve25519_scalarmult_basepoint(rec.pub, priv);
        if (seal(kek, priv, &rec) == PGP_DEC_OK && openpgp_state_dec_set(&rec) == 0) {
            memcpy(pub_out, rec.pub, PGP_DEC_KEY_LEN);
            rc = PGP_DEC_OK;
        }
    }
    memzero(priv, sizeof priv);
    memzero(&rec, sizeof rec);
    return rc;
}

int pgp_dec_read_pubkey(uint8_t pub_out[PGP_DEC_KEY_LEN])
{
    openpgp_dec_rec_t rec;
    if (pub_out == NULL) return PGP_DEC_BAD_PARAM;
    int rc = openpgp_state_dec_get(&rec) == 0 ? PGP_DEC_OK : PGP_DEC_NO_KEY;
    memcpy(pub_out, rec.pub, PGP_DEC_KEY_LEN);      /* zero when there is none */
    memzero(&rec, sizeof rec);
    return rc;
}

int pgp_dec_ecdh(const uint8_t kek[PGP_DEC_KEY_LEN], const uint8_t peer[PGP_DEC_KEY_LEN],
                 uint8_t shared_out[PGP_DEC_KEY_LEN])
{
    uint8_t priv[PGP_DEC_KEY_LEN];
    openpgp_dec_rec_t rec;
    int rc;
    if (shared_out == NULL) return PGP_DEC_BAD_PARAM;
    memzero(shared_out, PGP_DEC_KEY_LEN);                /* zero on every failure (Jan) */
    if (kek == NULL || peer == NULL) return PGP_DEC_BAD_PARAM;
    if (openpgp_state_dec_get(&rec) != 0) {
        rc = PGP_DEC_NO_KEY;
    } else {
        rc = open_wrap(kek, &rec, priv);
        if (rc == PGP_DEC_OK) curve25519_scalarmult(shared_out, priv, peer);
    }
    memzero(priv, sizeof priv);
    memzero(&rec, sizeof rec);
    return rc;
}
