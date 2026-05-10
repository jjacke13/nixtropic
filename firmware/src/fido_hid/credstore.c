/*
 * Stub credential store — fixed Ed25519 keypair derived from a hardcoded
 * seed. Phase 5 replaces with TROPIC01 ECC slots. See credstore.h for
 * the safety caveat.
 *
 * Uses trezor_crypto's ed25519-donna directly (already linked in
 * via Phase 3 M4's L3 secure-session work).
 */

#include "credstore.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "ed25519-donna/ed25519.h"

/* 32-byte Ed25519 seed. The bytes spell "nixtropic stub seed v1" + nul
 * padding so this is easily recognizable in firmware dumps. NOT secret:
 * publicly embedded in the binary. */
static const uint8_t STUB_SEED[32] = {
    'n','i','x','t','r','o','p','i',
    'c',' ','s','t','u','b',' ','s',
    'e','e','d',' ','v','1', 0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
};

/* Fixed 32-byte credential ID. Also recognizable. */
static const uint8_t STUB_CRED_ID[CREDSTORE_CRED_ID_LEN] = {
    'n','i','x','t','r','o','p','i',
    'c','-','c','r','e','d','-','v',
    '1', 0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  1,
};

static uint8_t  s_pubkey[CREDSTORE_PUBKEY_LEN];
static int      s_initted;
static uint32_t s_signcount;

void credstore_init(void)
{
    if (s_initted) return;
    /* ed25519_publickey derives the public key from the secret (seed). */
    ed25519_publickey(STUB_SEED, s_pubkey);
    s_signcount = 0;
    s_initted = 1;
}

const uint8_t *credstore_pubkey(void)
{
    if (!s_initted) credstore_init();
    return s_pubkey;
}

const uint8_t *credstore_cred_id(void)
{
    return STUB_CRED_ID;
}

void credstore_sign(const uint8_t *msg, size_t msg_len, uint8_t *sig_out)
{
    if (!s_initted) credstore_init();
    /* trezor_crypto ed25519_sign signature: (m, mlen, sk, sig).
     * 4 args — no separate public-key parameter. */
    ed25519_sign(msg, msg_len, STUB_SEED, sig_out);
}

uint32_t credstore_peek_signcount(void)
{
    return s_signcount + 1u;
}

void credstore_commit_signcount(void)
{
    s_signcount++;
}
