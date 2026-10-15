/*
 * pinUvAuthToken state — see pin_token.h.
 */

#include "pin_token.h"

#include <string.h>

#include "hmac.h"
#include "memzero.h"

static uint8_t  s_token[PUAT_TOKEN_LEN];
static int      s_in_use;
static int      s_used;          /* verified at least once (initial timer stops) */
static int      s_uv;
static uint8_t  s_perms;
static int      s_has_rp;
static uint8_t  s_rp_hash[PUAT_RP_HASH_LEN];
static uint32_t s_issued_ms;
/* Bumped on every new token and every reset: lets stateful users (credMgmt
 * iterators) tell whether the token that authorised them still lives. */
static uint32_t s_generation;

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

void puat_reset(void)
{
    s_generation++;
    memzero(s_token, sizeof s_token);
    memset(s_rp_hash, 0, sizeof s_rp_hash);
    s_in_use = 0;
    s_used = 0;
    s_uv = 0;
    s_perms = 0;
    s_has_rp = 0;
    s_issued_ms = 0;
}

void puat_begin(const uint8_t token[PUAT_TOKEN_LEN], uint8_t perms,
                const uint8_t *rp_hash, uint32_t now_ms)
{
    puat_reset();
    memcpy(s_token, token, PUAT_TOKEN_LEN);
    s_perms = (uint8_t)(perms & PUAT_PERMS_KNOWN);
    if (rp_hash != NULL) {
        memcpy(s_rp_hash, rp_hash, PUAT_RP_HASH_LEN);
        s_has_rp = 1;
    }
    s_uv = 1;
    s_issued_ms = now_ms;
    s_in_use = 1;
    s_generation++;
}

/* Timer observer, run lazily before every use. */
static void expire(uint32_t now_ms)
{
    if (!s_in_use) return;
    uint32_t age = now_ms - s_issued_ms;      /* wraps correctly */
    if (age > PUAT_MAX_LIFE_MS || (!s_used && age > PUAT_INITIAL_USE_MS)) {
        puat_reset();
    }
}

int puat_verify(const uint8_t *param, size_t param_len,
                const uint8_t *msg, size_t msg_len, uint32_t now_ms)
{
    expire(now_ms);
    if (!s_in_use || param == NULL || param_len != PUAT_PARAM_LEN) return -1;
    if (msg == NULL && msg_len > 0u) return -1;

    uint8_t mac[32];
    hmac_sha256(s_token, PUAT_TOKEN_LEN, msg, (uint32_t) msg_len, mac);
    int ok = ct_equal(mac, param, PUAT_PARAM_LEN);
    memzero(mac, sizeof mac);
    if (!ok) return -1;
    s_used = 1;
    return 0;
}

int puat_in_use(uint32_t now_ms)
{
    expire(now_ms);
    return s_in_use;
}

uint32_t puat_generation(void)
{
    return s_generation;
}

const uint8_t *puat_token(void)
{
    return s_in_use ? s_token : NULL;
}

int puat_has_perm(uint8_t perm)
{
    return s_in_use && (s_perms & perm) == perm && perm != 0u;
}

int puat_user_verified(void)
{
    return s_in_use && s_uv;
}

int puat_has_rp(void)
{
    return s_in_use && s_has_rp;
}

int puat_rp_matches(const uint8_t rp_hash[PUAT_RP_HASH_LEN])
{
    if (!s_has_rp) return 1;
    return memcmp(s_rp_hash, rp_hash, PUAT_RP_HASH_LEN) == 0;
}

void puat_bind_rp(const uint8_t rp_hash[PUAT_RP_HASH_LEN])
{
    if (!s_in_use || s_has_rp) return;
    memcpy(s_rp_hash, rp_hash, PUAT_RP_HASH_LEN);
    s_has_rp = 1;
}

void puat_consume(void)
{
    if (!s_in_use) return;
    s_uv = 0;
    s_perms = 0;
}
