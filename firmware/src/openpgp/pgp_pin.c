/*
 * OpenPGP PIN handling.  See pgp_pin.h.
 *
 * Single shared session state — PW1 / PW3 / RC verified flags persist
 * until pgp_pin_clear_session() is called.
 */

#include "pgp_pin.h"
#include "openpgp_state.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sha2.h"     /* trezor_crypto SHA-256 */
#include "memzero.h"  /* trezor_crypto secure-zero */

/* Session state — RAM-only, lost on USB reset / power cycle. */
static uint8_t s_verified[OPENPGP_PIN_COUNT];

/* PIN length validation per OpenPGP card spec §4.3.  RC has no
 * separate minimum — uses PW3's minimum. */
static int pin_len_ok(int which, size_t len)
{
    if (len > OPENPGP_PIN_MAX_LEN) return 0;
    switch (which) {
    case OPENPGP_PIN_PW1: return (len >= OPENPGP_PW1_MIN_LEN);
    case OPENPGP_PIN_PW3: return (len >= OPENPGP_PW3_MIN_LEN);
    case OPENPGP_PIN_RC:  return (len >= OPENPGP_RC_MIN_LEN);
    default: return 0;
    }
}

static uint8_t initial_retries(int which)
{
    switch (which) {
    case OPENPGP_PIN_PW1: return OPENPGP_PW1_RETRIES_INITIAL;
    case OPENPGP_PIN_PW3: return OPENPGP_PW3_RETRIES_INITIAL;
    case OPENPGP_PIN_RC:  return OPENPGP_PW3_RETRIES_INITIAL;  /* spec: same as PW3 */
    default: return 0;
    }
}

void pgp_pin_hash(const uint8_t *pin, size_t len,
                  uint8_t out[OPENPGP_PIN_HASH_LEN])
{
    uint8_t full[32];
    sha256_Raw(pin, (uint32_t) len, full);
    memcpy(out, full, OPENPGP_PIN_HASH_LEN);
    memzero(full, sizeof full);
}

/* Constant-time compare. */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static uint8_t retries_get(int which)
{
    switch (which) {
    case OPENPGP_PIN_PW1: return openpgp_state_pw1_retries_get();
    case OPENPGP_PIN_PW3: return openpgp_state_pw3_retries_get();
    case OPENPGP_PIN_RC:  return openpgp_state_rc_retries_get();
    default: return 0;
    }
}

int pgp_pin_verify(int which, const uint8_t *pin, size_t len)
{
    if (which < 0 || which >= OPENPGP_PIN_COUNT) return PGP_PIN_BAD_LEN;
    if (pin == NULL) return PGP_PIN_BAD_LEN;
    if (!pin_len_ok(which, len)) return PGP_PIN_BAD_LEN;

    /* RC unset → can't verify against it. */
    if (which == OPENPGP_PIN_RC) {
        uint8_t r = openpgp_state_rc_retries_get();
        if (r == OPENPGP_RC_UNSET) return PGP_PIN_NOT_SET;
    }

    /* Retry counter exhausted? */
    uint8_t cur = retries_get(which);
    if (cur == 0u) return PGP_PIN_BLOCKED;

    /* Hash submitted PIN + constant-time compare. */
    uint8_t submitted[OPENPGP_PIN_HASH_LEN];
    pgp_pin_hash(pin, len, submitted);

    uint8_t stored[OPENPGP_PIN_HASH_LEN];
    int hg = openpgp_state_pin_hash_get(which, stored);
    if (hg != 0) {
        memzero(submitted, sizeof submitted);
        /* Map openpgp_state error code to a distinct PIN error so the
         * caller emits a distinct SW.  We get 1 HW iteration of clarity
         * out of this. */
        switch (hg) {
        case -3: return PGP_PIN_CHIP_ERR_READ_CHIP;
        case -4: return PGP_PIN_CHIP_ERR_READ_SHORT;
        case -1: return PGP_PIN_CHIP_ERR_READ_MAGIC;
        default: return PGP_PIN_CHIP_ERR_HASH_GET;
        }
    }

    int match = ct_eq(submitted, stored, OPENPGP_PIN_HASH_LEN);
    memzero(submitted, sizeof submitted);
    memzero(stored,    sizeof stored);

    if (match) {
        /* Reset counter + flag session-verified. */
        if (openpgp_state_pin_retries_set(which, initial_retries(which)) != 0) {
            return PGP_PIN_CHIP_ERR_RETRIES_MATCH;
        }
        s_verified[which] = 1;
        return PGP_PIN_OK;
    }

    /* Wrong — decrement counter, clear session flag for safety. */
    s_verified[which] = 0;
    uint8_t new_count = (uint8_t)(cur - 1u);
    if (openpgp_state_pin_retries_set(which, new_count) != 0) {
        return PGP_PIN_CHIP_ERR_RETRIES_BAD;
    }
    return (new_count == 0u) ? PGP_PIN_BLOCKED : PGP_PIN_BAD;
}

int pgp_pin_change(int which,
                   const uint8_t *old_pin, size_t old_len,
                   const uint8_t *new_pin, size_t new_len)
{
    if (which < 0 || which >= OPENPGP_PIN_COUNT) return PGP_PIN_BAD_LEN;
    if (!pin_len_ok(which, new_len)) return PGP_PIN_BAD_LEN;
    /* RC can be cleared by PUT DATA D3 of length 0; CHANGE doesn't
     * support that — use PUT DATA D3 separately. */

    int rc = pgp_pin_verify(which, old_pin, old_len);
    if (rc != PGP_PIN_OK) return rc;

    /* Hash + write new. */
    uint8_t new_hash[OPENPGP_PIN_HASH_LEN];
    pgp_pin_hash(new_pin, new_len, new_hash);
    int store_rc = openpgp_state_pin_hash_set(which, new_hash);
    memzero(new_hash, sizeof new_hash);

    if (store_rc != 0) return PGP_PIN_CHIP_ERR;
    /* M6 audit H2 — record new PIN length so the next CHANGE REF can
     * split at the canonical boundary without a search loop. */
    if (openpgp_state_pin_len_set(which, (uint8_t) new_len) != 0) {
        return PGP_PIN_CHIP_ERR;
    }
    /* Counter already reset by successful verify; session flag set too. */
    return PGP_PIN_OK;
}

int pgp_pin_reset_pw1_via_rc(const uint8_t *rc_bytes, size_t rc_len,
                             const uint8_t *new_pw1, size_t new_pw1_len)
{
    if (!pin_len_ok(OPENPGP_PIN_PW1, new_pw1_len)) return PGP_PIN_BAD_LEN;

    int rc = pgp_pin_verify(OPENPGP_PIN_RC, rc_bytes, rc_len);
    if (rc != PGP_PIN_OK) return rc;

    uint8_t new_hash[OPENPGP_PIN_HASH_LEN];
    pgp_pin_hash(new_pw1, new_pw1_len, new_hash);
    int store_rc = openpgp_state_pin_hash_set(OPENPGP_PIN_PW1, new_hash);
    memzero(new_hash, sizeof new_hash);
    if (store_rc != 0) return PGP_PIN_CHIP_ERR;

    /* M6 audit H2 — record new PW1 length. */
    if (openpgp_state_pin_len_set(OPENPGP_PIN_PW1, (uint8_t) new_pw1_len) != 0) {
        return PGP_PIN_CHIP_ERR;
    }
    if (openpgp_state_pin_retries_set(OPENPGP_PIN_PW1,
                                       OPENPGP_PW1_RETRIES_INITIAL) != 0) {
        return PGP_PIN_CHIP_ERR;
    }
    /* PW1 now usable; explicitly NOT auto-flagged as verified — user
     * still needs to VERIFY PW1 before signing. */
    s_verified[OPENPGP_PIN_PW1] = 0;
    return PGP_PIN_OK;
}

int pgp_pin_reset_pw1_via_pw3(const uint8_t *new_pw1, size_t new_pw1_len)
{
    if (!pin_len_ok(OPENPGP_PIN_PW1, new_pw1_len)) return PGP_PIN_BAD_LEN;
    if (!s_verified[OPENPGP_PIN_PW3]) return PGP_PIN_BAD;  /* SW_SECURITY_NOT_SATISFIED at caller */

    uint8_t new_hash[OPENPGP_PIN_HASH_LEN];
    pgp_pin_hash(new_pw1, new_pw1_len, new_hash);
    int store_rc = openpgp_state_pin_hash_set(OPENPGP_PIN_PW1, new_hash);
    memzero(new_hash, sizeof new_hash);
    if (store_rc != 0) return PGP_PIN_CHIP_ERR;

    /* M6 audit H2 — record new PW1 length. */
    if (openpgp_state_pin_len_set(OPENPGP_PIN_PW1, (uint8_t) new_pw1_len) != 0) {
        return PGP_PIN_CHIP_ERR;
    }
    if (openpgp_state_pin_retries_set(OPENPGP_PIN_PW1,
                                       OPENPGP_PW1_RETRIES_INITIAL) != 0) {
        return PGP_PIN_CHIP_ERR;
    }
    s_verified[OPENPGP_PIN_PW1] = 0;
    return PGP_PIN_OK;
}

int pgp_pin_set_rc(const uint8_t *rc_bytes, size_t rc_len)
{
    if (!s_verified[OPENPGP_PIN_PW3]) return PGP_PIN_BAD;

    if (rc_len == 0u) {
        /* Clear RC — hash region zeroed, counter set to UNSET. */
        uint8_t zero[OPENPGP_PIN_HASH_LEN] = {0};
        if (openpgp_state_pin_hash_set(OPENPGP_PIN_RC, zero) != 0) {
            return PGP_PIN_CHIP_ERR;
        }
        if (openpgp_state_pin_retries_set(OPENPGP_PIN_RC,
                                          OPENPGP_RC_UNSET) != 0) {
            return PGP_PIN_CHIP_ERR;
        }
        /* M6 audit H2 — RC length 0 = unset sentinel. */
        if (openpgp_state_pin_len_set(OPENPGP_PIN_RC, 0u) != 0) {
            return PGP_PIN_CHIP_ERR;
        }
        return PGP_PIN_OK;
    }

    if (!pin_len_ok(OPENPGP_PIN_RC, rc_len)) return PGP_PIN_BAD_LEN;

    uint8_t new_hash[OPENPGP_PIN_HASH_LEN];
    pgp_pin_hash(rc_bytes, rc_len, new_hash);
    int store_rc = openpgp_state_pin_hash_set(OPENPGP_PIN_RC, new_hash);
    memzero(new_hash, sizeof new_hash);
    if (store_rc != 0) return PGP_PIN_CHIP_ERR;

    /* M6 audit H2 — record new RC length. */
    if (openpgp_state_pin_len_set(OPENPGP_PIN_RC, (uint8_t) rc_len) != 0) {
        return PGP_PIN_CHIP_ERR;
    }
    if (openpgp_state_pin_retries_set(OPENPGP_PIN_RC,
                                       OPENPGP_PW3_RETRIES_INITIAL) != 0) {
        return PGP_PIN_CHIP_ERR;
    }
    return PGP_PIN_OK;
}

int pgp_pin_is_verified(int which)
{
    if (which < 0 || which >= OPENPGP_PIN_COUNT) return 0;
    return s_verified[which] ? 1 : 0;
}

void pgp_pin_clear_session(void)
{
    memzero(s_verified, sizeof s_verified);
}
