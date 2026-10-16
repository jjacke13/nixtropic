/*
 * OpenPGP PINs on the M&D kernel v2.  See pgp_pin.h.
 */
#include "pgp_pin.h"
#include "openpgp_state.h"

#include <stdbool.h>
#include <string.h>

#include "memzero.h"
#include "sha2.h"
#include "tropic/pin_md_kernel.h"
#include "tropic/rec_pair.h"

#define MAT_LEN  32u

static rec_pair_t s_o4 = REC_PAIR(50, 53, 4, 1);
static rec_pair_t s_o5 = REC_PAIR(51, 54, 5, 1);
static rec_pair_t s_o6 = REC_PAIR(52, 55, 6, 1);

static const pin_md_layout_t LAYOUT[3] = {
    [OPENPGP_PIN_PW1] = { .rec = &s_o4, .base = { 16, 19 }, .ranges = 2,
                          .rounds = OPENPGP_PIN_ROUNDS, .mat_len = MAT_LEN },
    [OPENPGP_PIN_PW3] = { .rec = &s_o5, .base = { 22, 25 }, .ranges = 2,
                          .rounds = OPENPGP_PIN_ROUNDS, .mat_len = MAT_LEN },
    [OPENPGP_PIN_RC]  = { .rec = &s_o6, .base = { 28, 0 }, .ranges = 1,
                          .rounds = OPENPGP_PIN_ROUNDS, .mat_len = MAT_LEN },
};

_Static_assert(MAT_LEN <= PIN_MD_KERNEL_MATERIAL_MAX, "PIN material");

static const char FACTORY_PW1[] = "123456";
static const char FACTORY_PW3[] = "12345678";

static bool which_ok(int which)
{
    return which >= OPENPGP_PIN_PW1 && which <= OPENPGP_PIN_RC;
}

static size_t min_len(int which)
{
    return which == OPENPGP_PIN_PW1 ? OPENPGP_PW1_MIN_LEN
         : which == OPENPGP_PIN_PW3 ? OPENPGP_PW3_MIN_LEN : OPENPGP_RC_MIN_LEN;
}

static bool len_ok(int which, const uint8_t *pin, size_t len)
{
    return pin != NULL && len >= min_len(which) && len <= OPENPGP_PIN_MAX_LEN;
}

static void material(const uint8_t *pin, size_t len, uint8_t out[MAT_LEN])
{
    sha256_Raw(pin, (uint32_t) len, out);
}

pgp_pin_state_t pgp_pin_status(int which, uint8_t *attempts, uint8_t *pin_len)
{
    uint8_t att = 0, plen = 0;
    pgp_pin_state_t res = PGP_PIN_ERROR;
    if (attempts != NULL) *attempts = 0;
    if (pin_len != NULL) *pin_len = 0;
    if (!which_ok(which)) return PGP_PIN_ERROR;
    pgp_lifecycle_t lc = openpgp_state_lifecycle();
    if (which == OPENPGP_PIN_RC) {
        if (lc != PGP_LC_OPERATIONAL) return PGP_PIN_ERROR;
        if (openpgp_state_rc_set() == 0u) return PGP_PIN_NOT_SET;   /* O6 ignored */
    }
    switch (pin_md_kernel_status(&LAYOUT[which], &att, &plen)) {
    case PMD_ACTIVE:  res = PGP_PIN_ACTIVE; break;
    case PMD_BLOCKED: res = PGP_PIN_BLOCKED; break;
    case PMD_ABSENT:
        /* The guard decides (§2.5): only a TERMINATED card has no PW1/PW3;
         * an RC under rc_set 1, or a state that cannot be read, is ERROR. */
        res = (which != OPENPGP_PIN_RC && lc == PGP_LC_TERMINATED) ? PGP_PIN_NOT_SET
                                                                   : PGP_PIN_ERROR;
        break;
    default:          res = PGP_PIN_ERROR; break;
    }
    if (res == PGP_PIN_ACTIVE || res == PGP_PIN_BLOCKED) {
        if (attempts != NULL) *attempts = att;
        if (pin_len != NULL) *pin_len = plen;
    }
    return res;
}

static int map_rc(int rc, int correct)
{
    if (rc == PMD_OK) return correct ? PGP_PIN_OK : PGP_PIN_WRONG;
    return rc == PMD_ERR_BLOCKED ? PGP_PIN_BLK : PGP_PIN_ERR;
}

int pgp_pin_verify(int which, const uint8_t *pin, size_t len)
{
    uint8_t mat[MAT_LEN];
    int correct = 0;
    if (!which_ok(which) || !len_ok(which, pin, len)) return PGP_PIN_BAD_LEN;
    if (which == OPENPGP_PIN_RC) {
        if (openpgp_state_lifecycle() != PGP_LC_OPERATIONAL) return PGP_PIN_ERR;
        if (openpgp_state_rc_set() == 0u) return PGP_PIN_UNSET;
    }
    /* The kernel refuses BLOCKED and ABSENT itself; ABSENT maps to ERR (a
     * guard says the PIN exists: only a TERMINATED card has none, and the
     * applet serves no VERIFY there). */
    material(pin, len, mat);
    int rc = pin_md_kernel_verify(&LAYOUT[which], mat, &correct, NULL);
    memzero(mat, sizeof mat);
    return map_rc(rc, correct);
}

int pgp_pin_change(int which, const uint8_t *old_pin, size_t old_len,
                   const uint8_t *new_pin, size_t new_len)
{
    uint8_t a[MAT_LEN], b[MAT_LEN];
    int correct = 0;
    if (which != OPENPGP_PIN_PW1 && which != OPENPGP_PIN_PW3) return PGP_PIN_ERR;
    if (!len_ok(which, old_pin, old_len) || !len_ok(which, new_pin, new_len)) {
        return PGP_PIN_BAD_LEN;
    }
    material(old_pin, old_len, a);
    material(new_pin, new_len, b);
    int rc = pin_md_kernel_change(&LAYOUT[which], a, b, (uint8_t) new_len, &correct, NULL);
    memzero(a, sizeof a);
    memzero(b, sizeof b);
    return map_rc(rc, correct);
}

static int bind(int which, const uint8_t *pin, size_t len)
{
    uint8_t mat[MAT_LEN];
    material(pin, len, mat);
    int rc = pin_md_kernel_setup(&LAYOUT[which], mat, (uint8_t) len, NULL);
    memzero(mat, sizeof mat);
    return rc == PMD_OK ? PGP_PIN_OK : PGP_PIN_ERR;
}

int pgp_pin_reset_pw1(const uint8_t *pin, size_t len)
{
    if (!len_ok(OPENPGP_PIN_PW1, pin, len)) return PGP_PIN_BAD_LEN;
    if (openpgp_state_lifecycle() != PGP_LC_OPERATIONAL) return PGP_PIN_ERR;
    return bind(OPENPGP_PIN_PW1, pin, len);
}

int pgp_pin_set_rc(const uint8_t *rc, size_t len)
{
    if (len != 0u && !len_ok(OPENPGP_PIN_RC, rc, len)) return PGP_PIN_BAD_LEN;
    if (openpgp_state_lifecycle() != PGP_LC_OPERATIONAL) return PGP_PIN_ERR;
    /* Clear first: one range, so setup never re-keys a live binding (§3.3).
     * The clear needs no record, so it is also the way out of an uncertain
     * or damaged O6.  Guard cleared after the object, set after it. */
    s_o6.uncertain = false;
    if (pin_md_kernel_clear(&LAYOUT[OPENPGP_PIN_RC]) != PMD_OK) return PGP_PIN_ERR;
    if (openpgp_state_rc_set() != 0u && openpgp_state_set_rc_set(0) != 0) return PGP_PIN_ERR;
    if (len == 0u) return PGP_PIN_OK;
    if (bind(OPENPGP_PIN_RC, rc, len) != PGP_PIN_OK) return PGP_PIN_ERR;
    return openpgp_state_set_rc_set(1) == 0 ? PGP_PIN_OK : PGP_PIN_ERR;
}

int pgp_pin_bind_factory(void)
{
    if (bind(OPENPGP_PIN_PW1, (const uint8_t *) FACTORY_PW1, sizeof FACTORY_PW1 - 1u) != 0) {
        return PGP_PIN_ERR;
    }
    return bind(OPENPGP_PIN_PW3, (const uint8_t *) FACTORY_PW3, sizeof FACTORY_PW3 - 1u);
}

int pgp_pin_clear_all(void)
{
    for (int w = OPENPGP_PIN_PW1; w <= OPENPGP_PIN_RC; ++w) {
        LAYOUT[w].rec->uncertain = false;    /* checked retire + erase, needs no record */
        if (pin_md_kernel_clear(&LAYOUT[w]) != PMD_OK) return PGP_PIN_ERR;
    }
    return PGP_PIN_OK;
}

#ifdef NIXTROPIC_HOST_TEST
void pgp_pin_test_reboot(void)
{
    s_o4.uncertain = false;
    s_o5.uncertain = false;
    s_o6.uncertain = false;
}
#endif
