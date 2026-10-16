/*
 * OpenPGP persistent state O3 on a record pair.  See openpgp_state.h.
 */
#include "openpgp_state.h"

#include <stdbool.h>
#include <string.h>

#include "memzero.h"
#include "tropic/rec_pair.h"

#define O3_SLOT_A   33u
#define O3_SLOT_B   43u
#define O3_OBJ       3u
#define O3_SCHEMA    1u

#define OFF_LC          0u
#define OFF_RC_SET      1u
#define OFF_C4          2u
#define OFF_UIF         3u
#define OFF_NAME_LEN    4u
#define OFF_NAME        5u
#define OFF_LANG       44u
#define OFF_SEX        46u
#define OFF_FPR        47u
#define OFF_GENTIME   107u
#define OFF_SIGCNT    119u
#define OFF_DEC       122u
#define O3_LEN        154u

_Static_assert(OFF_NAME + OPENPGP_NAME_MAX == OFF_LANG, "O3 layout");
_Static_assert(OFF_DEC + OPENPGP_DEC_PRIV_LEN == O3_LEN, "O3 layout");
_Static_assert(O3_LEN <= REC_PAYLOAD_MAX, "O3 fits a record");

#define SEX_NA  0x39u   /* ISO 5218 "not applicable" */

static rec_pair_t s_o3 = REC_PAIR(O3_SLOT_A, O3_SLOT_B, O3_OBJ, O3_SCHEMA);
static uint8_t    s_cur[O3_LEN];   /* the committed record, valid while s_loaded */
static bool       s_loaded;

static bool usable(void)
{
    return s_loaded && !s_o3.uncertain;
}

static bool sex_ok(uint8_t v)
{
    return v == 0x31u || v == 0x32u || v == SEX_NA;
}

/* Out-of-range fields are damage, never a state. */
static bool fields_ok(const uint8_t *b)
{
    return (b[OFF_LC] == PGP_LC_OPERATIONAL || b[OFF_LC] == PGP_LC_TERMINATED)
        && b[OFF_RC_SET] <= 1u && b[OFF_C4] <= 1u && b[OFF_UIF] <= 2u
        && b[OFF_NAME_LEN] <= OPENPGP_NAME_MAX
        && (b[OFF_LC] == PGP_LC_TERMINATED || sex_ok(b[OFF_SEX]));
}

static void defaults(uint8_t out[O3_LEN], pgp_lifecycle_t lc)
{
    memset(out, 0, O3_LEN);
    out[OFF_LC] = (uint8_t) lc;
    if (lc != PGP_LC_OPERATIONAL) return;
    out[OFF_C4] = 1u;               /* PIN once per plug-in (D9) */
    out[OFF_UIF] = 1u;              /* touch for every key operation */
    out[OFF_LANG] = 'e';
    out[OFF_LANG + 1] = 'n';
    out[OFF_SEX] = SEX_NA;
}

/* Commit `next` (both copies), then take it into RAM. */
static int commit(uint8_t next[O3_LEN])
{
    int rc = -1;
    if (usable() && s_cur[OFF_LC] == PGP_LC_OPERATIONAL
        && rec_pair_write(&s_o3, next, O3_LEN) == REC_OK) {
        memcpy(s_cur, next, O3_LEN);
        rc = 0;
    }
    memzero(next, O3_LEN);
    return rc;
}

/* A copy of the committed state to edit. */
static void edit(uint8_t next[O3_LEN])
{
    memcpy(next, s_cur, O3_LEN);
}

int openpgp_state_load(void)
{
    uint8_t buf[REC_PAYLOAD_MAX];
    size_t n = 0;
    int rc = -1;
    s_loaded = false;
    rec_status_t st = rec_pair_read(&s_o3, buf, sizeof buf, &n, NULL);
    if (st == REC_ABSENT) {
        rc = 1;
    } else if (st == REC_OK && n == O3_LEN && fields_ok(buf)) {
        memcpy(s_cur, buf, O3_LEN);
        s_loaded = true;
        rc = 0;
    }
    memzero(buf, sizeof buf);
    return rc;
}

pgp_lifecycle_t openpgp_state_lifecycle(void)
{
    return usable() ? (pgp_lifecycle_t) s_cur[OFF_LC] : PGP_LC_ERROR;
}

int openpgp_state_loaded(void)
{
    return s_loaded;
}

int openpgp_state_clear(void)
{
    s_loaded = false;
    memzero(s_cur, sizeof s_cur);
    s_o3.uncertain = false;   /* checked erase: the way out (design §6) */
    return rec_pair_clear(&s_o3) == REC_OK ? 0 : -1;
}

int openpgp_state_init(pgp_lifecycle_t lc)
{
    uint8_t buf[O3_LEN];
    int rc = -1;
    s_loaded = false;
    s_o3.uncertain = false;
    defaults(buf, lc);
    if (lc != PGP_LC_ERROR && rec_pair_init(&s_o3, buf, O3_LEN) == REC_OK) {
        memcpy(s_cur, buf, O3_LEN);
        s_loaded = true;
        rc = 0;
    }
    memzero(buf, sizeof buf);
    return rc;
}

int openpgp_state_activate(void)
{
    uint8_t buf[O3_LEN];
    int rc = -1;
    defaults(buf, PGP_LC_OPERATIONAL);
    if (usable() && s_cur[OFF_LC] == PGP_LC_TERMINATED
        && rec_pair_write(&s_o3, buf, O3_LEN) == REC_OK) {
        memcpy(s_cur, buf, O3_LEN);
        rc = 0;
    }
    memzero(buf, sizeof buf);
    return rc;
}

/* ---- getters ---- */

static uint8_t byte_at(size_t off)
{
    return usable() ? s_cur[off] : 0u;
}

static void copy_out(uint8_t *out, size_t off, size_t len)
{
    if (usable()) memcpy(out, &s_cur[off], len);
    else memset(out, 0, len);
}

static bool key_ok(int key)
{
    return key >= 0 && key <= 2;
}

uint8_t openpgp_state_rc_set(void)  { return byte_at(OFF_RC_SET); }
uint8_t openpgp_state_c4_multi(void) { return byte_at(OFF_C4); }

uint8_t openpgp_state_uif(void)
{
    return usable() ? s_cur[OFF_UIF] : 1u;      /* unknown: the stricter policy */
}

size_t openpgp_state_name(uint8_t out[OPENPGP_NAME_MAX])
{
    size_t n = byte_at(OFF_NAME_LEN);
    copy_out(out, OFF_NAME, n);
    return n;
}

void openpgp_state_lang(uint8_t out[OPENPGP_LANG_LEN])
{
    copy_out(out, OFF_LANG, OPENPGP_LANG_LEN);
}

uint8_t openpgp_state_sex(void)
{
    return usable() ? s_cur[OFF_SEX] : SEX_NA;
}

void openpgp_state_fingerprint(int key, uint8_t out[OPENPGP_FPR_LEN])
{
    if (!key_ok(key)) { memset(out, 0, OPENPGP_FPR_LEN); return; }
    copy_out(out, OFF_FPR + (size_t) key * OPENPGP_FPR_LEN, OPENPGP_FPR_LEN);
}

void openpgp_state_gentime(int key, uint8_t out[OPENPGP_GENTIME_LEN])
{
    if (!key_ok(key)) { memset(out, 0, OPENPGP_GENTIME_LEN); return; }
    copy_out(out, OFF_GENTIME + (size_t) key * OPENPGP_GENTIME_LEN, OPENPGP_GENTIME_LEN);
}

void openpgp_state_sig_counter(uint8_t out[OPENPGP_SIG_COUNTER_LEN])
{
    copy_out(out, OFF_SIGCNT, OPENPGP_SIG_COUNTER_LEN);
}

int openpgp_state_dec_priv_get(uint8_t out[OPENPGP_DEC_PRIV_LEN])
{
    static const uint8_t zero[OPENPGP_DEC_PRIV_LEN];
    copy_out(out, OFF_DEC, OPENPGP_DEC_PRIV_LEN);
    if (!usable() || memcmp(out, zero, OPENPGP_DEC_PRIV_LEN) == 0) {
        memzero(out, OPENPGP_DEC_PRIV_LEN);
        return -1;
    }
    return 0;
}

/* ---- setters ---- */

static int set_byte(size_t off, uint8_t v)
{
    uint8_t next[O3_LEN];
    edit(next);
    next[off] = v;
    return commit(next);
}

static int set_bytes(size_t off, const uint8_t *v, size_t len)
{
    uint8_t next[O3_LEN];
    edit(next);
    memcpy(&next[off], v, len);
    return commit(next);
}

int openpgp_state_set_rc_set(uint8_t v)
{
    return v <= 1u ? set_byte(OFF_RC_SET, v) : -1;
}

int openpgp_state_set_c4_multi(uint8_t v)
{
    return v <= 1u ? set_byte(OFF_C4, v) : -1;
}

int openpgp_state_set_uif(uint8_t v)
{
    if (v > 2u) return -1;
    if (usable() && s_cur[OFF_UIF] == 2u && v != 2u) return -3;   /* only TERMINATE clears it */
    return set_byte(OFF_UIF, v);
}

int openpgp_state_set_name(const uint8_t *data, size_t len)
{
    uint8_t next[O3_LEN];
    if (len > OPENPGP_NAME_MAX || (len > 0u && data == NULL)) return -1;
    edit(next);
    next[OFF_NAME_LEN] = (uint8_t) len;
    memset(&next[OFF_NAME], 0, OPENPGP_NAME_MAX);
    if (len > 0u) memcpy(&next[OFF_NAME], data, len);
    return commit(next);
}

int openpgp_state_set_lang(const uint8_t data[OPENPGP_LANG_LEN])
{
    return data != NULL ? set_bytes(OFF_LANG, data, OPENPGP_LANG_LEN) : -1;
}

int openpgp_state_set_sex(uint8_t v)
{
    return sex_ok(v) ? set_byte(OFF_SEX, v) : -1;
}

int openpgp_state_set_fingerprint(int key, const uint8_t fpr[OPENPGP_FPR_LEN])
{
    if (!key_ok(key) || fpr == NULL) return -1;
    return set_bytes(OFF_FPR + (size_t) key * OPENPGP_FPR_LEN, fpr, OPENPGP_FPR_LEN);
}

int openpgp_state_set_gentime(int key, const uint8_t gt[OPENPGP_GENTIME_LEN])
{
    if (!key_ok(key) || gt == NULL) return -1;
    return set_bytes(OFF_GENTIME + (size_t) key * OPENPGP_GENTIME_LEN, gt, OPENPGP_GENTIME_LEN);
}

/* DO 93: a 24-bit big-endian count (spec §4.4.3.2), wraps to 0. */
int openpgp_state_sig_counter_increment(void)
{
    uint8_t next[O3_LEN];
    edit(next);
    uint32_t c = ((uint32_t) next[OFF_SIGCNT] << 16) | ((uint32_t) next[OFF_SIGCNT + 1] << 8)
               | next[OFF_SIGCNT + 2];
    c = (c + 1u) & 0x00FFFFFFu;
    next[OFF_SIGCNT] = (uint8_t) (c >> 16);
    next[OFF_SIGCNT + 1] = (uint8_t) (c >> 8);
    next[OFF_SIGCNT + 2] = (uint8_t) c;
    return commit(next);
}

int openpgp_state_dec_priv_set(const uint8_t key[OPENPGP_DEC_PRIV_LEN])
{
    return key != NULL ? set_bytes(OFF_DEC, key, OPENPGP_DEC_PRIV_LEN) : -1;
}

#ifdef NIXTROPIC_HOST_TEST
void openpgp_state_test_reboot(void)
{
    s_loaded = false;
    memzero(s_cur, sizeof s_cur);
    s_o3.uncertain = false;
}
#endif
