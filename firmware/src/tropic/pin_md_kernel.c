/*
 * MAC-and-Destroy PIN kernel v2.  See pin_md_kernel.h and
 * docs/history/PHASE-9-M4-DESIGN.md §3.
 *
 * Binding record payload (§3.1):
 *   range u8 | retire_pending u8 | next_slot u8 | pin_len u8 | tag[32] | ci[rounds][32]
 */
#include "tropic/pin_md_kernel.h"

#include <stdbool.h>
#include <string.h>

#include "hmac.h"
#include "memzero.h"
#include "tropic/tropic.h"

#define SZ        PIN_MD_KERNEL_SLOT_SIZE
#define BIND_HDR  4u
#define BIND_LEN(rounds) (BIND_HDR + PIN_MD_KERNEL_TAG_LEN + (size_t) (rounds) * SZ)

_Static_assert(BIND_LEN(PIN_MD_KERNEL_ROUNDS_MAX) <= REC_PAYLOAD_MAX,
               "binding record must fit a rec_pair record");

typedef struct {
    uint8_t range;
    uint8_t retire_pending;
    uint8_t next;
    uint8_t pin_len;
    uint8_t tag[PIN_MD_KERNEL_TAG_LEN];
    uint8_t ci[PIN_MD_KERNEL_ROUNDS_MAX][SZ];
} binding_t;

/* ----- helpers ----- */

static bool valid_layout(const pin_md_layout_t *L)
{
    if (L == NULL || L->rec == NULL) return false;
    if (L->rounds == 0u || L->rounds > PIN_MD_KERNEL_ROUNDS_MAX) return false;
    if (L->ranges != 1u && L->ranges != 2u) return false;
    if (L->mat_len == 0u || L->mat_len > PIN_MD_KERNEL_MATERIAL_MAX) return false;
    for (uint8_t r = 0; r < L->ranges; ++r) {
        if ((unsigned) L->base[r] + L->rounds > 128u) return false;   /* M&D slots 0..127 */
    }
    /* Overlapping A/B would let a retirement destroy the live range. */
    if (L->ranges == 2u && L->base[0] < L->base[1] + L->rounds
        && L->base[1] < L->base[0] + L->rounds) {
        return false;
    }
    return true;
}

/* out = HMAC(key, msg); key and msg 32 B / one byte as the scheme needs. */
static void kdf(const uint8_t s[32], uint8_t label, uint8_t out[32])
{
    hmac_sha256(s, 32, &label, 1, out);
}

static void pin_v(const pin_md_layout_t *L, const uint8_t *mat, uint8_t v[32])
{
    static const uint8_t zeros[32];
    hmac_sha256(zeros, sizeof zeros, mat, L->mat_len, v);
}

/* k_i = HMAC(w_i, mat); out = a XOR k_i (ci from s, or s from ci). */
static void slot_xor(const pin_md_layout_t *L, const uint8_t w[32], const uint8_t *mat,
                     const uint8_t a[32], uint8_t out[32])
{
    uint8_t k_i[32];
    hmac_sha256(w, 32, mat, L->mat_len, k_i);
    for (size_t i = 0; i < 32u; ++i) out[i] = (uint8_t) (a[i] ^ k_i[i]);
    memzero(k_i, sizeof k_i);
}

static bool tag_equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < PIN_MD_KERNEL_TAG_LEN; ++i) diff |= (uint8_t) (a[i] ^ b[i]);
    return diff == 0u;
}

static uint8_t md_slot(const pin_md_layout_t *L, uint8_t range, uint8_t i)
{
    return (uint8_t) (L->base[range] + i);
}

/* ----- the record ----- */

/* REC_OK with *b filled, or REC_ABSENT / REC_ERROR (damaged or out-of-range
 * fields count as ERROR: never a binding). */
static rec_status_t load(const pin_md_layout_t *L, binding_t *b)
{
    uint8_t buf[REC_PAYLOAD_MAX];
    size_t n = 0;
    rec_status_t st = rec_pair_read(L->rec, buf, sizeof buf, &n, NULL);
    if (st == REC_CORRUPT) st = REC_ERROR;
    if (st == REC_OK) {
        bool ok = n == BIND_LEN(L->rounds) && buf[0] < L->ranges && buf[1] <= 1u
               && (buf[1] == 0u || L->ranges == 2u) && buf[2] <= L->rounds;
        if (ok) {
            b->range = buf[0];
            b->retire_pending = buf[1];
            b->next = buf[2];
            b->pin_len = buf[3];
            memcpy(b->tag, buf + BIND_HDR, PIN_MD_KERNEL_TAG_LEN);
            memcpy(b->ci, buf + BIND_HDR + PIN_MD_KERNEL_TAG_LEN, (size_t) L->rounds * SZ);
        } else {
            st = REC_ERROR;
        }
    }
    memzero(buf, sizeof buf);
    return st;
}

/* Commit *b in both copies: init for a first binding, else a pair write. */
static int store(const pin_md_layout_t *L, const binding_t *b, bool first)
{
    uint8_t buf[REC_PAYLOAD_MAX];
    size_t n = BIND_LEN(L->rounds);
    buf[0] = b->range;
    buf[1] = b->retire_pending;
    buf[2] = b->next;
    buf[3] = b->pin_len;
    memcpy(buf + BIND_HDR, b->tag, PIN_MD_KERNEL_TAG_LEN);
    memcpy(buf + BIND_HDR + PIN_MD_KERNEL_TAG_LEN, b->ci, (size_t) L->rounds * SZ);
    rec_status_t st = first ? rec_pair_init(L->rec, buf, n) : rec_pair_write(L->rec, buf, n);
    memzero(buf, sizeof buf);
    return st == REC_OK ? PMD_OK : PMD_ERR;
}

/* One checked M&D call with fresh random data per slot [J2a]. */
static int retire(const pin_md_layout_t *L, uint8_t range)
{
    uint8_t rnd[32], out[32];
    int rc = PMD_OK;
    for (uint8_t i = 0; i < L->rounds && rc == PMD_OK; ++i) {
        if (tropic_random(rnd, sizeof rnd) != 0
            || tropic_mac_and_destroy(md_slot(L, range, i), rnd, out) != 0) {
            rc = PMD_ERR;
        }
    }
    memzero(rnd, sizeof rnd);
    memzero(out, sizeof out);
    return rc;
}

/* Load the binding and finish a pending retirement (§3.4).  A failed or
 * lost M&D reply leaves retire_pending set: never marked done on a guess. */
static rec_status_t settle(const pin_md_layout_t *L, binding_t *b)
{
    rec_status_t st = load(L, b);
    if (st != REC_OK || b->retire_pending == 0u) return st;
    if (retire(L, (uint8_t) (1u - b->range)) != PMD_OK) return REC_ERROR;
    b->retire_pending = 0;
    return store(L, b, false) == PMD_OK ? REC_OK : REC_ERROR;
}

/* ----- the scheme, with s inside ----- */

/* §3.3 setup(mat, s): write the free range, commit, retire the old one. */
static int setup_s(const pin_md_layout_t *L, const uint8_t *mat, uint8_t pin_len,
                   const uint8_t s[32])
{
    binding_t cur, nb;
    uint8_t u[32], v[32], w[32], ignore[32];
    int rc = PMD_ERR;
    rec_status_t st = settle(L, &cur);
    bool have = st == REC_OK;
    if ((st != REC_OK && st != REC_ABSENT) || (have && L->ranges < 2u)) goto out;

    memset(&nb, 0, sizeof nb);
    nb.range = have ? (uint8_t) (1u - cur.range) : 0u;
    nb.retire_pending = have ? 1u : 0u;
    nb.pin_len = pin_len;
    kdf(s, 0x00, nb.tag);
    kdf(s, 0x01, u);
    pin_v(L, mat, v);
    for (uint8_t i = 0; i < L->rounds; ++i) {
        uint8_t slot = md_slot(L, nb.range, i);
        if (tropic_mac_and_destroy(slot, u, ignore) != 0
            || tropic_mac_and_destroy(slot, v, w) != 0
            || tropic_mac_and_destroy(slot, u, ignore) != 0) {
            goto out;
        }
        slot_xor(L, w, mat, s, nb.ci[i]);
    }
    if (store(L, &nb, !have) != PMD_OK) goto out;        /* the commit */
    /* From here the new PIN is live.  Success (and k) only once the old
     * range is retired and that is recorded: until then a copied old record
     * plus the old PIN still opens s (§3.3 step 4, §3.4).  A failure here
     * returns PMD_ERR with the new binding live and retire_pending set —
     * never rolled back; the next call's settle finishes the retirement. */
    if (have) {
        if (retire(L, cur.range) != PMD_OK) goto out;
        nb.retire_pending = 0;
        if (store(L, &nb, false) != PMD_OK) goto out;
    }
    rc = PMD_OK;
out:
    memzero(&cur, sizeof cur);
    memzero(&nb, sizeof nb);
    memzero(u, sizeof u);
    memzero(v, sizeof v);
    memzero(w, sizeof w);
    memzero(ignore, sizeof ignore);
    return rc;
}

/* §3.3 verify(mat): reserve, one M&D, compare; right → restore, next 0.
 * On a right PIN, s goes to s_out. */
static int verify_s(const pin_md_layout_t *L, const uint8_t *mat, int *correct,
                    uint8_t s_out[32])
{
    binding_t b;
    uint8_t v[32], w[32], s[32], t[32], u[32], ignore[32], idx;
    int rc = PMD_ERR;
    *correct = 0;
    rec_status_t st = settle(L, &b);
    if (st == REC_ABSENT) { rc = PMD_ERR_ABSENT; goto out; }
    if (st != REC_OK) goto out;
    if (b.next >= L->rounds) { rc = PMD_ERR_BLOCKED; goto out; }

    idx = b.next;
    b.next = (uint8_t) (idx + 1u);
    if (store(L, &b, false) != PMD_OK) goto out;          /* reserve before the M&D call */

    pin_v(L, mat, v);
    if (tropic_mac_and_destroy(md_slot(L, b.range, idx), v, w) != 0) goto out;
    slot_xor(L, w, mat, b.ci[idx], s);
    kdf(s, 0x00, t);
    if (!tag_equal(t, b.tag)) { rc = PMD_OK; goto out; }  /* wrong: the attempt is spent */

    kdf(s, 0x01, u);
    for (uint8_t i = 0; i < L->rounds; ++i) {
        if (tropic_mac_and_destroy(md_slot(L, b.range, i), u, ignore) != 0) goto out;
    }
    b.next = 0;
    if (store(L, &b, false) != PMD_OK) goto out;
    memcpy(s_out, s, 32);
    *correct = 1;
    rc = PMD_OK;
out:
    memzero(&b, sizeof b);
    memzero(v, sizeof v);
    memzero(w, sizeof w);
    memzero(s, sizeof s);
    memzero(t, sizeof t);
    memzero(u, sizeof u);
    memzero(ignore, sizeof ignore);
    return rc;
}

static void k_out(const uint8_t s[32], uint8_t out_k[PIN_MD_KERNEL_K_LEN])
{
    if (out_k != NULL) kdf(s, 0x02, out_k);
}

static void k_wipe(uint8_t out_k[PIN_MD_KERNEL_K_LEN])
{
    if (out_k != NULL) memzero(out_k, PIN_MD_KERNEL_K_LEN);
}

/* ----- public API ----- */

pmd_state_t pin_md_kernel_status(const pin_md_layout_t *L, uint8_t *attempts,
                                 uint8_t *pin_len)
{
    binding_t b;
    pmd_state_t res = PMD_ERROR;
    if (attempts != NULL) *attempts = 0;   /* never a stale "retries" on ABSENT / ERROR */
    if (pin_len != NULL) *pin_len = 0;
    if (!valid_layout(L)) return PMD_ERROR;
    rec_status_t st = settle(L, &b);
    if (st == REC_ABSENT) {
        res = PMD_ABSENT;
    } else if (st == REC_OK) {
        res = b.next >= L->rounds ? PMD_BLOCKED : PMD_ACTIVE;
        if (attempts != NULL) *attempts = (uint8_t) (L->rounds - b.next);
        if (pin_len != NULL) *pin_len = b.pin_len;
    }
    memzero(&b, sizeof b);
    return res;
}

int pin_md_kernel_setup(const pin_md_layout_t *L, const uint8_t *mat, uint8_t pin_len,
                        uint8_t out_k[PIN_MD_KERNEL_K_LEN])
{
    uint8_t s[32];
    int rc = PMD_ERR;
    k_wipe(out_k);
    if (!valid_layout(L) || mat == NULL) return PMD_ERR;
    if (tropic_random(s, sizeof s) == 0) rc = setup_s(L, mat, pin_len, s);
    if (rc == PMD_OK) k_out(s, out_k);
    memzero(s, sizeof s);
    return rc;
}

int pin_md_kernel_verify(const pin_md_layout_t *L, const uint8_t *mat, int *out_correct,
                         uint8_t out_k[PIN_MD_KERNEL_K_LEN])
{
    uint8_t s[32];
    k_wipe(out_k);
    if (out_correct == NULL) return PMD_ERR;
    *out_correct = 0;
    if (!valid_layout(L) || mat == NULL) return PMD_ERR;
    int rc = verify_s(L, mat, out_correct, s);
    if (rc == PMD_OK && *out_correct == 1) k_out(s, out_k);
    memzero(s, sizeof s);
    return rc;
}

int pin_md_kernel_change(const pin_md_layout_t *L, const uint8_t *old_mat,
                         const uint8_t *new_mat, uint8_t new_pin_len,
                         int *out_correct, uint8_t out_k[PIN_MD_KERNEL_K_LEN])
{
    uint8_t s[32];
    k_wipe(out_k);
    if (out_correct == NULL) return PMD_ERR;
    *out_correct = 0;
    if (!valid_layout(L) || L->ranges < 2u || old_mat == NULL || new_mat == NULL) {
        return PMD_ERR;                                   /* RC: clear + setup (§3.3) */
    }
    int rc = verify_s(L, old_mat, out_correct, s);
    if (rc == PMD_OK && *out_correct == 1) {
        rc = setup_s(L, new_mat, new_pin_len, s);        /* same s: k survives (D4) */
        if (rc == PMD_OK) k_out(s, out_k);
        else *out_correct = 0;
    }
    memzero(s, sizeof s);
    return rc;
}

int pin_md_kernel_clear(const pin_md_layout_t *L)
{
    if (!valid_layout(L)) return PMD_ERR;
    for (uint8_t r = 0; r < L->ranges; ++r) {
        if (retire(L, r) != PMD_OK) return PMD_ERR;
    }
    return rec_pair_clear(L->rec) == REC_OK ? PMD_OK : PMD_ERR;
}
