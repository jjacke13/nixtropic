/*
 * Mirrored R-mem record pairs.  See rec_pair.h and
 * docs/PHASE-9-M4-DESIGN.md §2.
 */
#include "tropic/rec_pair.h"

#include <string.h>

#include "sha2.h"   /* trezor_crypto SHA-256 */
#include "tropic/tropic.h"

#define REC_HDR   12u
#define REC_SUM   8u
#define REC_MAX   (REC_HDR + REC_PAYLOAD_MAX + REC_SUM)   /* 444 */
#define SLOT_MAX  475u   /* largest R-mem slot (FW >= 2.0.0): read it whole,
                            so an over-long slot reads as damaged */

typedef enum { COPY_VALID, COPY_EMPTY, COPY_BAD, COPY_ERR } copy_t;

/* ponytail: static scratch, not reentrant (one request at a time). */
static uint8_t s_a[SLOT_MAX], s_b[SLOT_MAX], s_rec[REC_MAX], s_check[SLOT_MAX];

static uint32_t gen_of(const uint8_t *r)
{
    return ((uint32_t) r[6] << 24) | ((uint32_t) r[7] << 16)
         | ((uint32_t) r[8] << 8) | r[9];
}

static size_t len_of(const uint8_t *r)
{
    return ((size_t) r[10] << 8) | r[11];
}

static void checksum(const uint8_t *r, size_t n, uint8_t out[REC_SUM])
{
    uint8_t full[32];
    sha256_Raw(r, (uint32_t) n, full);
    memcpy(out, full, REC_SUM);
}

static size_t encode(const rec_pair_t *p, uint32_t gen, const uint8_t *payload,
                     size_t len, uint8_t *out)
{
    memcpy(out, "NXR1", 4);
    out[4] = p->obj;
    out[5] = p->schema;
    out[6] = (uint8_t) (gen >> 24);
    out[7] = (uint8_t) (gen >> 16);
    out[8] = (uint8_t) (gen >> 8);
    out[9] = (uint8_t) gen;
    out[10] = (uint8_t) (len >> 8);
    out[11] = (uint8_t) len;
    if (len != 0u) memcpy(out + REC_HDR, payload, len);
    checksum(out, REC_HDR + len, out + REC_HDR + len);
    return REC_HDR + len + REC_SUM;
}

static bool valid(const rec_pair_t *p, const uint8_t *r, size_t n)
{
    uint8_t sum[REC_SUM];
    if (n < REC_HDR + REC_SUM || n > REC_MAX) return false;
    if (memcmp(r, "NXR1", 4) != 0 || r[4] != p->obj || r[5] != p->schema) return false;
    if (gen_of(r) == 0u || n != REC_HDR + len_of(r) + REC_SUM) return false;
    checksum(r, REC_HDR + len_of(r), sum);
    return memcmp(sum, r + REC_HDR + len_of(r), REC_SUM) == 0;
}

static copy_t read_copy(const rec_pair_t *p, uint16_t slot, uint8_t *buf, size_t *n)
{
    size_t got = 0;
    int rc = tropic_rmem_read(slot, buf, SLOT_MAX, &got);
    if (rc == TROPIC_ERR_RMEM_SLOT_EMPTY) return COPY_EMPTY;
    if (rc != 0) return COPY_ERR;
    if (got == 0u) return COPY_EMPTY;   /* a failed decrypt reads as length 0 [J1b] */
    *n = got;
    return valid(p, buf, got) ? COPY_VALID : COPY_BAD;
}

/* Erase, write, read back: true only when the copy holds exactly `rec`. */
static bool commit_copy(uint16_t slot, const uint8_t *rec, size_t n)
{
    size_t got = 0;
    if (tropic_rmem_erase(slot) != 0) return false;
    if (tropic_rmem_write(slot, rec, n) != 0) return false;
    if (tropic_rmem_read(slot, s_check, SLOT_MAX, &got) != 0) return false;
    return got == n && memcmp(s_check, rec, n) == 0;
}

/* Erase, then prove the slot reads empty. */
static bool erase_checked(uint16_t slot)
{
    size_t got = 0;
    if (tropic_rmem_erase(slot) != 0) return false;
    int rc = tropic_rmem_read(slot, s_check, SLOT_MAX, &got);
    return rc == TROPIC_ERR_RMEM_SLOT_EMPTY || (rc == 0 && got == 0u);
}

static rec_status_t uncertain(rec_pair_t *p)
{
    p->uncertain = true;
    return REC_ERROR;
}

rec_status_t rec_pair_read(rec_pair_t *p, uint8_t *payload, size_t max,
                           size_t *len, uint32_t *gen)
{
    size_t na = 0, nb = 0;
    if (p->uncertain) return REC_ERROR;
    copy_t a = read_copy(p, p->slot_a, s_a, &na);
    if (a == COPY_ERR) return REC_ERROR;
    copy_t b = read_copy(p, p->slot_b, s_b, &nb);
    if (b == COPY_ERR) return REC_ERROR;

    const uint8_t *win;
    size_t nwin;
    const uint16_t *repair = NULL;   /* the copy to rewrite from the winner */
    if (a == COPY_VALID && b == COPY_VALID) {
        uint32_t ga = gen_of(s_a), gb = gen_of(s_b);
        if (ga == gb) {
            if (na != nb || memcmp(s_a, s_b, na) != 0) return REC_ERROR;  /* a bug */
            win = s_a; nwin = na;
        } else if (ga == gb + 1u) {
            win = s_a; nwin = na; repair = &p->slot_b;     /* cut after A was committed */
        } else if (gb == ga + 1u) {
            win = s_b; nwin = nb; repair = &p->slot_a;
        } else {
            return REC_ERROR;                       /* no single fault explains a gap */
        }
    } else if (a == COPY_VALID) {
        win = s_a; nwin = na; repair = &p->slot_b;
    } else if (b == COPY_VALID) {
        win = s_b; nwin = nb; repair = &p->slot_a;
    } else if (a == COPY_EMPTY && b == COPY_EMPTY) {
        return REC_ABSENT;
    } else {
        return REC_CORRUPT;
    }

    size_t plen = len_of(win);
    if (payload != NULL && plen > max) return REC_ERROR;
    if (repair != NULL && !commit_copy(*repair, win, nwin)) return uncertain(p);
    if (payload != NULL && plen != 0u) memcpy(payload, win + REC_HDR, plen);
    if (len != NULL) *len = plen;
    if (gen != NULL) *gen = gen_of(win);
    return REC_OK;
}

/* Write `gen` + payload into A, then B; acknowledged only if both read back. */
static rec_status_t commit_both(rec_pair_t *p, uint32_t gen, const uint8_t *payload,
                                size_t len)
{
    size_t n = encode(p, gen, payload, len, s_rec);
    if (!commit_copy(p->slot_a, s_rec, n) || !commit_copy(p->slot_b, s_rec, n)) {
        return uncertain(p);
    }
    return REC_OK;
}

static bool bad_args(const uint8_t *payload, size_t len)
{
    return len > REC_PAYLOAD_MAX || (len != 0u && payload == NULL);
}

rec_status_t rec_pair_write(rec_pair_t *p, const uint8_t *payload, size_t len)
{
    uint32_t gen = 0;
    if (bad_args(payload, len)) return REC_ERROR;
    rec_status_t st = rec_pair_read(p, NULL, 0, NULL, &gen);
    if (st != REC_OK) return st;
    if (gen == UINT32_MAX) return REC_ERROR;   /* exhausted: the object is read-only */
    return commit_both(p, gen + 1u, payload, len);
}

rec_status_t rec_pair_clear(rec_pair_t *p)
{
    if (p->uncertain) return REC_ERROR;
    if (!erase_checked(p->slot_b) || !erase_checked(p->slot_a)) return uncertain(p);
    return REC_OK;
}

rec_status_t rec_pair_init(rec_pair_t *p, const uint8_t *payload, size_t len)
{
    if (bad_args(payload, len)) return REC_ERROR;
    rec_status_t st = rec_pair_clear(p);
    if (st != REC_OK) return st;
    return commit_both(p, 1u, payload, len);
}
