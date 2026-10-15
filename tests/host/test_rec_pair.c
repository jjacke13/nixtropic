/*
 * Host tests for firmware/src/tropic/rec_pair.c (Phase 9 M4 step 1) against
 * the mock chip: the record format (§2.1, encoded independently here), the
 * read rules row by row (§2.2), read-back commit and repair (§2.3), and a
 * single-fault sweep over write, init and clear.
 */
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "sha2.h"
#include "tropic/rec_pair.h"
#include "tropic/tropic.h"

#define SA 33u
#define SB 43u
#define OBJ 3u
#define SCHEMA 1u

static rec_pair_t pair(void)
{
    rec_pair_t p = REC_PAIR(SA, SB, OBJ, SCHEMA);
    return p;
}

/* Independent encoder of the §2.1 format. */
static size_t raw(uint8_t *out, uint8_t obj, uint8_t schema, uint32_t gen,
                  const char *pl, size_t n)
{
    uint8_t sum[32];
    memcpy(out, "NXR1", 4);
    out[4] = obj;
    out[5] = schema;
    out[6] = (uint8_t) (gen >> 24);
    out[7] = (uint8_t) (gen >> 16);
    out[8] = (uint8_t) (gen >> 8);
    out[9] = (uint8_t) gen;
    out[10] = (uint8_t) (n >> 8);
    out[11] = (uint8_t) n;
    memcpy(out + 12, pl, n);
    sha256_Raw(out, (uint32_t) (12 + n), sum);
    memcpy(out + 12 + n, sum, 8);
    return 12 + n + 8;
}

static void put_raw(uint16_t slot, const uint8_t *rec, size_t n)
{
    CHECK(tropic_rmem_erase(slot) == 0);
    CHECK(tropic_rmem_write(slot, rec, n) == 0);
}

static void put(uint16_t slot, uint32_t gen, const char *pl)
{
    uint8_t r[444];
    put_raw(slot, r, raw(r, OBJ, SCHEMA, gen, pl, strlen(pl)));
}

/* Slot contents, or 0 if the slot reads empty / errors. */
static size_t slot_get(uint16_t slot, uint8_t *out)
{
    size_t n = 0;
    return tropic_rmem_read(slot, out, 475, &n) == 0 ? n : 0;
}

static bool slots_equal(void)
{
    uint8_t a[475], b[475];
    size_t na = slot_get(SA, a), nb = slot_get(SB, b);
    return na != 0 && na == nb && memcmp(a, b, na) == 0;
}

/* Read and compare with an expected generation + payload. */
static bool reads(rec_pair_t *p, uint32_t gen, const char *pl)
{
    uint8_t buf[REC_PAYLOAD_MAX];
    size_t n = 0;
    uint32_t g = 0;
    return rec_pair_read(p, buf, sizeof buf, &n, &g) == REC_OK
        && g == gen && n == strlen(pl) && memcmp(buf, pl, n) == 0;
}

static rec_status_t status(rec_pair_t *p)
{
    uint8_t buf[REC_PAYLOAD_MAX];
    return rec_pair_read(p, buf, sizeof buf, NULL, NULL);
}

static void test_format_and_roundtrip(void)
{
    uint8_t want[444], got[475];
    rec_pair_t p = pair();
    mock_reset(1);
    CHECK(status(&p) == REC_ABSENT);
    CHECK(rec_pair_init(&p, (const uint8_t *) "hello", 5) == REC_OK);
    CHECK(reads(&p, 1, "hello"));
    CHECK(rec_pair_write(&p, (const uint8_t *) "world!", 6) == REC_OK);
    CHECK(reads(&p, 2, "world!"));
    size_t n = raw(want, OBJ, SCHEMA, 2, "world!", 6);
    CHECK(slot_get(SA, got) == n && memcmp(got, want, n) == 0);
    CHECK(slots_equal());
}

static void test_max_payload_and_bounds(void)
{
    uint8_t big[REC_PAYLOAD_MAX + 1], buf[REC_PAYLOAD_MAX], small[4], got[475];
    rec_pair_t p = pair();
    memset(big, 0x42, sizeof big);
    mock_reset(1);
    CHECK(rec_pair_init(&p, big, sizeof big) == REC_ERROR);       /* 445 B record: too big */
    CHECK(mock_calls(MOCK_OP_RMEM_WRITE) == 0);
    CHECK(rec_pair_init(&p, big, REC_PAYLOAD_MAX) == REC_OK);
    CHECK(slot_get(SA, got) == 444u);
    size_t n = 0;
    CHECK(rec_pair_read(&p, buf, sizeof buf, &n, NULL) == REC_OK && n == REC_PAYLOAD_MAX);
    CHECK(rec_pair_read(&p, small, sizeof small, &n, NULL) == REC_ERROR);
    CHECK(rec_pair_write(&p, big, sizeof big) == REC_ERROR);
}

/* Copy kinds for the rules table. */
enum { V1 = 1, V2, V1X, V3, E, M, G, W, S, Z, T, C };

static void setup_copy(uint16_t slot, int kind)
{
    uint8_t r[475];
    switch (kind) {
    case V1:  put(slot, 1, "one"); break;
    case V2:  put(slot, 2, "two"); break;
    case V1X: put(slot, 1, "ONE"); break;
    case V3:  put(slot, 3, "three"); break;
    case E:   break;
    case M:   put(slot, 1, "one"); mock_rmem_damage(slot, MOCK_DAMAGE_MASKED); break;
    case G:   put(slot, 1, "one"); mock_rmem_damage(slot, MOCK_DAMAGE_GARBLE); break;
    case W:   put_raw(slot, r, raw(r, OBJ + 1, SCHEMA, 1, "one", 3)); break;  /* other object */
    case S:   put_raw(slot, r, raw(r, OBJ, SCHEMA + 1, 1, "one", 3)); break;  /* other schema */
    case Z:   put_raw(slot, r, raw(r, OBJ, SCHEMA, 0, "one", 3)); break;      /* gen 0 */
    case T:   put_raw(slot, r, raw(r, OBJ, SCHEMA, 1, "one", 3) - 1); break;  /* truncated */
    case C: {                                       /* payload byte flipped: only the checksum sees it */
        size_t n = raw(r, OBJ, SCHEMA, 1, "one", 3);
        r[12] ^= 0x01;
        put_raw(slot, r, n);
        break;
    }
    }
}

static void test_rules_table(void)
{
    static const struct {
        int a, b;
        rec_status_t want;
        uint32_t gen;      /* REC_OK: expected generation (payload follows) */
        bool repair;
    } rows[] = {
        { V1, V1,  REC_OK, 1, false },
        { V2, V1,  REC_OK, 2, true },
        { V1, V2,  REC_OK, 2, true },
        { V1, E,   REC_OK, 1, true },  { E, V1, REC_OK, 1, true },
        { V1, G,   REC_OK, 1, true },  { G, V1, REC_OK, 1, true },
        { V1, M,   REC_OK, 1, true },  { M, V1, REC_OK, 1, true },
        { V1, W,   REC_OK, 1, true },  { V1, S, REC_OK, 1, true },
        { V1, Z,   REC_OK, 1, true },  { T, V1, REC_OK, 1, true },
        { C, V1,   REC_OK, 1, true },  { C, E, REC_CORRUPT, 0, false },
        { Z, E,    REC_CORRUPT, 0, false }, { E, T, REC_CORRUPT, 0, false },
        { E, E,    REC_ABSENT, 0, false },
        { M, M,    REC_ABSENT, 0, false },
        { G, E,    REC_CORRUPT, 0, false }, { E, G, REC_CORRUPT, 0, false },
        { G, G,    REC_CORRUPT, 0, false }, { W, E, REC_CORRUPT, 0, false },
        { V1, V1X, REC_ERROR, 0, false },   /* same generation, different record */
        { V1, V3,  REC_ERROR, 0, false },   /* generation gap */
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; ++i) {
        rec_pair_t p = pair();
        mock_reset(1);
        setup_copy(SA, rows[i].a);
        setup_copy(SB, rows[i].b);
        unsigned w0 = mock_calls(MOCK_OP_RMEM_WRITE);
        if (rows[i].want == REC_OK) {
            CHECK(reads(&p, rows[i].gen, rows[i].gen == 2 ? "two" : "one"));
            CHECK(slots_equal());
        } else {
            CHECK(status(&p) == rows[i].want);
        }
        unsigned writes = mock_calls(MOCK_OP_RMEM_WRITE) - w0;
        CHECK(writes == (rows[i].repair ? 1u : 0u));
        if (writes != (rows[i].repair ? 1u : 0u)) fprintf(stderr, "  row %zu\n", i);
    }
}

static void test_read_error_fails_closed(void)
{
    for (unsigned n = 1; n <= 2; ++n) {
        rec_pair_t p = pair();
        mock_reset(1);
        setup_copy(SA, V1);                     /* B empty: a repair would write */
        mock_fail_nth(MOCK_OP_RMEM_READ, n, -1, false);
        unsigned w0 = mock_calls(MOCK_OP_RMEM_WRITE), e0 = mock_calls(MOCK_OP_RMEM_ERASE);
        CHECK(status(&p) == REC_ERROR);
        CHECK(mock_calls(MOCK_OP_RMEM_WRITE) == w0 && mock_calls(MOCK_OP_RMEM_ERASE) == e0);
    }
}

static void test_generation_exhausted(void)
{
    rec_pair_t p = pair();
    mock_reset(1);
    put(SA, UINT32_MAX, "last");
    put(SB, UINT32_MAX, "last");
    CHECK(reads(&p, UINT32_MAX, "last"));
    unsigned w0 = mock_calls(MOCK_OP_RMEM_WRITE);
    CHECK(rec_pair_write(&p, (const uint8_t *) "more", 4) == REC_ERROR);
    CHECK(mock_calls(MOCK_OP_RMEM_WRITE) == w0);
    CHECK(reads(&p, UINT32_MAX, "last"));
}

/* An unproven write leaves the pair refusing, without chip calls, until reboot. */
static void test_uncertain_until_reboot(void)
{
    rec_pair_t p = pair();
    mock_reset(1);
    CHECK(rec_pair_init(&p, (const uint8_t *) "old", 3) == REC_OK);
    mock_tear_nth(MOCK_OP_RMEM_WRITE, 1, 0, MOCK_DAMAGE_GARBLE);   /* "succeeds", stores garbage */
    CHECK(rec_pair_write(&p, (const uint8_t *) "new", 3) == REC_ERROR);
    CHECK(p.uncertain);
    unsigned r0 = mock_calls(MOCK_OP_RMEM_READ);
    CHECK(status(&p) == REC_ERROR);
    CHECK(rec_pair_clear(&p) == REC_ERROR);
    CHECK(rec_pair_init(&p, (const uint8_t *) "x", 1) == REC_ERROR);
    CHECK(mock_calls(MOCK_OP_RMEM_READ) == r0);
    p = pair();                                 /* reboot */
    CHECK(reads(&p, 1, "old"));                 /* A garbled → B's old record, repaired */
    CHECK(slots_equal());
}

/* I6: after an acknowledged write, one damaged copy never rolls it back. */
static void test_ack_survives_damage(void)
{
    static const uint16_t slots[] = { SA, SB };
    static const mock_damage_t how[] = { MOCK_DAMAGE_GARBLE, MOCK_DAMAGE_MASKED };
    for (size_t s = 0; s < 2; ++s) {
        for (size_t h = 0; h < 2; ++h) {
            rec_pair_t p = pair();
            mock_reset(1);
            CHECK(rec_pair_init(&p, (const uint8_t *) "old", 3) == REC_OK);
            CHECK(rec_pair_write(&p, (const uint8_t *) "new", 3) == REC_OK);
            mock_rmem_damage(slots[s], how[h]);
            p = pair();
            CHECK(reads(&p, 2, "new") && slots_equal());
        }
    }
}

static void test_repair_failure(void)
{
    rec_pair_t p = pair();
    mock_reset(1);
    setup_copy(SA, V1);
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 1, -1, false);
    CHECK(status(&p) == REC_ERROR && p.uncertain);
    p = pair();
    CHECK(reads(&p, 1, "one") && slots_equal());
}

/* ---- single-fault sweep ---- */

enum fault { F_ERR, F_LOST, F_GARBLE, F_MASK, F_SILENT, F_SILENT_MASK, F_COUNT };
enum action { A_WRITE, A_INIT, A_INIT_FRESH, A_CLEAR };

static void arm(mock_op_t op, unsigned n, enum fault f)
{
    switch (f) {
    case F_ERR:    mock_fail_nth(op, n, -1, false); break;
    case F_LOST:   mock_fail_nth(op, n, -1, true); break;
    case F_GARBLE: mock_tear_nth(op, n, -1, MOCK_DAMAGE_GARBLE); break;
    case F_MASK:   mock_tear_nth(op, n, -1, MOCK_DAMAGE_MASKED); break;
    case F_SILENT: mock_tear_nth(op, n, 0, MOCK_DAMAGE_GARBLE); break;
    case F_SILENT_MASK: mock_tear_nth(op, n, 0, MOCK_DAMAGE_MASKED); break;   /* §13 limit */
    default: break;
    }
}

/* Before state: "old" at generation 2 (or nothing for A_INIT_FRESH). */
static void before(rec_pair_t *p, enum action a)
{
    mock_reset(1);
    if (a == A_INIT_FRESH) return;
    CHECK(rec_pair_init(p, (const uint8_t *) "old", 3) == REC_OK);
    CHECK(rec_pair_write(p, (const uint8_t *) "old", 3) == REC_OK);
}

static rec_status_t act(rec_pair_t *p, enum action a)
{
    switch (a) {
    case A_WRITE: return rec_pair_write(p, (const uint8_t *) "new", 3);
    case A_CLEAR: return rec_pair_clear(p);
    default:      return rec_pair_init(p, (const uint8_t *) "new", 3);
    }
}

/* Chip calls of each op in a fault-free run. */
static unsigned clean_calls(enum action a, mock_op_t op)
{
    rec_pair_t p = pair();
    before(&p, a);
    unsigned c0 = mock_calls(op);
    CHECK(act(&p, a) == REC_OK);
    return mock_calls(op) - c0;
}

/* The §13 window: a torn call on one copy while the other holds no valid
 * record.  Clear = erase B, erase A; init = clear, then (erase, write) A,
 * then (erase, write) B. */
static bool corrupt_window(enum action a, mock_op_t op, unsigned n)
{
    if (op == MOCK_OP_RMEM_WRITE) return (a == A_INIT || a == A_INIT_FRESH) && n == 1u;
    if (op != MOCK_OP_RMEM_ERASE) return false;
    switch (a) {
    case A_CLEAR:      return n == 2u;
    case A_INIT:       return n == 2u || n == 3u;
    case A_INIT_FRESH: return n <= 3u;
    default:           return false;
    }
}

/* Raw chip state right after an acknowledged action, before any repairing read. */
static bool acked_raw(enum action a)
{
    uint8_t want[444], got[475];
    if (a == A_CLEAR) return slot_get(SA, got) == 0 && slot_get(SB, got) == 0;
    size_t n = raw(want, OBJ, SCHEMA, a == A_WRITE ? 3 : 1, "new", 3);
    return slots_equal() && slot_get(SA, got) == n && memcmp(got, want, n) == 0;
}

static void check_after(enum action a, enum fault f, mock_op_t op, unsigned n,
                        rec_status_t acted, rec_pair_t *p)
{
    bool tear = f == F_GARBLE || f == F_MASK || f == F_SILENT || f == F_SILENT_MASK;
    bool is_old = a != A_INIT_FRESH && reads(p, 2, "old");
    bool is_new = a != A_CLEAR && reads(p, a == A_WRITE ? 3 : 1, "new");
    rec_status_t st = (is_old || is_new) ? REC_OK : status(p);
    bool ok;
    if (acted == REC_OK) {
        ok = a == A_CLEAR ? st == REC_ABSENT : is_new;          /* acknowledged = done */
    } else if (a == A_WRITE) {
        ok = is_old || is_new;                                  /* never anything else */
    } else {
        /* init/clear: before, after, or absent; a tear inside the last
         * erase / first write of an empty pair fails closed (CORRUPT). */
        ok = is_old || is_new || st == REC_ABSENT
          || (tear && corrupt_window(a, op, n) && st == REC_CORRUPT);
    }
    if ((is_old || is_new) && !slots_equal()) ok = false;      /* repaired */
    CHECK(ok);
    if (!ok) fprintf(stderr, "  action %d fault %d op %d call %u: acted %d after %d\n",
                     a, f, op, n, acted, st);
}

static void sweep(enum action a)
{
    static const mock_op_t ops[] = { MOCK_OP_RMEM_READ, MOCK_OP_RMEM_WRITE, MOCK_OP_RMEM_ERASE };
    for (size_t o = 0; o < 3; ++o) {
        mock_op_t op = ops[o];
        unsigned calls = clean_calls(a, op);
        for (unsigned n = 1; n <= calls; ++n) {
            for (int f = 0; f < F_COUNT; ++f) {
                if (op == MOCK_OP_RMEM_READ && f != F_ERR) continue;   /* reads change nothing */
                rec_pair_t p = pair();
                before(&p, a);
                arm(op, n, (enum fault) f);
                rec_status_t acted = act(&p, a);
                if (acted == REC_OK) {
                    CHECK(acked_raw(a));               /* both copies proven, no repair needed */
                } else if (a == A_WRITE && op == MOCK_OP_RMEM_READ && n <= 2u) {
                    /* the write's first read failed: nothing written */
                    CHECK(!p.uncertain && reads(&p, 2, "old"));
                } else {
                    CHECK(p.uncertain && status(&p) == REC_ERROR);
                }
                p = pair();                                            /* reboot */
                check_after(a, (enum fault) f, op, n, acted, &p);
            }
        }
    }
}

int main(void)
{
    test_format_and_roundtrip();
    test_max_payload_and_bounds();
    test_rules_table();
    test_read_error_fails_closed();
    test_generation_exhausted();
    test_uncertain_until_reboot();
    test_ack_survives_damage();
    test_repair_failure();
    sweep(A_WRITE);
    sweep(A_INIT);
    sweep(A_INIT_FRESH);
    sweep(A_CLEAR);
    return check_done("rec_pair");
}
