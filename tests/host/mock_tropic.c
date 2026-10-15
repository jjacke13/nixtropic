/*
 * Host mock of firmware/src/tropic/tropic.h.  See mock_tropic.h.
 */
#include "mock_tropic.h"
#include "tropic/tropic.h"

#include <string.h>

#include "hmac.h"
#include "libtropic_common.h"

#define MOCK_RMEM_SLOTS   512u
#define MOCK_RMEM_SIZE    475u   /* FW >= 2.0.0 user payload */
#define MOCK_MAD_SLOTS    128u

static struct {
    bool     written;
    bool     masked;    /* holds data but reads SLOT_EMPTY */
    size_t   len;
    uint8_t  data[MOCK_RMEM_SIZE];
} s_rmem[MOCK_RMEM_SLOTS];

static uint8_t  s_mad[MOCK_MAD_SLOTS][32];
static uint8_t  s_kfa[32];
static uint32_t s_prng;

static unsigned s_calls[MOCK_OP_COUNT];
static struct {
    unsigned at;        /* absolute call number that fails; 0 = none */
    int      rc;
    bool     executed;
    mock_damage_t tear;  /* 0 = plain fault */
} s_fault[MOCK_OP_COUNT];

/* Damage of the call in progress (set by enter()). */
static mock_damage_t s_tear;

static uint8_t prng_byte(void)
{
    /* xorshift32: deterministic, test-only. */
    s_prng ^= s_prng << 13;
    s_prng ^= s_prng >> 17;
    s_prng ^= s_prng << 5;
    return (uint8_t) s_prng;
}

void mock_reset(uint32_t seed)
{
    memset(s_rmem, 0, sizeof s_rmem);
    memset(s_calls, 0, sizeof s_calls);
    memset(s_fault, 0, sizeof s_fault);
    s_prng = seed ? seed : 0x6e697874u;
    for (size_t i = 0; i < sizeof s_kfa; ++i) s_kfa[i] = prng_byte();
    for (unsigned i = 0; i < MOCK_MAD_SLOTS; ++i) {
        uint8_t idx = (uint8_t) i;
        hmac_sha256(s_kfa, sizeof s_kfa, &idx, 1, s_mad[i]);
    }
}

void mock_fail_nth(mock_op_t op, unsigned n, int rc, bool executed)
{
    s_fault[op].at = s_calls[op] + n;
    s_fault[op].rc = rc;
    s_fault[op].executed = executed;
    s_fault[op].tear = 0;
}

void mock_tear_nth(mock_op_t op, unsigned n, int rc, mock_damage_t how)
{
    mock_fail_nth(op, n, rc, true);
    s_fault[op].tear = how;
}

void mock_rmem_damage(uint16_t slot, mock_damage_t how)
{
    if (slot >= MOCK_RMEM_SLOTS) return;
    if (how == MOCK_DAMAGE_MASKED) {
        s_rmem[slot].masked = s_rmem[slot].written;
        return;
    }
    if (!s_rmem[slot].written) {            /* garbage where nothing was */
        memset(s_rmem[slot].data, 0xa5, 16);
        s_rmem[slot].len = 16;
        s_rmem[slot].written = true;
        return;
    }
    s_rmem[slot].data[s_rmem[slot].len / 2] ^= 0x5a;
}

void mock_disarm(void)
{
    memset(s_fault, 0, sizeof s_fault);
}

unsigned mock_calls(mock_op_t op)
{
    return s_calls[op];
}

/* Count the call; returns the injected rc if this call fails, else 0.
 * *execute tells the caller whether the chip acts on this call. */
static int enter(mock_op_t op, bool *execute)
{
    s_calls[op]++;
    *execute = true;
    s_tear = 0;
    if (s_fault[op].at != 0 && s_fault[op].at == s_calls[op]) {
        s_fault[op].at = 0;
        *execute = s_fault[op].executed;
        s_tear = s_fault[op].tear;
        return s_fault[op].rc;
    }
    return 0;
}

int tropic_random(uint8_t *out, size_t len)
{
    bool exec;
    int rc = enter(MOCK_OP_RANDOM, &exec);
    if (out == NULL || len == 0u || len > 255u) return -1;
    if (exec) {
        for (size_t i = 0; i < len; ++i) out[i] = prng_byte();
    }
    return rc;
}

int tropic_rmem_write(uint16_t slot, const uint8_t *data, size_t len)
{
    bool exec;
    int rc = enter(MOCK_OP_RMEM_WRITE, &exec);
    if (slot >= MOCK_RMEM_SLOTS || data == NULL || len == 0u || len > MOCK_RMEM_SIZE) {
        return -(int) LT_L3_INVALID_CMD;
    }
    if (exec) {
        if (s_rmem[slot].written) return -(int) LT_L3_SLOT_NOT_EMPTY;  /* write-once until erased */
        memcpy(s_rmem[slot].data, data, len);
        s_rmem[slot].len = len;
        s_rmem[slot].written = true;
    }
    if (s_tear) mock_rmem_damage(slot, s_tear);
    return rc;
}

int tropic_rmem_read(uint16_t slot, uint8_t *out, size_t max, size_t *actual)
{
    bool exec;
    int rc = enter(MOCK_OP_RMEM_READ, &exec);
    if (slot >= MOCK_RMEM_SLOTS || out == NULL || max == 0u) return -1;
    if (rc != 0) return rc;
    if (!s_rmem[slot].written || s_rmem[slot].masked) return -(int) LT_L3_R_MEM_DATA_READ_SLOT_EMPTY;
    size_t n = s_rmem[slot].len < max ? s_rmem[slot].len : max;
    memcpy(out, s_rmem[slot].data, n);
    if (actual) *actual = n;
    return 0;
}

int tropic_rmem_erase(uint16_t slot)
{
    bool exec;
    int rc = enter(MOCK_OP_RMEM_ERASE, &exec);
    if (slot >= MOCK_RMEM_SLOTS) return -(int) LT_L3_INVALID_CMD;
    if (exec && !s_tear) {
        memset(&s_rmem[slot], 0, sizeof s_rmem[slot]);
    }
    if (s_tear) mock_rmem_damage(slot, s_tear);   /* torn erase: old content, damaged */
    return rc;
}

int tropic_mac_and_destroy(uint8_t idx, const uint8_t *data_out, uint8_t *data_in)
{
    bool exec;
    int rc = enter(MOCK_OP_MAC_AND_DESTROY, &exec);
    if (idx >= MOCK_MAD_SLOTS || data_out == NULL || data_in == NULL) return -1;
    if (exec) {
        uint8_t in[33], nv[32], out[32];
        memcpy(in, data_out, 32);
        in[32] = idx;
        hmac_sha256(s_kfa, sizeof s_kfa, in, sizeof in, nv);        /* new = F1(data || slot) */
        memcpy(in, nv, 32);
        hmac_sha256(s_mad[idx], 32, in, sizeof in, out);            /* out = F2(old, new, slot) */
        memcpy(s_mad[idx], nv, 32);
        if (rc == 0) memcpy(data_in, out, 32);   /* lost response: caller gets nothing */
    }
    return rc;
}
