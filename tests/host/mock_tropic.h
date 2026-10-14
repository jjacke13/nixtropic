/*
 * Host-side mock of the TROPIC01 wrapper API (firmware/src/tropic/tropic.h).
 *
 * Phase 9 M0.  Lets firmware modules that sit on top of tropic.h (M&D kernel,
 * slot/state stores) run as ordinary host programs, with fault injection:
 * a chosen call can fail before the chip acts (clean error) or after it
 * (the chip executed, the answer was lost: the ambiguous case of guard
 * rail 5 in docs/PHASE-9-PLAN.md).
 *
 * Only the wrapper functions some test needs are implemented; a test that
 * links a module using another one fails to link, which is the reminder to
 * model it here.
 *
 * MAC-and-Destroy model (PIN application note, Appendix A, simplified):
 * each slot holds 32 bytes x.  MACANDD(i, d) returns HMAC(x, d) and then
 * replaces x with HMAC(K_FA, d), K_FA being a per-chip secret.  So calling
 * with the same d twice in a row restores the slot, and any other d
 * destroys what the slot held.
 */
#ifndef NIXTROPIC_TESTS_MOCK_TROPIC_H
#define NIXTROPIC_TESTS_MOCK_TROPIC_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    MOCK_OP_RANDOM,
    MOCK_OP_RMEM_READ,
    MOCK_OP_RMEM_WRITE,
    MOCK_OP_RMEM_ERASE,
    MOCK_OP_MAC_AND_DESTROY,
    MOCK_OP_COUNT
} mock_op_t;

/* Fresh chip: empty R-mem, factory M&D slots, PRNG seeded, no faults. */
void mock_reset(uint32_t seed);

/* Make the n-th next call of `op` (1 = the very next one) return `rc`
 * (a negative libtropic-style code).  If `executed` is true the chip still
 * performs the operation first: the caller sees an error although the
 * state changed.  One pending fault per op. */
void mock_fail_nth(mock_op_t op, unsigned n, int rc, bool executed);

/* Number of calls of `op` since mock_reset. */
unsigned mock_calls(mock_op_t op);

#endif /* NIXTROPIC_TESTS_MOCK_TROPIC_H */
