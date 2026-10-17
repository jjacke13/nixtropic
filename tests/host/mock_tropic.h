/*
 * Host-side mock of the TROPIC01 wrapper API (firmware/src/tropic/tropic.h).
 *
 * Phase 9 M0.  Lets firmware modules that sit on top of tropic.h (M&D kernel,
 * slot/state stores) run as ordinary host programs, with fault injection:
 * a chosen call can fail before the chip acts (clean error) or after it
 * (the chip executed, the answer was lost: the ambiguous case of guard
 * rail 5 in docs/history/PHASE-9-PLAN.md).
 *
 * Only the wrapper functions some test needs are implemented; a test that
 * links a module using another one fails to link, which is the reminder to
 * model it here.
 *
 * MAC-and-Destroy model (PIN application note §3.2 + Appendix A,
 * simplified; M4 design §7): each slot i holds 32 bytes x.  MACANDD(i, d)
 * sets x' = F1(d || i) = HMAC(K_FA, d || i), K_FA a per-chip secret, and
 * returns F2(x, x', i) = HMAC(x, x' || i).  So a slot is a function of the
 * last input only: M&D(u) puts it back after any other call (how a correct
 * verify restores and how a binding is retired), and a consumed slot still
 * answers OK, with a wrong value [J2a, J2b].
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
    MOCK_OP_ECC_ERASE,
    MOCK_OP_MCOUNTER,          /* init and get */
    MOCK_OP_COUNT
} mock_op_t;

/* Fresh chip: empty R-mem, factory M&D slots, PRNG seeded, no faults. */
void mock_reset(uint32_t seed);

/* Make the n-th next call of `op` (1 = the very next one) return `rc`
 * (a negative libtropic-style code).  If `executed` is true the chip still
 * performs the operation first: the caller sees an error although the
 * state changed.  One pending fault per op. */
void mock_fail_nth(mock_op_t op, unsigned n, int rc, bool executed);

/* ECC key slots (Phase 9 M4 step 3): put a key / ask whether one is there. */
void mock_ecc_put(uint8_t slot);
bool mock_ecc_present(uint8_t slot);

/* Current value of M&D slot `idx` (to prove another PIN's slots untouched). */
void mock_mad_peek(uint8_t idx, uint8_t out[32]);

/* Drop every pending fault. */
void mock_disarm(void);

/* Chip-state-changing calls so far (R-mem write + erase + M&D), and that
 * count at the moment the last injected fault fired. */
unsigned mock_mutations(void);
unsigned mock_mutations_at_fault(void);

/* Number of calls of `op` since mock_reset. */
unsigned mock_calls(mock_op_t op);

/* R-mem damage (Phase 9 M4).  A damaged slot either reads back with wrong
 * content, or reads SLOT_EMPTY although it holds data: the chip reports a
 * failed decrypt as an empty slot [Jan J1b].  A masked slot still refuses a
 * write until it is erased. */
typedef enum {
    MOCK_DAMAGE_GARBLE = 1,
    MOCK_DAMAGE_MASKED,
} mock_damage_t;

/* Damage `slot` at rest. */
void mock_rmem_damage(uint16_t slot, mock_damage_t how);

/* The n-th next call of `op` (MOCK_OP_RMEM_WRITE or _ERASE) is torn: the
 * chip acts, the slot ends damaged `how`, and the call returns `rc`
 * (0 = the chip claims success). */
void mock_tear_nth(mock_op_t op, unsigned n, int rc, mock_damage_t how);

#endif /* NIXTROPIC_TESTS_MOCK_TROPIC_H */
