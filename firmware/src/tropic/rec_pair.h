/*
 * Mirrored R-mem record pairs (Phase 9 M4, docs/history/PHASE-9-M4-DESIGN.md §2).
 *
 * One persistent object = one record kept in two R-mem slots, copies A and
 * B, that hold the same record at rest.  A write commits A, then B, each
 * proven by an exact read-back; only then is it acknowledged.  A read takes
 * the newer valid copy and repairs the other.  So one power cut or one
 * damaged slot never rolls an object back, and never makes it look
 * never-written while the other copy holds it.
 *
 * Record (≤ 444 B, PLAN rule 6):
 *   "NXR1" | obj u8 | schema u8 | gen u32 BE | len u16 BE | payload | SHA-256(all before)[:8]
 * The checksum catches torn or garbled content and another object's record.
 * It is not a MAC: integrity against a reflashed STM32 is Phase 10.
 *
 * An unproven write, erase or repair marks the pair uncertain: it refuses
 * everything until the next boot, where the read rules decide from what the
 * chip then holds (§2.3).
 *
 * Not reentrant (shared static buffers): one request at a time, PROJECT
 * decision 18.
 */
#ifndef NIXTROPIC_TROPIC_REC_PAIR_H
#define NIXTROPIC_TROPIC_REC_PAIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define REC_PAYLOAD_MAX 424u   /* 444 B record - 12 B header - 8 B checksum */

typedef enum {
    REC_OK = 0,    /* both copies hold the record (the other one repaired if they differed) */
    REC_ABSENT,    /* both copies read empty: never written, cleared, or masked damage —
                      the caller's guard decides (§2.5) */
    REC_CORRUPT,   /* no valid copy, at least one damaged */
    REC_ERROR,     /* chip error, copies contradict, generation exhausted, bad argument,
                      or the pair is uncertain */
} rec_status_t;

typedef struct {
    uint16_t slot_a;
    uint16_t slot_b;
    uint8_t  obj;        /* object id O1…O6 (§2.4) */
    uint8_t  schema;     /* payload schema; another schema reads as damaged */
    bool     uncertain;  /* RAM only; set by a failed write, erase or repair */
} rec_pair_t;

#define REC_PAIR(a, b, obj, schema) { (a), (b), (obj), (schema), false }

/* Read the object.  On REC_OK copies the payload (if `payload` is not NULL;
 * REC_ERROR if it does not fit `max`) and sets *len / *gen when non-NULL. */
rec_status_t rec_pair_read(rec_pair_t *p, uint8_t *payload, size_t max,
                           size_t *len, uint32_t *gen);

/* Replace the payload of an existing object (generation + 1).  Refused
 * unless the pair reads REC_OK; returns that status otherwise. */
rec_status_t rec_pair_write(rec_pair_t *p, const uint8_t *payload, size_t len);

/* (Re)initialise: checked erase of both copies, then write generation 1. */
rec_status_t rec_pair_init(rec_pair_t *p, const uint8_t *payload, size_t len);

/* Checked erase of B, then A. */
rec_status_t rec_pair_clear(rec_pair_t *p);

#endif /* NIXTROPIC_TROPIC_REC_PAIR_H */
