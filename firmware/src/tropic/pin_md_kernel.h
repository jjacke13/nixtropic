/*
 * MAC-and-Destroy PIN kernel v2 (Phase 9 M4, docs/PHASE-9-M4-DESIGN.md §3).
 *
 * One PIN = one binding record in a rec_pair (rec_pair.h) plus one or two
 * M&D slot ranges (A/B).  The record is the only PIN state: no software
 * check, no second counter; retries = rounds - next_slot (D5).
 *
 * Crypto as in PHASE-5-M4-DESIGN.md: t = HMAC(s,0), u = HMAC(s,1),
 * k = HMAC(s,2), v = HMAC(0^32, mat), w_i = M&D(slot_i, v) after
 * M&D(slot_i, u), ci_i = s XOR HMAC(w_i, mat).
 *
 * - setup writes the range the live binding does not use, commits the record
 *   (both copies), then retires the old range: before the commit the old PIN
 *   works, after it the new one (§3.3).
 * - verify reserves the attempt (record, both copies) before the M&D call.
 * - change keeps s inside the kernel, so k survives a PIN change (D4).
 * - every call except clear first settles a pending retirement (§3.4).
 *
 * s, u and the slot keys never leave the kernel; k leaves only through
 * out_k, written only on success (wiped on every other path).
 */
#ifndef NIXTROPIC_TROPIC_PIN_MD_KERNEL_H
#define NIXTROPIC_TROPIC_PIN_MD_KERNEL_H

#include <stdint.h>

#include "tropic/rec_pair.h"

#define PIN_MD_KERNEL_SLOT_SIZE    32u   /* TR01_MAC_AND_DESTROY_DATA_SIZE */
#define PIN_MD_KERNEL_TAG_LEN      32u
#define PIN_MD_KERNEL_K_LEN        32u
#define PIN_MD_KERNEL_ROUNDS_MAX   8u    /* FIDO; record 4 + 32 + 8*32 = 292 B */
#define PIN_MD_KERNEL_MATERIAL_MAX 32u

typedef struct {
    rec_pair_t *rec;        /* the binding record (O2, O4, O5 or O6) */
    uint8_t     base[2];    /* first M&D slot of range A and of range B */
    uint8_t     ranges;     /* 2, or 1 (RC: clear before a new setup, §3.3) */
    uint8_t     rounds;     /* slots per range = wrong attempts before BLOCKED */
    uint8_t     mat_len;    /* PIN material length */
} pin_md_layout_t;

typedef enum { PMD_ABSENT, PMD_ACTIVE, PMD_BLOCKED, PMD_ERROR } pmd_state_t;

/* Return codes of setup / verify / change / clear. */
#define PMD_OK            0
#define PMD_ERR          (-1)   /* chip, record or argument error: refuse */
#define PMD_ERR_BLOCKED  (-2)   /* no attempts left */
#define PMD_ERR_ABSENT   (-3)   /* no binding (the caller's guard decides, §2.5) */

/* Settles, then reports the PIN.  ABSENT is the record's view only: the
 * caller checks its guard.  `attempts` / `pin_len` (nullable) are set for
 * ACTIVE and BLOCKED, 0 otherwise.  A read error, damaged record or failed settle is
 * PMD_ERROR, never "not set" or "full retries" (F4, F6). */
pmd_state_t pin_md_kernel_status(const pin_md_layout_t *L, uint8_t *attempts,
                                 uint8_t *pin_len);

/* New binding with a fresh s, over no binding or over an existing one
 * (reset paths; refused for a one-range layout that is not ABSENT).
 * PMD_ERR does not always mean "nothing changed": a failure after the
 * commit (retiring the old range) leaves the NEW PIN live, retirement
 * pending (setup and change alike). */
int pin_md_kernel_setup(const pin_md_layout_t *L, const uint8_t *mat,
                        uint8_t pin_len, uint8_t out_k[PIN_MD_KERNEL_K_LEN]);

/* PMD_OK with *out_correct 1 (k out) or 0 (the attempt is spent). */
int pin_md_kernel_verify(const pin_md_layout_t *L, const uint8_t *mat,
                         int *out_correct, uint8_t out_k[PIN_MD_KERNEL_K_LEN]);

/* verify(old), then setup(new) with the same s.  PMD_OK with *out_correct 0
 * = wrong old PIN; PMD_OK with 1 = changed. */
int pin_md_kernel_change(const pin_md_layout_t *L, const uint8_t *old_mat,
                         const uint8_t *new_mat, uint8_t new_pin_len,
                         int *out_correct, uint8_t out_k[PIN_MD_KERNEL_K_LEN]);

/* Retire every range (checked), then clear the record.  Needs no readable
 * record, so it also recovers a damaged one. */
int pin_md_kernel_clear(const pin_md_layout_t *L);

#endif /* NIXTROPIC_TROPIC_PIN_MD_KERNEL_H */
