/*
 * OpenPGP persistent state O3 (Phase 9 M4, docs/PHASE-9-M4-DESIGN.md §5).
 *
 * One record pair (tropic/rec_pair.h), R-mem slots 33 / 43, cached in RAM
 * after it was read; every change is written through (both copies) and
 * only then taken into RAM.  O3 holds the lifecycle, the RC guard, the DOs,
 * the signature counter, DO C4 byte 0, UIF and the DEC private key (until
 * M5 wraps it).  No PIN hashes, retry mirrors or PIN lengths: the PIN
 * bindings O4/O5/O6 (pgp_pin.h) are the only PIN state (D5, D6).
 *
 * Payload (schema 1, 154 B):
 *   off  len  field
 *     0    1  lifecycle (1 OPERATIONAL, 2 TERMINATED)
 *     1    1  rc_set (guard of O6, §2.5)
 *     2    1  DO C4 byte 0, spec meaning: 00 = PW1 valid for one PSO:CDS,
 *             01 = valid until reset (default, Vaios: PIN once per plug-in)
 *     3    1  UIF (0 off, 1 on, 2 permanent) for D6/D7/D8
 *     4    1  name length (0..39), then 39 B name (DO 5B)
 *    44    2  language (DO 5F2D)
 *    46    1  sex (DO 5F35)
 *    47   60  fingerprints sig | dec | aut (DO C7..C9)
 *   107   12  generation times sig | dec | aut (DO CE..D0)
 *   119    3  signature counter (DO 93)
 *   122   32  X25519 DEC private key (all zero = none)
 *
 * The state is usable only after it was read cleanly (or written) in this
 * power cycle, and never while its pair is uncertain (a failed write):
 * openpgp_state_lifecycle() then reports PGP_LC_ERROR and every setter
 * refuses.  Getters of an unusable state return zeros / defaults; callers
 * gate on the lifecycle first.
 */
#ifndef NIXTROPIC_OPENPGP_STATE_H
#define NIXTROPIC_OPENPGP_STATE_H

#include <stddef.h>
#include <stdint.h>

#define OPENPGP_NAME_MAX         39u
#define OPENPGP_LANG_LEN          2u
#define OPENPGP_FPR_LEN          20u
#define OPENPGP_GENTIME_LEN       4u
#define OPENPGP_SIG_COUNTER_LEN   3u
#define OPENPGP_DEC_PRIV_LEN     32u

typedef enum {
    PGP_LC_ERROR = 0,           /* unread, damaged, unreadable or uncertain */
    PGP_LC_OPERATIONAL = 1,
    PGP_LC_TERMINATED = 2,
} pgp_lifecycle_t;

/* Read O3 into RAM.  0 = loaded; 1 = ABSENT (both copies empty: the
 * caller bootstraps); negative = damaged / unreadable (stays ERROR). */
int openpgp_state_load(void);

pgp_lifecycle_t openpgp_state_lifecycle(void);

/* 1 once a state was loaded or written in this power cycle (it may still
 * have become uncertain since). */
int openpgp_state_loaded(void);

/* Checked erase of both copies (the DEC key is inside).  Also the way out
 * of an uncertain pair.  0 = both copies read empty. */
int openpgp_state_clear(void);

/* (Re)initialise O3: checked erase of both copies, then the defaults of
 * that lifecycle (TERMINATED: everything zero). */
int openpgp_state_init(pgp_lifecycle_t lc);

/* TERMINATED → OPERATIONAL defaults (ACTIVATE), as one pair write. */
int openpgp_state_activate(void);

/* ---- getters (RAM) ---- */
uint8_t openpgp_state_rc_set(void);
uint8_t openpgp_state_c4_multi(void);       /* DO C4 byte 0 */
uint8_t openpgp_state_uif(void);
size_t  openpgp_state_name(uint8_t out[OPENPGP_NAME_MAX]);
void    openpgp_state_lang(uint8_t out[OPENPGP_LANG_LEN]);
uint8_t openpgp_state_sex(void);
void    openpgp_state_fingerprint(int key, uint8_t out[OPENPGP_FPR_LEN]);   /* 0 sig, 1 dec, 2 aut */
void    openpgp_state_gentime(int key, uint8_t out[OPENPGP_GENTIME_LEN]);
void    openpgp_state_sig_counter(uint8_t out[OPENPGP_SIG_COUNTER_LEN]);
/* 0 = key copied (caller wipes it); -1 = none or state unusable. */
int     openpgp_state_dec_priv_get(uint8_t out[OPENPGP_DEC_PRIV_LEN]);

/* ---- setters (OPERATIONAL only; 0 = committed in both copies) ---- */
int openpgp_state_set_rc_set(uint8_t v);
int openpgp_state_set_c4_multi(uint8_t v);
int openpgp_state_set_uif(uint8_t v);          /* -3: permanent cannot be lowered */
int openpgp_state_set_name(const uint8_t *data, size_t len);
int openpgp_state_set_lang(const uint8_t data[OPENPGP_LANG_LEN]);
int openpgp_state_set_sex(uint8_t v);
int openpgp_state_set_fingerprint(int key, const uint8_t fpr[OPENPGP_FPR_LEN]);
int openpgp_state_set_gentime(int key, const uint8_t gt[OPENPGP_GENTIME_LEN]);
int openpgp_state_sig_counter_increment(void);
int openpgp_state_dec_priv_set(const uint8_t key[OPENPGP_DEC_PRIV_LEN]);

#ifdef NIXTROPIC_HOST_TEST
void openpgp_state_test_reboot(void);
#endif

#endif /* NIXTROPIC_OPENPGP_STATE_H */
