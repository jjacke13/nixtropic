/*
 * OpenPGP lifecycle (Phase 9 M4, docs/PHASE-9-M4-DESIGN.md §5, D8, D11).
 *
 * wipe (hard barriers, any failure stops it): erase ECC 29, 30, 31 →
 *      checked erase of both O3 copies (the DEC key is inside) → retire
 *      and clear PW1, PW3, RC.  Never PINs cleared or set to factory
 *      values while a key or the DEC key may remain.
 * boot: O3 read OK → use it; O3 ABSENT → bootstrap = wipe → factory PINs
 *      (fresh s) → O3 OPERATIONAL; anything else → ERROR (TERMINATE is
 *      the way out).
 * terminate: wipe → O3 TERMINATED.
 * activate: only from a cleanly read TERMINATED O3 → factory PINs → O3
 *      OPERATIONAL.
 *
 * No automatic migration from the v0.2/M3 layout (Vaios, 2026-10-16; Jan
 * approved): an old PG7R record never reads as an NXR1 record, so O3 reads
 * damaged → ERROR → the user runs TERMINATE + ACTIVATE once.
 */
#ifndef NIXTROPIC_OPENPGP_PGP_LIFECYCLE_H
#define NIXTROPIC_OPENPGP_PGP_LIFECYCLE_H

/* 0 = O3 usable (OPERATIONAL or TERMINATED); negative = ERROR. */
int pgp_lifecycle_boot(void);

/* 0 = everything OpenPGP owns wiped; negative = stopped part-way. */
int pgp_lifecycle_wipe(void);

int pgp_lifecycle_terminate(void);

/* 0 = OPERATIONAL; -1 = refused (not a clean TERMINATED); -2 = failed. */
int pgp_lifecycle_activate(void);

#endif /* NIXTROPIC_OPENPGP_PGP_LIFECYCLE_H */
