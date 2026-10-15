/*
 * FIDO persistent state at boot and reset (Phase 9 M4, design §4, D8).
 *
 * Boot:  O1 OK → orphan scrub, PIN guard repair, signature counter must
 *        read; O1 ABSENT (first boot, interrupted reset, both copies
 *        damaged) → the checked wipe below; anything else → error, FIDO
 *        refuses all but authenticatorReset.
 * Wipe (authenticatorReset, and boot on O1 ABSENT), hard barriers in this
 *        order, any failure stops it: erase every FIDO key (ECC 0..28) →
 *        checked erase of every metadata slot (R-mem 1..29) → clear the PIN
 *        binding (retire its M&D ranges, clear O2) → fresh O1 (bitmap 0,
 *        Force-UV off, guard 0) → signature counter back to its start.
 *        Never credentials without the PIN; the counter starts again only
 *        after a completed checked wipe.
 *
 * No automatic migration from the v0.2/M3 layout (Vaios, 2026-10-16; Jan
 * approved): old records never read as valid NXR1 records, so O1 reads
 * damaged → error → the user runs authenticatorReset once.
 */
#ifndef NIXTROPIC_FIDO_HID_FIDO_STATE_H
#define NIXTROPIC_FIDO_HID_FIDO_STATE_H

#define FIDO_SIGNCOUNT_MCOUNTER  0u
#define FIDO_MCOUNTER_MAX        0xFFFFFFFEu   /* TR01_MCOUNTER_VALUE_MAX */

/* 0 = FIDO usable; negative = refuse all but authenticatorReset. */
int fido_state_boot(void);

/* 0 = everything FIDO owns wiped and fresh; negative = stopped part-way. */
int fido_state_wipe(void);

#endif /* NIXTROPIC_FIDO_HID_FIDO_STATE_H */
