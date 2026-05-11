/*
 * Phase 5 M4 — MAC-and-Destroy-backed PIN retry counter.
 *
 * Wraps TROPIC01's MAC-and-Destroy primitive into a PIN verification
 * scheme where wrong attempts physically consume hardware slots. After
 * SLOTS_MD_ROUNDS (8) wrong attempts, the slots are destroyed at the
 * silicon level and PIN entry is permanently locked until factory_reset.
 *
 * The scheme is the canonical Tropic Square recipe — see
 * `docs/PHASE-5-M4-DESIGN.md` for the full algorithm + security analysis.
 *
 * Operates on top of slots.h's M&D state (`slots_global_md_*`).
 */

#ifndef NIXTROPIC_FIDO_HID_PIN_MD_H
#define NIXTROPIC_FIDO_HID_PIN_MD_H

#include <stdint.h>
#include <stddef.h>

#define PIN_MD_MASTER_SECRET_LEN  32u
#define PIN_MD_INTERNAL_KEY_LEN   32u

/* PIN material used by the M&D scheme. We use SHA-256(raw_PIN)[:16] —
 * matching what M3 stores in R-mem (slots_global_pin_set hash) and what
 * the platform sends in pinHashEnc for getPinToken. This way the scheme
 * works identically from setPin (raw PIN available) and from getPinToken
 * (only hash available). */
#define PIN_MD_MATERIAL_LEN  16u

/**
 * @brief Initialize the M&D PIN scheme.
 *
 * Generates a random master_secret from TROPIC01 TRNG, derives per-slot
 * encryption keys via M&D probes (3 chip calls each: init/consume/
 * re-init), encrypts master_secret with each derived key, stores
 * ciphertexts + verification tag in R-mem slot 0, and zeros all
 * intermediate values.
 *
 * @param pin_material  16 B PIN material (typically SHA-256(PIN)[:16])
 * @return 0 on success; negative on chip/setup error
 */
int pin_md_setup(const uint8_t pin_material[PIN_MD_MATERIAL_LEN]);

/**
 * @brief Verify submitted PIN material against the M&D state.
 *
 * Advances the next-slot pointer FIRST (committed to R-mem before
 * crypto — power-loss-safe). Probes the slot via M&D, derives the
 * encryption key, attempts to recover the master_secret. If the
 * recovered tag matches the stored tag, PIN was correct → re-initialize
 * all slots + reset pointer. If mismatch, slot is gone (forever); next
 * attempt uses next slot.
 *
 * @param pin_material   16 B PIN material to verify
 * @param out_correct    1 if PIN matched, 0 if wrong
 * @return 0 on success (verify ran, *out_correct is valid); -1 on chip
 *         error; -2 if no attempts remain (HW-enforced lockout)
 */
int pin_md_verify(const uint8_t pin_material[PIN_MD_MATERIAL_LEN],
                  int *out_correct);

/**
 * @brief Has setPin been completed (M&D state active)?
 */
int pin_md_is_active(void);

/**
 * @brief How many wrong PIN attempts remain before HW-lockout.
 *        Returns SLOTS_MD_ROUNDS - next_slot.
 */
int pin_md_attempts_remaining(void);

#endif /* NIXTROPIC_FIDO_HID_PIN_MD_H */
