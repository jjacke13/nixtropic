/*
 * TROPIC01 power-up + libtropic L1/L2 (and L3 in M4) round-trips.
 *
 * Public API:
 *   tropic_init()           — power up chip, configure SPI AF, run lt_init
 *   tropic_l2_sweep()       — Phase 1 printf-based sweep (CDC console)
 *   tropic_chip_id_read()   — structured read of chip_id (128 B) for HID RPC
 *
 * Phase 3 M3 adds the structured tropic_chip_id_read. Phase 1's
 * tropic_l2_sweep is kept for the CDC console path (Phase 1 validate-phase1.sh
 * still calls it). Both share the same global lt_handle_t.
 */

#ifndef NIXTROPIC_TROPIC_H
#define NIXTROPIC_TROPIC_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Power up TROPIC01, configure SPI1 GPIO AF mux, run lt_init.
 *
 * Sequence:
 *   1. Configure PA5/6/7 → AF5 (SPI1 SCK/MISO/MOSI)
 *   2. Drive PA0 HIGH (TROPIC01 power switch enable)
 *   3. HAL_Delay(50) for chip stabilization
 *   4. Populate lt_dev_stm32u5xx_t struct, call lt_init
 *
 * @return 0 on success; non-zero on failure (see error codes in source).
 */
int tropic_init(void);

/**
 * @brief Run the Phase 1 L2 sweep and emit results to printf.
 *
 * Calls in order:
 *   - lt_get_info_chip_id
 *   - lt_get_info_riscv_fw_ver
 *   - lt_get_info_spect_fw_ver
 *   - lt_get_info_fw_bank for FW1, FW2, SPECT1, SPECT2
 *
 * Prints `[chip_id]`, `[riscv_fw]`, `[spect_fw]`, `[fw_bank ...]` lines
 * over USB CDC for host-side validate-phase1.sh.
 *
 * @return 0 on success; non-zero if any L2 call failed.
 */
int tropic_l2_sweep(void);

/**
 * @brief Read TROPIC01 chip ID into the caller's buffer (no printf).
 *
 * Calls lt_get_info_chip_id. Output is 128 bytes — the same layout the
 * stock TS1302 firmware returns, the same bytes lt-util prints when
 * given `-i`. Used by the HID RPC LT_RPC_CMD_CHIP_ID handler.
 *
 * @param  out       Destination buffer (must be at least 128 bytes)
 * @param  out_size  Size of `out`; must be >= 128
 * @return 128 on success; negative on failure (e.g., libtropic err).
 */
int tropic_chip_id_read(uint8_t *out, size_t out_size);

/**
 * @brief Lazily open the L3 secure session (idempotent).
 *
 * First call: reads cert store, extracts STPUB, calls lt_session_start
 * with default sh0_prod0 pairing keys. Subsequent calls: no-op.
 *
 * @return 0 on success; negative libtropic error on failure.
 */
int tropic_l3_session_ensure(void);

/**
 * @brief Generate an ECC keypair in the given slot.
 * @param slot   0..31
 * @param curve  0 = Ed25519, 1 = P-256
 */
int tropic_ecc_generate(uint8_t slot, uint8_t curve);

/**
 * @brief Read the ECC public key from a slot.
 * @return number of pubkey bytes (32 for Ed25519, 64 for P-256), or negative.
 */
int tropic_ecc_pubkey_read(uint8_t slot, uint8_t *out, size_t out_size);

/**
 * @brief Sign a message with the Ed25519 key in `slot`. Always returns 64 B sig.
 */
int tropic_ecc_eddsa_sign(uint8_t slot, const uint8_t *msg, size_t msg_len,
                          uint8_t *sig, size_t sig_size);

/**
 * @brief Erase the key in the given ECC slot (returns OK whether or not the
 *        slot was occupied).
 */
int tropic_ecc_erase(uint8_t slot);

/**
 * @brief Ensure SH0 has UAP access for ECC ops on `slot`.
 *
 * TROPIC01 R-config divides ECC slots into 4 groups of 8 (0..7, 8..15,
 * 16..23, 24..31).  Each group has independent per-pairing-key access
 * bits.  Factory default on our chip authorizes SH0 for groups
 * 0..23 but NOT 24..31 — calling lt_ecc_key_generate on slot ≥24 with
 * the SH0 session returns LT_L3_UNAUTHORIZED (21).
 *
 * Phase 7 OpenPGP uses slots 29/30/31 (per plan §4.6).  We must
 * authorize SH0 for the slot-24..31 group on first use.  R-config
 * writes are mutable until `lt_set_config_to_i_config` is called
 * (which we don't), so this works fine and persists across power
 * cycles.
 *
 * Authorizes generate / read / erase / eddsa_sign operations.
 * Idempotent: if the bits are already set, no write happens.
 *
 * @return 0 on success, negative on chip error.
 */
int tropic_ecc_ensure_slot_authorized(uint8_t slot);

/**
 * @brief Write `len` bytes to TROPIC01 R-mem slot. Requires open L3 session.
 *
 * Slot range: 0..511. Caller is responsible for ensuring the slot was
 * erased before writing (R-mem is write-once-until-erased per TROPIC01
 * spec). For atomic overwrite semantics, callers prefer the
 * `tropic_rmem_erase + tropic_rmem_write` sequence.
 *
 * @return 0 on success; negative libtropic error code otherwise.
 */
int tropic_rmem_write(uint16_t slot, const uint8_t *data, size_t len);

/**
 * @brief Read up to `max` bytes from R-mem slot into `out`. Sets *actual
 *        to the number of bytes written. Returns 0 on success.
 *
 * @return 0 on success; negative libtropic error code otherwise.
 */
int tropic_rmem_read(uint16_t slot, uint8_t *out, size_t max, size_t *actual);

/**
 * @brief Erase a single R-mem slot. Returns OK whether or not the slot
 *        was previously populated.
 */
int tropic_rmem_erase(uint16_t slot);

/**
 * @brief Get `len` random bytes from TROPIC01's TRNG. Requires open L3
 *        session. For < 256 B at a time (libtropic random is L3-only,
 *        single-call).
 *
 * @return 0 on success; negative libtropic error code otherwise.
 */
int tropic_random(uint8_t *out, size_t len);

/**
 * @brief Initialize TROPIC01 monotonic counter `idx` (0..15) to `value`.
 *        TROPIC01 counters DECREMENT — init with a high value, each
 *        update brings it toward 0. At 0, further updates return error.
 *        Safe to call on an already-initialized counter (resets it).
 *
 * @return 0 on success; negative libtropic error code otherwise.
 */
int tropic_mcounter_init(uint8_t idx, uint32_t value);

/**
 * @brief Decrement TROPIC01 monotonic counter `idx` by 1. Atomic on chip.
 *
 * @return 0 on success; negative libtropic error code otherwise.
 */
int tropic_mcounter_update(uint8_t idx);

/**
 * @brief Read TROPIC01 monotonic counter `idx`. Out parameter receives
 *        the current chip value (high values = "still has remaining").
 *
 * @return 0 on success; negative libtropic error code otherwise.
 */
int tropic_mcounter_get(uint8_t idx, uint32_t *out_value);

/**
 * @brief Execute one MAC-and-Destroy probe on slot `idx` (0..127).
 *        See docs/PHASE-5-M4-DESIGN.md for semantics — a slot must be
 *        called 3 times during init (init/consume/re-init), and exactly
 *        once on a wrong-PIN attempt (consume → permanently destroyed).
 *
 * @param idx       M&D slot index (0..127)
 * @param data_out  Input to chip (32 B)
 * @param data_in   Output from chip (32 B) — caller-allocated
 * @return 0 on success; negative libtropic error code otherwise.
 */
int tropic_mac_and_destroy(uint8_t idx, const uint8_t *data_out, uint8_t *data_in);

#endif /* NIXTROPIC_TROPIC_H */
