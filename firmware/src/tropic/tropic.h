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

#endif /* NIXTROPIC_TROPIC_H */
