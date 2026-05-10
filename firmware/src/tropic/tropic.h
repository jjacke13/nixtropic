/*
 * TROPIC01 power-up + libtropic L1/L2 round-trip.
 *
 * Phase 1 D-group public API:
 *   tropic_init()          — power up chip, configure SPI AF mux, lt_init
 *   tropic_l2_sweep()      — print chip ID + RISC-V FW + SPECT FW + bank headers
 *
 * Both routines write progress / errors to USB CDC via printf.
 * Returns 0 on success, non-zero error code on failure.
 */

#ifndef NIXTROPIC_TROPIC_H
#define NIXTROPIC_TROPIC_H

#include <stdint.h>

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

#endif /* NIXTROPIC_TROPIC_H */
