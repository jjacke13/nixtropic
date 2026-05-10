/*
 * Direct SPI1 driver — used by Phase 2 cdc_protocol/ for raw USB↔SPI passthrough.
 *
 * In Phase 1 the SPI peripheral was driven via libtropic's hal/stm32/stm32u5xx
 * port. Phase 2 talks to TROPIC01 in pure byte-passthrough mode (host runs
 * libtropic), so we own the SPI peripheral directly.
 *
 * Mode 0, MSB-first, 8-bit, soft NSS. Default prescaler /16 → 3 MHz at 48 MHz fclk.
 * SPI peripheral config matches libtropic_port_stm32u5xx.c verbatim so wire
 * timing is identical to Phase 1 + stock fw.
 */

#ifndef NIXTROPIC_PLATFORM_SPI_H
#define NIXTROPIC_PLATFORM_SPI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Initialize SPI1 peripheral + GPIO AF mux on PA5/6/7 + CS pin output on PA4.
 * RCC clocks for SPI1 and GPIOA assumed enabled by caller (gpio_init() handles
 * GPIOA; this function enables SPI1's own RCC bit).
 * Returns 0 on success, non-zero on HAL error. */
int spi_init(void);

/* CS line manual control on PA4 (active-low: LOW = chip selected). */
void spi_cs_assert(void);
void spi_cs_release(void);
bool spi_cs_is_asserted(void);

/* Blocking full-duplex transfer. tx and rx may alias for in-place transfer.
 * Returns 0 on success, non-zero on HAL error. */
int spi_transfer(const uint8_t *tx, uint8_t *rx, size_t n);

/* Prescaler control for the CLKDIV command. Allowed: 2, 4, 8, 16, 32, 64, 128, 256.
 * spi_set_prescaler_div returns 0 on success; -1 if CS currently asserted
 * (refuse mid-transaction); -2 if div not in allowed set; -3 on HAL error. */
uint32_t spi_get_prescaler_div(void);
int spi_set_prescaler_div(uint32_t div);

#endif /* NIXTROPIC_PLATFORM_SPI_H */
