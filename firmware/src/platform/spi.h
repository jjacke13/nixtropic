/*
 * SPI1 bring-up — the bus to TROPIC01 on PA4/5/6/7 (NSS/SCK/MISO/MOSI, AF5).
 *
 * Mode 0, MSB-first, 8-bit, soft NSS.  Default prescaler /16 → 3 MHz
 * at 48 MHz fclk.  Peripheral config copied verbatim from libtropic's
 * upstream `hal/port/stm32/libtropic_port_stm32u5xx.c` so wire timing
 * matches the stock TS1302 firmware exactly (verified byte-faithful
 * round-trip against the stock fw).
 *
 * Boot stage 4 only (main.c): all chip traffic afterwards goes through
 * libtropic's own port (tropic/tropic.c), which drives SPI1 and the CS
 * pin itself.  The CDC SPI passthrough that also used this module was
 * removed in Phase 9 M1.
 */

#ifndef NIXTROPIC_PLATFORM_SPI_H
#define NIXTROPIC_PLATFORM_SPI_H

/* Initialize SPI1 peripheral + GPIO AF mux on PA5/6/7 + CS pin output on PA4.
 * RCC clocks for SPI1 and GPIOA assumed enabled by caller (gpio_init() handles
 * GPIOA; this function enables SPI1's own RCC bit).
 * Returns 0 on success, non-zero on HAL error. */
int spi_init(void);

#endif /* NIXTROPIC_PLATFORM_SPI_H */
