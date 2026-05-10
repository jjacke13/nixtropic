/*
 * TROPIC01 power-up + libtropic L2 round-trip — see tropic.h.
 *
 * Phase 1 scope (per plan §0): L1 (SPI) + L2 (framing) only. NO L3
 * secure session — that's Phase 5. P1.11 verified `lt_get_info_*`
 * functions work without a session via direct L2 GET_INFO requests.
 */

#include <stdio.h>
#include <string.h>

#include "tropic.h"
#include "platform/board.h"

#include "stm32u5xx_hal.h"

#include "libtropic.h"
#include "libtropic_port_stm32u5xx.h"

/* Pump USB CDC between blocking SPI ops so the host doesn't lose
 * /dev/ttyACM* during a long L2 sweep. */
#include "tusb.h"

/* libtropic device + handle held statically (decision P1.8: no malloc). */
static lt_dev_stm32u5xx_t s_device;
static lt_handle_t        s_handle;

/* ----- Helpers ----- */

static void hexprint(const char *prefix, const uint8_t *buf, size_t n)
{
    printf("%s", prefix);
    for (size_t i = 0; i < n; ++i) {
        printf(" %02x", buf[i]);
    }
    printf("\n");
}

/* ----- SPI1 GPIO AF mux + TROPIC01 power ----- */

static void spi1_pins_init(void)
{
    /* PA5 (SCK), PA6 (MISO), PA7 (MOSI) — all AF5 */
    GPIO_InitTypeDef cfg = {0};
    cfg.Pin       = BOARD_SPI_SCK_PIN | BOARD_SPI_MOSI_PIN;
    cfg.Mode      = GPIO_MODE_AF_PP;
    cfg.Pull      = GPIO_NOPULL;
    cfg.Speed     = GPIO_SPEED_FREQ_HIGH;
    cfg.Alternate = GPIO_AF5_SPI1;
    HAL_GPIO_Init(BOARD_SPI_PORT, &cfg);

    /* PA6 MISO — pull-up matches stock fw + libtropic port comment */
    cfg.Pin   = BOARD_SPI_MISO_PIN;
    cfg.Pull  = GPIO_PULLUP;
    HAL_GPIO_Init(BOARD_SPI_PORT, &cfg);
}

/* ----- libtropic init ----- */

#include "platform/rng.h"

int tropic_init(void)
{
    /* Step 1: SPI1 pin AF mux. */
    spi1_pins_init();

    /* Step 2: enable SPI1 RCC clock. (libtropic's HAL_SPI_Init expects
     * the peripheral clock to be on.) */
    BOARD_SPI_RCC_ENABLE();

    /* Step 3: TROPIC01 power-up sequence. Stock TS1302 fw cycles OFF→ON
     * to ensure clean power-on (`stock app/main.c:51-54`). */
    HAL_GPIO_WritePin(BOARD_TROPIC_PWR_PORT, BOARD_TROPIC_PWR_PIN, GPIO_PIN_RESET);
    HAL_Delay(20);   /* generous off-time so VCC fully discharges */
    HAL_GPIO_WritePin(BOARD_TROPIC_PWR_PORT, BOARD_TROPIC_PWR_PIN, GPIO_PIN_SET);
    /* TROPIC01 needs time for its own boot from Maintenance → Application.
     * Per ODN_TR01 specs, total power-on-to-Application transition can
     * be hundreds of ms. Be generous; pump USB during the wait. */
    for (int i = 0; i < 10; ++i) {
        HAL_Delay(30);
        tud_task();
    }
    /* Total post-power-on wait: ~300 ms */

    /* Step 4: populate device handle + call lt_init.
     * SPI prescaler ÷16 → 48 MHz / 16 = 3 MHz, safely below TROPIC01's
     * 5 MHz SCLK max (decision P1.3). */
    memset(&s_device, 0, sizeof s_device);
    s_device.spi_instance       = BOARD_SPI_INSTANCE;
    s_device.baudrate_prescaler = SPI_BAUDRATEPRESCALER_16;
    s_device.spi_cs_gpio_pin    = BOARD_SPI_CS_PIN;
    s_device.spi_cs_gpio_bank   = BOARD_SPI_CS_PORT;
    s_device.rng_handle         = rng_handle();

    if (s_device.rng_handle == NULL) {
        printf("[tropic] rng_handle is NULL — rng_init must run first\n");
        return 1;
    }

    s_handle.l2.device = &s_device;

    lt_ret_t r = lt_init(&s_handle);
    if (r != LT_OK) {
        printf("[tropic] lt_init failed: %d\n", (int) r);
        return 2;
    }

    printf("[tropic] lt_init OK (TROPIC01 powered + L1 link up)\n");
    return 0;
}

/* ----- L2 sweep ----- */

static int read_chip_id(void)
{
    /* lt_chip_id_t is opaque to us — TR01_L2_GET_INFO_CHIP_ID_SIZE = 128
     * bytes of structured data. We dump the raw bytes; host-side
     * validate-phase1.sh parses them or compares to the Phase 0 baseline. */
    struct lt_chip_id_t chip_id;
    memset(&chip_id, 0, sizeof chip_id);

    lt_ret_t r = lt_get_info_chip_id(&s_handle, &chip_id);
    if (r != LT_OK) {
        printf("[chip_id] FAIL ret=%d\n", (int) r);
        return 1;
    }

    /* lt_chip_id_t is a struct, but it's fundamentally 128 bytes. Treat
     * as a flat byte buffer for the dump (matches TR01_L2_GET_INFO_CHIP_ID_SIZE). */
    hexprint("[chip_id]", (const uint8_t *) &chip_id, sizeof chip_id);
    return 0;
}

static int read_riscv_fw(void)
{
    uint8_t ver[TR01_L2_GET_INFO_RISCV_FW_SIZE];
    memset(ver, 0, sizeof ver);

    lt_ret_t r = lt_get_info_riscv_fw_ver(&s_handle, ver);
    if (r != LT_OK) {
        printf("[riscv_fw] FAIL ret=%d\n", (int) r);
        return 1;
    }
    hexprint("[riscv_fw]", ver, sizeof ver);
    return 0;
}

static int read_spect_fw(void)
{
    uint8_t ver[TR01_L2_GET_INFO_SPECT_FW_SIZE];
    memset(ver, 0, sizeof ver);

    lt_ret_t r = lt_get_info_spect_fw_ver(&s_handle, ver);
    if (r != LT_OK) {
        printf("[spect_fw] FAIL ret=%d\n", (int) r);
        return 1;
    }
    hexprint("[spect_fw]", ver, sizeof ver);
    return 0;
}

static int read_fw_bank(lt_bank_id_t bank, const char *name)
{
    uint8_t header[256];   /* generous; libtropic returns header_read_size */
    uint16_t read_size = 0;

    lt_ret_t r = lt_get_info_fw_bank(&s_handle, bank, header, sizeof header, &read_size);
    if (r != LT_OK) {
        printf("[fw_bank %s] FAIL ret=%d\n", name, (int) r);
        return 1;
    }
    char prefix[32];
    snprintf(prefix, sizeof prefix, "[fw_bank %s len=%u]", name, (unsigned) read_size);
    hexprint(prefix, header, read_size);
    return 0;
}

int tropic_l2_sweep(void)
{
    /* tud_task between each step keeps USB CDC alive during the sweep
     * — each L2 call may block on SPI for ~1 sec if chip is in a
     * weird state, and we don't want host to drop /dev/ttyACM*. */

    /* Critical L2 commands — failure of any of these is a Phase 1 FAIL.
     * These exercise the L1 SPI link + L2 framing on data paths that
     * work regardless of silicon revision (chip identification + FW
     * version tags). */
    int critical_errors = 0;
    if (read_chip_id()   != 0) critical_errors++; tud_task();
    if (read_riscv_fw()  != 0) critical_errors++; tud_task();
    if (read_spect_fw()  != 0) critical_errors++; tud_task();

    /* Informational L2 commands — failures here are NOT a Phase 1 fail.
     * On ACAB silicon (the user's TR01-C2P-T101 chip) FW banks are
     * auto-managed by the chip itself, and the explicit-bank
     * GET_INFO(FW_BANK, FW1|FW2|SPECT1|SPECT2) query returns
     * LT_L2_GEN_ERR (37 — "some other error"). This is consistent with
     * the chip not exposing per-bank introspection on auto-managed silicon.
     * On ABAB silicon the same calls would succeed.
     *
     * We log the result but don't count toward Phase 1 errors, since
     * Phase 1 is "validate libtropic L1+L2 round-trip on STM32U5", not
     * "exercise every L2 command". */
    int fw_bank_warnings = 0;
    if (read_fw_bank(TR01_FW_BANK_FW1,    "FW1")    != 0) fw_bank_warnings++; tud_task();
    if (read_fw_bank(TR01_FW_BANK_FW2,    "FW2")    != 0) fw_bank_warnings++; tud_task();
    if (read_fw_bank(TR01_FW_BANK_SPECT1, "SPECT1") != 0) fw_bank_warnings++; tud_task();
    if (read_fw_bank(TR01_FW_BANK_SPECT2, "SPECT2") != 0) fw_bank_warnings++; tud_task();

    if (fw_bank_warnings > 0) {
        printf("[tropic] %d fw_bank query warnings (expected on ACAB silicon — auto-managed banks)\n",
               fw_bank_warnings);
    }

    if (critical_errors == 0) {
        printf("[tropic] L2 sweep PASS (chip_id + riscv_fw + spect_fw OK)\n");
    } else {
        printf("[tropic] L2 sweep FAIL: %d critical errors\n", critical_errors);
    }

    return critical_errors;
}
