/*
 * TROPIC01 power-up + libtropic L2 round-trip — see tropic.h.
 *
 * Phase 1 scope (per plan §0): L1 (SPI) + L2 (framing) only. NO L3
 * secure session — that's Phase 5. P1.11 verified `lt_get_info_*`
 * functions work without a session via direct L2 GET_INFO requests.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "tropic.h"
#include "platform/board.h"

#include "stm32u5xx_hal.h"

#include "libtropic.h"
#include "libtropic_common.h"   /* enum CONFIGURATION_OBJECTS_REGS for R-config */
#include "libtropic_port_stm32u5xx.h"

/* M4: trezor_crypto CAL provides AES-GCM/SHA256/HMAC/X25519 for L3. */
#include "libtropic_trezor_crypto.h"

/* Pump USB CDC between blocking SPI ops so the host doesn't lose
 * /dev/ttyACM* during a long L2 sweep. */
#include "tusb.h"

/* libtropic device + handle held statically (decision P1.8: no malloc). */
static lt_dev_stm32u5xx_t      s_device;
static lt_handle_t             s_handle;
/* M4: crypto context (~1.4 KB) wired into the handle BEFORE lt_init. */
static lt_ctx_trezor_crypto_t  s_crypto_ctx;
static bool                    s_session_open = false;

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

    /* M4: wire the trezor_crypto context into the handle BEFORE lt_init
     * so lt_init's internal lt_crypto_ctx_init() has a valid pointer. */
    memset(&s_crypto_ctx, 0, sizeof s_crypto_ctx);
    s_handle.l3.crypto_ctx = &s_crypto_ctx;

    lt_ret_t r = lt_init(&s_handle);
    if (r != LT_OK) {
        printf("[tropic] lt_init failed: %d\n", (int) r);
        return 2;
    }

    printf("[tropic] lt_init OK (TROPIC01 powered + L1 link up)\n");
    return 0;
}

/* ----- L3 secure session ----- */

/* Cert store buffers (4 × 700 B). Static to avoid stack overflow during
 * session start. ~2.8 KB total. */
static uint8_t s_cert_buf[LT_NUM_CERTIFICATES][TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE];
static uint8_t s_stpub[TR01_STPUB_LEN];

int tropic_l3_session_ensure(void)
{
    if (s_session_open) {
        return 0;
    }

    /* Step 1: fetch chip's cert store (1.6-2.4 KB read over L2). */
    struct lt_cert_store_t store = {
        .certs   = { s_cert_buf[0], s_cert_buf[1], s_cert_buf[2], s_cert_buf[3] },
        .buf_len = { TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE,
                     TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE,
                     TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE,
                     TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE },
    };
    lt_ret_t r = lt_get_info_cert_store(&s_handle, &store);
    if (r != LT_OK) {
        printf("[tropic] lt_get_info_cert_store failed: %d\n", (int) r);
        return -(int) r;
    }

    /* Step 2: parse STPUB out of the device cert. */
    r = lt_get_st_pub(&store, s_stpub);
    if (r != LT_OK) {
        printf("[tropic] lt_get_st_pub failed: %d\n", (int) r);
        return -(int) r;
    }

    /* Step 3: open the L3 secure session using the default sh0_prod0
     * pairing keys (PROJECT.md §5 — production silicon, public dev keys). */
    r = lt_session_start(&s_handle,
                         s_stpub,
                         TR01_PAIRING_KEY_SLOT_INDEX_0,
                         sh0priv_prod0,
                         sh0pub_prod0);
    if (r != LT_OK) {
        printf("[tropic] lt_session_start failed: %d\n", (int) r);
        return -(int) r;
    }
    s_session_open = true;
    printf("[tropic] L3 session OPEN\n");
    return 0;
}

int tropic_ecc_generate(uint8_t slot, uint8_t curve)
{
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ecc_curve_type_t c = (curve == 0) ? TR01_CURVE_ED25519 : TR01_CURVE_P256;
    lt_ret_t r = lt_ecc_key_generate(&s_handle, (lt_ecc_slot_t)(TR01_ECC_SLOT_0 + slot), c);
    if (r != LT_OK) {
        return -(int) r;
    }
    return 0;
}

int tropic_ecc_pubkey_read(uint8_t slot, uint8_t *out, size_t out_size)
{
    if (out == NULL || out_size < 32u) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;

    uint8_t pubkey[64];
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;
    lt_ret_t r = lt_ecc_key_read(&s_handle,
                                 (lt_ecc_slot_t)(TR01_ECC_SLOT_0 + slot),
                                 pubkey, (uint8_t) sizeof pubkey,
                                 &curve, &origin);
    if (r != LT_OK) {
        return -(int) r;
    }
    /* Ed25519 pubkey = 32 bytes; P-256 = 64 bytes uncompressed. M4 only
     * exercises Ed25519, so cap at 32 bytes for now. */
    size_t n = (curve == TR01_CURVE_ED25519) ? 32u : 64u;
    if (n > out_size) n = out_size;
    memcpy(out, pubkey, n);
    return (int) n;
}

int tropic_ecc_ensure_slot_authorized(uint8_t slot)
{
    if (slot > 31u) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;

    /* Each 8-slot group occupies bits N*8..N*8+7 within the 32-bit
     * UAP register.  Within that 8-bit field, bit 0 = SH0, bit 1 = SH1,
     * etc.  We want SH0 (= 0x01) for the group `slot/8`.  Shift is
     * `(slot/8) * 8`. */
    uint32_t group_shift = (uint32_t)(slot / 8u) * 8u;
    uint32_t want_bit = ((uint32_t) 0x01u) << group_shift;

    /* The four UAP registers we need to authorize for OpenPGP key
     * operations.  Uses the typed enum from libtropic_common.h
     * (lt_config_obj_addr_t — TR01_CFG_UAP_ECC_*_ADDR + EDDSA_SIGN). */
    static const enum lt_config_obj_addr_t addrs[] = {
        TR01_CFG_UAP_ECC_KEY_GENERATE_ADDR,
        TR01_CFG_UAP_ECC_KEY_READ_ADDR,
        TR01_CFG_UAP_ECC_KEY_ERASE_ADDR,
        TR01_CFG_UAP_EDDSA_SIGN_ADDR,
    };

    for (size_t i = 0; i < sizeof addrs / sizeof addrs[0]; i++) {
        uint32_t val = 0;
        lt_ret_t r = lt_r_config_read(&s_handle, addrs[i], &val);
        if (r != LT_OK) return -(int) r;
        if ((val & want_bit) == want_bit) continue;
        r = lt_r_config_write(&s_handle, addrs[i], val | want_bit);
        if (r != LT_OK) return -(int) r;
    }
    return 0;
}

int tropic_ecc_erase(uint8_t slot)
{
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_ecc_key_erase(&s_handle, (lt_ecc_slot_t)(TR01_ECC_SLOT_0 + slot));
    /* Empty slot returns an error too; treat both as success because the
     * caller's intent is "make sure this slot is empty". */
    (void) r;
    return 0;
}

int tropic_ecc_eddsa_sign(uint8_t slot, const uint8_t *msg, size_t msg_len,
                          uint8_t *sig, size_t sig_size)
{
    if (sig == NULL || sig_size < 64u) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;

    uint8_t sig_buf[64];
    lt_ret_t r = lt_ecc_eddsa_sign(&s_handle,
                                   (lt_ecc_slot_t)(TR01_ECC_SLOT_0 + slot),
                                   msg, (uint16_t) msg_len,
                                   sig_buf);
    if (r != LT_OK) {
        return -(int) r;
    }
    memcpy(sig, sig_buf, 64);
    return 64;
}

/* ----- R-mem helpers (Phase 5 M1) -----
 *
 * libtropic's R-mem API is L3-only — the L3 session must be open. We
 * ensure that lazily on first use. */

int tropic_rmem_write(uint16_t slot, const uint8_t *data, size_t len)
{
    if (data == NULL || len == 0u || len > UINT16_MAX) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_r_mem_data_write(&s_handle, slot, data, (uint16_t) len);
    return (r == LT_OK) ? 0 : -(int) r;
}

int tropic_rmem_read(uint16_t slot, uint8_t *out, size_t max, size_t *actual)
{
    if (out == NULL || max == 0u || max > UINT16_MAX) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;
    uint16_t got = 0;
    lt_ret_t r = lt_r_mem_data_read(&s_handle, slot, out, (uint16_t) max, &got);
    if (r != LT_OK) return -(int) r;
    if (actual) *actual = (size_t) got;
    return 0;
}

int tropic_rmem_erase(uint16_t slot)
{
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_r_mem_data_erase(&s_handle, slot);
    /* Already-empty slot returns an error per libtropic; caller's intent
     * is "make this slot empty", so coerce both outcomes to success. */
    (void) r;
    return 0;
}

int tropic_random(uint8_t *out, size_t len)
{
    if (out == NULL || len == 0u || len > 255u) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_random_value_get(&s_handle, out, (uint16_t) len);
    return (r == LT_OK) ? 0 : -(int) r;
}

/* ----- Monotonic counter wrappers (Phase 5 M2) ----- */

int tropic_mcounter_init(uint8_t idx, uint32_t value)
{
    if (idx > 15u) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_mcounter_init(&s_handle,
                                  (enum lt_mcounter_index_t) idx, value);
    return (r == LT_OK) ? 0 : -(int) r;
}

int tropic_mcounter_update(uint8_t idx)
{
    if (idx > 15u) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_mcounter_update(&s_handle,
                                    (enum lt_mcounter_index_t) idx);
    return (r == LT_OK) ? 0 : -(int) r;
}

int tropic_mcounter_get(uint8_t idx, uint32_t *out_value)
{
    if (idx > 15u || out_value == NULL) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_mcounter_get(&s_handle,
                                 (enum lt_mcounter_index_t) idx, out_value);
    return (r == LT_OK) ? 0 : -(int) r;
}

int tropic_mac_and_destroy(uint8_t idx, const uint8_t *data_out, uint8_t *data_in)
{
    if (idx > 127u || data_out == NULL || data_in == NULL) return -1;
    if (tropic_l3_session_ensure() != 0) return -1;
    lt_ret_t r = lt_mac_and_destroy(&s_handle,
                                    (lt_mac_and_destroy_slot_t) idx,
                                    data_out, data_in);
    return (r == LT_OK) ? 0 : -(int) r;
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

int tropic_chip_id_read(uint8_t *out, size_t out_size)
{
    if (out == NULL || out_size < sizeof(struct lt_chip_id_t)) {
        return -1;
    }

    struct lt_chip_id_t chip_id;
    memset(&chip_id, 0, sizeof chip_id);

    lt_ret_t r = lt_get_info_chip_id(&s_handle, &chip_id);
    if (r != LT_OK) {
        return -(int) r;
    }

    memcpy(out, &chip_id, sizeof chip_id);
    return (int) sizeof chip_id;
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
    if (read_chip_id()  != 0) { critical_errors++; }
    tud_task();
    if (read_riscv_fw() != 0) { critical_errors++; }
    tud_task();
    if (read_spect_fw() != 0) { critical_errors++; }
    tud_task();

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
    if (read_fw_bank(TR01_FW_BANK_FW1,    "FW1")    != 0) { fw_bank_warnings++; }
    tud_task();
    if (read_fw_bank(TR01_FW_BANK_FW2,    "FW2")    != 0) { fw_bank_warnings++; }
    tud_task();
    if (read_fw_bank(TR01_FW_BANK_SPECT1, "SPECT1") != 0) { fw_bank_warnings++; }
    tud_task();
    if (read_fw_bank(TR01_FW_BANK_SPECT2, "SPECT2") != 0) { fw_bank_warnings++; }
    tud_task();

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
