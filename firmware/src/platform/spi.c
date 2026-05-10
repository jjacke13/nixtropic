/*
 * SPI1 driver — see spi.h.
 *
 * Peripheral config copied verbatim from libtropic_port_stm32u5xx.c so wire
 * behavior on SPI1 is byte-identical to Phase 1 (and stock fw).
 */

#include "spi.h"

#include <string.h>

#include "stm32u5xx_hal.h"

#include "board.h"

static SPI_HandleTypeDef s_spi;
static volatile bool     s_cs_asserted = false;

static int prescaler_div_to_hal(uint32_t div, uint32_t *out)
{
    switch (div) {
    case 2:   *out = SPI_BAUDRATEPRESCALER_2;   return 0;
    case 4:   *out = SPI_BAUDRATEPRESCALER_4;   return 0;
    case 8:   *out = SPI_BAUDRATEPRESCALER_8;   return 0;
    case 16:  *out = SPI_BAUDRATEPRESCALER_16;  return 0;
    case 32:  *out = SPI_BAUDRATEPRESCALER_32;  return 0;
    case 64:  *out = SPI_BAUDRATEPRESCALER_64;  return 0;
    case 128: *out = SPI_BAUDRATEPRESCALER_128; return 0;
    case 256: *out = SPI_BAUDRATEPRESCALER_256; return 0;
    default:  return -1;
    }
}

static uint32_t prescaler_hal_to_div(uint32_t hal)
{
    switch (hal) {
    case SPI_BAUDRATEPRESCALER_2:   return 2;
    case SPI_BAUDRATEPRESCALER_4:   return 4;
    case SPI_BAUDRATEPRESCALER_8:   return 8;
    case SPI_BAUDRATEPRESCALER_16:  return 16;
    case SPI_BAUDRATEPRESCALER_32:  return 32;
    case SPI_BAUDRATEPRESCALER_64:  return 64;
    case SPI_BAUDRATEPRESCALER_128: return 128;
    case SPI_BAUDRATEPRESCALER_256: return 256;
    default: return 0;
    }
}

static void spi_pins_init(void)
{
    GPIO_InitTypeDef cfg = {0};

    /* PA5 (SCK) + PA7 (MOSI) — AF5, push-pull, no pull, high speed. */
    cfg.Pin       = BOARD_SPI_SCK_PIN | BOARD_SPI_MOSI_PIN;
    cfg.Mode      = GPIO_MODE_AF_PP;
    cfg.Pull      = GPIO_NOPULL;
    cfg.Speed     = GPIO_SPEED_FREQ_HIGH;
    cfg.Alternate = GPIO_AF5_SPI1;
    HAL_GPIO_Init(BOARD_SPI_PORT, &cfg);

    /* PA6 (MISO) — AF5 with pull-up. Stock fw + libtropic both pull up MISO. */
    cfg.Pin   = BOARD_SPI_MISO_PIN;
    cfg.Pull  = GPIO_PULLUP;
    HAL_GPIO_Init(BOARD_SPI_PORT, &cfg);

    /* PA4 (CS) — output, push-pull, default HIGH (idle). */
    HAL_GPIO_WritePin(BOARD_SPI_CS_PORT, BOARD_SPI_CS_PIN, GPIO_PIN_SET);
    GPIO_InitTypeDef cs_cfg = {0};
    cs_cfg.Pin   = BOARD_SPI_CS_PIN;
    cs_cfg.Mode  = GPIO_MODE_OUTPUT_PP;
    cs_cfg.Pull  = GPIO_PULLUP;
    cs_cfg.Speed = GPIO_SPEED_FREQ_MEDIUM;
    HAL_GPIO_Init(BOARD_SPI_CS_PORT, &cs_cfg);
}

int spi_init(void)
{
    spi_pins_init();
    BOARD_SPI_RCC_ENABLE();

    memset(&s_spi, 0, sizeof s_spi);
    s_spi.Instance                       = BOARD_SPI_INSTANCE;
    s_spi.Init.Mode                      = SPI_MODE_MASTER;
    s_spi.Init.Direction                 = SPI_DIRECTION_2LINES;
    s_spi.Init.DataSize                  = SPI_DATASIZE_8BIT;
    s_spi.Init.CLKPolarity               = SPI_POLARITY_LOW;
    s_spi.Init.CLKPhase                  = SPI_PHASE_1EDGE;
    s_spi.Init.NSS                       = SPI_NSS_SOFT;
    s_spi.Init.BaudRatePrescaler         = SPI_BAUDRATEPRESCALER_16;
    s_spi.Init.FirstBit                  = SPI_FIRSTBIT_MSB;
    s_spi.Init.TIMode                    = SPI_TIMODE_DISABLE;
    s_spi.Init.CRCCalculation            = SPI_CRCCALCULATION_DISABLE;
    s_spi.Init.CRCPolynomial             = 0x7;
    s_spi.Init.NSSPMode                  = SPI_NSS_PULSE_DISABLE;
    s_spi.Init.NSSPolarity               = SPI_NSS_POLARITY_LOW;
    s_spi.Init.FifoThreshold             = SPI_FIFO_THRESHOLD_01DATA;
    s_spi.Init.MasterSSIdleness          = SPI_MASTER_SS_IDLENESS_00CYCLE;
    s_spi.Init.MasterInterDataIdleness   = SPI_MASTER_INTERDATA_IDLENESS_00CYCLE;
    s_spi.Init.MasterReceiverAutoSusp    = SPI_MASTER_RX_AUTOSUSP_DISABLE;
    s_spi.Init.MasterKeepIOState         = SPI_MASTER_KEEP_IO_STATE_DISABLE;
    s_spi.Init.IOSwap                    = SPI_IO_SWAP_DISABLE;
    s_spi.Init.ReadyMasterManagement     = SPI_RDY_MASTER_MANAGEMENT_INTERNALLY;
    s_spi.Init.ReadyPolarity             = SPI_RDY_POLARITY_HIGH;

    if (HAL_SPI_Init(&s_spi) != HAL_OK) {
        return 1;
    }

    /* Explicitly disable autonomous-trigger mode. Default is disabled but
     * libtropic_port_stm32u5xx.c calls this — match exactly so SPI peripheral
     * state mirrors Phase 1. Without this, some STM32U5 silicon may have
     * inherited autonomous-mode bits from a previous run that affect L2
     * polling timing. */
    SPI_AutonomousModeConfTypeDef auto_cfg = {
        .TriggerState     = SPI_AUTO_MODE_DISABLE,
        .TriggerSelection = SPI_GRP1_GPDMA_CH0_TCF_TRG,
        .TriggerPolarity  = SPI_TRIG_POLARITY_RISING,
    };
    if (HAL_SPIEx_SetConfigAutonomousMode(&s_spi, &auto_cfg) != HAL_OK) {
        HAL_SPI_DeInit(&s_spi);
        return 2;
    }

    spi_cs_release();
    return 0;
}

void spi_cs_assert(void)
{
    HAL_GPIO_WritePin(BOARD_SPI_CS_PORT, BOARD_SPI_CS_PIN, GPIO_PIN_RESET);
    s_cs_asserted = true;
}

void spi_cs_release(void)
{
    HAL_GPIO_WritePin(BOARD_SPI_CS_PORT, BOARD_SPI_CS_PIN, GPIO_PIN_SET);
    s_cs_asserted = false;
}

bool spi_cs_is_asserted(void)
{
    return s_cs_asserted;
}

int spi_transfer(const uint8_t *tx, uint8_t *rx, size_t n)
{
    if (n == 0) {
        return 0;
    }
    /* HAL_SPI_TransmitReceive's tx parameter is non-const but the peripheral
     * does not modify the buffer. Cast away const safely. */
    HAL_StatusTypeDef r = HAL_SPI_TransmitReceive(
        &s_spi,
        (uint8_t *)(uintptr_t) tx,
        rx,
        (uint16_t) n,
        HAL_MAX_DELAY);
    return (r == HAL_OK) ? 0 : 1;
}

uint32_t spi_get_prescaler_div(void)
{
    return prescaler_hal_to_div(s_spi.Init.BaudRatePrescaler);
}

int spi_set_prescaler_div(uint32_t div)
{
    if (s_cs_asserted) {
        return -1;
    }
    uint32_t hal_val;
    if (prescaler_div_to_hal(div, &hal_val) != 0) {
        return -2;
    }
    HAL_SPI_DeInit(&s_spi);
    s_spi.Init.BaudRatePrescaler = hal_val;
    if (HAL_SPI_Init(&s_spi) != HAL_OK) {
        return -3;
    }
    return 0;
}
