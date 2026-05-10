/*
 * Clock subsystem bring-up — see clock.h.
 *
 * Mirrors stock TS1302 fw `sdk/drv_u5/sys.c:_sys_clock_config` minus the
 * LL idioms — we use HAL throughout for consistency with libtropic's port.
 */

#include "clock.h"

#include "stm32u5xx_hal.h"

int clock_init(void)
{
    /* Step 0: enable the PWR peripheral clock gate (RCC_AHB3ENR.PWREN).
     * On U5, PWR registers are clock-gated and silently no-op without this.
     * Symptom of forgetting: HAL_PWREx_ControlVoltageScaling times out
     * waiting for VOSRDY (which never gets set because the MODIFY_REG
     * write to PWR->VOSR didn't land). Cost us a Group B HW iteration. */
    __HAL_RCC_PWR_CLK_ENABLE();

    /* Step 1: voltage scale Range 3 (lowest power, max 50 MHz).
     * 48 MHz fits comfortably under the 50 MHz cap. Stock fw also uses Range 3. */
    if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE3) != HAL_OK) {
        return 1;
    }

    /* Step 2: enable HSE (8 MHz crystal X1) and PLL.
     *   HSE 8 MHz → PLLM = ÷2 → 4 MHz → PLLN ×96 → 384 MHz → PLLR ÷8 → 48 MHz
     */
    RCC_OscInitTypeDef osc = {0};
    osc.OscillatorType   = RCC_OSCILLATORTYPE_HSE;
    osc.HSEState         = RCC_HSE_ON;
    osc.PLL.PLLState     = RCC_PLL_ON;
    osc.PLL.PLLSource    = RCC_PLLSOURCE_HSE;
    osc.PLL.PLLM         = 2;
    osc.PLL.PLLN         = 96;
    osc.PLL.PLLP         = 2;   /* unused but legal */
    osc.PLL.PLLQ         = 2;   /* unused but legal */
    osc.PLL.PLLR         = 8;   /* SYSCLK = 384/8 = 48 MHz */
    osc.PLL.PLLRGE       = RCC_PLLVCIRANGE_1;  /* PLL input 4–8 MHz */
    osc.PLL.PLLFRACN     = 0;
    osc.PLL.PLLMBOOST    = RCC_PLLMBOOST_DIV1;

    if (HAL_RCC_OscConfig(&osc) != HAL_OK) {
        return 2;
    }

    /* Step 3: switch SYSCLK to PLL with appropriate flash latency.
     *   At Range 3 + 48 MHz, FLASH_LATENCY_1 (1 wait state) is required
     *   per RM0456 §7.3.4 (flash read access).
     */
    RCC_ClkInitTypeDef clk = {0};
    clk.ClockType     = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK
                       | RCC_CLOCKTYPE_PCLK1  | RCC_CLOCKTYPE_PCLK2
                       | RCC_CLOCKTYPE_PCLK3);
    clk.SYSCLKSource  = RCC_SYSCLKSOURCE_PLLCLK;
    clk.AHBCLKDivider = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider= RCC_HCLK_DIV1;
    clk.APB2CLKDivider= RCC_HCLK_DIV1;
    clk.APB3CLKDivider= RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_1) != HAL_OK) {
        return 3;
    }

    return 0;
}
