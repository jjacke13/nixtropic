/* Host-test stand-in for the STM32 HAL: only HAL_GetTick, driven by the test. */
#ifndef NIXTROPIC_TESTS_STM32U5XX_HAL_H
#define NIXTROPIC_TESTS_STM32U5XX_HAL_H
#include <stdint.h>

extern uint32_t mock_tick;

static inline uint32_t HAL_GetTick(void)
{
    return mock_tick;
}
#endif
