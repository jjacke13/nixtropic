/* Host-test stand-in for the STM32 HAL: HAL_GetTick driven by the test, plus
 * the GPIO/delay names user_presence.c uses (defined by the test that links it). */
#ifndef NIXTROPIC_TESTS_STM32U5XX_HAL_H
#define NIXTROPIC_TESTS_STM32U5XX_HAL_H
#include <stdint.h>

extern uint32_t mock_tick;

static inline uint32_t HAL_GetTick(void)
{
    return mock_tick;
}

typedef enum { GPIO_PIN_RESET = 0, GPIO_PIN_SET } GPIO_PinState;
#define GPIOA       ((void *) 0)
#define GPIOB       ((void *) 0)
#define GPIOH       ((void *) 0)
#define GPIO_PIN_3  ((uint16_t) 0x0008u)

GPIO_PinState HAL_GPIO_ReadPin(void *port, uint16_t pin);
void HAL_Delay(uint32_t ms);
#endif
