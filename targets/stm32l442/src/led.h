#ifndef _LED_H_
#define _LED_H_

#include <stdint.h>

void led_rgb(uint32_t hex);
void led_test_colors();

#define LED_PIN_G     LL_GPIO_PIN_0
#define LED_PIN_B     LL_GPIO_PIN_1
#define LED_PIN_R     LL_GPIO_PIN_2
#define LED_PORT      GPIOA

#endif
