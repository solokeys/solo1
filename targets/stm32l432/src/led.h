// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
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
