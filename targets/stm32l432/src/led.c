// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>
#include <stdio.h>

#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_tim.h"

#include "led.h"
#include "device.h"
#include "log.h"

// normalization formula: 16.06*x^0.33 = (0%-100%)
// here values: value * 10
uint8_t norm_k[] = {
	0,   80,  101, 115, 127, 137, 145, 153, 159, 166,
	172, 177, 182, 187, 192, 196, 200, 205, 208, 212,
	216, 219, 223, 226, 229, 232, 235, 238, 241, 245};
#define norm_k_len sizeof(norm_k)

uint32_t led_normalization(uint8_t value)
{
	if (value > norm_k_len - 1)
	{
		return value * 10;
	} else {
		return norm_k[value];
	}
}

void led_rgb(uint32_t hex)
{
    uint32_t r = led_normalization((hex >> 16) & 0xff);
    uint32_t g = led_normalization((hex >> 8) & 0xff);
    uint32_t b = led_normalization(hex & 0xff);

    // CCR2 == blue
    // CCR3 == red
    // CCR4 == green

    // map and scale colors
	// normalization table values: value * 10
    TIM2->CCR2 = 1000 - (b * 100)/(256);
    TIM2->CCR3 = 1000 - (r * 100)/(256*6);
    TIM2->CCR4 = 1000 - (g * 100)/(256);
}

void led_test_colors()
{
    // Should produce pulsing of various colors
    int i = 0;
#if DEBUG_LEVEL > 0
    int j = 0;
#endif
    int inc = 1;
    uint32_t time = 0;
#define update() do {\
        i += inc;\
        if (i > 254)\
        {\
            inc *= -1;\
        }\
        else if (i == 0)\
        {\
            inc *= -1;\
        }\
        delay(2);\
        }while(0);

    while(1)
    {

        printf1(TAG_GREEN, "%d: %lu\r\n", j++, millis());

        printf1(TAG_GREEN,"white pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            led_rgb(i | (i << 8) | (i << 16));
        }

        printf1(TAG_GREEN,"blue pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            led_rgb(i);
        }

        printf1(TAG_GREEN,"green pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            led_rgb(i<<8);
        }

        printf1(TAG_GREEN,"red pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            led_rgb(i<<16);
        }

        printf1(TAG_GREEN,"purple pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            led_rgb((i<<16) | i);
        }

        printf1(TAG_GREEN,"orange pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            led_rgb((i<<16) | (i<<8));
        }

        printf1(TAG_GREEN,"yellow pulse\r\n");
        time = millis();
        while((millis() - time) < 5000)
        {
            update();
            led_rgb((i<<8) | (i<<0));
        }
    }
}
