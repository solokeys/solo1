/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 * 
 * This file is part of Solo.
 * 
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 * 
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */
#include <stdint.h>
#include <stdio.h>

#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_tim.h"

#include "led.h"
#include "device.h"
#include "log.h"

void led_rgb(uint32_t hex)
{
    uint32_t r = hex >> 16;
    uint32_t g = (hex >> 8)&0xff;
    uint32_t b = hex & 0xff;

    // CCR2 == blue
    // CCR3 == red
    // CCR4 == green

    // map and scale colors
    TIM2->CCR2 = 1000 - (b * 1000)/(256);
    TIM2->CCR3 = 1000 - (r * 1000)/(256*6);
    TIM2->CCR4 = 1000 - (g * 1000)/(256);
}

void led_test_colors()
{
    // Should produce pulsing of various colors
    int i = 0;
    int j = 0;
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
