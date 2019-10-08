// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_rcc.h"
#include "stm32l4xx_ll_system.h"
#include "stm32l4xx_ll_pwr.h"
#include "stm32l4xx_ll_utils.h"
#include "stm32l4xx_ll_cortex.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_usart.h"
#include "stm32l4xx_ll_bus.h"
#include "stm32l4xx_ll_usb.h"

#include "stm32l4xx_hal_pcd.h"

#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_hid.h"
/*#include "usbd_hid.h"*/

#include APP_CONFIG
#include "flash.h"
#include "rng.h"
#include "led.h"
#include "device.h"
#include "util.h"
#include "fifo.h"
#include "log.h"

#ifdef TEST_SOLO_STM32
#define Error_Handler() _Error_Handler(__FILE__,__LINE__)
#define PAGE_SIZE		2048
#define PAGES			128
// Pages 119-127 are data
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)


uint32_t __90_ms = 0;
#define IS_BUTTON_PRESSED()         (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN))

// Timer6 overflow handler.  happens every ~90ms.
void TIM6_DAC_IRQHandler()
{
    // timer is only 16 bits, so roll it over here
    TIM6->SR = 0;
    __90_ms += 1;
}

uint32_t millis(void)
{
    return (((uint32_t)TIM6->CNT) + (__90_ms * 90));
}

void _Error_Handler(char *file, int line)
{
    while(1)
    {
    }
}

int main(void)
{
    uint32_t i = 5;

    hw_init();

    LL_GPIO_SetPinMode(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_MODE_INPUT);
    LL_GPIO_SetPinPull(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_PULL_UP);
    flash_option_bytes_init(1);

    while (1)
    {
        uint32_t t0 = millis() % 750;
        if (! IS_BUTTON_PRESSED())
        {
            if (t0 < 750*1/3)
            {
                led_rgb(0 | (0 << 8) | (i << 17));
            }
            else if (t0 < 750*2/3)
            {
                led_rgb(0 | (i << 8) | (0 << 16));
            }
            else
            {
                led_rgb(i | (0 << 8) | (0 << 16));
            }
        }
        else
        {
            led_rgb(0x151515);
        }

    }
}

#endif
