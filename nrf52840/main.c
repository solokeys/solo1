/**
 * Copyright (c) 2014 - 2018, Nordic Semiconductor ASA
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 * 
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 * 
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 * 
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 * 
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */
/** @file
 *
 * @defgroup blinky_example_main main.c
 * @{
 * @ingroup blinky_example
 * @brief Blinky Example Application main file.
 *
 * This file contains the source code for a sample application to blink LEDs.
 *
 */
#define DEBUG
#include <stdbool.h>
#include <stdint.h>

#include "nrf.h"
#include "nrf_gpio.h"
#include "nrf_delay.h"
#include "nrf_drv_clock.h"
#include "nrf_drv_power.h"
#include "nrf_strerror.h"
#include "nrf_drv_rtc.h"
#include "nrf_drv_clock.h"

#include "SEGGER_RTT.h"
#include "boards.h"

#include "usb.h"


#define COMPARE_COUNTERTIME  (3UL)                                        /**< Get Compare event COMPARE_TIME seconds after the counter starts from 0. */

#ifdef BSP_LED_0
    #define TICK_EVENT_OUTPUT     BSP_LED_0                                 /**< Pin number for indicating tick event. */
#endif
#ifndef TICK_EVENT_OUTPUT
    #error "Please indicate output pin"
#endif
#ifdef BSP_LED_1
    #define COMPARE_EVENT_OUTPUT   BSP_LED_1                                /**< Pin number for indicating compare event. */
#endif
#ifndef COMPARE_EVENT_OUTPUT
    #error "Please indicate output pin"
#endif

const nrf_drv_rtc_t rtc = NRF_DRV_RTC_INSTANCE(0); /**< Declaring an instance of nrf_drv_rtc for RTC0. */

#define printf(fmt,...)  SEGGER_RTT_printf(0, fmt, ##__VA_ARGS__);


/*lint -save -e14 */
void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    error_info_t * e = (error_info_t *)info;
    SEGGER_RTT_printf(0, "Error: %d: %s at %d:%s\n",e->err_code, nrf_strerror_get(e->err_code), e->line_num, e->p_file_name);
    while(1)
        ;
}

void log_resetreason(void);



static void init_power_clock(void)
{
    ret_code_t ret;
    /* Initializing power and clock */
    ret = nrf_drv_clock_init();
    APP_ERROR_CHECK(ret);
    ret = nrf_drv_power_init(NULL);
    APP_ERROR_CHECK(ret);
    nrf_drv_clock_hfclk_request(NULL);
    nrf_drv_clock_lfclk_request(NULL);
    while (!(nrf_drv_clock_hfclk_is_running() &&
            nrf_drv_clock_lfclk_is_running()))
    {
        /* Just waiting */
    }
}


static void rtc_config(void)
{
    uint32_t err_code;

    //Initialize RTC instance
    nrf_drv_rtc_config_t config = NRF_DRV_RTC_DEFAULT_CONFIG;
    config.prescaler = 32;
    err_code = nrf_drv_rtc_init(&rtc, &config, NULL);
    APP_ERROR_CHECK(err_code);

    //Enable tick event & interrupt
    /*nrf_drv_rtc_tick_enable(&rtc,true);*/

    /*//Set compare channel to trigger interrupt after COMPARE_COUNTERTIME seconds*/
    /*err_code = nrf_drv_rtc_cc_set(&rtc,0,COMPARE_COUNTERTIME * 8,true);*/
    /*APP_ERROR_CHECK(err_code);*/

    //Power on RTC instance
    nrf_drv_rtc_enable(&rtc);
}



int main(void)
{
    /* Configure board. */
    /*bsp_board_init(BSP_INIT_LEDS);*/
    /*lfclk_config();*/
    /*SEGGER_RTT_printf(0, "Hello FIDO2\n");*/

    uint32_t count;
    int i = 0;

    printf("hello FIDO2\r\n");
    log_resetreason();
    if ((nrf_power_resetreas_get() & NRF_POWER_RESETREAS_RESETPIN_MASK) == 0)
    {
        // Hard reset. this is for engineering A sample to work for USB ...
        nrf_power_resetreas_clear(nrf_power_resetreas_get());
        nrf_gpio_cfg_output(NRF_GPIO_PIN_MAP(0,31));
        nrf_gpio_pin_clear(NRF_GPIO_PIN_MAP(0,31));
        while (1)
            ;
    }
    nrf_power_resetreas_clear(nrf_power_resetreas_get());


    init_power_clock();
    rtc_config();
    usb_init();

    while (1)
    {
        i++;
        for (int i = 0; i < LEDS_NUMBER; i++)
        {
            bsp_board_led_invert(i);
            nrf_delay_ms(25);
        }
        count = nrf_drv_rtc_counter_get(&rtc);

        printf("toggle\r\n");
        SEGGER_RTT_SetTerminal(0);
        SEGGER_RTT_printf(0, "Hello World %d!\n", count);
        SEGGER_RTT_SetTerminal(1);
        SEGGER_RTT_printf(0, "Hello World %d!\n", i);
    }
}


