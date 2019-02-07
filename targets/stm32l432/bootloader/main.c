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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "stm32l4xx_ll_rcc.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx.h"

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "app.h"
#include "memory_layout.h"
#include "init.h"


uint8_t REBOOT_FLAG = 0;


void  BOOT_boot(void)
{
  typedef void (*pFunction)(void);

  uint32_t *bootAddress = (uint32_t *)(APPLICATION_START_ADDR);

  /* Set new vector table */
  SCB->VTOR = APPLICATION_START_ADDR;

  /* Read new SP and PC from vector table */
  __set_MSP(bootAddress[0]);
  ((pFunction)bootAddress[1])();
}

int main(int argc, char * argv[])
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;
    uint32_t stboot_time = 0;
    uint32_t boot = 1;

    set_logging_mask(
            /*0*/
            TAG_GEN|
            // TAG_MC |
            // TAG_GA |
            // TAG_WALLET |
            TAG_STOR |
            // TAG_CP |
            // TAG_CTAP|
           // TAG_HID|
            /*TAG_U2F|*/
            // TAG_PARSE |
           // TAG_TIME|
           // TAG_DUMP|
           // TAG_DUMP2|
            TAG_BOOT|
            TAG_EXT|
            TAG_GREEN|
            TAG_RED|
            TAG_ERR
            );

    // device_init();
    
    init_gpio();

    init_millisecond_timer(1);

#if DEBUG_LEVEL > 0
        init_debug_uart();
#endif

    printf1(TAG_GEN,"init device\n");

    t1 = millis();
    while(device_is_button_pressed())
    {
        if ((millis() - t1) > 2000)
        {
            boot = 0;
            break;
        }
    }


#ifdef SOLO_HACKER
    if (!is_bootloader_disabled())
    {
        stboot_time = millis();
        if ( RCC->CSR & (1<<29) )// check if there was independent watchdog reset
        {
            RCC->CSR |= (1<<23); // clear reset flags
            goto start_bootloader;
        }
    }
#endif

    if (is_authorized_to_boot() && (boot || is_bootloader_disabled()))
    {
        BOOT_boot();
    }
    else
    {

        printf1(TAG_RED,"Not authorized to boot (%08x == %08lx)\r\n", AUTH_WORD_ADDR, *(uint32_t*)AUTH_WORD_ADDR);
    }
    start_bootloader:

    SystemClock_Config();
    init_gpio();
    init_millisecond_timer(0);
    init_pwm();
    init_rng();
    usbhid_init();

    printf1(TAG_GEN,"init usb\n");

    ctaphid_init();
    printf1(TAG_GEN,"init ctaphid\n");

    memset(hidmsg,0,sizeof(hidmsg));

    printf1(TAG_GEN,"recv'ing hid msg \n");


    while(1)
    {
        if (millis() - t1 > HEARTBEAT_PERIOD)
        {
            bootloader_heartbeat();
            t1 = millis();
        }

        device_manage();

        if (usbhid_recv(hidmsg) > 0)
        {
            ctaphid_handle_packet(hidmsg);
            memset(hidmsg, 0, sizeof(hidmsg));
        }
        else
        {
        }
        ctaphid_check_timeouts();

        if (REBOOT_FLAG)
        {
            delay(250);
            device_reboot();
        }
#ifdef SOLO_HACKER
        // Boot ST bootloader if button is held for 5s
        if (!device_is_button_pressed())
        {
            stboot_time = millis();
        }
        if ((millis() - stboot_time) > 5000)
        {
            boot_st_bootloader();
        }
#endif
    }

    // Should never get here
    usbhid_close();
    printf1(TAG_GREEN, "done\n");
    return 0;
}
