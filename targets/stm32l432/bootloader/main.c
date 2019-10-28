// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
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

void SystemClock_Config(void);

void BOOT_boot(void)
{
  typedef void (*pFunction)(void);

  uint32_t *bootAddress = (uint32_t *)(APPLICATION_START_ADDR);

  /* Set new vector table */
  SCB->VTOR = APPLICATION_START_ADDR;

  /* Read new SP and PC from vector table */
  __set_MSP(bootAddress[0]);
  ((pFunction)bootAddress[1])();
}

int main()
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

    device_init_button();

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


    if (!is_bootloader_disabled())
    {
        stboot_time = millis();
        if ( RCC->CSR & (1<<29) )// check if there was independent watchdog reset
        {
            RCC->CSR |= (1<<23); // clear reset flags
            goto start_bootloader;
        }
    }

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

    extern volatile version_t current_firmware_version;
    printf1(TAG_BOOT,"Current firmware version address: %p\r\n", &current_firmware_version);
    printf1(TAG_BOOT,"Current firmware version: %d.%d.%d.%d (%02x.%02x.%02x.%02x)\r\n",
            current_firmware_version.major, current_firmware_version.minor, current_firmware_version.patch, current_firmware_version.reserved,
            current_firmware_version.major, current_firmware_version.minor, current_firmware_version.patch, current_firmware_version.reserved
    );
    dump_hex1(TAG_BOOT, (uint8_t*)(&current_firmware_version) - 16, 32);


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
