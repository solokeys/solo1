/*
   Copyright 2018 Conor Patrick

   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "app.h"

#include "stm32l4xx.h"

uint8_t REBOOT_FLAG = 0;


#if defined ( __CC_ARM   )
__asm void BOOT_jump(uint32_t sp, uint32_t pc)
{
  /* Set new MSP, PSP based on SP (r0)*/
  msr msp, r0
  msr psp, r0

  /* Jump to PC (r1)*/
  bx r1
}
#else
void __attribute__((optimize("O0"))) BOOT_jump(uint32_t sp, uint32_t pc)
{
  (void) sp;
  (void) pc;
  /* Set new MSP, PSP based on SP (r0)*/
  __asm("msr msp, r0");
  __asm("msr psp, r0");

  /* Jump to PC (r1)*/
  __asm("mov pc, r1");
}
#endif


void __attribute__((optimize("O0"))) BOOT_boot(void)
{
  uint32_t pc, sp;

  uint32_t *bootAddress = (uint32_t *)(APPLICATION_JUMP_ADDR);

  /* Set new vector table */
  SCB->VTOR = (uint32_t)bootAddress;

  /* Read new SP and PC from vector table */
  sp = bootAddress[0];
  pc = bootAddress[1];

  /* Do a jump by loading the PC and SP into the CPU registers */
  BOOT_jump(sp, pc);
}

int main(int argc, char * argv[])
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;
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
            TAG_GREEN|
            TAG_RED|
            TAG_ERR
            );

    device_init();
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

    if (boot && is_authorized_to_boot())
    {
        BOOT_boot();
    }
    else
    {
        printf1(TAG_RED,"Not authorized to boot\r\n");
    }

    printf1(TAG_GEN,"init ctaphid\n");
    ctaphid_init();


    memset(hidmsg,0,sizeof(hidmsg));

    printf1(TAG_GEN,"recv'ing hid msg \n");


    while(1)
    {
        if (millis() - t1 > 8)
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
            device_reboot();
        }
    }

    // Should never get here
    usbhid_close();
    printf1(TAG_GREEN, "done\n");
    return 0;
}
