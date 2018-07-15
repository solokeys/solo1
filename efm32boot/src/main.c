#include "em_device.h"
#include "em_chip.h"

#include "device.h"
#include "app.h"
#include "u2f.h"
#include "log.h"
#include "InitDevice.h"

void bootloader_init(void);
uint8_t REBOOT_FLAG;

int main(void)
{
    int count = 0;
    uint32_t t1 = 0;
    uint32_t t2 = 0;
    uint32_t accum = 0;
    uint32_t dt = 0;
    uint8_t hidmsg[64];
    /* Chip errata */
    CHIP_Init();

    EMU_enter_DefaultMode_from_RESET();
    CMU_enter_DefaultMode_from_RESET();
    //	ADC0_enter_DefaultMode_from_RESET();
    USART0_enter_DefaultMode_from_RESET();
    USART1_enter_DefaultMode_from_RESET();
    //	LDMA_enter_DefaultMode_from_RESET();
    CRYOTIMER_enter_DefaultMode_from_RESET();
    PORTIO_enter_DefaultMode_from_RESET();

    bootloader_init();

    set_logging_mask(
            /*0*/
           TAG_GEN|
            /*TAG_MC |*/
            /*TAG_GA |*/
            /*TAG_WALLET |*/
            TAG_STOR |
            /*TAG_CP |*/
//            TAG_CTAP|
            /*TAG_HID|*/
            /*TAG_U2F|*/
            /*TAG_PARSE |*/
//            TAG_TIME|
            /*TAG_DUMP|*/
            /*TAG_GREEN|*/
            /*TAG_RED|*/
            TAG_ERR
            );

    printf1(TAG_GEN,"Bootloader init\r\n");

    if (GPIO_PinInGet(PUSH_BUTTON) == 0)
    {
        t1 = millis();
        while(GPIO_PinInGet(PUSH_BUTTON) == 0 && (millis() - t1) < 2000)
            ;
        if (GPIO_PinInGet(PUSH_BUTTON) == 0) {
bootmode:
            printf1(TAG_GEN,"Reflash condition detected\n");
            ctaphid_init();
            reset_efm8();
            /* Infinite loop */
            int count = 0;
            while (1) {
                if (millis() - t1 > 1000)
                {
                    /*printf("heartbeat %ld\n", beat++);*/
                    heartbeat();
                    t1 = millis();
                }

                if (usbhid_recv(hidmsg) > 0)
                {
                    /*printf("%d>> ",count++); dump_hex1(TAG_DUMP, hidmsg,sizeof(hidmsg));*/
                    //		            t2 = millis();
                    ctaphid_handle_packet(hidmsg);
                    //		            accum += millis() - t2;
                    //		            printf("accum: %d\n", (uint32_t)accum);
                    //		            printf("dt: %d\n", t2 - dt);
                    //		            dt = t2;
//                    memset(hidmsg, 0, sizeof(hidmsg));
                }
                else
                {
                    /*main_loop_delay();*/
                }
                ctaphid_check_timeouts();

                if (REBOOT_FLAG) break;
            }

//            delay(100);

        }
    }

    printf1(TAG_GEN,"Normal boot\n");

    if (is_authorized_to_boot())
    {
        BOOT_boot();
    } else {
        printf1(TAG_GEN,"Warning: not authorized to boot\n");
        goto bootmode;
    }

}
