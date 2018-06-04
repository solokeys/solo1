#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"


#if !defined(TEST)

int main(int argc, char * argv[])
{
    int count = 0;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t accum = 0;
    uint8_t hidmsg[64];

    set_logging_mask(
            /*0*/
            /*TAG_GEN|*/
            /*TAG_MC |*/
            /*TAG_GA |*/
            /*TAG_CP |*/
            TAG_CTAP|
            /*TAG_HID|*/
            /*TAG_U2F|*/
            /*TAG_PARSE |*/
            /*TAG_TIME|*/
            TAG_DUMP|
            /*TAG_GREEN|*/
            /*TAG_RED|*/
            TAG_ERR
            );

    printf1(TAG_GEN,"init device\n");
    device_init();

    printf1(TAG_GEN,"init ctaphid\n");
    ctaphid_init();

    printf1(TAG_GEN,"init ctap\n");
    ctap_init();

    memset(hidmsg,0,sizeof(hidmsg));

    printf1(TAG_GEN,"recv'ing hid msg \n");


    while(1)
    {
        if (millis() - t1 > 100)
        {
            /*printf("heartbeat %ld\n", beat++);*/
            heartbeat();
            t1 = millis();
        }

        if (usbhid_recv(hidmsg) > 0)
        {
            printf1(TAG_DUMP,"%d>> ",count++); dump_hex1(TAG_DUMP, hidmsg,sizeof(hidmsg));
            t2 = millis();
            ctaphid_handle_packet(hidmsg);
            accum += millis() - t2;
            printf1(TAG_TIME,"accum: %lu\n", (uint32_t)accum);
            memset(hidmsg, 0, sizeof(hidmsg));
        }
        else
        {
            /*main_loop_delay();*/
        }
        ctaphid_check_timeouts();
    }

    // Should never get here
    usbhid_close();
    printf("done\n");
    return 0;
}

#endif


