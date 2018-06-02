#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
#include "util.h"
#include "log.h"
#include "ctap.h"


#ifndef TEST

int main(int argc, char * argv[])
{
    int count = 0;
    uint64_t t1 = 0;
    uint8_t hidmsg[64];

    set_logging_mask(
            /*TAG_MC |*/
            /*TAG_GA |*/
            /*TAG_CP |*/
            TAG_CTAP|
            /*TAG_U2F|*/
            /*TAG_PARSE |*/
            TAG_TIME
            /*TAG_DUMP|*/
            /*TAG_GREEN|*/
            /*TAG_RED|*/
            /*TAG_ERR*/
            );

    printf("init device\n");
    device_init();

    printf("init ctaphid\n");
    ctaphid_init();

    printf("init ctap\n");
    ctap_init();

    memset(hidmsg,0,sizeof(hidmsg));

    printf("recv'ing hid msg \n");

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

            ctaphid_handle_packet(hidmsg);
            memset(hidmsg, 0, sizeof(hidmsg));
        }
        else
        {
            main_loop_delay();
        }
        ctaphid_check_timeouts();
    }

    // Should never get here
    usbhid_close();
    printf("done\n");
    return 0;
}

#endif
