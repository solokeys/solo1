#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "cbor.h"
#include "usbhid.h"
#include "ctaphid.h"
#include "util.h"
#include "log.h"
#include "ctap.h"


static void check_ret(CborError ret)
{
    if (ret != CborNoError)
    {
        printf("CborError: %d\n", ret);
        exit(1);
    }
}

#ifndef TEST
int main(int argc, char * argv[])
{
    set_logging_mask(
            TAG_MC |
            TAG_GA |
            TAG_CP |
            TAG_CTAP |
            TAG_PARSE |
            TAG_DUMP|
            TAG_GREEN|
            TAG_RED|
            TAG_ERR
            );

    printf("init usbhid\n");
    usbhid_init();
    printf("init ctaphid\n");
    ctaphid_init();
    printf("init ctap\n");
    ctap_init();

    int count = 0;
    uint8_t hidmsg[64];
    memset(hidmsg,0,sizeof(hidmsg));

    printf("recv'ing hid msg \n");

    while(1)
    {
        usbhid_recv(hidmsg);
        printf("%d>> ",count++); dump_hex(hidmsg,sizeof(hidmsg));

        ctaphid_handle_packet(hidmsg);
        memset(hidmsg, 0, sizeof(hidmsg));
    }


    usbhid_close();
    printf("done\n");
    return 0;
}
#endif
