// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include APP_CONFIG

#if !defined(TEST)

bool use_udp = true;

void usage(const char * cmd)
{
    fprintf(stderr, "Usage: %s [-b udp|hidg]\n", cmd);
    fprintf(stderr, "   -b      backing implementation: udp(default) or hidg\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;
    int opt;

    while ((opt = getopt(argc, argv, "b:")) != -1)
    {
        switch (opt)
        {
            case 'b':
                if (strcmp("udp", optarg) == 0)
                {
                    use_udp = true;
                }
                else if (strcmp("hidg", optarg) == 0)
                {
                    use_udp = false;
                }
                else
                {
                    usage(argv[0]);
                }
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    set_logging_mask(
		/*0*/
		//TAG_GEN|
		//TAG_MC |
		//TAG_GA |
		//TAG_WALLET |
		TAG_STOR |
		//TAG_NFC_APDU |
		TAG_NFC |
		//TAG_CP |
		//TAG_CTAP|
		//TAG_HID|
		//TAG_U2F|
		//TAG_PARSE |
		//TAG_TIME|
		//TAG_DUMP|
		TAG_GREEN|
		TAG_RED|
		TAG_ERR
	);

    device_init();



    memset(hidmsg,0,sizeof(hidmsg));

    // printf1(TAG_GEN,"recv'ing hid msg \n");


    while(1)
    {
        if (millis() - t1 > HEARTBEAT_PERIOD)
        {
            heartbeat();
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

    }

    // Should never get here
    usbhid_close();
    printf1(TAG_GREEN, "done\n");
    return 0;
}

#endif
