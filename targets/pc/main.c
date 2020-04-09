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
#include <time.h>

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "app.h"


void device_init(int argc, char *argv[]);
int usbhid_recv(uint8_t * msg);



int main(int argc, char *argv[])
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;

    set_logging_mask(
		/*0*/
		// TAG_GEN|
		// TAG_MC |
		// TAG_GA |
		TAG_WALLET |
		TAG_STOR |
		//TAG_NFC_APDU |
		TAG_NFC |
		// TAG_CP |
		// TAG_CTAP|
		// TAG_HID|
		TAG_U2F|
		// TAG_PARSE |
		//TAG_TIME|
		// TAG_DUMP|
		// TAG_DUMP2|
		TAG_GREEN|
		TAG_RED|
        TAG_EXT|
        TAG_CCID|
		TAG_ERR
	);

    device_init(argc, argv);

    memset(hidmsg,0,sizeof(hidmsg));


    while(1)
    {

        if (usbhid_recv(hidmsg) > 0)
        {
            ctaphid_handle_packet(hidmsg);
            memset(hidmsg, 0, sizeof(hidmsg));
        }
        else
        {
        }

        ctaphid_check_timeouts();

        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 1000*1000*10;
        nanosleep(&ts,NULL);
    }

    // Should never get here
    printf1(TAG_GREEN, "done\n");
    return 0;
}
