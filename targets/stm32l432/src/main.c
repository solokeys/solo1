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
#include "openpgplib.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include APP_CONFIG

#if !defined(TEST)

extern void (*_spreinit_array []) (void) __attribute__((weak));
extern void (*_epreinit_array [])(void) __attribute__((weak));
extern void (*_sinit_array [])(void) __attribute__((weak));
extern void (*_einit_array [])(void) __attribute__((weak));

int main(int argc, char *argv[])
{
    // Call C++ static initializers.
    // ('preinit_array' functions are unlikely if the user
    //  doesn't define any, I think. But check for them anyways.)
    int cpp_count = 0;
    int cpp_size = &(_epreinit_array[0]) - &(_spreinit_array[0]);
    for (cpp_count = 0; cpp_count < cpp_size; ++cpp_count) {
        _spreinit_array[cpp_count]();
    }
    // ('init_array' sections call static constructors)
    cpp_size = &(_einit_array[0]) - &(_sinit_array[0]);
    for (cpp_count = 0; cpp_count < cpp_size; ++cpp_count) {
        _sinit_array[cpp_count]();
    }
    
    uint8_t hidmsg[64];
    uint32_t t1 = 0;

    set_logging_mask(
		/*0*/
		//TAG_GEN|
		// TAG_MC |
		// TAG_GA |
		TAG_WALLET |
		TAG_STOR |
		//TAG_NFC_APDU |
		TAG_NFC |
		//TAG_CP |
		// TAG_CTAP|
		//TAG_HID|
		TAG_U2F|
        TAG_OPENPGP|
		//TAG_PARSE |
		//TAG_TIME|
		// TAG_DUMP|
		TAG_GREEN|
		TAG_RED|
        TAG_EXT|
        TAG_CCID|
		TAG_ERR
	);

    device_init(argc, argv);
    OpenpgpInit();

    memset(hidmsg,0,sizeof(hidmsg));


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