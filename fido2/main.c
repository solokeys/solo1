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

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include APP_CONFIG

#if !defined(TEST)

int main(int argc, char * argv[])
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;

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
