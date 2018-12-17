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
#include "device.h"
#include "util.h"
#include "ctap.h"
#include "u2f.h"

#if defined(STUB_CTAPHID) || defined(STUB_CTAP)



void ctap_init()
{
    printf1(TAG_GEN,"STUB: ctap_init\n");
}
#endif

#if defined(STUB_CTAPHID)
void ctaphid_init()
{
    printf1(TAG_GEN,"STUB: ctaphid_init\n");
}
void ctaphid_handle_packet(uint8_t * hidmsg)
{
    printf1(TAG_GEN,"STUB: ctaphid_handle_packet\n");
}

void ctaphid_check_timeouts()
{

}

#endif


#ifdef STUB_CTAP

void ctap_reset_state()
{
    printf1(TAG_GEN,"STUB: ctap_reset_state\n");
}

void ctap_response_init(CTAP_RESPONSE * resp)
{
}

void u2f_request(struct u2f_request_apdu* req, CTAP_RESPONSE * resp)
{
    printf1(TAG_GEN,"STUB: u2f_request\n");
}

uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    printf1(TAG_GEN,"STUB: ctap_request\n");
    return 0;
}
#endif
