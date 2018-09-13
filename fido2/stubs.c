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
#include "device.h"
#include "util.h"
#include "ctap.h"
#include "u2f.h"

#if defined(STUB_CTAPHID) || defined(STUB_CTAP)



void ctap_init()
{
    printf("STUB: ctap_init\n");
}
#endif

#if defined(STUB_CTAPHID)
void ctaphid_init()
{
    printf("STUB: ctaphid_init\n");
}
void ctaphid_handle_packet(uint8_t * hidmsg)
{
    printf("STUB: ctaphid_handle_packet\n");
}

void ctaphid_check_timeouts()
{

}

#endif


#ifdef STUB_CTAP

void ctap_reset_state()
{
    printf("STUB: ctap_reset_state\n");
}

void ctap_response_init(CTAP_RESPONSE * resp)
{
}

void u2f_request(struct u2f_request_apdu* req, CTAP_RESPONSE * resp)
{
    printf("STUB: u2f_request\n");
}

uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    printf("STUB: ctap_request\n");
    return 0;
}
#endif
