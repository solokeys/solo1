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
