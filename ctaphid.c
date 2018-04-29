#include <stdio.h>
#include <stdlib.h>

#include "ctaphid.h"
#include "time.h"

typedef enum
{
    IDLE = 0,
    HANDLING_REQUEST,
} CTAP_STATE;

static int state;
static int active_cid;
static uint64_t active_cid_timestamp;
static uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];

void ctaphid_init()
{
    state = IDLE;
    active_cid = 0;
    active_cid_timestamp = millis();
}

uint32_t get_new_cid()
{
    static uint32_t cid = 1;
    return cid++;
}

static int is_broadcast(CTAPHID_PACKET * pkt)
{
    return (pkt->cid == CTAPHID_BROADCAST_CID);
}

static int is_init_pkt(CTAPHID_PACKET * pkt)
{
    return (pkt->pkt.init.cmd == CTAPHID_INIT);
}

static int is_active_cid(CTAPHID_PACKET * pkt)
{
    return (pkt->cid == active_cid);
}

static int is_timed_out()
{
    return (millis() - active_cid_timestamp > 500);
}



void ctaphid_handle_packet(uint8_t * pkt_raw)
{
/*HID_MESSAGE_SIZE*/
    CTAPHID_PACKET * pkt = (CTAPHID_PACKET *)(pkt_raw);

    printf("Recv packet\n");
    printf("  CID: %08x\n", pkt->cid);
    printf("  cmd: %02x\n", pkt->pkt.init.cmd);
    printf("  length: %d\n", ctaphid_packet_len(pkt));

start_over:

    switch (state)
    {
        case IDLE:
            if (is_broadcast(pkt))
            {
                printf("starting a new request\n");
                state = HANDLING_REQUEST;
                active_cid = get_new_cid();
                active_cid_timestamp = millis();
            }
            else
            {
                printf("Error, unknown request\n");
            }
            break;
        case HANDLING_REQUEST:
            if (is_active_cid(pkt))
            {
                if (is_init_pkt(pkt))
                {
                    printf("received abort request from %08x\n", pkt->cid);
                    ctaphid_init();

                }
                active_cid_timestamp = millis();
            }
            else if (is_timed_out())
            {
                ctaphid_init();
                goto start_over;
            }
            else
            {
                printf("Too busy with current transaction\n");
            }
            break;
        default:
            printf("invalid state\n");
            exit(1);
    }

}



