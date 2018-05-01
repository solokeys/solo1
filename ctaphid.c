#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctaphid.h"
#include "time.h"
#include "util.h"

typedef enum
{
    IDLE = 0,
    HANDLING_REQUEST,
} CTAP_STATE;

typedef enum
{
    EMPTY = 0,
    BUFFERING,
    BUFFERED,
} CTAP_BUFFER_STATE;

#define SUCESS          0
#define SEQUENCE_ERROR  1

static int state;
static int active_cid;
static uint64_t active_cid_timestamp;
static uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
static int ctap_buffer_cmd;
static int ctap_buffer_bcnt;
static int ctap_buffer_offset;
static int ctap_packet_seq;

void ctaphid_init()
{
    state = IDLE;
    active_cid = 0;
    active_cid_timestamp = millis();
    ctap_buffer_bcnt = 0;
    ctap_buffer_offset = 0;
    ctap_packet_seq = 0;
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

static int is_cont_pkt(CTAPHID_PACKET * pkt)
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

static int buffer_packet(CTAPHID_PACKET * pkt)
{
    if (pkt->pkt.init.cmd & TYPE_INIT)
    {
        ctap_buffer_bcnt = ctaphid_packet_len(pkt);
        int pkt_len = (ctap_buffer_bcnt < CTAPHID_INIT_PAYLOAD_SIZE) ? ctap_buffer_bcnt : CTAPHID_INIT_PAYLOAD_SIZE;
        ctap_buffer_cmd = pkt->pkt.init.cmd;
        ctap_buffer_offset = pkt_len;
        ctap_packet_seq = -1;
        memmove(ctap_buffer, pkt->pkt.init.payload, pkt_len);
    }
    else
    {
        int leftover = ctap_buffer_bcnt - ctap_buffer_offset;
        int diff = leftover - CTAPHID_CONT_PAYLOAD_SIZE;
        ctap_packet_seq++;
        if (ctap_packet_seq != pkt->pkt.cont.seq)
        {
            return SEQUENCE_ERROR;
        }

        if (diff <= 0)
        {
            // only move the leftover amount
            memmove(ctap_buffer + ctap_buffer_offset, pkt->pkt.cont.payload, leftover);
            ctap_buffer_offset += leftover;
        }
        else
        {
            memmove(ctap_buffer + ctap_buffer_offset, pkt->pkt.cont.payload, CTAPHID_CONT_PAYLOAD_SIZE);
            ctap_buffer_offset += CTAPHID_CONT_PAYLOAD_SIZE;
        }
    }
    return SUCESS;
}

static int buffer_status()
{
    if (ctap_buffer_bcnt == 0)
    {
        return EMPTY;
    }
    else if (ctap_buffer_offset == ctap_buffer_bcnt)
    {
        return BUFFERED;
    }
    else
    {
        return BUFFERING;
    }
}

static int buffer_cmd()
{
    return ctap_buffer_cmd;
}

void ctaphid_handle_packet(uint8_t * pkt_raw, CTAPHID_STATUS * stat)
{
    CTAPHID_PACKET * pkt = (CTAPHID_PACKET *)(pkt_raw);

    printf("Recv packet\n");
    printf("  CID: %08x\n", pkt->cid);
    printf("  cmd: %02x\n", pkt->pkt.init.cmd);
    printf("  length: %d\n", ctaphid_packet_len(pkt));

    int ret;
    static CTAPHID_INIT_RESPONSE init_resp;

    memset(stat, 0, sizeof(CTAPHID_STATUS));

start_over:

    switch (state)
    {
        case IDLE:
            if (is_broadcast(pkt))
            {
                printf("starting a new request\n");
                state = HANDLING_REQUEST;
                buffer_packet(pkt);
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

                if (!is_cont_pkt(pkt) && buffer_status() == BUFFERING)
                {
                    printf("Error, expecting cont packet\n");
                }
                active_cid_timestamp = millis();
                ret = buffer_packet(pkt);
                if (ret == SEQUENCE_ERROR)
                {
                    printf("Sequence error\n");
                }
            }
            else if (is_timed_out())
            {
                ctaphid_init();
                printf("dropping last channel -- timeout");
                goto start_over;
            }
            else
            {
                printf("Too busy with current transaction\n");
            }
            break;
        default:
            printf("invalid state; abort\n");
            exit(1);
    }


    switch(buffer_status())
    {
        case BUFFERING:
            printf("BUFFERING\n");
            stat->status = NO_RESPONSE;
            stat->length = 0;
            stat->data= NULL;
            active_cid_timestamp = millis();
            break;
        case BUFFERED:
            switch(buffer_cmd())
            {
                case CTAPHID_INIT:
                    printf("CTAPHID_INIT\n");

                    active_cid = get_new_cid();
                    active_cid_timestamp = millis();

                    init_resp.broadcast = CTAPHID_BROADCAST_CID;
                    init_resp.cmd = CTAPHID_INIT;
                    init_resp.bcnth = (17 & 0xff00) >> 8;
                    init_resp.bcntl = (17 & 0xff) >> 0;
                    memmove(init_resp.nonce, pkt->pkt.init.payload, 8);
                    init_resp.cid = active_cid;
                    init_resp.protocol_version = 0;//?
                    init_resp.version_major = 0;//?
                    init_resp.version_minor = 0;//?
                    init_resp.build_version = 0;//?
                    init_resp.capabilities = CAPABILITY_WINK | CAPABILITY_CBOR;

                    stat->status = CTAPHID_RESPONSE;
                    stat->length = sizeof(CTAPHID_INIT_RESPONSE);
                    stat->data = (uint8_t *)&init_resp;

                    break;
                case CTAPHID_PING:
                    printf("CTAPHID_PING\n");
                    break;
                case CTAPHID_WINK:
                    printf("CTAPHID_WINK\n");
                    break;
                default:
                    printf("error, unimplemented HID cmd: %02x\r\n", buffer_cmd());
                    break;
            }
            break;
        case EMPTY:
            printf("empty buffer!\n");
        default:
            printf("invalid buffer state; abort\n");
            exit(1);
            break;
    }


}


void ctaphid_dump_status(CTAPHID_STATUS * stat)
{
    switch(stat->status)
    {
        case NO_RESPONSE:
            printf("NO_RESPONSE");
            break;
        case CTAPHID_RESPONSE:
            printf("CTAPHID_RESPONSE");
            break;
        case U2F_RESPONSE:
            printf("U2F_RESPONSE");
            break;
        case CBOR_RESPONSE:
            printf("CBOR_RESPONSE");
            break;
        default:
            printf("\ninvalid status %d; abort\n", stat->status);
            exit(1);
    }
    printf(" (%d)\n  ", stat->length);
    if (stat->length > 0)
    {
        dump_hex(stat->data, stat->length);
    }
}


