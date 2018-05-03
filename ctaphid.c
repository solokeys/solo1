#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctaphid.h"
#include "ctap.h"
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
static uint16_t ctap_buffer_bcnt;
static int ctap_buffer_offset;
static int ctap_packet_seq;

static uint32_t _next_cid = 0;

void ctaphid_init()
{
    state = IDLE;
    active_cid = 0;
    active_cid_timestamp = millis();
    ctap_buffer_bcnt = 0;
    ctap_buffer_offset = 0;
    ctap_packet_seq = 0;
    ctap_write(NULL, -1);
}

static uint32_t set_next_cid(uint32_t cid)
{
    _next_cid = cid;
}

static uint32_t get_new_cid()
{
    static uint32_t cid = 1;

    if (_next_cid != 0)
    {
        int tmp = _next_cid;
        _next_cid = 0;
        return tmp;
    }

    return cid++;
}

static int is_broadcast(CTAPHID_PACKET * pkt)
{
    return (pkt->cid == CTAPHID_BROADCAST_CID);
}

static int is_init_pkt(CTAPHID_PACKET * pkt)
{
    return (pkt->pkt.init.cmd == CTAPHID_INIT) && ctaphid_packet_len(pkt) == 8;
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

static int buffer_len()
{
    return ctap_buffer_bcnt;
}


static void ctaphid_send_error(uint32_t cid, uint8_t error)
{
    uint8_t buf[HID_MESSAGE_SIZE];
    memset(buf,0,sizeof(buf));
    CTAPHID_RESPONSE * resp = (CTAPHID_RESPONSE *) buf;
    resp->cid = cid;
    resp->cmd = CTAPHID_ERROR;
    resp->bcnth = 0;
    resp->bcntl = 1;
    buf[sizeof(CTAPHID_RESPONSE)] = error;
    ctap_write_block(buf);
}

void ctaphid_handle_packet(uint8_t * pkt_raw)
{
    CTAPHID_PACKET * pkt = (CTAPHID_PACKET *)(pkt_raw);

    printf("Recv packet\n");
    printf("  CID: %08x active(%08x)\n", pkt->cid, active_cid);
    printf("  cmd: %02x\n", pkt->pkt.init.cmd);
    printf("  length: %d\n", ctaphid_packet_len(pkt));

    int ret;
    static CTAPHID_INIT_RESPONSE init_resp;
    static CTAPHID_RESPONSE resp;

    CTAP_RESPONSE ctap_resp;


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
                ctaphid_send_error(pkt->cid, ERR_INVALID_PAR);
                return;
            }
            break;
        case HANDLING_REQUEST:
            if (is_active_cid(pkt))
            {
                if (is_init_pkt(pkt))
                {
                    printf("received abort request from %08x\n", pkt->cid);

                    set_next_cid(active_cid);   // reuse last CID in current channel
                    ctaphid_init();
                    buffer_packet(pkt);
                }
                else if (!is_cont_pkt(pkt) && buffer_status() == BUFFERING)
                {
                    printf("Error, expecting cont packet\n");
                    ctaphid_send_error(pkt->cid, ERR_INVALID_PAR);
                    return;
                }
                else if(!is_cont_pkt(pkt))
                {
                    if (ctaphid_packet_len(pkt) > CTAPHID_BUFFER_SIZE)
                    {
                        printf("Error, internal buffer not big enough\n");
                        ctaphid_send_error(pkt->cid, ERR_INVALID_LEN);
                        ctaphid_init();
                        return;
                    }
                }

                active_cid_timestamp = millis();
                ret = buffer_packet(pkt);
                if (ret == SEQUENCE_ERROR)
                {
                    printf("Sequence error\n");
                    ctaphid_send_error(pkt->cid, ERR_INVALID_SEQ);
                    ctaphid_init();
                    return;
                }
            }
            else if (is_timed_out())
            {
                ctaphid_init();
                printf("dropping last channel -- timeout");
                ctaphid_send_error(pkt->cid, ERR_MSG_TIMEOUT);
                goto start_over;
            }
            else
            {
                ctaphid_send_error(pkt->cid, ERR_CHANNEL_BUSY);
                printf("Too busy with current transaction\n");
                return;
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
            active_cid_timestamp = millis();
            break;

        case EMPTY:
            printf("empty buffer!\n");
        case BUFFERED:
            switch(buffer_cmd())
            {
                case CTAPHID_INIT:
                    printf("CTAPHID_INIT\n");

                    if (buffer_len() != 8)
                    {
                        printf("Error,invalid length field for init packet\n");
                        ctaphid_send_error(pkt->cid, ERR_INVALID_LEN);
                        ctaphid_init();
                        return;
                    }

                    active_cid = get_new_cid();

                    printf("cid: %08x\n",active_cid);
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

                    ctap_write(&init_resp,sizeof(CTAPHID_INIT_RESPONSE));
                    ctap_write(NULL,0);


                    break;
                case CTAPHID_PING:

                    resp.cid = active_cid;
                    resp.cmd = CTAPHID_PING;
                    resp.bcnth = (buffer_len() & 0xff00) >> 8;
                    resp.bcntl = (buffer_len() & 0xff) >> 0;

                    ctap_write(&resp,sizeof(CTAPHID_RESPONSE));
                    ctap_write(ctap_buffer, buffer_len());
                    ctap_write(NULL,0);

                    printf("CTAPHID_PING\n");
                    break;

                case CTAPHID_WINK:

                    if (buffer_len() != 0)
                    {
                        printf("Error,invalid length field for wink packet\n");
                        ctaphid_send_error(pkt->cid, ERR_INVALID_LEN);
                        ctaphid_init();
                        return;
                    }

                    resp.cid = active_cid;
                    resp.cmd = CTAPHID_WINK;
                    resp.bcntl = 0;
                    resp.bcnth = 0;

                    ctap_write(&resp,sizeof(CTAPHID_RESPONSE));
                    ctap_write(NULL,0);

                    printf("CTAPHID_WINK\n");
                    break;

                case CTAPHID_CBOR:
                    printf("CTAPHID_CBOR\n");
                    if (buffer_len() == 0)
                    {
                        printf("Error,invalid 0 length field for cbor packet\n");
                        ctaphid_send_error(pkt->cid, ERR_INVALID_LEN);
                        ctaphid_init();
                        return;
                    }

                    ctap_handle_packet(ctap_buffer, buffer_len(), &ctap_resp);

                    resp.cid = active_cid;
                    resp.cmd = CTAPHID_MSG;
                    resp.bcntl = (ctap_resp.length & 0x00ff) >> 0;
                    resp.bcnth = (ctap_resp.length & 0xff00) >> 8;

                    ctap_write(&resp,sizeof(CTAPHID_RESPONSE));
                    ctap_write(ctap_resp.data, ctap_resp.length);
                    ctap_write(NULL, 0);


                    break;

                default:
                    printf("error, unimplemented HID cmd: %02x\r\n", buffer_cmd());
                    break;
            }
            break;

        default:
            printf("invalid buffer state; abort\n");
            exit(1);
            break;
    }
    
    printf("\n");

}

