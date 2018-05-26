#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctaphid.h"
#include "ctap.h"
#include "u2f.h"
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


typedef struct
{
    uint8_t cmd;
    uint32_t cid;
    uint16_t bcnt;
    int offset;
    int bytes_written;
    uint8_t seq;
    uint8_t buf[HID_MESSAGE_SIZE];
} CTAPHID_WRITE_BUFFER;


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

static void buffer_reset();

#define CTAPHID_WRITE_INIT      0x01
#define CTAPHID_WRITE_FLUSH     0x02
#define CTAPHID_WRITE_RESET     0x04

#define     ctaphid_write_buffer_init(x)    memset(x,0,sizeof(CTAPHID_WRITE_BUFFER))
static void ctaphid_write(CTAPHID_WRITE_BUFFER * wb, void * _data, int len);

void ctaphid_init()
{
    state = IDLE;
    active_cid = 0;
    buffer_reset();
    active_cid_timestamp = millis();
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
    return (pkt->pkt.init.cmd == CTAPHID_INIT);
}

static int is_cont_pkt(CTAPHID_PACKET * pkt)
{
    return !(pkt->pkt.init.cmd & TYPE_INIT);
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

static void buffer_reset()
{
    ctap_buffer_bcnt = 0;
    ctap_buffer_offset = 0;
    ctap_packet_seq = 0;
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

// Buffer data and send in HID_MESSAGE_SIZE chunks
// if len == 0, FLUSH
static void ctaphid_write(CTAPHID_WRITE_BUFFER * wb, void * _data, int len)
{
    uint8_t * data = (uint8_t *)_data;
    if (_data == NULL)
    {
        if (wb->offset == 0 && wb->bytes_written == 0)
        {
            memmove(wb->buf, &wb->cid, 4);
            wb->offset += 4;

            wb->buf[4] = wb->cmd;
            wb->buf[5] = (wb->bcnt & 0xff00) >> 8;
            wb->buf[6] = (wb->bcnt & 0xff) >> 0;
            wb->offset += 3;
        }

        if (wb->offset > 0)
        {
            memset(wb->buf + wb->offset, 0, HID_MESSAGE_SIZE - wb->offset);
            ctaphid_write_block(wb->buf);
        }
        return;
    }
    int i;
    for (i = 0; i < len; i++)
    {
        if (wb->offset == 0 )
        {
            memmove(wb->buf, &wb->cid, 4);
            wb->offset += 4;

            if (wb->bytes_written == 0)
            {
                wb->buf[4] = wb->cmd;
                wb->buf[5] = (wb->bcnt & 0xff00) >> 8;
                wb->buf[6] = (wb->bcnt & 0xff) >> 0;
                wb->offset += 3;
            }
            else
            {
                wb->buf[4] = wb->seq++;
                wb->offset += 1;
            }
        }
        wb->buf[wb->offset++] = data[i];
        wb->bytes_written += 1;
        if (wb->offset == HID_MESSAGE_SIZE)
        {
            ctaphid_write_block(wb->buf);
            wb->offset = 0;
        }
    }
}


static void ctaphid_send_error(uint32_t cid, uint8_t error)
{
    uint8_t buf[HID_MESSAGE_SIZE];
    CTAPHID_WRITE_BUFFER wb;
    ctaphid_write_buffer_init(&wb);

    wb.cid = cid;
    wb.cmd = CTAPHID_ERROR;
    wb.bcnt = 1;

    ctaphid_write(&wb, &error, 1);
    ctaphid_write(&wb, NULL, 0);
}

void ctaphid_handle_packet(uint8_t * pkt_raw)
{
    CTAPHID_PACKET * pkt = (CTAPHID_PACKET *)(pkt_raw);

    printf("Recv packet\n");
    printf("  CID: %08x active(%08x)\n", pkt->cid, active_cid);
    printf("  cmd: %02x\n", pkt->pkt.init.cmd);
    if (!is_cont_pkt(pkt)) printf("  length: %d\n", ctaphid_packet_len(pkt));

    int ret;
    uint8_t status;
    uint32_t oldcid;
    static CTAPHID_INIT_RESPONSE init_resp;
    static CTAPHID_WRITE_BUFFER wb;

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
                    ctaphid_write_buffer_init(&wb);

                    wb.cid = active_cid;
                    active_cid_timestamp = millis();

                    ctaphid_init();

                    active_cid = wb.cid;
                    wb.cmd = CTAPHID_INIT;
                    wb.bcnt = 0;
                    ctaphid_write(&wb, ctap_buffer, buffer_len());
                    ctaphid_write(&wb, NULL, 0);
                    return;
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
                        ctaphid_send_error(pkt->cid, CTAP1_ERR_INVALID_LENGTH);
                        return;
                    }
                }

                active_cid_timestamp = millis();
                ret = buffer_packet(pkt);
                if (ret == SEQUENCE_ERROR)
                {
                    printf("Sequence error\n");
                    ctaphid_send_error(pkt->cid, ERR_INVALID_SEQ);
                    return;
                }
            }
            else if (is_timed_out())
            {
                printf("dropping last channel -- timeout");
                oldcid = active_cid;
                ctaphid_init();
                ctaphid_send_error(active_cid, ERR_MSG_TIMEOUT);
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
                        ctaphid_send_error(pkt->cid, CTAP1_ERR_INVALID_LENGTH);
                        return;
                    }

                    active_cid = get_new_cid();

                    printf("cid: %08x\n",active_cid);
                    active_cid_timestamp = millis();

                    ctaphid_write_buffer_init(&wb);
                    wb.cid = CTAPHID_BROADCAST_CID;
                    wb.cmd = CTAPHID_INIT;
                    wb.bcnt = 17;

                    memmove(init_resp.nonce, pkt->pkt.init.payload, 8);
                    init_resp.cid = active_cid;
                    init_resp.protocol_version = 0;//?
                    init_resp.version_major = 0;//?
                    init_resp.version_minor = 0;//?
                    init_resp.build_version = 0;//?
                    init_resp.capabilities = CTAP_CAPABILITIES;

                    ctaphid_write(&wb,&init_resp,sizeof(CTAPHID_INIT_RESPONSE));
                    ctaphid_write(&wb,NULL,0);


                    break;
                case CTAPHID_PING:
                    printf("CTAPHID_PING\n");

                    ctaphid_write_buffer_init(&wb);
                    wb.cid = active_cid;
                    wb.cmd = CTAPHID_PING;
                    wb.bcnt = buffer_len();

                    ctaphid_write(&wb, ctap_buffer, buffer_len());
                    ctaphid_write(&wb, NULL,0);

                    break;

                case CTAPHID_WINK:
                    printf("CTAPHID_WINK\n");

                    if (buffer_len() != 0)
                    {
                        printf("Error,invalid length field for wink packet\n");
                        ctaphid_send_error(pkt->cid, CTAP1_ERR_INVALID_LENGTH);
                        return;
                    }

                    ctaphid_write_buffer_init(&wb);

                    wb.cid = active_cid;
                    wb.cmd = CTAPHID_WINK;

                    ctaphid_write(&wb,NULL,0);

                    break;

                case CTAPHID_CBOR:
                    printf("CTAPHID_CBOR\n");
                    if (buffer_len() == 0)
                    {
                        printf("Error,invalid 0 length field for cbor packet\n");
                        ctaphid_send_error(pkt->cid, CTAP1_ERR_INVALID_LENGTH);
                        return;
                    }

                    ctap_response_init(&ctap_resp);
                    status = ctap_handle_packet(ctap_buffer, buffer_len(), &ctap_resp);

                    ctaphid_write_buffer_init(&wb);
                    wb.cid = active_cid;
                    wb.cmd = CTAPHID_CBOR;
                    wb.bcnt = (ctap_resp.length+1);

                    ctaphid_write(&wb, &status, 1);
                    ctaphid_write(&wb, ctap_resp.data, ctap_resp.length);
                    ctaphid_write(&wb, NULL, 0);
                    break;

                case CTAPHID_MSG:
                    printf("CTAPHID_MSG\n");
                    if (buffer_len() == 0)
                    {
                        printf("Error,invalid 0 length field for MSG/U2F packet\n");
                        ctaphid_send_error(pkt->cid, CTAP1_ERR_INVALID_LENGTH);
                        return;
                    }

                    ctap_response_init(&ctap_resp);
                    u2f_request((struct u2f_request_apdu*)ctap_buffer, &ctap_resp);

                    ctaphid_write_buffer_init(&wb);
                    wb.cid = active_cid;
                    wb.cmd = CTAPHID_MSG;
                    wb.bcnt = (ctap_resp.length);

                    ctaphid_write(&wb, ctap_resp.data, ctap_resp.length);
                    ctaphid_write(&wb, NULL, 0);
                    break;

                default:
                    printf("error, unimplemented HID cmd: %02x\r\n", buffer_cmd());
                    break;
            }

            buffer_reset();
            break;

        default:
            printf("invalid buffer state; abort\n");
            exit(1);
            break;
    }
    
    printf("\n");

}

