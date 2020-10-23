// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _CTAPHID_H_H
#define _CTAPHID_H_H

#include "device.h"
#include "ctap_errors.h"

#define TYPE_INIT               0x80
#define TYPE_CONT               0x00

#define CTAPHID_PING         (TYPE_INIT | 0x01)
#define CTAPHID_MSG          (TYPE_INIT | 0x03)
#define CTAPHID_LOCK         (TYPE_INIT | 0x04)
#define CTAPHID_INIT         (TYPE_INIT | 0x06)
#define CTAPHID_WINK         (TYPE_INIT | 0x08)
#define CTAPHID_CBOR         (TYPE_INIT | 0x10)
#define CTAPHID_CANCEL       (TYPE_INIT | 0x11)
#define CTAPHID_ERROR        (TYPE_INIT | 0x3f)
#define CTAPHID_KEEPALIVE    (TYPE_INIT | 0x3b)

// Custom commands between 0x40-0x7f
#define CTAPHID_BOOT            (TYPE_INIT | 0x50)
#define CTAPHID_ENTERBOOT       (TYPE_INIT | 0x51)
#define CTAPHID_ENTERSTBOOT     (TYPE_INIT | 0x52)
#define CTAPHID_REBOOT          (TYPE_INIT | 0x53)
#define CTAPHID_GETRNG          (TYPE_INIT | 0x60)
#define CTAPHID_GETVERSION      (TYPE_INIT | 0x61)
#define CTAPHID_LOADKEY         (TYPE_INIT | 0x62)
// reserved for debug, not implemented except for HACKER and DEBUG_LEVEl > 0
#define CTAPHID_PROBE           (TYPE_INIT | 0x70)

    #define ERR_INVALID_CMD         0x01
    #define ERR_INVALID_PAR         0x02
    #define ERR_INVALID_SEQ         0x04
    #define ERR_MSG_TIMEOUT         0x05
    #define ERR_CHANNEL_BUSY        0x06

#define CTAPHID_PROTOCOL_VERSION    2

#define CTAPHID_STATUS_IDLE         0
#define CTAPHID_STATUS_PROCESSING   1
#define CTAPHID_STATUS_UPNEEDED     2

#define CTAPHID_INIT_PAYLOAD_SIZE  (HID_MESSAGE_SIZE-7)
#define CTAPHID_CONT_PAYLOAD_SIZE  (HID_MESSAGE_SIZE-5)

#define CTAPHID_BROADCAST_CID       0xffffffff

#define CTAPHID_BUFFER_SIZE         7609

#define CAPABILITY_WINK             0x01
#define CAPABILITY_LOCK             0x02
#define CAPABILITY_CBOR             0x04
#define CAPABILITY_NMSG             0x08

#define CTAP_CAPABILITIES           (CAPABILITY_WINK | CAPABILITY_CBOR)

#define HID_MESSAGE_SIZE        64

typedef struct
{
    uint32_t cid;
    union{
        struct{
            uint8_t cmd;
            uint8_t bcnth;
            uint8_t bcntl;
            uint8_t payload[CTAPHID_INIT_PAYLOAD_SIZE];
        } init;
        struct{
            uint8_t seq;
            uint8_t payload[CTAPHID_CONT_PAYLOAD_SIZE];
        } cont;
    } pkt;
} CTAPHID_PACKET;


typedef struct
{
    uint8_t nonce[8];
    uint32_t cid;
    uint8_t protocol_version;
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t build_version;
    uint8_t capabilities;
} __attribute__((packed)) CTAPHID_INIT_RESPONSE;



void ctaphid_init();

uint8_t ctaphid_handle_packet(uint8_t * pkt_raw);

void ctaphid_check_timeouts();

void ctaphid_update_status(int8_t status);


#define ctaphid_packet_len(pkt)     ((uint16_t)((pkt)->pkt.init.bcnth << 8) | ((pkt)->pkt.init.bcntl))

#endif
