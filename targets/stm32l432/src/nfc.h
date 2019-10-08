#ifndef _NFC_H_
#define _NFC_H_

#include <stdint.h>
#include <stdbool.h>
#include "apdu.h"

// Return number of bytes read if any.
int nfc_loop(void);

int nfc_init(void);

typedef struct
{
    uint8_t cclen_hi;
    uint8_t cclen_lo;
    uint8_t version;
    uint8_t MLe_hi;
    uint8_t MLe_lo;
    uint8_t MLc_hi;
    uint8_t MLc_lo;
    uint8_t tlv[8];
} __attribute__((packed)) CAPABILITY_CONTAINER;

// WTX time in ms
#define WTX_TIME_DEFAULT              300

#define NFC_CMD_REQA                  0x26
#define NFC_CMD_WUPA                  0x52
#define NFC_CMD_HLTA                  0x50
#define NFC_CMD_RATS                  0xe0

#define NFC_CMD_PPSS                  0xd0
#define IS_PPSS_CMD(x)                (((x) & 0xf0) == NFC_CMD_PPSS)
#define NFC_CMD_IBLOCK                0x00
#define IS_IBLOCK(x)                  ( (((x) & 0xc0) == NFC_CMD_IBLOCK) && (((x) & 0x02) == 0x02) )
#define NFC_CMD_RBLOCK                0xa0
#define NFC_CMD_RBLOCK_ACK            0x10
#define IS_RBLOCK(x)                  ( (((x) & 0xe0) == NFC_CMD_RBLOCK) && (((x) & 0x02) == 0x02) )
#define NFC_CMD_SBLOCK                0xc0
#define IS_SBLOCK(x)                  ( (((x) & 0xc0) == NFC_CMD_SBLOCK) && (((x) & 0x02) == 0x02) )

extern uint8_t p14443_block_offset(uint8_t pcb);

#define NFC_SBLOCK_DESELECT           0x30
#define NFC_SBLOCK_WTX                0x30

#define AID_NDEF_TYPE_4               "\xD2\x76\x00\x00\x85\x01\x01"
#define AID_NDEF_MIFARE_TYPE_4        "\xD2\x76\x00\x00\x85\x01\x00"
#define AID_CAPABILITY_CONTAINER      "\xE1\x03"
#define AID_NDEF_TAG                  "\xE1\x04"
#define AID_FIDO                      "\xa0\x00\x00\x06\x47\x2f\x00\x01"

typedef enum
{
    APP_NOTHING = 0,
    APP_NDEF_TYPE_4 = 1,
    APP_MIFARE_TYPE_4,
    APP_CAPABILITY_CONTAINER,
    APP_NDEF_TAG,
	APP_FIDO,
} APPLETS;

void WTX_timer_exec(void);

#endif
