#ifndef _NFC_H_
#define _NFC_H_

#include <stdint.h>

void nfc_loop();
void nfc_init();

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

typedef struct
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc;
} __attribute__((packed)) APDU_HEADER;

#define NFC_CMD_REQA                  0x26
#define NFC_CMD_WUPA                  0x52
#define NFC_CMD_HLTA                  0x50
#define NFC_CMD_RATS                  0xe0

#define NFC_CMD_PPSS                  0xd0
#define IS_PPSS_CMD(x)                (((x) & 0xf0) == NFC_CMD_PPSS)
#define NFC_CMD_IBLOCK                0x02
#define IS_IBLOCK(x)                  (((x) & 0xe2) == NFC_CMD_IBLOCK)
#define NFC_CMD_RBLOCK                0xa2
#define IS_RBLOCK(x)                  (((x) & 0xe6) == NFC_CMD_RBLOCK)
#define NFC_CMD_SBLOCK                0xc2
#define IS_SBLOCK(x)                  (((x) & 0xc7) == NFC_CMD_SBLOCK)

#define NFC_SBLOCK_DESELECT           0x30

#define APDU_INS_SELECT               0xA4
#define APDU_INS_READ_BINARY          0xB0

#define AID_NDEF_TYPE_4               "\xD2\x76\x00\x00\x85\x01\x01"
#define AID_NDEF_MIFARE_TYPE_4        "\xD2\x76\x00\x00\x85\x01\x00"
#define AID_CAPABILITY_CONTAINER      "\xE1\x03"
#define AID_NDEF_TAG                  "\x11\x11"

typedef enum
{
    APP_NDEF_TYPE_4 = 1,
    APP_MIFARE_TYPE_4,
    APP_CAPABILITY_CONTAINER,
    APP_NDEF_TAG,
} APPLETS;

#define APDU_STATUS_SUCCESS           0x9000

#endif
