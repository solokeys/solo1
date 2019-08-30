#ifndef _APDU_H_
#define _APDU_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc;
} __attribute__((packed)) APDU_HEADER;

typedef struct
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc[3];
} __attribute__((packed)) EXT_APDU_HEADER;

typedef struct
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint16_t lc;
    uint8_t *data;
    uint32_t le;
    bool extended_apdu;
    uint8_t case_type;
} __attribute__((packed)) APDU_STRUCT;

extern uint16_t apdu_decode(uint8_t *data, size_t len, APDU_STRUCT *apdu);

#define APDU_FIDO_U2F_REGISTER        0x01
#define APDU_FIDO_U2F_AUTHENTICATE    0x02
#define APDU_FIDO_U2F_VERSION         0x03
#define APDU_FIDO_NFCCTAP_MSG         0x10
#define APDU_FIDO_U2F_VENDOR_FIRST    0xc0    // First vendor defined command
#define APDU_FIDO_U2F_VENDOR_LAST     0xff    // Last vendor defined command
#define APDU_SOLO_RESET               0xee

#define APDU_INS_SELECT               0xA4
#define APDU_INS_READ_BINARY          0xB0
#define APDU_GET_RESPONSE             0xC0

#define SW_SUCCESS                    0x9000
#define SW_GET_RESPONSE               0x6100  // Command successfully executed; 'XX' bytes of data are available and can be requested using GET RESPONSE.
#define SW_WRONG_LENGTH               0x6700
#define SW_COND_USE_NOT_SATISFIED     0x6985
#define SW_FILE_NOT_FOUND             0x6a82
#define SW_INCORRECT_P1P2             0x6a86
#define SW_INS_INVALID                0x6d00  // Instruction code not supported or invalid
#define SW_CLA_INVALID                0x6e00  
#define SW_INTERNAL_EXCEPTION         0x6f00

#endif //_APDU_H_
