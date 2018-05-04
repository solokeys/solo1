#ifndef _CTAP_H
#define _CTAP_H

#define CTAP_MAKE_CREDENTIAL        0x01
#define CTAP_GET_ASSERTION          0x02
#define CTAP_CANCEL                 0x03
#define CTAP_GET_INFO               0x04
#define CTAP_CLIENT_PIN             0x06
#define CTAP_RESET                  0x07
#define GET_NEXT_ASSERTION          0x08
#define CTAP_VENDOR_FIRST           0x40
#define CTAP_VENDOR_LAST            0xBF

#define CTAP_AAGUID                 ((uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")

typedef struct
{
    uint8_t * data;
    uint16_t length;
} CTAP_RESPONSE;


uint8_t ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp);

// Must be implemented by application
// data is HID_MESSAGE_SIZE long in bytes
extern void ctap_write_block(uint8_t * data);

// Buffer data and send in HID_MESSAGE_SIZE chunks
// if len == 0, FLUSH
// if len == -1, RESET
extern void ctap_write(void * _data, int len);


#endif
