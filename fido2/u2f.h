// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _U2F_H_
#define _U2F_H_

#include <stdint.h>
#include "ctap.h"

#define U2F_EC_FMT_UNCOMPRESSED             0x04

#define U2F_EC_POINT_SIZE                   32
#define U2F_EC_PUBKEY_SIZE                  65
#define U2F_APDU_SIZE                       7
#define U2F_CHALLENGE_SIZE                  32
#define U2F_APPLICATION_SIZE                32
#define U2F_KEY_HANDLE_TAG_SIZE             16
#define U2F_KEY_HANDLE_KEY_SIZE             32
#define U2F_KEY_HANDLE_SIZE                 (U2F_KEY_HANDLE_KEY_SIZE+U2F_KEY_HANDLE_TAG_SIZE)
#define U2F_REGISTER_REQUEST_SIZE           (U2F_CHALLENGE_SIZE+U2F_APPLICATION_SIZE)
#define U2F_MAX_REQUEST_PAYLOAD             (1 + U2F_CHALLENGE_SIZE+U2F_APPLICATION_SIZE + 1 + U2F_KEY_HANDLE_SIZE)


// U2F native commands
#define U2F_REGISTER                        0x01
#define U2F_AUTHENTICATE                    0x02
#define U2F_VERSION                         0x03
#define U2F_VENDOR_FIRST                    0xc0
#define U2F_VENDOR_LAST                     0xff

// U2F_CMD_REGISTER command defines
#define U2F_REGISTER_ID                     0x05
#define U2F_REGISTER_HASH_ID                0x00

// U2F Authenticate
#define U2F_AUTHENTICATE_CHECK              0x7
#define U2F_AUTHENTICATE_SIGN               0x3
#define U2F_AUTHENTICATE_SIGN_NO_USER       0x8


// Command status responses
#define U2F_SW_NO_ERROR                     0x9000
#define U2F_SW_CONDITIONS_NOT_SATISFIED     0x6985
#define U2F_SW_INS_NOT_SUPPORTED            0x6d00
#define U2F_SW_WRONG_LENGTH                 0x6700
#define U2F_SW_CLASS_NOT_SUPPORTED          0x6E00
#define U2F_SW_WRONG_DATA                   0x6a80
#define U2F_SW_INSUFFICIENT_MEMORY          0x9210

// Delay in milliseconds to wait for user input
#define U2F_MS_USER_INPUT_WAIT              3000

struct u2f_request_apdu
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t LC1;
    uint8_t LC2;
    uint8_t LC3;
    uint8_t payload[U2F_MAX_REQUEST_PAYLOAD];
};

struct u2f_ec_point
{
    uint8_t fmt;
    uint8_t x[U2F_EC_POINT_SIZE];
    uint8_t y[U2F_EC_POINT_SIZE];
};

struct u2f_register_request
{
    uint8_t chal[U2F_CHALLENGE_SIZE];
    uint8_t app[U2F_APPLICATION_SIZE];
};


struct u2f_key_handle
{
    uint8_t tag[U2F_KEY_HANDLE_TAG_SIZE];
    uint8_t key[U2F_KEY_HANDLE_KEY_SIZE];
};


struct u2f_authenticate_request
{
    uint8_t chal[U2F_CHALLENGE_SIZE];
    uint8_t app[U2F_APPLICATION_SIZE];
    uint8_t khl;
    struct u2f_key_handle kh;
};

// u2f_request send a U2F message to U2F protocol
// @req U2F message
void u2f_request(struct u2f_request_apdu* req, CTAP_RESPONSE * resp);

// u2f_request send a U2F message to NFC protocol
// @req data with iso7816 apdu message
// @len data length
void u2f_request_nfc(uint8_t * header, uint8_t * data, int datalen, CTAP_RESPONSE * resp);

int8_t u2f_authenticate_credential(struct u2f_key_handle * kh, uint8_t key_handle_len, uint8_t * appid);

int8_t u2f_response_writeback(const uint8_t * buf, uint16_t len);
void u2f_reset_response();
void u2f_set_writeback_buffer(CTAP_RESPONSE * resp);

int16_t u2f_version();


#endif /* U2F_H_ */
