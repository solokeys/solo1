/*
 * wallet.h
 *
 *  Created on: Jul 7, 2018
 *      Author: conor
 */

#ifndef WALLET_H_
#define WALLET_H_

#include <stdint.h>

#define WALLET_MAX_BUFFER	(32 + 255)

// Sign request
// op: 					0x10
// authType:			0x00 //sign?
// reserved:			0x00 // mbedtls signature alg identifier
// pinAuth:             data[16]
// challenge-length:    1-255
// challenge:			data[1-255]
// keyID-length:		1-255
// keyID:				data[1-255]

// Resp: normal U2F auth response

// Register request
// op: 					0x11
// formatType:			0x00 //sign?	[0x00: WIF, 0x01: raw]
// keyType:				0x03 // mbedtls signature alg identifier
// key-length:    		1-255
// key:					data[1-255]


// Resp: modded U2F auth response

// PIN request
// op: 					0x12
// subcmd:				0x00	// Same as CTAP pin subcommands
// reserved:			0x03 	// mbedtls signature alg identifier
// publickey:    		data[64]
// OR
// pinAuth				data[64]
// OR
// pinHashEnc			data[64]
// OR
// newPinEnc			data[64]

// key:					data[1-255]
// keyID-length:		1-255
// keyID:				data[1-255]

// Resp: modded U2F auth response
// Returns public key OR pinAuth

// Only response to this challenge to prevent interference
#define CHALLENGE_PIN  "\xf6\xa2\x3c\xa4\x0a\xf9\xda\xd4\x5f\xdc\xba\x7d\xc9\xde\xcb\xed\xb5\x84\x64\x3a\x4c\x9f\x44\xc2\x04\xb0\x17\xd7\xf4\x3e\xe0\x3f"

#define WALLET_VERSION  "WALLET_V1.0"

#define MAX_CHALLENGE_SIZE          233
#define MAX_KEYID_SIZE              232

#define MAX_PAYLOAD_SIZE            (255 - 16 - 4)

typedef struct
{
    uint8_t operation;
    uint8_t p1;
    uint8_t p2;
    uint8_t numArgs;
    uint8_t pinAuth[16];
    uint8_t payload[MAX_PAYLOAD_SIZE];
}__attribute__((packed)) wallet_request;



int16_t bridge_u2f_to_wallet(uint8_t * chal, uint8_t * appid, uint8_t klen, uint8_t * keyh);

void wallet_init();

#endif /* WALLET_H_ */
