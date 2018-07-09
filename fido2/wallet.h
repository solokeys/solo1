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
