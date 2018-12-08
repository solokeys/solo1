/*
   Copyright 2018 Conor Patrick

   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
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
#define WALLET_TAG  "\x8C\x27\x90\xf6"

#define WALLET_MIN_LENGTH   (4 + 4 + 16)

#define WALLET_VERSION  "WALLET_V1.0"

#define MAX_CHALLENGE_SIZE          229
#define MAX_KEYID_SIZE              228

#define MAX_PAYLOAD_SIZE            (255 - 16 - 4 - 4)

typedef struct
{
    uint8_t operation;
    uint8_t p1;
    uint8_t p2;
    uint8_t numArgs;
    uint8_t tag[4];
    uint8_t pinAuth[16];
    uint8_t payload[MAX_PAYLOAD_SIZE];
}__attribute__((packed)) wallet_request;


typedef enum
{
    WalletSign = 0x10,
    WalletRegister = 0x11,
    WalletPin = 0x12,
    WalletReset= 0x13,
    WalletVersion= 0x14,
    WalletRng = 0x15,
} WalletOperation;


int16_t bridge_u2f_to_extensions(uint8_t * chal, uint8_t * appid, uint8_t klen, uint8_t * keyh);

// return 1 if request is a wallet request
int is_extension_request(uint8_t * req, int len);

void wallet_init();

#endif /* WALLET_H_ */
