/*
 * wallet.c
 *
 *  Created on: Jul 7, 2018
 *      Author: conor
 */
#include "wallet.h"
#include "ctap.h"
#include "u2f.h"
#include "log.h"

typedef enum
{
	WalletSign = 0x10,
	WalletRegister = 0x11,
	WalletPin = 0x12,
} WalletOperation;


int16_t bridge_u2f_to_wallet(uint8_t * chal, uint8_t * appid, uint8_t klen, uint8_t * keyh)
{
	static uint8_t msg_buf[WALLET_MAX_BUFFER];
	int reqlen = klen;

	uint32_t count;
	uint8_t up = 1;
	uint8_t sig[72];



	wallet_request * req = (wallet_request *) msg_buf;

//	memmove(msg_buf, chal, 32);
	memmove(msg_buf, keyh, klen);

	count = ctap_atomic_count(0);

	switch(req->operation)
	{
	case WalletSign:
		printf1(TAG_WALLET,"WalletSign\n");
		break;
	case WalletRegister:
		printf1(TAG_WALLET,"WalletRegister\n");
		break;
	case WalletPin:
		printf1(TAG_WALLET,"WalletPin\n");
		break;
	default:
		printf2(TAG_ERR,"Invalid wallet command: %x\n",req->operation);
		break;
	}
//	printf1(TAG_WALLET, "chal: "); dump_hex1(TAG_WALLET, chal,32);
//	printf1(TAG_WALLET, "appid: "); dump_hex1(TAG_WALLET, appid,32);
//	printf1(TAG_WALLET, "keyh: "); dump_hex1(TAG_WALLET, keyh,klen);
//	printf1(TAG_WALLET, "u2f2wallet: "); dump_hex1(TAG_WALLET, msg_buf,reqlen);

    u2f_response_writeback(&up,1);
    u2f_response_writeback((uint8_t *)&count,4);
    u2f_response_writeback(sig,72);

	return U2F_SW_NO_ERROR;
}
