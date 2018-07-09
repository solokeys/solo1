/*
 * wallet.c
 *
 *  Created on: Jul 7, 2018
 *      Author: conor
 */
#include "wallet.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "crypto.h"
#include "u2f.h"
#include "log.h"
#include "util.h"

typedef enum
{
    WalletSign = 0x10,
    WalletRegister = 0x11,
    WalletPin = 0x12,
} WalletOperation;


// return 1 if hash is valid, 0 otherwise
int check_pinhash(uint8_t * pinAuth, uint8_t * msg, uint8_t len)
{
    uint8_t hmac[32];
    crypto_sha256_hmac_init(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);
    crypto_sha256_update(msg, 4);
    crypto_sha256_update(msg+ 4 + 16, len - 4 - 16);
    crypto_sha256_hmac_final(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);

    printf1(TAG_WALLET, "recalc pinhash:"); dump_hex1(TAG_WALLET, hmac,32);

    return (memcmp(pinAuth, hmac, 16) == 0);
}
/*int16_t wallet_sign(uint8_t alg, uint8_t * chal, uint8_t len, uint8_t * kh, uint8_t kl)*/
/*{*/
    /*crypto_sha256_hmac_init(uint8_t * key, uint32_t klen, uint8_t * hmac);*/
/*}*/

void wallet_init()
{
    // TODO dont leave this
    printf1(TAG_WALLET,"Wallet is ready\n");


    ctap_update_pin("1234", 4);

}

int8_t wallet_pin(uint8_t subcmd, uint8_t * pinAuth, uint8_t * arg1, uint8_t * arg2)
{
    uint8_t pinTokenEnc[PIN_TOKEN_SIZE];
    int ret;

    switch(subcmd)
    {
        case CP_cmdGetKeyAgreement:
            printf1(TAG_WALLET,"cmdGetKeyAgreement\n");

            u2f_response_writeback(KEY_AGREEMENT_PUB,sizeof(KEY_AGREEMENT_PUB));
            printf1(TAG_WALLET,"pubkey: "); dump_hex1(TAG_WALLET,KEY_AGREEMENT_PUB,64);

            break;
        case CP_cmdGetRetries:
            printf1(TAG_WALLET,"cmdGetRetries\n");
            return CTAP2_ERR_UNSUPPORTED_OPTION;
            break;
        case CP_cmdSetPin:
            printf1(TAG_WALLET,"cmdSetPin\n");
            return CTAP2_ERR_UNSUPPORTED_OPTION;
            break;
        case CP_cmdChangePin:
            printf1(TAG_WALLET,"cmdChangePin\n");
            return CTAP2_ERR_UNSUPPORTED_OPTION;
            break;
        case CP_cmdGetPinToken:
            printf1(TAG_WALLET,"cmdGetPinToken\n");

            ret = ctap_add_pin_if_verified(pinTokenEnc, arg1, pinAuth); // pubkey, pinHashEnc
            if (ret != 0)
                return ret;

            printf1(TAG_WALLET,"pinToken: "); dump_hex1(TAG_WALLET, PIN_TOKEN, 16);
            u2f_response_writeback(pinTokenEnc, PIN_TOKEN_SIZE);

            break;

        default:
            printf2(TAG_ERR,"Error, invalid client pin subcommand\n");
            return CTAP2_ERR_INVALID_OPTION;
    }



    return 0;
}

int16_t bridge_u2f_to_wallet(uint8_t * _chal, uint8_t * _appid, uint8_t klen, uint8_t * keyh)
{
    static uint8_t msg_buf[WALLET_MAX_BUFFER];
    int reqlen = klen;
    int i;
    int8_t ret = 0;
    uint32_t count;
    uint8_t up = 1;
    uint8_t sig[200];

    uint8_t * args[5] = {NULL,NULL,NULL,NULL,NULL};
    uint8_t lens[5];


    for (i = 0; i < sizeof(sig); i++)
    {
        sig[i] = i;
    }

    wallet_request * req = (wallet_request *) msg_buf;
    uint8_t * payload = req->payload;

    memmove(msg_buf, keyh, klen);

    printf1(TAG_WALLET, "u2f2wallet [%d]: ",reqlen); dump_hex1(TAG_WALLET, msg_buf,reqlen);

    count = ctap_atomic_count(0);
    u2f_response_writeback(&up,1);
    u2f_response_writeback((uint8_t *)&count,4);
    u2f_response_writeback((uint8_t *)&ret,1);

    int offset = 0;
    for (i = 0; i < MIN(5,req->numArgs); i++)
    {
        if (offset > MAX_PAYLOAD_SIZE)
        {
            ret = CTAP1_ERR_INVALID_LENGTH;
            goto cleanup;
        }
        lens[i] = *(payload + offset);
        offset++;
        args[i] = payload + offset;
        offset += lens[i];
    }
    if (offset > MAX_PAYLOAD_SIZE)
    {
        ret = CTAP1_ERR_INVALID_LENGTH;
        printf2(TAG_ERR,"Wallet operation lengths too big\n");
        goto cleanup;
    }


    switch(req->operation)
    {
        case WalletSign:
            printf1(TAG_WALLET,"WalletSign\n");
            printf1(TAG_WALLET,"pinAuth:"); dump_hex1(TAG_WALLET, req->pinAuth, 16);

            if (args[0] == NULL)
            {
                ret = CTAP2_ERR_MISSING_PARAMETER;
                printf2(TAG_ERR,"Missing parameter for WalletSign\n");
                goto cleanup;
            }

            printf1(TAG_WALLET,"challenge:"); dump_hex1(TAG_WALLET, args[0], lens[0]);
            if (args[1] != NULL) printf1(TAG_WALLET,"keyid:"); dump_hex1(TAG_WALLET, args[1], lens[1]);

            if (check_pinhash(req->pinAuth, msg_buf, reqlen))
            {
                printf1(TAG_WALLET,"pinAuth is valid\n");
            }
            else
            {
                printf1(TAG_WALLET,"pinAuth is NOT valid\n");
                ret = CTAP2_ERR_PIN_AUTH_INVALID;
                goto cleanup;
            }
            break;
        case WalletRegister:
            printf1(TAG_WALLET,"WalletRegister\n");
            break;
        case WalletPin:
            printf1(TAG_WALLET,"WalletPin\n");
            ret = wallet_pin(req->p1, req->pinAuth, args[0], args[1]);
            break;
        default:
            printf2(TAG_ERR,"Invalid wallet command: %x\n",req->operation);
            ret = CTAP1_ERR_INVALID_COMMAND;
            break;
    }

cleanup:
    if (ret != 0)
    {
        u2f_reset_response();
        u2f_response_writeback(&up,1);
        u2f_response_writeback((uint8_t *)&count,4);

        memset(sig,0,sizeof(sig));
        sig[0] = ret;
        u2f_response_writeback(sig,72);
    }
    else
    {
        /*u2f_response_writeback(sig,sizeof(sig));*/
    }
    return U2F_SW_NO_ERROR;
}
