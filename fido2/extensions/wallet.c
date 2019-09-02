// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include "wallet.h"
#include APP_CONFIG
#include "ctap.h"
#include "ctap_errors.h"
#include "crypto.h"
#include "u2f.h"
#include "log.h"
#include "util.h"
#include "storage.h"
#include "device.h"
#include "extensions.h"

typedef enum
{
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    MBEDTLS_ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    MBEDTLS_ECP_DP_CURVE25519,           /*!< Curve25519               */
    MBEDTLS_ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
} mbedtls_ecp_group_id;



// return 1 if hash is valid, 0 otherwise
int check_pinhash(uint8_t * pinAuth, uint8_t * msg, uint8_t len)
{
    uint8_t hmac[32];
    crypto_sha256_hmac_init(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);
    crypto_sha256_update(msg, 8);
    crypto_sha256_update(msg+ 8 + 16, len - 8 - 16);
    crypto_sha256_hmac_final(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);

    return (memcmp(pinAuth, hmac, 16) == 0);
}


void wallet_init()
{
    printf1(TAG_WALLET,"Wallet is ready\n");
}

int8_t wallet_pin(uint8_t subcmd, uint8_t * pinAuth, uint8_t * arg1, uint8_t * arg2, uint8_t * arg3, int len)
{
    uint8_t pinTokenEnc[PIN_TOKEN_SIZE];
    int ret;

    switch(subcmd)
    {
        case CP_cmdGetKeyAgreement:
            printf1(TAG_WALLET,"cmdGetKeyAgreement\n");

            if ( ctap_device_locked() )
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }

            extension_writeback(KEY_AGREEMENT_PUB,sizeof(KEY_AGREEMENT_PUB));
            printf1(TAG_WALLET,"pubkey: "); dump_hex1(TAG_WALLET,KEY_AGREEMENT_PUB,64);

            break;
        case CP_cmdGetRetries:
            printf1(TAG_WALLET,"cmdGetRetries\n");
            pinTokenEnc[0] = ctap_leftover_pin_attempts();
            extension_writeback(pinTokenEnc,1);

            break;
        case CP_cmdSetPin:
            printf1(TAG_WALLET,"cmdSetPin\n");
            if (ctap_is_pin_set() || ctap_device_locked())
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }

            if (!ctap_user_presence_test(5000))
            {
                return CTAP2_ERR_OPERATION_DENIED;
            }

                                              //pinEnc     // plat_pubkey
            ret = ctap_update_pin_if_verified(   arg2, len,     arg1,     pinAuth, NULL);
            if (ret != 0)
                return ret;

//            printf1(TAG_WALLET,"Success.  Pin = %s\n", STATE.pin_code);

            break;
        case CP_cmdChangePin:
            printf1(TAG_WALLET,"cmdChangePin\n");

            if (! ctap_is_pin_set() )
            {
                return CTAP2_ERR_PIN_NOT_SET;
            }

            if ( ctap_device_locked() )
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }

            if (!ctap_user_presence_test(5000))
            {
                return CTAP2_ERR_OPERATION_DENIED;
            }


                                              //pinEnc     // plat_pubkey        // pinHashEnc
            ret = ctap_update_pin_if_verified(   arg2, len,     arg1,     pinAuth, arg3);
            if (ret != 0)
                return ret;

            break;
        case CP_cmdGetPinToken:


            printf1(TAG_WALLET,"cmdGetPinToken\n");

            if ( ctap_device_locked() )
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }

            if (!ctap_user_presence_test(5000))
            {
                return CTAP2_ERR_OPERATION_DENIED;
            }

            ret = ctap_add_pin_if_verified(pinTokenEnc, arg1, pinAuth); // pubkey, pinHashEnc
            if (ret != 0)
                return ret;

            printf1(TAG_WALLET,"pinToken: "); dump_hex1(TAG_WALLET, PIN_TOKEN, 16);
            extension_writeback(pinTokenEnc, PIN_TOKEN_SIZE);

            break;

        default:
            printf2(TAG_ERR,"Error, invalid client pin subcommand\n");
            return CTAP2_ERR_INVALID_OPTION;
    }



    return 0;
}

int16_t bridge_to_wallet(uint8_t * keyh, uint8_t klen)
{
    static uint8_t msg_buf[WALLET_MAX_BUFFER];
    int reqlen = klen;
    int i;
    int8_t ret = 0;

    uint8_t sig[200];

    uint8_t * args[5] = {NULL,NULL,NULL,NULL,NULL};
    uint8_t lens[5];

    uint8_t key[256];
    uint8_t shasum[32];
    uint8_t chksum[4];

    int keysize = sizeof(key);

    memset(lens,0,sizeof(lens));

    wallet_request * req = (wallet_request *) msg_buf;
    uint8_t * payload = req->payload;

    memmove(msg_buf, keyh, klen);

    printf1(TAG_WALLET, "u2f2wallet [%d]: ",reqlen); dump_hex1(TAG_WALLET, msg_buf,reqlen);

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

            if (args[0] == NULL || lens[0] == 0)
            {
                ret = CTAP2_ERR_MISSING_PARAMETER;
                printf2(TAG_ERR,"Missing parameter for WalletSign\n");
                goto cleanup;
            }

            printf1(TAG_WALLET,"challenge:"); dump_hex1(TAG_WALLET, args[0], lens[0]);
            if (args[1] != NULL && req->numArgs > 1)
            {
                printf1(TAG_WALLET,"keyid is specified\n");
                printf1(TAG_WALLET,"keyid:"); dump_hex1(TAG_WALLET, args[1], lens[1]);
            }

            if (ctap_is_pin_set())
            {
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
            }
            else
            {
                printf1(TAG_WALLET,"Warning: no pin is set.  Ignoring pinAuth\n");
            }


            ret = ctap_load_key(0, key);

            if (ret != 0)
            {
                ret = CTAP2_ERR_NO_CREDENTIALS;
                goto cleanup;
            }

            keysize = ctap_key_len(0);

            crypto_load_external_key(key, keysize);
            crypto_ecdsa_sign(args[0], lens[0], sig, MBEDTLS_ECP_DP_SECP256K1);

            extension_writeback(sig,64);

            break;
        case WalletRegister:
            printf1(TAG_WALLET,"WalletRegister\n");
            if (args[0] == NULL)
            {
                ret = CTAP2_ERR_MISSING_PARAMETER;
                printf2(TAG_ERR,"Missing parameter for WalletReg\n");
                goto cleanup;
            }
            if (lens[0] < 8 || lens[0] > keysize)
            {
                ret = CTAP1_ERR_INVALID_LENGTH;
                printf2(TAG_ERR,"Invalid length for WalletReg\n");
                goto cleanup;
            }
            if (ctap_is_pin_set())
            {
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
            }
            else
            {
                printf1(TAG_WALLET,"Warning: no pin is set.  Ignoring pinAuth\n");
            }

            memmove(chksum, args[0] + lens[0] - 4, 4);
            lens[0] -= 4;

            // perform integrity check
            /*printf1(TAG_WALLET,"shasum on [%d]: ",lens[0]); dump_hex1(TAG_WALLET, args[0], lens[0]);*/
            crypto_sha256_init();
            crypto_sha256_update(args[0], lens[0]);
            crypto_sha256_final(shasum);
            crypto_sha256_init();
            crypto_sha256_update(shasum, 32);
            crypto_sha256_final(shasum);

            /*printf1(TAG_WALLET,"shasum: "); dump_hex1(TAG_WALLET, shasum, 32);*/

            if (memcmp(shasum, chksum, 4) != 0)
            {
                ret = CTAP2_ERR_CREDENTIAL_NOT_VALID;
                printf2(TAG_ERR,"Integrity fail for WalletReg\n");
                dump_hex1(TAG_ERR, chksum, sizeof(chksum));
                goto cleanup;
            }

            // drop the first byte
            args[0]++;
            lens[0]--;

            printf1(TAG_WALLET,"adding key [%d]: ",lens[0]); dump_hex1(TAG_WALLET, args[0], lens[0]);

            if (lens[0] == 33)
            {
                // drop the last byte
                lens[0]--;
            }

            ret = ctap_store_key(0, args[0], lens[0]);

            if (ret == ERR_NO_KEY_SPACE || ret == ERR_KEY_SPACE_TAKEN)
            {
                ret = CTAP2_ERR_KEY_STORE_FULL;
                goto cleanup;
            }


            break;
        case WalletPin:
            printf1(TAG_WALLET,"WalletPin\n");
            ret = wallet_pin(req->p1, req->pinAuth, args[0], args[1], args[2], lens[0]);
            break;
        case WalletReset:
            // resets device
            printf1(TAG_WALLET,"WalletReset\n");

            if ( ! ctap_device_locked() )
            {
                if ( ctap_is_pin_set() )
                {
                    if ( ! check_pinhash(req->pinAuth, msg_buf, reqlen))
                    {
                        printf2(TAG_ERR,"pinAuth is NOT valid\n");
                        dump_hex1(TAG_ERR,msg_buf,reqlen);
                        ret = CTAP2_ERR_PIN_AUTH_INVALID;
                        goto cleanup;
                    }

                }
            }

            if (ctap_user_presence_test(5000))
            {
                printf1(TAG_WALLET,"Reseting device!\n");
                ctap_reset();
            }
            else
            {
                ret = CTAP2_ERR_OPERATION_DENIED;
                goto cleanup;
            }


            break;


        default:
            printf2(TAG_ERR,"Invalid wallet command: %x\n",req->operation);
            ret = CTAP1_ERR_INVALID_COMMAND;
            break;
    }

cleanup:

    return ret;
}
