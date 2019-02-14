// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "ctap.h"
#include "ctaphid.h"
#include "ctap_parse.h"
#include "ctap_errors.h"
#include "cose_key.h"
#include "crypto.h"
#include "util.h"
#include "log.h"
#include "device.h"
#include APP_CONFIG
#include "wallet.h"
#include "extensions.h"

#include "device.h"

#define PIN_TOKEN_SIZE      16
uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
uint8_t KEY_AGREEMENT_PUB[64];
static uint8_t KEY_AGREEMENT_PRIV[32];
static uint8_t PIN_CODE_HASH[32];
static int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

AuthenticatorState STATE;

static struct {
    CTAP_authDataHeader authData;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    CTAP_credentialDescriptor creds[ALLOW_LIST_MAX_SIZE-1];
    uint8_t lastcmd;
    uint32_t count;
    uint32_t index;
    uint32_t time;
    uint8_t user_verified;
} getAssertionState;

uint8_t verify_pin_auth(uint8_t * pinAuth, uint8_t * clientDataHash)
{
    uint8_t hmac[32];

    crypto_sha256_hmac_init(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);
    crypto_sha256_update(clientDataHash, CLIENT_DATA_HASH_SIZE);
    crypto_sha256_hmac_final(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);

    if (memcmp(pinAuth, hmac, 16) == 0)
    {
        return 0;
    }
    else
    {
        printf2(TAG_ERR,"Pin auth failed\n");
        dump_hex1(TAG_ERR,pinAuth,16);
        dump_hex1(TAG_ERR,hmac,16);
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

}

uint8_t ctap_get_info(CborEncoder * encoder)
{
    int ret;
    CborEncoder array;
    CborEncoder map;
    CborEncoder options;
    CborEncoder pins;

    const int number_of_versions = 2;

    ret = cbor_encoder_create_map(encoder, &map, 5);
    check_ret(ret);
    {

        ret = cbor_encode_uint(&map, RESP_versions);     //  versions key
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, number_of_versions);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "U2F_V2");
                check_ret(ret);
                ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_aaguid);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, CTAP_AAGUID, 16);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_maxMsgSize);
        check_ret(ret);
        {
            ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_pinProtocols);
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &pins, 1);
            check_ret(ret);
            {
                ret = cbor_encode_int(&pins, 1);
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &pins);
            check_ret(ret);
        }



        ret = cbor_encode_uint(&map, RESP_options);
        check_ret(ret);
        {
            ret = cbor_encoder_create_map(&map, &options,4);
            check_ret(ret);
            {
                ret = cbor_encode_text_string(&options, "plat", 4);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 0);     // Not attached to platform
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "rk", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);     // Capable of storing keys locally
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "up", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);     // Capable of testing user presence
                    check_ret(ret);
                }

                // NOT [yet] capable of verifying user
                // Do not add option if UV isn't supported.
                //
                // ret = cbor_encode_text_string(&options, "uv", 2);
                // check_ret(ret);
                // {
                //     ret = cbor_encode_boolean(&options, 0);
                //     check_ret(ret);
                // }
                ret = cbor_encode_text_string(&options, "clientPin", 9);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, ctap_is_pin_set());
                    check_ret(ret);
                }


            }
            ret = cbor_encoder_close_container(&map, &options);
            check_ret(ret);
        }


    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return CTAP1_ERR_SUCCESS;
}



static int ctap_add_cose_key(CborEncoder * cose_key, uint8_t * x, uint8_t * y, uint8_t credtype, int32_t algtype)
{
    int ret;
    CborEncoder map;

    ret = cbor_encoder_create_map(cose_key, &map, 5);
    check_ret(ret);


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
        check_ret(ret);
        ret = cbor_encode_int(&map, COSE_KEY_KTY_EC2);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
        check_ret(ret);
        ret = cbor_encode_int(&map, algtype);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_CRV);
        check_ret(ret);
        ret = cbor_encode_int(&map, COSE_KEY_CRV_P256);
        check_ret(ret);
    }


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, x, 32);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_Y);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, y, 32);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(cose_key, &map);
    check_ret(ret);

    return 0;
}
static int ctap_generate_cose_key(CborEncoder * cose_key, uint8_t * hmac_input, int len, uint8_t credtype, int32_t algtype)
{
    uint8_t x[32], y[32];

    if (credtype != PUB_KEY_CRED_PUB_KEY)
    {
        printf2(TAG_ERR,"Error, pubkey credential type not supported\n");
        return -1;
    }
    switch(algtype)
    {
        case COSE_ALG_ES256:
            crypto_ecc256_derive_public_key(hmac_input, len, x, y);
            break;
        default:
            printf2(TAG_ERR,"Error, COSE alg %d not supported\n", algtype);
            return -1;
    }
    int ret = ctap_add_cose_key(cose_key, x, y, credtype, algtype);
    check_ret(ret);
    return 0;
}

void make_auth_tag(uint8_t * rpIdHash, uint8_t * nonce, uint32_t count, uint8_t * tag)
{
    uint8_t hashbuf[32];
    crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY, 0, hashbuf);
    crypto_sha256_update(rpIdHash, 32);
    crypto_sha256_update(nonce, CREDENTIAL_NONCE_SIZE);
    crypto_sha256_update((uint8_t*)&count, 4);
    crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY,0,hashbuf);

    memmove(tag, hashbuf, CREDENTIAL_TAG_SIZE);
}

void ctap_flush_state(int backup)
{
    authenticator_write_state(&STATE, 0);
    if (backup)
    {
        authenticator_write_state(&STATE, 1);
    }
}

static uint32_t auth_data_update_count(CTAP_authDataHeader * authData)
{
    uint32_t count = ctap_atomic_count( 0 );
    if (count == 0)     // count 0 will indicate invalid token
    {
        count = ctap_atomic_count( 0 );

    }
    uint8_t * byte = (uint8_t*) &authData->signCount;

    *byte++ = (count >> 24) & 0xff;
    *byte++ = (count >> 16) & 0xff;
    *byte++ = (count >> 8) & 0xff;
    *byte++ = (count >> 0) & 0xff;

    return count;
}

static void ctap_increment_rk_store()
{
    STATE.rk_stored++;
    ctap_flush_state(1);
}

static int is_matching_rk(CTAP_residentKey * rk, CTAP_residentKey * rk2)
{
    return (memcmp(rk->id.rpIdHash, rk2->id.rpIdHash, 32) == 0) &&
           (memcmp(rk->user.id, rk2->user.id, rk->user.id_size) == 0) &&
           (rk->user.id_size == rk2->user.id_size);
}


static int ctap_make_auth_data(struct rpId * rp, CborEncoder * map, uint8_t * auth_data_buf, unsigned int len, CTAP_userEntity * user, uint8_t credtype, int32_t algtype, int32_t * sz, int store)
{
    CborEncoder cose_key;
    int auth_data_sz, ret;
    uint32_t count;
    CTAP_residentKey rk, rk2;
    CTAP_authData * authData = (CTAP_authData *)auth_data_buf;

    uint8_t * cose_key_buf = auth_data_buf + sizeof(CTAP_authData);

    if((sizeof(CTAP_authDataHeader)) > len)
    {
        printf1(TAG_ERR,"assertion fail, auth_data_buf must be at least %d bytes\n", sizeof(CTAP_authData) - sizeof(CTAP_attestHeader));
        exit(1);
    }

    crypto_sha256_init();
    crypto_sha256_update(rp->id, rp->size);
    crypto_sha256_final(authData->head.rpIdHash);

    printf1(TAG_RED, "rpId: "); dump_hex1(TAG_RED, rp->id, rp->size);
    printf1(TAG_RED, "hash: "); dump_hex1(TAG_RED, authData->head.rpIdHash, 32);

    count = auth_data_update_count(&authData->head);

    device_set_status(CTAPHID_STATUS_UPNEEDED);
    int but = ctap_user_presence_test();

    if (!but)
    {
        return CTAP2_ERR_OPERATION_DENIED;
    }
    else if (but < 0)   // Cancel
    {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    device_set_status(CTAPHID_STATUS_PROCESSING);

    authData->head.flags = (but << 0);
    authData->head.flags |= (ctap_is_pin_set() << 2);



    if (credtype != 0)
    {
        // add attestedCredentialData
        authData->head.flags |= (1 << 6);//include attestation data

        cbor_encoder_init(&cose_key, cose_key_buf, len - sizeof(CTAP_authData), 0);

        memmove(authData->attest.aaguid, CTAP_AAGUID, 16);
        authData->attest.credLenL =  sizeof(CredentialId) & 0x00FF;
        authData->attest.credLenH = (sizeof(CredentialId) & 0xFF00) >> 8;

        memset((uint8_t*)&authData->attest.id, 0, sizeof(CredentialId));

        ctap_generate_rng(authData->attest.id.nonce, CREDENTIAL_NONCE_SIZE);

        authData->attest.id.count = count;

        memmove(authData->attest.id.rpIdHash, authData->head.rpIdHash, 32);

        // Make a tag we can later check to make sure this is a token we made
        make_auth_tag(authData->head.rpIdHash, authData->attest.id.nonce, count, authData->attest.id.tag);

        // resident key
        if (store)
        {
            memmove(&rk.id, &authData->attest.id, sizeof(CredentialId));
            memmove(&rk.user, user, sizeof(CTAP_userEntity));

            unsigned int index = STATE.rk_stored;
            unsigned int i;
            for (i = 0; i < index; i++)
            {
                ctap_load_rk(i, &rk2);
                if (is_matching_rk(&rk, &rk2))
                {
                    ctap_overwrite_rk(i, &rk);
                    goto done_rk;
                }
            }
            if (index >= ctap_rk_size())
            {
                printf2(TAG_ERR, "Out of memory for resident keys\r\n");
                return CTAP2_ERR_KEY_STORE_FULL;
            }
            ctap_increment_rk_store();
            ctap_store_rk(index, &rk);
            dump_hex1(TAG_GREEN, rk.id.rpIdHash, 32);
        }
done_rk:

        // DELETE
        //crypto_aes256_init(CRYPTO_TRANSPORT_KEY, NULL);
        //crypto_aes256_encrypt((uint8_t*)&authData->attest.credential.user, CREDENTIAL_ENC_SIZE);
        printf1(TAG_GREEN, "MADE credId: "); dump_hex1(TAG_GREEN, (uint8_t*) &authData->attest.id, sizeof(CredentialId));

        ctap_generate_cose_key(&cose_key, (uint8_t*)&authData->attest.id, sizeof(CredentialId), credtype, algtype);

        auth_data_sz = sizeof(CTAP_authData) + cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);

    }
    else
    {
        auth_data_sz = sizeof(CTAP_authDataHeader);
    }

    {
        ret = cbor_encode_int(map,RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(map, auth_data_buf, auth_data_sz);
        check_ret(ret);
    }

    if (sz) *sz = auth_data_sz;
    return 0;
}


/**
 *
 * @param in_sigbuf IN location to deposit signature (must be 64 bytes)
 * @param out_sigder OUT location to deposit der signature (must be 72 bytes)
 * @return length of der signature
 * // FIXME add tests for maximum and minimum length of the input and output
 */
int ctap_encode_der_sig(const uint8_t * const in_sigbuf, uint8_t * const out_sigder)
{
    // Need to caress into dumb der format ..
    uint8_t i;
    uint8_t lead_s = 0;  // leading zeros
    uint8_t lead_r = 0;
    for (i=0; i < 32; i++)
        if (in_sigbuf[i] == 0) lead_r++;
        else break;

    for (i=0; i < 32; i++)
        if (in_sigbuf[i+32] == 0) lead_s++;
        else break;

    int8_t pad_s = ((in_sigbuf[32 + lead_s] & 0x80) == 0x80);
    int8_t pad_r = ((in_sigbuf[0 + lead_r] & 0x80) == 0x80);

    memset(out_sigder, 0, 72);
    out_sigder[0] = 0x30;
    out_sigder[1] = 0x44 + pad_s + pad_r - lead_s - lead_r;

    // R ingredient
    out_sigder[2] = 0x02;
    out_sigder[3 + pad_r] = 0;
    out_sigder[3] = 0x20 + pad_r - lead_r;
    memmove(out_sigder + 4 + pad_r, in_sigbuf + lead_r, 32u - lead_r);

    // S ingredient
    out_sigder[4 + 32 + pad_r - lead_r] = 0x02;
    out_sigder[5 + 32 + pad_r + pad_s - lead_r] = 0;
    out_sigder[5 + 32 + pad_r - lead_r] = 0x20 + pad_s - lead_s;
    memmove(out_sigder + 6 + 32 + pad_r + pad_s - lead_r, in_sigbuf + 32u + lead_s, 32u - lead_s);

    return 0x46 + pad_s + pad_r - lead_r - lead_s;
}

// require load_key prior to this
// @data data to hash before signature
// @clientDataHash for signature
// @tmp buffer for hash.  (can be same as data if data >= 32 bytes)
// @sigbuf OUT location to deposit signature (must be 64 bytes)
// @sigder OUT location to deposit der signature (must be 72 bytes)
// @return length of der signature
int ctap_calculate_signature(uint8_t * data, int datalen, uint8_t * clientDataHash, uint8_t * hashbuf, uint8_t * sigbuf, uint8_t * sigder)
{
    // calculate attestation sig
    crypto_sha256_init();
    crypto_sha256_update(data, datalen);
    crypto_sha256_update(clientDataHash, CLIENT_DATA_HASH_SIZE);
    crypto_sha256_final(hashbuf);

    crypto_ecc256_sign(hashbuf, 32, sigbuf);

    return ctap_encode_der_sig(sigbuf,sigder);
}

uint8_t ctap_add_attest_statement(CborEncoder * map, uint8_t * sigder, int len)
{
    int ret;

    CborEncoder stmtmap;
    CborEncoder x5carr;


    ret = cbor_encode_int(map,RESP_attStmt);
    check_ret(ret);
    ret = cbor_encoder_create_map(map, &stmtmap, 3);
    check_ret(ret);
    {
        ret = cbor_encode_text_stringz(&stmtmap,"alg");
        check_ret(ret);
        ret = cbor_encode_int(&stmtmap,COSE_ALG_ES256);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"sig");
        check_ret(ret);
        ret = cbor_encode_byte_string(&stmtmap, sigder, len);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"x5c");
        check_ret(ret);
        ret = cbor_encoder_create_array(&stmtmap, &x5carr, 1);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&x5carr, attestation_cert_der, attestation_cert_der_size);
            check_ret(ret);
            ret = cbor_encoder_close_container(&stmtmap, &x5carr);
            check_ret(ret);
        }
    }

    ret = cbor_encoder_close_container(map, &stmtmap);
    check_ret(ret);
    return 0;
}

// Return 1 if credential belongs to this token
int ctap_authenticate_credential(struct rpId * rp, CTAP_credentialDescriptor * desc)
{
    uint8_t tag[16];

    make_auth_tag(desc->credential.id.rpIdHash, desc->credential.id.nonce, desc->credential.id.count, tag);

    return (memcmp(desc->credential.id.tag, tag, CREDENTIAL_TAG_SIZE) == 0);
}



uint8_t ctap_make_credential(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_makeCredential MC;
    int ret;
    unsigned int i;
    uint8_t auth_data_buf[300];
    CTAP_credentialDescriptor * excl_cred = (CTAP_credentialDescriptor *) auth_data_buf;
    uint8_t * sigbuf = auth_data_buf + 32;
    uint8_t * sigder = auth_data_buf + 32 + 64;

    ret = ctap_parse_make_credential(&MC,encoder,request,length);
    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_make_credential failed\n");
        return ret;
    }
    if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask)
    {
        printf2(TAG_ERR,"error, required parameter(s) for makeCredential are missing\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (ctap_is_pin_set() == 1 && MC.pinAuthPresent == 0)
    {
        printf2(TAG_ERR,"pinAuth is required\n");
        return CTAP2_ERR_PIN_REQUIRED;
    }
    else
    {
        if (ctap_is_pin_set() || (MC.pinAuthPresent))
        {
            ret = verify_pin_auth(MC.pinAuth, MC.clientDataHash);
            check_retr(ret);
        }
    }

    if (MC.up)
    {
        return CTAP2_ERR_INVALID_OPTION;
    }

    // crypto_aes256_init(CRYPTO_TRANSPORT_KEY, NULL);
    for (i = 0; i < MC.excludeListSize; i++)
    {
        ret = parse_credential_descriptor(&MC.excludeList, excl_cred);
        if (ret == CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        {
            continue;
        }
        check_retr(ret);

        printf1(TAG_GREEN, "checking credId: "); dump_hex1(TAG_GREEN, (uint8_t*) &excl_cred->credential.id, sizeof(CredentialId));
        // DELETE
        // crypto_aes256_reset_iv(NULL);
        // crypto_aes256_decrypt((uint8_t*)& excl_cred->credential.enc, CREDENTIAL_ENC_SIZE);
        if (ctap_authenticate_credential(&MC.rp, excl_cred))
        {
            printf1(TAG_MC, "Cred %d failed!\r\n",i);
            return CTAP2_ERR_CREDENTIAL_EXCLUDED;
        }

        ret = cbor_value_advance(&MC.excludeList);
        check_ret(ret);
    }

    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);
    int32_t auth_data_sz;

    ret = ctap_make_auth_data(&MC.rp, &map, auth_data_buf, sizeof(auth_data_buf),
            &MC.user, MC.publicKeyCredentialType, MC.COSEAlgorithmIdentifier, &auth_data_sz, MC.rk);

    check_retr(ret);

    crypto_ecc256_load_attestation_key();
    int sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_sz, MC.clientDataHash, auth_data_buf, sigbuf, sigder);

    printf1(TAG_MC,"der sig [%d]: ", sigder_sz); dump_hex1(TAG_MC, sigder, sigder_sz);

    ret = ctap_add_attest_statement(&map, sigder, sigder_sz);
    check_retr(ret);

    {
        ret = cbor_encode_int(&map,RESP_fmt);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&map, "packed");
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return CTAP1_ERR_SUCCESS;
}

/*static int pick_first_authentic_credential(CTAP_getAssertion * GA)*/
/*{*/
    /*int i;*/
    /*for (i = 0; i < GA->credLen; i++)*/
    /*{*/
        /*if (GA->creds[i].credential.enc.count != 0)*/
        /*{*/
            /*return i;*/
        /*}*/
    /*}*/
    /*return -1;*/
/*}*/

static uint8_t ctap_add_credential_descriptor(CborEncoder * map, CTAP_credentialDescriptor * cred)
{
    CborEncoder desc;
    int ret = cbor_encode_int(map, RESP_credential);
    check_ret(ret);

    ret = cbor_encoder_create_map(map, &desc, 2);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&desc, "type", 4);
        check_ret(ret);

        ret = cbor_encode_text_string(&desc, "public-key", 10);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_string(&desc, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&desc, (uint8_t*)&cred->credential.id, sizeof(CredentialId));
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(map, &desc);
    check_ret(ret);

    return 0;
}

uint8_t ctap_add_user_entity(CborEncoder * map, CTAP_userEntity * user)
{
    CborEncoder entity;
    int ret = cbor_encode_int(map, RESP_publicKeyCredentialUserEntity);
    check_ret(ret);

    int dispname = (user->name[0] != 0) && getAssertionState.user_verified;

    if (dispname)
        ret = cbor_encoder_create_map(map, &entity, 4);
    else
        ret = cbor_encoder_create_map(map, &entity, 1);
    check_ret(ret);

    printf1(TAG_GREEN,"id_size: %d\r\n", user->id_size);
    {
        ret = cbor_encode_text_string(&entity, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&entity, user->id, user->id_size);
        check_ret(ret);
    }

    if (dispname)
    {
        ret = cbor_encode_text_string(&entity, "name", 4);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->name);
        check_ret(ret);

        ret = cbor_encode_text_string(&entity, "displayName", 11);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->displayName);
        check_ret(ret);

        ret = cbor_encode_text_string(&entity, "icon", 4);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->icon);
        check_ret(ret);


    }

    ret = cbor_encoder_close_container(map, &entity);
    check_ret(ret);

    return 0;
}

static int cred_cmp_func(const void * _a, const void * _b)
{
    CTAP_credentialDescriptor * a = (CTAP_credentialDescriptor * )_a;
    CTAP_credentialDescriptor * b = (CTAP_credentialDescriptor * )_b;
    return b->credential.id.count - a->credential.id.count;
}

static void add_existing_user_info(CTAP_credentialDescriptor * cred)
{
    CTAP_residentKey rk;
    int index = STATE.rk_stored;
    int i;
    for (i = 0; i < index; i++)
    {
        ctap_load_rk(i, &rk);
        if (is_matching_rk(&rk, (CTAP_residentKey *)&cred->credential))
        {
            printf1(TAG_GREEN, "found rk match for allowList item (%d)\r\n", i);
            memmove(&cred->credential.user, &rk.user, sizeof(CTAP_userEntity));
            return;
        }

    }
    printf1(TAG_GREEN, "NO rk match for allowList item \r\n");
}

// @return the number of valid credentials
// sorts the credentials.  Most recent creds will be first, invalid ones last.
int ctap_filter_invalid_credentials(CTAP_getAssertion * GA)
{
    int i;
    int count = 0;
    uint8_t rpIdHash[32];
    CTAP_residentKey rk;

    for (i = 0; i < GA->credLen; i++)
    {
        if (! ctap_authenticate_credential(&GA->rp, &GA->creds[i]))
        {
            printf1(TAG_GA, "CRED #%d is invalid\n", GA->creds[i].credential.id.count);
#ifdef ENABLE_U2F_EXTENSIONS
            if (is_extension_request((uint8_t*)&GA->creds[i].credential.id, sizeof(CredentialId)))
            {
                printf1(TAG_EXT, "CRED #%d is extension\n", GA->creds[i].credential.id.count);
                count++;
            }
            else
#endif
            {
                GA->creds[i].credential.id.count = 0;      // invalidate
            }

        }
        else
        {
            // add user info if it exists
            add_existing_user_info(&GA->creds[i]);
            count++;
        }
    }

    // No allowList, so use all matching RK's matching rpId
    if (!GA->credLen)
    {
        crypto_sha256_init();
        crypto_sha256_update(GA->rp.id,GA->rp.size);
        crypto_sha256_final(rpIdHash);

        printf1(TAG_GREEN, "true rpIdHash: ");  dump_hex1(TAG_GREEN, rpIdHash, 32);
        for(i = 0; i < STATE.rk_stored; i++)
        {
            ctap_load_rk(i, &rk);
            printf1(TAG_GREEN, "rpIdHash%d: ", i);  dump_hex1(TAG_GREEN, rk.id.rpIdHash, 32);
            if (memcmp(rk.id.rpIdHash, rpIdHash, 32) == 0)
            {
                printf1(TAG_GA, "RK %d is a rpId match!\r\n", i);
                if (count == ALLOW_LIST_MAX_SIZE-1)
                {
                    printf2(TAG_ERR, "not enough ram allocated for matching RK's (%d)\r\n", count);
                    break;
                }
                GA->creds[count].type = PUB_KEY_CRED_PUB_KEY;
                memmove(&(GA->creds[count].credential), &rk, sizeof(CTAP_residentKey));
                count++;
            }
        }
        GA->credLen = count;
    }

    printf1(TAG_GA, "qsort length: %d\n", GA->credLen);
    qsort(GA->creds, GA->credLen, sizeof(CTAP_credentialDescriptor), cred_cmp_func);
    return count;
}


static void save_credential_list(CTAP_authDataHeader * head, uint8_t * clientDataHash, CTAP_credentialDescriptor * creds, uint32_t count)
{
    if(count)
    {
        if (count > ALLOW_LIST_MAX_SIZE-1)
        {
            printf2(TAG_ERR, "ALLOW_LIST_MAX_SIZE Exceeded\n");
            exit(1);
        }
        memmove(getAssertionState.clientDataHash, clientDataHash, CLIENT_DATA_HASH_SIZE);
        memmove(&getAssertionState.authData, head, sizeof(CTAP_authDataHeader));
        memmove(getAssertionState.creds, creds, sizeof(CTAP_credentialDescriptor) * (count));
    }
    getAssertionState.count = count;
    printf1(TAG_GA,"saved %d credentials\n",count);
}

static CTAP_credentialDescriptor * pop_credential()
{
    if (getAssertionState.count > 0)
    {
        getAssertionState.count--;
        return &getAssertionState.creds[getAssertionState.count];
    }
    else
    {
        return NULL;
    }
}

// adds 2 to map, or 3 if add_user is true
uint8_t ctap_end_get_assertion(CborEncoder * map, CTAP_credentialDescriptor * cred, uint8_t * auth_data_buf, uint8_t * clientDataHash, int add_user)
{
    int ret;
    uint8_t sigbuf[64];
    uint8_t sigder[72];
    int sigder_sz;

    if (add_user)
    {
        printf1(TAG_GREEN, "adding user details to output\r\n");
        ret = ctap_add_user_entity(map, &cred->credential.user);
        check_retr(ret);
    }

    ret = ctap_add_credential_descriptor(map, cred);
    check_retr(ret);

    crypto_ecc256_load_key((uint8_t*)&cred->credential.id, sizeof(CredentialId), NULL, 0);

#ifdef ENABLE_U2F_EXTENSIONS
    if ( extend_fido2(&cred->credential.id, sigder) )
    {
        sigder_sz = 72;
    }
    else
#endif
    {
        sigder_sz = ctap_calculate_signature(auth_data_buf, sizeof(CTAP_authDataHeader), clientDataHash, auth_data_buf, sigbuf, sigder);
    }

    {
        ret = cbor_encode_int(map, RESP_signature);
        check_ret(ret);
        ret = cbor_encode_byte_string(map, sigder, sigder_sz);
        check_ret(ret);
    }
    return 0;
}

uint8_t ctap_get_next_assertion(CborEncoder * encoder)
{
    int ret;
    CborEncoder map;
    CTAP_authDataHeader authData;
    memmove(&authData, &getAssertionState.authData, sizeof(CTAP_authDataHeader));
    // CTAP_authDataHeader * authData = &getAssertionState.authData;

    CTAP_credentialDescriptor * cred = pop_credential();

    if (cred == NULL)
    {
        return CTAP2_ERR_NOT_ALLOWED;
    }

    auth_data_update_count(&authData);
    int add_user_info = cred->credential.user.id_size;

    if (add_user_info)
    {
        printf1(TAG_GREEN, "adding user info to assertion response\r\n");
        ret = cbor_encoder_create_map(encoder, &map, 4);
    }
    else
    {
        printf1(TAG_GREEN, "NOT adding user info to assertion response\r\n");
        ret = cbor_encoder_create_map(encoder, &map, 3);
    }

    check_ret(ret);
    printf1(TAG_RED, "RPID hash: "); dump_hex1(TAG_RED, authData.rpIdHash, 32);

    {
        ret = cbor_encode_int(&map,RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, (uint8_t *)&authData, sizeof(CTAP_authDataHeader));
        check_ret(ret);
    }

    // if only one account for this RP, null out the user details
    if (!getAssertionState.user_verified)
    {
        printf1(TAG_GREEN, "Not verified, nulling out user details on response\r\n");
        memset(cred->credential.user.name, 0, USER_NAME_LIMIT);
    }


    ret = ctap_end_get_assertion(&map, cred, (uint8_t *)&authData, getAssertionState.clientDataHash, add_user_info);
    check_retr(ret);

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return 0;
}

uint8_t ctap_get_assertion(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_getAssertion GA;
    uint8_t auth_data_buf[sizeof(CTAP_authDataHeader)];
    int ret = ctap_parse_get_assertion(&GA,request,length);

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_get_assertion failed\n");
        return ret;
    }

    if (ctap_is_pin_set() && GA.pinAuthPresent == 0)
    {
        printf2(TAG_ERR,"pinAuth is required\n");
        return CTAP2_ERR_PIN_REQUIRED;
    }
    else
    {
        if (ctap_is_pin_set() || (GA.pinAuthPresent))
        {
            ret = verify_pin_auth(GA.pinAuth, GA.clientDataHash);
            check_retr(ret);
            getAssertionState.user_verified = 1;
        }
    }

    if (!GA.rp.size || !GA.clientDataHashPresent)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CborEncoder map;

    int map_size = 3;

    printf1(TAG_GA, "ALLOW_LIST has %d creds\n", GA.credLen);
    int validCredCount = ctap_filter_invalid_credentials(&GA);

    int add_user_info = GA.creds[validCredCount - 1].credential.user.id_size;
    if (validCredCount > 1)
    {
       map_size += 1;
    }

    if (add_user_info)
    {
        map_size += 1;
    }

    ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);

#ifdef ENABLE_U2F_EXTENSIONS
    if ( is_extension_request((uint8_t*)&GA.creds[validCredCount - 1].credential.id, sizeof(CredentialId)) )
    {
        ret = cbor_encode_int(&map,RESP_authData);
        check_ret(ret);
        memset(auth_data_buf,0,sizeof(auth_data_buf));
        ret = cbor_encode_byte_string(&map, auth_data_buf, sizeof(auth_data_buf));
        check_ret(ret);
    }
    else
#endif
    {
        ret = ctap_make_auth_data(&GA.rp, &map, auth_data_buf, sizeof(auth_data_buf), NULL, 0,0,NULL, 0);
        check_retr(ret);
    }

    /*for (int j = 0; j < GA.credLen; j++)*/
    /*{*/
        /*printf1(TAG_GA,"CRED ID (# %d): ", GA.creds[j].credential.enc.count);*/
        /*dump_hex1(TAG_GA, (uint8_t*)&GA.creds[j].credential, sizeof(struct Credential));*/
        /*if (ctap_authenticate_credential(&GA.rp, &GA.creds[j]))   // warning encryption will break this*/
        /*{*/
            /*printf1(TAG_GA,"  Authenticated.\n");*/
        /*}*/
        /*else*/
        /*{*/
            /*printf1(TAG_GA,"  NOT authentic.\n");*/
        /*}*/
    /*}*/

    // Decrypt here

    //
    if (validCredCount > 0)
    {
        save_credential_list((CTAP_authDataHeader*)auth_data_buf, GA.clientDataHash, GA.creds, validCredCount-1);   // skip last one
    }
    else
    {
        printf2(TAG_ERR,"Error, no authentic credential\n");
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    // if only one account for this RP, null out the user details
    if (validCredCount < 2 || !getAssertionState.user_verified)
    {
        printf1(TAG_GREEN, "Only one account, nulling out user details on response\r\n");
        memset(&GA.creds[0].credential.user.name, 0, USER_NAME_LIMIT);
    }

    printf1(TAG_GA,"resulting order of creds:\n");
    int j;
    for (j = 0; j < GA.credLen; j++)
    {
        printf1(TAG_GA,"CRED ID (# %d)\n", GA.creds[j].credential.id.count);
    }

    if (validCredCount > 1)
    {
        ret = cbor_encode_int(&map, RESP_numberOfCredentials);
        check_ret(ret);
        ret = cbor_encode_int(&map, validCredCount);
        check_ret(ret);
    }

    CTAP_credentialDescriptor * cred = &GA.creds[validCredCount - 1];

    ret = ctap_end_get_assertion(&map, cred, auth_data_buf, GA.clientDataHash, add_user_info);
    check_retr(ret);

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return 0;
}

// Return how many trailing zeros in a buffer
static int trailing_zeros(uint8_t * buf, int indx)
{
    int c = 0;
    while(0==buf[indx] && indx)
    {
        indx--;
        c++;
    }
    return c;
}

uint8_t ctap_update_pin_if_verified(uint8_t * pinEnc, int len, uint8_t * platform_pubkey, uint8_t * pinAuth, uint8_t * pinHashEnc)
{
    uint8_t shared_secret[32];
    uint8_t hmac[32];
    int ret;

    if (len < 64)
    {
        return CTAP1_ERR_OTHER;
    }

    if (ctap_is_pin_set())  // Check first, prevent SCA
    {
        if (ctap_device_locked())
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
    }

    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_sha256_hmac_init(shared_secret, 32, hmac);
    crypto_sha256_update(pinEnc, len);
    if (pinHashEnc != NULL)
    {
        crypto_sha256_update(pinHashEnc, 16);
    }
    crypto_sha256_hmac_final(shared_secret, 32, hmac);

    if (memcmp(hmac, pinAuth, 16) != 0)
    {
        printf2(TAG_ERR,"pinAuth failed for update pin\n");
        dump_hex1(TAG_ERR, hmac,16);
        dump_hex1(TAG_ERR, pinAuth,16);
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    crypto_aes256_init(shared_secret, NULL);

    while((len & 0xf) != 0) // round up to nearest  AES block size multiple
    {
        len++;
    }

    crypto_aes256_decrypt(pinEnc, len);



    ret = trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
    ret = NEW_PIN_ENC_MIN_SIZE  - ret;

    if (ret < NEW_PIN_MIN_SIZE || ret >= NEW_PIN_MAX_SIZE)
    {
        printf2(TAG_ERR,"new PIN is too short or too long [%d bytes]\n", ret);
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    else
    {
        printf1(TAG_CP,"new pin: %s [%d bytes]\n", pinEnc, ret);
        dump_hex1(TAG_CP, pinEnc, ret);
    }

    if (ctap_is_pin_set())
    {
        if (ctap_device_locked())
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        crypto_aes256_reset_iv(NULL);
        crypto_aes256_decrypt(pinHashEnc, 16);
        if (memcmp(pinHashEnc, PIN_CODE_HASH, 16) != 0)
        {
            crypto_ecc256_make_key_pair(KEY_AGREEMENT_PUB, KEY_AGREEMENT_PRIV);
            ctap_decrement_pin_attempts();
            if (ctap_device_boot_locked())
            {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }
            return CTAP2_ERR_PIN_INVALID;
        }
        else
        {
            ctap_reset_pin_attempts();
        }
    }

    ctap_update_pin(pinEnc, ret);

    return 0;
}

uint8_t ctap_add_pin_if_verified(uint8_t * pinTokenEnc, uint8_t * platform_pubkey, uint8_t * pinHashEnc)
{
    uint8_t shared_secret[32];

    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_aes256_init(shared_secret, NULL);

    crypto_aes256_decrypt(pinHashEnc, 16);


    if (memcmp(pinHashEnc, PIN_CODE_HASH, 16) != 0)
    {
        printf2(TAG_ERR,"Pin does not match!\n");
        printf2(TAG_ERR,"platform-pin-hash: "); dump_hex1(TAG_ERR, pinHashEnc, 16);
        printf2(TAG_ERR,"authentic-pin-hash: "); dump_hex1(TAG_ERR, PIN_CODE_HASH, 16);
        printf2(TAG_ERR,"shared-secret: "); dump_hex1(TAG_ERR, shared_secret, 32);
        printf2(TAG_ERR,"platform-pubkey: "); dump_hex1(TAG_ERR, platform_pubkey, 64);
        printf2(TAG_ERR,"device-pubkey: "); dump_hex1(TAG_ERR, KEY_AGREEMENT_PUB, 64);
        // Generate new keyAgreement pair
        crypto_ecc256_make_key_pair(KEY_AGREEMENT_PUB, KEY_AGREEMENT_PRIV);
        ctap_decrement_pin_attempts();
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        return CTAP2_ERR_PIN_INVALID;
    }

    ctap_reset_pin_attempts();
    crypto_aes256_reset_iv(NULL);

    memmove(pinTokenEnc, PIN_TOKEN, PIN_TOKEN_SIZE);
    crypto_aes256_encrypt(pinTokenEnc, PIN_TOKEN_SIZE);

    return 0;
}

uint8_t ctap_client_pin(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_clientPin CP;
    CborEncoder map;
    uint8_t pinTokenEnc[PIN_TOKEN_SIZE];
    int ret = ctap_parse_client_pin(&CP,request,length);

    switch(CP.subCommand)
    {
        case CP_cmdSetPin:
        case CP_cmdChangePin:
        case CP_cmdGetPinToken:
            if (ctap_device_locked())
            {
                return  CTAP2_ERR_PIN_BLOCKED;
            }
            if (ctap_device_boot_locked())
            {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }
    }

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_client_pin failed\n");
        return ret;
    }

    if (CP.pinProtocol != 1 || CP.subCommand == 0)
    {
        return CTAP1_ERR_OTHER;
    }

    int num_map = (CP.getRetries ? 1 : 0);

    switch(CP.subCommand)
    {
        case CP_cmdGetRetries:
            printf1(TAG_CP,"CP_cmdGetRetries\n");
            ret = cbor_encoder_create_map(encoder, &map, 1);
            check_ret(ret);

            CP.getRetries = 1;

            break;
        case CP_cmdGetKeyAgreement:
            printf1(TAG_CP,"CP_cmdGetKeyAgreement\n");
            num_map++;
            ret = cbor_encoder_create_map(encoder, &map, num_map);
            check_ret(ret);

            ret = cbor_encode_int(&map, RESP_keyAgreement);
            check_ret(ret);
            ret = ctap_add_cose_key(&map, KEY_AGREEMENT_PUB, KEY_AGREEMENT_PUB+32, PUB_KEY_CRED_PUB_KEY, COSE_ALG_ES256);
            check_retr(ret);

            break;
        case CP_cmdSetPin:
            printf1(TAG_CP,"CP_cmdSetPin\n");

            if (ctap_is_pin_set())
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }
            if (!CP.newPinEncSize || !CP.pinAuthPresent || !CP.keyAgreementPresent)
            {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinAuth, NULL);
            check_retr(ret);
            break;
        case CP_cmdChangePin:
            printf1(TAG_CP,"CP_cmdChangePin\n");

            if (! ctap_is_pin_set())
            {
                return CTAP2_ERR_PIN_NOT_SET;
            }

            if (!CP.newPinEncSize || !CP.pinAuthPresent || !CP.keyAgreementPresent || !CP.pinHashEncPresent)
            {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinAuth, CP.pinHashEnc);
            check_retr(ret);
            break;
        case CP_cmdGetPinToken:
            if (!ctap_is_pin_set())
            {
                return CTAP2_ERR_PIN_NOT_SET;
            }
            num_map++;
            ret = cbor_encoder_create_map(encoder, &map, num_map);
            check_ret(ret);

            printf1(TAG_CP,"CP_cmdGetPinToken\n");
            if (CP.keyAgreementPresent == 0 || CP.pinHashEncPresent == 0)
            {
                printf2(TAG_ERR,"Error, missing keyAgreement or pinHashEnc for cmdGetPin\n");
                return CTAP2_ERR_MISSING_PARAMETER;
            }
            ret = cbor_encode_int(&map, RESP_pinToken);
            check_ret(ret);

            /*ret = ctap_add_pin_if_verified(&map, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);*/
            ret = ctap_add_pin_if_verified(pinTokenEnc, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);
            check_retr(ret);

            ret = cbor_encode_byte_string(&map, pinTokenEnc, PIN_TOKEN_SIZE);
            check_ret(ret);



            break;

        default:
            printf2(TAG_ERR,"Error, invalid client pin subcommand\n");
            return CTAP1_ERR_OTHER;
    }

    if (CP.getRetries)
    {
        ret = cbor_encode_int(&map, RESP_retries);
        check_ret(ret);
        ret = cbor_encode_int(&map, ctap_leftover_pin_attempts());
        check_ret(ret);
    }

    if (num_map || CP.getRetries)
    {
        ret = cbor_encoder_close_container(encoder, &map);
        check_ret(ret);
    }

    return 0;
}

void ctap_response_init(CTAP_RESPONSE * resp)
{
    memset(resp, 0, sizeof(CTAP_RESPONSE));
    resp->data_size = CTAP_RESPONSE_BUFFER_SIZE;
}


uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    CborEncoder encoder;
    uint8_t status = 0;
    uint8_t cmd = *pkt_raw;
    pkt_raw++;
    length--;

    uint8_t * buf = resp->data;

    cbor_encoder_init(&encoder, buf, resp->data_size, 0);

    printf1(TAG_CTAP,"cbor input structure: %d bytes\n", length);
    printf1(TAG_DUMP,"cbor req: "); dump_hex1(TAG_DUMP, pkt_raw, length);

    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
        case CTAP_GET_ASSERTION:
            if (ctap_device_locked())
            {
                status = CTAP2_ERR_PIN_BLOCKED;
                goto done;
            }
            if (ctap_device_boot_locked())
            {
                status = CTAP2_ERR_PIN_AUTH_BLOCKED;
                goto done;
            }
            break;
    }

    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
            device_set_status(CTAPHID_STATUS_PROCESSING);
            printf1(TAG_CTAP,"CTAP_MAKE_CREDENTIAL\n");
            timestamp();
            status = ctap_make_credential(&encoder, pkt_raw, length);
            printf1(TAG_TIME,"make_credential time: %d ms\n", timestamp());

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            dump_hex1(TAG_DUMP, buf, resp->length);

            break;
        case CTAP_GET_ASSERTION:
            device_set_status(CTAPHID_STATUS_PROCESSING);
            printf1(TAG_CTAP,"CTAP_GET_ASSERTION\n");
            timestamp();
            status = ctap_get_assertion(&encoder, pkt_raw, length);
            printf1(TAG_TIME,"get_assertion time: %d ms\n", timestamp());

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            printf1(TAG_DUMP,"cbor [%d]: \n",  resp->length);
                dump_hex1(TAG_DUMP,buf, resp->length);
            break;
        case CTAP_CANCEL:
            printf1(TAG_CTAP,"CTAP_CANCEL\n");
            break;
        case CTAP_GET_INFO:
            printf1(TAG_CTAP,"CTAP_GET_INFO\n");
            status = ctap_get_info(&encoder);

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            dump_hex1(TAG_DUMP, buf, resp->length);

            break;
        case CTAP_CLIENT_PIN:
            printf1(TAG_CTAP,"CTAP_CLIENT_PIN\n");
            status = ctap_client_pin(&encoder, pkt_raw, length);

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            dump_hex1(TAG_DUMP, buf, resp->length);
            break;
        case CTAP_RESET:
            printf1(TAG_CTAP,"CTAP_RESET\n");
            if (ctap_user_presence_test())
            {
                ctap_reset();
            }
            else
            {
                status = CTAP2_ERR_OPERATION_DENIED;
            }
            break;
        case GET_NEXT_ASSERTION:
            printf1(TAG_CTAP,"CTAP_NEXT_ASSERTION\n");
            if (getAssertionState.lastcmd == CTAP_GET_ASSERTION)
            {
                status = ctap_get_next_assertion(&encoder);
                resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
                dump_hex1(TAG_DUMP, buf, resp->length);
                if (status == 0)
                {
                    cmd = CTAP_GET_ASSERTION;       // allow for next assertion
                }
            }
            else
            {
                printf2(TAG_ERR, "unwanted GET_NEXT_ASSERTION.  lastcmd == 0x%02x\n", getAssertionState.lastcmd);
                dump_hex1(TAG_GREEN, (uint8_t*)&getAssertionState, sizeof(getAssertionState));
                status = CTAP2_ERR_NOT_ALLOWED;
            }
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            printf2(TAG_ERR,"error, invalid cmd\n");
    }

done:
    device_set_status(CTAPHID_STATUS_IDLE);
    getAssertionState.lastcmd = cmd;

    if (status != CTAP1_ERR_SUCCESS)
    {
        resp->length = 0;
    }

    printf1(TAG_CTAP,"cbor output structure: %d bytes.  Return 0x%02x\n", resp->length, status);

    return status;
}



static void ctap_state_init()
{
    // Set to 0xff instead of 0x00 to be easier on flash
    memset(&STATE, 0xff, sizeof(AuthenticatorState));
    // Fresh RNG for key
    ctap_generate_rng(STATE.key_space, KEY_SPACE_BYTES);

    STATE.is_initialized = INITIALIZED_MARKER;
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
    STATE.is_pin_set = 0;
    STATE.rk_stored = 0;

    ctap_reset_rk();
}

void ctap_init()
{
    crypto_ecc256_init();

    authenticator_read_state(&STATE);

    device_set_status(CTAPHID_STATUS_IDLE);

    if (STATE.is_initialized == INITIALIZED_MARKER)
    {
        printf1(TAG_STOR,"Auth state is initialized\n");
    }
    else
    {
        printf1(TAG_STOR,"Auth state is NOT initialized.  Initializing..\n");
        if (authenticator_is_backup_initialized())
        {
            printf1(TAG_ERR,"Warning: memory corruption detected.  restoring from backup..\n");
            authenticator_read_backup_state(&STATE);
            authenticator_write_state(&STATE, 0);
        }
        else
        {
            ctap_state_init();
            authenticator_write_state(&STATE, 0);
            authenticator_write_state(&STATE, 1);

        }
    }

    crypto_load_master_secret(STATE.key_space);

    if (ctap_is_pin_set())
    {
        printf1(TAG_STOR,"pin code: \"%s\"\n", STATE.pin_code);
        crypto_sha256_init();
        crypto_sha256_update(STATE.pin_code, STATE.pin_code_length);
        crypto_sha256_final(PIN_CODE_HASH);
        printf1(TAG_STOR, "attempts_left: %d\n", STATE.remaining_tries);
    }
    else
    {
        printf1(TAG_STOR,"pin not set.\n");
    }
    if (ctap_device_locked())
    {
        printf1(TAG_ERR, "DEVICE LOCKED!\n");
    }

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        exit(1);
    }

    crypto_ecc256_make_key_pair(KEY_AGREEMENT_PUB, KEY_AGREEMENT_PRIV);

#ifdef BRIDGE_TO_WALLET
    wallet_init();
#endif

}

uint8_t ctap_is_pin_set()
{
    return STATE.is_pin_set == 1;
}

uint8_t ctap_pin_matches(uint8_t * pin, int len)
{
    return memcmp(pin, STATE.pin_code, len) == 0;
}


void ctap_update_pin(uint8_t * pin, int len)
{
    if (len > NEW_PIN_ENC_MIN_SIZE || len < 4)
    {
        printf2(TAG_ERR, "Update pin fail length\n");
        exit(1);
    }
    memset(STATE.pin_code, 0, NEW_PIN_ENC_MIN_SIZE);
    memmove(STATE.pin_code, pin, len);
    STATE.pin_code_length = len;
    STATE.pin_code[NEW_PIN_ENC_MIN_SIZE - 1] = 0;

    crypto_sha256_init();
    crypto_sha256_update(STATE.pin_code, len);
    crypto_sha256_final(PIN_CODE_HASH);

    STATE.is_pin_set = 1;

    authenticator_write_state(&STATE, 1);
    authenticator_write_state(&STATE, 0);

    printf1(TAG_CTAP, "New pin set: %s\n", STATE.pin_code);
}

uint8_t ctap_decrement_pin_attempts()
{
    if (PIN_BOOT_ATTEMPTS_LEFT > 0)
    {
        PIN_BOOT_ATTEMPTS_LEFT--;
    }
    if (! ctap_device_locked())
    {
        STATE.remaining_tries--;
        ctap_flush_state(0);
        printf1(TAG_CP, "ATTEMPTS left: %d\n", STATE.remaining_tries);

        if (ctap_device_locked())
        {
            memset(PIN_TOKEN,0,sizeof(PIN_TOKEN));
            memset(PIN_CODE_HASH,0,sizeof(PIN_CODE_HASH));
            printf1(TAG_CP, "Device locked!\n");
        }
    }
    else
    {
        printf1(TAG_CP, "Device locked!\n");
        return -1;
    }
    return 0;
}

int8_t ctap_device_locked()
{
    return STATE.remaining_tries <= 0;
}

int8_t ctap_device_boot_locked()
{
    return PIN_BOOT_ATTEMPTS_LEFT <= 0;
}

int8_t ctap_leftover_pin_attempts()
{
    return STATE.remaining_tries;
}

void ctap_reset_pin_attempts()
{
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
    PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;
    ctap_flush_state(0);
}

void ctap_reset_state()
{
    memset(&getAssertionState, 0, sizeof(getAssertionState));
}

uint16_t ctap_keys_stored()
{
    int total = 0;
    int i;
    for (i = 0; i < MAX_KEYS; i++)
    {
        if (STATE.key_lens[i] != 0xffff)
        {
            total += 1;
        }
        else
        {
            break;
        }
    }
    return total;
}

static uint16_t key_addr_offset(int index)
{
    uint16_t offset = 0;
    int i;
    for (i = 0; i < index; i++)
    {
        if (STATE.key_lens[i] != 0xffff) offset += STATE.key_lens[i];
    }
    return offset;
}

uint16_t ctap_key_len(uint8_t index)
{
    int i = ctap_keys_stored();
    if (index >= i || index >= MAX_KEYS)
    {
        return 0;
    }
    if (STATE.key_lens[index] == 0xffff) return 0;
    return STATE.key_lens[index];

}

int8_t ctap_store_key(uint8_t index, uint8_t * key, uint16_t len)
{
    int i = ctap_keys_stored();
    uint16_t offset;
    if (i >= MAX_KEYS || index >= MAX_KEYS || !len)
    {
        return ERR_NO_KEY_SPACE;
    }

    if (STATE.key_lens[index] != 0xffff)
    {
        return ERR_KEY_SPACE_TAKEN;
    }

    offset = key_addr_offset(index);

    if ((offset + len) > KEY_SPACE_BYTES)
    {
        return ERR_NO_KEY_SPACE;
    }

    STATE.key_lens[index] = len;

    memmove(STATE.key_space + offset, key, len);

    ctap_flush_state(1);

    return 0;
}

int8_t ctap_load_key(uint8_t index, uint8_t * key)
{
    int i = ctap_keys_stored();
    uint16_t offset;
    uint16_t len;
    if (index >= i || index >= MAX_KEYS)
    {
        return ERR_NO_KEY_SPACE;
    }

    if (STATE.key_lens[index] == 0xffff)
    {
        return ERR_KEY_SPACE_EMPTY;
    }

    offset = key_addr_offset(index);
    len = ctap_key_len(index);

    if ((offset + len) > KEY_SPACE_BYTES)
    {
        return ERR_NO_KEY_SPACE;
    }

    memmove(key, STATE.key_space + offset, len);

    return 0;
}



void ctap_reset()
{
    ctap_state_init();

    authenticator_write_state(&STATE, 0);
    authenticator_write_state(&STATE, 1);

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        exit(1);
    }

    ctap_reset_state();
    memset(PIN_CODE_HASH,0,sizeof(PIN_CODE_HASH));
    crypto_ecc256_make_key_pair(KEY_AGREEMENT_PUB, KEY_AGREEMENT_PRIV);

    crypto_reset_master_secret();
}
