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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "ctap.h"
#include "ctap_parse.h"
#include "ctap_errors.h"
#include "cose_key.h"
#include "crypto.h"
#include "util.h"
#include "log.h"
#include "device.h"
#include "app.h"
#include "wallet.h"

#include "device.h"

#define PIN_TOKEN_SIZE      16
uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
uint8_t KEY_AGREEMENT_PUB[64];
static uint8_t KEY_AGREEMENT_PRIV[32];
static uint8_t PIN_CODE_HASH[32];

AuthenticatorState STATE;

static struct {
    CTAP_authDataHeader authData;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    CTAP_credentialDescriptor creds[ALLOW_LIST_MAX_SIZE-1];
    uint8_t lastcmd;
    uint32_t count;
    uint32_t index;
    uint32_t time;
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
            ret = cbor_encoder_create_map(&map, &options,5);
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
                    ret = cbor_encode_boolean(&options, 0);     // State-less device, requires allowList parameter.
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "up", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);     // Capable of testing user presence
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "uv", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 0);     // NOT [yet] capable of verifying user
                    check_ret(ret);
                }
                ret = cbor_encode_text_string(&options, "clientPin", 9);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, ctap_is_pin_set());     // NOT [yet] capable of verifying user
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
    ctap_add_cose_key(cose_key, x, y, credtype, algtype);
    return 0;
}

void make_auth_tag(struct rpId * rp, CTAP_userEntity * user, uint32_t count, uint8_t * tag)
{
    uint8_t hashbuf[32];
    crypto_sha256_hmac_init(NULL, 0, hashbuf);
    crypto_sha256_update(rp->id, rp->size);
    crypto_sha256_update(user->id, user->id_size);
    crypto_sha256_update(user->name, strnlen((const char*)user->name, USER_NAME_LIMIT));
    crypto_sha256_update((uint8_t*)&count, 4);
    crypto_sha256_hmac_final(NULL,0,hashbuf);

    memmove(tag, hashbuf, CREDENTIAL_TAG_SIZE);
}

static uint32_t auth_data_update_count(CTAP_authDataHeader * authData)
{
    uint32_t count = ctap_atomic_count( 0 );
    if (count == 0)     // count 0 will indicate invalid token
    {
        count = ctap_atomic_count( 0 );
    }
    uint8_t * byte = (uint8_t*) &authData->signCount;

    *byte++ = count & 0xff;
    count = count >> 8;
    *byte++ = count & 0xff;
    count = count >> 8;
    *byte++ = count & 0xff;
    count = count >> 8;
    *byte++ = count & 0xff;

    return count;
}

static int ctap_make_auth_data(struct rpId * rp, CborEncoder * map, uint8_t * auth_data_buf, int len, CTAP_userEntity * user, uint8_t credtype, int32_t algtype)
{
    CborEncoder cose_key;
    int auth_data_sz, ret;
    uint32_t count;
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

    count = auth_data_update_count(&authData->head);

    authData->head.flags = (ctap_user_presence_test() << 0);
    authData->head.flags |= (ctap_user_verification(0) << 2);


    if (credtype != 0)
    {
        // add attestedCredentialData
        authData->head.flags |= (1 << 6);//include attestation data

        cbor_encoder_init(&cose_key, cose_key_buf, len - sizeof(CTAP_authData), 0);

        memmove(authData->attest.aaguid, CTAP_AAGUID, 16);
        authData->attest.credLenL = CREDENTIAL_ID_SIZE & 0x00FF;
        authData->attest.credLenH = (CREDENTIAL_ID_SIZE & 0xFF00) >> 8;

#if CREDENTIAL_ID_SIZE != 168
#error "need to double check credential ID layout"
#else
        memset((uint8_t*)&authData->attest.credential, 0, sizeof(struct Credential));

        // Make a tag we can later check to make sure this is a token we made
        make_auth_tag(rp, user, count, authData->attest.credential.tag);

        memmove(&authData->attest.credential.enc.user, user, sizeof(CTAP_userEntity)); //TODO encrypt this
        authData->attest.credential.enc.count = count;

        crypto_aes256_init(CRYPTO_TRANSPORT_KEY, NULL);
        crypto_aes256_encrypt((uint8_t*)&authData->attest.credential.enc, CREDENTIAL_ENC_SIZE);

        ctap_generate_cose_key(&cose_key, (uint8_t*)&authData->attest.credential, sizeof(struct Credential), credtype, algtype);

        printf1(TAG_MC,"COSE_KEY: "); dump_hex1(TAG_MC, cose_key_buf, cbor_encoder_get_buffer_size(&cose_key, cose_key_buf));

        auth_data_sz = sizeof(CTAP_authData) + cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);
#endif

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

    return auth_data_sz;
}


int ctap_encode_der_sig(uint8_t * sigbuf, uint8_t * sigder)
{
    // Need to caress into dumb der format ..
    int i;
    int8_t lead_s = 0;  // leading zeros
    int8_t lead_r = 0;
    for (i=0; i < 32; i++)
        if (sigbuf[i] == 0) lead_r++;
        else break;

    for (i=0; i < 32; i++)
        if (sigbuf[i+32] == 0) lead_s++;
        else break;

    int8_t pad_s = ((sigbuf[32 + lead_s] & 0x80) == 0x80);
    int8_t pad_r = ((sigbuf[0 + lead_r] & 0x80) == 0x80);

    sigder[0] = 0x30;
    sigder[1] = 0x44 + pad_s + pad_r - lead_s - lead_r;

    sigder[2] = 0x02;
    sigder[3 + pad_r] = 0;
    sigder[3] = 0x20 + pad_r - lead_r;
    memmove(sigder + 4 + pad_r, sigbuf + lead_r, 32);

    sigder[4 + 32 + pad_r - lead_r] = 0x02;
    sigder[5 + 32 + pad_r + pad_s - lead_r] = 0;
    sigder[5 + 32 + pad_r - lead_r] = 0x20 + pad_s - lead_s;
    memmove(sigder + 6 + 32 + pad_r + pad_s - lead_r, sigbuf + 32 + lead_s, 32);
    //
    return 0x46 + pad_s + pad_r - lead_r - lead_s;
}

// require load_key prior to this
// @data data to hash before signature
// @clientDataHash for signature
// @tmp buffer for hash.  (can be same as data if data >= 32 bytes)
// @sigbuf location to deposit signature (must be 64 bytes)
// @sigder location to deposit der signature (must be 72 bytes)
// @return length of der signature
int ctap_calculate_signature(uint8_t * data, int datalen, uint8_t * clientDataHash, uint8_t * hashbuf, uint8_t * sigbuf, uint8_t * sigder)
{
    // calculate attestation sig
    crypto_sha256_init();
    crypto_sha256_update(data, datalen);
    crypto_sha256_update(clientDataHash, CLIENT_DATA_HASH_SIZE);
    crypto_sha256_final(hashbuf);

    printf1(TAG_GREEN, "sha256: ");  dump_hex1(TAG_DUMP,hashbuf,32);
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
    if (desc->type != PUB_KEY_CRED_PUB_KEY)
    {
        printf1(TAG_GA,"unsupported credential type: %d\n", desc->type);
        return 0;
    }

    make_auth_tag(rp, &desc->credential.enc.user, desc->credential.enc.count, tag);

    return (memcmp(desc->credential.tag, tag, CREDENTIAL_TAG_SIZE) == 0);
}



uint8_t ctap_make_credential(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_makeCredential MC;
    int ret, i;
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
        if (ctap_is_pin_set())
        {
            ret = verify_pin_auth(MC.pinAuth, MC.clientDataHash);
            check_retr(ret);
        }
    }

    for (i = 0; i < MC.excludeListSize; i++)
    {
        ret = parse_credential_descriptor(&MC.excludeList, excl_cred);
        if (ret == CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        {
            continue;
        }
        check_retr(ret);

        if (ctap_authenticate_credential(&MC.rp, excl_cred))
        {
            return CTAP2_ERR_CREDENTIAL_EXCLUDED;
        }

        ret = cbor_value_advance(&MC.excludeList);
        check_ret(ret);
    }

    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);

    int auth_data_sz = ctap_make_auth_data(&MC.rp, &map, auth_data_buf, sizeof(auth_data_buf),
            &MC.user, MC.publicKeyCredentialType, MC.COSEAlgorithmIdentifier);

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

        ret = cbor_encode_int(&desc, cred->type);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_string(&desc, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&desc, (uint8_t*)&cred->credential, sizeof(struct Credential));
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

    ret = cbor_encoder_create_map(map, &entity, 2);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&entity, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&entity, user->id, user->id_size);
        check_ret(ret);
    }


    {
        ret = cbor_encode_text_string(&entity, "displayName", 11);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->name);
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
    return b->credential.enc.count - a->credential.enc.count;
}

// @return the number of valid credentials
// sorts the credentials.  Most recent creds will be first, invalid ones last.
int ctap_filter_invalid_credentials(CTAP_getAssertion * GA)
{
    int i;
    int count = 0;
    crypto_aes256_init(CRYPTO_TRANSPORT_KEY, NULL);


    for (i = 0; i < GA->credLen; i++)
    {
        crypto_aes256_reset_iv(NULL);
        crypto_aes256_decrypt((uint8_t*)&GA->creds[i].credential.enc, CREDENTIAL_ENC_SIZE);
        if (! ctap_authenticate_credential(&GA->rp, &GA->creds[i]))
        {
            printf1(TAG_GA, "CRED #%d is invalid\n", GA->creds[i].credential.enc.count);
            GA->creds[i].credential.enc.count = 0;      // invalidate
        }
        else
        {
            count++;
        }
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

uint8_t ctap_end_get_assertion(CborEncoder * map, CTAP_credentialDescriptor * cred, uint8_t * auth_data_buf, uint8_t * clientDataHash)
{
    int ret;
    uint8_t sigbuf[64];
    uint8_t sigder[72];

    ret = ctap_add_user_entity(map, &cred->credential.enc.user);
    check_retr(ret);

    // Re-encrypt the credential
    crypto_aes256_init(CRYPTO_TRANSPORT_KEY, NULL);
    crypto_aes256_encrypt((uint8_t*)&cred->credential.enc, CREDENTIAL_ENC_SIZE);
    //

    ret = ctap_add_credential_descriptor(map, cred);
    check_retr(ret);

    crypto_ecc256_load_key((uint8_t*)&cred->credential, sizeof(struct Credential), NULL, 0);

    /*printf1(TAG_GREEN,"auth_data_buf: "); dump_hex1(TAG_DUMP, auth_data_buf, sizeof(CTAP_authDataHeader));*/
    /*printf1(TAG_GREEN,"clientdatahash: "); dump_hex1(TAG_DUMP, clientDataHash, 32);*/
    /*printf1(TAG_GREEN,"credential: # %d\n", cred->credential.enc.count);*/
    /*dump_hex1(TAG_DUMP, clientDataHash, 32);*/

    int sigder_sz = ctap_calculate_signature(auth_data_buf, sizeof(CTAP_authDataHeader), clientDataHash, auth_data_buf, sigbuf, sigder);

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
    CTAP_authDataHeader * authData = &getAssertionState.authData;

    CTAP_credentialDescriptor * cred = pop_credential();

    if (cred == NULL)
    {
        return CTAP2_ERR_NOT_ALLOWED;
    }

    auth_data_update_count(authData);


    ret = cbor_encoder_create_map(encoder, &map, 4);
    check_ret(ret);

    {
        ret = cbor_encode_int(&map,RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, (uint8_t *)authData, sizeof(CTAP_authDataHeader));
        check_ret(ret);
    }

    ret = ctap_end_get_assertion(&map, cred, (uint8_t *)authData, getAssertionState.clientDataHash);
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
        if (ctap_is_pin_set())
        {
            ret = verify_pin_auth(GA.pinAuth, GA.clientDataHash);
            check_retr(ret);
        }
    }


    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 5);
    check_ret(ret);

    ctap_make_auth_data(&GA.rp, &map, auth_data_buf, sizeof(auth_data_buf), NULL, 0,0);

    printf1(TAG_GA, "ALLOW_LIST has %d creds\n", GA.credLen);
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
    int validCredCount = ctap_filter_invalid_credentials(&GA);
    if (validCredCount > 0)
    {
        save_credential_list((CTAP_authDataHeader*)auth_data_buf, GA.clientDataHash, GA.creds, validCredCount-1);   // skip last one
    }
    else
    {
        printf2(TAG_ERR,"Error, no authentic credential\n");
        return CTAP2_ERR_CREDENTIAL_NOT_VALID;
    }

    printf1(TAG_RED,"resulting order of creds:\n");
    for (int j = 0; j < GA.credLen; j++)
    {
        printf1(TAG_RED,"CRED ID (# %d)\n", GA.creds[j].credential.enc.count);
    }

    {
        ret = cbor_encode_int(&map, RESP_numberOfCredentials);
        check_ret(ret);
        ret = cbor_encode_int(&map, validCredCount);
        check_ret(ret);
    }

    CTAP_credentialDescriptor * cred = &GA.creds[validCredCount - 1];

    ret = ctap_end_get_assertion(&map, cred, auth_data_buf, GA.clientDataHash);
    check_retr(ret);

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return 0;
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
            return CTAP2_ERR_OPERATION_DENIED;
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

    printf1(TAG_CP,"new pin: %s\n", pinEnc);

    ret = strnlen((const char *)pinEnc, NEW_PIN_ENC_MAX_SIZE);
    if (ret == NEW_PIN_ENC_MAX_SIZE)
    {
        printf2(TAG_ERR,"No NULL terminator in new pin string\n");
        return CTAP1_ERR_OTHER;
    }
    else if (ret < 4)
    {
        printf2(TAG_ERR,"new PIN is too short\n");
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }

    if (ctap_is_pin_set())
    {
        if (ctap_device_locked())
        {
            return CTAP2_ERR_OPERATION_DENIED;
        }
        crypto_aes256_reset_iv(NULL);
        crypto_aes256_decrypt(pinHashEnc, 16);
        if (memcmp(pinHashEnc, PIN_CODE_HASH, 16) != 0)
        {
            crypto_ecc256_make_key_pair(KEY_AGREEMENT_PUB, KEY_AGREEMENT_PRIV);
            ctap_decrement_pin_attempts();
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

    if (num_map)
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
    uint64_t t1;
    uint64_t t2;
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
        case CTAP_CLIENT_PIN:
            if (ctap_device_locked())
            {
                status = CTAP2_ERR_OPERATION_DENIED;
                goto done;
            }
            break;
    }

    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
            printf1(TAG_CTAP,"CTAP_MAKE_CREDENTIAL\n");
            t1 = millis();
            status = ctap_make_credential(&encoder, pkt_raw, length);
            t2 = millis();
            printf1(TAG_TIME,"make_credential time: %d ms\n", t2-t1);

            dump_hex1(TAG_DUMP, buf, cbor_encoder_get_buffer_size(&encoder, buf));

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_GET_ASSERTION:
            printf1(TAG_CTAP,"CTAP_GET_ASSERTION\n");
            t1 = millis();
            status = ctap_get_assertion(&encoder, pkt_raw, length);
            t2 = millis();
            printf1(TAG_TIME,"get_assertion time: %d ms\n", t2-t1);

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            printf1(TAG_DUMP,"cbor [%d]: \n",  cbor_encoder_get_buffer_size(&encoder, buf));
                dump_hex1(TAG_DUMP,buf, cbor_encoder_get_buffer_size(&encoder, buf));
            break;
        case CTAP_CANCEL:
            printf1(TAG_CTAP,"CTAP_CANCEL\n");
            break;
        case CTAP_GET_INFO:
            printf1(TAG_CTAP,"CTAP_GET_INFO\n");
            status = ctap_get_info(&encoder);

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            dump_hex1(TAG_DUMP, buf, cbor_encoder_get_buffer_size(&encoder, buf));

            break;
        case CTAP_CLIENT_PIN:
            printf1(TAG_CTAP,"CTAP_CLIENT_PIN\n");
            status = ctap_client_pin(&encoder, pkt_raw, length);
            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            dump_hex1(TAG_DUMP, buf, cbor_encoder_get_buffer_size(&encoder, buf));
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
                dump_hex1(TAG_DUMP, buf, cbor_encoder_get_buffer_size(&encoder, buf));
                if (status == 0)
                {
                    cmd = CTAP_GET_ASSERTION;       // allow for next assertion
                }
            }
            else
            {
                printf2(TAG_ERR, "unwanted GET_NEXT_ASSERTION\n");
                status = CTAP2_ERR_NOT_ALLOWED;
            }
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            printf2(TAG_ERR,"error, invalid cmd\n");
    }

done:
    getAssertionState.lastcmd = cmd;

    if (status != CTAP1_ERR_SUCCESS)
    {
        resp->length = 0;
    }

    printf1(TAG_CTAP,"cbor output structure: %d bytes\n", resp->length);

    return status;
}

void ctap_flush_state(int backup)
{
    authenticator_write_state(&STATE, 0);
    if (backup)
    {
        authenticator_write_state(&STATE, 1);
    }
}

static void ctap_state_init()
{
    // Set to 0xff instead of 0x00 to be easier on flash
    memset(&STATE, 0xff, sizeof(AuthenticatorState));
    STATE.is_initialized = INITIALIZED_MARKER;
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
    STATE.is_pin_set = 0;
}

void ctap_init()
{
    crypto_ecc256_init();

    authenticator_read_state(&STATE);

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

    if (ctap_is_pin_set())
    {
        printf1(TAG_STOR,"pin code: \"%s\"\n", STATE.pin_code);
        crypto_sha256_init();
        crypto_sha256_update(STATE.pin_code, strnlen((char *)STATE.pin_code, NEW_PIN_ENC_MAX_SIZE));
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
    // TODO this should go in flash
    if (len > NEW_PIN_ENC_MAX_SIZE-1 || len < 4)
    {
        printf2(TAG_ERR, "Update pin fail length\n");
        exit(1);
    }
    memset(STATE.pin_code, 0, NEW_PIN_ENC_MAX_SIZE);
    memmove(STATE.pin_code, pin, len);

    crypto_sha256_init();
    crypto_sha256_update(STATE.pin_code, len);
    crypto_sha256_final(PIN_CODE_HASH);

    STATE.is_pin_set = 1;

    printf1(TAG_CTAP, "New pin set: %s\n", STATE.pin_code);
}

uint8_t ctap_decrement_pin_attempts()
{
    if (STATE.remaining_tries > 0)
    {
        STATE.remaining_tries--;
        ctap_flush_state(0);
        printf1(TAG_CP, "ATTEMPTS left: %d\n", STATE.remaining_tries);

        if (STATE.remaining_tries == 0)
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
    return STATE.remaining_tries == 0;
}

int8_t ctap_leftover_pin_attempts()
{
    return STATE.remaining_tries;
}

void ctap_reset_pin_attempts()
{
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
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

    ctap_flush_state(0);
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

    crypto_reset_master_secret();   // Not sure what the significance of this is??
}

