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
#include "u2f.h"
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
#include "data_migration.h"

uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
uint8_t KEY_AGREEMENT_PUB[64];
static uint8_t KEY_AGREEMENT_PRIV[32];
static int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

AuthenticatorState STATE;

static void ctap_reset_key_agreement();

struct _getAssertionState getAssertionState;

// Generate a mask to keep the confidentiality of the "metadata" field in the credential ID.
// Mask = hmac(device-secret, 14-random-bytes-in-credential-id)
// Masked_output = Mask ^ metadata
static void add_masked_metadata_for_credential(CredentialId * credential, uint32_t metadata){
    uint8_t mask[32];
    crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY, 0, mask);
    crypto_sha256_update(credential->entropy.nonce, CREDENTIAL_NONCE_SIZE - 4);
    crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY,0, mask);

    credential->entropy.metadata.value = *((uint32_t*)mask) ^ metadata;
}

static uint32_t read_metadata_from_masked_credential(CredentialId * credential){
    uint8_t mask[32];
    crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY, 0, mask);
    crypto_sha256_update(credential->entropy.nonce, CREDENTIAL_NONCE_SIZE - 4);
    crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY,0, mask);

    return credential->entropy.metadata.value ^ *((uint32_t*)mask);
}

static uint32_t read_cred_protect_from_masked_credential(CredentialId * credential)
{
    return read_metadata_from_masked_credential(credential) & 0xffffU;
}

static int32_t read_cose_alg_from_masked_credential(CredentialId * credential)
{
    uint8_t  alg = (read_metadata_from_masked_credential(credential) >> 16) & 0xffU;

    switch (alg)
    {
        default: // what else?
        case CREDID_ALG_ES256:
            return COSE_ALG_ES256;
        case CREDID_ALG_EDDSA:
            return COSE_ALG_EDDSA;
    }
}

static uint8_t check_credential_metadata(CredentialId * credential, uint8_t is_verified, uint8_t is_from_credid_list)
{
    uint32_t cred_protect = read_cred_protect_from_masked_credential(credential);

    switch (cred_protect){
        case EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID:
            if (!is_from_credid_list) {
                if (!is_verified)
                {
                    return CTAP2_ERR_NOT_ALLOWED;
                }
            }
        break;
        case EXT_CRED_PROTECT_REQUIRED:
            if (!is_verified)
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }
        break;
    }

    return 0;
}

static uint8_t verify_pin_auth_ex(uint8_t * pinAuth, uint8_t *buf, size_t len)
{
    uint8_t hmac[32];

    crypto_sha256_hmac_init(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);
    crypto_sha256_update(buf, len);
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

uint8_t verify_pin_auth(uint8_t * pinAuth, uint8_t * clientDataHash)
{
    return verify_pin_auth_ex(pinAuth, clientDataHash, CLIENT_DATA_HASH_SIZE);
}

uint8_t ctap_get_info(CborEncoder * encoder)
{
    int ret;
    CborEncoder array;
    CborEncoder map;
    CborEncoder options;
    CborEncoder pins;
    uint8_t aaguid[16];
    device_read_aaguid(aaguid);

    ret = cbor_encoder_create_map(encoder, &map, 8);
    check_ret(ret);
    {

        ret = cbor_encode_uint(&map, RESP_versions);     //  versions key
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, 3);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "U2F_V2");
                check_ret(ret);
                ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
                check_ret(ret);
                ret = cbor_encode_text_stringz(&array, "FIDO_2_1_PRE");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_extensions);
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, 2);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "credProtect");
                check_ret(ret);

                ret = cbor_encode_text_stringz(&array, "hmac-secret");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_aaguid);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, aaguid, 16);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_options);
        check_ret(ret);
        {
            ret = cbor_encoder_create_map(&map, &options,5);
            check_ret(ret);
            {
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

                ret = cbor_encode_text_string(&options, "plat", 4);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 0);     // Not attached to platform
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "credMgmt", 8);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);
                    check_ret(ret);
                }

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


        ret = cbor_encode_uint(&map, 0x07); //maxCredentialCountInList
        check_ret(ret);
        {
            ret = cbor_encode_uint(&map, ALLOW_LIST_MAX_SIZE);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, 0x08); // maxCredentialIdLength
        check_ret(ret);
        {
            ret = cbor_encode_uint(&map, 128);
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

    ret = cbor_encoder_create_map(cose_key, &map, algtype != COSE_ALG_EDDSA? 5 : 4);
    check_ret(ret);


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
        check_ret(ret);
        ret = cbor_encode_int(&map, algtype != COSE_ALG_EDDSA? COSE_KEY_KTY_EC2 : COSE_KEY_KTY_OKP);
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
        ret = cbor_encode_int(&map, algtype != COSE_ALG_EDDSA? COSE_KEY_CRV_P256: COSE_KEY_CRV_ED25519);
        check_ret(ret);
    }


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, x, 32);
        check_ret(ret);
    }

    if (algtype != COSE_ALG_EDDSA)
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
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
            crypto_ecc256_derive_public_key(hmac_input, len, x, y);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_IDLE);
            break;
        case COSE_ALG_EDDSA:
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
            crypto_ed25519_derive_public_key(hmac_input, len, x);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_IDLE);
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
    memset(hashbuf,0,sizeof(hashbuf));
    crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY, 0, hashbuf);
    crypto_sha256_update(rpIdHash, 32);
    crypto_sha256_update(nonce, CREDENTIAL_NONCE_SIZE);
    crypto_sha256_update((uint8_t*)&count, 4);
    crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY,0,hashbuf);

    memmove(tag, hashbuf, CREDENTIAL_TAG_SIZE);
}

void ctap_flush_state()
{
    authenticator_write_state(&STATE);
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
    ctap_flush_state();
}
static void ctap_decrement_rk_store()
{
    STATE.rk_stored--;
    ctap_flush_state();
}

// Return 1 if rk is valid, 0 if not.
static int ctap_rk_is_valid(CTAP_residentKey * rk)
{
    return (rk->id.count > 0 && rk->id.count != 0xffffffff);
}

static int load_nth_valid_rk(int n, CTAP_residentKey * rk) {

    int valid_count = 0;
    unsigned int i;
    for (i = 0; i < ctap_rk_size(); i++)
    {
        ctap_load_rk(i, rk);
        if ( ctap_rk_is_valid(rk) ) {
            if (valid_count == n) {
                return i;
            }
            valid_count++;
        }
    }
    return -1;
}

static int is_matching_rk(CTAP_residentKey * rk, CTAP_residentKey * rk2)
{
    return (memcmp(rk->id.rpIdHash, rk2->id.rpIdHash, 32) == 0) &&
           (memcmp(rk->user.id, rk2->user.id, rk->user.id_size) == 0) &&
           (rk->user.id_size == rk2->user.id_size);
}

static int is_cred_id_matching_rk(CredentialId * credId, CTAP_residentKey * rk)
{
    return (memcmp(credId, &rk->id, sizeof(CredentialId)) == 0);
}

static int ctap_make_extensions(CTAP_extensions * ext, uint8_t * ext_encoder_buf, unsigned int * ext_encoder_buf_size)
{
    CborEncoder extensions;
    int ret;
    uint8_t extensions_used = 0;
    uint8_t hmac_secret_output_is_valid = 0;
    uint8_t hmac_secret_requested_is_valid = 0;
    uint8_t cred_protect_is_valid = 0;
    uint8_t hmac_secret_output[64];
    uint8_t shared_secret[32];
    uint8_t hmac[32];
    uint8_t credRandom[32];
    uint8_t saltEnc[64];

    if (ext->hmac_secret_present == EXT_HMAC_SECRET_PARSED)
    {
        printf1(TAG_CTAP, "Processing hmac-secret..\r\n");
        memmove(saltEnc, ext->hmac_secret.saltEnc, sizeof(saltEnc));

        crypto_ecc256_shared_secret((uint8_t*) &ext->hmac_secret.keyAgreement.pubkey,
                                    KEY_AGREEMENT_PRIV,
                                    shared_secret);
        crypto_sha256_init();
        crypto_sha256_update(shared_secret, 32);
        crypto_sha256_final(shared_secret);

        crypto_sha256_hmac_init(shared_secret, 32, hmac);
        crypto_sha256_update(saltEnc, ext->hmac_secret.saltLen);
        crypto_sha256_hmac_final(shared_secret, 32, hmac);

        if (memcmp(ext->hmac_secret.saltAuth, hmac, 16) == 0)
        {
            printf1(TAG_CTAP, "saltAuth is valid\r\n");
        }
        else
        {
            printf1(TAG_CTAP, "saltAuth is invalid\r\n");
            return CTAP2_ERR_EXTENSION_FIRST;
        }

        // Generate credRandom
        crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY2, 0, credRandom);
        crypto_sha256_update((uint8_t*)&ext->hmac_secret.credential->id, sizeof(CredentialId));
        crypto_sha256_update(&getAssertionState.user_verified, 1);
        crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY2, 0, credRandom);

        // Decrypt saltEnc
        crypto_aes256_init(shared_secret, NULL);
        crypto_aes256_decrypt(saltEnc, ext->hmac_secret.saltLen);

        // Generate outputs
        crypto_sha256_hmac_init(credRandom, 32, hmac_secret_output);
        crypto_sha256_update(saltEnc, 32);
        crypto_sha256_hmac_final(credRandom, 32, hmac_secret_output);

        if (ext->hmac_secret.saltLen == 64)
        {
            crypto_sha256_hmac_init(credRandom, 32, hmac_secret_output + 32);
            crypto_sha256_update(saltEnc + 32, 32);
            crypto_sha256_hmac_final(credRandom, 32, hmac_secret_output + 32);
        }

        // Encrypt for final output
        crypto_aes256_init(shared_secret, NULL);
        crypto_aes256_encrypt(hmac_secret_output, ext->hmac_secret.saltLen);


        extensions_used += 1;
        hmac_secret_output_is_valid = 1;
    }
    else if (ext->hmac_secret_present == EXT_HMAC_SECRET_REQUESTED)
    {
        extensions_used += 1;
        hmac_secret_requested_is_valid = 1;
    }
    if (ext->cred_protect != EXT_CRED_PROTECT_INVALID) {
        if (
            ext->cred_protect == EXT_CRED_PROTECT_OPTIONAL ||
            ext->cred_protect == EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID ||
            ext->cred_protect == EXT_CRED_PROTECT_REQUIRED
            )
        {
            extensions_used += 1;
            cred_protect_is_valid = 1;
        }
    }

    if (extensions_used > 0)
    {

        // output
        cbor_encoder_init(&extensions, ext_encoder_buf, *ext_encoder_buf_size, 0);
        {
            CborEncoder extension_output_map;
            ret = cbor_encoder_create_map(&extensions, &extension_output_map, extensions_used);
            check_ret(ret);
            if (hmac_secret_output_is_valid) {
                {
                    ret = cbor_encode_text_stringz(&extension_output_map, "hmac-secret");
                    check_ret(ret);

                    ret = cbor_encode_byte_string(&extension_output_map, hmac_secret_output, ext->hmac_secret.saltLen);
                    check_ret(ret);
                }
            }
            if (cred_protect_is_valid) {
                {
                    ret = cbor_encode_text_stringz(&extension_output_map, "credProtect");
                    check_ret(ret);

                    ret = cbor_encode_int(&extension_output_map, ext->cred_protect);
                    check_ret(ret);
                }
            }
            if (hmac_secret_requested_is_valid) {
                {
                    ret = cbor_encode_text_stringz(&extension_output_map, "hmac-secret");
                    check_ret(ret);

                    ret = cbor_encode_boolean(&extension_output_map, 1);
                    check_ret(ret);
                }
            }

            ret = cbor_encoder_close_container(&extensions, &extension_output_map);
            check_ret(ret);

        }
        *ext_encoder_buf_size = cbor_encoder_get_buffer_size(&extensions, ext_encoder_buf);

    } else
    {
        *ext_encoder_buf_size = 0;
    }



    return 0;
}

static unsigned int get_credential_id_size(int type)
{
    if (type == PUB_KEY_CRED_CTAP1)
        return U2F_KEY_HANDLE_SIZE;
    if (type == PUB_KEY_CRED_CUSTOM)
        return getAssertionState.customCredIdSize;
    return sizeof(CredentialId);
}

static int ctap2_user_presence_test()
{
    device_set_status(CTAPHID_STATUS_UPNEEDED);
    int ret = ctap_user_presence_test(CTAP2_UP_DELAY_MS);
    if ( ret > 1 )
    {
        return CTAP2_ERR_PROCESSING;
    }
    else if ( ret > 0 )
    {
        return CTAP1_ERR_SUCCESS;
    }
    else if (ret < 0)
    {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    else
    {
        return CTAP2_ERR_ACTION_TIMEOUT;
    }
}

static int ctap_make_auth_data(struct rpId * rp, CborEncoder * map, uint8_t * auth_data_buf, uint32_t * len, CTAP_credInfo * credInfo, CTAP_extensions * extensions)
{
    CborEncoder cose_key;

    unsigned int auth_data_sz = sizeof(CTAP_authDataHeader);
    uint32_t count;
    CTAP_residentKey rk, rk2;
    CTAP_authData * authData = (CTAP_authData *)auth_data_buf;

    uint8_t * cose_key_buf = auth_data_buf + sizeof(CTAP_authData);

    // memset(&cose_key, 0, sizeof(CTAP_residentKey));
    memset(&rk, 0, sizeof(CTAP_residentKey));
    memset(&rk2, 0, sizeof(CTAP_residentKey));

    if((sizeof(CTAP_authDataHeader)) > *len)
    {
        printf1(TAG_ERR,"assertion fail, auth_data_buf must be at least %d bytes\n", sizeof(CTAP_authData) - sizeof(CTAP_attestHeader));
        exit(1);
    }

    crypto_sha256_init();
    crypto_sha256_update(rp->id, rp->size);
    crypto_sha256_final(authData->head.rpIdHash);

    count = auth_data_update_count(&authData->head);

    int but;

    but = ctap2_user_presence_test();
    if (CTAP2_ERR_PROCESSING == but)
    {
        authData->head.flags = (0 << 0);        // User presence disabled
    }
    else
    {
        check_retr(but);
        authData->head.flags = (1 << 0);        // User presence
    }


    device_set_status(CTAPHID_STATUS_PROCESSING);

    authData->head.flags |= (ctap_is_pin_set() << 2);


    if (credInfo != NULL)
    {
        // add attestedCredentialData
        authData->head.flags |= (1 << 6);//include attestation data

        cbor_encoder_init(&cose_key, cose_key_buf, *len - sizeof(CTAP_authData), 0);

        device_read_aaguid(authData->attest.aaguid);
        authData->attest.credLenL =  sizeof(CredentialId) & 0x00FF;
        authData->attest.credLenH = (sizeof(CredentialId) & 0xFF00) >> 8;

        memset((uint8_t*)&authData->attest.id, 0, sizeof(CredentialId));

        ctap_generate_rng(authData->attest.id.entropy.nonce, CREDENTIAL_NONCE_SIZE);

        uint8_t alg = credInfo->COSEAlgorithmIdentifier == COSE_ALG_EDDSA? CREDID_ALG_EDDSA : CREDID_ALG_ES256;
        add_masked_metadata_for_credential(&authData->attest.id, extensions->cred_protect | (alg << 16));

        authData->attest.id.count = count;

        memmove(authData->attest.id.rpIdHash, authData->head.rpIdHash, 32);

        // Make a tag we can later check to make sure this is a token we made
        make_auth_tag(authData->head.rpIdHash, authData->attest.id.entropy.nonce, count, authData->attest.id.tag);

        // resident key
        if (credInfo->rk)
        {
            memmove(&rk.id, &authData->attest.id, sizeof(CredentialId));
            memmove(&rk.user, &credInfo->user, sizeof(CTAP_userEntity));

            // Copy rpId to RK, but it could be cropped.
            int rp_id_size = rp->size < sizeof(rk.rpId) ? rp->size : sizeof(rk.rpId);
            memmove(rk.rpId, rp->id, rp_id_size);
            rk.rpIdSize = rp_id_size;

            unsigned int index = STATE.rk_stored;
            unsigned int i;
            for (i = 0; i < index; i++)
            {
                int raw_i = load_nth_valid_rk(i, &rk2);
                if (is_matching_rk(&rk, &rk2))
                {
                    ctap_overwrite_rk(raw_i, &rk);
                    goto done_rk;
                }
            }
            for (i = 0; i < ctap_rk_size(); i++){
                ctap_load_rk(i, &rk2);
                if ( ! ctap_rk_is_valid(&rk2) ){
                    ctap_increment_rk_store();
                    ctap_store_rk(i, &rk);
                    printf1(TAG_GREEN, "Created rk %d:", i); dump_hex1(TAG_GREEN, rk.id.rpIdHash, 32);
                    goto done_rk;
                }
            }

            printf2(TAG_ERR, "Out of memory for resident keys\r\n");
            return CTAP2_ERR_KEY_STORE_FULL;
        }
done_rk:

        printf1(TAG_GREEN, "MADE credId: "); dump_hex1(TAG_GREEN, (uint8_t*) &authData->attest.id, sizeof(CredentialId));

        ctap_generate_cose_key(&cose_key, (uint8_t*)&authData->attest.id, sizeof(CredentialId), credInfo->publicKeyCredentialType, credInfo->COSEAlgorithmIdentifier);

        auth_data_sz = sizeof(CTAP_authData) + cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);

    }





    *len = auth_data_sz;
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
    {
        if (in_sigbuf[i] == 0)
        {
            lead_r++;
        }
        else
        {
            break;
        }
    }

    for (i=0; i < 32; i++)
    {
        if (in_sigbuf[i+32] == 0)
        {
            lead_s++;
        }
        else
        {
            break;
        }
    }

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
// @data data to hash before signature, MUST have room to append clientDataHash for ED25519
// @clientDataHash for signature
// @tmp buffer for hash.  (can be same as data if data >= 32 bytes)
// @sigbuf OUT location to deposit signature (must be 64 bytes)
// @sigder OUT location to deposit der signature (must be 72 bytes)
// @return length of der signature
int ctap_calculate_signature(uint8_t * data, int datalen, uint8_t * clientDataHash, uint8_t * hashbuf, uint8_t * sigbuf, uint8_t * sigder, int32_t alg)
{
    // calculate attestation sig
    if (alg == COSE_ALG_EDDSA)
    {
        crypto_ed25519_sign(data, datalen, clientDataHash, CLIENT_DATA_HASH_SIZE, sigder); // not DER, just plain binary!
        return 64;
    }
    else
    {
        crypto_sha256_init();
        crypto_sha256_update(data, datalen);
        crypto_sha256_update(clientDataHash, CLIENT_DATA_HASH_SIZE);
        crypto_sha256_final(hashbuf);

        crypto_ecc256_sign(hashbuf, 32, sigbuf);
        return ctap_encode_der_sig(sigbuf,sigder);
    }
}

uint8_t ctap_add_attest_statement(CborEncoder * map, uint8_t * sigder, int len)
{
    int ret;
    uint8_t cert[1024];
    uint16_t cert_size = device_attestation_cert_der_get_size();
    if (cert_size > sizeof(cert)){
        printf2(TAG_ERR,"Certificate is too large for CTAP2 buffer\r\n");
        return CTAP2_ERR_PROCESSING;
    }
    device_attestation_read_cert_der(cert);

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
            ret = cbor_encode_byte_string(&x5carr, cert, device_attestation_cert_der_get_size());
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
    uint8_t rpIdHash[32];
    uint8_t tag[16];

    switch(desc->type)
    {
        case PUB_KEY_CRED_PUB_KEY:
            crypto_sha256_init();
            crypto_sha256_update(rp->id, rp->size);
            crypto_sha256_final(rpIdHash);

            printf1(TAG_RED,"rpId: %s\r\n", rp->id); dump_hex1(TAG_RED,rp->id, rp->size);
            if (memcmp(desc->credential.id.rpIdHash, rpIdHash, 32) != 0)
            {
                return 0;
            }
            make_auth_tag(rpIdHash, desc->credential.id.entropy.nonce, desc->credential.id.count, tag);
            return (memcmp(desc->credential.id.tag, tag, CREDENTIAL_TAG_SIZE) == 0);
        break;
        case PUB_KEY_CRED_CTAP1:
            crypto_sha256_init();
            crypto_sha256_update(rp->id, rp->size);
            crypto_sha256_final(rpIdHash);
            return u2f_authenticate_credential((struct u2f_key_handle *)&desc->credential.id, U2F_KEY_HANDLE_SIZE,rpIdHash);
        break;
        case PUB_KEY_CRED_CUSTOM:
            return is_extension_request(getAssertionState.customCredId, getAssertionState.customCredIdSize);
        break;
        default:
        printf1(TAG_ERR, "PUB_KEY_CRED_UNKNOWN %x\r\n",desc->type);
        break;
    }

    return 0;
}



uint8_t ctap_make_credential(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_makeCredential MC;
    int ret;
    unsigned int i;
    uint8_t auth_data_buf[310];
    CTAP_credentialDescriptor * excl_cred = (CTAP_credentialDescriptor *) auth_data_buf;
    uint8_t * sigbuf = auth_data_buf + 32;
    uint8_t * sigder = auth_data_buf + 32 + 64;

    ret = ctap_parse_make_credential(&MC,encoder,request,length);

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_make_credential failed\n");
        return ret;
    }
    if (MC.pinAuthEmpty)
    {
        ret = ctap2_user_presence_test();
        check_retr(ret);
        return ctap_is_pin_set() == 1 ? CTAP2_ERR_PIN_AUTH_INVALID : CTAP2_ERR_PIN_NOT_SET;
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

    if (MC.up == 1 || MC.up == 0)
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

        if (ctap_authenticate_credential(&MC.rp, excl_cred))
        {
            if ( check_credential_metadata(&excl_cred->credential.id, MC.pinAuthPresent, 1) == 0)
            {
                ret = ctap2_user_presence_test();
                check_retr(ret);
                printf1(TAG_MC, "Cred %d failed!\r\n",i);
                return CTAP2_ERR_CREDENTIAL_EXCLUDED;
            }
        }

        ret = cbor_value_advance(&MC.excludeList);
        check_ret(ret);
    }


    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);

    {
        ret = cbor_encode_int(&map,RESP_fmt);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&map, "packed");
        check_ret(ret);
    }

    uint32_t auth_data_sz = sizeof(auth_data_buf);

    ret = ctap_make_auth_data(&MC.rp, &map, auth_data_buf, &auth_data_sz,
            &MC.credInfo, &MC.extensions);
    check_retr(ret);

    {
        unsigned int ext_encoder_buf_size = sizeof(auth_data_buf) - auth_data_sz;
        uint8_t * ext_encoder_buf = auth_data_buf + auth_data_sz;

        ret = ctap_make_extensions(&MC.extensions, ext_encoder_buf, &ext_encoder_buf_size);
        check_retr(ret);
        if (ext_encoder_buf_size)
        {
            ((CTAP_authData *)auth_data_buf)->head.flags |= (1 << 7);
            auth_data_sz += ext_encoder_buf_size;
        }
    }

    {
        ret = cbor_encode_int(&map,RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_sz);
        check_ret(ret);
    }

    crypto_ecc256_load_attestation_key();
    int sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_sz, MC.clientDataHash, auth_data_buf, sigbuf, sigder, COSE_ALG_ES256);
    printf1(TAG_MC,"der sig [%d]: ", sigder_sz); dump_hex1(TAG_MC, sigder, sigder_sz);

    ret = ctap_add_attest_statement(&map, sigder, sigder_sz);
    check_retr(ret);

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

static uint8_t ctap_add_credential_descriptor(CborEncoder * map, struct Credential * cred, int type)
{
    CborEncoder desc;

    int ret = cbor_encoder_create_map(map, &desc, 2);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&desc, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&desc, (uint8_t*)&cred->id,
            get_credential_id_size(type));
        check_ret(ret);
    }

    {
        ret = cbor_encode_text_string(&desc, "type", 4);
        check_ret(ret);

        ret = cbor_encode_text_string(&desc, "public-key", 10);
        check_ret(ret);
    }


    ret = cbor_encoder_close_container(map, &desc);
    check_ret(ret);

    return 0;
}

uint8_t ctap_add_user_entity(CborEncoder * map, CTAP_userEntity * user, int is_verified)
{
    CborEncoder entity;
    int dispname = (user->name[0] != 0) && is_verified;
    int ret;
    int map_size = 1;

    if (dispname)
    {
        map_size = strlen((const char *)user->icon) > 0 ? 4 : 3;
    }
    ret = cbor_encoder_create_map(map, &entity, map_size);
    check_ret(ret);

    ret = cbor_encode_text_string(&entity, "id", 2);
    check_ret(ret);

    ret = cbor_encode_byte_string(&entity, user->id, user->id_size);
    check_ret(ret);

    if (dispname)
    {
        if (strlen((const char *)user->icon) > 0)
        {
            ret = cbor_encode_text_string(&entity, "icon", 4);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&entity, (const char *)user->icon);
            check_ret(ret);
        }

        ret = cbor_encode_text_string(&entity, "name", 4);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->name);
        check_ret(ret);

        ret = cbor_encode_text_string(&entity, "displayName", 11);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->displayName);
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

// Return 1 if existing info found, 0 otherwise
static int add_existing_user_info(CTAP_credentialDescriptor * cred)
{
    CTAP_residentKey rk;
    int index = STATE.rk_stored;
    int i;
    for (i = 0; i < index; i++)
    {
        load_nth_valid_rk(i, &rk);
        if (is_cred_id_matching_rk(&cred->credential.id, &rk))
        {
            printf1(TAG_GREEN, "found rk match for allowList item (%d)\r\n", i);
            memmove(&cred->credential.user, &rk.user, sizeof(CTAP_userEntity));
            return 1;
        }

    }
    printf1(TAG_GREEN, "NO rk match for allowList item \r\n");
    return 0;
}

// @return the number of valid credentials
// sorts the credentials.  Most recent creds will be first, invalid ones last.
int ctap_filter_invalid_credentials(CTAP_getAssertion * GA)
{
    unsigned int i;
    int count = 0;
    uint8_t rpIdHash[32];
    CTAP_residentKey rk;

    for (i = 0; i < (unsigned int)GA->credLen; i++)
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

            int protection_status =
                check_credential_metadata(&GA->creds[i].credential.id, getAssertionState.user_verified, 1);

            if (protection_status != 0) {
                printf1(TAG_GREEN,"skipping protected wrapped credential.\r\n");
                GA->creds[i].credential.id.count = 0;      // invalidate
            }
            else
            {
                count++;
                // add user info if it exists
                if ( add_existing_user_info(&GA->creds[i]) ) {
                    printf1(TAG_GREEN,"USER ID SIZE: %d\r\n", GA->creds[i].credential.user.id_size);
                    // If RK matches credential in the allow_list, we should
                    // only return one credential.
                    GA->credLen = i+1;
                    break;
                }
            }

        }
    }

    // No allowList, so use all matching RK's matching rpId
    if (!GA->credLen)
    {
        crypto_sha256_init();
        crypto_sha256_update(GA->rp.id,GA->rp.size);
        crypto_sha256_final(rpIdHash);

        printf1(TAG_GREEN, "true rpIdHash: ");  dump_hex1(TAG_GREEN, rpIdHash, 32);
        for(i = 0; i < ctap_rk_size(); i++)
        {
            ctap_load_rk(i, &rk);
            if (! ctap_rk_is_valid(&rk)) {
                continue;
            }

            printf1(TAG_GREEN, "rpIdHash%d: ", i);  dump_hex1(TAG_GREEN, rk.id.rpIdHash, 32);

            int protection_status =
                check_credential_metadata(&rk.id, getAssertionState.user_verified, 0);

            if (protection_status != 0) {
                printf1(TAG_GREEN,"skipping protected rk credential.\r\n");
                continue;
            }

            if (memcmp(rk.id.rpIdHash, rpIdHash, 32) == 0)
            {
                printf1(TAG_GA, "RK %d is a rpId match!\r\n", i);
                if (count >= ALLOW_LIST_MAX_SIZE)
                {
                    printf2(TAG_ERR, "not enough ram allocated for matching RK's (%d).  Skipping.\r\n", count);
                    break;
                }
                GA->creds[count].type = PUB_KEY_CRED_PUB_KEY;
                memmove(&(GA->creds[count].credential), &rk, sizeof(struct Credential));
                count++;
            }
        }
        GA->credLen = count;
    }

    printf1(TAG_GA, "qsort length: %d\n", GA->credLen);
    qsort(GA->creds, GA->credLen, sizeof(CTAP_credentialDescriptor), cred_cmp_func);
    return count;
}


static int8_t save_credential_list( uint8_t * clientDataHash,
                                    CTAP_credentialDescriptor * creds,
                                    uint32_t count,
                                    CTAP_extensions * extensions)
{
    if(count)
    {
        if (count > ALLOW_LIST_MAX_SIZE-1)
        {
            printf2(TAG_ERR, "ALLOW_LIST_MAX_SIZE Exceeded\n");
            return CTAP2_ERR_TOO_MANY_ELEMENTS;
        }

        memmove(getAssertionState.clientDataHash, clientDataHash, CLIENT_DATA_HASH_SIZE);
        memmove(getAssertionState.creds, creds, sizeof(CTAP_credentialDescriptor) * (count));
        memmove(&getAssertionState.extensions, extensions, sizeof(CTAP_extensions));

    }
    getAssertionState.count = count;
    getAssertionState.index = 0;
    printf1(TAG_GA,"saved %d credentials\n",count);
    return 0;
}

static CTAP_credentialDescriptor * pop_credential()
{
    if (getAssertionState.count > 0 && getAssertionState.index < getAssertionState.count)
    {
        return &getAssertionState.creds[getAssertionState.index++];
    }
    else
    {
        return NULL;
    }
}

// adds 2 to map, or 3 if add_user is true
uint8_t ctap_end_get_assertion(CborEncoder * map, CTAP_credentialDescriptor * cred, uint8_t * auth_data_buf, unsigned int auth_data_buf_sz, uint8_t * clientDataHash)
{
    int ret;
    uint8_t sigbuf[64];
    uint8_t sigder[72];
    int sigder_sz;

    ret = cbor_encode_int(map, RESP_credential);
    check_ret(ret);

    ret = ctap_add_credential_descriptor(map, &cred->credential, cred->type);  // 1
    check_retr(ret);

    {
        ret = cbor_encode_int(map,RESP_authData);  // 2
        check_ret(ret);
        ret = cbor_encode_byte_string(map, auth_data_buf, auth_data_buf_sz);
        check_ret(ret);
    }

    unsigned int cred_size = get_credential_id_size(cred->type);
    int32_t cose_alg = read_cose_alg_from_masked_credential(&cred->credential.id);
    if (cose_alg == COSE_ALG_EDDSA)
    {
        crypto_ed25519_load_key((uint8_t*)&cred->credential.id, cred_size);
    }
    else
    {
        crypto_ecc256_load_key((uint8_t*)&cred->credential.id, cred_size, NULL, 0);
    }

#ifdef ENABLE_U2F_EXTENSIONS
    if ( extend_fido2(&cred->credential.id, sigder) )
    {
        sigder_sz = 72;
    }
    else
#endif
    {
        sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_buf_sz, clientDataHash, auth_data_buf, sigbuf, sigder, cose_alg);
    }

    printf1(TAG_GREEN, "sigder_sz = %d\n", sigder_sz);

    {
        ret = cbor_encode_int(map, RESP_signature);  // 3
        check_ret(ret);
        ret = cbor_encode_byte_string(map, sigder, sigder_sz);
        check_ret(ret);
    }

    if (cred->credential.user.id_size)
    {
        printf1(TAG_GREEN, "adding user details to output\r\n");

        int ret = cbor_encode_int(map, RESP_publicKeyCredentialUserEntity);
        check_ret(ret);

        ret = ctap_add_user_entity(map, &cred->credential.user, getAssertionState.user_verified);  // 4
        check_retr(ret);
    }


    return 0;
}

uint8_t ctap_get_next_assertion(CborEncoder * encoder)
{
    int ret;
    CborEncoder map;

    CTAP_credentialDescriptor * cred = pop_credential();

    if (cred == NULL)
    {
        return CTAP2_ERR_NOT_ALLOWED;
    }

    auth_data_update_count(&getAssertionState.buf.authData);
    memmove(getAssertionState.buf.authData.rpIdHash, cred->credential.id.rpIdHash, 32);

    if (cred->credential.user.id_size)
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

    // if only one account for this RP, null out the user details
    if (!getAssertionState.user_verified)
    {
        printf1(TAG_GREEN, "Not verified, nulling out user details on response\r\n");
        memset(cred->credential.user.name, 0, USER_NAME_LIMIT);
    }

    unsigned int ext_encoder_buf_size = sizeof(getAssertionState.buf.extensions);
    ret = ctap_make_extensions(&getAssertionState.extensions, getAssertionState.buf.extensions, &ext_encoder_buf_size);

    if (ret == 0)
    {
        if (ext_encoder_buf_size)
        {
            getAssertionState.buf.authData.flags |= (1 << 7);
        } else {
            getAssertionState.buf.authData.flags &= ~(1 << 7);
        }
    }

    ret = ctap_end_get_assertion(&map, cred,
                                (uint8_t *)&getAssertionState.buf.authData,
                                sizeof(CTAP_authDataHeader) + ext_encoder_buf_size,
                                getAssertionState.clientDataHash);

    check_retr(ret);

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return 0;
}

uint8_t ctap_cred_metadata(CborEncoder * encoder)
{
    CborEncoder map;
    int ret = cbor_encoder_create_map(encoder, &map, 2);
    check_ret(ret);
    ret = cbor_encode_int(&map, 1);
    check_ret(ret);
    ret = cbor_encode_int(&map, STATE.rk_stored);
    check_ret(ret);
    ret = cbor_encode_int(&map, 2);
    check_ret(ret);
    int remaining_rks = ctap_rk_size() - STATE.rk_stored;
    ret = cbor_encode_int(&map, remaining_rks);
    check_ret(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return 0;
}

uint8_t ctap_cred_rp(CborEncoder * encoder, int rk_ind, int rp_count)
{
    CTAP_residentKey rk;
    ctap_load_rk(rk_ind, &rk);

    CborEncoder map;
    size_t map_size = rp_count > 0 ? 3 : 2;
    int ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);
    ret = cbor_encode_int(&map, 3);
    check_ret(ret);
    {
        CborEncoder rp;
        ret = cbor_encoder_create_map(&map, &rp, 2);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&rp, "id");
        check_ret(ret);
        if (rk.rpIdSize <= sizeof(rk.rpId))
        {
            ret = cbor_encode_text_string(&rp, (const char *)rk.rpId, rk.rpIdSize);
        }
        else
        {
            ret = cbor_encode_text_string(&rp, "", 0);
        }
        check_ret(ret);
        ret = cbor_encode_text_stringz(&rp, "name");
        check_ret(ret);
        ret = cbor_encode_text_stringz(&rp, (const char *)rk.user.name);
        check_ret(ret);
        ret = cbor_encoder_close_container(&map, &rp);
        check_ret(ret);
    }
    ret = cbor_encode_int(&map, 4);
    check_ret(ret);
    cbor_encode_byte_string(&map, rk.id.rpIdHash, 32);
    check_ret(ret);
    if (rp_count > 0)
    {
        ret = cbor_encode_int(&map, 5);
        check_ret(ret);
        ret = cbor_encode_int(&map, rp_count);
        check_ret(ret);
    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return 0;
}

uint8_t ctap_cred_rk(CborEncoder * encoder, int rk_ind, int rk_count)
{
    CTAP_residentKey rk;
    ctap_load_rk(rk_ind, &rk);

    uint32_t cred_protect = read_metadata_from_masked_credential(&rk.id);
    if ( cred_protect == 0 || cred_protect > 3 )
    {
        // Take default value of userVerificationOptional
        cred_protect = EXT_CRED_PROTECT_OPTIONAL;
    }

    int32_t cose_alg = read_cose_alg_from_masked_credential(&rk.id);

    CborEncoder map;
    size_t map_size = rk_count > 0 ? 5 : 4;
    int ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);

    ret = cbor_encode_int(&map, 6);
    check_ret(ret);
    {
        ret = ctap_add_user_entity(&map, &rk.user, 1);
        check_ret(ret);
    }

    ret = cbor_encode_int(&map, 7);
    check_ret(ret);
    {
        ret = ctap_add_credential_descriptor(&map, (struct Credential*)&rk, PUB_KEY_CRED_PUB_KEY);
        check_ret(ret);
    }

    ret = cbor_encode_int(&map, 8);
    check_ret(ret);
    {
        ctap_generate_cose_key(&map, (uint8_t*)&rk.id, sizeof(CredentialId), PUB_KEY_CRED_PUB_KEY, cose_alg);
    }

    if (rk_count > 0)
    {
        ret = cbor_encode_int(&map, 9);
        check_ret(ret);
        ret = cbor_encode_int(&map, rk_count);
        check_ret(ret);
    }

    ret = cbor_encode_int(&map, 0x0A);
    check_ret(ret);
    ret = cbor_encode_int(&map, cred_protect);
    check_ret(ret);

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return 0;
}

uint8_t ctap_cred_mgmt_pinauth(CTAP_credMgmt *CM)
{
    if (CM->cmd != CM_cmdMetadata &&
        CM->cmd != CM_cmdRPBegin &&
        CM->cmd != CM_cmdRKBegin &&
        CM->cmd != CM_cmdRKDelete)
    {
        // pinAuth is not required for other commands
        return 0;
    }

    int8_t ret = verify_pin_auth_ex(CM->pinAuth, (uint8_t*)&CM->hashed, CM->subCommandParamsCborSize + 1);

    if (ret == CTAP2_ERR_PIN_AUTH_INVALID)
    {
        ctap_decrement_pin_attempts();
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    else
    {
        ctap_reset_pin_attempts();
    }

    return ret;
}

static int credentialId_to_rk_index(CredentialId * credId){
    unsigned int i;
    CTAP_residentKey rk;

    for (i = 0; i < ctap_rk_size(); i++)
    {
        ctap_load_rk(i, &rk);
        if ( ctap_rk_is_valid(&rk) ) {
            if (memcmp(&rk.id, credId, sizeof(CredentialId)) == 0)
            {
                return i;
            }
        }
    }

    return -1;
}

// Load the next valid resident key of a different rpIdHash
static int scan_for_next_rp(int index){
    CTAP_residentKey rk;
    uint8_t nextRpIdHash[32];

    if (index == -1)
    {
        ctap_load_rk(0, &rk);
        if (ctap_rk_is_valid(&rk))
        {
            return 0;
        }
        else
        {
            index = 0;
        }
    }

    int occurs_previously;
    do {
        occurs_previously = 0;

        index++;
        if ((unsigned int)index >= ctap_rk_size())
        {
            return -1;
        }

        ctap_load_rk(index, &rk);
        memmove(nextRpIdHash, rk.id.rpIdHash, 32);

        if (!ctap_rk_is_valid(&rk))
        {
            occurs_previously = 1;
            continue;
        } else {
        }

        // Check if we have scanned the rpIdHash before.
        int i;
        for (i = 0; i < index; i++)
        {
            ctap_load_rk(i, &rk);
            if (memcmp(rk.id.rpIdHash, nextRpIdHash, 32) == 0)
            {
                occurs_previously = 1;
                break;
            }
        }

    } while (occurs_previously);

    return index;
}

// Load the next valid resident key of the same rpIdHash
static int scan_for_next_rk(int index, uint8_t * initialRpIdHash){
    CTAP_residentKey rk;
    uint8_t lastRpIdHash[32];

    if (initialRpIdHash != NULL) {
        memmove(lastRpIdHash, initialRpIdHash, 32);
        index = -1;
    }
    else
    {
        ctap_load_rk(index, &rk);
        memmove(lastRpIdHash, rk.id.rpIdHash, 32);
    }

    do
    {
        index++;
        if ((unsigned int)index >= ctap_rk_size())
        {
            return -1;
        }
        ctap_load_rk(index, &rk);
    }
    while ( memcmp( rk.id.rpIdHash, lastRpIdHash, 32 ) != 0 );

    return index;
}



uint8_t ctap_cred_mgmt(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_credMgmt CM;
    int i = 0;

    // RP / RK pointers
    static int curr_rp_ind = 0;
    static int curr_rk_ind = 0;

    // flags that authenticate whether *Begin was before *Next
    static bool rp_auth = false;
    static bool rk_auth = false;

    int rp_count = 0;
    int rk_count = 0;

    int ret = ctap_parse_cred_mgmt(&CM, request, length);
    if (ret != 0)
    {
        printf2(TAG_ERR,"error, ctap_parse_cred_mgmt failed\n");
        return ret;
    }
    ret = ctap_cred_mgmt_pinauth(&CM);
    check_retr(ret);
    if (STATE.rk_stored == 0 && CM.cmd != CM_cmdMetadata)
    {
        printf2(TAG_ERR,"No resident keys\n");
        return 0;
    }
    if (CM.cmd == CM_cmdRPBegin)
    {
        curr_rk_ind = -1;
        rp_auth = true;
        rk_auth = false;
        curr_rp_ind = scan_for_next_rp(-1);

        // Count total unique RP's
        while (curr_rp_ind >= 0)
        {
            curr_rp_ind = scan_for_next_rp(curr_rp_ind);
            rp_count++;
        }

        // Reset scan
        curr_rp_ind = scan_for_next_rp(-1);

        printf1(TAG_MC, "RP Begin @%d.  %d total.\n", curr_rp_ind, rp_count);
    }
    else if (CM.cmd == CM_cmdRKBegin)
    {
        curr_rk_ind = scan_for_next_rk(0, CM.subCommandParams.rpIdHash);
        rk_auth = true;

        // Count total RK's associated to RP
        while (curr_rk_ind >= 0)
        {
            curr_rk_ind = scan_for_next_rk(curr_rk_ind, NULL);
            rk_count++;
        }

        // Reset scan
        curr_rk_ind = scan_for_next_rk(0, CM.subCommandParams.rpIdHash);
        printf1(TAG_MC, "Cred Begin @%d.  %d total.\n", curr_rk_ind, rk_count);
    }
    else if (CM.cmd != CM_cmdRKNext && CM.cmd != CM_cmdRPNext)
    {
        rk_auth = false;
        rp_auth = false;
        curr_rk_ind = -1;
        curr_rp_ind = -1;
    }

    switch (CM.cmd)
    {
        case CM_cmdMetadata:
            printf1(TAG_CM, "CM_cmdMetadata\n");
            ret = ctap_cred_metadata(encoder);
            check_ret(ret);
            break;
        case CM_cmdRPBegin:
        case CM_cmdRPNext:
            printf1(TAG_CM, "Get RP %d\n", curr_rp_ind);
            if (curr_rp_ind < 0 || !rp_auth) {
                rp_auth = false;
                rk_auth = false;
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            ret = ctap_cred_rp(encoder, curr_rp_ind, rp_count);
            check_ret(ret);
            curr_rp_ind = scan_for_next_rp(curr_rp_ind);

            break;
        case CM_cmdRKBegin:
        case CM_cmdRKNext:
            printf1(TAG_CM, "Get Cred %d\n", curr_rk_ind);
            if (curr_rk_ind < 0 || !rk_auth) {
                rp_auth = false;
                rk_auth = false;
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            ret = ctap_cred_rk(encoder, curr_rk_ind, rk_count);
            check_ret(ret);

            curr_rk_ind = scan_for_next_rk(curr_rk_ind, NULL);

            break;
        case CM_cmdRKDelete:
            printf1(TAG_CM, "CM_cmdRKDelete\n");
            i = credentialId_to_rk_index(&CM.subCommandParams.credentialDescriptor.credential.id);
            if (i >= 0) {
                ctap_delete_rk(i);
                ctap_decrement_rk_store();
                printf1(TAG_CM, "Deleted rk %d\n", i);
            } else {
                printf1(TAG_CM, "No Rk by given credId\n");
                return CTAP2_ERR_NO_CREDENTIALS;
            }
            break;
        default:
            printf2(TAG_ERR, "error, invalid credMgmt cmd: 0x%02x\n", CM.cmd);
            return CTAP1_ERR_INVALID_COMMAND;
    }
    return 0;
}

uint8_t ctap_get_assertion(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_getAssertion GA;

    int ret = ctap_parse_get_assertion(&GA,request,length);

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_get_assertion failed\n");
        return ret;
    }

    if (GA.pinAuthEmpty)
    {
        ret = ctap2_user_presence_test();
        check_retr(ret);
        return ctap_is_pin_set() == 1 ? CTAP2_ERR_PIN_AUTH_INVALID : CTAP2_ERR_PIN_NOT_SET;
    }
    if (GA.pinAuthPresent)
    {
        ret = verify_pin_auth(GA.pinAuth, GA.clientDataHash);
        check_retr(ret);
        getAssertionState.user_verified = 1;
    }
    else
    {
        getAssertionState.user_verified = 0;
    }

    if (!GA.rp.size || !GA.clientDataHashPresent)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CborEncoder map;

    int map_size = 3;

    printf1(TAG_GA, "ALLOW_LIST has %d creds\n", GA.credLen);
    int validCredCount = ctap_filter_invalid_credentials(&GA);

    if (validCredCount == 0)
    {
        printf2(TAG_ERR,"Error, no authentic credential\n");
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    else if (validCredCount > 1)
    {
       map_size += 1;
    }

    printf1(TAG_GREEN,"2 USER ID SIZE: %d\r\n", GA.creds[0].credential.user.id_size);

    if (GA.creds[validCredCount - 1].credential.user.id_size)
    {
        map_size += 1;
    }
    if (GA.extensions.hmac_secret_present == EXT_HMAC_SECRET_PARSED)
    {
        printf1(TAG_GA, "hmac-secret is present\r\n");
    }

    ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);

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

    CTAP_credentialDescriptor * cred = &GA.creds[0];

    GA.extensions.hmac_secret.credential = &cred->credential;

    uint32_t auth_data_buf_sz = sizeof(CTAP_authDataHeader);

#ifdef ENABLE_U2F_EXTENSIONS
    if ( is_extension_request((uint8_t*)&GA.creds[0].credential.id, sizeof(CredentialId)) )
    {
        crypto_sha256_init();
        crypto_sha256_update(GA.rp.id, GA.rp.size);
        crypto_sha256_final(getAssertionState.buf.authData.rpIdHash);

        getAssertionState.buf.authData.flags = (1 << 0);
        getAssertionState.buf.authData.flags |= (1 << 2);
    }
    else
#endif
    {
        device_disable_up(GA.up == 0);
        ret = ctap_make_auth_data(&GA.rp, &map, (uint8_t*)&getAssertionState.buf.authData, &auth_data_buf_sz, NULL, &GA.extensions);
        device_disable_up(false);
        check_retr(ret);

        getAssertionState.buf.authData.flags &= ~(1 << 2);
        getAssertionState.buf.authData.flags |= (getAssertionState.user_verified << 2);

        {
            unsigned int ext_encoder_buf_size = sizeof(getAssertionState.buf.extensions);

            ret = ctap_make_extensions(&GA.extensions, getAssertionState.buf.extensions, &ext_encoder_buf_size);
            check_retr(ret);
            if (ext_encoder_buf_size)
            {
                getAssertionState.buf.authData.flags |= (1 << 7);
                auth_data_buf_sz += ext_encoder_buf_size;
            }
        }

    }

    ret = ctap_end_get_assertion(&map, cred, (uint8_t*)&getAssertionState.buf, auth_data_buf_sz, GA.clientDataHash);  // 1,2,3,4
    check_retr(ret);

    if (validCredCount > 1)
    {
        ret = cbor_encode_int(&map, RESP_numberOfCredentials);  // 5
        check_ret(ret);
        ret = cbor_encode_int(&map, validCredCount);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    ret = save_credential_list( GA.clientDataHash,
                                GA.creds + 1 /* skip first credential*/,
                                validCredCount - 1,
                                &GA.extensions);
    check_retr(ret);

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

//    Validate incoming data packet len
    if (len < 64)
    {
        return CTAP1_ERR_OTHER;
    }

//    Validate device's state
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

//    calculate shared_secret
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

//     decrypt new PIN with shared secret
    crypto_aes256_init(shared_secret, NULL);

    while((len & 0xf) != 0) // round up to nearest  AES block size multiple
    {
        len++;
    }

    crypto_aes256_decrypt(pinEnc, len);

//      validate new PIN (length)

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

//    validate device's state, decrypt and compare pinHashEnc (user provided current PIN hash) with stored PIN_CODE_HASH

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

        uint8_t pinHashEncSalted[32];
        crypto_sha256_init();
        crypto_sha256_update(pinHashEnc, 16);
        crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
        crypto_sha256_final(pinHashEncSalted);

        if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 16) != 0)
        {
            ctap_reset_key_agreement();
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

//      set new PIN (update and store PIN_CODE_HASH)
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

    uint8_t pinHashEncSalted[32];
    crypto_sha256_init();
    crypto_sha256_update(pinHashEnc, 16);
    crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
    crypto_sha256_final(pinHashEncSalted);
    if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 16) != 0)
    {
        printf2(TAG_ERR,"Pin does not match!\n");
        printf2(TAG_ERR,"platform-pin-hash: "); dump_hex1(TAG_ERR, pinHashEnc, 16);
        printf2(TAG_ERR,"authentic-pin-hash: "); dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, 16);
        printf2(TAG_ERR,"shared-secret: "); dump_hex1(TAG_ERR, shared_secret, 32);
        printf2(TAG_ERR,"platform-pubkey: "); dump_hex1(TAG_ERR, platform_pubkey, 64);
        printf2(TAG_ERR,"device-pubkey: "); dump_hex1(TAG_ERR, KEY_AGREEMENT_PUB, 64);
        // Generate new keyAgreement pair
        ctap_reset_key_agreement();
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

            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
            crypto_ecc256_compute_public_key(KEY_AGREEMENT_PRIV, KEY_AGREEMENT_PUB);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_IDLE);

            ret = ctap_add_cose_key(&map, KEY_AGREEMENT_PUB, KEY_AGREEMENT_PUB+32, PUB_KEY_CRED_PUB_KEY, COSE_ALG_ECDH_ES_HKDF_256);
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
    memset(&encoder,0,sizeof(CborEncoder));
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
        case CTAP_CBOR_CRED_MGMT:
        case CTAP_CBOR_CRED_MGMT_PRE:
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
            printf1(TAG_CTAP,"CTAP_MAKE_CREDENTIAL\n");
            timestamp();
            status = ctap_make_credential(&encoder, pkt_raw, length);
            printf1(TAG_TIME,"make_credential time: %d ms\n", timestamp());

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            dump_hex1(TAG_DUMP, buf, resp->length);

            break;
        case CTAP_GET_ASSERTION:
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
            status = ctap2_user_presence_test();
            if (status == CTAP1_ERR_SUCCESS)
            {
                ctap_reset();
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
                status = CTAP2_ERR_NOT_ALLOWED;
            }
            break;
        case CTAP_CBOR_CRED_MGMT:
        case CTAP_CBOR_CRED_MGMT_PRE:
            printf1(TAG_CTAP,"CTAP_CBOR_CRED_MGMT_PRE\n");
            status = ctap_cred_mgmt(&encoder, pkt_raw, length);

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            dump_hex1(TAG_DUMP,buf, resp->length);
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            printf2(TAG_ERR,"error, invalid cmd: 0x%02x\n", cmd);
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
    STATE.data_version = STATE_VERSION;

    ctap_reset_rk();

    if (ctap_generate_rng(STATE.PIN_SALT, sizeof(STATE.PIN_SALT)) != 1) {
        printf2(TAG_ERR, "Error, rng failed\n");
        exit(1);
    }

    printf1(TAG_STOR, "Generated PIN SALT: ");
    dump_hex1(TAG_STOR, STATE.PIN_SALT, sizeof STATE.PIN_SALT);
}

/** Overwrite master secret from external source.
 * @param keybytes an array of KEY_SPACE_BYTES length.
 *
 * This function should only be called from a privilege mode.
*/
void ctap_load_external_keys(uint8_t * keybytes){
    memmove(STATE.key_space, keybytes, KEY_SPACE_BYTES);
    authenticator_write_state(&STATE);
    crypto_load_master_secret(STATE.key_space);
}

#include "version.h"
void ctap_init()
{
    printf1(TAG_ERR,"Current firmware version address: %p\r\n", &firmware_version);
    printf1(TAG_ERR,"Current firmware version: %d.%d.%d.%d (%02x.%02x.%02x.%02x)\r\n",
            firmware_version.major, firmware_version.minor, firmware_version.patch, firmware_version.reserved,
            firmware_version.major, firmware_version.minor, firmware_version.patch, firmware_version.reserved
            );
    crypto_ecc256_init();

    int is_init = authenticator_read_state(&STATE);

    device_set_status(CTAPHID_STATUS_IDLE);

    if (is_init)
    {
        printf1(TAG_STOR,"Auth state is initialized\n");
    }
    else
    {
        ctap_state_init();
        authenticator_write_state(&STATE);
    }

    do_migration_if_required(&STATE);

    crypto_load_master_secret(STATE.key_space);

    if (ctap_is_pin_set())
    {
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

    ctap_reset_key_agreement();

#ifdef BRIDGE_TO_WALLET
    wallet_init();
#endif


}

uint8_t ctap_is_pin_set()
{
    return STATE.is_pin_set == 1;
}

/**
 * Set new PIN, by updating PIN hash. Save state.
 * Globals: STATE
 * @param pin new PIN (raw)
 * @param len pin array length
 */
void ctap_update_pin(uint8_t * pin, int len)
{
    if (len >= NEW_PIN_ENC_MIN_SIZE || len < 4)
    {
        printf2(TAG_ERR, "Update pin fail length\n");
        exit(1);
    }

    crypto_sha256_init();
    crypto_sha256_update(pin, len);
    uint8_t intermediateHash[32];
    crypto_sha256_final(intermediateHash);

    crypto_sha256_init();
    crypto_sha256_update(intermediateHash, 16);
    memset(intermediateHash, 0, sizeof(intermediateHash));
    crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
    crypto_sha256_final(STATE.PIN_CODE_HASH);

    STATE.is_pin_set = 1;

    authenticator_write_state(&STATE);

    printf1(TAG_CTAP, "New pin set: %s [%d]\n", pin, len);
    dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, sizeof(STATE.PIN_CODE_HASH));
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
        ctap_flush_state();
        printf1(TAG_CP, "ATTEMPTS left: %d\n", STATE.remaining_tries);

        if (ctap_device_locked())
        {
            lock_device_permanently();
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
    ctap_flush_state();
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

    ctap_flush_state();

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

static void ctap_reset_key_agreement()
{
    ctap_generate_rng(KEY_AGREEMENT_PRIV, sizeof(KEY_AGREEMENT_PRIV));
}

void ctap_reset()
{
    ctap_state_init();

    authenticator_write_state(&STATE);

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        exit(1);
    }

    ctap_reset_state();
    ctap_reset_key_agreement();

    crypto_load_master_secret(STATE.key_space);
}

void lock_device_permanently() {
    memset(PIN_TOKEN, 0, sizeof(PIN_TOKEN));
    memset(STATE.PIN_CODE_HASH, 0, sizeof(STATE.PIN_CODE_HASH));

    printf1(TAG_CP, "Device locked!\n");

    authenticator_write_state(&STATE);
}
