#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "ctap.h"
#include "cose_key.h"
#include "crypto.h"
#include "util.h"


#define check_ret(r)    _check_ret(r,__LINE__, __FILE__)
static void _check_ret(CborError ret, int line, const char * filename)
{
    if (ret != CborNoError)
    {
        printf("CborError: 0x%x: %s: %d: %s\n", ret, filename, line, cbor_error_string(ret));
        exit(1);
    }
}

static const char * cbor_value_get_type_string(const CborValue *value)
{
    switch(cbor_value_get_type(value))
    {
        case CborIntegerType:
            return "CborIntegerType";
            break;
        case CborByteStringType:
            return "CborByteStringType";
            break;
        case CborTextStringType:
            return "CborTextStringType";
            break;
        case CborArrayType:
            return "CborArrayType";
            break;
        case CborMapType:
            return "CborMapType";
            break;
        case CborTagType:
            return "CborTagType";
            break;
        case CborSimpleType:
            return "CborSimpleType";
            break;
        case CborBooleanType:
            return "CborBooleanType";
            break;
        case CborNullType:
            return "CborNullType";
            break;
        case CborUndefinedType:
            return "CborUndefinedType";
            break;
        case CborHalfFloatType:
            return "CborHalfFloatType";
            break;
        case CborFloatType:
            return "CborFloatType";
            break;
        case CborDoubleType:
            return "CborDoubleType";
            break;
    }
    return "Invalid type";
}

void ctap_get_info(CborEncoder * encoder)
{
    int ret;
    CborEncoder array;
    CborEncoder map;

    const int number_of_map_items = 2;
    const int number_of_versions = 2;

    ret = cbor_encoder_create_map(encoder, &map, number_of_map_items);
    check_ret(ret);
    {

        ret = cbor_encode_uint(&map, 0x01);     //  versions key
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, number_of_versions);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "1.0");
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "2.0");
            check_ret(ret);
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, 0x03);     //  aaguid key
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, CTAP_AAGUID, 16);
            check_ret(ret);
        }

    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
}

static int parse_client_data_hash(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz;
    int ret;
    if (cbor_value_get_type(val) != CborByteStringType)
    {
        printf("error, wrong type\n");
        return -1;
    }
    ret = cbor_value_calculate_string_length(val, &sz);
    check_ret(ret);
    if (sz != CLIENT_DATA_HASH_SIZE)
    {
        printf("error, wrong size for client data hash\n");
        return -1;
    }
    ret = cbor_value_copy_byte_string(val, MC->clientDataHash, &sz, NULL);
    check_ret(ret);

    MC->paramsParsed |= PARAM_clientDataHash;

    return 0;
}


static int parse_user(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz, map_length;
    uint8_t key[8];
    int ret;
    int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        printf("error, wrong type\n");
        return -1;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf("Error, expecting text string type for user map key, got %s\n", cbor_value_get_type_string(&map));
            return -1;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            printf("Error, rp map key is too large\n");
            return -1;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (strcmp(key, "id") == 0)
        {

            if (cbor_value_get_type(&map) != CborByteStringType)
            {
                printf("Error, expecting byte string type for rp map value\n");
                return -1;
            }

            sz = USER_ID_MAX_SIZE;
            ret = cbor_value_copy_byte_string(&map, MC->userId, &sz, NULL);
            if (ret == CborErrorOutOfMemory)
            {
                printf("Error, USER_ID is too large\n");
                return -1;
            }
            MC->userIdSize = sz;
            check_ret(ret);
        }
        else if (strcmp(key, "name") == 0)
        {
            sz = USER_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, MC->userName, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->userName[USER_NAME_LIMIT - 1] = 0;
        }
        else
        {
            printf("ignoring key %s for user map\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }

    MC->paramsParsed |= PARAM_user;

    return 0;
}

static int parse_pub_key_cred_param(CborValue * val, uint8_t * cred_type, int32_t * alg_type)
{
    CborValue map;
    CborValue cred;
    CborValue alg;
    int ret;
    uint8_t type_str[16];
    size_t sz = sizeof(type_str);

    if (cbor_value_get_type(val) != CborMapType)
    {
        printf("error, expecting map type\n");
        return -1;
    }

    ret = cbor_value_map_find_value(val, "type", &cred);
    check_ret(ret);
    ret = cbor_value_map_find_value(val, "alg", &alg);
    check_ret(ret);

    if (cbor_value_get_type(&cred) != CborTextStringType)
    {
        printf("Error, parse_pub_key could not find credential param\n");
        return -1;
    }
    if (cbor_value_get_type(&alg) != CborIntegerType)
    {
        printf("Error, parse_pub_key could not find alg param\n");
        return -1;
    }

    ret = cbor_value_copy_text_string(&cred, type_str, &sz, NULL);
    check_ret(ret);

    type_str[sizeof(type_str) - 1] = 0;

    if (strcmp(type_str, "public-key") == 0)
    {
        *cred_type = PUB_KEY_CRED_PUB_KEY;
    }
    else
    {
        *cred_type = PUB_KEY_CRED_UNKNOWN;
    }

    ret = cbor_value_get_int_checked(&alg, alg_type);
    check_ret(ret);

    return 0;
}

// Check if public key credential+algorithm type is supported
static int pub_key_cred_param_supported(uint8_t cred, int32_t alg)
{
    if (cred == PUB_KEY_CRED_PUB_KEY)
    {
        if (alg == COSE_ALG_ES256)
        {
            return  CREDENTIAL_IS_SUPPORTED;
        }
    }

    return  CREDENTIAL_NOT_SUPPORTED;
}

static int parse_pub_key_cred_params(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz, arr_length;
    uint8_t cred_type;
    int32_t alg_type;
    uint8_t key[8];
    int ret;
    int i;
    CborValue arr;


    if (cbor_value_get_type(val) != CborArrayType)
    {
        printf("error, expecting array type\n");
        return -1;
    }

    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);

    ret = cbor_value_get_array_length(val, &arr_length);
    check_ret(ret);

    for (i = 0; i < arr_length; i++)
    {
        if (parse_pub_key_cred_param(&arr, &cred_type, &alg_type) == 0)
        {
            if (pub_key_cred_param_supported(cred_type, alg_type) == CREDENTIAL_IS_SUPPORTED)
            {
                MC->publicKeyCredentialType = cred_type;
                MC->COSEAlgorithmIdentifier = alg_type;
                MC->paramsParsed |= PARAM_pubKeyCredParams;
                return 0;
            }
        }
        else
        {
            // Continue? fail?
        }
        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }

    printf("Error, no public key credential parameters are supported!\n");
    return -1;
}


static int parse_rp(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz, map_length;
    uint8_t key[8];
    int ret;
    int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        printf("error, wrong type\n");
        return -1;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf("Error, expecting text string type for rp map key, got %s\n", cbor_value_get_type_string(&map));
            return -1;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            printf("Error, rp map key is too large\n");
            return -1;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf("Error, expecting text string type for rp map value\n");
            return -1;
        }

        if (strcmp(key, "id") == 0)
        {
            sz = DOMAIN_NAME_MAX_SIZE;
            ret = cbor_value_copy_text_string(&map, MC->rpId, &sz, NULL);
            if (ret == CborErrorOutOfMemory)
            {
                printf("Error, RP_ID is too large\n");
                return -1;
            }
            MC->rpId[DOMAIN_NAME_MAX_SIZE] = 0;     // Extra byte defined in struct.
            MC->rpIdSize = sz;
            check_ret(ret);
        }
        else if (strcmp(key, "name") == 0)
        {
            sz = RP_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, MC->rpName, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->rpName[RP_NAME_LIMIT - 1] = 0;
        }
        else
        {
            printf("ignoring key %s for RP map\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }

    MC->paramsParsed |= PARAM_rp;


    return 0;
}


static int ctap_parse_make_credential(CTAP_makeCredential * MC, CborEncoder * encoder, uint8_t * request, int length)
{
    int ret;
    int i;
    int key;
    size_t map_length;
    size_t sz;
    CborParser parser;
    CborValue it,map;

    memset(MC, 0, sizeof(CTAP_makeCredential));
    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    check_ret(ret);

    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        printf("Error, expecting cbor map\n");
        return -1;
    }

    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);

    printf("map has %d elements\n",map_length);

    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            printf("Error, expecting int for map key\n");
        }
        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);

        switch(key)
        {

            case MC_clientDataHash:
                printf("CTAP_clientDataHash\n");

                ret = parse_client_data_hash(MC, &map);

                printf("  "); dump_hex(MC->clientDataHash, 32);
                break;
            case MC_rp:
                printf("CTAP_rp\n");

                ret = parse_rp(MC, &map);

                printf("  ID: %s\n", MC->rpId);
                printf("  name: %s\n", MC->rpName);
                break;
            case MC_user:
                printf("CTAP_user\n");

                ret = parse_user(MC, &map);

                printf("  ID: "); dump_hex(MC->userId, MC->userIdSize);
                printf("  name: %s\n", MC->userName);

                break;
            case MC_pubKeyCredParams:
                printf("CTAP_pubKeyCredParams\n");

                ret = parse_pub_key_cred_params(MC, &map);

                printf("  cred_type: 0x%02x\n", MC->publicKeyCredentialType);
                printf("  alg_type: %d\n", MC->COSEAlgorithmIdentifier);

                break;
            case MC_excludeList:
                printf("CTAP_excludeList\n");
                break;
            case MC_extensions:
                printf("CTAP_extensions\n");
                break;
            case MC_options:
                printf("CTAP_options\n");
                break;
            case MC_pinAuth:
                printf("CTAP_pinAuth\n");
                break;
            case MC_pinProtocol:
                printf("CTAP_pinProtocol\n");
                break;
            default:
                printf("invalid key %d\n", key);

        }
        if (ret != 0)
        {
            return ret;
        }

        cbor_value_advance(&map);
        check_ret(ret);
    }

    return 0;
}

static int ctap_generate_cose_key(CTAP_makeCredential * MC, CborEncoder * cose_key, uint8_t * rpId, int l1, uint8_t * entropy, int l2)
{
    uint8_t x[32], y[32];
    int ret;
    CborEncoder map;

    ret = cbor_encoder_create_map(cose_key, &map, 5);
    check_ret(ret);

    if (MC->publicKeyCredentialType != PUB_KEY_CRED_PUB_KEY)
    {
        printf("Error, pubkey credential type not supported\n");
        return -1;
    }
    switch(MC->COSEAlgorithmIdentifier)
    {
        case COSE_ALG_ES256:
            crypto_ecc256_init();
            crypto_derive_ecc256_public_key(rpId, l1,
                    entropy, l2, x, y);
            break;
        default:
            printf("Error, COSE alg %d not supported\n", MC->COSEAlgorithmIdentifier);
            return -1;
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
        check_ret(ret);
        ret = cbor_encode_int(&map, COSE_KEY_KTY_EC2);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
        check_ret(ret);
        ret = cbor_encode_int(&map, MC->COSEAlgorithmIdentifier);
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
}

void ctap_make_credential(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_makeCredential MC;
    int ret;
    uint8_t auth_data_buf[200];
    uint8_t * cose_key_buf = auth_data_buf +  + sizeof(CTAP_authData);
    uint8_t hashbuf[32];
    uint8_t sigbuf[64];
    uint8_t sigder[64 + 2 + 6];
    int auth_data_sz;
    CTAP_authData * authData = (CTAP_authData *)auth_data_buf;
    CborEncoder cose_key;
    CborEncoder map;
        CborEncoder stmtmap;

    cbor_encoder_init(&cose_key, cose_key_buf, sizeof(auth_data_buf) - sizeof(CTAP_authData), 0);

    ret = ctap_parse_make_credential(&MC,encoder,request,length);
    if (ret != 0)
    {
        printf("error, parse_make_credential failed\n");
        return;
    }
    if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask)
    {
        printf("error, required parameter(s) for makeCredential are missing\n");
        return;
    }

    crypto_sha256_init();
    crypto_sha256_update(MC.rpId, MC.rpIdSize);
    crypto_sha256_final(authData->rpIdHash);

    authData->flags = (ctap_user_presence_test() << 0);
    authData->flags |= (ctap_user_verification(0) << 2);
    authData->flags |= (1 << 6);//include attestation data

    authData->signCount = ctap_atomic_count();

    memmove(authData->attest.aaguid, CTAP_AAGUID, 16);
    authData->attest.credLenL = CREDENTIAL_ID_SIZE & 0x00FF;
    authData->attest.credLenH = (CREDENTIAL_ID_SIZE & 0xFF00) >> 8;

#if CREDENTIAL_ID_SIZE != 48
#error "need to update credential ID layout"
#else
    memmove(authData->attest.credentialId, authData->rpIdHash, 16);
    ctap_generate_rng(authData->attest.credentialId + 16, 32);

    ctap_generate_cose_key(&MC, &cose_key, authData->attest.credentialId, 16,
            authData->attest.credentialId, 32);

    printf("COSE_KEY: "); dump_hex(cose_key_buf, cbor_encoder_get_buffer_size(&cose_key, cose_key_buf));

    auth_data_sz = sizeof(CTAP_authData) + cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);
#endif

    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);

    {
        ret = cbor_encode_int(&map,RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_sz);

        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map,RESP_fmt);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&map, "packed");
        check_ret(ret);
    }

    // calculate attestation sig
    crypto_sha256_init();
    crypto_sha256_update(auth_data_buf, auth_data_sz);
    crypto_sha256_update(MC.clientDataHash, CLIENT_DATA_HASH_SIZE);
    crypto_sha256_final(hashbuf);

    crypto_ecc256_load_attestation_key();
    crypto_ecc256_sign(hashbuf, 32, sigbuf);

    // Need to caress into dumb der format ..
    uint8_t pad_s = (sigbuf[32] & 0x80) == 0x80;
    uint8_t pad_r = (sigbuf[0] & 0x80) == 0x80;
    sigder[0] = 0x30;
    sigder[1] = 0x44 + pad_s + pad_r;

    sigder[2] = 0x02;
    sigder[3 + pad_r] = 0;
    sigder[3] = 0x20 + pad_r;
    memmove(sigder + 4 + pad_r, sigbuf, 32);

    sigder[4 + 32 + pad_r] = 0x02;
    sigder[5 + 32 + pad_r + pad_s] = 0;
    sigder[5 + 32 + pad_r] = 0x20 + pad_s;
    memmove(sigder + 6 + 32 + pad_r + pad_s, sigbuf + 32, 32);
    //
    printf("der sig [%d]: ", 0x44+pad_s+pad_r); dump_hex(sigder, 0x44+pad_s+pad_r);

    {
        ret = cbor_encode_int(&map,RESP_attStmt);
        check_ret(ret);
        ret = cbor_encoder_create_map(&map, &stmtmap, 3);
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
            ret = cbor_encode_byte_string(&stmtmap, sigder, 0x44 + pad_s + pad_r);
            check_ret(ret);
        }
        {
            ret = cbor_encode_text_stringz(&stmtmap,"x5c");
            check_ret(ret);
            ret = cbor_encode_byte_string(&stmtmap, attestation_cert_der, attestation_cert_der_size);
            check_ret(ret);
        }

        cbor_encoder_close_container(&map, &stmtmap);
        check_ret(ret);

    }


    cbor_encoder_close_container(encoder, &map);
}


uint8_t ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    uint8_t cmd = *pkt_raw;
    pkt_raw++;


    uint8_t buf[1024];
    memset(buf,0,sizeof(buf));

    resp->data = buf;
    resp->length = 0;

    CborEncoder encoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);

    printf("cbor req: "); dump_hex(pkt_raw, length - 1);


    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
            printf("CTAP_MAKE_CREDENTIAL\n");
            ctap_make_credential(&encoder, pkt_raw, length - 1);
            dump_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));
            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_GET_ASSERTION:
            printf("CTAP_GET_ASSERTION\n");
            break;
        case CTAP_CANCEL:
            printf("CTAP_CANCEL\n");
            break;
        case CTAP_GET_INFO:
            printf("CTAP_GET_INFO\n");
            ctap_get_info(&encoder);
            dump_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            break;
        case CTAP_CLIENT_PIN:
            printf("CTAP_CLIENT_PIN\n");
            break;
        case CTAP_RESET:
            printf("CTAP_RESET\n");
            break;
        case GET_NEXT_ASSERTION:
            printf("CTAP_NEXT_ASSERTION\n");
            break;
        default:
            printf("error, invalid cmd\n");
    }

    printf("cbor structure: %d bytes\n", length - 1);
    return 0;
}
