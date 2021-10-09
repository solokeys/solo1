// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>

#include "cbor.h"

#include "ctap.h"
#include "u2f.h"
#include "ctap_parse.h"
#include "ctap_errors.h"
#include "cose_key.h"
#include "util.h"
#include "log.h"

extern struct _getAssertionState getAssertionState;

void _check_ret(CborError ret, int line, const char * filename)
{
    if (ret != CborNoError)
    {
        printf1(TAG_ERR,"CborError: 0x%x: %s: %d: %s\n", ret, filename, line, cbor_error_string(ret));
        /*exit(1);*/
    }
}

const char * cbor_value_get_type_string(const CborValue *value)
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
        default:
            return "Invalid type";
    }
}


uint8_t parse_user(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz, map_length;
    uint8_t key[24];
    int ret;
    unsigned int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        printf2(TAG_ERR,"error, wrong type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf2(TAG_ERR,"Error, expecting text string type for user map key, got %s\n", cbor_value_get_type_string(&map));
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, (char *)key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            printf2(TAG_ERR,"Error, rp map key is too large\n");
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }

        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (strcmp((const char*)key, "id") == 0)
        {

            if (cbor_value_get_type(&map) != CborByteStringType)
            {
                printf2(TAG_ERR,"Error, expecting byte string type for rp map value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }

            sz = USER_ID_MAX_SIZE;
            ret = cbor_value_copy_byte_string(&map, MC->credInfo.user.id, &sz, NULL);
            if (ret == CborErrorOutOfMemory)
            {
                printf2(TAG_ERR,"Error, USER_ID is too large\n");
                return CTAP2_ERR_LIMIT_EXCEEDED;
            }
            MC->credInfo.user.id_size = sz;
            check_ret(ret);
        }
        else if (strcmp((const char *)key, "name") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                printf2(TAG_ERR,"Error, expecting text string type for user.name value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = USER_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.name, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->credInfo.user.name[USER_NAME_LIMIT - 1] = 0;
        }
        else if (strcmp((const char *)key, "displayName") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                printf2(TAG_ERR,"Error, expecting text string type for user.displayName value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = DISPLAY_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.displayName, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->credInfo.user.displayName[DISPLAY_NAME_LIMIT - 1] = 0;
        }
        else if (strcmp((const char *)key, "icon") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                printf2(TAG_ERR,"Error, expecting text string type for user.icon value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = ICON_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.icon, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->credInfo.user.icon[ICON_LIMIT - 1] = 0;

        }
        else
        {
            printf1(TAG_PARSE,"ignoring key %s for user map\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }

    MC->paramsParsed |= PARAM_user;

    return 0;
}


uint8_t parse_pub_key_cred_param(CborValue * val, uint8_t * cred_type, int32_t * alg_type)
{
    CborValue cred;
    CborValue alg;
    int ret;
    uint8_t type_str[16];
    size_t sz = sizeof(type_str);

    if (cbor_value_get_type(val) != CborMapType)
    {
        printf2(TAG_ERR,"error, expecting map type, got %s\n", cbor_value_get_type_string(val));
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_map_find_value(val, "type", &cred);
    check_ret(ret);
    ret = cbor_value_map_find_value(val, "alg", &alg);
    check_ret(ret);

    if (cbor_value_get_type(&cred) != CborTextStringType)
    {
        printf2(TAG_ERR,"Error, parse_pub_key could not find credential param\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (cbor_value_get_type(&alg) != CborIntegerType)
    {
        printf2(TAG_ERR,"Error, parse_pub_key could not find alg param\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    ret = cbor_value_copy_text_string(&cred, (char*)type_str, &sz, NULL);
    check_ret(ret);

    type_str[sizeof(type_str) - 1] = 0;

    if (strcmp((const char*)type_str, "public-key") == 0)
    {
        *cred_type = PUB_KEY_CRED_PUB_KEY;
    }
    else
    {
        *cred_type = PUB_KEY_CRED_UNKNOWN;
    }

    ret = cbor_value_get_int_checked(&alg, (int*)alg_type);
    check_ret(ret);

    return 0;
}

// Check if public key credential+algorithm type is supported
static int pub_key_cred_param_supported(uint8_t cred, int32_t alg)
{
    if (cred == PUB_KEY_CRED_PUB_KEY)
    {
        if (alg == COSE_ALG_ES256 || alg == COSE_ALG_EDDSA)
        {
            return  CREDENTIAL_IS_SUPPORTED;
        }
    }

    return  CREDENTIAL_NOT_SUPPORTED;
}

uint8_t parse_pub_key_cred_params(CTAP_makeCredential * MC, CborValue * val)
{
    size_t arr_length;
    uint8_t cred_type;
    int32_t alg_type;
    int ret;
    unsigned int i;
    CborValue arr;


    if (cbor_value_get_type(val) != CborArrayType)
    {
        printf2(TAG_ERR,"error, expecting array type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);

    ret = cbor_value_get_array_length(val, &arr_length);
    check_ret(ret);

    for (i = 0; i < arr_length; i++)
    {
        if ((ret = parse_pub_key_cred_param(&arr, &cred_type, &alg_type)) != 0)
        {
            return ret;
        }
        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }

    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);

    for (i = 0; i < arr_length; i++)
    {
        if ((ret = parse_pub_key_cred_param(&arr, &cred_type, &alg_type)) == 0)
        {
            if (pub_key_cred_param_supported(cred_type, alg_type) == CREDENTIAL_IS_SUPPORTED)
            {
                MC->credInfo.publicKeyCredentialType = cred_type;
                MC->credInfo.COSEAlgorithmIdentifier = alg_type;
                MC->paramsParsed |= PARAM_pubKeyCredParams;
                return 0;
            }
        }
        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }

    printf2(TAG_ERR,"Error, no public key credential parameters are supported!\n");
    return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

uint8_t parse_fixed_byte_string(CborValue * map, uint8_t * dst, unsigned int len)
{
    size_t sz;
    int ret;
    if (cbor_value_get_type(map) == CborByteStringType)
    {
        sz = len;
        ret = cbor_value_copy_byte_string(map, dst, &sz, NULL);
        check_ret(ret);
        if (sz != len)
        {
            printf2(TAG_ERR, "error byte string is different length (%d vs %d)\r\n", len, sz);
            return CTAP1_ERR_INVALID_LENGTH;
        }
    }
    else
    {
        printf2(TAG_ERR, "error, CborByteStringType expected\r\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    return 0;
}

uint8_t parse_verify_exclude_list(CborValue * val)
{
    unsigned int i;
    int ret;
    CborValue arr;
    size_t size;
    CTAP_credentialDescriptor cred;
    if (cbor_value_get_type(val) != CborArrayType)
    {
        printf2(TAG_ERR,"error, exclude list is not a map\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    ret = cbor_value_get_array_length(val, &size);
    check_ret(ret);
    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);
    for (i = 0; i < size; i++)
    {
        ret = parse_credential_descriptor(&arr, &cred);
        check_ret(ret);
        ret = cbor_value_advance(&arr);
        check_ret(ret);

    }
    return 0;
}

uint8_t parse_rp_id(struct rpId * rp, CborValue * val)
{
    size_t sz = DOMAIN_NAME_MAX_SIZE;
    if (cbor_value_get_type(val) != CborTextStringType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    int ret = cbor_value_copy_text_string(val, (char*)rp->id, &sz, NULL);
    if (ret == CborErrorOutOfMemory)
    {
        printf2(TAG_ERR,"Error, RP_ID is too large\n");
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    check_ret(ret);
    rp->id[DOMAIN_NAME_MAX_SIZE] = 0;     // Extra byte defined in struct.
    rp->size = sz;
    return 0;
}

uint8_t parse_rp(struct rpId * rp, CborValue * val)
{
    size_t sz, map_length;
    char key[8];
    int ret;
    unsigned int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        printf2(TAG_ERR,"error, wrong type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    rp->size = 0;

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf2(TAG_ERR,"Error, expecting text string type for rp map key, got %s\n", cbor_value_get_type_string(&map));
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            printf2(TAG_ERR,"Error, rp map key is too large\n");
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf2(TAG_ERR,"Error, expecting text string type for rp map value\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        if (strcmp(key, "id") == 0)
        {
            ret = parse_rp_id(rp, &map);
            if (ret != 0)
            {
                return ret;
            }
        }
        else if (strcmp(key, "name") == 0)
        {
            sz = RP_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char*)rp->name, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            rp->name[RP_NAME_LIMIT - 1] = 0;
        }
        else
        {
            printf1(TAG_PARSE,"ignoring key %s for RP map\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }
    if (rp->size == 0)
    {
        printf2(TAG_ERR,"Error, no RPID provided\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }


    return 0;
}

uint8_t parse_options(CborValue * val, uint8_t * rk, uint8_t * uv, uint8_t * up)
{
    size_t sz, map_length;
    char key[8];
    int ret;
    unsigned int i;
    _Bool b;
    CborValue map;

    if (cbor_value_get_type(val) != CborMapType)
    {
        printf2(TAG_ERR,"error, wrong type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);


    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf2(TAG_ERR,"Error, expecting text string type for options map key, got %s\n", cbor_value_get_type_string(&map));
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            printf2(TAG_ERR,"Error, rp map key is too large\n");
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (cbor_value_get_type(&map) != CborBooleanType)
        {
            printf2(TAG_ERR,"Error, expecting bool type for option map value\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        if (strncmp(key, "rk",2) == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            printf1(TAG_GA, "rk: %d\r\n",b);
            *rk = b;
        }
        else if (strncmp(key, "uv",2) == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            printf1(TAG_GA, "uv: %d\r\n",b);
            *uv = b;
        }
        else if (strncmp(key, "up",2) == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            printf1(TAG_GA, "up: %d\r\n",b);
            *up = b;
        }
        else
        {
            printf2(TAG_PARSE,"ignoring option specified %s\n", key);
        }
        ret = cbor_value_advance(&map);
        check_ret(ret);
    }
    return 0;
}

uint8_t ctap_parse_hmac_secret(CborValue * val, CTAP_hmac_secret * hs)
{
    size_t map_length;
    size_t salt_len;
    uint8_t parsed_count = 0;
    int key;
    int ret;
    unsigned int i;
    CborValue map;

    if (cbor_value_get_type(val) != CborMapType)
    {
        printf2(TAG_ERR,"error, wrong type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborIntegerType)
        {
            printf2(TAG_ERR,"Error, expecting CborIntegerTypefor hmac-secret map key, got %s\n", cbor_value_get_type_string(&map));
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        ret = cbor_value_get_int(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);

        switch(key)
        {
            case EXT_HMAC_SECRET_COSE_KEY:
                ret = parse_cose_key(&map, &hs->keyAgreement);
                check_retr(ret);
                parsed_count++;
            break;
            case EXT_HMAC_SECRET_SALT_ENC:
                salt_len = 64;
                ret = cbor_value_copy_byte_string(&map, hs->saltEnc, &salt_len, NULL);
                if ((salt_len != 32 && salt_len != 64) || ret == CborErrorOutOfMemory)
                {
                    return CTAP1_ERR_INVALID_LENGTH;
                }
                check_ret(ret);
                hs->saltLen = salt_len;
                parsed_count++;
            break;
            case EXT_HMAC_SECRET_SALT_AUTH:
                salt_len = 32;
                ret = cbor_value_copy_byte_string(&map, hs->saltAuth, &salt_len, NULL);
                check_ret(ret);
                parsed_count++;
            break;
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }

    if (parsed_count != 3)
    {
        printf2(TAG_ERR, "ctap_parse_hmac_secret missing parameter.  Got %d.\r\n", parsed_count);
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    return 0;
}


uint8_t ctap_parse_extensions(CborValue * val, CTAP_extensions * ext)
{
    CborValue map;
    size_t sz, map_length;
    char key[16];
    int ret;
    unsigned int i;
    bool b;

    if (cbor_value_get_type(val) != CborMapType)
    {
        printf2(TAG_ERR,"error, wrong type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val, &map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            printf2(TAG_ERR,"Error, expecting text string type for options map key, got %s\n", cbor_value_get_type_string(&map));
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            printf2(TAG_ERR,"Error, rp map key is too large. Ignoring.\n");
            check_ret( cbor_value_advance(&map) );
            check_ret( cbor_value_advance(&map) );
            continue;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);


        if (strncmp(key, "hmac-secret",11) == 0)
        {
            if (cbor_value_get_type(&map) == CborBooleanType)
            {
                ret = cbor_value_get_boolean(&map, &b);
                check_ret(ret);
                if (b) ext->hmac_secret_present = EXT_HMAC_SECRET_REQUESTED;
                printf1(TAG_CTAP, "set hmac_secret_present to %d\r\n", b);
            }
            else if (cbor_value_get_type(&map) == CborMapType)
            {
                ret = ctap_parse_hmac_secret(&map, &ext->hmac_secret);
                check_retr(ret);
                ext->hmac_secret_present = EXT_HMAC_SECRET_PARSED;
                printf1(TAG_CTAP, "parsed hmac_secret request\r\n");
            }
            else
            {
                printf1(TAG_RED, "warning: hmac_secret request ignored for being wrong type\r\n");
            }
        }
        else if (strncmp(key, "credProtect",11) == 0) {
            if (cbor_value_get_type(&map) == CborIntegerType) {
                ret = cbor_value_get_int(&map, (int*)&ext->cred_protect);
                check_ret(ret);
            } else {
                printf1(TAG_RED, "warning: credProtect request ignored for being wrong type\r\n");
            }
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }
    return 0;
}

uint8_t ctap_parse_make_credential(CTAP_makeCredential * MC, CborEncoder * encoder, uint8_t * request, int length)
{
    int ret;
    unsigned int i;
    int key;
    size_t map_length;
    CborParser parser;
    CborValue it,map;

    memset(MC, 0, sizeof(CTAP_makeCredential));
    MC->up = 0xff;
    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    check_retr(ret);

    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        printf2(TAG_ERR,"Error, expecting cbor map\n");
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);

    printf1(TAG_MC,"map has %d elements\n",map_length);

    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            printf2(TAG_ERR,"Error, expecting int for map key\n");
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);
        ret = 0;

        switch(key)
        {

            case MC_clientDataHash:
                printf1(TAG_MC,"CTAP_clientDataHash\n");

                ret = parse_fixed_byte_string(&map, MC->clientDataHash, CLIENT_DATA_HASH_SIZE);
                if (ret == 0)
                {
                    MC->paramsParsed |= PARAM_clientDataHash;
                }

                printf1(TAG_MC,"  "); dump_hex1(TAG_MC,MC->clientDataHash, 32);
                break;
            case MC_rp:
                printf1(TAG_MC,"CTAP_rp\n");

                ret = parse_rp(&MC->rp, &map);
                if (ret == 0)
                {
                    MC->paramsParsed |= PARAM_rp;
                }


                printf1(TAG_MC,"  ID: %s\n", MC->rp.id);
                printf1(TAG_MC,"  name: %s\n", MC->rp.name);
                break;
            case MC_user:
                printf1(TAG_MC,"CTAP_user\n");

                ret = parse_user(MC, &map);

                printf1(TAG_MC,"  ID: "); dump_hex1(TAG_MC, MC->credInfo.user.id, MC->credInfo.user.id_size);
                printf1(TAG_MC,"  name: %s\n", MC->credInfo.user.name);

                break;
            case MC_pubKeyCredParams:
                printf1(TAG_MC,"CTAP_pubKeyCredParams\n");

                ret = parse_pub_key_cred_params(MC, &map);

                printf1(TAG_MC,"  cred_type: 0x%02x\n", MC->credInfo.publicKeyCredentialType);
                printf1(TAG_MC,"  alg_type: %d\n", MC->credInfo.COSEAlgorithmIdentifier);

                break;
            case MC_excludeList:
                printf1(TAG_MC,"CTAP_excludeList\n");
                ret = parse_verify_exclude_list(&map);
                check_ret(ret);

                ret = cbor_value_enter_container(&map, &MC->excludeList);
                check_ret(ret);

                ret = cbor_value_get_array_length(&map, &MC->excludeListSize);
                check_ret(ret);


                printf1(TAG_MC,"CTAP_excludeList done\n");
                break;
            case MC_extensions:
                printf1(TAG_MC,"CTAP_extensions\n");
                type = cbor_value_get_type(&map);
                if (type != CborMapType)
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                ret = ctap_parse_extensions(&map, &MC->extensions);
                check_retr(ret);
                break;

            case MC_options:
                printf1(TAG_MC,"CTAP_options\n");
                ret = parse_options(&map, &MC->credInfo.rk, &MC->uv, &MC->up);
                check_retr(ret);
                break;
            case MC_pinAuth: {
                printf1(TAG_MC,"CTAP_pinAuth\n");

                size_t pinSize;
                if (cbor_value_get_type(&map) == CborByteStringType &&
                    cbor_value_get_string_length(&map, &pinSize) == CborNoError &&
                    pinSize == 0)
                {
                    MC->pinAuthEmpty = 1;
                    break;
                }

                ret = parse_fixed_byte_string(&map, MC->pinAuth, 16);
                if (CTAP1_ERR_INVALID_LENGTH != ret)    // damn microsoft
                {
                    check_retr(ret);
                }
                else
                {
                    ret = 0;
                }
                MC->pinAuthPresent = 1;
                break;
            }
            case MC_pinProtocol:
                printf1(TAG_MC,"CTAP_pinProtocol\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &MC->pinProtocol);
                    check_ret(ret);
                    printf1(TAG_MC," == %d\n",MC->pinProtocol);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }

                break;

            default:
                printf1(TAG_MC,"invalid key %d\n", key);

        }
        if (ret != 0)
        {
            return ret;
        }
        ret = cbor_value_advance(&map);
        check_ret(ret);
    }

    return 0;
}

uint8_t parse_credential_descriptor(CborValue * arr, CTAP_credentialDescriptor * cred)
{
    int ret;
    size_t buflen;
    char type[12];
    CborValue val;
    cred->type = 0;

    if (cbor_value_get_type(arr) != CborMapType)
    {
        printf2(TAG_ERR,"Error, CborMapType expected in credential\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_map_find_value(arr, "id", &val);
    check_ret(ret);

    if (cbor_value_get_type(&val) != CborByteStringType)
    {
        printf2(TAG_ERR,"Error, No valid ID field (%s)\n", cbor_value_get_type_string(&val));
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    buflen = sizeof(CredentialId);
    ret = cbor_value_copy_byte_string(&val, (uint8_t*)&cred->credential.id, &buflen, NULL);

    if (buflen == U2F_KEY_HANDLE_SIZE)
    {
        printf2(TAG_PARSE,"CTAP1 credential\n");
        cred->type = PUB_KEY_CRED_CTAP1;
    }
    else if (buflen != sizeof(CredentialId))
    {
        printf2(TAG_ERR,"Ignoring credential is incorrect length, treating as custom\n");
        cred->type = PUB_KEY_CRED_CUSTOM;
        buflen = 256;
        ret = cbor_value_copy_byte_string(&val, getAssertionState.customCredId, &buflen, NULL);
        getAssertionState.customCredIdSize = buflen;
    }
    check_ret(ret);

    ret = cbor_value_map_find_value(arr, "type", &val);
    check_ret(ret);

    if (cbor_value_get_type(&val) != CborTextStringType)
    {
        printf2(TAG_ERR,"Error, No valid type field\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    buflen = sizeof(type);
    ret = cbor_value_copy_text_string(&val, type, &buflen, NULL);
    if (ret == CborErrorOutOfMemory)
    {
        cred->type = PUB_KEY_CRED_UNKNOWN;
    }
    else
    {
        check_ret(ret);
    }


    if (strncmp(type, "public-key",11) == 0)
    {
        if (0 == cred->type)
        {
            cred->type = PUB_KEY_CRED_PUB_KEY;
        }
    }
    else
    {
        cred->type = PUB_KEY_CRED_UNKNOWN;
        printf1(TAG_RED, "Unknown type: %s\r\n", type);
    }

    return 0;
}

uint8_t parse_allow_list(CTAP_getAssertion * GA, CborValue * it)
{
    CborValue arr;
    size_t len;
    int ret;
    unsigned int i;
    CTAP_credentialDescriptor * cred;

    if (cbor_value_get_type(it) != CborArrayType)
    {
        printf2(TAG_ERR,"Error, expecting cbor array\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(it,&arr);
    check_ret(ret);

    ret = cbor_value_get_array_length(it, &len);
    check_ret(ret);

    GA->credLen = 0;

    for(i = 0; i < len; i++)
    {
        if (i >= ALLOW_LIST_MAX_SIZE)
        {
            printf1(TAG_PARSE,"Error, out of memory for allow list.\n");
            return CTAP2_ERR_TOO_MANY_ELEMENTS;
        }

        GA->credLen += 1;
        cred = &GA->creds[i];

        memset(cred, 0, sizeof(CTAP_credentialDescriptor));
        ret = parse_credential_descriptor(&arr,cred);
        check_retr(ret);

        ret = cbor_value_advance(&arr);
        check_ret(ret);

    }
    return 0;
}

static uint8_t parse_cred_mgmt_subcommandparams(CborValue * val, CTAP_credMgmt * CM)
{
    size_t map_length;
    int key;
    int ret;
    unsigned int i;
    CborValue map;
    size_t sz = 32;

    if (cbor_value_get_type(val) != CborMapType)
    {
        printf2(TAG_ERR,"error, wrong type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }


    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    const uint8_t * start_byte = cbor_value_get_next_byte(&map) - 1;

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborIntegerType)
        {
            printf2(TAG_ERR,"Error, expecting integer type for map key, got %s\n", cbor_value_get_type_string(&map));
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        ret = cbor_value_get_int(&map, &key);
        check_ret(ret);
        ret = cbor_value_advance(&map);
        check_ret(ret);
        switch(key)
        {
            case CM_subCommandRpId:
                ret = cbor_value_copy_byte_string(&map, CM->subCommandParams.rpIdHash, &sz, NULL);
                if (ret == CborErrorOutOfMemory)
                {
                    printf2(TAG_ERR,"Error, map key is too large\n");
                    return CTAP2_ERR_LIMIT_EXCEEDED;
                }
                check_ret(ret);
                break;
            case CM_subCommandCred:
                ret = parse_credential_descriptor(&map, &CM->subCommandParams.credentialDescriptor);
                check_ret(ret);;
                break;
        }
        ret = cbor_value_advance(&map);
        check_ret(ret);
    }

    const uint8_t * end_byte = cbor_value_get_next_byte(&map);

    uint32_t length = (uint32_t)(end_byte - start_byte);
    if (length > sizeof(CM->hashed.subCommandParamsCborCopy))
    {
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    // Copy the details that were hashed so they can be verified later.
    memmove(CM->hashed.subCommandParamsCborCopy, start_byte, length);
    CM->subCommandParamsCborSize = length;

    return 0;
}

uint8_t ctap_parse_cred_mgmt(CTAP_credMgmt * CM, uint8_t * request, int length)
{
    int ret;
    unsigned int i;
    int key;
    size_t map_length;
    CborParser parser;
    CborValue it,map;

    memset(CM, 0, sizeof(CTAP_credMgmt));
    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    check_ret(ret);

    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        printf2(TAG_ERR,"Error, expecting cbor map\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }


    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);

    printf1(TAG_PARSE, "CM map has %d elements\n", map_length);

    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            printf2(TAG_ERR,"Error, expecting int for map key\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);

        switch(key)
        {
            case CM_cmd:
                printf1(TAG_PARSE, "CM_cmd\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &CM->cmd);
                    check_ret(ret);
                    CM->hashed.cmd = CM->cmd;
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case CM_subCommandParams:
                printf1(TAG_PARSE, "CM_subCommandParams\n");
                ret = parse_cred_mgmt_subcommandparams(&map, CM);
                check_ret(ret);
                break;
            case CM_pinProtocol:
                printf1(TAG_PARSE, "CM_pinProtocol\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &CM->pinProtocol);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case CM_pinAuth:
                printf1(TAG_PARSE, "CM_pinAuth\n");
                ret = parse_fixed_byte_string(&map, CM->pinAuth, 16);
                check_retr(ret);
                CM->pinAuthPresent = 1;
                break;
        }
        ret = cbor_value_advance(&map);
        check_ret(ret);
    }

    return 0;
}

uint8_t ctap_parse_get_assertion(CTAP_getAssertion * GA, uint8_t * request, int length)
{
    int ret;
    unsigned int i;
    int key;
    size_t map_length;
    CborParser parser;
    CborValue it,map;

    memset(GA, 0, sizeof(CTAP_getAssertion));
    GA->creds = getAssertionState.creds;     // Save stack memory
    GA->up = 0xff;

    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    check_ret(ret);

    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        printf2(TAG_ERR,"Error, expecting cbor map\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);

    printf1(TAG_GA,"GA map has %d elements\n",map_length);

    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            printf2(TAG_ERR,"Error, expecting int for map key\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);
        ret = 0;

        switch(key)
        {

            case GA_clientDataHash:
                printf1(TAG_GA,"GA_clientDataHash\n");

                ret = parse_fixed_byte_string(&map, GA->clientDataHash, CLIENT_DATA_HASH_SIZE);
                check_retr(ret);
                GA->clientDataHashPresent = 1;

                printf1(TAG_GA,"  "); dump_hex1(TAG_GA, GA->clientDataHash, 32);
                break;
            case GA_rpId:
                printf1(TAG_GA,"GA_rpId\n");

                ret = parse_rp_id(&GA->rp, &map);

                printf1(TAG_GA,"  ID: %s\n", GA->rp.id);
                break;
            case GA_allowList:
                printf1(TAG_GA,"GA_allowList\n");
                ret = parse_allow_list(GA, &map);
                check_ret(ret);
                GA->allowListPresent = 1;

                break;
            case GA_extensions:
                printf1(TAG_GA,"GA_extensions\n");
                ret = ctap_parse_extensions(&map, &GA->extensions);
                check_retr(ret);
                break;

            case GA_options:
                printf1(TAG_GA,"CTAP_options\n");
                ret = parse_options(&map, &GA->rk, &GA->uv, &GA->up);
                check_retr(ret);
                break;
            case GA_pinAuth: {
                printf1(TAG_GA,"CTAP_pinAuth\n");

                size_t pinSize;
                if (cbor_value_get_type(&map) == CborByteStringType &&
                    cbor_value_get_string_length(&map, &pinSize) == CborNoError &&
                    pinSize == 0)
                {
                    GA->pinAuthEmpty = 1;
                    break;
                }

                ret = parse_fixed_byte_string(&map, GA->pinAuth, 16);
                if (CTAP1_ERR_INVALID_LENGTH != ret)    // damn microsoft
                {
                    check_retr(ret);

                }
                else
                {
                    ret = 0;
                }

                check_retr(ret);
                GA->pinAuthPresent = 1;

                break;
            }
            case GA_pinProtocol:
                printf1(TAG_GA,"CTAP_pinProtocol\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &GA->pinProtocol);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }

                break;

        }
        if (ret != 0)
        {
            printf2(TAG_ERR,"error, parsing failed\n");
            return ret;
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }


    return 0;
}

uint8_t parse_cose_key(CborValue * it, COSE_key * cose)
{
    CborValue map;
    size_t map_length;
    int ret,key;
    unsigned int i;
    int xkey = 0,ykey = 0;
    cose->kty = 0;
    cose->crv = 0;


    CborType type = cbor_value_get_type(it);
    if (type != CborMapType)
    {
        printf2(TAG_ERR,"Error, expecting cbor map\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(it, &map_length);
    check_ret(ret);

    printf1(TAG_PARSE,"cose key has %d elements\n",map_length);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborIntegerType)
        {
            printf2(TAG_ERR,"Error, expecting int for map key\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);

        switch(key)
        {
            case COSE_KEY_LABEL_KTY:
                printf1(TAG_PARSE,"COSE_KEY_LABEL_KTY\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &cose->kty);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case COSE_KEY_LABEL_ALG:
                printf1(TAG_PARSE,"COSE_KEY_LABEL_ALG\n");
                break;
            case COSE_KEY_LABEL_CRV:
                printf1(TAG_PARSE,"COSE_KEY_LABEL_CRV\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &cose->crv);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case COSE_KEY_LABEL_X:
                printf1(TAG_PARSE,"COSE_KEY_LABEL_X\n");
                ret = parse_fixed_byte_string(&map, cose->pubkey.x, 32);
                check_retr(ret);
                xkey = 1;

                break;
            case COSE_KEY_LABEL_Y:
                printf1(TAG_PARSE,"COSE_KEY_LABEL_Y\n");
                ret = parse_fixed_byte_string(&map, cose->pubkey.y, 32);
                check_retr(ret);
                ykey = 1;

                break;
            default:
                printf1(TAG_PARSE,"Warning, unrecognized cose key option %d\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }
    if (xkey == 0 || ykey == 0 || cose->kty == 0 || cose->crv == 0)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    return 0;
}

uint8_t ctap_parse_client_pin(CTAP_clientPin * CP, uint8_t * request, int length)
{
    int ret;
    unsigned int i;
    int key;
    size_t map_length;
    size_t sz;
    CborParser parser;
    CborValue it,map;

    memset(CP, 0, sizeof(CTAP_clientPin));
    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    check_ret(ret);

    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        printf2(TAG_ERR,"Error, expecting cbor map\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);

    printf1(TAG_CP,"CP map has %d elements\n",map_length);

    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            printf2(TAG_ERR,"Error, expecting int for map key\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);
        ret = 0;

        switch(key)
        {
            case CP_pinProtocol:
                printf1(TAG_CP,"CP_pinProtocol\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    cbor_value_get_int_checked(&map, &CP->pinProtocol);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case CP_subCommand:
                printf1(TAG_CP,"CP_subCommand\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    cbor_value_get_int_checked(&map, &CP->subCommand);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }

                break;
            case CP_keyAgreement:
                printf1(TAG_CP,"CP_keyAgreement\n");
                ret = parse_cose_key(&map, &CP->keyAgreement);
                check_retr(ret);
                CP->keyAgreementPresent = 1;
                break;
            case CP_pinAuth:
                printf1(TAG_CP,"CP_pinAuth\n");

                ret = parse_fixed_byte_string(&map, CP->pinAuth, 16);
                check_retr(ret);
                CP->pinAuthPresent = 1;
                break;
            case CP_newPinEnc:
                printf1(TAG_CP,"CP_newPinEnc\n");
                if (cbor_value_get_type(&map) == CborByteStringType)
                {
                    ret = cbor_value_calculate_string_length(&map, &sz);
                    check_ret(ret);
                    if (sz > NEW_PIN_ENC_MAX_SIZE || sz < NEW_PIN_ENC_MIN_SIZE)
                    {
                        return CTAP2_ERR_PIN_POLICY_VIOLATION;
                    }

                    CP->newPinEncSize = sz;
                    sz = NEW_PIN_ENC_MAX_SIZE;
                    ret = cbor_value_copy_byte_string(&map, CP->newPinEnc, &sz, NULL);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }

                break;
            case CP_pinHashEnc:
                printf1(TAG_CP,"CP_pinHashEnc\n");

                ret = parse_fixed_byte_string(&map, CP->pinHashEnc, 16);
                check_retr(ret);
                CP->pinHashEncPresent = 1;

                break;
            case CP_getKeyAgreement:
                printf1(TAG_CP,"CP_getKeyAgreement\n");
                if (cbor_value_get_type(&map) != CborBooleanType)
                {
                    printf2(TAG_ERR,"Error, expecting cbor boolean\n");
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                ret = cbor_value_get_boolean(&map, &CP->getKeyAgreement);
                check_ret(ret);
                break;
            case CP_getRetries:
                printf1(TAG_CP,"CP_getRetries\n");
                if (cbor_value_get_type(&map) != CborBooleanType)
                {
                    printf2(TAG_ERR,"Error, expecting cbor boolean\n");
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                ret = cbor_value_get_boolean(&map, &CP->getRetries);
                check_ret(ret);
                break;
            default:
                printf1(TAG_CP,"Unknown key %d\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }


    return 0;
}
