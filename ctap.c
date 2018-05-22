#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "ctap.h"
#include "ctap_errors.h"
#include "cose_key.h"
#include "crypto.h"
#include "util.h"
#include "log.h"


#define check_ret(r)    _check_ret(r,__LINE__, __FILE__);\
                        if ((r) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

#define check_retr(r)    _check_ret(r,__LINE__, __FILE__);\
                        if ((r) != CborNoError) return r;


#define PIN_TOKEN_SIZE      16
static uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
static uint8_t KEY_AGREEMENT_PUB[64];
static uint8_t KEY_AGREEMENT_PRIV[32];
static uint8_t PIN_CODE_SET = 0;
static uint8_t PIN_CODE[NEW_PIN_ENC_MAX_SIZE];
static uint8_t PIN_CODE_HASH[32];
static uint8_t DEVICE_LOCKOUT = 0;

static CborEncoder * _ENCODER;
static void _check_ret(CborError ret, int line, const char * filename)
{
    if (ret != CborNoError)
    {
        printf1(TAG_ERR,"CborError: 0x%x: %s: %d: %s\n", ret, filename, line, cbor_error_string(ret));
        /*exit(1);*/
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

/*static CborError cbor_value_map_find_value_by_int(const CborValue *map, const int key, CborValue * element)*/
/*{*/
    /*size_t sz;*/
    /*CborValue ckey, it;*/
    /*int rkey;*/
    /*int ret = cbor_value_get_map_length(map, &sz);*/
    /*check_ret(ret);*/

    /*cbor_value_enter_container(map, &it);*/

    /*int i;*/
    /*for (i = 0; i < sz; i++)*/
    /*{*/
        /*if (cbor_value_get_type(&it) == CborIntegerType)*/
        /*{*/
            /*ret = cbor_value_advance(&it);*/
            /*check_ret(ret);*/
            /*ret = cbor_value_get_int_checked(&it, &rkey);*/
            /*check_ret(ret);*/
            /*ret = cbor_value_advance(&it);*/
            /*check_ret(ret);*/
        /*}*/
        /*else*/
        /*{*/
            /*cbor_value_advance(&it);*/
            /*cbor_value_advance(&it);*/
        /*}*/
    /*}*/

    /*return CborNoError;*/
/*}*/

uint8_t verify_pin_auth(uint8_t * pinAuth, uint8_t * clientDataHash)
{
    uint8_t hmac[32];
    crypto_sha256_hmac(PIN_TOKEN, PIN_TOKEN_SIZE, clientDataHash, CLIENT_DATA_HASH_SIZE, hmac);

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

            }
            ret = cbor_encoder_close_container(&map, &options);
            check_ret(ret);
        }


    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return CTAP1_ERR_SUCCESS;
}


static uint8_t parse_user(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz, map_length;
    uint8_t key[8];
    int ret;
    int i;
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

        if (strcmp(key, "id") == 0)
        {

            if (cbor_value_get_type(&map) != CborByteStringType)
            {
                printf2(TAG_ERR,"Error, expecting byte string type for rp map value\n");
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }

            sz = USER_ID_MAX_SIZE;
            ret = cbor_value_copy_byte_string(&map, MC->user.id, &sz, NULL);
            if (ret == CborErrorOutOfMemory)
            {
                printf2(TAG_ERR,"Error, USER_ID is too large\n");
                return CTAP2_ERR_LIMIT_EXCEEDED;
            }
            MC->user.id_size = sz;
            check_ret(ret);
        }
        else if (strcmp(key, "name") == 0)
        {
            sz = USER_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, MC->user.name, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->user.name[USER_NAME_LIMIT - 1] = 0;
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

static uint8_t parse_pub_key_cred_params(CTAP_makeCredential * MC, CborValue * val)
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
        printf2(TAG_ERR,"error, expecting array type\n");
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);

    ret = cbor_value_get_array_length(val, &arr_length);
    check_ret(ret);

    for (i = 0; i < arr_length; i++)
    {
        if ((ret = parse_pub_key_cred_param(&arr, &cred_type, &alg_type)) == 0)
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
            return ret;
        }
        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }

    printf2(TAG_ERR,"Error, no public key credential parameters are supported!\n");
    return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

uint8_t parse_fixed_byte_string(CborValue * map, uint8_t * dst, int len)
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
            return CTAP1_ERR_OTHER;
        }
    }
    else
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    return 0;
}


static int parse_rp_id(struct rpId * rp, CborValue * val)
{
    size_t sz = DOMAIN_NAME_MAX_SIZE;
    int ret = cbor_value_copy_text_string(val, rp->id, &sz, NULL);
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

static uint8_t parse_rp(struct rpId * rp, CborValue * val)
{
    size_t sz, map_length;
    uint8_t key[8];
    int ret;
    int i;
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
            ret = cbor_value_copy_text_string(&map, rp->name, &sz, NULL);
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

static uint8_t parse_options(CborValue * val, uint8_t * rk, uint8_t * uv)
{
    size_t sz, map_length;
    uint8_t key[8];
    int ret;
    int i;
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
            printf2(TAG_ERR,"Error, expecting text string type for rp map value\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        if (strcmp(key, "rk") == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            *rk = b;
        }
        else if (strcmp(key, "uv") == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            *uv = b;
        }
        else
        {
            printf1(TAG_PARSE,"ignoring key %s for option map\n", key);
        }



    }
}

static uint8_t ctap_parse_make_credential(CTAP_makeCredential * MC, CborEncoder * encoder, uint8_t * request, int length)
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

                printf1(TAG_MC,"  ID: "); dump_hex1(TAG_MC, MC->user.id, MC->user.id_size);
                printf1(TAG_MC,"  name: %s\n", MC->user.name);

                break;
            case MC_pubKeyCredParams:
                printf1(TAG_MC,"CTAP_pubKeyCredParams\n");

                ret = parse_pub_key_cred_params(MC, &map);

                printf1(TAG_MC,"  cred_type: 0x%02x\n", MC->publicKeyCredentialType);
                printf1(TAG_MC,"  alg_type: %d\n", MC->COSEAlgorithmIdentifier);

                break;
            case MC_excludeList:
                printf1(TAG_MC,"CTAP_excludeList\n");
                break;
            case MC_extensions:
                printf1(TAG_MC,"CTAP_extensions\n");
                break;

            case MC_options:
                printf1(TAG_MC,"CTAP_options\n");
                ret = parse_options(&map, &MC->rk, &MC->uv);
                check_retr(ret);
                break;
            case MC_pinAuth:
                printf1(TAG_MC,"CTAP_pinAuth\n");

                ret = parse_fixed_byte_string(&map, MC->pinAuth, 16);
                check_retr(ret);
                MC->pinAuthPresent = 1;

                break;
            case MC_pinProtocol:
                printf1(TAG_MC,"CTAP_pinProtocol\n");
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &MC->pinProtocol);
                    check_ret(ret);
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

        cbor_value_advance(&map);
        check_ret(ret);
    }

    return 0;
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
}

void make_auth_tag(struct rpId * rp, CTAP_userEntity * user, uint32_t count, uint8_t * tag)
{
    uint8_t hashbuf[32];
    crypto_sha256_init();
    crypto_sha256_update(rp->id, rp->size);
    crypto_sha256_update(user->id, user->id_size);
    crypto_sha256_update(user->name, strnlen(user->name, USER_NAME_LIMIT));
    crypto_sha256_update((uint8_t*)&count, 4);
    crypto_sha256_update_secret();
    crypto_sha256_final(hashbuf);

    memmove(tag, hashbuf, CREDENTIAL_TAG_SIZE);
}

static int ctap_make_auth_data(struct rpId * rp, CborEncoder * map, uint8_t * auth_data_buf, int len, CTAP_userEntity * user, uint8_t credtype, int32_t algtype)
{
    CborEncoder cose_key;
    int auth_data_sz, ret;
    uint32_t count;
    CTAP_authData * authData = (CTAP_authData *)auth_data_buf;

    uint8_t * cose_key_buf = auth_data_buf + sizeof(CTAP_authData);

    if((sizeof(CTAP_authData) - sizeof(CTAP_attestHeader)) > len)
    {
        printf1(TAG_ERR,"assertion fail, auth_data_buf must be at least %d bytes\n", sizeof(CTAP_authData) - sizeof(CTAP_attestHeader));
        exit(1);
    }

    crypto_sha256_init();
    crypto_sha256_update(rp->id, rp->size);
    crypto_sha256_final(authData->rpIdHash);

    authData->flags = (ctap_user_presence_test() << 0);
    authData->flags |= (ctap_user_verification(0) << 2);

    count = ctap_atomic_count( 0 );
    authData->signCount = ntohl(count);

    if (credtype != 0)
    {
        // add attestedCredentialData
        authData->flags |= (1 << 6);//include attestation data

        cbor_encoder_init(&cose_key, cose_key_buf, len - sizeof(CTAP_authData), 0);
        _ENCODER = &cose_key;

        memmove(authData->attest.aaguid, CTAP_AAGUID, 16);
        authData->attest.credLenL = CREDENTIAL_ID_SIZE & 0x00FF;
        authData->attest.credLenH = (CREDENTIAL_ID_SIZE & 0xFF00) >> 8;

#if CREDENTIAL_ID_SIZE != 150
#error "need to update credential ID layout"
#else
        memset(authData->attest.credential.id, 0, CREDENTIAL_ID_SIZE);

        // Make a tag we can later check to make sure this is a token we made
        make_auth_tag(rp, user, count, authData->attest.credential.fields.tag);

        memmove(&authData->attest.credential.fields.user, user, sizeof(CTAP_userEntity)); //TODO encrypt this

        authData->attest.credential.fields.count = count;

        ctap_generate_cose_key(&cose_key, authData->attest.credential.id, CREDENTIAL_ID_SIZE, credtype, algtype);

        printf1(TAG_MC,"COSE_KEY: "); dump_hex1(TAG_MC, cose_key_buf, cbor_encoder_get_buffer_size(&cose_key, cose_key_buf));

        auth_data_sz = sizeof(CTAP_authData) + cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);
#endif

    }
    else
    {
        auth_data_sz = sizeof(CTAP_authData) - sizeof(CTAP_attestHeader);
    }

    {
        ret = cbor_encode_int(map,RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(map, auth_data_buf, auth_data_sz);
        check_ret(ret);
    }


    return auth_data_sz;
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

    crypto_ecc256_sign(hashbuf, 32, sigbuf);

    /*printf1("signature hash: "); dump_hex(hashbuf, 32);*/
    /*printf1("R: "); dump_hex(sigbuf, 32);*/
    /*printf1("S: "); dump_hex(sigbuf+32, 32);*/

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

    return 0x46 + pad_s + pad_r;
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
}


uint8_t ctap_make_credential(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_makeCredential MC;
    int ret;
    uint8_t auth_data_buf[300];
    uint8_t * hashbuf = auth_data_buf + 0;
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

    if (PIN_CODE_SET == 1 && MC.pinAuthPresent == 0)
    {
        printf2(TAG_ERR,"pinAuth is required\n");
        return CTAP2_ERR_PIN_REQUIRED;
    }
    else
    {
        ret = verify_pin_auth(MC.pinAuth, MC.clientDataHash);
        check_retr(ret);
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

static int parse_allow_list(CTAP_getAssertion * GA, CborValue * it)
{
    CborValue arr, val;
    size_t len,buflen;
    uint8_t type[12];
    int i,ret;

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

        if (cbor_value_get_type(&arr) != CborMapType)
        {
            printf2(TAG_ERR,"Error, CborMapType expected in allow_list\n");
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        ret = cbor_value_map_find_value(&arr, "id", &val);
        check_ret(ret);

        if (cbor_value_get_type(&val) != CborByteStringType)
        {
            printf2(TAG_ERR,"Error, No valid ID field (%s)\n", cbor_value_get_type_string(&val));
            return CTAP2_ERR_MISSING_PARAMETER;
        }

        buflen = CREDENTIAL_ID_SIZE;
        cbor_value_copy_byte_string(&val, GA->creds[i].credential.id, &buflen, NULL);
        if (buflen != CREDENTIAL_ID_SIZE)
        {
            printf2(TAG_ERR,"Error, credential is incorrect length\n");
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE; // maybe just skip it instead of fail?
        }

        ret = cbor_value_map_find_value(&arr, "type", &val);
        check_ret(ret);

        if (cbor_value_get_type(&val) != CborTextStringType)
        {
            printf2(TAG_ERR,"Error, No valid type field\n");
            return CTAP2_ERR_MISSING_PARAMETER;
        }

        buflen = sizeof(type);
        cbor_value_copy_text_string(&val, type, &buflen, NULL);

        if (strcmp(type, "public-key") == 0)
        {
            GA->creds[i].type = PUB_KEY_CRED_PUB_KEY;
        }
        else
        {
            GA->creds[i].type = PUB_KEY_CRED_UNKNOWN;
        }

        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }
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

    make_auth_tag(rp, &desc->credential.fields.user, desc->credential.fields.count, tag);

    return (memcmp(desc->credential.fields.tag, tag, CREDENTIAL_TAG_SIZE) == 0);
}

int ctap_parse_get_assertion(CTAP_getAssertion * GA, uint8_t * request, int length)
{
    int ret;
    int i,j;
    int key;
    size_t map_length;
    size_t sz;
    CborParser parser;
    CborValue it,map;

    memset(GA, 0, sizeof(CTAP_getAssertion));
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
                if (ret == 0)
                {
                    for (j = 0; j < GA->credLen; j++)
                    {
                        printf1(TAG_GA,"CRED ID (# %d): ", GA->creds[j].credential.fields.count);
                        dump_hex1(TAG_GA, GA->creds[j].credential.id, CREDENTIAL_ID_SIZE);
                        if (ctap_authenticate_credential(&GA->rp, &GA->creds[j]))   // warning encryption will break this
                        {
                            printf1(TAG_GA,"  Authenticated.\n");
                        }
                        else
                        {
                            printf1(TAG_GA,"  NOT authentic.\n");
                        }
                    }
                }
                break;
            case GA_extensions:
                printf1(TAG_GA,"GA_extensions\n");
                break;

            case GA_options:
                printf1(TAG_GA,"CTAP_options\n");
                ret = parse_options(&map, &GA->rk, &GA->uv);
                check_retr(ret);
                break;
            case GA_pinAuth:
                printf1(TAG_GA,"CTAP_pinAuth\n");

                ret = parse_fixed_byte_string(&map, GA->pinAuth, 16);
                check_retr(ret);
                GA->pinAuthPresent = 1;

                break;
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

        cbor_value_advance(&map);
        check_ret(ret);
    }


    return 0;
}

static int pick_first_authentic_credential(CTAP_getAssertion * GA)
{
    int i;
    for (i = 0; i < GA->credLen; i++)
    {
        if (ctap_authenticate_credential(&GA->rp, &GA->creds[i]))
        {
            return i;
        }
    }
    return -1;
}

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

        ret = cbor_encode_byte_string(&desc, cred->credential.id, CREDENTIAL_ID_SIZE);
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

        ret = cbor_encode_text_stringz(&entity, user->name);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(map, &entity);
    check_ret(ret);

    return 0;
}

uint8_t ctap_get_assertion(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_getAssertion GA;
    uint8_t auth_data_buf[32 + 1 + 4];
    uint8_t sigbuf[64];
    uint8_t sigder[72];

    int ret = ctap_parse_get_assertion(&GA,request,length);

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_get_assertion failed\n");
        return ret;
    }

    if (PIN_CODE_SET == 1 && GA.pinAuthPresent == 0)
    {
        printf2(TAG_ERR,"pinAuth is required\n");
        return CTAP2_ERR_PIN_REQUIRED;
    }
    else
    {
        ret = verify_pin_auth(GA.pinAuth, GA.clientDataHash);
        check_retr(ret);
    }


    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 5);
    check_ret(ret);

    ctap_make_auth_data(&GA.rp, &map, auth_data_buf, sizeof(auth_data_buf), NULL, 0,0);

    int pick = pick_first_authentic_credential(&GA);    // TODO let this handle decryption? lazy?
    if (pick == -1)
    {
        printf2(TAG_ERR,"Error, no authentic credential\n");
        return CTAP2_ERR_CREDENTIAL_NOT_VALID;
    }

    ret = ctap_add_credential_descriptor(&map, &GA.creds[pick]);
    check_retr(ret);

    ret = ctap_add_user_entity(&map, &GA.creds[pick].credential.fields.user);
    check_retr(ret);

    crypto_ecc256_load_key(GA.creds[pick].credential.id, CREDENTIAL_ID_SIZE);

    int sigder_sz = ctap_calculate_signature(auth_data_buf, sizeof(auth_data_buf), GA.clientDataHash, auth_data_buf, sigbuf, sigder);

    {
        ret = cbor_encode_int(&map, RESP_signature);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, sigder, sigder_sz);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, RESP_numberOfCredentials);
        check_ret(ret);
        ret = cbor_encode_int(&map, GA.credLen);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

}

uint8_t parse_cose_key(CborValue * it, uint8_t * x, uint8_t * y, int * kty, int * crv)
{
    CborValue map;
    size_t map_length;
    size_t ptsz;
    int i,ret,key;
    int xkey = 0,ykey = 0;
    *kty = 0;
    *crv = 0;


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
                    ret = cbor_value_get_int_checked(&map, kty);
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
                    ret = cbor_value_get_int_checked(&map, crv);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case COSE_KEY_LABEL_X:
                printf1(TAG_PARSE,"COSE_KEY_LABEL_X\n");
                ret = parse_fixed_byte_string(&map, x, 32);
                check_retr(ret);
                xkey = 1;

                break;
            case COSE_KEY_LABEL_Y:
                printf1(TAG_PARSE,"COSE_KEY_LABEL_Y\n");
                ret = parse_fixed_byte_string(&map, y, 32);
                check_retr(ret);
                ykey = 1;

                break;
            default:
                printf1(TAG_PARSE,"Warning, unrecognized cose key option %d\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }
    if (xkey == 0 || ykey == 0 || *kty == 0 || *crv == 0)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    return 0;
}

int ctap_parse_client_pin(CTAP_clientPin * CP, uint8_t * request, int length)
{
    int ret;
    int i,j;
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
                ret = parse_cose_key(&map, CP->keyAgreement.pubkey.x, CP->keyAgreement.pubkey.y, &CP->keyAgreement.kty, &CP->keyAgreement.crv);
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
                    if (sz > NEW_PIN_ENC_MAX_SIZE)
                    {
                        return CTAP1_ERR_OTHER;
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
                break;
            case CP_getRetries:
                printf1(TAG_CP,"CP_getRetries\n");
                break;
            default:
                printf1(TAG_CP,"Unknown key %d\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }


    return 0;
}

uint8_t ctap_update_pin_if_verified(uint8_t * pinEnc, int len, uint8_t * platform_pubkey, uint8_t * pinAuth)
{
    uint8_t shared_secret[32];
    uint8_t hmac[32];
    int ret;

    if (len < 64)
    {
        return CTAP1_ERR_OTHER;
    }


    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_sha256_hmac(shared_secret, 32, pinEnc, len, hmac);

    if (memcmp(hmac, pinAuth, 16) != 0)
    {
        printf2(TAG_ERR,"pinAuth failed for update pin\n");
        dump_hex1(TAG_ERR, hmac,16);
        dump_hex1(TAG_ERR, pinAuth,16);
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    crypto_aes256_init(shared_secret);

    while((len & 0xf) != 0) // round up to nearest  AES block size multiple
    {
        len++;
    }

    crypto_aes256_decrypt(pinEnc, len);

    ret = strnlen(pinEnc, NEW_PIN_ENC_MAX_SIZE);
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
    else
    {
        ctap_update_pin(pinEnc, ret);
    }

    return 0;
}

uint8_t ctap_add_pin_if_verified(CborEncoder * map, uint8_t * platform_pubkey, uint8_t * pinHashEnc)
{
    uint8_t shared_secret[32];
    int ret;

    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_aes256_init(shared_secret);

    crypto_aes256_decrypt(pinHashEnc, 16);


    if (memcmp(pinHashEnc, PIN_CODE_HASH, 16) != 0)
    {
        printf2(TAG_ERR,"Pin does not match!\n");
        printf2(TAG_ERR,"platform-pin-hash: "); dump_hex1(TAG_ERR, pinHashEnc, 16);
        printf2(TAG_ERR,"authentic-pin-hash: "); dump_hex1(TAG_ERR, PIN_CODE_HASH, 16);
        // Generate new keyAgreement pair
        crypto_ecc256_make_key_pair(KEY_AGREEMENT_PUB, KEY_AGREEMENT_PRIV);
        ctap_decrement_pin_attempts();
        return CTAP2_ERR_PIN_INVALID;
    }

    crypto_aes256_reset_iv();

    // reuse share_secret memory for encrypted pinToken
    memmove(shared_secret, PIN_TOKEN, PIN_TOKEN_SIZE);
    crypto_aes256_encrypt(shared_secret, PIN_TOKEN_SIZE);

    ret = cbor_encode_byte_string(map, shared_secret, PIN_TOKEN_SIZE);
    check_ret(ret);

    return 0;
}

uint8_t ctap_client_pin(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_clientPin CP;
    CborEncoder map;
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
            ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinAuth);
            check_retr(ret);

            break;
        case CP_cmdChangePin:
            printf1(TAG_CP,"CP_cmdChangePin\n");
            return CTAP1_ERR_INVALID_COMMAND;

            break;
        case CP_cmdGetPinToken:
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

            ret = ctap_add_pin_if_verified(&map, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);
            check_retr(ret);

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

uint8_t ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    uint8_t status = 0;
    uint8_t cmd = *pkt_raw;
    pkt_raw++;
    length--;


    static uint8_t buf[1024];
    memset(buf,0,sizeof(buf));

    resp->data = buf;
    resp->length = 0;

    CborEncoder encoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    _ENCODER = &encoder;

    printf1(TAG_CTAP,"cbor input structure: %d bytes\n", length);
    printf1(TAG_DUMP,"cbor req: "); dump_hex1(TAG_DUMP, pkt_raw, length);


    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
            printf1(TAG_CTAP,"CTAP_MAKE_CREDENTIAL\n");
            status = ctap_make_credential(&encoder, pkt_raw, length);

            dump_hex1(TAG_DUMP, buf, cbor_encoder_get_buffer_size(&encoder, buf));

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_GET_ASSERTION:
            printf1(TAG_CTAP,"CTAP_GET_ASSERTION\n");
            status = ctap_get_assertion(&encoder, pkt_raw, length);

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
            break;
        case GET_NEXT_ASSERTION:
            printf1(TAG_CTAP,"CTAP_NEXT_ASSERTION\n");
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            printf2(TAG_ERR,"error, invalid cmd\n");
    }

    if (status != CTAP1_ERR_SUCCESS)
    {
        resp->length = 0;
    }

    printf1(TAG_CTAP,"cbor output structure: %d bytes\n", resp->length);
    return status;
}

void ctap_init()
{
    crypto_ecc256_init();
    ctap_reset_pin_attempts();

    DEVICE_LOCKOUT = 0;

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        exit(1);
    }

    crypto_ecc256_make_key_pair(KEY_AGREEMENT_PUB, KEY_AGREEMENT_PRIV);
}

void ctap_update_pin(uint8_t * pin, int len)
{
    // TODO this should go in flash
    if (len > NEW_PIN_ENC_MAX_SIZE-1 || len < 4)
    {
        printf2(TAG_ERR, "Update pin fail length\n");
        exit(1);
    }
    memset(PIN_CODE,0,sizeof(PIN_CODE));
    memmove(PIN_CODE, pin, len);

    crypto_sha256_init();
    crypto_sha256_update(PIN_CODE, len);
    crypto_sha256_final(PIN_CODE_HASH);

    PIN_CODE_SET = 1;

    printf1(TAG_CTAP, "New pin set: %s\n", PIN_CODE);
}

// TODO flash
static int8_t _flash_tries;
uint8_t ctap_decrement_pin_attempts()
{
    if (_flash_tries > 0)
    {
        _flash_tries--;
    }
    else
    {
        DEVICE_LOCKOUT = 1;
        return -1;
    }
    return 0;
}

int8_t ctap_leftover_pin_attempts()
{
    return _flash_tries;
}

void ctap_reset_pin_attempts()
{
    _flash_tries = 8;
}

