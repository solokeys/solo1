#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "ctap.h"
#include "cose_key.h"
#include "crypto.h"
#include "util.h"


#define check_ret(r)    _check_ret(r,__LINE__, __FILE__)
static CborEncoder * _ENCODER;
static void _check_ret(CborError ret, int line, const char * filename)
{
    if (ret != CborNoError)
    {
        printf("CborError: 0x%x: %s: %d: %s\n", ret, filename, line, cbor_error_string(ret));
        if (ret == 0x80000000)
            printf("  need %d more bytes\n",cbor_encoder_get_extra_bytes_needed(_ENCODER));
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
    CborEncoder options;

    const int number_of_versions = 2;

    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);
    {

        ret = cbor_encode_uint(&map, RESP_versions);     //  versions key
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, number_of_versions);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "U2F_V2");
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
            check_ret(ret);
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_aaguid);     //  aaguid key
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, CTAP_AAGUID, 16);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_options);     //  aaguid key
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
}

static int parse_client_data_hash(uint8_t * clientDataHash, CborValue * val)
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
    ret = cbor_value_copy_byte_string(val, clientDataHash, &sz, NULL);
    check_ret(ret);

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
            ret = cbor_value_copy_byte_string(&map, MC->user.id, &sz, NULL);
            if (ret == CborErrorOutOfMemory)
            {
                printf("Error, USER_ID is too large\n");
                return -1;
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


static int parse_rp_id(struct rpId * rp, CborValue * val)
{
    size_t sz = DOMAIN_NAME_MAX_SIZE;
    int ret = cbor_value_copy_text_string(val, rp->id, &sz, NULL);
    if (ret == CborErrorOutOfMemory)
    {
        printf("Error, RP_ID is too large\n");
        return -1;
    }
    rp->id[DOMAIN_NAME_MAX_SIZE] = 0;     // Extra byte defined in struct.
    rp->size = sz;
    check_ret(ret);
    return 0;
}

static int parse_rp(struct rpId * rp, CborValue * val)
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

    rp->size = 0;

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
            printf("ignoring key %s for RP map\n", key);
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }
    if (rp->size == 0)
    {
        printf("Error, no RPID provided\n");
        return -1;
    }


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
        ret = 0;

        switch(key)
        {

            case MC_clientDataHash:
                printf("CTAP_clientDataHash\n");

                ret = parse_client_data_hash(MC->clientDataHash, &map);
                if (ret == 0)
                {
                    MC->paramsParsed |= PARAM_clientDataHash;
                }

                printf("  "); dump_hex(MC->clientDataHash, 32);
                break;
            case MC_rp:
                printf("CTAP_rp\n");

                ret = parse_rp(&MC->rp, &map);
                if (ret == 0)
                {
                    MC->paramsParsed |= PARAM_rp;
                }


                printf("  ID: %s\n", MC->rp.id);
                printf("  name: %s\n", MC->rp.name);
                break;
            case MC_user:
                printf("CTAP_user\n");

                ret = parse_user(MC, &map);

                printf("  ID: "); dump_hex(MC->user.id, MC->user.id_size);
                printf("  name: %s\n", MC->user.name);

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

static int ctap_generate_cose_key(CborEncoder * cose_key, uint8_t * hmac_input, int len, uint8_t credtype, int32_t algtype)
{
    uint8_t x[32], y[32];
    int ret;
    CborEncoder map;

    ret = cbor_encoder_create_map(cose_key, &map, 5);
    int extra = cbor_encoder_get_extra_bytes_needed(&map);
    printf(" extra? %d\n", extra);
    check_ret(ret);

    if (credtype != PUB_KEY_CRED_PUB_KEY)
    {
        printf("Error, pubkey credential type not supported\n");
        return -1;
    }
    switch(algtype)
    {
        case COSE_ALG_ES256:
            crypto_ecc256_init();
            crypto_ecc256_derive_public_key(hmac_input, len, x, y);
            break;
        default:
            printf("Error, COSE alg %d not supported\n", algtype);
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
        printf("assertion fail, auth_data_buf must be at least %d bytes\n", sizeof(CTAP_authData) - sizeof(CTAP_attestHeader));
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

        printf("COSE_KEY: "); dump_hex(cose_key_buf, cbor_encoder_get_buffer_size(&cose_key, cose_key_buf));

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

    /*printf("signature hash: "); dump_hex(hashbuf, 32);*/
    /*printf("R: "); dump_hex(sigbuf, 32);*/
    /*printf("S: "); dump_hex(sigbuf+32, 32);*/

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

void ctap_add_attest_statement(CborEncoder * map, uint8_t * sigder, int len)
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


void ctap_make_credential(CborEncoder * encoder, uint8_t * request, int length)
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
        printf("error, parse_make_credential failed\n");
        return;
    }
    if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask)
    {
        printf("error, required parameter(s) for makeCredential are missing\n");
        return;
    }


    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);

    int auth_data_sz = ctap_make_auth_data(&MC.rp, &map, auth_data_buf, sizeof(auth_data_buf),
            &MC.user, MC.publicKeyCredentialType, MC.COSEAlgorithmIdentifier);

    crypto_ecc256_load_attestation_key();
    int sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_sz, MC.clientDataHash, auth_data_buf, sigbuf, sigder);

    printf("der sig [%d]: ", sigder_sz); dump_hex(sigder, sigder_sz);

    ctap_add_attest_statement(&map, sigder, sigder_sz);

    {
        ret = cbor_encode_int(&map,RESP_fmt);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&map, "packed");
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
}

static int parse_allow_list(CTAP_getAssertion * GA, CborValue * it)
{
    CborValue arr, val;
    size_t len,buflen;
    uint8_t type[12];
    int i,ret;

    if (cbor_value_get_type(it) != CborArrayType)
    {
        printf("Error, expecting cbor array\n");
        return -1;
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
            printf("Warning, out of memory for allow list, truncating.\n");
            break;
        }
        GA->credLen += 1;

        if (cbor_value_get_type(&arr) != CborMapType)
        {
            printf("Error, CborMapType expected in allow_list\n");
            return -1;
        }

        ret = cbor_value_map_find_value(&arr, "id", &val);
        check_ret(ret);

        if (cbor_value_get_type(&val) != CborByteStringType)
        {
            printf("Error, No valid ID field (%s)\n", cbor_value_get_type_string(&val));
            return -1;
        }

        buflen = CREDENTIAL_ID_SIZE;
        cbor_value_copy_byte_string(&val, GA->creds[i].credential.id, &buflen, NULL);
        if (buflen != CREDENTIAL_ID_SIZE)
        {
            printf("Error, credential is incorrect length\n");
            return -1;  // maybe just skip it instead of fail?
        }

        ret = cbor_value_map_find_value(&arr, "type", &val);
        check_ret(ret);

        if (cbor_value_get_type(&val) != CborTextStringType)
        {
            printf("Error, No valid type field\n");
            return -1;
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
        printf("unsupported credential type: %d\n", desc->type);
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
        printf("Error, expecting cbor map\n");
        return -1;
    }

    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);

    printf("GA map has %d elements\n",map_length);

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
        ret = 0;

        switch(key)
        {

            case GA_clientDataHash:
                printf("GA_clientDataHash\n");

                ret = parse_client_data_hash(GA->clientDataHash, &map);

                printf("  "); dump_hex(GA->clientDataHash, 32);
                break;
            case GA_rpId:
                printf("GA_rpId\n");

                ret = parse_rp_id(&GA->rp, &map);

                printf("  ID: %s\n", GA->rp.id);
                break;
            case GA_allowList:
                printf("GA_allowList\n");
                ret = parse_allow_list(GA, &map);
                if (ret == 0)
                {
                    for (j = 0; j < GA->credLen; j++)
                    {
                        printf("CRED ID (# %d): ", GA->creds[j].credential.fields.count);
                        dump_hex(GA->creds[j].credential.id, CREDENTIAL_ID_SIZE);
                        if (ctap_authenticate_credential(&GA->rp, &GA->creds[j]))   // warning encryption will break this
                        {
                            printf("  Authenticated.\n");
                        }
                        else
                        {
                            printf("  NOT authentic.\n");
                        }
                    }
                }
                break;
            case GA_extensions:
                printf("GA_extensions\n");
                break;
            case GA_options:
                printf("GA_options\n");
                break;
            case GA_pinAuth:
                printf("GA_pinAuth\n");
                break;
            case GA_pinProtocol:
                printf("GA_pinProtocol\n");
                break;
            default:
                printf("invalid key %d\n", key);

        }
        if (ret != 0)
        {
            printf("error, parsing failed\n");
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

static void ctap_add_credential_descriptor(CborEncoder * map, CTAP_credentialDescriptor * cred)
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
}

void ctap_add_user_entity(CborEncoder * map, CTAP_userEntity * user)
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

}

void ctap_get_assertion(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_getAssertion GA;
    uint8_t auth_data_buf[32 + 1 + 4];
    uint8_t sigbuf[64];
    uint8_t sigder[72];

    int ret = ctap_parse_get_assertion(&GA,request,length);

    if (ret != 0)
    {
        printf("error, parse_get_assertion failed\n");
        return;
    }

    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 5);
    check_ret(ret);

    ctap_make_auth_data(&GA.rp, &map, auth_data_buf, sizeof(auth_data_buf), NULL, 0,0);

    int pick = pick_first_authentic_credential(&GA);    // TODO let this handle decryption? lazy?
    if (pick == -1)
    {
        printf("Error, no authentic credential\n");
        return;
    }

    ctap_add_credential_descriptor(&map, &GA.creds[pick]);

    ctap_add_user_entity(&map, &GA.creds[pick].credential.fields.user);

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

uint8_t ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    uint8_t cmd = *pkt_raw;
    pkt_raw++;


    static uint8_t buf[1024];
    memset(buf,0,sizeof(buf));

    resp->data = buf;
    resp->length = 0;

    CborEncoder encoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    _ENCODER = &encoder;

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
            ctap_get_assertion(&encoder, pkt_raw, length - 1);
            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            printf("cbor [%d]: \n",  cbor_encoder_get_buffer_size(&encoder, buf)); dump_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));
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

    printf("cbor input structure: %d bytes\n", length - 1);
    printf("cbor output structure: %d bytes\n", resp->length);
    return 0;
}
