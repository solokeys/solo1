// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _CTAP_H
#define _CTAP_H

#include "cbor.h"

#define CTAP_MAKE_CREDENTIAL        0x01
#define CTAP_GET_ASSERTION          0x02
#define CTAP_CANCEL                 0x03
#define CTAP_GET_INFO               0x04
#define CTAP_CLIENT_PIN             0x06
#define CTAP_RESET                  0x07
#define GET_NEXT_ASSERTION          0x08
#define CTAP_CBOR_CRED_MGMT         0x0A
#define CTAP_VENDOR_FIRST           0x40
#define CTAP_CBOR_CRED_MGMT_PRE     0x41
#define CTAP_VENDOR_LAST            0xBF

#define MC_clientDataHash         0x01
#define MC_rp                     0x02
#define MC_user                   0x03
#define MC_pubKeyCredParams       0x04
#define MC_excludeList            0x05
#define MC_extensions             0x06
#define MC_options                0x07
#define MC_pinAuth                0x08
#define MC_pinProtocol            0x09

#define GA_rpId                   0x01
#define GA_clientDataHash         0x02
#define GA_allowList              0x03
#define GA_extensions             0x04
#define GA_options                0x05
#define GA_pinAuth                0x06
#define GA_pinProtocol            0x07

#define CM_cmd                    0x01
    #define CM_cmdMetadata        0x01
    #define CM_cmdRPBegin         0x02
    #define CM_cmdRPNext          0x03
    #define CM_cmdRKBegin         0x04
    #define CM_cmdRKNext          0x05
    #define CM_cmdRKDelete        0x06
#define CM_subCommandParams       0x02
    #define CM_subCommandRpId     0x01
    #define CM_subCommandCred     0x02
#define CM_pinProtocol            0x03
#define CM_pinAuth                0x04

#define CP_pinProtocol            0x01
#define CP_subCommand             0x02
    #define CP_cmdGetRetries      0x01
    #define CP_cmdGetKeyAgreement 0x02
    #define CP_cmdSetPin          0x03
    #define CP_cmdChangePin       0x04
    #define CP_cmdGetPinToken     0x05
#define CP_keyAgreement           0x03
#define CP_pinAuth                0x04
#define CP_newPinEnc              0x05
#define CP_pinHashEnc             0x06
#define CP_getKeyAgreement        0x07
#define CP_getRetries             0x08

#define EXT_HMAC_SECRET_COSE_KEY    0x01
#define EXT_HMAC_SECRET_SALT_ENC    0x02
#define EXT_HMAC_SECRET_SALT_AUTH   0x03

#define EXT_HMAC_SECRET_REQUESTED   0x01
#define EXT_HMAC_SECRET_PARSED      0x02

#define EXT_CRED_PROTECT_INVALID                0x00
#define EXT_CRED_PROTECT_OPTIONAL               0x01
#define EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID   0x02
#define EXT_CRED_PROTECT_REQUIRED               0x03

#define CREDID_ALG_ES256            0x0
#define CREDID_ALG_EDDSA            0x1

#define RESP_versions               0x1
#define RESP_extensions             0x2
#define RESP_aaguid                 0x3
#define RESP_options                0x4
#define RESP_maxMsgSize             0x5
#define RESP_pinProtocols           0x6

#define RESP_fmt                    0x01
#define RESP_authData               0x02
#define RESP_attStmt                0x03

#define RESP_credential             0x01
#define RESP_signature              0x03
#define RESP_publicKeyCredentialUserEntity 0x04
#define RESP_numberOfCredentials    0x05

#define RESP_keyAgreement           0x01
#define RESP_pinToken               0x02
#define RESP_retries                0x03

#define PARAM_clientDataHash        (1 << 0)
#define PARAM_rp                    (1 << 1)
#define PARAM_user                  (1 << 2)
#define PARAM_pubKeyCredParams      (1 << 3)
#define PARAM_excludeList           (1 << 4)
#define PARAM_extensions            (1 << 5)
#define PARAM_options               (1 << 6)
#define PARAM_pinAuth               (1 << 7)
#define PARAM_pinProtocol           (1 << 8)
#define PARAM_rpId                  (1 << 9)
#define PARAM_allowList             (1 << 10)

#define MC_requiredMask             (0x0f)


#define CLIENT_DATA_HASH_SIZE       32  //sha256 hash
#define DOMAIN_NAME_MAX_SIZE        253
#define RP_NAME_LIMIT               32  // application limit, name parameter isn't needed.
#define USER_ID_MAX_SIZE            64
#define USER_NAME_LIMIT             65  // Must be minimum of 64 bytes but can be more.
#define DISPLAY_NAME_LIMIT          32  // Must be minimum of 64 bytes but can be more.
#define ICON_LIMIT                  128 // Must be minimum of 64 bytes but can be more.
#define CTAP_MAX_MESSAGE_SIZE       1200

#define CREDENTIAL_RK_FLASH_PAD     2   // size of RK should be 8-byte aligned to store in flash easily.
#define CREDENTIAL_TAG_SIZE         16
#define CREDENTIAL_NONCE_SIZE       (16 + CREDENTIAL_RK_FLASH_PAD)
#define CREDENTIAL_COUNTER_SIZE     (4)
#define CREDENTIAL_ENC_SIZE         176  // pad to multiple of 16 bytes

#define PUB_KEY_CRED_PUB_KEY        0x01
#define PUB_KEY_CRED_CTAP1          0x41
#define PUB_KEY_CRED_CUSTOM         0x42
#define PUB_KEY_CRED_UNKNOWN        0x3F

#define CREDENTIAL_IS_SUPPORTED     1
#define CREDENTIAL_NOT_SUPPORTED    0

#define ALLOW_LIST_MAX_SIZE         20

#define NEW_PIN_ENC_MAX_SIZE        256     // includes NULL terminator
#define NEW_PIN_ENC_MIN_SIZE        64
#define NEW_PIN_MAX_SIZE            64
#define NEW_PIN_MIN_SIZE            4

#define CTAP_RESPONSE_BUFFER_SIZE   4096

#define PIN_LOCKOUT_ATTEMPTS        8       // Number of attempts total
#define PIN_BOOT_ATTEMPTS           3       // number of attempts per boot

#define CTAP2_UP_DELAY_MS           29000

typedef struct
{
    uint8_t id[USER_ID_MAX_SIZE];
    uint8_t id_size;
    uint8_t name[USER_NAME_LIMIT];
    uint8_t displayName[DISPLAY_NAME_LIMIT];
    uint8_t icon[ICON_LIMIT];
}__attribute__((packed)) CTAP_userEntity;

typedef struct {
    uint8_t tag[CREDENTIAL_TAG_SIZE];
    union {
        uint8_t nonce[CREDENTIAL_NONCE_SIZE];
        struct {
            uint8_t _pad[CREDENTIAL_NONCE_SIZE - 4];
            uint32_t value;
        }__attribute__((packed)) metadata;
    }__attribute__((packed)) entropy;
    uint8_t rpIdHash[32];
    uint32_t count;
}__attribute__((packed)) CredentialId;

struct  __attribute__((packed)) Credential {
    CredentialId id;
    CTAP_userEntity user;
};
typedef struct {
    CredentialId id;
    CTAP_userEntity user;

    // Maximum amount of "extra" space in resident key.
    uint8_t rpId[48];
    uint8_t rpIdSize;
} __attribute__((packed)) CTAP_residentKey;

typedef struct
{
    uint8_t type;
    struct Credential credential;
} CTAP_credentialDescriptor;

typedef struct
{
    uint8_t aaguid[16];
    uint8_t credLenH;
    uint8_t credLenL;
    CredentialId id;
} __attribute__((packed)) CTAP_attestHeader;

typedef struct
{
    uint8_t rpIdHash[32];
    uint8_t flags;
    uint32_t signCount;
} __attribute__((packed)) CTAP_authDataHeader;

typedef struct
{
    CTAP_authDataHeader head;
    CTAP_attestHeader attest;
} __attribute__((packed)) CTAP_authData;

typedef struct
{
    uint8_t data[CTAP_RESPONSE_BUFFER_SIZE];
    uint16_t data_size;
    uint16_t length;
} CTAP_RESPONSE;

struct rpId
{
    uint8_t id[DOMAIN_NAME_MAX_SIZE + 1];     // extra for NULL termination
    size_t size;
    uint8_t name[RP_NAME_LIMIT];
};

typedef struct
{
    struct{
        uint8_t x[32];
        uint8_t y[32];
    } pubkey;

    int kty;
    int crv;
} COSE_key;

typedef struct
{
    uint8_t saltLen;
    uint8_t saltEnc[64];
    uint8_t saltAuth[32];
    COSE_key keyAgreement;
    struct Credential * credential;
} CTAP_hmac_secret;

typedef struct
{
    uint8_t hmac_secret_present;
    CTAP_hmac_secret hmac_secret;
    uint32_t cred_protect;
} CTAP_extensions;

typedef struct
{
    CTAP_userEntity user;
    uint8_t publicKeyCredentialType;
    int32_t COSEAlgorithmIdentifier;
    uint8_t rk;
} CTAP_credInfo;

typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    struct rpId rp;

    CTAP_credInfo credInfo;

    CborValue excludeList;
    size_t excludeListSize;

    uint8_t uv;
    uint8_t up;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    // pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
    // This is exclusive with |pinAuthPresent|. It exists because an empty
    // pinAuth is a special signal to block for touch. See
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
    uint8_t pinAuthEmpty;
    int pinProtocol;
    CTAP_extensions extensions;

} CTAP_makeCredential;



typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    uint8_t clientDataHashPresent;

    struct rpId rp;

    int credLen;

    uint8_t rk;
    uint8_t uv;
    uint8_t up;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    // pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
    // This is exclusive with |pinAuthPresent|. It exists because an empty
    // pinAuth is a special signal to block for touch. See
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorGetAssertion
    uint8_t pinAuthEmpty;
    int pinProtocol;

    CTAP_credentialDescriptor * creds;
    uint8_t allowListPresent;

    CTAP_extensions extensions;

} CTAP_getAssertion;

typedef struct
{
    int cmd;
    struct {
        uint8_t rpIdHash[32];
        CTAP_credentialDescriptor credentialDescriptor;
    } subCommandParams;

    struct {
        uint8_t cmd;
        uint8_t subCommandParamsCborCopy[sizeof(CTAP_credentialDescriptor) + 16];
    } hashed;
    uint32_t subCommandParamsCborSize;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    int pinProtocol;
} CTAP_credMgmt;


typedef struct
{
    int pinProtocol;
    int subCommand;
    COSE_key keyAgreement;
    uint8_t keyAgreementPresent;
    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    uint8_t newPinEnc[NEW_PIN_ENC_MAX_SIZE];
    int newPinEncSize;
    uint8_t pinHashEnc[16];
    uint8_t pinHashEncPresent;
    _Bool getKeyAgreement;
    _Bool getRetries;
} CTAP_clientPin;


struct _getAssertionState {
    // Room for both authData struct and extensions
    struct {
        CTAP_authDataHeader authData;
        uint8_t extensions[80];
    } __attribute__((packed)) buf;
    CTAP_extensions extensions;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    CTAP_credentialDescriptor creds[ALLOW_LIST_MAX_SIZE];
    uint8_t lastcmd;
    uint32_t count;
    uint32_t index;
    uint32_t time;
    uint8_t user_verified;
    uint8_t customCredId[256];
    uint8_t customCredIdSize;
};

void ctap_response_init(CTAP_RESPONSE * resp);

uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp);

// Encodes R,S signature to 2 der sequence of two integers.  Sigder must be at least 72 bytes.
// @return length of der signature
int ctap_encode_der_sig(uint8_t const * const in_sigbuf, uint8_t * const out_sigder);

// Run ctap related power-up procedures (init pinToken, generate shared secret)
void ctap_init();

// Resets state between different accesses of different applications
void ctap_reset_state();

uint8_t ctap_add_pin_if_verified(uint8_t * pinTokenEnc, uint8_t * platform_pubkey, uint8_t * pinHashEnc);
uint8_t ctap_update_pin_if_verified(uint8_t * pinEnc, int len, uint8_t * platform_pubkey, uint8_t * pinAuth, uint8_t * pinHashEnc);

void ctap_update_pin(uint8_t * pin, int len);
uint8_t ctap_decrement_pin_attempts();
int8_t ctap_leftover_pin_attempts();
void ctap_reset_pin_attempts();
uint8_t ctap_is_pin_set();
uint8_t ctap_pin_matches(uint8_t * pin, int len);
void ctap_reset();
int8_t ctap_device_locked();
int8_t ctap_device_boot_locked();

// Key storage API

// Return length of key at index.  0 if not exist.
uint16_t ctap_key_len(uint8_t index);

// See error codes in storage.h
int8_t ctap_store_key(uint8_t index, uint8_t * key, uint16_t len);
int8_t ctap_load_key(uint8_t index, uint8_t * key);
uint16_t ctap_key_len(uint8_t index);

#define PIN_TOKEN_SIZE      16
extern uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
extern uint8_t KEY_AGREEMENT_PUB[64];

void lock_device_permanently();

void ctap_load_external_keys(uint8_t * keybytes);

#endif
