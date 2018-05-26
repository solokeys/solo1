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
#define CTAP_VENDOR_FIRST           0x40
#define CTAP_VENDOR_LAST            0xBF

#define CTAP_AAGUID                 ((uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")

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
#define CTAP_MAX_MESSAGE_SIZE       1024

#define CREDENTIAL_TAG_SIZE         16
#define CREDENTIAL_NONCE_SIZE       8
#define CREDENTIAL_COUNTER_SIZE     (4)
#define CREDENTIAL_ENC_SIZE         144  // pad to multiple of 16 bytes
#define CREDENTIAL_PAD_SIZE         (CREDENTIAL_ENC_SIZE - (USER_ID_MAX_SIZE + USER_NAME_LIMIT + CREDENTIAL_COUNTER_SIZE + 1))
#define CREDENTIAL_ID_SIZE          (CREDENTIAL_TAG_SIZE + CREDENTIAL_NONCE_SIZE + CREDENTIAL_ENC_SIZE)

#define PUB_KEY_CRED_PUB_KEY        0x01
#define PUB_KEY_CRED_UNKNOWN        0x3F

#define CREDENTIAL_IS_SUPPORTED     1
#define CREDENTIAL_NOT_SUPPORTED    0

#define ALLOW_LIST_MAX_SIZE         20

#define NEW_PIN_ENC_MAX_SIZE        256     // includes NULL terminator

#define CTAP_RESPONSE_BUFFER_SIZE   1024

typedef struct
{
    uint8_t id[USER_ID_MAX_SIZE];
    uint8_t id_size;
    uint8_t name[USER_NAME_LIMIT];
}__attribute__((packed)) CTAP_userEntity;

struct Credential {
    uint8_t tag[CREDENTIAL_TAG_SIZE];
    uint8_t nonce[CREDENTIAL_NONCE_SIZE];
    struct {
        CTAP_userEntity user;
        uint32_t count;
        uint8_t _pad[CREDENTIAL_PAD_SIZE];
    } __attribute__((packed)) enc;
};

typedef struct
{
    uint8_t aaguid[16];
    uint8_t credLenH;
    uint8_t credLenL;
    struct Credential credential;
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
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    struct rpId rp;
    CTAP_userEntity user;

    uint8_t publicKeyCredentialType;
    int32_t COSEAlgorithmIdentifier;

    CborValue excludeList;
    size_t excludeListSize;

    uint8_t rk;
    uint8_t uv;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    int pinProtocol;

} CTAP_makeCredential;

typedef struct
{
    uint8_t type;
    struct Credential credential;
} CTAP_credentialDescriptor;

typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];

    struct rpId rp;

    int credLen;

    uint8_t rk;
    uint8_t uv;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    int pinProtocol;

    CTAP_credentialDescriptor creds[ALLOW_LIST_MAX_SIZE];
} CTAP_getAssertion;

typedef struct
{
    int pinProtocol;
    int subCommand;
    struct
    {
        struct{
            uint8_t x[32];
            uint8_t y[32];
        } pubkey;

        int kty;
        int crv;
    } keyAgreement;
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


void ctap_response_init(CTAP_RESPONSE * resp);

uint8_t ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp);


// Run ctap related power-up procedures (init pinToken, generate shared secret)
void ctap_init();

void ctap_update_pin(uint8_t * pin, int len);
uint8_t ctap_decrement_pin_attempts();
int8_t ctap_leftover_pin_attempts();
void ctap_reset_pin_attempts();
uint8_t ctap_is_pin_set();
uint8_t ctap_pin_matches(uint8_t * pin, int len);
void ctap_reset();
int8_t ctap_device_locked();


// Test for user presence
// Return 1 for user is present, 0 user not present
extern int ctap_user_presence_test();

// Generate @num bytes of random numbers to @dest
// return 1 if success, error otherwise
extern int ctap_generate_rng(uint8_t * dst, size_t num);

// Increment atomic counter and return it.  
// Must support two counters, @sel selects counter0 or counter1.
uint32_t ctap_atomic_count(int sel);

// Verify the user
// return 1 if user is verified, 0 if not
extern int ctap_user_verification(uint8_t arg);

// Must be implemented by application
// data is HID_MESSAGE_SIZE long in bytes
extern void ctaphid_write_block(uint8_t * data);


#endif
