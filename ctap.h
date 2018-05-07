#ifndef _CTAP_H
#define _CTAP_H

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
#define CP_keyAgreement           0x03
#define CP_pinAuth                0x04
#define CP_newPinEnc              0x05
#define CP_pinHashEnc             0x06
#define CP_getKeyAgreement        0x07
#define CP_getRetries             0x08

#define RESP_fmt                    0x01
#define RESP_authData               0x02
#define RESP_attStmt                0x03



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

#define CREDENTIAL_ID_SIZE          48

#define PUB_KEY_CRED_PUB_KEY        0x01
#define PUB_KEY_CRED_UNKNOWN        0x3F

#define CREDENTIAL_IS_SUPPORTED     1
#define CREDENTIAL_NOT_SUPPORTED    0


typedef struct
{
    uint8_t aaguid[16];
    uint8_t credLenL;
    uint8_t credLenH;
    uint8_t credentialId[CREDENTIAL_ID_SIZE];
} __attribute__((packed)) CTAP_attestHeader;


typedef struct
{
    uint8_t rpIdHash[32];
    uint8_t flags;
    uint32_t signCount;
    CTAP_attestHeader attest;
} __attribute__((packed)) CTAP_authData;



typedef struct
{
    uint8_t * data;
    uint16_t length;
} CTAP_RESPONSE;

typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];

    uint8_t rpId[DOMAIN_NAME_MAX_SIZE + 1];     // extra for NULL termination
    size_t rpIdSize;
    uint8_t rpName[RP_NAME_LIMIT];

    uint8_t userId[USER_ID_MAX_SIZE];
    uint8_t userIdSize;
    uint8_t userName[USER_NAME_LIMIT];

    uint8_t publicKeyCredentialType;
    int32_t COSEAlgorithmIdentifier;

    uint8_t pinProtocol;
} CTAP_makeCredential;

uint8_t ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp);

// Test for user presence
// Return 1 for user is present, 0 user not present
extern int ctap_user_presence_test();

// Generate @num bytes of random numbers to @dest
extern int ctap_generate_rng(uint8_t * dst, size_t num);

// Increment atomic counter and return it
extern uint32_t ctap_atomic_count();

// Verify the user
// return 1 if user is verified, 0 if not
extern int ctap_user_verification(uint8_t arg);

// Must be implemented by application
// data is HID_MESSAGE_SIZE long in bytes
extern void ctap_write_block(uint8_t * data);

// Buffer data and send in HID_MESSAGE_SIZE chunks
// if len == 0, FLUSH
// if len == -1, RESET
extern void ctap_write(void * _data, int len);

#endif
