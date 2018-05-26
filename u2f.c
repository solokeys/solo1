#include "u2f.h"
#include "ctap.h"
#include "crypto.h"

// void u2f_response_writeback(uint8_t * buf, uint8_t len);
static int16_t u2f_register(struct u2f_register_request * req);
static int16_t u2f_version();
static int16_t u2f_authenticate(struct u2f_authenticate_request * req, uint8_t control);

void u2f_request(struct u2f_request_apdu * req)
{
    uint16_t * rcode = (uint16_t *)req;
    uint32_t len = ((req->LC3) | ((uint32_t)req->LC2 << 8) | ((uint32_t)req->LC1 << 16));

    if (req->cla != 0)
    {
        u2f_response_set_length(2);
        *rcode = U2F_SW_CLASS_NOT_SUPPORTED;
        goto end;
    }

    switch(req->ins)
    {
        case U2F_REGISTER:
            if (len != 64)
            {
                u2f_response_set_length(2);
                *rcode = U2F_SW_WRONG_LENGTH;
            }
            else
            {
                *rcode = u2f_register((struct u2f_register_request*)req->payload);
            }
            break;
        case U2F_AUTHENTICATE:
            *rcode = u2f_authenticate((struct u2f_authenticate_request*)req->payload, req->p1);
            break;
        case U2F_VERSION:
            if (len)
            {
                u2f_response_set_length(2);
                *rcode = U2F_SW_WRONG_LENGTH;
            }
            else
            {
                *rcode = u2f_version();
            }
            break;
        case U2F_VENDOR_FIRST:
        case U2F_VENDOR_LAST:
            *rcode = U2F_SW_NO_ERROR;
            break;
        default:
            u2f_response_set_length(2);
            *rcode = U2F_SW_INS_NOT_SUPPORTED;
            break;
    }

end:
    u2f_response_writeback((uint8_t*)rcode,2);
    u2f_response_flush();
}


void u2f_response_writeback(const uint8_t * buf, uint16_t len)
{

}

// Set total length of U2F response.  Must be done before any writebacks
extern void u2f_response_set_length(uint16_t len)
{

}

// u2f_response_flush callback when u2f finishes and will
// indicate when all buffer data, if any, should be written
extern void u2f_response_flush()
{

}



static uint8_t get_signature_length(uint8_t * sig)
{
    return 0x46 + ((sig[32] & 0x80) == 0x80) + ((sig[0] & 0x80) == 0x80);
}

static void dump_signature_der(uint8_t * sig)
{
    uint8_t pad_s = (sig[32] & 0x80) == 0x80;
    uint8_t pad_r = (sig[0] & 0x80) == 0x80;
    uint8_t i[] = {0x30, 0x44};
    i[1] += (pad_s + pad_r);


    // DER encoded signature
    // write der sequence
    // has to be minimum distance and padded with 0x00 if MSB is a 1.
    u2f_response_writeback(i,2);
    i[1] = 0;

    // length of R value plus 0x00 pad if necessary
    u2f_response_writeback("\x02",1);
    i[0] = 0x20 + pad_r;
    u2f_response_writeback(i,1 + pad_r);

    // R value
    u2f_response_writeback(sig, 32);

    // length of S value plus 0x00 pad if necessary
    u2f_response_writeback("\x02",1);
    i[0] = 0x20 + pad_s;
    u2f_response_writeback(i,1 + pad_s);

    // S value
    u2f_response_writeback(sig+32, 32);
}
static int8_t u2f_load_key(struct u2f_key_handle * kh, uint8_t * appid)
{
    crypto_ecc256_load_key((uint8_t*)kh, U2F_KEY_HANDLE_SIZE, appid, U2F_APPLICATION_SIZE);
    return 0;
}

static void u2f_make_auth_tag(struct u2f_key_handle * kh, uint8_t * appid, uint8_t * tag)
{
    uint8_t hashbuf[32];
    crypto_sha256_hmac_init(CRYPTO_MASTER_KEY, 0, hashbuf);
    crypto_sha256_update(kh->key, U2F_KEY_HANDLE_KEY_SIZE);
    crypto_sha256_update(appid, U2F_APPLICATION_SIZE);
    crypto_sha256_hmac_final(CRYPTO_MASTER_KEY, 0,hashbuf);
    memmove(tag, hashbuf, CREDENTIAL_TAG_SIZE);
}


static int8_t u2f_appid_eq(struct u2f_key_handle * kh, uint8_t * appid)
{
    uint8_t tag[U2F_KEY_HANDLE_TAG_SIZE];
    u2f_make_auth_tag(kh, appid, kh->tag);
    if (memcmp(kh->tag, tag, U2F_KEY_HANDLE_TAG_SIZE) == 0)
        return 0;
    else
        return -1;
}



static int8_t u2f_new_keypair(struct u2f_key_handle * kh, uint8_t * appid, uint8_t * pubkey)
{
    ctap_generate_rng(kh->key, U2F_KEY_HANDLE_KEY_SIZE);
    u2f_make_auth_tag(kh, appid, kh->tag);
    crypto_ecc256_derive_public_key((uint8_t*)kh, U2F_KEY_HANDLE_SIZE, pubkey, pubkey+32);
    return 0;
}


static int16_t u2f_authenticate(struct u2f_authenticate_request * req, uint8_t control)
{

    uint8_t up = 1;
    uint32_t count;
    uint8_t hash[32];
    uint8_t * sig = (uint8_t*)req;

    if (control == U2F_AUTHENTICATE_CHECK)
    {
        u2f_response_set_length(2);
        if (u2f_appid_eq(&req->kh, req->app) == 0)
        {
            return U2F_SW_CONDITIONS_NOT_SATISFIED;
        }
        else
        {
            return U2F_SW_WRONG_DATA;
        }
    }
    if (
            control != U2F_AUTHENTICATE_SIGN ||
            req->khl != U2F_KEY_HANDLE_SIZE  ||
            u2f_appid_eq(&req->kh, req->app) != 0 ||     // Order of checks is important
            u2f_load_key(&req->kh, req->app) != 0

        )
    {
        u2f_response_set_length(2);
        return U2F_SW_WRONG_PAYLOAD;
    }



    if (ctap_user_presence_test())
    {
        u2f_response_set_length(2);
        return U2F_SW_CONDITIONS_NOT_SATISFIED;
    }

    count = ctap_atomic_count(0);

    crypto_sha256_init();

    crypto_sha256_update(req->app,32);
    crypto_sha256_update(&up,1);
    crypto_sha256_update((uint8_t *)&count,4);
    crypto_sha256_update(req->chal,32);

    crypto_sha256_final(hash);

    crypto_ecc256_sign(hash, 32, sig);


    u2f_response_set_length(7 + get_signature_length(sig));

    u2f_response_writeback(&up,1);
    u2f_response_writeback((uint8_t *)&count,4);
    dump_signature_der(sig);

    return U2F_SW_NO_ERROR;
}

static int16_t u2f_register(struct u2f_register_request * req)
{
    uint8_t i[] = {0x0,U2F_EC_FMT_UNCOMPRESSED};

    struct u2f_key_handle key_handle;
    uint8_t pubkey[64];
    uint8_t hash[32];
    uint8_t * sig = (uint8_t*)req;


    const uint16_t attest_size = attestation_cert_der_size;

    if (ctap_user_presence_test())
    {
        u2f_response_set_length(2);
        return U2F_SW_CONDITIONS_NOT_SATISFIED;
    }

    if ( u2f_new_keypair(&key_handle, req->app, pubkey) == -1)
    {
        u2f_response_set_length(2);
        return U2F_SW_INSUFFICIENT_MEMORY;
    }

    crypto_sha256_init();
    crypto_sha256_update(i,1);
    crypto_sha256_update(req->app,32);

    crypto_sha256_update(req->chal,32);

    crypto_sha256_update((uint8_t*)&key_handle,U2F_KEY_HANDLE_SIZE);
    crypto_sha256_update(i+1,1);
    crypto_sha256_update(pubkey,64);
    crypto_sha256_final(hash);

    crypto_ecc256_load_attestation_key();
    crypto_ecc256_sign(hash, 32, sig);

    u2f_response_set_length(69 + get_signature_length((uint8_t*)req) + U2F_KEY_HANDLE_SIZE + attest_size);
    i[0] = 0x5;
    u2f_response_writeback(i,2);
    u2f_response_writeback(pubkey,64);
    i[0] = U2F_KEY_HANDLE_SIZE;
    u2f_response_writeback(i,1);
    u2f_response_writeback((uint8_t*)&key_handle,U2F_KEY_HANDLE_SIZE);

    u2f_response_writeback(attestation_cert_der,attest_size);

    dump_signature_der((uint8_t*)req);


    return U2F_SW_NO_ERROR;
}

static int16_t u2f_version()
{
    const char version[] = "U2F_V2";
    u2f_response_set_length(2 + sizeof(version)-1);
    u2f_response_writeback(version, sizeof(version)-1);
    return U2F_SW_NO_ERROR;
}
