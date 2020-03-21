// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdlib.h>
#include "u2f.h"
#include "ctap.h"
#include "ctaphid.h"
#include "crypto.h"
#include "log.h"
#include "device.h"
#include "apdu.h"
#include "wallet.h"
#ifdef ENABLE_U2F_EXTENSIONS
#include "extensions.h"
#endif
#include APP_CONFIG

// void u2f_response_writeback(uint8_t * buf, uint8_t len);
#ifdef ENABLE_U2F
static int16_t u2f_register(struct u2f_register_request * req);
static int16_t u2f_authenticate(struct u2f_authenticate_request * req, uint8_t control);
#endif
int8_t u2f_response_writeback(const uint8_t * buf, uint16_t len);
void u2f_reset_response();

void make_auth_tag(uint8_t * rpIdHash, uint8_t * nonce, uint32_t count, uint8_t * tag);

static CTAP_RESPONSE * _u2f_resp = NULL;

void u2f_request_ex(APDU_HEADER *req, uint8_t *payload, uint32_t len, CTAP_RESPONSE * resp)
{
    uint16_t rcode = 0;
    uint8_t byte;

    ctap_response_init(resp);
    u2f_set_writeback_buffer(resp);

    if (req->cla != 0)
    {
        printf1(TAG_U2F, "CLA not zero\n");
        rcode = U2F_SW_CLASS_NOT_SUPPORTED;
        goto end;
    }
#ifdef ENABLE_U2F_EXTENSIONS
    rcode = extend_u2f(req, payload, len);
#endif
    if (rcode != U2F_SW_NO_ERROR && rcode != U2F_SW_CONDITIONS_NOT_SATISFIED)       // If the extension didn't do anything...
    {
#ifdef ENABLE_U2F
        switch(req->ins)
        {
            case U2F_REGISTER:
                printf1(TAG_U2F, "U2F_REGISTER\n");
                if (len != 64)
                {
                    rcode = U2F_SW_WRONG_LENGTH;
                }
                else
                {

                    timestamp();
                    rcode = u2f_register((struct u2f_register_request*)payload);
                    printf1(TAG_TIME,"u2f_register time: %d ms\n", timestamp());

                }
                break;
            case U2F_AUTHENTICATE:
                printf1(TAG_U2F, "U2F_AUTHENTICATE\n");
                timestamp();
                rcode = u2f_authenticate((struct u2f_authenticate_request*)payload, req->p1);
                printf1(TAG_TIME,"u2f_authenticate time: %d ms\n", timestamp());
                break;
            case U2F_VERSION:
                printf1(TAG_U2F, "U2F_VERSION\n");
                if (len)
                {
                    rcode = U2F_SW_WRONG_LENGTH;
                }
                else
                {
                    rcode = u2f_version();
                }
                break;
            case U2F_VENDOR_FIRST:
            case U2F_VENDOR_LAST:
                printf1(TAG_U2F, "U2F_VENDOR\n");
                rcode = U2F_SW_NO_ERROR;
                break;
            default:
                printf1(TAG_ERR, "Error, unknown U2F command\n");
                rcode = U2F_SW_INS_NOT_SUPPORTED;
                break;
        }
#endif
    }

    device_set_status(CTAPHID_STATUS_IDLE);

end:
    if (rcode != U2F_SW_NO_ERROR)
    {
        printf1(TAG_U2F,"U2F Error code %04x\n", rcode);
        ctap_response_init(_u2f_resp);
    }

    byte = (rcode & 0xff00)>>8;
    u2f_response_writeback(&byte,1);
    byte = rcode & 0xff;
    u2f_response_writeback(&byte,1);

    printf1(TAG_U2F,"u2f resp: "); dump_hex1(TAG_U2F, _u2f_resp->data, _u2f_resp->length);
}

void u2f_request_nfc(uint8_t * header, uint8_t * data, int datalen, CTAP_RESPONSE * resp)
{
	if (!header)
		return;

    device_disable_up(true);  // disable presence test
	u2f_request_ex((APDU_HEADER *)header, data, datalen, resp);
    device_disable_up(false); // enable presence test
}

void u2f_request(struct u2f_request_apdu* req, CTAP_RESPONSE * resp)
{
    uint32_t len = ((req->LC3) | ((uint32_t)req->LC2 << 8) | ((uint32_t)req->LC1 << 16));

	u2f_request_ex((APDU_HEADER *)req, req->payload, len, resp);
}

int8_t u2f_response_writeback(const uint8_t * buf, uint16_t len)
{
    if ((_u2f_resp->length + len) > _u2f_resp->data_size)
    {
        printf2(TAG_ERR, "Not enough space for U2F response, writeback\n");
        exit(1);
    }
    memmove(_u2f_resp->data + _u2f_resp->length, buf, len);
    _u2f_resp->length += len;
    return 0;
}

void u2f_reset_response()
{
    ctap_response_init(_u2f_resp);
}

void u2f_set_writeback_buffer(CTAP_RESPONSE * resp)
{
    _u2f_resp = resp;
}

#ifdef ENABLE_U2F
static void dump_signature_der(uint8_t * sig)
{
    uint8_t sigder[72];
    int len;
    len = ctap_encode_der_sig(sig, sigder);
    u2f_response_writeback(sigder, len);
}
static int8_t u2f_load_key(struct u2f_key_handle * kh, uint8_t khl, uint8_t * appid)
{
    crypto_ecc256_load_key((uint8_t*)kh, khl, NULL, 0);
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

int8_t u2f_new_keypair(struct u2f_key_handle * kh, uint8_t * appid, uint8_t * pubkey)
{
    ctap_generate_rng(kh->key, U2F_KEY_HANDLE_KEY_SIZE);
    u2f_make_auth_tag(kh, appid, kh->tag);

    crypto_ecc256_derive_public_key((uint8_t*)kh, U2F_KEY_HANDLE_SIZE, pubkey, pubkey+32);
    return 0;
}


// Return 1 if authenticate, 0 if not.
int8_t u2f_authenticate_credential(struct u2f_key_handle * kh, uint8_t key_handle_len, uint8_t * appid)
{
    printf1(TAG_U2F, "checked CRED SIZE %d. (FIDO2: %d)\n", key_handle_len, sizeof(CredentialId));
    uint8_t tag[U2F_KEY_HANDLE_TAG_SIZE];

    if (key_handle_len == sizeof(CredentialId))
    {
        printf1(TAG_U2F, "FIDO2 key handle detected.\n");
        CredentialId * cred = (CredentialId *) kh;
        // FIDO2 credential.

        if (memcmp(cred->rpIdHash, appid, 32) != 0)
        {
            printf1(TAG_U2F, "APPID does not match rpIdHash.\n");
            return 0;
        }
        make_auth_tag(appid, (uint8_t*)&cred->entropy, cred->count, tag);

        if (memcmp(cred->tag, tag, CREDENTIAL_TAG_SIZE) == 0){
            return 1;
        }

    }else if (key_handle_len == U2F_KEY_HANDLE_SIZE)
    {
        u2f_make_auth_tag(kh, appid, tag);
        if (memcmp(kh->tag, tag, U2F_KEY_HANDLE_TAG_SIZE) == 0)
        {
            return 1;
        }
    }

    printf1(TAG_U2F, "key handle + appid not authentic\n");
    printf1(TAG_U2F, "calc tag: \n"); dump_hex1(TAG_U2F,tag, U2F_KEY_HANDLE_TAG_SIZE);
    printf1(TAG_U2F, "inp  tag: \n"); dump_hex1(TAG_U2F,kh->tag, U2F_KEY_HANDLE_TAG_SIZE);
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
        printf1(TAG_U2F, "CHECK-ONLY\r\n");
        if (u2f_authenticate_credential(&req->kh, req->khl, req->app))
        {
            return U2F_SW_CONDITIONS_NOT_SATISFIED;
        }
        else
        {
            return U2F_SW_WRONG_DATA;
        }
    }
    if (
            (control != U2F_AUTHENTICATE_SIGN && control != U2F_AUTHENTICATE_SIGN_NO_USER) ||
            (!u2f_authenticate_credential(&req->kh, req->khl, req->app)) ||     // Order of checks is important
            u2f_load_key(&req->kh, req->khl, req->app) != 0

        )
    {
        return U2F_SW_WRONG_DATA;
    }

	// dont-enforce-user-presence-and-sign
	if (control == U2F_AUTHENTICATE_SIGN_NO_USER)
		up = 0;

	if(up)
	{
		if (ctap_user_presence_test(750) == 0)
		{
			return U2F_SW_CONDITIONS_NOT_SATISFIED;
		}
	}

    count = ctap_atomic_count(0);
    hash[0] = (count >> 24) & 0xff;
    hash[1] = (count >> 16) & 0xff;
    hash[2] = (count >> 8) & 0xff;
    hash[3] = (count >> 0) & 0xff;
    crypto_sha256_init();

    crypto_sha256_update(req->app, 32);
    crypto_sha256_update(&up, 1);
    crypto_sha256_update(hash, 4);
    crypto_sha256_update(req->chal, 32);

    crypto_sha256_final(hash);

    printf1(TAG_U2F, "sha256: "); dump_hex1(TAG_U2F, hash, 32);
    crypto_ecc256_sign(hash, 32, sig);

    u2f_response_writeback(&up,1);
    hash[0] = (count >> 24) & 0xff;
    hash[1] = (count >> 16) & 0xff;
    hash[2] = (count >> 8) & 0xff;
    hash[3] = (count >> 0) & 0xff;
    u2f_response_writeback(hash,4);
    dump_signature_der(sig);

    return U2F_SW_NO_ERROR;
}

static int16_t u2f_register(struct u2f_register_request * req)
{
    uint8_t i[] = {0x0,U2F_EC_FMT_UNCOMPRESSED};
    uint8_t cert[1024];
    struct u2f_key_handle key_handle;
    uint8_t pubkey[64];
    uint8_t hash[32];
    uint8_t * sig = (uint8_t*)req;


    const uint16_t attest_size = device_attestation_cert_der_get_size();

    if (attest_size > sizeof(cert)){
        printf2(TAG_ERR,"Certificate is too large for buffer\r\n");
        return U2F_SW_INSUFFICIENT_MEMORY;
    }

	if ( ! ctap_user_presence_test(750))
	{
		return U2F_SW_CONDITIONS_NOT_SATISFIED;
	}

    if ( u2f_new_keypair(&key_handle, req->app, pubkey) == -1)
    {
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

    printf1(TAG_U2F, "sha256: "); dump_hex1(TAG_U2F,hash,32);
    crypto_ecc256_sign(hash, 32, sig);

    i[0] = 0x5;
    u2f_response_writeback(i,2);
    u2f_response_writeback(pubkey,64);
    i[0] = U2F_KEY_HANDLE_SIZE;
    u2f_response_writeback(i,1);
    u2f_response_writeback((uint8_t*)&key_handle,U2F_KEY_HANDLE_SIZE);

    device_attestation_read_cert_der(cert);
    u2f_response_writeback(cert,attest_size);

    dump_signature_der(sig);


    return U2F_SW_NO_ERROR;
}
#endif

int16_t u2f_version()
{
    const char version[] = "U2F_V2";
    u2f_response_writeback((uint8_t*)version, sizeof(version)-1);
    return U2F_SW_NO_ERROR;
}
