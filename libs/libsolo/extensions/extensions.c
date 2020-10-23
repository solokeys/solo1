// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include <stdint.h>
#include "extensions.h"
#include "u2f.h"
#include "ctap.h"
#include "wallet.h"
#include "solo.h"
#include "device.h"

#include "log.h"

#define htonl(x)    (((x & 0xff) << 24) | ((x & 0xff00) << 8) \
                    | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24) )

int is_extension_request(uint8_t * kh, int len)
{
    wallet_request * req = (wallet_request *) kh;

    if (len < WALLET_MIN_LENGTH)
        return 0;

    return memcmp(req->tag, WALLET_TAG, sizeof(WALLET_TAG)-1) == 0;
}


int extension_needs_atomic_count(uint8_t klen, uint8_t * keyh)
{
    return ((wallet_request *) keyh)->operation == WalletRegister
            || ((wallet_request *) keyh)->operation == WalletSign;
}

static uint8_t * output_buffer_ptr;
uint8_t output_buffer_offset;
uint8_t output_buffer_size;

void extension_writeback_init(uint8_t * buffer, uint8_t size)
{
    output_buffer_ptr = buffer;
    output_buffer_offset = 0;
    output_buffer_size = size;
}

void extension_writeback(uint8_t * buf, uint8_t size)
{
    if ((output_buffer_offset + size) > output_buffer_size)
    {
        return;
    }
    memmove(output_buffer_ptr + output_buffer_offset, buf, size);
    output_buffer_offset += size;
}


int16_t bridge_u2f_to_extensions(uint8_t * _chal, uint8_t * _appid, uint8_t klen, uint8_t * keyh)
{
    int8_t ret = 0;
    uint32_t count;
    uint8_t up = 1;
    uint8_t sig[72];
    if (extension_needs_atomic_count(klen, keyh))
    {
        count = htonl(ctap_atomic_count(0));
    }
    else
    {
        count = htonl(10);
    }

    u2f_response_writeback(&up,1);
    u2f_response_writeback((uint8_t *)&count,4);
    u2f_response_writeback((uint8_t *)&ret,1);
#ifdef IS_BOOTLOADER
    ret = bootloader_bridge(klen, keyh);
#else
    ret = bridge_u2f_to_solo(sig, keyh, klen);
    u2f_response_writeback(sig,72);
#endif

    if (ret != 0)
    {
        u2f_reset_response();
        u2f_response_writeback(&up,1);
        u2f_response_writeback((uint8_t *)&count,4);

        memset(sig,0,sizeof(sig));
        sig[0] = ret;
        u2f_response_writeback(sig,72);
    }

    return U2F_SW_NO_ERROR;
}

// Returns 1 if this is a extension request.
// Else 0 if nothing is done.
int16_t extend_fido2(CredentialId * credid, uint8_t * output)
{
    if (is_extension_request((uint8_t*)credid, sizeof(CredentialId)))
    {
        printf1(TAG_EXT,"IS EXT REQ\r\n");
        output[0] = bridge_u2f_to_solo(output+1, (uint8_t*)credid, sizeof(CredentialId));
        return 1;
    }
    else
    {
        return 0;
    }
}

int16_t extend_u2f(APDU_HEADER * req, uint8_t * payload, uint32_t len)
{

    struct u2f_authenticate_request * auth = (struct u2f_authenticate_request *) payload;
    uint16_t rcode;

    if (req->ins == U2F_AUTHENTICATE)
    {
        if (req->p1 == U2F_AUTHENTICATE_CHECK)
        {

            if (is_extension_request((uint8_t *) &auth->kh, auth->khl))     // Pin requests
            {
                rcode =  U2F_SW_CONDITIONS_NOT_SATISFIED;
            }
            else
            {
                rcode =  U2F_SW_WRONG_DATA;
            }
            printf1(TAG_EXT,"Ignoring U2F check request\n");
            dump_hex1(TAG_EXT, (uint8_t *) &auth->kh, auth->khl);
            goto end;
        }
        else
        {
            if ( ! is_extension_request((uint8_t *) &auth->kh, auth->khl))     // Pin requests
            {
                rcode = U2F_SW_WRONG_DATA;
                printf1(TAG_EXT, "Ignoring U2F auth request\n");
                dump_hex1(TAG_EXT, (uint8_t *) &auth->kh, auth->khl);
                goto end;
            }
            rcode = bridge_u2f_to_extensions(auth->chal, auth->app, auth->khl, (uint8_t*)&auth->kh);
        }
    }
    else if (req->ins == U2F_VERSION)
    {
        printf1(TAG_EXT, "U2F_VERSION\n");
        if (len)
        {
            rcode = U2F_SW_WRONG_LENGTH;
        }
        else
        {
            rcode = u2f_version();
        }
    }
    else
    {
        rcode = U2F_SW_INS_NOT_SUPPORTED;
    }
end:
    return rcode;
}
