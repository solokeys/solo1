#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "aes.h"
#include "crypto.h"
#include "util.h"

#define BLOCK_SIZE 16

static struct AES_ctx aes_ctx;

// void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);

int8_t crypto_aes256_gcm_encrypt(uint8_t * data, uint32_t length, uint8_t * authtag)
{
    memset(authtag, 0, BLOCK_SIZE);
    AES_CTR_xcrypt_buffer(&aes_ctx, authtag, BLOCK_SIZE);

    return 0;
}

#ifdef TEST

int main(int argc, char * argv[])
{
    uint8_t nonce[16];
    uint8_t key[32];
    uint8_t authtag[BLOCK_SIZE];

    // uint8_t * authtag1 = (uint8_t *)"\x53\x0f\x8a\xfb\xc7\x45\x36\xb9\xa9\x63\xb4\xf1\xc4\xcb\x73\x8b";

    memset(nonce,0,16);
    memset(key,0,16);

    AES_init_ctx_iv(&aes_ctx, key, nonce);

    crypto_aes256_gcm_encrypt(NULL, 0, authtag);

    printf("Auth tag: "); dump_hex(authtag, BLOCK_SIZE);


    return 0;
}

#endif
