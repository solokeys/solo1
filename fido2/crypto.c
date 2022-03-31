// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*
 *  Wrapper for crypto implementation on device.
 *
 *  Can be replaced with different crypto implementation by
 *  defining EXTERNAL_SOLO_CRYPTO
 *
 * */
#ifndef EXTERNAL_SOLO_CRYPTO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "crypto.h"

#include "sha256.h"
#include "uECC.h"
#include "aes.h"
#include "ctap.h"
#include "device.h"
// stuff for SHA512
#include "sha2.h"
#include "blockwise.h"
#include APP_CONFIG
#include "log.h"

#if defined(STM32L432xx)
#include "salty.h"
#else
#include <sodium/crypto_sign_ed25519.h>
#endif

typedef enum
{
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    MBEDTLS_ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    MBEDTLS_ECP_DP_CURVE25519,           /*!< Curve25519               */
    MBEDTLS_ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
} mbedtls_ecp_group_id;


static SHA256_CTX sha256_ctx;
static cf_sha512_context sha512_ctx;
static const struct uECC_Curve_t * _es256_curve = NULL;
static const uint8_t * _signing_key = NULL;
static int _key_len = 0;

// Secrets for testing only
static uint8_t master_secret[64];
static uint8_t transport_secret[32];


void crypto_sha256_init(void)
{
    sha256_init(&sha256_ctx);
}

void crypto_sha512_init(void)
{
    cf_sha512_init(&sha512_ctx);
}

void crypto_load_master_secret(uint8_t * key)
{
#if KEY_SPACE_BYTES < 96
#error "need more key bytes"
#endif
    memmove(master_secret, key, 64);
    memmove(transport_secret, key+64, 32);
}

void crypto_reset_master_secret(void)
{
    memset(master_secret, 0, 64);
    memset(transport_secret, 0, 32);
    ctap_generate_rng(master_secret, 64);
    ctap_generate_rng(transport_secret, 32);
}


void crypto_sha256_update(uint8_t * data, size_t len)
{
    sha256_update(&sha256_ctx, data, len);
}

void crypto_sha512_update(const uint8_t * data, size_t len) {
    cf_sha512_update(&sha512_ctx, data, len);
}

void crypto_sha256_update_secret()
{
    sha256_update(&sha256_ctx, master_secret, 32);
}

void crypto_sha256_final(uint8_t * hash)
{
    sha256_final(&sha256_ctx, hash);
}

void crypto_sha512_final(uint8_t * hash)
{
    // NB: there is also cf_sha512_digest
    cf_sha512_digest_final(&sha512_ctx, hash);
}

void crypto_sha256_hmac_init(uint8_t * key, uint32_t klen, uint8_t * hmac)
{
    uint8_t buf[64];
    unsigned int i;
    memset(buf, 0, sizeof(buf));

    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret)/2;
    }
    else if (key == CRYPTO_TRANSPORT_KEY)
    {
        key = transport_secret;
        klen = 32;
    }

    if(klen > 64)
    {
        printf2(TAG_ERR, "Error, key size must be <= 64\n");
        exit(1);
    }

    memmove(buf, key, klen);

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = buf[i] ^ 0x36;
    }

    crypto_sha256_init();
    crypto_sha256_update(buf, 64);
}

void crypto_sha256_hmac_final(uint8_t * key, uint32_t klen, uint8_t * hmac)
{
    uint8_t buf[64];
    unsigned int i;
    crypto_sha256_final(hmac);
    memset(buf, 0, sizeof(buf));
    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret)/2;
    }
    else if (key == CRYPTO_TRANSPORT_KEY2)
    {
        key = transport_secret;
        klen = 32;
    }


    if(klen > 64)
    {
        printf2(TAG_ERR, "Error, key size must be <= 64\n");
        exit(1);
    }
    memmove(buf, key, klen);

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = buf[i] ^ 0x5c;
    }

    crypto_sha256_init();
    crypto_sha256_update(buf, 64);
    crypto_sha256_update(hmac, 32);
    crypto_sha256_final(hmac);
}


void crypto_ecc256_init(void)
{
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    _es256_curve = uECC_secp256r1();
}


void crypto_ecc256_load_attestation_key(void)
{
    _signing_key = device_get_attestation_key();
    _key_len = 32;
}

void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig)
{
    if ( uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0)
    {
        printf2(TAG_ERR, "error, uECC failed\n");
        exit(1);
    }
}

void crypto_ecc256_load_key(uint8_t * data, int len, uint8_t * data2, int len2)
{
    static uint8_t privkey[32];
    generate_private_key(data,len,data2,len2,privkey);
    _signing_key = privkey;
    _key_len = 32;
}

void crypto_ecdsa_sign(uint8_t * data, int len, uint8_t * sig, int MBEDTLS_ECP_ID)
{

    const struct uECC_Curve_t * curve = NULL;

    switch(MBEDTLS_ECP_ID)
    {
        case MBEDTLS_ECP_DP_SECP192R1:
            curve = uECC_secp192r1();
            if (_key_len != 24)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP224R1:
            curve = uECC_secp224r1();
            if (_key_len != 28)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP256R1:
            curve = uECC_secp256r1();
            if (_key_len != 32)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP256K1:
            curve = uECC_secp256k1();
            if (_key_len != 32)  goto fail;
            break;
        default:
            printf2(TAG_ERR, "error, invalid ECDSA alg specifier\n");
            exit(1);
    }

    if ( uECC_sign(_signing_key, data, len, sig, curve) == 0)
    {
        printf2(TAG_ERR, "error, uECC failed\n");
        exit(1);
    }
    return;

fail:
    printf2(TAG_ERR, "error, invalid key length\n");
    exit(1);

}

void generate_private_key(uint8_t * data, int len, uint8_t * data2, int len2, uint8_t * privkey)
{
    crypto_sha256_hmac_init(CRYPTO_MASTER_KEY, 0, privkey);
    crypto_sha256_update(data, len);
    crypto_sha256_update(data2, len2);
    crypto_sha256_update(master_secret, 32);    // TODO AES
    crypto_sha256_hmac_final(CRYPTO_MASTER_KEY, 0, privkey);

    crypto_aes256_init(master_secret + 32, NULL);
    crypto_aes256_encrypt(privkey, 32);
}


/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);*/
void crypto_ecc256_derive_public_key(uint8_t * data, int len, uint8_t * x, uint8_t * y)
{
    uint8_t privkey[32];
    uint8_t pubkey[64];

    generate_private_key(data,len,NULL,0,privkey);

    memset(pubkey,0,sizeof(pubkey));
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
    memmove(x,pubkey,32);
    memmove(y,pubkey+32,32);
}
void crypto_ecc256_compute_public_key(uint8_t * privkey, uint8_t * pubkey)
{
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
}


void crypto_load_external_key(uint8_t * key, int len)
{
    _signing_key = key;
    _key_len = len;
}


void crypto_ecc256_make_key_pair(uint8_t * pubkey, uint8_t * privkey)
{
    if (uECC_make_key(pubkey, privkey, _es256_curve) != 1)
    {
        printf2(TAG_ERR, "Error, uECC_make_key failed\n");
        exit(1);
    }
}

void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret)
{
    if (uECC_shared_secret(pubkey, privkey, shared_secret, _es256_curve) != 1)
    {
        printf2(TAG_ERR, "Error, uECC_shared_secret failed\n");
        exit(1);
    }

}

struct AES_ctx aes_ctx;
void crypto_aes256_init(uint8_t * key, uint8_t * nonce)
{
    if (key == CRYPTO_TRANSPORT_KEY)
    {
        AES_init_ctx(&aes_ctx, transport_secret);
    }
    else
    {
        AES_init_ctx(&aes_ctx, key);
    }
    if (nonce == NULL)
    {
        memset(aes_ctx.Iv, 0, 16);
    }
    else
    {
        memmove(aes_ctx.Iv, nonce, 16);
    }
}

// prevent round key recomputation
void crypto_aes256_reset_iv(uint8_t * nonce)
{
    if (nonce == NULL)
    {
        memset(aes_ctx.Iv, 0, 16);
    }
    else
    {
        memmove(aes_ctx.Iv, nonce, 16);
    }
}

void crypto_aes256_decrypt(uint8_t * buf, int length)
{
    AES_CBC_decrypt_buffer(&aes_ctx, buf, length);
}

void crypto_aes256_encrypt(uint8_t * buf, int length)
{
    AES_CBC_encrypt_buffer(&aes_ctx, buf, length);
}

void crypto_ed25519_derive_public_key(uint8_t * data, int len, uint8_t * x)
{
#if defined(STM32L432xx)

    uint8_t seed[salty_SECRETKEY_SEED_LENGTH];

    generate_private_key(data, len, NULL, 0, seed);
    salty_public_key(&seed, (uint8_t (*)[salty_PUBLICKEY_SERIALIZED_LENGTH])x);

#else

    uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
    uint8_t   sk[crypto_sign_ed25519_SECRETKEYBYTES];

    generate_private_key(data, len, NULL, 0, seed);
    crypto_sign_ed25519_seed_keypair(x, sk, seed);

#endif
}

void crypto_ed25519_load_key(uint8_t * data, int len)
{
#if defined(STM32L432xx)

    static uint8_t seed[salty_SECRETKEY_SEED_LENGTH];

    generate_private_key(data, len, NULL, 0, seed);

    _signing_key = seed;
    _key_len = salty_SECRETKEY_SEED_LENGTH;

#else

    uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
    uint8_t   pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    static uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];

    generate_private_key(data, len, NULL, 0, seed);
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);

    _signing_key = sk;
    _key_len = crypto_sign_ed25519_SECRETKEYBYTES;

#endif
}

void crypto_ed25519_sign(uint8_t * data1, int len1, uint8_t * data2, int len2, uint8_t * sig)
{
    // ed25519 signature APIs need the message at once (by design!) and in one
    // contiguous buffer (could be changed).

    // 512 is an arbitrary sanity limit, could be less
    if (len1 < 0 || len2 < 0 || len1 > 512 || len2 > 512)
    {
        memset(sig, 0, 64); // ed25519 signature len is 64 bytes
        return;
    }
    // XXX: dynamically sized allocation on the stack
    const int len = len1 + len2; // 0 <= len <= 1024
    uint8_t data[len1 + len2];

    memcpy(data, data1, len1);
    if (len2)
    {
        memcpy(data + len1, data2, len2);
    }

#if defined(STM32L432xx)

    // TODO: check that correct load_key() had been called?
    salty_sign((uint8_t (*)[salty_SECRETKEY_SEED_LENGTH])_signing_key, data, len,
            (uint8_t (*)[salty_SIGNATURE_SERIALIZED_LENGTH])sig);

#else

    // TODO: check that correct load_key() had been called?
    crypto_sign_ed25519_detached(sig, NULL, data, len, _signing_key);

#endif
}

#endif
