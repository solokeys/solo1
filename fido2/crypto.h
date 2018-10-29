/*
   Copyright 2018 Conor Patrick

   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stddef.h>

#define USE_SOFTWARE_IMPLEMENTATION

void crypto_sha256_init();
void crypto_sha256_update(uint8_t * data, size_t len);
void crypto_sha256_update_secret();
void crypto_sha256_final(uint8_t * hash);

void crypto_sha256_hmac_init(uint8_t * key, uint32_t klen, uint8_t * hmac);
void crypto_sha256_hmac_final(uint8_t * key, uint32_t klen, uint8_t * hmac);


void crypto_ecc256_init();
void crypto_ecc256_derive_public_key(uint8_t * data, int len, uint8_t * x, uint8_t * y);

void crypto_ecc256_load_key(uint8_t * data, int len, uint8_t * data2, int len2);
void crypto_ecc256_load_attestation_key();
void crypto_load_external_key(uint8_t * key, int len);
void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig);
void crypto_ecdsa_sign(uint8_t * data, int len, uint8_t * sig, int MBEDTLS_ECP_ID);


void generate_private_key(uint8_t * data, int len, uint8_t * data2, int len2, uint8_t * privkey);
void crypto_ecc256_make_key_pair(uint8_t * pubkey, uint8_t * privkey);
void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret);

#define CRYPTO_TRANSPORT_KEY            ((uint8_t*)1)
#define CRYPTO_MASTER_KEY               ((uint8_t*)0)

void crypto_aes256_init(uint8_t * key, uint8_t * nonce);
void crypto_aes256_reset_iv(uint8_t * nonce);

// buf length must be multiple of 16 bytes
void crypto_aes256_decrypt(uint8_t * buf, int lenth);
void crypto_aes256_encrypt(uint8_t * buf, int lenth);

void crypto_reset_master_secret();
void crypto_load_master_secret(uint8_t * key);


extern const uint8_t attestation_cert_der[];
extern const uint16_t attestation_cert_der_size;

extern const uint8_t attestation_key[];
extern const uint16_t attestation_key_size;

#endif
