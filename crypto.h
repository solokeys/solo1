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
void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig);


void generate_private_key(uint8_t * data, int len, uint8_t * data2, int len2, uint8_t * privkey);
void crypto_ecc256_make_key_pair(uint8_t * pubkey, uint8_t * privkey);
void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret);

// Key must be 32 bytes
#define CRYPTO_TRANSPORT_KEY            NULL
#define CRYPTO_MASTER_KEY               NULL

void crypto_aes256_init(uint8_t * key, uint8_t * nonce);
void crypto_aes256_reset_iv(uint8_t * nonce);

// buf length must be multiple of 16 bytes
void crypto_aes256_decrypt(uint8_t * buf, int lenth);
void crypto_aes256_encrypt(uint8_t * buf, int lenth);

void crypto_reset_master_secret();


extern const uint8_t attestation_cert_der[];
extern const uint16_t attestation_cert_der_size;



#endif
