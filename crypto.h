#ifndef _CRYPTO_H
#define _CRYPTO_H


#define USE_SOFTWARE_IMPLEMENTATION

void crypto_sha256_init();
void crypto_sha256_update(uint8_t * data, size_t len);
void crypto_sha256_final(uint8_t * hash);

#endif
