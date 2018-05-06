/*
 *  Wrapper for crypto implementation on device
 *
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "crypto.h"

#ifdef USE_SOFTWARE_IMPLEMENTATION

#include "sha256.h"

static SHA256_CTX sha256_ctx;

void crypto_sha256_init()
{
    sha256_init(&sha256_ctx);
}


void crypto_sha256_update(uint8_t * data, size_t len)
{
    sha256_update(&sha256_ctx, data, len);
}


void crypto_sha256_final(uint8_t * hash)
{
    sha256_final(&sha256_ctx, hash);
}

#else
#error "No crypto implementation defined"
#endif
