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
#include "uECC.h"
#include "ctap.h"


const uint8_t attestation_cert_der[];
const uint16_t attestation_cert_der_size;
const uint8_t attestation_key[];
const uint16_t attestation_key_size;



static SHA256_CTX sha256_ctx;
static const struct uECC_Curve_t * _es256_curve = NULL;
static uint8_t * _signing_key = NULL;

// Secret for testing only
static uint8_t master_secret[32] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
                                "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";


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


void crypto_ecc256_init()
{
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    _es256_curve = uECC_secp256r1();
}

void crypto_ecc256_load_key(uint8_t * rpId, int len1, uint8_t * entropy, int len2)
{
    // TODO
}


void crypto_ecc256_load_attestation_key()
{
    _signing_key = attestation_key;
}

void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig)
{
    uECC_sign(_signing_key, data, len, sig, _es256_curve);
}


/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);*/
void crypto_derive_ecc256_public_key(uint8_t * rpId, int len1, uint8_t * entropy, int len2, uint8_t * x, uint8_t * y)
{
    uint8_t privkey[32];
    uint8_t pubkey[64];

    // poor man's hmac
    crypto_sha256_init();
    crypto_sha256_update(rpId, len1);
    crypto_sha256_update(entropy, len2);
    crypto_sha256_update(master_secret, 32);
    crypto_sha256_final(privkey);

    memset(pubkey,0,sizeof(pubkey));
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
    memmove(x,pubkey,32);
    memmove(y,pubkey+32,32);
}


const uint8_t attestation_cert_der[] =
    "\x30\x82\x01\x4e\x30\x81\xf6\x02\x01\x00\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04"
    "\x03\x02\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30"
    "\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x0c"
    "\x07\x54\x45\x53\x54\x20\x43\x41\x30\x20\x17\x0d\x31\x38\x30\x35\x30\x36\x32\x32"
    "\x34\x39\x32\x35\x5a\x18\x0f\x32\x30\x36\x38\x30\x34\x32\x33\x32\x32\x34\x39\x32"
    "\x35\x5a\x30\x3a\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30"
    "\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x1e\x30\x1c\x06\x03\x55\x04\x0a\x0c"
    "\x15\x54\x45\x53\x54\x20\x41\x54\x54\x45\x53\x54\x41\x54\x49\x4f\x4e\x20\x43\x45"
    "\x52\x54\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48"
    "\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x45\xa9\x02\xc1\x2e\x9c\x0a\x33\xfa\x3e\x84"
    "\x50\x4a\xb8\x02\xdc\x4d\xb9\xaf\x15\xb1\xb6\x3a\xea\x8d\x3f\x03\x03\x55\x65\x7d"
    "\x70\x3f\xb4\x02\xa4\x97\xf4\x83\xb8\xa6\xf9\x3c\xd0\x18\xad\x92\x0c\xb7\x8a\x5a"
    "\x3e\x14\x48\x92\xef\x08\xf8\xca\xea\xfb\x32\xab\x20\x30\x0a\x06\x08\x2a\x86\x48"
    "\xce\x3d\x04\x03\x02\x03\x47\x00\x30\x44\x02\x20\x03\x81\x09\xa6\x99\xb3\x69\x69"
    "\x69\xa1\xd9\x40\xbc\x32\xa5\x37\x05\x1d\xa8\x42\x54\x3b\xee\x77\xbe\x25\xb2\x03"
    "\x16\x90\x77\x9c\x02\x20\x6b\xfb\x26\x30\x68\x6d\x72\x49\xac\xbf\x0e\x06\xd3\x61"
    "\x32\xe0\x60\x78\x60\xab\x7e\x7f\xd3\x4f\xd7\x25\xfa\x2d\x95\x1b\x19\xdd";


const uint16_t attestation_cert_der_size = sizeof(attestation_cert_der)-1;


const uint8_t attestation_key[] = "\xcdg\xaa1\r\t\x1e\xd1n~\x98\x92\xaa\x07\x0e\x19\x94\xfc\xd7\x14\xae|@\x8f\xb9F\xb7._\xe7]0";
const uint16_t attestation_key_size = sizeof(attestation_key)-1;



#else
#error "No crypto implementation defined"
#endif


