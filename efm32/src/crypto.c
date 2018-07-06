/*
 *  Wrapper for crypto implementation on device
 *
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "crypto.h"


#include "sha256.h"
#include "uECC.h"
#include "aes.h"
#include "ctap.h"

#include MBEDTLS_CONFIG_FILE
#include "sha256_alt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"

const uint8_t attestation_cert_der[];
const uint16_t attestation_cert_der_size;
const uint8_t attestation_key[];
const uint16_t attestation_key_size;



static SHA256_CTX sha256_ctx;
mbedtls_sha256_context embed_sha256_ctx;

static const struct uECC_Curve_t * _es256_curve = NULL;
static const uint8_t * _signing_key = NULL;

// Secrets for testing only
static uint8_t master_secret[32] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
                                "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";

static uint8_t transport_secret[32] = "\x10\x01\x22\x33\x44\x55\x66\x77\x87\x90\x0a\xbb\x3c\xd8\xee\xff"
                                "\xff\xee\x8d\x1c\x3b\xfa\x99\x88\x77\x86\x55\x44\xd3\xff\x33\x00";



void crypto_sha256_init()
{
	mbedtls_sha256_init( &embed_sha256_ctx );
	mbedtls_sha256_starts(&embed_sha256_ctx,0);
//    sha256_init(&sha256_ctx);
}

void crypto_reset_master_secret()
{
    ctap_generate_rng(master_secret, 32);
}


void crypto_sha256_update(uint8_t * data, size_t len)
{
	mbedtls_sha256_update(&embed_sha256_ctx,data,len);
//    sha256_update(&sha256_ctx, data, len);
}

void crypto_sha256_update_secret()
{
	mbedtls_sha256_update(&embed_sha256_ctx,master_secret,32);
//    sha256_update(&sha256_ctx, master_secret, 32);
}

void crypto_sha256_final(uint8_t * hash)
{
	mbedtls_sha256_finish( &embed_sha256_ctx, hash );
//    sha256_final(&sha256_ctx, hash);
}

void crypto_sha256_hmac_init(uint8_t * key, uint32_t klen, uint8_t * hmac)
{
    uint8_t buf[64];
    int i;
    memset(buf, 0, sizeof(buf));

    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret);
    }

    if(klen > 64)
    {
        printf("Error, key size must be <= 64\n");
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
    int i;
    crypto_sha256_final(hmac);
    memset(buf, 0, sizeof(buf));
    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret);
    }


    if(klen > 64)
    {
        printf("Error, key size must be <= 64\n");
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

mbedtls_ctr_drbg_context ctr_drbg;

void crypto_ecc256_init()
{
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    _es256_curve = uECC_secp256r1();
    mbedtls_ctr_drbg_init(&ctr_drbg);
}


void crypto_ecc256_load_attestation_key()
{
    _signing_key = attestation_key;
}

/**
 * \brief           Import a point from unsigned binary data
 *
 * \param grp       Group to which the point should belong
 * \param P         Point to import
 * \param buf       Input buffer
 * \param ilen      Actual length of input
 *
 * \return          0 if successful,
 *                  MBEDTLS_ERR_ECP_BAD_INPUT_DATA if input is invalid,
 *                  MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *                  MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the point format
 *                  is not implemented.
 *
 * \note            This function does NOT check that the point actually
 *                  belongs to the given group, see mbedtls_ecp_check_pubkey() for
 *                  that.
 */
//int mbedtls_ecp_point_read_binary( const mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
//                           const unsigned char *buf, size_t ilen );

/**
 * \brief          Import X from unsigned binary data, big endian
 *
 * \param X        Destination MPI
 * \param buf      Input buffer
 * \param buflen   Input buffer size
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
//int mbedtls_mpi_read_binary( mbedtls_mpi *X, const unsigned char *buf, size_t buflen );

/*
 * Set context from an mbedtls_ecp_keypair
 */
//int mbedtls_ecdsa_from_keypair( mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key );



void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig)
{
    mbedtls_ecp_group grp;      /*!<  Elliptic curve and base point     */
    mbedtls_mpi d;              /*!<  our secret value                  */
//#define CRYPTO_ENABLE CMU->HFBUSCLKEN0 |= CMU_HFBUSCLKEN0_CRYPTO; \
//  CRYPTO->IFC = _CRYPTO_IFC_MASK; \
//  CRYPTO->CMD = CRYPTO_CMD_SEQSTOP; \
//  CRYPTO->CTRL = CRYPTO_CTRL_DMA0RSEL_DDATA0; \
//  CRYPTO->SEQCTRL = 0; \
//  CRYPTO->SEQCTRLB = 0
//
//#define CRYPTO_DISABLE \
//  CRYPTO->IEN = 0; \
//  CMU->HFBUSCLKEN0 &= ~CMU_HFBUSCLKEN0_CRYPTO;
//  CRYPTO_DISABLE;
//	CRYPTO_ENABLE;
    mbedtls_ecp_group_init( &grp );
    mbedtls_mpi_init( &d );
	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
	mbedtls_mpi_read_binary(&d, _signing_key, 32);

	mbedtls_mpi r,s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	printf("signing..\n");
	dump_hex(data,len);
	mbedtls_ecdsa_sign_det( &grp, &r, &s, &d,
	                             data, 32, MBEDTLS_MD_SHA256 );// Issue: this will freeze on 13th iteration..
	printf("signed\n");

	mbedtls_mpi_write_binary(&r,sig,32);
	mbedtls_mpi_write_binary(&s,sig+32,32);

//    if ( uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0)
//    {
//        printf("error, uECC failed\n");
//        exit(1);
//    }

}

/*
 * Generate a keypair with configurable base point
 */
// mbedtls_ecp_gen_keypair( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng )
// mbedtls_ecp_gen_keypair_base( grp, &grp->G, d, Q, f_rng, p_rng )
/*
 * Curve types: internal for now, might be exposed later
 */
typedef enum
{
    ECP_TYPE_NONE = 0,
    ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
    ECP_TYPE_MONTGOMERY,           /* y^2 = x^3 + a x^2 + x    */
} ecp_curve_type;
/*
 * Get the type of a curve
 */
static inline ecp_curve_type ecp_get_type( const mbedtls_ecp_group *grp )
{
    if( grp->G.X.p == NULL )
        return( ECP_TYPE_NONE );

    if( grp->G.Y.p == NULL )
        return( ECP_TYPE_MONTGOMERY );
    else
        return( ECP_TYPE_SHORT_WEIERSTRASS );
}
static int mbedtls_ecp_gen_privkey( mbedtls_ecp_group *grp,
                     const mbedtls_ecp_point *G,
                     mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret;
    size_t n_size = ( grp->nbits + 7 ) / 8;

#if defined(ECP_MONTGOMERY)
    if( ecp_get_type( grp ) == ECP_TYPE_MONTGOMERY )
    {
        /* [M225] page 5 */
        size_t b;

        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( d, n_size, f_rng, p_rng ) );

        /* Make sure the most significant bit is nbits */
        b = mbedtls_mpi_bitlen( d ) - 1; /* mbedtls_mpi_bitlen is one-based */
        if( b > grp->nbits )
            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( d, b - grp->nbits ) );
        else
            MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( d, grp->nbits, 1 ) );

        /* Make sure the last three bits are unset */
        MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( d, 0, 0 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( d, 1, 0 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( d, 2, 0 ) );
    }
    else
#endif /* ECP_MONTGOMERY */
#if defined(ECP_SHORTWEIERSTRASS)
    if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
    {
        /* SEC1 3.2.1: Generate d such that 1 <= n < N */
        int count = 0;
        unsigned char rnd[MBEDTLS_ECP_MAX_BYTES];

        /*
         * Match the procedure given in RFC 6979 (deterministic ECDSA):
         * - use the same byte ordering;
         * - keep the leftmost nbits bits of the generated octet string;
         * - try until result is in the desired range.
         * This also avoids any biais, which is especially important for ECDSA.
         */
        do
        {
            MBEDTLS_MPI_CHK( f_rng( p_rng, rnd, n_size ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( d, rnd, n_size ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( d, 8 * n_size - grp->nbits ) );

            /*
             * Each try has at worst a probability 1/2 of failing (the msb has
             * a probability 1/2 of being 0, and then the result will be < N),
             * so after 30 tries failure probability is a most 2**(-30).
             *
             * For most curves, 1 try is enough with overwhelming probability,
             * since N starts with a lot of 1s in binary, but some curves
             * such as secp224k1 are actually very close to the worst case.
             */
            if( ++count > 30 )
                return( MBEDTLS_ERR_ECP_RANDOM_FAILED );
        }
        while( mbedtls_mpi_cmp_int( d, 1 ) < 0 ||
               mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0 );
    }
    else
#endif /* ECP_SHORTWEIERSTRASS */
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

cleanup:
    if( ret != 0 )
        return( ret );

    return 0;
}

static int mbedtls_ecp_derive_pubkey( mbedtls_ecp_group *grp,
                     const mbedtls_ecp_point *G,
                     mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
	return( mbedtls_ecp_mul( grp, Q, d, G, f_rng, p_rng ) );
}


static int hmac_vector_func(uint8_t * hmac, uint8_t * dst, int len)
{
	static int hmac_ptr = 0;
	if (hmac==NULL)
	{
		hmac_ptr = 0;
		return 0;
	}
	int i;
	while(len--)
	{
		*dst++ = hmac[hmac_ptr++ % 32];
	}
	return 0;
}

void generate_private_key(uint8_t * data, int len, uint8_t * data2, int len2, uint8_t * privkey)
{
    crypto_sha256_hmac_init(CRYPTO_MASTER_KEY, 0, privkey);
    crypto_sha256_update(data, len);
    crypto_sha256_update(data2, len2);
    crypto_sha256_update(master_secret, 32);
    crypto_sha256_hmac_final(CRYPTO_MASTER_KEY, 0, privkey);

    mbedtls_ecp_group grp;      /*!<  Elliptic curve and base point     */
    mbedtls_mpi d;              /*!<  our secret value                  */
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init( &grp );
    mbedtls_mpi_init( &d );
    mbedtls_ecp_point_init(&Q);

	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

//	mbedtls_mpi_read_binary(&d, _signing_key, 32);
	hmac_vector_func(NULL, NULL, 0);
	mbedtls_ecp_gen_privkey(&grp, &grp.G, &d, &Q, hmac_vector_func, privkey);
    mbedtls_mpi_write_binary(&d,privkey,32);
}


/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);*/
void crypto_ecc256_derive_public_key(uint8_t * data, int len, uint8_t * x, uint8_t * y)
{
	int ret;
    uint8_t privkey[32];
    uint8_t pubkey[64];

//    generate_private_key(data,len,NULL,0,privkey);

    crypto_sha256_hmac_init(CRYPTO_MASTER_KEY, 0, privkey);
    crypto_sha256_update(data, len);
    crypto_sha256_update(NULL, 0);
    crypto_sha256_update(master_secret, 32);
    crypto_sha256_hmac_final(CRYPTO_MASTER_KEY, 0, privkey);

    mbedtls_ecp_group grp;      /*!<  Elliptic curve and base point     */
    mbedtls_mpi d;              /*!<  our secret value                  */
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init( &grp );
    mbedtls_mpi_init( &d );
    mbedtls_ecp_point_init(&Q);

	mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

//	mbedtls_mpi_read_binary(&d, _signing_key, 32);
	hmac_vector_func(NULL, NULL, 0);
	ret= mbedtls_ecp_gen_privkey(&grp, &grp.G, &d, &Q, hmac_vector_func, privkey);
    if (ret != 0)
    {
    	printf("error with priv key -0x04%x\n", -ret);
    }
//    mbedtls_mpi_write_binary(&d,privkey,32);

    memset(pubkey,0,sizeof(pubkey));

    ret = mbedtls_ecp_derive_pubkey( &grp, &grp.G,
    		&d, &Q, hmac_vector_func, privkey);

    if (ret != 0)
    {
    	printf("error with public key\n");
    }

    mbedtls_mpi_write_binary(&Q.X,x,32);
    mbedtls_mpi_write_binary(&Q.Y,y,32);

//    uECC_compute_public_key(privkey, pubkey, _es256_curve);
//    memmove(x,pubkey,32);
//    memmove(y,pubkey+32,32);
}

void crypto_ecc256_load_key(uint8_t * data, int len, uint8_t * data2, int len2)
{
    static uint8_t privkey[32];
    generate_private_key(data,len,data2,len2,privkey);
    _signing_key = privkey;
}

void crypto_ecc256_make_key_pair(uint8_t * pubkey, uint8_t * privkey)
{
    if (uECC_make_key(pubkey, privkey, _es256_curve) != 1)
    {
        printf("Error, uECC_make_key failed\n");
        exit(1);
    }
}

void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret)
{
    if (uECC_shared_secret(pubkey, privkey, shared_secret, _es256_curve) != 1)
    {
        printf("Error, uECC_shared_secret failed\n");
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


const uint8_t attestation_cert_der[] =
"\x30\x82\x01\xfb\x30\x82\x01\xa1\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0a\x06\x08"
"\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e"
"\x06\x03\x55\x04\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x30\x20\x17\x0d\x31\x38"
"\x30\x35\x31\x30\x30\x33\x30\x36\x32\x30\x5a\x18\x0f\x32\x30\x36\x38\x30\x34\x32"
"\x37\x30\x33\x30\x36\x32\x30\x5a\x30\x7c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
"\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x0f\x30\x0d"
"\x06\x03\x55\x04\x07\x0c\x06\x4c\x61\x75\x72\x65\x6c\x31\x15\x30\x13\x06\x03\x55"
"\x04\x0a\x0c\x0c\x54\x45\x53\x54\x20\x43\x4f\x4d\x50\x41\x4e\x59\x31\x22\x30\x20"
"\x06\x03\x55\x04\x0b\x0c\x19\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x6f\x72"
"\x20\x41\x74\x74\x65\x73\x74\x61\x74\x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04"
"\x03\x0c\x0b\x63\x6f\x6e\x6f\x72\x70\x70\x2e\x63\x6f\x6d\x30\x59\x30\x13\x06\x07"
"\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
"\x04\x45\xa9\x02\xc1\x2e\x9c\x0a\x33\xfa\x3e\x84\x50\x4a\xb8\x02\xdc\x4d\xb9\xaf"
"\x15\xb1\xb6\x3a\xea\x8d\x3f\x03\x03\x55\x65\x7d\x70\x3f\xb4\x02\xa4\x97\xf4\x83"
"\xb8\xa6\xf9\x3c\xd0\x18\xad\x92\x0c\xb7\x8a\x5a\x3e\x14\x48\x92\xef\x08\xf8\xca"
"\xea\xfb\x32\xab\x20\xa3\x62\x30\x60\x30\x46\x06\x03\x55\x1d\x23\x04\x3f\x30\x3d"
"\xa1\x30\xa4\x2e\x30\x2c\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\x4d\x44\x31\x10\x30\x0e\x06\x03\x55\x04"
"\x0a\x0c\x07\x54\x45\x53\x54\x20\x43\x41\x82\x09\x00\xf7\xc9\xec\x89\xf2\x63\x94"
"\xd9\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55\x1d\x0f\x04"
"\x04\x03\x02\x04\xf0\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00"
"\x30\x45\x02\x20\x18\x38\xb0\x45\x03\x69\xaa\xa7\xb7\x38\x62\x01\xaf\x24\x97\x5e"
"\x7e\x74\x64\x1b\xa3\x7b\xf7\xe6\xd3\xaf\x79\x28\xdb\xdc\xa5\x88\x02\x21\x00\xcd"
"\x06\xf1\xe3\xab\x16\x21\x8e\xd8\xc0\x14\xaf\x09\x4f\x5b\x73\xef\x5e\x9e\x4b\xe7"
"\x35\xeb\xdd\x9b\x6d\x8f\x7d\xf3\xc4\x3a\xd7";


const uint16_t attestation_cert_der_size = sizeof(attestation_cert_der)-1;


const uint8_t attestation_key[] = "\xcd\x67\xaa\x31\x0d\x09\x1e\xd1\x6e\x7e\x98\x92\xaa\x07\x0e\x19\x94\xfc\xd7\x14\xae\x7c\x40\x8f\xb9\x46\xb7\x2e\x5f\xe7\x5d\x30";
const uint16_t attestation_key_size = sizeof(attestation_key)-1;



