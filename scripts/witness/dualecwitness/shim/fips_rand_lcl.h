/* The parts of the FIPS module's fips_rand_lcl.h that fips_drbg_ec.c
 * uses, with the fields it reads and writes and nothing else. The Dual
 * EC structure is copied from OpenSSL-fips-2_0_5 unchanged. */
#ifndef DUALEC_SHIM_LCL_H
#define DUALEC_SHIM_LCL_H
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

typedef struct drbg_ctx_st DRBG_CTX;

#define EC_PRNG_MAX_SEEDLEN 66

typedef struct drbg_ec_ctx_st {
	const EVP_MD *md;
	EC_GROUP *curve;
	EC_POINT *Q;
	EC_POINT *ptmp;
	size_t exbits;
	BIGNUM *s;
	unsigned char sbuf[EC_PRNG_MAX_SEEDLEN];
	unsigned char tbuf[EC_PRNG_MAX_SEEDLEN];
	EVP_MD_CTX mctx;
	unsigned char vtmp[EC_PRNG_MAX_SEEDLEN];
	BN_CTX *bctx;
} DRBG_EC_CTX;

#define DRBG_CUSTOM_RESEED 0x2
#define DRBG_STATUS_RESEED 2

struct drbg_ctx_st {
	int type;
	unsigned int xflags;
	unsigned int iflags;
	int strength;
	size_t blocklength;
	size_t max_request;
	size_t min_entropy, max_entropy;
	size_t min_nonce, max_nonce;
	size_t max_pers, max_adin;
	unsigned int reseed_counter;
	unsigned int reseed_interval;
	size_t seedlen;
	int status;
	union { DRBG_EC_CTX ec; } d;
	int (*instantiate)(DRBG_CTX *, const unsigned char *, size_t,
			const unsigned char *, size_t, const unsigned char *, size_t);
	int (*reseed)(DRBG_CTX *, const unsigned char *, size_t,
			const unsigned char *, size_t);
	int (*generate)(DRBG_CTX *, unsigned char *, size_t,
			const unsigned char *, size_t);
	int (*uninstantiate)(DRBG_CTX *);
	unsigned char lb[EVP_MAX_MD_SIZE];
	int lb_valid;
};

int fips_drbg_ec_init(DRBG_CTX *dctx);
/* The continuous test compares each block with the last; a test
 * harness has no use for it. */
static inline int fips_drbg_cprng_test(DRBG_CTX *dctx, const unsigned char *out)
	{ (void)dctx; (void)out; return 1; }
#endif
