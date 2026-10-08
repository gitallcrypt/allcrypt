/* Stand-in for the FIPS module's <openssl/fips_rand.h>: only the flag
 * that turns off the continuous test's discarded first block, which the
 * known-answer tests run without. */
#ifndef DUALEC_SHIM_FIPS_RAND_H
#define DUALEC_SHIM_FIPS_RAND_H
#define DRBG_FLAG_TEST 0x2
typedef struct drbg_ctx_st DRBG_CTX;
#endif
