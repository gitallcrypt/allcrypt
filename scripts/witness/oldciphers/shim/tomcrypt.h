/* Just enough of libtomcrypt 1.18.2's headers for its cipher files to
 * compile alone: the types, the macros those files use, the key structs
 * and the descriptor, laid out as src/headers/tomcrypt_cipher.h has them.
 * The self-tests are compiled out (LTC_TEST is not defined). The same
 * shape as ../nessie/shim/tomcrypt.h, for the ciphers built here. */
#ifndef OLDCIPHERS_TOMCRYPT_SHIM
#define OLDCIPHERS_TOMCRYPT_SHIM
#include <stdint.h>
#include <string.h>

typedef uint64_t ulong64;
typedef uint32_t ulong32;
#define CONST64(n) n##ULL

#define LTC_SKIPJACK
#define LTC_SAFER
#define LTC_KASUMI
#define LTC_SAFERP

enum { CRYPT_OK = 0, CRYPT_ERROR, CRYPT_NOP, CRYPT_INVALID_KEYSIZE, CRYPT_INVALID_ROUNDS,
       CRYPT_FAIL_TESTVECTOR };
#define LTC_ARGCHK(x) do { if (!(x)) return CRYPT_ERROR; } while (0)
#define LTC_ARGCHKVD(x) do { if (!(x)) return; } while (0)
#define LTC_UNUSED_PARAM(x) (void)(x)

#define LOAD32H(x, y) do { (x) = ((ulong32)(y)[0] << 24) | ((ulong32)(y)[1] << 16) | \
                                 ((ulong32)(y)[2] << 8) | (ulong32)(y)[3]; } while (0)
#define STORE32H(x, y) do { (y)[0] = (unsigned char)((x) >> 24); \
                            (y)[1] = (unsigned char)((x) >> 16); \
                            (y)[2] = (unsigned char)((x) >> 8); \
                            (y)[3] = (unsigned char)(x); } while (0)

static inline void zeromem(volatile void *p, size_t n) { memset((void *)p, 0, n); }
static inline void burn_stack(unsigned long n) { (void)n; }

struct skipjack_key { unsigned char key[10]; };
#define LTC_SAFER_K64_DEFAULT_NOF_ROUNDS     6
#define LTC_SAFER_K128_DEFAULT_NOF_ROUNDS   10
#define LTC_SAFER_SK64_DEFAULT_NOF_ROUNDS    8
#define LTC_SAFER_SK128_DEFAULT_NOF_ROUNDS  10
#define LTC_SAFER_MAX_NOF_ROUNDS            13
#define LTC_SAFER_BLOCK_LEN                  8
#define LTC_SAFER_KEY_LEN     (1 + LTC_SAFER_BLOCK_LEN * (1 + 2 * LTC_SAFER_MAX_NOF_ROUNDS))
typedef unsigned char safer_block_t[LTC_SAFER_BLOCK_LEN];
typedef unsigned char safer_key_t[LTC_SAFER_KEY_LEN];
struct safer_key { safer_key_t key; };
struct kasumi_key {
    ulong32 KLi1[8], KLi2[8],
            KOi1[8], KOi2[8], KOi3[8],
            KIi1[8], KIi2[8], KIi3[8];
};
struct saferp_key {
   unsigned char K[33][16];
   long rounds;
};
typedef union { struct skipjack_key skipjack; struct safer_key safer;
                struct kasumi_key kasumi; struct saferp_key saferp; } symmetric_key;

struct ltc_cipher_descriptor {
    const char *name;
    unsigned char ID;
    int min_key_length, max_key_length, block_length, default_rounds;
    int (*setup)(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
    int (*ecb_encrypt)(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
    int (*ecb_decrypt)(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
    int (*test)(void);
    void (*done)(symmetric_key *skey);
    int (*keysize)(int *keysize);
    void *accelerated[14];
};

int skipjack_setup(const unsigned char *, int, int, symmetric_key *);
int skipjack_ecb_encrypt(const unsigned char *, unsigned char *, symmetric_key *);
int skipjack_ecb_decrypt(const unsigned char *, unsigned char *, symmetric_key *);
int skipjack_test(void);
void skipjack_done(symmetric_key *);
int skipjack_keysize(int *);
int safer_k64_setup(const unsigned char *, int, int, symmetric_key *);
int safer_sk64_setup(const unsigned char *, int, int, symmetric_key *);
int safer_k128_setup(const unsigned char *, int, int, symmetric_key *);
int safer_sk128_setup(const unsigned char *, int, int, symmetric_key *);
int safer_ecb_encrypt(const unsigned char *, unsigned char *, symmetric_key *);
int safer_ecb_decrypt(const unsigned char *, unsigned char *, symmetric_key *);
int safer_k64_test(void);
int safer_sk64_test(void);
int safer_sk128_test(void);
void safer_done(symmetric_key *);
int safer_64_keysize(int *);
int safer_128_keysize(int *);
int kasumi_setup(const unsigned char *, int, int, symmetric_key *);
int kasumi_ecb_encrypt(const unsigned char *, unsigned char *, symmetric_key *);
int kasumi_ecb_decrypt(const unsigned char *, unsigned char *, symmetric_key *);
int kasumi_test(void);
void kasumi_done(symmetric_key *);
int kasumi_keysize(int *);
int saferp_setup(const unsigned char *, int, int, symmetric_key *);
int saferp_ecb_encrypt(const unsigned char *, unsigned char *, symmetric_key *);
int saferp_ecb_decrypt(const unsigned char *, unsigned char *, symmetric_key *);
int saferp_test(void);
void saferp_done(symmetric_key *);
int saferp_keysize(int *);
#endif
