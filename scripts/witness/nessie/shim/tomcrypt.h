/* Just enough of libtomcrypt 1.18.2's headers for its cipher files to
 * compile alone: the types, the macros those files use, the key structs
 * and the descriptor, laid out as src/headers/tomcrypt_cipher.h has them.
 * The self-tests are compiled out (LTC_TEST is not defined). */
#ifndef NESSIE_TOMCRYPT_SHIM
#define NESSIE_TOMCRYPT_SHIM
#include <stdint.h>
#include <string.h>

typedef uint64_t ulong64;
typedef uint32_t ulong32;
#define CONST64(n) n##ULL

#define LTC_KHAZAD
#define LTC_ANUBIS
#define LTC_NOEKEON

enum { CRYPT_OK = 0, CRYPT_ERROR, CRYPT_NOP, CRYPT_INVALID_KEYSIZE, CRYPT_INVALID_ROUNDS,
       CRYPT_FAIL_TESTVECTOR };
#define LTC_ARGCHK(x) do { if (!(x)) return CRYPT_ERROR; } while (0)
#define LTC_ARGCHKVD(x) do { if (!(x)) return; } while (0)
#define LTC_UNUSED_PARAM(x) (void)(x)

#define ROL(x, y) ((ulong32)(((x) << ((y) & 31)) | ((x) >> ((32 - ((y) & 31)) & 31))))
#define ROR(x, y) ((ulong32)(((x) >> ((y) & 31)) | ((x) << ((32 - ((y) & 31)) & 31))))
#define ROLc ROL
#define RORc ROR
#define LOAD32H(x, y) do { (x) = ((ulong32)(y)[0] << 24) | ((ulong32)(y)[1] << 16) | \
                                 ((ulong32)(y)[2] << 8) | (ulong32)(y)[3]; } while (0)
#define STORE32H(x, y) do { (y)[0] = (unsigned char)((x) >> 24); \
                            (y)[1] = (unsigned char)((x) >> 16); \
                            (y)[2] = (unsigned char)((x) >> 8); \
                            (y)[3] = (unsigned char)(x); } while (0)

static inline void zeromem(volatile void *p, size_t n) { memset((void *)p, 0, n); }
static inline void burn_stack(unsigned long n) { (void)n; }

struct khazad_key { ulong64 roundKeyEnc[8 + 1]; ulong64 roundKeyDec[8 + 1]; };
struct anubis_key { int keyBits; int R; ulong32 roundKeyEnc[18 + 1][4];
                    ulong32 roundKeyDec[18 + 1][4]; };
struct noekeon_key { ulong32 K[4], dK[4]; };
typedef union { struct khazad_key khazad; struct anubis_key anubis;
                struct noekeon_key noekeon; } symmetric_key;

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

int khazad_setup(const unsigned char *, int, int, symmetric_key *);
int khazad_ecb_encrypt(const unsigned char *, unsigned char *, symmetric_key *);
int khazad_ecb_decrypt(const unsigned char *, unsigned char *, symmetric_key *);
int khazad_test(void);
void khazad_done(symmetric_key *);
int khazad_keysize(int *);
int anubis_setup(const unsigned char *, int, int, symmetric_key *);
int anubis_ecb_encrypt(const unsigned char *, unsigned char *, symmetric_key *);
int anubis_ecb_decrypt(const unsigned char *, unsigned char *, symmetric_key *);
int anubis_test(void);
void anubis_done(symmetric_key *);
int anubis_keysize(int *);
int noekeon_setup(const unsigned char *, int, int, symmetric_key *);
int noekeon_ecb_encrypt(const unsigned char *, unsigned char *, symmetric_key *);
int noekeon_ecb_decrypt(const unsigned char *, unsigned char *, symmetric_key *);
int noekeon_test(void);
void noekeon_done(symmetric_key *);
int noekeon_keysize(int *);
int compare_testvector(const void *, unsigned long, const void *, unsigned long, const char *,
                       int);
#endif
