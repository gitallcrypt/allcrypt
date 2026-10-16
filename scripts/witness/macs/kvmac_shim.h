/* What the Linux kernel's crypto/vmac.c needs from the kernel, in user
 * space, so its VMAC core - key setup, NH, the polynomial, L3 and the
 * pad - can run unchanged as a witness. AES is OpenSSL's. Included
 * before the extracted part of vmac.c; see build.sh. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <openssl/aes.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t __le64;
typedef uint64_t __be64;

#define CONFIG_64BIT 1
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN 1234
#define le64_to_cpup(p) (*(const u64 *)(p))
#define be64_to_cpu(x) __builtin_bswap64(x)
#else
#define le64_to_cpup(p) __builtin_bswap64(*(const u64 *)(p))
#define be64_to_cpu(x) (x)
#endif
static inline void put_unaligned_be64(u64 v, u8 *out) {
    for (int i = 7; i >= 0; i--) { out[i] = (u8)v; v >>= 8; }
}
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define round_down(x, y) ((x) / (y) * (y))
#define round_up(x, y) (((x) + (y) - 1) / (y) * (y))
#define BUILD_BUG_ON(x) ((void)sizeof(char[1 - 2 * !!(x)]))

struct crypto_cipher { AES_KEY key; };
static inline int crypto_cipher_setkey(struct crypto_cipher *c, const u8 *k, unsigned int len) {
    return AES_set_encrypt_key(k, (int)len * 8, &c->key) ? -EINVAL : 0;
}
static inline void crypto_cipher_encrypt_one(struct crypto_cipher *c, u8 *out, const u8 *in) {
    AES_encrypt(in, out, &c->key);
}

struct crypto_shash { _Alignas(16) unsigned char ctx[2048]; };
struct shash_desc { struct crypto_shash *tfm; _Alignas(16) unsigned char ctx[2048]; };
#define crypto_shash_ctx(tfm) ((void *)(tfm)->ctx)
#define shash_desc_ctx(desc) ((void *)(desc)->ctx)

/* vmac.c defines its own. */
#undef UINT64_C
