/* Just enough of the Linux kernel for crypto/speck.c (v4.19) to compile
 * in user space: the integer types, unaligned little-endian loads and
 * stores, rotations, crypto_tfm and crypto_alg as the module fills them
 * in, and the module macros as nothing. The kernel headers the module
 * includes are empty files the build makes, apart from its own
 * crypto/speck.h; this is passed with -include. */
#ifndef OLDCIPHERS_KERNEL_SHIM
#define OLDCIPHERS_KERNEL_SHIM
#include <errno.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

static inline u32 get_unaligned_le32(const void *p) {
    const u8 *b = p;
    return (u32)b[0] | (u32)b[1] << 8 | (u32)b[2] << 16 | (u32)b[3] << 24;
}
static inline u64 get_unaligned_le64(const void *p) {
    return (u64)get_unaligned_le32(p) | (u64)get_unaligned_le32((const u8 *)p + 4) << 32;
}
static inline void put_unaligned_le32(u32 v, void *p) {
    u8 *b = p;
    b[0] = (u8)v; b[1] = (u8)(v >> 8); b[2] = (u8)(v >> 16); b[3] = (u8)(v >> 24);
}
static inline void put_unaligned_le64(u64 v, void *p) {
    put_unaligned_le32((u32)v, p);
    put_unaligned_le32((u32)(v >> 32), (u8 *)p + 4);
}
static inline u32 rol32(u32 w, unsigned s) { return (w << (s & 31)) | (w >> ((-s) & 31)); }
static inline u32 ror32(u32 w, unsigned s) { return (w >> (s & 31)) | (w << ((-s) & 31)); }
static inline u64 rol64(u64 w, unsigned s) { return (w << (s & 63)) | (w >> ((-s) & 63)); }
static inline u64 ror64(u64 w, unsigned s) { return (w >> (s & 63)) | (w << ((-s) & 63)); }

struct crypto_tfm { void *ctx; };
static inline void *crypto_tfm_ctx(struct crypto_tfm *tfm) { return tfm->ctx; }

struct cipher_alg {
    unsigned int cia_min_keysize, cia_max_keysize;
    int (*cia_setkey)(struct crypto_tfm *, const u8 *, unsigned int);
    void (*cia_encrypt)(struct crypto_tfm *, u8 *, const u8 *);
    void (*cia_decrypt)(struct crypto_tfm *, u8 *, const u8 *);
};
struct crypto_alg {
    const char *cra_name, *cra_driver_name;
    int cra_priority;
    u32 cra_flags;
    unsigned int cra_blocksize, cra_ctxsize, cra_alignmask;
    void *cra_module;
    union { struct cipher_alg cipher; } cra_u;
};
#define CRYPTO_ALG_TYPE_CIPHER 1
#define THIS_MODULE NULL
#define __init
#define __exit
#define __always_inline inline __attribute__((always_inline))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define EXPORT_SYMBOL_GPL(f)
#define module_init(f)
#define module_exit(f)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_AUTHOR(x)
#define MODULE_ALIAS_CRYPTO(x)
static inline int crypto_register_algs(struct crypto_alg *algs, int n) { (void)algs; (void)n; return 0; }
static inline void crypto_unregister_algs(struct crypto_alg *algs, int n) { (void)algs; (void)n; }
#endif
