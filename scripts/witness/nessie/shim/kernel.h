/* Just enough of the Linux kernel's headers for a crypto/ cipher module
 * to compile in user space: the integer types, the byte-order helpers,
 * crypto_tfm and crypto_alg as the module fills them in, and the module
 * macros as nothing. The kernel's own headers the module names are empty
 * files the build makes; this is passed with -include. */
#ifndef NESSIE_KERNEL_SHIM
#define NESSIE_KERNEL_SHIM
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __be32;
typedef uint64_t __be64;
#define be32_to_cpu(x) be32toh(x)
#define cpu_to_be32(x) htobe32(x)
#define be64_to_cpu(x) be64toh(x)
#define cpu_to_be64(x) htobe64(x)

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
    u32 cra_flags;
    unsigned int cra_blocksize, cra_ctxsize, cra_alignmask;
    void *cra_module;
    union { struct cipher_alg cipher; } cra_u;
};
#define CRYPTO_ALG_TYPE_CIPHER 1
#define THIS_MODULE NULL
#define __init
#define __exit
#define subsys_initcall(f)
#define module_init(f)
#define module_exit(f)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_ALIAS_CRYPTO(x)
static inline int crypto_register_alg(struct crypto_alg *alg) { (void)alg; return 0; }
static inline void crypto_unregister_alg(struct crypto_alg *alg) { (void)alg; }
#endif
