/* A Linux kernel crypto/ cipher as a witness: ALG is its crypto_alg and
 * SOURCE its file, given on the command line, e.g.
 *     -DALG=khazad_alg -DSOURCE='"khazad.c"' */
#include SOURCE

static unsigned char ctx[8192] __attribute__((aligned(16)));
static struct crypto_tfm tfm = { ctx };

static int set_key(const unsigned char *key, size_t len) {
    unsigned char aligned[256] __attribute__((aligned(16)));
    if (len < ALG.cra_u.cipher.cia_min_keysize || len > ALG.cra_u.cipher.cia_max_keysize
            || ALG.cra_ctxsize > sizeof ctx)
        return -1;
    memcpy(aligned, key, len);
    return ALG.cra_u.cipher.cia_setkey(&tfm, aligned, (unsigned int)len) ? -1 : 0;
}
static void encrypt(unsigned char *b) {
    unsigned char in[64] __attribute__((aligned(16))), out[64] __attribute__((aligned(16)));
    memcpy(in, b, ALG.cra_blocksize);
    ALG.cra_u.cipher.cia_encrypt(&tfm, out, in);
    memcpy(b, out, ALG.cra_blocksize);
}
static void decrypt(unsigned char *b) {
    unsigned char in[64] __attribute__((aligned(16))), out[64] __attribute__((aligned(16)));
    memcpy(in, b, ALG.cra_blocksize);
    ALG.cra_u.cipher.cia_decrypt(&tfm, out, in);
    memcpy(b, out, ALG.cra_blocksize);
}
static size_t block_size(void) { return ALG.cra_blocksize; }

#include "driver.h"
