/* The Linux kernel's vmac64, as a witness: `vmac aes <key> <nonce> <msg>
 * 8` per line, hex, "-" for empty; the tag in hex, or "error ...". AES-128,
 * 64 bit tags. The kernel takes a 16 byte nonce with its top bit clear;
 * a shorter one is right-aligned in zeros, which is how the draft's pad
 * derivation reads it. vmac_core.c is vmac.c's VMAC core, extracted by
 * build.sh. */
#include "kvmac_shim.h"
#include "vmac_core.c"
#include <stdio.h>
#include <stdlib.h>

static size_t unhex(const char *s, u8 *out) {
    if (strcmp(s, "-") == 0) return 0;
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
    return n;
}

int main(void) {
    static char line[1 << 24];
    static u8 key[64], nonce[64], msg[1 << 23];
    while (fgets(line, sizeof line, stdin)) {
        char op[8], cipher[16], k[256], n[256], *m = malloc(sizeof line);
        int taglen;
        if (sscanf(line, "%7s %15s %255s %255s %s %d", op, cipher, k, n, m, &taglen) != 6
            || strcmp(op, "vmac")) {
            puts("error request"); fflush(stdout); free(m); continue;
        }
        size_t kl = unhex(k, key), nl = unhex(n, nonce), ml = unhex(m, msg);
        free(m);
        if (strcmp(cipher, "aes") || kl != 16 || taglen != 8) {
            puts("error unsupported"); fflush(stdout); continue;
        }
        if (nl < 1 || nl > 16) { puts("error nonce"); fflush(stdout); continue; }
        u8 full[16] = {0};
        memcpy(full + 16 - nl, nonce, nl);
        struct crypto_cipher aes;
        struct crypto_shash tfm;
        struct shash_desc desc = { .tfm = &tfm };
        struct vmac_tfm_ctx *tctx = crypto_shash_ctx(&tfm);
        tctx->cipher = &aes;
        u8 tag[8];
        /* An exact-size copy, so a read past the message is a sanitizer report. */
        u8 *exact = malloc(ml ? ml : 1);
        memcpy(exact, msg, ml);
        if (vmac_setkey(&tfm, key, 16) || vmac_init(&desc) || vmac_update(&desc, full, 16)
            || vmac_update(&desc, exact, (unsigned int)ml) || vmac_final(&desc, tag)) {
            puts("error refused");
        } else {
            for (int i = 0; i < 8; i++) printf("%02x", tag[i]);
            puts("");
        }
        free(exact);
        fflush(stdout);
    }
    return 0;
}
