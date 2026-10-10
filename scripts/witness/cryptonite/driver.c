/* cryptonite-witness BLOCK_BITS OPERATION
 *
 * cryptonite's DSTU 7624 (Kalyna) modes over stdin: one request per
 * line of space-separated hex fields ("-" for empty), one hex line out
 * or "error: <code>". A fresh context per line, the standard S-boxes.
 *
 *   ecb  KEY DATA          ctr  KEY IV DATA       cbc  KEY IV DATA
 *   cfb  KEY IV DATA       ofb  KEY IV DATA       (whole-block feedback)
 *   cmac KEY QBYTES DATA   kw   KEY DATA          unkw KEY DATA
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dstu7624.h"

static ByteArray *field(char *s) {
    static uint8_t buf[1 << 16];
    size_t n = 0;
    if (strcmp(s, "-") != 0)
        for (; s[0] && s[1]; s += 2) { unsigned v; sscanf(s, "%2x", &v); buf[n++] = (uint8_t)v; }
    return ba_alloc_from_uint8(buf, n);
}

int main(int argc, char **argv) {
    size_t block = (size_t)atoi(argv[1]) / 8;
    const char *op = argv[2];
    static char line[1 << 18];
    while (fgets(line, sizeof line, stdin)) {
        char *f[4] = {0};
        int nf = 0;
        for (char *t = strtok(line, " \n"); t && nf < 4; t = strtok(NULL, " \n")) f[nf++] = t;
        Dstu7624Ctx *ctx = dstu7624_alloc(DSTU7624_SBOX_1);
        ByteArray *out = NULL;
        int ret;
        ByteArray *key = field(f[0]);
        if (!strcmp(op, "ecb")) {
            ret = dstu7624_init_ecb(ctx, key, block);
            if (!ret) ret = dstu7624_encrypt(ctx, field(f[1]), &out);
        } else if (!strcmp(op, "ctr") || !strcmp(op, "cbc") || !strcmp(op, "ofb") || !strcmp(op, "cfb")) {
            ByteArray *iv = field(f[1]);
            ret = !strcmp(op, "ctr") ? dstu7624_init_ctr(ctx, key, iv)
                : !strcmp(op, "cbc") ? dstu7624_init_cbc(ctx, key, iv)
                : !strcmp(op, "ofb") ? dstu7624_init_ofb(ctx, key, iv)
                : dstu7624_init_cfb(ctx, key, iv, block);
            if (!ret) ret = dstu7624_encrypt(ctx, field(f[2]), &out);
        } else if (!strcmp(op, "cmac")) {
            ret = dstu7624_init_cmac(ctx, key, block, (size_t)atoi(f[1]));
            if (!ret) ret = dstu7624_update_mac(ctx, field(nf > 2 ? f[2] : "-"));
            if (!ret) ret = dstu7624_final_mac(ctx, &out);
        } else if (!strcmp(op, "kw") || !strcmp(op, "unkw")) {
            ret = dstu7624_init_kw(ctx, key, block);
            if (!ret) ret = !strcmp(op, "kw") ? dstu7624_encrypt(ctx, field(f[1]), &out)
                                              : dstu7624_decrypt(ctx, field(f[1]), &out);
        } else {
            ret = -1;
        }
        if (ret) printf("error: %d\n", ret);
        else {
            for (size_t i = 0; i < ba_get_len(out); i++) printf("%02x", ba_get_buf(out)[i]);
            printf("\n");
        }
        dstu7624_free(ctx);
    }
    return 0;
}
