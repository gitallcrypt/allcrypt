/* gost-engine's CryptoPro key wrap as a witness: `wrap <set> <kek hex>
 * <ukm hex> <cek hex>` per line - a 32 byte key encryption key, an 8 byte
 * UKM and a 32 byte key to wrap - gives keyWrapCryptoPro's 44 bytes
 * (UKM, encrypted key, MAC) in hex, and `diversify <set> <kek hex> <ukm
 * hex>` keyDiversifyCryptoPro's 32. <set> is test, a, b, c, d or z: the
 * GOST 28147-89 parameter set the context is initialised with, as
 * gost-engine's key transport initialises it from the message's
 * encryptionParamSet. The inputs and output are in exact-size heap
 * buffers at an offset of OFFSET bytes (0 unless -DOFFSET=1). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gost89.h"
#include "gost_keywrap.h"

#ifndef OFFSET
#define OFFSET 0
#endif

static int unhex(const char *s, unsigned char *out, size_t want) {
    if (strlen(s) != 2 * want) return 0;
    for (size_t i = 0; i < want; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (unsigned char)v;
    }
    return 1;
}

static const gost_subst_block *named(const char *set) {
    if (!strcmp(set, "test")) return &Gost28147_TestParamSet;
    if (!strcmp(set, "a")) return &Gost28147_CryptoProParamSetA;
    if (!strcmp(set, "b")) return &Gost28147_CryptoProParamSetB;
    if (!strcmp(set, "c")) return &Gost28147_CryptoProParamSetC;
    if (!strcmp(set, "d")) return &Gost28147_CryptoProParamSetD;
    if (!strcmp(set, "z")) return &Gost28147_TC26ParamSetZ;
    return NULL;
}

int main(void) {
    char line[512], op[16], set[16], k[80], u[32], c[80];
    while (fgets(line, sizeof line, stdin)) {
        int fields = sscanf(line, "%15s %15s %79s %31s %79s", op, set, k, u, c);
        const gost_subst_block *box = fields >= 4 ? named(set) : NULL;
        unsigned char *kbuf = malloc(32 + OFFSET), *ubuf = malloc(8 + OFFSET);
        unsigned char *cbuf = malloc(32 + OFFSET), *obuf = malloc(44 + OFFSET);
        unsigned char *kek = kbuf + OFFSET, *ukm = ubuf + OFFSET, *cek = cbuf + OFFSET;
        unsigned char *out = obuf + OFFSET;
        gost_ctx ctx;
        if (!box || !unhex(k, kek, 32) || !unhex(u, ukm, 8)) {
            puts("error request");
        } else if (!strcmp(op, "diversify") && fields == 4) {
            gost_init(&ctx, box);
            keyDiversifyCryptoPro(&ctx, kek, ukm, out);
            for (int i = 0; i < 32; i++) printf("%02x", out[i]);
            putchar('\n');
        } else if (!strcmp(op, "wrap") && fields == 5 && unhex(c, cek, 32)) {
            gost_init(&ctx, box);
            keyWrapCryptoPro(&ctx, kek, ukm, cek, out);
            for (int i = 0; i < 44; i++) printf("%02x", out[i]);
            putchar('\n');
        } else {
            puts("error request");
        }
        fflush(stdout);
        free(kbuf);
        free(ubuf);
        free(cbuf);
        free(obuf);
    }
    return 0;
}
