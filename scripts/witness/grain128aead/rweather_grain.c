/* Grain-128AEADv2 as a witness: Rhys Weatherley's lwc-finalists
 * (rweather/lwc-finalists, 77b23e6), src/combined/grain-aead.c and
 * internal-grain128.c with internal-util.c, the portable C path. One
 * request per line, hex, "-" for empty:
 *
 *   seal <key> <nonce> <ad> <plaintext>
 *
 * The answer is the ciphertext followed by the 8 byte tag, or "error ...".
 * Every buffer handed to the implementation is an exact-size heap copy,
 * at an offset of OFFSET bytes (0 unless -DOFFSET=1). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "grain-aead.h"

#ifndef OFFSET
#define OFFSET 0
#endif

static size_t unhex(const char *s, unsigned char *out) {
    size_t n = 0;
    if (strcmp(s, "-") == 0) return 0;
    while (s[0] && s[1]) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

static unsigned char *copy_in(const unsigned char *src, size_t len) {
    unsigned char *p = malloc(len + OFFSET + 1);
    memcpy(p + OFFSET, src, len);
    return p + OFFSET;
}

int main(void) {
    static char line[1 << 22];
    static char f[4][1 << 21];
    static unsigned char buf[4][1 << 20];
    while (fgets(line, sizeof line, stdin)) {
        char op[16];
        if (sscanf(line, "%15s %s %s %s %s", op, f[0], f[1], f[2], f[3]) != 5
                || strcmp(op, "seal") != 0) {
            puts("error request");
            fflush(stdout);
            continue;
        }
        size_t n[4];
        for (int i = 0; i < 4; i++) n[i] = unhex(f[i], buf[i]);
        if (n[0] != 16 || n[1] != 12) {
            puts("error key or nonce");
            fflush(stdout);
            continue;
        }
        unsigned char *k = copy_in(buf[0], 16), *npub = copy_in(buf[1], 12);
        unsigned char *ad = copy_in(buf[2], n[2]), *m = copy_in(buf[3], n[3]);
        unsigned char *c = copy_in(buf[3], n[3] + GRAIN128_TAG_SIZE);
        size_t clen = 0;
        if (grain128_aead_encrypt(c, &clen, m, n[3], ad, n[2], npub, k) != 0
                || clen != n[3] + GRAIN128_TAG_SIZE) {
            puts("error encrypt");
        } else {
            /* Decrypting it back must give the plaintext. */
            unsigned char *back = copy_in(buf[3], n[3] + 1);
            size_t mlen = 0;
            if (grain128_aead_decrypt(back, &mlen, c, clen, ad, n[2], npub, k) != 0
                    || mlen != n[3] || memcmp(back, m, n[3]) != 0) {
                puts("error decrypt");
            } else {
                for (size_t i = 0; i < clen; i++) printf("%02x", c[i]);
                putchar('\n');
            }
            free(back - OFFSET);
        }
        fflush(stdout);
        free(k - OFFSET); free(npub - OFFSET); free(ad - OFFSET); free(m - OFFSET);
        free(c - OFFSET);
    }
    return 0;
}
