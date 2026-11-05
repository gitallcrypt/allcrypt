/* The Grain v1 reference implementation (Hell, Johansson and Meier's
 * grain.c, one bit per int) as a witness: `stream grainv1 <key hex> <iv
 * hex> <length>` per line; the first <length> bytes of keystream in hex,
 * or "error ...". The copy this builds against ends in a main() of its
 * own that does not compile; build.sh cuts the file at it and this
 * includes what is left, the cipher. Its interface takes the key, IV and
 * keystream as arrays of int, one byte each; they are given exact-size
 * heap arrays. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "grain_cipher.c"

static size_t unhex(const char *s, int *out, size_t max) {
    size_t n = 0;
    while (s[0] && s[1] && n < max) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (int)v;
        s += 2;
    }
    return n;
}

int main(void) {
    static char line[1 << 16];
    while (fgets(line, sizeof line, stdin)) {
        char op[16], cipher[32], k[256], v[256];
        unsigned long n;
        int kbuf[64], ivbuf[64];
        if (sscanf(line, "%15s %31s %255s %255s %lu", op, cipher, k, v, &n) != 5
            || strcmp(op, "stream") != 0) {
            puts("error request");
            fflush(stdout);
            continue;
        }
        if (strcmp(cipher, "grainv1") != 0) {
            puts("error unsupported");
            fflush(stdout);
            continue;
        }
        size_t klen = unhex(k, kbuf, 64), ivlen = unhex(v, ivbuf, 64);
        if (klen != 10 || ivlen != 8) {
            puts("error key or iv length");
            fflush(stdout);
            continue;
        }
        int *key = malloc(klen * sizeof(int)), *iv = malloc(ivlen * sizeof(int));
        int *out = malloc((n + 1) * sizeof(int));
        memcpy(key, kbuf, klen * sizeof(int));
        memcpy(iv, ivbuf, ivlen * sizeof(int));
        grain g;
        keysetup(&g, key, 80, 64);
        ivsetup(&g, iv);
        keystream_bytes(&g, out, (int)n);
        for (unsigned long i = 0; i < n; i++) printf("%02x", out[i] & 0xff);
        putchar('\n');
        fflush(stdout);
        free(key);
        free(iv);
        free(out);
    }
    return 0;
}
