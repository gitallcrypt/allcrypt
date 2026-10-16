/* An eSTREAM submission, through its ECRYPT interface, as a witness:
 * `stream <cipher> <key hex> <iv hex> <length>` per line, "-" for an
 * empty IV; the first <length> bytes of keystream in hex, or "error ...".
 * Built once per submission with -DCIPHER='"name"'. The key and IV are
 * given to it in exact-size heap buffers, at an offset of OFFSET bytes
 * (0 unless -DOFFSET=1), and the keystream is zeros encrypted in one
 * call, as the ECRYPT interface allows a length that is not a whole block
 * only on the last, and not every submission has ECRYPT_keystream_bytes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ecrypt-sync.h"

#ifndef OFFSET
#define OFFSET 0
#endif

static size_t unhex(const char *s, unsigned char *out, size_t max) {
    size_t n = 0;
    if (strcmp(s, "-") == 0) return 0;
    while (s[0] && s[1] && n < max) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

int main(void) {
    static char line[1 << 16];
    ECRYPT_init();
    while (fgets(line, sizeof line, stdin)) {
        char op[16], cipher[32], k[256], v[256];
        unsigned long n;
        unsigned char kbuf[64], ivbuf[64];
        if (sscanf(line, "%15s %31s %255s %255s %lu", op, cipher, k, v, &n) != 5
            || strcmp(op, "stream") != 0) {
            puts("error request");
            fflush(stdout);
            continue;
        }
        if (strcmp(cipher, CIPHER) != 0) {
            puts("error unsupported");
            fflush(stdout);
            continue;
        }
        size_t klen = unhex(k, kbuf, sizeof kbuf), ivlen = unhex(v, ivbuf, sizeof ivbuf);
        unsigned char *key = malloc(klen + OFFSET), *iv = malloc(ivlen + OFFSET + 1);
        unsigned char *zero = calloc(n + OFFSET + 1, 1), *out = malloc(n + OFFSET + 1);
        memcpy(key + OFFSET, kbuf, klen);
        memcpy(iv + OFFSET, ivbuf, ivlen);
        ECRYPT_ctx ctx;
        ECRYPT_keysetup(&ctx, key + OFFSET, (u32)(klen * 8), (u32)(ivlen * 8));
        if (ivlen) ECRYPT_ivsetup(&ctx, iv + OFFSET);
        ECRYPT_encrypt_bytes(&ctx, zero + OFFSET, out + OFFSET, (u32)n);
        for (unsigned long i = 0; i < n; i++) printf("%02x", out[OFFSET + i]);
        putchar('\n');
        fflush(stdout);
        free(key);
        free(iv);
        free(out);
        free(zero);
    }
    return 0;
}
