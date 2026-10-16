/* libtomcrypt's Rabbit and SOSEMANUK (develop branch) as a witness:
 * `stream <cipher> <key hex> <iv hex> <length>` per line, "-" for an
 * empty IV; the first <length> bytes of keystream in hex, or "error ...".
 * Ciphers: rabbit (16 byte key, no IV), rabbit-iv (8 byte IV) and
 * sosemanuk (1 to 32 byte key, 16 byte IV). The keystream is asked for
 * in pieces of 1, 2, 3 .. bytes; the key, IV and keystream are in
 * exact-size heap buffers at an offset of OFFSET bytes (0 unless
 * -DOFFSET=1). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

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
    while (fgets(line, sizeof line, stdin)) {
        char op[16], cipher[16], k[256], v[256];
        unsigned long n;
        unsigned char kbuf[64], ivbuf[64];
        if (sscanf(line, "%15s %15s %255s %255s %lu", op, cipher, k, v, &n) != 5
            || strcmp(op, "stream") != 0) {
            puts("error request");
            fflush(stdout);
            continue;
        }
        size_t klen = unhex(k, kbuf, sizeof kbuf), ivlen = unhex(v, ivbuf, sizeof ivbuf);
        unsigned char *key = malloc(klen + OFFSET + 1), *iv = malloc(ivlen + OFFSET + 1);
        unsigned char *out = malloc(n + OFFSET + 1);
        memcpy(key + OFFSET, kbuf, klen);
        memcpy(iv + OFFSET, ivbuf, ivlen);
        int err = CRYPT_OK, known = 1;
        if (strcmp(cipher, "rabbit") == 0 || strcmp(cipher, "rabbit-iv") == 0) {
            rabbit_state st;
            int with_iv = strcmp(cipher, "rabbit-iv") == 0;
            if (klen != 16 || (with_iv ? ivlen != 8 : ivlen != 0)) err = CRYPT_INVALID_ARG;
            if (err == CRYPT_OK) err = rabbit_setup(&st, key + OFFSET, klen);
            if (err == CRYPT_OK && with_iv) err = rabbit_setiv(&st, iv + OFFSET, ivlen);
            for (unsigned long at = 0, piece = 1; err == CRYPT_OK && at < n; piece++) {
                unsigned long take = piece < n - at ? piece : n - at;
                err = rabbit_keystream(&st, out + OFFSET + at, take);
                at += take;
            }
        } else if (strcmp(cipher, "sosemanuk") == 0) {
            sosemanuk_state st;
            if (klen < 1 || klen > 32 || ivlen != 16) err = CRYPT_INVALID_ARG;
            if (err == CRYPT_OK) err = sosemanuk_setup(&st, key + OFFSET, klen);
            if (err == CRYPT_OK) err = sosemanuk_setiv(&st, iv + OFFSET, ivlen);
            for (unsigned long at = 0, piece = 1; err == CRYPT_OK && at < n; piece++) {
                unsigned long take = piece < n - at ? piece : n - at;
                err = sosemanuk_keystream(&st, out + OFFSET + at, take);
                at += take;
            }
        } else {
            known = 0;
        }
        if (!known) puts("error unsupported");
        else if (err != CRYPT_OK) printf("error %s\n", error_to_string(err));
        else {
            for (unsigned long i = 0; i < n; i++) printf("%02x", out[OFFSET + i]);
            putchar('\n');
        }
        free(out);
        free(key);
        free(iv);
        fflush(stdout);
    }
    return 0;
}
