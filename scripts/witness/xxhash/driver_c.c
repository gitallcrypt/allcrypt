/* The reference xxHash, xxhash.h 0.8.3, compiled whole into this file.
 * One request per line on stdin, "NAME KEY PATH": NAME is xxh32, xxh64,
 * xxh3 or xxh128; KEY is "seed:" and sixteen hex digits, or "secret:"
 * and the path of a file holding the secret, which only xxh3 and xxh128
 * take. Answered with the canonical (big endian) hash of the file's
 * bytes as lowercase hex, or "error". The data goes in through the
 * streaming interface in pieces of 1, 2, 3 ... bytes. */
#define XXH_INLINE_ALL
#include "xxhash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
    *len = fread(buf, 1, n, f);
    fclose(f);
    return buf;
}

#define PIECES(update, state) \
    for (size_t at = 0, step = 1; at < len; at += step, step++) \
        update(state, data + at, step < len - at ? step : len - at)

/* Returns the canonical length written to out, or 0. */
static size_t hash(const char *name, unsigned long long seed, const unsigned char *secret,
                   size_t secret_len, const unsigned char *data, size_t len,
                   unsigned char *out) {
    if (!strcmp(name, "xxh32") && !secret && seed <= 0xffffffffULL) {
        XXH32_state_t *s = XXH32_createState();
        XXH32_reset(s, (XXH32_hash_t)seed);
        PIECES(XXH32_update, s);
        XXH32_canonicalFromHash((XXH32_canonical_t *)out, XXH32_digest(s));
        XXH32_freeState(s);
        return 4;
    }
    if (!strcmp(name, "xxh64") && !secret) {
        XXH64_state_t *s = XXH64_createState();
        XXH64_reset(s, seed);
        PIECES(XXH64_update, s);
        XXH64_canonicalFromHash((XXH64_canonical_t *)out, XXH64_digest(s));
        XXH64_freeState(s);
        return 8;
    }
    if (!strcmp(name, "xxh3")) {
        XXH3_state_t *s = XXH3_createState();
        if (secret ? XXH3_64bits_reset_withSecret(s, secret, secret_len)
                   : XXH3_64bits_reset_withSeed(s, seed)) return 0;
        PIECES(XXH3_64bits_update, s);
        XXH64_canonicalFromHash((XXH64_canonical_t *)out, XXH3_64bits_digest(s));
        XXH3_freeState(s);
        return 8;
    }
    if (!strcmp(name, "xxh128")) {
        XXH3_state_t *s = XXH3_createState();
        if (secret ? XXH3_128bits_reset_withSecret(s, secret, secret_len)
                   : XXH3_128bits_reset_withSeed(s, seed)) return 0;
        PIECES(XXH3_128bits_update, s);
        XXH128_canonicalFromHash((XXH128_canonical_t *)out, XXH3_128bits_digest(s));
        XXH3_freeState(s);
        return 16;
    }
    return 0;
}

int main(void) {
    char line[8192], name[64], key[4000], path[4000];
    while (fgets(line, sizeof line, stdin)) {
        size_t len, secret_len = 0, n = 0;
        unsigned long long seed = 0;
        unsigned char *data, *secret = NULL, out[16];
        if (sscanf(line, "%63s %3999s %3999s", name, key, path) != 3
                || !(data = slurp(path, &len))) {
            printf("error\n");
            continue;
        }
        if (!strncmp(key, "seed:", 5) && strlen(key) == 21) {
            seed = strtoull(key + 5, NULL, 16);
            n = hash(name, seed, NULL, 0, data, len, out);
        } else if (!strncmp(key, "secret:", 7) && (secret = slurp(key + 7, &secret_len))) {
            n = hash(name, 0, secret, secret_len, data, len, out);
            free(secret);
        }
        if (!n) printf("error");
        for (size_t i = 0; i < n; i++) printf("%02x", out[i]);
        printf("\n");
        fflush(stdout);
        free(data);
    }
    return 0;
}
