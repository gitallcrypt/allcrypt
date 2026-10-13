/* The BLAKE3 team's C implementation, portable code only. Requests are
 * MODE/LENGTH/SEEK, MODE being "hash", "keyed=KEY" or "derive=CONTEXT"
 * with the key or context in hex: LENGTH bytes of output from byte SEEK.
 * See ../oldhashes/slurp.h. The data goes in in pieces of 1, 2, 3 ...
 * bytes. */
#define OUT_MAX 4096
#include "slurp.h"
#include "blake3.h"

static int unhex(const char *hex, size_t n, unsigned char *out) {
    for (size_t i = 0; i < n; i++)
        if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1) return 0;
    return 1;
}

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    char mode[200];
    size_t length;
    unsigned long long seek;
    if (sscanf(name, "%199[^/]/%zu/%llu", mode, &length, &seek) != 3 || !length || length > OUT_MAX)
        return 0;
    blake3_hasher hasher;
    if (!strcmp(mode, "hash")) {
        blake3_hasher_init(&hasher);
    } else if (!strncmp(mode, "keyed=", 6) && strlen(mode) == 6 + 64) {
        unsigned char key[32];
        if (!unhex(mode + 6, 32, key)) return 0;
        blake3_hasher_init_keyed(&hasher, key);
    } else if (!strncmp(mode, "derive=", 7) && strlen(mode) % 2 == 1) {
        unsigned char context[100];
        size_t n = (strlen(mode) - 7) / 2;
        if (!unhex(mode + 7, n, context)) return 0;
        blake3_hasher_init_derive_key_raw(&hasher, context, n);
    } else {
        return 0;
    }
    for (size_t at = 0, step = 1; at < len; at += step, step++)
        blake3_hasher_update(&hasher, data + at, step < len - at ? step : len - at);
    blake3_hasher_finalize_seek(&hasher, seek, out, length);
    return length;
}
