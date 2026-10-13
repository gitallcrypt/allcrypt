/* RHash's Tiger, Tiger2, Snefru-128 and Snefru-256; see slurp.h. The data
 * goes in in pieces of 1, 2, 3 ... bytes. */
#include "slurp.h"
#include "tiger.h"
#include "snefru.h"

#define FEED(update, cc) \
    for (size_t at = 0, step = 1; at < len; at += step, step++) \
        update(cc, data + at, step < len - at ? step : len - at)

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    if (!strcmp(name, "tiger") || !strcmp(name, "tiger2")) {
        tiger_ctx cc;
        if (name[5]) rhash_tiger2_init(&cc); else rhash_tiger_init(&cc);
        FEED(rhash_tiger_update, &cc);
        rhash_tiger_final(&cc, out);
        return tiger_hash_length;
    }
    if (!strcmp(name, "snefru128") || !strcmp(name, "snefru256")) {
        snefru_ctx cc;
        if (name[6] == '1') rhash_snefru128_init(&cc); else rhash_snefru256_init(&cc);
        FEED(rhash_snefru_update, &cc);
        rhash_snefru_final(&cc, out);
        return name[6] == '1' ? snefru128_hash_length : snefru256_hash_length;
    }
    /* snefruBITS_length_N: no data, but the context told it has taken N
     * bytes (a whole number of blocks), so the length block alone shows
     * how a length past 2^32 bits is written. */
    unsigned long long n;
    char which[4];
    if (sscanf(name, "snefru%3[0-9]_length_%llu", which, &n) == 2) {
        snefru_ctx cc;
        if (!strcmp(which, "128")) rhash_snefru128_init(&cc);
        else if (!strcmp(which, "256")) rhash_snefru256_init(&cc);
        else return 0;
        if (n % (64 - cc.digest_length)) return 0;
        cc.length = n;
        rhash_snefru_final(&cc, out);
        return cc.digest_length;
    }
    return 0;
}
