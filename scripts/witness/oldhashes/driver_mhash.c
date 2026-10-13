/* mhash 0.9.9's HAVAL (all fifteen, through havalInit), Snefru-128 and
 * -256, and Tiger, which it writes with each 64 bit word big endian; see
 * slurp.h. The data goes in in pieces of 1, 2, 3 ... bytes. */
#include "slurp.h"
#include "libdefs.h"
#include "mhash_haval.h"
#include "mhash_snefru.h"
#include "mhash_tiger.h"

#define FEED(update, cc) \
    for (size_t at = 0, step = 1; at < len; at += step, step++) \
        update(cc, data + at, step < len - at ? step : len - at)

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned bits, passes;
    if (sscanf(name, "haval%u_%u", &bits, &passes) == 2) {
        havalContext cc;
        if (havalInit(&cc, passes, bits) != MUTILS_OK) return 0;
        FEED(havalUpdate, &cc);
        havalFinal(&cc, out);
        return bits / 8;
    }
    if (!strcmp(name, "tiger")) {
        struct tiger_ctx cc;
        tiger_init(&cc);
        FEED(tiger_update, &cc);
        tiger_final(&cc);
        tiger_digest(&cc, out);
        return 24;
    }
    if (!strcmp(name, "snefru128")) {
        struct snefru_ctx cc;
        snefru_init(&cc);
        FEED(snefru128_update, &cc);
        snefru128_final(&cc);
        snefru128_digest(&cc, out);
        return 16;
    }
    if (!strcmp(name, "snefru256")) {
        struct snefru_ctx cc;
        snefru_init(&cc);
        FEED(snefru256_update, &cc);
        snefru256_final(&cc);
        snefru256_digest(&cc, out);
        return 32;
    }
    /* snefruBITS_length_N, as in driver_rhash.c. */
    unsigned long long n;
    char which[4];
    if (sscanf(name, "snefru%3[0-9]_length_%llu", which, &n) == 2) {
        struct snefru_ctx cc;
        int is128 = !strcmp(which, "128");
        if (!is128 && strcmp(which, "256")) return 0;
        if (n % (is128 ? 48 : 32)) return 0;
        snefru_init(&cc);
        cc.hashlen = n * 8;
        if (is128) { snefru128_final(&cc); snefru128_digest(&cc, out); return 16; }
        snefru256_final(&cc);
        snefru256_digest(&cc, out);
        return 32;
    }
    return 0;
}
