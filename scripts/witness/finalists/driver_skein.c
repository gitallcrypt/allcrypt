/* The Skein team's own code (SUPERCOP's skein512512/opt, which has all
 * three widths): skeinSTATE_BITS, any whole number of bytes, through
 * Skein_256_Init, Skein_512_Init and Skein1024_Init. See
 * ../oldhashes/slurp.h. The data goes in in pieces of 1, 2, 3 ... bytes. */
/* skein1024_2056 is 257 bytes, and the requests go up to 512 * 8 bits:
 * the default of 64 is Skein-512's output, and Final writes the whole
 * length asked for into this buffer. */
#define OUT_MAX 512
#include "slurp.h"
#include "skein.h"

#define RUN(W, ctx_t) do { \
        ctx_t cc; \
        if (Skein_##W##_Init(&cc, bits) != SKEIN_SUCCESS) return 0; \
        for (size_t at = 0, step = 1; at < len; at += step, step++) \
            Skein_##W##_Update(&cc, data + at, step < len - at ? step : len - at); \
        Skein_##W##_Final(&cc, out); \
    } while (0)
#define Skein_1024_Init Skein1024_Init
#define Skein_1024_Update Skein1024_Update
#define Skein_1024_Final Skein1024_Final

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned state, bits;
    char rest;
    if (sscanf(name, "skein%u_%u%c", &state, &bits, &rest) != 2 || bits % 8 || !bits || bits > 512 * 8)
        return 0;
    if (state == 256) RUN(256, Skein_256_Ctxt_t);
    else if (state == 512) RUN(512, Skein_512_Ctxt_t);
    else if (state == 1024) RUN(1024, Skein1024_Ctxt_t);
    else return 0;
    return bits / 8;
}
