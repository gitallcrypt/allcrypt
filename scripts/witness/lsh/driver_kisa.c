/* KISA's LSH reference (no_arch), as the distribution's ZIP has it:
 * lshWIDTH_BITS through LSH_MAKE_TYPE, any whole number of bytes up to the
 * width. See ../oldhashes/slurp.h. The data goes in in pieces of 1, 2,
 * 3 ... bytes. */
#include "slurp.h"
#include "lsh.h"

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned width, bits;
    char rest;
    if (sscanf(name, "lsh%u_%u%c", &width, &bits, &rest) != 2 || bits % 8 || !bits) return 0;
    if ((width != 256 || bits > 256) && (width != 512 || bits > 512)) return 0;
    union LSH_Context ctx;
    if (lsh_init(&ctx, LSH_MAKE_TYPE(width == 512, bits)) != LSH_SUCCESS) return 0;
    for (size_t at = 0, step = 1; at < len; at += step, step++)
        if (lsh_update(&ctx, data + at, 8 * (step < len - at ? step : len - at)) != LSH_SUCCESS)
            return 0;
    if (lsh_final(&ctx, out) != LSH_SUCCESS) return 0;
    return bits / 8;
}
