/* Bob Jenkins's ISAAC as a witness: rand.c's portable version, randport.c
 * (1998, public domain), with rand.h and standard.h, as Rust 0.4 vendored
 * them unchanged in src/rt/isaac/. randinit(ctx, TRUE) over the seed puts
 * block 0 in randrsl; each isaac(ctx) after it, the next. 32 bit requests
 * only.
 *
 * standard.h declares ub4, "unsigned 4-byte quantities", as `unsigned long
 * int`, which is 8 bytes on LP64. isaac() masks its words to 32 bits, but
 * randinit's mix() does not, so its right shifts bring the bits above 32
 * back down and the whole state is wrong. `long` is defined away while
 * standard.h is read, which makes ub4 `unsigned int`, the width it names;
 * its ub8 and sb8, which rand.c does not use, become 32 bits too. */
#include "driver.h"
#include <stddef.h>
#define STDIO
#define STDDEF
#define long
#include "standard.h"
#undef long
#include "rand.h"
#include "randport.c"

static const char *w_blocks(int bits, const void *seed, size_t first, size_t count,
                            uint8_t *out) {
    if (bits != 32) return "error unsupported";
    randctx *ctx = heap(sizeof *ctx);
    for (int i = 0; i < WORDS; i++) ctx->randrsl[i] = ((const uint32_t *)seed)[i];
    randinit(ctx, TRUE);
    for (size_t b = 0; b < first + count; b++) {
        if (b > 0) isaac(ctx);
        if (b < first) continue;
        for (int i = 0; i < WORDS; i++)
            put_word(out + ((b - first) * WORDS + i) * 4, ctx->randrsl[i], 4);
    }
    release(ctx);
    return 0;
}
