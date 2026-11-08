/* ISAAC-64 as a witness: Bob Jenkins's isaac64.c (public domain) as
 * Math::Int64 adapts it into one header, isaac64.h (salva/p5-Math-Int64),
 * its state in a struct and its words uint64_t. randinit(is, 1) over the
 * seed puts block 0 in randrsl; each isaac64(is) after it, the next. 64
 * bit requests only. */
#include "driver.h"
#include "isaac64.h"

static const char *w_blocks(int bits, const void *seed, size_t first, size_t count,
                            uint8_t *out) {
    if (bits != 64) return "error unsupported";
    isaac64_state_t *is = heap(sizeof *is);
    memcpy(is->randrsl, seed, sizeof is->randrsl);
    randinit(is, 1);
    for (size_t b = 0; b < first + count; b++) {
        if (b > 0) isaac64(is);
        if (b < first) continue;
        for (int i = 0; i < WORDS; i++)
            put_word(out + ((b - first) * WORDS + i) * 8, is->randrsl[i], 8);
    }
    release(is);
    return 0;
}
