/* coreutils's ISAAC and ISAAC-64 as a witness: gl/lib/rand-isaac.c and
 * rand-isaac.h, Colin Plumb's and Paul Eggert's rewrite of Jenkins's code,
 * which shred and sort --random-sort use. One file serves both sizes, chosen by
 * ISAAC_BITS_LOG at compile time; build.sh compiles this twice. The seed
 * goes in the state's m array, isaac_seed mixes it, and each isaac_refill
 * writes a block - the first being randinit's. */
#include "driver.h"
#include "config.h"
#include "rand-isaac.h"

static const char *w_blocks(int bits, const void *seed, size_t first, size_t count,
                            uint8_t *out) {
    if (bits != ISAAC_BITS) return "error unsupported";
    struct isaac_state *s = heap(sizeof *s);
    isaac_word *result = heap(sizeof(isaac_word) * ISAAC_WORDS);
    for (int i = 0; i < WORDS; i++)
        s->m[i] = bits == 32 ? ((const uint32_t *)seed)[i] : ((const uint64_t *)seed)[i];
    isaac_seed(s);
    for (size_t b = 0; b < first + count; b++) {
        isaac_refill(s, result);
        if (b < first) continue;
        for (int i = 0; i < WORDS; i++)
            put_word(out + ((b - first) * WORDS + i) * (bits / 8), result[i], bits / 8);
    }
    release(result);
    release(s);
    return 0;
}
