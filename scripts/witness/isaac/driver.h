/* The request loop shared by the C witnesses of scripts/witness/isaac.
 * One request per line, an answer per line, hex throughout:
 *
 *   isaac <bits> <key> <first> <count>
 *
 * <bits> is 32 (ISAAC) or 64 (ISAAC-64). <key> is up to 1024 bytes (2048
 * for ISAAC-64), or "-" for none; it is read as little-endian words,
 * zero-padded, into the seed array randinit takes with its flag set. The
 * answer is the results arrays of the blocks numbered <first> to
 * <first> + <count> - 1, block 0 being the one randinit computes: each
 * array's words in index order, 0 to 255, each word little endian. Or
 * "error ..." for what the witness cannot do. The implementations take no
 * byte buffers - the seed and the results are words in their own state
 * structs - so nothing is misaligned on purpose; every state and results
 * array is an exact-size heap allocation, for the sanitizers. Each witness
 * defines w_blocks, returning 0 or an error string. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define WORDS 256

/* seed: WORDS words of bits/8 bytes each, the key's words then zeros, as
 * native integers. out: count * WORDS * bits/8 bytes. */
static const char *w_blocks(int bits, const void *seed, size_t first, size_t count,
                            uint8_t *out);

static size_t unhex(const char *s, uint8_t *out, size_t max) {
    size_t n = 0;
    if (strcmp(s, "-") == 0) return 0;
    while (s[0] && s[1] && n < max + 1) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

/* An exact-size heap block, zeroed. */
static void *heap(size_t len) {
    return calloc(len, 1);
}

static void release(void *p) {
    free(p);
}

/* A word written little endian, whatever the machine. */
static void put_word(uint8_t *out, uint64_t w, int bytes) {
    for (int i = 0; i < bytes; i++) out[i] = (uint8_t)(w >> (8 * i));
}

int main(void) {
    static char line[8192];
    static uint8_t key[2049];
    while (fgets(line, sizeof line, stdin)) {
        char op[16], k[4200];
        int bits;
        size_t first, count;
        if (sscanf(line, "%15s %d %4199s %zu %zu", op, &bits, k, &first, &count) != 5
                || strcmp(op, "isaac") != 0 || (bits != 32 && bits != 64)
                || count == 0 || count > 64 || first > 1024) {
            puts("error request");
            fflush(stdout);
            continue;
        }
        int bytes = bits / 8;
        size_t klen = unhex(k, key, sizeof key - 1);
        if (klen > (size_t)WORDS * bytes) {
            puts("error key");
            fflush(stdout);
            continue;
        }
        void *seed = heap((size_t)WORDS * bytes);
        for (size_t i = 0; i < klen; i++) {
            if (bits == 32)
                ((uint32_t *)seed)[i / 4] |= (uint32_t)key[i] << (8 * (i % 4));
            else
                ((uint64_t *)seed)[i / 8] |= (uint64_t)key[i] << (8 * (i % 8));
        }
        size_t n = count * WORDS * bytes;
        uint8_t *out = heap(n);
        const char *err = w_blocks(bits, seed, first, count, out);
        if (err) {
            puts(err);
        } else {
            for (size_t i = 0; i < n; i++) printf("%02x", out[i]);
            putchar('\n');
        }
        fflush(stdout);
        release(seed);
        release(out);
    }
    return 0;
}
