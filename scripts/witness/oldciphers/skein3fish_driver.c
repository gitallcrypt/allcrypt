/* Skein3Fish's Threefish (wernerd/Skein3Fish: the Skein team's Threefish
 * with a block cipher interface, in C) as a witness. BITS is 256, 512 or
 * 1024. A key is the key alone, with a tweak of zero, or the key followed
 * by the 16 byte tweak; the API takes both as little-endian words. */
#include <stdint.h>
#include <string.h>
#include <threefishApi.h>

#define WORDS (BITS / 64)

static ThreefishKey_t ctx;

static uint64_t word(const unsigned char *p) {
    uint64_t w = 0;
    for (int i = 7; i >= 0; i--) w = w << 8 | p[i];
    return w;
}

static int set_key(const unsigned char *key, size_t len) {
    uint64_t k[WORDS], t[2] = {0, 0};
    if (len != 8 * WORDS && len != 8 * WORDS + 16) return -1;
    for (int i = 0; i < WORDS; i++) k[i] = word(key + 8 * i);
    if (len > 8 * WORDS) {
        t[0] = word(key + 8 * WORDS);
        t[1] = word(key + 8 * WORDS + 8);
    }
    threefishSetKey(&ctx, (ThreefishSize_t)BITS, k, t);
    return 0;
}
static void encrypt(unsigned char *b) {
    unsigned char out[8 * WORDS];
    threefishEncryptBlockBytes(&ctx, b, out);
    memcpy(b, out, sizeof out);
}
static void decrypt(unsigned char *b) {
    unsigned char out[8 * WORDS];
    threefishDecryptBlockBytes(&ctx, b, out);
    memcpy(b, out, sizeof out);
}
static size_t block_size(void) { return 8 * WORDS; }

#include "driver.h"
