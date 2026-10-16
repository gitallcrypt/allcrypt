/* MISTY1 as Crypt::Misty1 1.1.3 computes it (gitpan/Crypt-Misty1), as a
 * witness: its _misty1.c, an implementation of RFC 2994 with a main()
 * of its own that is renamed out of the way, compiled as fetched. */
#include <string.h>
#define main misty1_reference_main
#include "_misty1.c"
#undef main

static unsigned int key_state[32];

static int set_key(const unsigned char *key, size_t len) {
    if (len != 16) return -1;
    keyinit((unsigned char *)key, key_state);
    return 0;
}
static void encrypt(unsigned char *b) {
    unsigned char out[8];
    misty1_encrypt(key_state, b, out);
    memcpy(b, out, 8);
}
static void decrypt(unsigned char *b) {
    unsigned char out[8];
    misty1_decrypt(key_state, b, out);
    memcpy(b, out, 8);
}
static size_t block_size(void) { return 8; }

#include "driver.h"
