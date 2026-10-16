/* A libtomcrypt 1.18.2 cipher as a witness, as ../nessie/ltc_driver.c,
 * with a round count: DESC is its descriptor and SOURCE its file, both
 * given on the command line, e.g.
 *     -DDESC=safer_k64_desc -DSOURCE='"safer.c"'
 * and the environment's ROUNDS, when set, is passed to the setup; unset
 * or 0 is the descriptor's default. */
#include <stdlib.h>
#include "tomcrypt.h"
#include SOURCE

static symmetric_key key_state;

static int set_key(const unsigned char *key, size_t len) {
    const char *rounds = getenv("ROUNDS");
    if ((int)len < DESC.min_key_length || (int)len > DESC.max_key_length) return -1;
    return DESC.setup(key, (int)len, rounds ? atoi(rounds) : 0, &key_state) == CRYPT_OK
        ? 0 : -1;
}
static void encrypt(unsigned char *b) {
    unsigned char out[64];
    DESC.ecb_encrypt(b, out, &key_state);
    memcpy(b, out, (size_t)DESC.block_length);
}
static void decrypt(unsigned char *b) {
    unsigned char out[64];
    DESC.ecb_decrypt(b, out, &key_state);
    memcpy(b, out, (size_t)DESC.block_length);
}
static size_t block_size(void) { return (size_t)DESC.block_length; }

#include "driver.h"
