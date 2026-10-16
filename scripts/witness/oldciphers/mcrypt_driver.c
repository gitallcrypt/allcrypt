/* A libmcrypt 2.5.8 algorithm module as a witness: SOURCE is its file,
 * given on the command line, e.g. -DSOURCE='"saferplus.c"', compiled
 * against shim/mcrypt/libdefs.h and libmcrypt's own mcrypt_modules.h.
 *
 * The module's functions take the key and the block as arrays of 32-bit
 * words, and each module decides how to read them - some byte-swap on a
 * little-endian machine, some reverse the words. They are handed the
 * bytes as they are in memory, on a little-endian machine, which is what
 * a program calling libmcrypt there does. The key lengths are the
 * module's own list. */
#include SOURCE

static void *key_state;

static int set_key(const unsigned char *key, size_t len) {
    int count, i, allowed = 0;
    const int *sizes = _mcrypt_get_supported_key_sizes(&count);
    word32 words[16] = {0};
    for (i = 0; i < count; i++) allowed |= (size_t)sizes[i] == len;
    if (!allowed || len > sizeof words) return -1;
    if (!key_state) key_state = calloc(1, (size_t)_mcrypt_get_size());
    memcpy(words, key, len);
    return _mcrypt_set_key((void *)key_state, (void *)words, (int)len) ? -1 : 0;
}
static void encrypt(unsigned char *b) {
    word32 words[16];
    memcpy(words, b, (size_t)_mcrypt_get_block_size());
    _mcrypt_encrypt((void *)key_state, (void *)words);
    memcpy(b, words, (size_t)_mcrypt_get_block_size());
}
static void decrypt(unsigned char *b) {
    word32 words[16];
    memcpy(words, b, (size_t)_mcrypt_get_block_size());
    _mcrypt_decrypt((void *)key_state, (void *)words);
    memcpy(b, words, (size_t)_mcrypt_get_block_size());
}
static size_t block_size(void) { return (size_t)_mcrypt_get_block_size(); }

#include "driver.h"
