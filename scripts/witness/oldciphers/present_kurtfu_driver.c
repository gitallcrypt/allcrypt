/* kurtfu/present's C PRESENT as a witness. The project fixes its key size
 * at compile time (conf.h), so present.c is compiled twice against
 * shim/present/conf.h, once for 80 bit keys and once, with KEY128, for
 * 128, its two functions renamed present80_ and present128_; the key's
 * length picks one. It takes the key and the block with their bytes in
 * the reverse of the specification's order - the least significant byte
 * first - so this driver reverses each byte string on the way in and the
 * result on the way out, and speaks the specification's order like the
 * other witnesses. present.c reads the block through a uint16_t pointer,
 * so the block it is handed is aligned for one. */
#include <stddef.h>
#include <stdint.h>

void present80_encrypt(uint8_t *p_text, uint8_t const *p_key);
void present80_decrypt(uint8_t *p_text, uint8_t const *p_key);
void present128_encrypt(uint8_t *p_text, uint8_t const *p_key);
void present128_decrypt(uint8_t *p_text, uint8_t const *p_key);

static uint8_t key_reversed[16];
static size_t key_len;

static void reverse(unsigned char *out, const unsigned char *in, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = in[len - 1 - i];
}

static int set_key(const unsigned char *key, size_t len) {
    if (len != 10 && len != 16) return -1;
    reverse(key_reversed, key, len);
    key_len = len;
    return 0;
}
typedef union {
    uint8_t bytes[8];
    uint16_t words[4];
} block_t;

static void encrypt(unsigned char *b) {
    block_t text;
    reverse(text.bytes, b, 8);
    if (key_len == 10) present80_encrypt(text.bytes, key_reversed);
    else present128_encrypt(text.bytes, key_reversed);
    reverse(b, text.bytes, 8);
}
static void decrypt(unsigned char *b) {
    block_t text;
    reverse(text.bytes, b, 8);
    if (key_len == 10) present80_decrypt(text.bytes, key_reversed);
    else present128_decrypt(text.bytes, key_reversed);
    reverse(b, text.bytes, 8);
}
static size_t block_size(void) { return 8; }

#include "driver.h"
