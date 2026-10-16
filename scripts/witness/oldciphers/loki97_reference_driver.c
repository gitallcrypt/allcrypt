/* LOKI97 as its designers' reference C computes it, as Crypt::Loki97
 * 1.0.1 carries it (gitpan/Crypt-Loki97), as a witness: build.sh's copy
 * of its _loki97.c, with each word half declared `unsigned int` rather
 * than `unsigned long`, and its main() renamed out of the way. The NIST
 * API it implements is called with a NULL IV and a key buffer padded
 * with zeros past the key, because cipherInit reads 32 hex digits from
 * a non-NULL IV and makeKey copies its key with strncpy. */
#include <string.h>
#define main loki97_reference_main
#include "_loki97.c"
#undef main

static keyInstance enc_key, dec_key;
static cipherInstance ecb;

static int set_key(const unsigned char *key, size_t len) {
    unsigned char material[MAX_KEY_SIZE + 1] = {0};
    if (len != 16 && len != 24 && len != 32) return -1;
    memcpy(material, key, len);
    if (cipherInit(&ecb, MODE_ECB, NULL) != S_TRUE) return -1;
    if (makeKey(&enc_key, DIR_ENCRYPT, (int)len * 8, material) != S_TRUE) return -1;
    if (makeKey(&dec_key, DIR_DECRYPT, (int)len * 8, material) != S_TRUE) return -1;
    return 0;
}
static void encrypt(unsigned char *b) {
    BYTE out[BLOCK_SIZE];
    blockEncrypt(&ecb, &enc_key, b, 8 * BLOCK_SIZE, out);
    memcpy(b, out, BLOCK_SIZE);
}
static void decrypt(unsigned char *b) {
    BYTE out[BLOCK_SIZE];
    blockDecrypt(&ecb, &dec_key, b, 8 * BLOCK_SIZE, out);
    memcpy(b, out, BLOCK_SIZE);
}
static size_t block_size(void) { return BLOCK_SIZE; }

#include "driver.h"
