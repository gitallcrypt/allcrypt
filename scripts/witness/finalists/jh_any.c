/* SUPERCOP's JH (crypto_hash/round3jh256/simple, from the designer's
 * bitsliced code), included whole so that its compression function can
 * be reached: jh_ref_any hashes at any of JH's four lengths, where the
 * file itself has only JH-256's starting value. The starting value is
 * what the specification says it is - F8 of an all-zero block on a
 * state holding the length, big endian, in its first two bytes - and
 * jh_ref_check_iv compares that with the file's own for 256 bits. */
#include "hash.c"

static void start(uint64 x[8][2], int bits) {
    unsigned char block[64] = {0};
    memset(x, 0, 128);
    ((unsigned char *)x)[0] = bits >> 8;
    ((unsigned char *)x)[1] = bits & 0xff;
    F8(x, block);
}

int jh_ref_check_iv(void) {
    uint64 x[8][2];
    start(x, 256);
    return memcmp(x, iv, 128);
}

int jh_ref_any(int bits, unsigned char *out, const unsigned char *in, unsigned long long inlen) {
    uint64 x[8][2];
    unsigned char buffer[64];
    unsigned long long length = inlen * 8;
    int i;
    if (bits != 224 && bits != 256 && bits != 384 && bits != 512) return -1;
    start(x, bits);
    /* The rest is crypto_hash's, with the output length a parameter. */
    while (inlen >= 64) {
        F8(x, in);
        in += 64;
        inlen -= 64;
    }
    memset(buffer, 0, 64);
    if (inlen > 0) {
        memcpy(buffer, in, inlen);
        buffer[inlen] |= 128;
        F8(x, buffer);
        memset(buffer, 0, 64);
    } else {
        buffer[0] = 128;
    }
    for (i = 0; i < 8; i++) buffer[63 - i] = (length >> (8 * i)) & 0xff;
    F8(x, buffer);
    memcpy(out, (unsigned char *)x + 128 - bits / 8, bits / 8);
    return 0;
}
