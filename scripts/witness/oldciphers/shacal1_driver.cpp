// SHACAL-1 from a SHA-1 compression function, as a witness: the block is
// the chaining value, the key the message block, and the encryption is
// the compression's result less the chaining value it started from,
// word by word - the feed-forward taken off. With CRYPTOPP, Crypto++
// 8.9.0's SHA1::Transform; otherwise OpenSSL's SHA1_Transform. A key of
// 16 to 64 bytes is zero-padded to 64, as SHACAL defines it.
//
// The compression function has no inverse, so this witness encrypts
// only: a decryption request ends the program with an error.
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#ifdef CRYPTOPP
#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#include "algparam.h"
#include "sha.h"
// The two definitions cryptopp_driver.cpp gives, for the same reason.
namespace CryptoPP {
bool AssignIntToInteger(const std::type_info &, void *, const void *) { return false; }
template <> std::string IntToString<word64>(word64 value, unsigned int) {
    return std::to_string(value);
}
}
static void compress(uint32_t state[5], const uint32_t w[16]) {
    CryptoPP::SHA1::Transform(state, w);
}
#else
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
static void compress(uint32_t state[5], const uint32_t w[16]) {
    SHA_CTX ctx;
    std::memset(&ctx, 0, sizeof ctx);
    ctx.h0 = state[0]; ctx.h1 = state[1]; ctx.h2 = state[2]; ctx.h3 = state[3]; ctx.h4 = state[4];
    unsigned char block[64];
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 4; j++) block[4 * i + j] = (unsigned char)(w[i] >> (24 - 8 * j));
    SHA1_Transform(&ctx, block);
    state[0] = ctx.h0; state[1] = ctx.h1; state[2] = ctx.h2; state[3] = ctx.h3; state[4] = ctx.h4;
}
#endif

static uint32_t key_words[16];

static uint32_t word(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static int set_key(const unsigned char *key, size_t len) {
    unsigned char padded[64] = {0};
    if (len < 16 || len > 64) return -1;
    std::memcpy(padded, key, len);
    for (int i = 0; i < 16; i++) key_words[i] = word(padded + 4 * i);
    return 0;
}
static void encrypt(unsigned char *b) {
    uint32_t start[5], state[5];
    for (int i = 0; i < 5; i++) start[i] = state[i] = word(b + 4 * i);
    compress(state, key_words);
    for (int i = 0; i < 5; i++) {
        uint32_t v = state[i] - start[i];
        for (int j = 0; j < 4; j++) b[4 * i + j] = (unsigned char)(v >> (24 - 8 * j));
    }
}
static void decrypt(unsigned char *) {
    std::fprintf(stderr, "this witness encrypts only\n");
    std::exit(2);
}
static size_t block_size(void) { return 20; }

#include "driver.h"
