// A Crypto++ 8.9.0 block cipher as a witness: CLASS is its class and
// HEADER its header, e.g. -DCLASS=SHACAL2 -DHEADER='"shacal2.h"', linked
// with the handful of library files it needs. The key lengths are the
// class's own (IsValidKeyLength).
#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#include "algparam.h"
#include HEADER

// Two definitions from integer.cpp, which would bring the whole of
// Crypto++'s big integers in. The witness passes no parameters, so the
// first is never asked to convert anything; the second formats lengths
// for error messages, which a valid request never produces.
namespace CryptoPP {
bool AssignIntToInteger(const std::type_info &, void *, const void *) { return false; }
template <> std::string IntToString<word64>(word64 value, unsigned int) {
    return std::to_string(value);
}
}

static CryptoPP::CLASS::Encryption enc;
static CryptoPP::CLASS::Decryption dec;

static int set_key(const unsigned char *key, size_t len) {
    if (!enc.IsValidKeyLength(len)) return -1;
    enc.SetKey(key, len);
    dec.SetKey(key, len);
    return 0;
}
static void encrypt(unsigned char *b) { enc.ProcessBlock(b); }
static void decrypt(unsigned char *b) { dec.ProcessBlock(b); }
static size_t block_size(void) { return CryptoPP::CLASS::BLOCKSIZE; }

#include "driver.h"
