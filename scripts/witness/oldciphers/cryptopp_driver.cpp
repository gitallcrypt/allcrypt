// A Crypto++ 8.9.0 block cipher as a witness, as
// ../nessie/cryptopp_driver.cpp, with a round count: CLASS is its class
// and HEADER its header, e.g. -DCLASS=SAFER_K -DHEADER='"safer.h"', and
// the environment's ROUNDS, when set and not 0, goes to
// SetKeyWithRounds; otherwise the class's default for the key length.
// The key lengths are the class's own (IsValidKeyLength). With TWEAKED
// defined, for Threefish, a key may also be followed by the 16 byte
// tweak, which goes to SetKey as its Tweak parameter.
#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#include <cstdlib>
#include "algparam.h"
#include HEADER

// Two definitions from integer.cpp, which would bring the whole of
// Crypto++'s big integers in. The only parameter passed is an int round
// count, which is never converted to an Integer; the second formats
// lengths for error messages, which a valid request never produces.
namespace CryptoPP {
bool AssignIntToInteger(const std::type_info &, void *, const void *) { return false; }
template <> std::string IntToString<word64>(word64 value, unsigned int) {
    return std::to_string(value);
}
}

static CryptoPP::CLASS::Encryption enc;
static CryptoPP::CLASS::Decryption dec;

static int set_key(const unsigned char *key, size_t len) {
    const char *text = std::getenv("ROUNDS");
    int rounds = text ? std::atoi(text) : 0;
#ifdef TWEAKED
    if (len == CryptoPP::CLASS::DEFAULT_KEYLENGTH + 16) {
        CryptoPP::AlgorithmParameters tweak = CryptoPP::MakeParameters(
            CryptoPP::Name::Tweak(), CryptoPP::ConstByteArrayParameter(key + len - 16, 16));
        enc.SetKey(key, len - 16, tweak);
        dec.SetKey(key, len - 16, tweak);
        return 0;
    }
#endif
    if (!enc.IsValidKeyLength(len)) return -1;
    try {
        if (rounds) {
            enc.SetKeyWithRounds(key, len, rounds);
            dec.SetKeyWithRounds(key, len, rounds);
        } else {
            enc.SetKey(key, len);
            dec.SetKey(key, len);
        }
    } catch (const CryptoPP::Exception &) {
        return -1;
    }
    return 0;
}
static void encrypt(unsigned char *b) { enc.ProcessBlock(b); }
static void decrypt(unsigned char *b) { dec.ProcessBlock(b); }
static size_t block_size(void) { return CryptoPP::CLASS::BLOCKSIZE; }

#include "driver.h"
