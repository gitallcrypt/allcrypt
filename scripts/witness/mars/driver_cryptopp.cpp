// MARS witness on Crypto++ 8.9.0's mars.cpp; driver_common.h has the
// request format. The key goes to UncheckedSetKey, so every length the
// tweaked key schedule defines - 4 to 14 words - reaches it, not only the
// 16 to 56 bytes in steps of 8 that Crypto++'s SetKey admits; the schedule
// itself is the same code.

// Crypto++ declares its common templates `extern` everywhere and
// instantiates them in one file of the full library that is not built
// here; this file takes that role.
#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#include "algparam.h"
#include "mars.h"

using CryptoPP::byte;

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

struct Witness {
    CryptoPP::MARS::Encryption e;
    CryptoPP::MARS::Decryption d;
    void set_key(const byte *key, size_t len) {
        e.UncheckedSetKey(key, (unsigned)len, CryptoPP::g_nullNameValuePairs);
        d.UncheckedSetKey(key, (unsigned)len, CryptoPP::g_nullNameValuePairs);
    }
    void encrypt(byte *block) { e.ProcessBlock(block); }
    void decrypt(byte *block) { d.ProcessBlock(block); }
};

#include "driver_common.h"
