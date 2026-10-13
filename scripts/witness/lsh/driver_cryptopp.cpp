// Crypto++ 8.9.0's LSH, without its SIMD code: lshWIDTH_BITS, any whole
// number of bytes up to the width. Crypto++ names five sizes, not
// LSH-512-224, so this goes through its two base classes with the
// algorithm type KISA's reference defines - the width's flag and the
// output length in bytes. See ../oldhashes/slurp.h. The data goes in in
// pieces of 1, 2, 3 ... bytes.

// Crypto++ declares its common templates `extern` everywhere and
// instantiates them in one file of the full library that is not built
// here; this file takes that role.
#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#include "algparam.h"
#include "lsh.h"

// Two definitions from integer.cpp, which would bring the whole of
// Crypto++'s big integers in: nothing here converts a parameter to an
// Integer, and the second formats lengths for error messages.
namespace CryptoPP {
bool AssignIntToInteger(const std::type_info &, void *, const void *) { return false; }
template <> std::string IntToString<word64>(word64 value, unsigned int) {
    return std::to_string(value);
}
}

extern "C" {
#include "slurp.h"
}

template <class Base, unsigned Flag>
struct Lsh : Base {
    explicit Lsh(unsigned bytes) : Base(Flag | bytes, bytes) { this->Restart(); }
    std::string AlgorithmName() const { return "LSH"; }
};

template <class H>
static size_t run(unsigned bytes, const unsigned char *data, size_t len, unsigned char *out) {
    H h(bytes);
    for (size_t at = 0, step = 1; at < len; at += step, step++)
        h.Update(data + at, step < len - at ? step : len - at);
    h.Final(out);
    return bytes;
}

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned width, bits;
    char rest;
    if (sscanf(name, "lsh%u_%u%c", &width, &bits, &rest) != 2 || bits % 8 || !bits) return 0;
    try {
        if (width == 256 && bits <= 256) return run<Lsh<CryptoPP::LSH256_Base, 0>>(bits / 8, data, len, out);
        if (width == 512 && bits <= 512) return run<Lsh<CryptoPP::LSH512_Base, 0x10000>>(bits / 8, data, len, out);
    } catch (const std::exception &) {
    }
    return 0;
}
