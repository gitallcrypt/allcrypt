// The part of Botan 1.10's interface its cipher files under src/block
// use, so each compiles on its own: the block cipher base,
// Block_Cipher_Fixed_Params with its key limits, SecureVector, zeroise
// and Invalid_Argument. The same shape as ../nessie/shim/botan, with the
// word types the ciphers here need. A mistake here shows as a Botan
// witness failing the published vectors, which build.sh checks.
#ifndef OLDCIPHERS_WITNESS_BOTAN_SHIM_H
#define OLDCIPHERS_WITNESS_BOTAN_SHIM_H

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#define BOTAN_DLL

namespace Botan {

typedef std::uint8_t byte;
typedef std::uint16_t u16bit;
typedef std::uint32_t u32bit;
typedef std::uint64_t u64bit;
typedef std::int32_t s32bit;
using std::size_t;

struct Invalid_Argument : public std::invalid_argument {
    explicit Invalid_Argument(const std::string &what) : std::invalid_argument(what) {}
};

template<typename T> class SecureVector : public std::vector<T> {
public:
    explicit SecureVector(std::size_t n = 0) : std::vector<T>(n) {}
    void copy(const T in[], std::size_t n) {
        for (std::size_t i = 0; i < n; ++i) (*this)[i] = in[i];
    }
};

template<typename T> void zeroise(SecureVector<T> &v) {
    for (auto &x : v) x = 0;
}

class BlockCipher {
public:
    virtual ~BlockCipher() {}
    virtual void encrypt_n(const byte in[], byte out[], std::size_t blocks) const = 0;
    virtual void decrypt_n(const byte in[], byte out[], std::size_t blocks) const = 0;
    void set_key(const byte key[], std::size_t length) { key_schedule(key, length); }
private:
    virtual void key_schedule(const byte[], std::size_t) = 0;
};

template<std::size_t BS, std::size_t KMIN, std::size_t KMAX = 0, std::size_t KMOD = 1>
class Block_Cipher_Fixed_Params : public BlockCipher {
public:
    enum { BLOCK_SIZE = BS, MINIMUM_KEYLENGTH = KMIN,
           MAXIMUM_KEYLENGTH = KMAX ? KMAX : KMIN, KEYLENGTH_MULTIPLE = KMOD };
};

}

#endif
