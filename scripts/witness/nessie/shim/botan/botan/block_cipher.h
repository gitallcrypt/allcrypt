// The part of Botan 1.10's interface its NESSIE cipher files use
// (src/block/noekeon), so each compiles on its own: the block cipher
// base, Block_Cipher_Fixed_Params with its key limits, SecureVector and
// zeroise. A mistake here shows as the Botan witness failing the
// published vectors, which build.sh checks.
#ifndef NESSIE_WITNESS_BOTAN_SHIM_H
#define NESSIE_WITNESS_BOTAN_SHIM_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#define BOTAN_DLL

namespace Botan {

typedef std::uint8_t byte;
typedef std::uint32_t u32bit;
using std::size_t;

template<typename T> class SecureVector : public std::vector<T> {
public:
    explicit SecureVector(std::size_t n = 0) : std::vector<T>(n) {}
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
