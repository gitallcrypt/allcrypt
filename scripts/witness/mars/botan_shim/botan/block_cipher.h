// The part of Botan 1.10's interface that its src/block/mars/mars.cpp
// and mars.h use, so those two files compile on their own. Loads and
// stores are little endian; get_byte counts from the most significant
// byte, as Botan's does. A mistake here shows as the Botan witness
// failing Crypto++'s published MARS vectors, which build.sh checks.
#ifndef MARS_WITNESS_BOTAN_SHIM_H
#define MARS_WITNESS_BOTAN_SHIM_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#define BOTAN_DLL

namespace Botan {

typedef std::uint8_t byte;
typedef std::uint32_t u32bit;

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
    // Botan's set_key checks the length against the cipher's limits
    // first; this one does not, so the witness reaches every length the
    // key schedule handles.
    void set_key(const byte key[], std::size_t length) { key_schedule(key, length); }
private:
    virtual void key_schedule(const byte[], std::size_t) = 0;
};

template<std::size_t BS, std::size_t KMIN, std::size_t KMAX, std::size_t KMOD>
class Block_Cipher_Fixed_Params : public BlockCipher {
public:
    enum { BLOCK_SIZE = BS };
};

template<typename T> inline T load_le(const byte in[], std::size_t off) {
    in += off * sizeof(T);
    T out = 0;
    for (std::size_t i = sizeof(T); i > 0; --i) out = (T)((out << 8) | in[i - 1]);
    return out;
}

template<typename T> inline void load_le(const byte in[], T &x0, T &x1, T &x2, T &x3) {
    x0 = load_le<T>(in, 0);
    x1 = load_le<T>(in, 1);
    x2 = load_le<T>(in, 2);
    x3 = load_le<T>(in, 3);
}

template<typename T> inline void store_le(byte out[], T x0, T x1, T x2, T x3) {
    T v[4] = {x0, x1, x2, x3};
    for (std::size_t j = 0; j < 4; ++j)
        for (std::size_t i = 0; i < sizeof(T); ++i)
            out[j * sizeof(T) + i] = (byte)(v[j] >> (8 * i));
}

template<typename T> inline byte get_byte(std::size_t byte_num, T input) {
    return (byte)(input >> (((sizeof(T) - 1 - (byte_num & (sizeof(T) - 1))) << 3)));
}

template<typename T> inline T rotate_left(T input, std::size_t rot) {
    rot %= 8 * sizeof(T);
    return rot == 0 ? input : (T)((input << rot) | (input >> (8 * sizeof(T) - rot)));
}

template<typename T> inline T rotate_right(T input, std::size_t rot) {
    rot %= 8 * sizeof(T);
    return rot == 0 ? input : (T)((input >> rot) | (input << (8 * sizeof(T) - rot)));
}

}

#endif
