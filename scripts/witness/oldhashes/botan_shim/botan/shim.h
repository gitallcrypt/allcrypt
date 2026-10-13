// The part of Botan 1.10's interface that its src/hash/tiger and
// src/hash/mdx_hash use, so those files compile on their own. Loads and
// stores are little endian or big endian as named; get_byte counts from
// the most significant byte, as Botan's does. A mistake here shows as
// the Botan witness disagreeing with PHP, sphlib and RHash on Tiger at
// three passes, which build.sh checks before reporting success.
#ifndef OLDHASHES_BOTAN_SHIM_H
#define OLDHASHES_BOTAN_SHIM_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#define BOTAN_DLL

namespace Botan {

typedef std::uint8_t byte;
typedef std::uint32_t u32bit;
typedef std::uint64_t u64bit;

template<typename T> class MemoryRegion : public std::vector<T> {
public:
    explicit MemoryRegion(std::size_t n = 0) : std::vector<T>(n) {}
    // Botan's: as much of `in` as fits from `offset`.
    void copy(std::size_t offset, const T in[], std::size_t n) {
        if (offset >= this->size()) return;
        n = std::min(n, this->size() - offset);
        std::copy(in, in + n, this->begin() + offset);
    }
};

template<typename T> class SecureVector : public MemoryRegion<T> {
public:
    explicit SecureVector(std::size_t n = 0) : MemoryRegion<T>(n) {}
};

template<typename T> void zeroise(MemoryRegion<T> &v) {
    std::fill(v.begin(), v.end(), T());
}

inline std::string to_string(std::size_t n) { return std::to_string(n); }

struct Invalid_Argument : std::invalid_argument {
    explicit Invalid_Argument(const std::string &s) : std::invalid_argument(s) {}
};
struct Invalid_State : std::logic_error {
    explicit Invalid_State(const std::string &s) : std::logic_error(s) {}
};

template<typename T> inline byte get_byte(std::size_t i, T v) {
    return static_cast<byte>(v >> ((sizeof(T) - 1 - i) * 8));
}

inline void load_le(u64bit out[], const byte in[], std::size_t n) {
    for (std::size_t i = 0; i != n; ++i) {
        u64bit v = 0;
        for (int j = 7; j >= 0; --j) v = (v << 8) | in[8 * i + j];
        out[i] = v;
    }
}

inline void store_le(u64bit v, byte out[]) {
    for (int j = 0; j != 8; ++j) out[j] = static_cast<byte>(v >> (8 * j));
}

inline void store_be(u64bit v, byte out[]) {
    for (int j = 0; j != 8; ++j) out[j] = static_cast<byte>(v >> (56 - 8 * j));
}

class HashFunction {
public:
    virtual ~HashFunction() {}
    virtual std::string name() const = 0;
    virtual std::size_t output_length() const = 0;
    virtual HashFunction *clone() const = 0;
    virtual void clear() = 0;
    virtual std::size_t hash_block_size() const = 0;
    void update(const byte in[], std::size_t n) { add_data(in, n); }
    void final(byte out[]) { final_result(out); }
protected:
    virtual void add_data(const byte[], std::size_t) = 0;
    virtual void final_result(byte[]) = 0;
};

}

#endif
