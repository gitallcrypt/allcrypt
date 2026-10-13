// Botan 1.10's loads and stores, big endian, as its NESSIE cipher files
// call them.
#include <botan/block_cipher.h>

namespace Botan {

template<typename T> inline T load_be(const byte in[], std::size_t off) {
    in += off * sizeof(T);
    T out = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) out = (T)((out << 8) | in[i]);
    return out;
}

template<typename T> inline void store_be(byte out[], T x0, T x1, T x2, T x3) {
    T v[4] = {x0, x1, x2, x3};
    for (std::size_t j = 0; j < 4; ++j)
        for (std::size_t i = 0; i < sizeof(T); ++i)
            out[j * sizeof(T) + i] = (byte)(v[j] >> (8 * (sizeof(T) - 1 - i)));
}

}
