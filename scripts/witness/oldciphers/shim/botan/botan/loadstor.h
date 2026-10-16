// Botan 1.10's byte extraction, loads and stores, as its cipher files
// call them: get_byte counts from the most significant byte, the make_
// functions put their first argument on top, and load_le/store_le read
// and write each word least significant byte first.
#ifndef OLDCIPHERS_WITNESS_BOTAN_LOADSTOR_H
#define OLDCIPHERS_WITNESS_BOTAN_LOADSTOR_H
#include <botan/block_cipher.h>

namespace Botan {

template<typename T> inline byte get_byte(std::size_t byte_num, T input) {
    return (byte)(input >> ((sizeof(T) - 1 - (byte_num & (sizeof(T) - 1))) << 3));
}

inline u16bit make_u16bit(byte i0, byte i1) {
    return (u16bit)(((u16bit)i0 << 8) | i1);
}

inline u32bit make_u32bit(byte i0, byte i1, byte i2, byte i3) {
    return ((u32bit)i0 << 24) | ((u32bit)i1 << 16) | ((u32bit)i2 << 8) | (u32bit)i3;
}

template<typename T> inline T load_be(const byte in[], std::size_t off) {
    in += off * sizeof(T);
    T out = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) out = (T)((out << 8) | in[i]);
    return out;
}

template<typename T> inline T load_le(const byte in[], std::size_t off) {
    in += off * sizeof(T);
    T out = 0;
    for (std::size_t i = sizeof(T); i > 0; --i) out = (T)((out << 8) | in[i - 1]);
    return out;
}

template<typename T> inline void store_be(T x, byte out[]) {
    for (std::size_t i = 0; i < sizeof(T); ++i)
        out[i] = (byte)(x >> (8 * (sizeof(T) - 1 - i)));
}

template<typename T> inline void store_le(T x, byte out[]) {
    for (std::size_t i = 0; i < sizeof(T); ++i) out[i] = (byte)(x >> (8 * i));
}

template<typename T> inline void store_be(byte out[], T x0, T x1) {
    store_be(x0, out);
    store_be(x1, out + sizeof(T));
}

template<typename T> inline void store_le(byte out[], T x0, T x1) {
    store_le(x0, out);
    store_le(x1, out + sizeof(T));
}

template<typename T> inline void store_be(byte out[], T x0, T x1, T x2, T x3) {
    store_be(out, x0, x1);
    store_be(out + 2 * sizeof(T), x2, x3);
}

template<typename T> inline void store_le(byte out[], T x0, T x1, T x2, T x3) {
    store_le(out, x0, x1);
    store_le(out + 2 * sizeof(T), x2, x3);
}

}

#endif
