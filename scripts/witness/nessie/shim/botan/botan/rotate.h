// Botan 1.10's rotations.
#include <botan/block_cipher.h>

namespace Botan {

template<typename T> inline T rotate_left(T input, std::size_t rot) {
    rot %= 8 * sizeof(T);
    return rot == 0 ? input : (T)((input << rot) | (input >> (8 * sizeof(T) - rot)));
}

template<typename T> inline T rotate_right(T input, std::size_t rot) {
    rot %= 8 * sizeof(T);
    return rot == 0 ? input : (T)((input >> rot) | (input << (8 * sizeof(T) - rot)));
}

}
