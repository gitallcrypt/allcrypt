// Botan 1.10's number formatting, as its cipher files use it in name().
#ifndef OLDCIPHERS_WITNESS_BOTAN_PARSING_H
#define OLDCIPHERS_WITNESS_BOTAN_PARSING_H
#include <botan/block_cipher.h>

namespace Botan {

inline std::string to_string(u64bit n, std::size_t = 0) { return std::to_string(n); }

}

#endif
