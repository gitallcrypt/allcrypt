// MARS witness on Botan 1.10.17's src/block/mars/mars.cpp, compiled
// against the shim in botan_shim/; driver_common.h has the request
// format. Botan admits keys of 16 to 32 bytes; the shim's set_key calls
// the key schedule directly, so every length the tweaked schedule
// defines - 4 to 14 words - reaches it.
#include <botan/mars.h>

using Botan::byte;

struct Witness {
    Botan::MARS m;
    void set_key(const byte *key, size_t len) { m.set_key(key, len); }
    void encrypt(byte *block) { m.encrypt_n(block, block, 1); }
    void decrypt(byte *block) { m.decrypt_n(block, block, 1); }
};

#include "driver_common.h"
