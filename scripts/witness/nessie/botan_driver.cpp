// A Botan 1.10.17 block cipher as a witness: CLASS is its class and
// HEADER its header, given on the command line, e.g.
//     -DCLASS=Noekeon -DHEADER='<botan/noekeon.h>'
// compiled with the cipher's .cpp against shim/botan. The key lengths are
// the class's own limits.
#include HEADER

static Botan::CLASS cipher;

static int set_key(const unsigned char *key, size_t len) {
    typedef Botan::CLASS C;
    if (len < (size_t)C::MINIMUM_KEYLENGTH || len > (size_t)C::MAXIMUM_KEYLENGTH
            || len % C::KEYLENGTH_MULTIPLE)
        return -1;
    cipher.set_key(key, len);
    return 0;
}
static void encrypt(unsigned char *b) { cipher.encrypt_n(b, b, 1); }
static void decrypt(unsigned char *b) { cipher.decrypt_n(b, b, 1); }
static size_t block_size(void) { return Botan::CLASS::BLOCK_SIZE; }

#include "driver.h"
