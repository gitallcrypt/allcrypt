// A Botan 1.10.17 block cipher as a witness, as ../nessie/botan_driver.cpp,
// for classes whose constructor may take a round count: CLASS is its
// class and HEADER its header, given on the command line, e.g.
//     -DCLASS=SAFER_SK -DHEADER='<botan/safer_sk.h>' -DROUNDS_CTOR
// compiled with the cipher's .cpp against shim/botan. With ROUNDS_CTOR
// the environment's ROUNDS is required and goes to the constructor. The
// key lengths are the class's own limits.
#include <cstdlib>
#include HEADER

static Botan::CLASS *cipher;

static int set_key(const unsigned char *key, size_t len) {
    typedef Botan::CLASS C;
    if (len < (size_t)C::MINIMUM_KEYLENGTH || len > (size_t)C::MAXIMUM_KEYLENGTH
            || len % C::KEYLENGTH_MULTIPLE)
        return -1;
    delete cipher;
#ifdef ROUNDS_CTOR
    const char *text = std::getenv("ROUNDS");
    if (!text) return -1;
    try {
        cipher = new Botan::CLASS(std::atoi(text));
    } catch (...) {
        cipher = 0;
        return -1;
    }
#else
    cipher = new Botan::CLASS;
#endif
    cipher->set_key(key, len);
    return 0;
}
static void encrypt(unsigned char *b) { cipher->encrypt_n(b, b, 1); }
static void decrypt(unsigned char *b) { cipher->decrypt_n(b, b, 1); }
static size_t block_size(void) { return Botan::CLASS::BLOCK_SIZE; }

#include "driver.h"
