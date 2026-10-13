/* A designers' NESSIE reference implementation as a witness, through its
 * NESSIE API (NESSIEkeysetup, NESSIEencrypt, NESSIEdecrypt). SOURCE is
 * the file, given on the command line; it is compiled with
 * shim/reference on the include path, which makes its key size a
 * variable, and with -Dmain=reference_main, so its own test program
 * stays out of the way. The key lengths are the reference's own:
 * MIN_KEYSIZEB to MAX_KEYSIZEB in 32-bit steps. */
int nessie_key_bytes;
#include SOURCE
#undef main

static struct NESSIEstruct state;

static int set_key(const unsigned char *key, size_t len) {
    if ((int)len < MIN_KEYSIZEB || (int)len > MAX_KEYSIZEB || len % 4) return -1;
    nessie_key_bytes = (int)len;
    NESSIEkeysetup(key, &state);
    return 0;
}
static void encrypt(unsigned char *b) {
    unsigned char out[BLOCKSIZEB];
    NESSIEencrypt(&state, b, out);
    memcpy(b, out, BLOCKSIZEB);
}
static void decrypt(unsigned char *b) {
    unsigned char out[BLOCKSIZEB];
    NESSIEdecrypt(&state, b, out);
    memcpy(b, out, BLOCKSIZEB);
}
static size_t block_size(void) { return BLOCKSIZEB; }

#include "driver.h"
