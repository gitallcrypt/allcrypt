/* The designers' SipHash and HalfSipHash (veorq/SipHash), which fix
 * their round counts when compiled: build.sh compiles each file once per
 * pair, renaming its function to siphash_C_D or halfsiphash_C_D, and the
 * list below names them. Requests are KIND-C-D-BYTES:KEY with the key in
 * hex, KIND siphash or halfsiphash, and a file of message; see
 * ../oldhashes/slurp.h. */
#include "slurp.h"
#include <stdint.h>

#define ROUNDS(X) X(1, 3) X(2, 4) X(3, 5) X(4, 8)
#define DECLARE(c, d) \
    int siphash_##c##_##d(const void *, size_t, const void *, uint8_t *, size_t); \
    int halfsiphash_##c##_##d(const void *, size_t, const void *, uint8_t *, size_t);
ROUNDS(DECLARE)

static int unhex(const char *hex, size_t n, unsigned char *out) {
    if (strlen(hex) != 2 * n) return 0;
    for (size_t i = 0; i < n; i++)
        if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1) return 0;
    return 1;
}

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    char kind[16], hex[64];
    unsigned c, d, bytes;
    unsigned char key[16];
    if (sscanf(name, "%15[a-z]-%u-%u-%u:%63s", kind, &c, &d, &bytes, hex) != 5) return 0;
    int half = !strcmp(kind, "halfsiphash");
    if (!half && strcmp(kind, "siphash")) return 0;
    if (!unhex(hex, half ? 8 : 16, key)) return 0;
    if (half ? bytes != 4 && bytes != 8 : bytes != 8 && bytes != 16) return 0;
#define CALL(cc, dd) \
    if (c == cc && d == dd) \
        return (half ? halfsiphash_##cc##_##dd : siphash_##cc##_##dd)(data, len, key, out, bytes) \
            ? 0 : bytes;
    ROUNDS(CALL)
    return 0;
}
