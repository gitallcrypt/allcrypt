// Botan 1.10.17's Tiger, at any of its output lengths and pass counts:
// NAME is tigerBITS_PASSES, as PHP names them; see slurp.h. The data goes
// in in pieces of 1, 2, 3 ... bytes.
extern "C" {
#include "slurp.h"
}
#include <botan/tiger.h>

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned bits, passes;
    if (sscanf(name, "tiger%u_%u", &bits, &passes) != 2) return 0;
    try {
        Botan::Tiger tiger(bits / 8, passes);
        for (size_t at = 0, step = 1; at < len; at += step, step++)
            tiger.update(data + at, step < len - at ? step : len - at);
        tiger.final(out);
        return bits / 8;
    } catch (const std::exception &) {
        return 0;
    }
}
