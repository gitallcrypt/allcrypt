/* fletcher16, fletcher32 and fletcher64 from the C of the R package
 * fletcher, whose three functions build.sh cuts out of its R glue into
 * fletcher_rpkg.h. See ../oldhashes/slurp.h. One-shot: the functions
 * take the whole message. */
#define OUT_MAX 8
#include <stddef.h>
#include <stdint.h>
#include "slurp.h"
#include "fletcher_rpkg.h"

static size_t be(uint64_t v, size_t n, unsigned char *out) {
    for (size_t i = 0; i < n; i++) out[i] = (unsigned char)(v >> (8 * (n - 1 - i)));
    return n;
}

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    if (!strcmp(name, "fletcher16")) return be(fletcher16(data, len), 2, out);
    if (!strcmp(name, "fletcher32")) return be(fletcher32(data, len), 4, out);
    if (!strcmp(name, "fletcher64")) return be(fletcher64(data, len), 8, out);
    return 0;
}
