/* crc32 and adler32 from zlib, and crc32c from the SSE 4.2 CRC32 instruction, which
 * computes the Castagnoli CRC in hardware. See ../oldhashes/slurp.h. The
 * data goes in in pieces of 1, 2, 3 ... bytes; the instruction takes it
 * a byte at a time. */
#include <nmmintrin.h>
#include <stdint.h>
#include <zlib.h>
#include "slurp.h"

static size_t be32(uint32_t v, unsigned char *out) {
    for (int i = 0; i < 4; i++) out[i] = (unsigned char)(v >> (24 - 8 * i));
    return 4;
}

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    if (!strcmp(name, "crc32")) {
        uLong c = crc32(0, Z_NULL, 0);
        for (size_t at = 0, step = 1; at < len; at += step, step++)
            c = crc32(c, data + at, (uInt)(step < len - at ? step : len - at));
        return be32((uint32_t)c, out);
    }
    if (!strcmp(name, "adler32")) {
        uLong c = adler32(0, Z_NULL, 0);
        for (size_t at = 0, step = 1; at < len; at += step, step++)
            c = adler32(c, data + at, (uInt)(step < len - at ? step : len - at));
        return be32((uint32_t)c, out);
    }
    if (!strcmp(name, "crc32c")) {
        uint32_t c = 0xffffffff;
        for (size_t i = 0; i < len; i++) c = _mm_crc32_u8(c, data[i]);
        return be32(~c, out);
    }
    return 0;
}
