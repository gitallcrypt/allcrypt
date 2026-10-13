/* A finalist team's own code through the API NIST asked every
 * submission for - Init(state, hashbitlen), Update(state, data,
 * databitlen), Final(state, out) - compiled once per FAMILY, which names
 * the requests it answers: FAMILYBITS, as in groestl256. See
 * ../oldhashes/slurp.h. The data goes in in pieces of 1, 2, 3 ... bytes. */
#include "slurp.h"
#include "hash.h"

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    int bits;
    char rest;
    if (sscanf(name, FAMILY "%d%c", &bits, &rest) != 1) return 0;
    hashState state;
    if (Init(&state, bits) != SUCCESS) return 0;
    for (size_t at = 0, step = 1; at < len; at += step, step++)
        if (Update(&state, data + at, 8 * (step < len - at ? step : len - at)) != SUCCESS) return 0;
    if (Final(&state, out) != SUCCESS) return 0;
    return bits / 8;
}
