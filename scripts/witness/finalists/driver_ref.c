/* The finalists' own code, as SUPERCOP carries it: one-shot, through
 * crypto_hash. Each file is compiled with its crypto_hash and its global
 * tables renamed, so several can share this driver; see
 * ../oldhashes/slurp.h. BLAKE's reference files are compiled inside
 * ref_after.c, and NAME_after_N is as in driver_sph.c. JH's are
 * round3jh256/simple and round3jh512/simple, from the designer's
 * bitsliced code, which have JH-256's and JH-512's starting values
 * written out; jh_any.c reaches the other two lengths, and
 * jh256_derived and jh512_derived are the first two through it. */
#include "slurp.h"

int blake256_ref(unsigned char *, const unsigned char *, unsigned long long);
int blake512_ref(unsigned char *, const unsigned char *, unsigned long long);
int blake256_ref_after(unsigned char *, const unsigned char *, unsigned long long,
                       unsigned long long);
int blake512_ref_after(unsigned char *, const unsigned char *, unsigned long long,
                       unsigned long long);
int jh256_ref(unsigned char *, const unsigned char *, unsigned long long);
int jh512_ref(unsigned char *, const unsigned char *, unsigned long long);
int jh_ref_any(int, unsigned char *, const unsigned char *, unsigned long long);

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned long long taken;
    if (!strcmp(name, "blake256")) return blake256_ref(out, data, len) ? 0 : 32;
    if (!strcmp(name, "blake512")) return blake512_ref(out, data, len) ? 0 : 64;
    if (sscanf(name, "blake256_after_%llu", &taken) == 1)
        return blake256_ref_after(out, data, len, taken) ? 0 : 32;
    if (sscanf(name, "blake512_after_%llu", &taken) == 1)
        return blake512_ref_after(out, data, len, taken) ? 0 : 64;
    if (!strcmp(name, "jh256")) return jh256_ref(out, data, len) ? 0 : 32;
    if (!strcmp(name, "jh512")) return jh512_ref(out, data, len) ? 0 : 64;
    if (!strcmp(name, "jh224")) return jh_ref_any(224, out, data, len) ? 0 : 28;
    if (!strcmp(name, "jh384")) return jh_ref_any(384, out, data, len) ? 0 : 48;
    if (!strcmp(name, "jh256_derived")) return jh_ref_any(256, out, data, len) ? 0 : 32;
    if (!strcmp(name, "jh512_derived")) return jh_ref_any(512, out, data, len) ? 0 : 64;
    return 0;
}
