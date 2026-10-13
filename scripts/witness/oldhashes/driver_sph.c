/* sphlib 3.0's Tiger, Tiger2 and fifteen HAVALs; see slurp.h. The data
 * goes in in pieces of 1, 2, 3 ... bytes, which sphlib's own buffering
 * then has to put together. */
#include "slurp.h"
#include "sph_tiger.h"
#include "sph_haval.h"

#define ENTRY(id, ctx, bytes) { #id, sizeof(ctx), bytes, sph_##id##_init, sph_##id, sph_##id##_close }
static const struct {
    const char *name;
    size_t size, out;
    void (*init)(void *);
    void (*update)(void *, const void *, size_t);
    void (*close)(void *, void *);
} TABLE[] = {
    ENTRY(tiger, sph_tiger_context, 24), ENTRY(tiger2, sph_tiger2_context, 24),
    ENTRY(haval128_3, sph_haval_context, 16), ENTRY(haval160_3, sph_haval_context, 20),
    ENTRY(haval192_3, sph_haval_context, 24), ENTRY(haval224_3, sph_haval_context, 28),
    ENTRY(haval256_3, sph_haval_context, 32), ENTRY(haval128_4, sph_haval_context, 16),
    ENTRY(haval160_4, sph_haval_context, 20), ENTRY(haval192_4, sph_haval_context, 24),
    ENTRY(haval224_4, sph_haval_context, 28), ENTRY(haval256_4, sph_haval_context, 32),
    ENTRY(haval128_5, sph_haval_context, 16), ENTRY(haval160_5, sph_haval_context, 20),
    ENTRY(haval192_5, sph_haval_context, 24), ENTRY(haval224_5, sph_haval_context, 28),
    ENTRY(haval256_5, sph_haval_context, 32),
};

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    for (size_t i = 0; i < sizeof TABLE / sizeof TABLE[0]; i++) {
        if (strcmp(name, TABLE[i].name)) continue;
        void *cc = malloc(TABLE[i].size);
        TABLE[i].init(cc);
        for (size_t at = 0, step = 1; at < len; at += step, step++)
            TABLE[i].update(cc, data + at, step < len - at ? step : len - at);
        TABLE[i].close(cc, out);
        free(cc);
        return TABLE[i].out;
    }
    return 0;
}
