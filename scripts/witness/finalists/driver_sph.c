/* sphlib 3.0's SHA-3 finalists, as their teams finally submitted them;
 * see ../oldhashes/slurp.h. The data goes in in pieces of 1, 2, 3 ...
 * bytes, which sphlib's own buffering then has to put together. */
#include "slurp.h"
#include "sph_blake.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_skein.h"

#define ENTRY(id, ctx, bytes) { #id, sizeof(ctx), bytes, sph_##id##_init, sph_##id, sph_##id##_close }
/* sphlib's skein224 to skein512 are Skein-512 at those lengths. */
#define SKEIN(bits) { "skein512_" #bits, sizeof(sph_skein##bits##_context), bits / 8, \
                      sph_skein##bits##_init, sph_skein##bits, sph_skein##bits##_close }
static const struct {
    const char *name;
    size_t size, out;
    void (*init)(void *);
    void (*update)(void *, const void *, size_t);
    void (*close)(void *, void *);
} TABLE[] = {
    ENTRY(blake224, sph_blake224_context, 28), ENTRY(blake256, sph_blake256_context, 32),
    ENTRY(blake384, sph_blake384_context, 48), ENTRY(blake512, sph_blake512_context, 64),
    ENTRY(groestl224, sph_groestl224_context, 28), ENTRY(groestl256, sph_groestl256_context, 32),
    ENTRY(groestl384, sph_groestl384_context, 48), ENTRY(groestl512, sph_groestl512_context, 64),
    ENTRY(jh224, sph_jh224_context, 28), ENTRY(jh256, sph_jh256_context, 32),
    ENTRY(jh384, sph_jh384_context, 48), ENTRY(jh512, sph_jh512_context, 64),
    SKEIN(224), SKEIN(256), SKEIN(384), SKEIN(512),
};

/* NAME_after_N: the file's bytes hashed by a context told it has already
 * taken N bytes (whole blocks), which is how the counter's high word is
 * reached without hashing 512 MB. BLAKE only. */
static void after(const char *name, void *cc, unsigned long long taken) {
    if (!strncmp(name, "blake224", 8) || !strncmp(name, "blake256", 8)) {
        sph_blake_small_context *c = cc;
        c->T0 = (sph_u32)(taken << 3);
        c->T1 = (sph_u32)(taken >> 29);
    } else {
        sph_blake_big_context *c = cc;
        c->T0 = (sph_u64)(taken << 3);
        c->T1 = (sph_u64)(taken >> 61);
    }
}

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    char base[64];
    unsigned long long taken = 0;
    int is_after = sscanf(name, "%63[a-z0-9]_after_%llu", base, &taken) == 2;
    if (is_after) name = base;
    for (size_t i = 0; i < sizeof TABLE / sizeof TABLE[0]; i++) {
        if (strcmp(name, TABLE[i].name)) continue;
        if (is_after && strncmp(name, "blake", 5)) return 0;
        void *cc = malloc(TABLE[i].size);
        TABLE[i].init(cc);
        if (is_after) after(name, cc, taken);
        for (size_t at = 0, step = 1; at < len; at += step, step++)
            TABLE[i].update(cc, data + at, step < len - at ? step : len - at);
        TABLE[i].close(cc, out);
        free(cc);
        return TABLE[i].out;
    }
    return 0;
}
