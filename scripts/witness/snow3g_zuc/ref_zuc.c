/* The ZUC reference implementation, ETSI/SAGE 128-EEA3 & 128-EIA3 Document
 * 2 appendix A and Document 1 annex 1 (ZUC, EEA3 and EIA3), as
 * CryptoMobile's C_alg/ZUC.c carries it, under driver.h. EEA3 and EIA3
 * take the message as 32 bit words, the first bit the top of the first, so
 * the driver packs and unpacks them. EEA3 reads and writes C[L], one word
 * past its output, when the length is a multiple of 32, so the output is
 * given a spare word. */
#include "driver.h"
#include "ZUC.c"

static u32 *to_words(const uint8_t *bytes, uint32_t bits, u32 *n) {
    *n = (bits + 31) / 32;
    u32 *w = calloc(*n + 1, 4);
    for (uint32_t i = 0; i < (bits + 7) / 8; i++) w[i / 4] |= (u32)bytes[i] << (24 - 8 * (i % 4));
    return w;
}

static const char *w_stream(const char *cipher, const uint8_t *key, size_t klen,
                            const uint8_t *iv, size_t ivlen, uint8_t *out, size_t n) {
    if (strcmp(cipher, "zuc128") != 0) return "error unsupported";
    if (klen != 16 || ivlen != 16) return "error key or iv length";
    size_t nw = (n + 3) / 4;
    u32 *z = malloc(4 * nw + 4);
    ZUC((u8 *)key, (u8 *)iv, z, (u32)nw);
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(z[i / 4] >> (24 - 8 * (i % 4)));
    free(z);
    return 0;
}

static const char *w_f8(const char *alg, const uint8_t *key, uint32_t count, uint32_t bearer,
                        uint32_t dir, uint8_t *data, uint32_t bits) {
    if (strcmp(alg, "eea3") != 0) return "error unsupported";
    if (bits == 0) return 0;
    u32 n, *m = to_words(data, bits, &n), *c = calloc(n + 1, 4);
    EEA3((u8 *)key, count, bearer, dir, bits, m, c);
    for (uint32_t i = 0; i < (bits + 7) / 8; i++) data[i] = (uint8_t)(c[i / 4] >> (24 - 8 * (i % 4)));
    free(m);
    free(c);
    return 0;
}

static const char *w_f9(const char *alg, const uint8_t *key, uint32_t count, uint32_t fresh,
                        uint32_t dir, const uint8_t *data, uint32_t bits, uint8_t mac[4]) {
    if (strcmp(alg, "eia3") != 0) return "error unsupported";
    u32 n, *m = to_words(data, bits, &n), t;
    EIA3((u8 *)key, count, fresh, dir, bits, m, &t);
    for (int i = 0; i < 4; i++) mac[i] = (uint8_t)(t >> (24 - 8 * i));
    free(m);
    return 0;
}

static const char *w_zucmac(int tagbits, const uint8_t *key, size_t klen, const uint8_t *iv,
                            size_t ivlen, const uint8_t *data, uint32_t bits, uint8_t *tag) {
    (void)tagbits; (void)key; (void)klen; (void)iv; (void)ivlen; (void)data; (void)bits; (void)tag;
    return "error unsupported";
}
