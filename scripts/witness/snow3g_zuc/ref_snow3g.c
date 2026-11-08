/* The SNOW 3G reference implementation, ETSI/SAGE UEA2 & UIA2 Document 2
 * annex 4 and Document 1 annex 4 (Initialize, GenerateKeystream, f8 and
 * f9), as CryptoMobile's C_alg/SNOW_3G.c carries it, under driver.h.
 * snow3g's key and IV bytes are K0 K1 K2 K3 and IV0 IV1 IV2 IV3, each word
 * big endian, as the test data's section 3 lists them; f8 and f9 load
 * their CK and IK the other way round, the first word K3, themselves.
 * f8 XORs whole words, writing up to three bytes past a buffer sized in
 * bytes, so it is given the data padded to a whole word; 128-EIA1 is f9
 * with FRESH = BEARER || 0^27 (TS 33.401 B.2.2). An empty message is
 * refused rather than handed to f9. */
#include "driver.h"
#include "SNOW_3G.c"

static void words(const uint8_t *bytes, u32 w[4]) {
    for (int i = 0; i < 4; i++)
        w[i] = (u32)bytes[4 * i] << 24 | (u32)bytes[4 * i + 1] << 16
                   | (u32)bytes[4 * i + 2] << 8 | bytes[4 * i + 3];
}

static const char *w_stream(const char *cipher, const uint8_t *key, size_t klen,
                            const uint8_t *iv, size_t ivlen, uint8_t *out, size_t n) {
    if (strcmp(cipher, "snow3g") != 0) return "error unsupported";
    if (klen != 16 || ivlen != 16) return "error key or iv length";
    u32 k[4], v[4];
    words(key, k);
    words(iv, v);
    size_t nw = (n + 3) / 4;
    u32 *z = malloc(4 * nw + 4);
    Initialize(k, v);
    GenerateKeystream((u32)nw, z);
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(z[i / 4] >> (24 - 8 * (i % 4)));
    free(z);
    return 0;
}

static const char *w_f8(const char *alg, const uint8_t *key, uint32_t count, uint32_t bearer,
                        uint32_t dir, uint8_t *data, uint32_t bits) {
    if (strcmp(alg, "uea2") != 0) return "error unsupported";
    size_t dl = (bits + 7) / 8, padded = 4 * ((bits + 31) / 32);
    uint8_t *work = calloc(padded + 1, 1);
    memcpy(work, data, dl);
    f8((u8 *)key, count, bearer, dir, work, bits);
    memcpy(data, work, dl);
    free(work);
    return 0;
}

static const char *w_f9(const char *alg, const uint8_t *key, uint32_t count, uint32_t fresh,
                        uint32_t dir, const uint8_t *data, uint32_t bits, uint8_t mac[4]) {
    if (strcmp(alg, "eia1") == 0) fresh <<= 27;
    else if (strcmp(alg, "uia2") != 0) return "error unsupported";
    /* f9's block count is a u64 and its first loop runs to D - 2, which
     * for an empty message is 2^64 - 1. */
    if (bits == 0) return "error refused";
    /* f9 reads the message eight bytes at a time, the last word whole. */
    size_t dl = (bits + 7) / 8, padded = 8 * ((bits + 63) / 64) + 8;
    uint8_t *work = calloc(padded, 1);
    memcpy(work, data, dl);
    memcpy(mac, f9((u8 *)key, count, fresh, dir, work, bits), 4);
    free(work);
    return 0;
}

static const char *w_zucmac(int tagbits, const uint8_t *key, size_t klen, const uint8_t *iv,
                            size_t ivlen, const uint8_t *data, uint32_t bits, uint8_t *tag) {
    (void)tagbits; (void)key; (void)klen; (void)iv; (void)ivlen; (void)data; (void)bits; (void)tag;
    return "error unsupported";
}
