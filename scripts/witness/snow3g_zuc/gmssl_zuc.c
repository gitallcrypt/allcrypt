/* GmSSL's ZUC (guanzhi/GmSSL, src/zuc.c and src/zuc_modes.c) under
 * driver.h: zuc_init and zuc256_init for the keystream, zuc_mac_* and
 * zuc256_mac_* for the MAC with a raw IV, zuc_eea_encrypt for 128-EEA3,
 * and zuc_eia_generate_mac for 128-EIA3. zuc_eea_encrypt takes the message
 * as 32 bit words, the first bit the top of the first; zuc_eia_generate_mac
 * is typed the same way but reads the words' memory as bytes, so it is
 * handed the message bytes in order. ZUC-256's 25 byte IV goes to GmSSL
 * with its last eight six bit values packed into six bytes, first value
 * highest, as zuc256_init unpacks them. */
#include "driver.h"
#include <gmssl/zuc.h>

static void pack_iv(const uint8_t iv[25], uint8_t out[23]) {
    memcpy(out, iv, 17);
    uint64_t bits = 0;
    for (int i = 17; i < 25; i++) bits = bits << 6 | (iv[i] & 0x3f);
    for (int i = 0; i < 6; i++) out[17 + i] = (uint8_t)(bits >> (40 - 8 * i));
}

static int iv_ok(const uint8_t *iv, size_t ivlen) {
    if (ivlen != 25) return 0;
    for (int i = 17; i < 25; i++)
        if (iv[i] & 0xc0) return 0;
    return 1;
}

static const char *w_stream(const char *cipher, const uint8_t *key, size_t klen,
                            const uint8_t *iv, size_t ivlen, uint8_t *out, size_t n) {
    ZUC_STATE st;
    if (strcmp(cipher, "zuc128") == 0) {
        if (klen != 16 || ivlen != 16) return "error key or iv length";
        zuc_init(&st, key, iv);
    } else if (strcmp(cipher, "zuc256") == 0) {
        if (klen != 32 || !iv_ok(iv, ivlen)) return "error key or iv length";
        uint8_t packed[23];
        pack_iv(iv, packed);
        zuc256_init(&st, key, packed);
    } else {
        return "error unsupported";
    }
    for (size_t i = 0; i < n; i += 4) {
        uint32_t w = zuc_generate_keyword(&st);
        for (size_t j = 0; j < 4 && i + j < n; j++) out[i + j] = (uint8_t)(w >> (24 - 8 * j));
    }
    return 0;
}

static const char *w_f8(const char *alg, const uint8_t *key, uint32_t count, uint32_t bearer,
                        uint32_t dir, uint8_t *data, uint32_t bits) {
    if (strcmp(alg, "eea3") != 0) return "error unsupported";
    size_t nw = (bits + 31) / 32;
    uint32_t *in = calloc(nw + 1, 4), *out = calloc(nw + 1, 4);
    for (uint32_t i = 0; i < (bits + 7) / 8; i++) in[i / 4] |= (uint32_t)data[i] << (24 - 8 * (i % 4));
    zuc_eea_encrypt(in, out, bits, key, count, bearer, dir);
    for (uint32_t i = 0; i < (bits + 7) / 8; i++) data[i] = (uint8_t)(out[i / 4] >> (24 - 8 * (i % 4)));
    free(in);
    free(out);
    return 0;
}

static const char *w_f9(const char *alg, const uint8_t *key, uint32_t count, uint32_t fresh,
                        uint32_t dir, const uint8_t *data, uint32_t bits, uint8_t mac[4]) {
    if (strcmp(alg, "eia3") != 0) return "error unsupported";
    uint32_t t = zuc_eia_generate_mac((const ZUC_UINT32 *)data, bits, key, count, fresh, dir);
    for (int i = 0; i < 4; i++) mac[i] = (uint8_t)(t >> (24 - 8 * i));
    return 0;
}

static const char *w_zucmac(int tagbits, const uint8_t *key, size_t klen, const uint8_t *iv,
                            size_t ivlen, const uint8_t *data, uint32_t bits, uint8_t *tag) {
    if (klen == 16) {
        if (tagbits != 32 || ivlen != 16) return "error tag size or iv length";
        ZUC_MAC_CTX ctx;
        zuc_mac_init(&ctx, key, iv);
        zuc_mac_finish(&ctx, data, bits, tag);
        return 0;
    }
    if (klen != 32 || !iv_ok(iv, ivlen)) return "error key or iv length";
    uint8_t packed[23];
    pack_iv(iv, packed);
    ZUC256_MAC_CTX ctx;
    zuc256_mac_init(&ctx, key, packed, tagbits);
    zuc256_mac_finish(&ctx, data, bits, tag);
    return 0;
}
