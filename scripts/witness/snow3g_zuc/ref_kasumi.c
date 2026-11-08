/* The KASUMI reference implementation with f8 and f9, 3GPP TS 35.202
 * annex 2 and TS 35.201 annex 2, as CryptoMobile's C_alg/Kasumi.c carries
 * it, under driver.h: uea1 and uia1. f8 XORs whole bytes and clears the
 * bits past the length. f9 reads the message a byte at a time and takes
 * the last byte whole, the bits past the length included, so the driver
 * clears them. driver.h hands both exact-size heap copies. */
#include "driver.h"
#include "Kasumi.c"

static const char *w_stream(const char *cipher, const uint8_t *key, size_t klen,
                            const uint8_t *iv, size_t ivlen, uint8_t *out, size_t n) {
    (void)cipher; (void)key; (void)klen; (void)iv; (void)ivlen; (void)out; (void)n;
    return "error unsupported";
}

static const char *w_f8(const char *alg, const uint8_t *key, uint32_t count, uint32_t bearer,
                        uint32_t dir, uint8_t *data, uint32_t bits) {
    if (strcmp(alg, "uea1") != 0) return "error unsupported";
    f8((u8 *)key, count, bearer, dir, data, (int)bits);
    return 0;
}

static const char *w_f9(const char *alg, const uint8_t *key, uint32_t count, uint32_t fresh,
                        uint32_t dir, const uint8_t *data, uint32_t bits, uint8_t mac[4]) {
    if (strcmp(alg, "uia1") != 0) return "error unsupported";
    /* f9 ORs the last byte into the input whole, the bits past the length
     * included, so they are cleared first. */
    uint8_t *m = copy_in(data, (bits + 7) / 8, 0);
    zero_tail(m, bits);
    memcpy(mac, f9((u8 *)key, count, fresh, dir, m, (int)bits), 4);
    release(m);
    return 0;
}

static const char *w_zucmac(int tagbits, const uint8_t *key, size_t klen, const uint8_t *iv,
                            size_t ivlen, const uint8_t *data, uint32_t bits, uint8_t *tag) {
    (void)tagbits; (void)key; (void)klen; (void)iv; (void)ivlen; (void)data; (void)bits; (void)tag;
    return "error unsupported";
}
