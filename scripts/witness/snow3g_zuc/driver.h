/* The request loop shared by the C witnesses of scripts/witness/snow3g_zuc.
 * One request per line, an answer per line, hex throughout:
 *
 *   stream <cipher> <key> <iv> <bytes>      keystream, each 32 bit word big
 *                                           endian; snow3g, zuc128, zuc256
 *   f8 <alg> <key> <count> <bearer> <dir> <bits> <data>
 *                                           uea1, uea2 (= 128-EEA1) or eea3;
 *                                           the output's bits past <bits> zero
 *   f9 <alg> <key> <count> <fresh> <dir> <bits> <data>
 *                                           uia1, uia2, eia1 (<fresh> the
 *                                           bearer) or eia3 (<fresh> the
 *                                           bearer)
 *   zucmac <tagbits> <key> <iv> <bits> <data>
 *                                           the ZUC MAC with a raw IV: a 16
 *                                           byte key is ZUC-128's, 32 ZUC-256's
 *
 * count and fresh are hex words, bearer and dir decimal, <data> is
 * ceil(bits/8) bytes or "-" for none. A ZUC-256 IV is 25 bytes, the last
 * eight holding six bits each, as the specification writes it. The answer
 * is hex, or "error ..." for what the witness cannot do. Every buffer
 * handed to the implementation is an exact-size heap copy, at an offset of
 * OFFSET bytes (0 unless -DOFFSET=1). Each witness defines the functions
 * declared below, returning 0 or an error string. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef OFFSET
#define OFFSET 0
#endif

static const char *w_stream(const char *cipher, const uint8_t *key, size_t klen,
                            const uint8_t *iv, size_t ivlen, uint8_t *out, size_t n);
static const char *w_f8(const char *alg, const uint8_t *key, uint32_t count, uint32_t bearer,
                        uint32_t dir, uint8_t *data, uint32_t bits);
static const char *w_f9(const char *alg, const uint8_t *key, uint32_t count, uint32_t fresh,
                        uint32_t dir, const uint8_t *data, uint32_t bits, uint8_t mac[4]);
static const char *w_zucmac(int tagbits, const uint8_t *key, size_t klen, const uint8_t *iv,
                            size_t ivlen, const uint8_t *data, uint32_t bits, uint8_t *tag);

static size_t unhex(const char *s, uint8_t *out, size_t max) {
    size_t n = 0;
    if (strcmp(s, "-") == 0) return 0;
    while (s[0] && s[1] && n < max) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

/* An exact-size heap copy at OFFSET, with `extra` writable bytes after it
 * for the implementations that need them (said where they are asked for). */
static uint8_t *copy_in(const uint8_t *src, size_t len, size_t extra) {
    uint8_t *p = calloc(len + extra + OFFSET + 1, 1);
    memcpy(p + OFFSET, src, len);
    return p + OFFSET;
}

static void release(uint8_t *p) {
    free(p - OFFSET);
}

static void put_hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    putchar('\n');
}

static void zero_tail(uint8_t *data, uint32_t bits) {
    if (bits % 8) data[bits / 8] &= (uint8_t)(0xff << (8 - bits % 8));
}

int main(void) {
    static char line[1 << 18];
    static uint8_t a[1 << 16], b[1 << 16], d[1 << 16];
    while (fgets(line, sizeof line, stdin)) {
        char op[16], name[32], f[6][1 << 17];
        const char *err = "error request";
        int got = sscanf(line, "%15s %31s %s %s %s %s %s %s", op, name, f[0], f[1], f[2], f[3],
                         f[4], f[5]);
        if (got == 5 && strcmp(op, "stream") == 0) {
            size_t kl = unhex(f[0], a, sizeof a), vl = unhex(f[1], b, sizeof b);
            size_t n = strtoul(f[2], NULL, 10);
            uint8_t *k = copy_in(a, kl, 0), *v = copy_in(b, vl, 0), *o = copy_in(d, 0, n);
            err = w_stream(name, k, kl, v, vl, o, n);
            if (!err) put_hex(o, n);
            release(k); release(v); release(o);
        } else if (got == 8 && (strcmp(op, "f8") == 0 || strcmp(op, "f9") == 0)) {
            size_t kl = unhex(f[0], a, sizeof a);
            uint32_t count = strtoul(f[1], NULL, 16);
            uint32_t dir = strtoul(f[3], NULL, 10), bits = strtoul(f[4], NULL, 10);
            size_t dl = unhex(f[5], d, sizeof d);
            if (kl != 16 || dl != (bits + 7) / 8) {
                err = "error key or data length";
            } else if (op[1] == '8') {
                uint8_t *k = copy_in(a, kl, 0), *m = copy_in(d, dl, 0);
                err = w_f8(name, k, count, strtoul(f[2], NULL, 10), dir, m, bits);
                if (!err) { zero_tail(m, bits); put_hex(m, dl); }
                release(k); release(m);
            } else {
                uint8_t *k = copy_in(a, kl, 0), *m = copy_in(d, dl, 0), mac[4];
                int fresh = strcmp(name, "uia2") == 0 || strcmp(name, "uia1") == 0;
                uint32_t value = strtoul(f[2], NULL, fresh ? 16 : 10);
                err = w_f9(name, k, count, value, dir, m, bits, mac);
                if (!err) put_hex(mac, 4);
                release(k); release(m);
            }
        } else if (got == 6 && strcmp(op, "zucmac") == 0) {
            int tagbits = atoi(name);
            size_t kl = unhex(f[0], a, sizeof a), vl = unhex(f[1], b, sizeof b);
            uint32_t bits = strtoul(f[2], NULL, 10);
            size_t dl = unhex(f[3], d, sizeof d);
            uint8_t tag[16];
            if (dl != (bits + 7) / 8 || (tagbits != 32 && tagbits != 64 && tagbits != 128)) {
                err = "error data length or tag size";
            } else {
                uint8_t *k = copy_in(a, kl, 0), *v = copy_in(b, vl, 0), *m = copy_in(d, dl, 0);
                err = w_zucmac(tagbits, k, kl, v, vl, m, bits, tag);
                if (!err) put_hex(tag, tagbits / 8);
                release(k); release(v); release(m);
            }
        }
        if (err) puts(err);
        fflush(stdout);
    }
    return 0;
}
