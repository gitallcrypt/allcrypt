/* cryptonite-witness BLOCK_BITS OPERATION
 *
 * cryptonite's DSTU 7624 (Kalyna) modes over stdin: one request per
 * line of space-separated hex fields ("-" for empty), one hex line out
 * or "error: <code>". A fresh context per line, the standard S-boxes.
 *
 *   ecb  KEY DATA          ctr  KEY IV DATA       cbc  KEY IV DATA
 *   cfb  KEY IV DATA       ofb  KEY IV DATA       (whole-block feedback)
 *   cmac KEY QBYTES DATA   kw   KEY DATA          unkw KEY DATA
 *   gcm  KEY IV QBYTES AAD DATA       ciphertext || tag
 *   ungcm KEY IV QBYTES AAD CT TAG    the plaintext, or an error
 *   gmac KEY QBYTES DATA              GCM's tag with DATA as associated
 *                                     data, no message and a zero IV.
 *                                     Not through dstu7624_init_gmac:
 *                                     its update XORs the first block in
 *                                     again where the second belongs.
 *   ccm  KEY IV QBYTES NMAX AAD DATA  ciphertext || encrypted MAC
 *   xts  KEY IV DATA                  unxts KEY IV DATA
 *
 * NMAX is cryptonite's n_max in bits, from which it derives Nb.
 *
 *   kmac KEY DATA                     DSTU 7564's MAC (Kupyna), BLOCK_BITS
 *                                     read as the MAC's size
 *
 * GOST 28147-89 and GOST 34.311-95 under an S-box given as a 64-byte
 * DSTU 4145 DKE, expanded nibble by nibble, high first (BLOCK_BITS is
 * ignored):
 *
 *   gost-ecb DKE KEY DATA     gost-cfb DKE KEY IV DATA
 *   gost-cnt DKE KEY IV DATA  gost-mac DKE KEY DATA (4 bytes)
 *   gost3411 DKE DATA         the hash from a zero starting value
 *   gost-sbox ID              cryptonite's own table ID, packed as a DKE
 *
 * DSTU 4145-2002 (BLOCK_BITS ignored). CURVE is a named curve's number,
 * 0 to 9, or "M:K3,K2,K1:A:B:N:GX:GY" for one given whole. Integers and
 * field elements are big-endian hex; cryptonite's little-endian byte
 * arrays are reversed here. HASH is passed as given.
 *
 *   dstu4145-pub CURVE D             the public key, QX QY (Q = -dG)
 *   dstu4145-compress CURVE QX QY    the standard's compression
 *   dstu4145-decompress CURVE BYTES  QX QY
 *   dstu4145-verify CURVE QX QY HASH R S   "01" or "00"
 *   dstu4145-dh CURVE D QX QY COFACTOR      the shared point, ZX ZY
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dstu7564.h"
#include "dstu4145.h"
#include "cryptonite_errors.h"
#include "gost28147.h"
#include "gost34_311.h"
#include "dstu7624.h"

static ByteArray *field(char *s);

static ByteArray *expanded(char *dke_hex) {
    ByteArray *dke = field(dke_hex);
    uint8_t sbox[128];
    for (size_t i = 0; i < 64 && i < ba_get_len(dke); i++) {
        sbox[2 * i] = ba_get_buf(dke)[i] >> 4;
        sbox[2 * i + 1] = ba_get_buf(dke)[i] & 0xf;
    }
    ba_free(dke);
    return ba_alloc_from_uint8(sbox, 128);
}

/* Big-endian hex to cryptonite's little-endian byte array. */
static ByteArray *le(char *hex) {
    ByteArray *a = field(hex);
    ba_swap(a);
    return a;
}

static void print_be(ByteArray *a) {
    for (size_t i = ba_get_len(a); i > 0; i--) printf("%02x", ba_get_buf(a)[i - 1]);
}

static Dstu4145Ctx *curve(char *spec) {
    if (!strchr(spec, ':')) return dstu4145_alloc((Dstu4145ParamsId)(atoi(spec) + 1));
    char *parts[7];
    int n = 0;
    for (char *t = strtok(spec, ":"); t && n < 7; t = strtok(NULL, ":")) parts[n++] = t;
    if (n != 7) return NULL;
    int f[5] = {atoi(parts[0]), 0, 0, 0, 0};
    size_t f_len = 1;
    for (char *t = parts[1]; *t; ) {
        f[f_len++] = atoi(t);
        t = strchr(t, ',');
        if (!t) break;
        t++;
    }
    f[f_len++] = 0;
    return dstu4145_alloc_pb(f, f_len, atoi(parts[2]), le(parts[3]), le(parts[4]),
                             le(parts[5]), le(parts[6]));
}

static int dstu4145(const char *op, char **f, int nf) {
    Dstu4145Ctx *ctx = curve(f[0]);
    ByteArray *x = NULL, *y = NULL;
    int ret;
    if (!ctx) return -1;
    if (!strcmp(op, "dstu4145-pub")) {
        ret = dstu4145_get_pubkey(ctx, le(f[1]), &x, &y);
    } else if (!strcmp(op, "dstu4145-compress")) {
        ret = dstu4145_compress_pubkey(ctx, le(f[1]), le(f[2]), &x);
    } else if (!strcmp(op, "dstu4145-decompress")) {
        ret = dstu4145_decompress_pubkey(ctx, le(f[1]), &x, &y);
    } else if (!strcmp(op, "dstu4145-verify")) {
        ret = dstu4145_init_verify(ctx, le(f[1]), le(f[2]));
        if (!ret) {
            ret = dstu4145_verify(ctx, field(f[3]), le(f[4]), le(f[5]));
            if (ret == RET_VERIFY_FAILED) {
                printf("00\n");
                dstu4145_free(ctx);
                return 0;
            }
            if (!ret) printf("01\n");
        }
        dstu4145_free(ctx);
        return ret;
    } else if (!strcmp(op, "dstu4145-dh")) {
        ret = dstu4145_dh(ctx, atoi(f[4]) != 0, le(f[1]), le(f[2]), le(f[3]), &x, &y);
    } else {
        ret = -1;
    }
    if (!ret) {
        print_be(x);
        if (y) { printf(" "); print_be(y); }
        printf("\n");
    }
    dstu4145_free(ctx);
    return ret;
}

static int gost(const char *op, char **f, int nf, ByteArray **out) {
    int ret;
    if (!strcmp(op, "gost-sbox")) {
        Gost28147Ctx *c = gost28147_alloc((Gost28147SboxId)atoi(f[0]));
        ByteArray *sbox = NULL;
        if (!c) return -1;
        ret = gost28147_get_ext_sbox(c, &sbox);
        if (!ret) {
            uint8_t packed[64];
            for (size_t i = 0; i < 64; i++)
                packed[i] = (uint8_t)(ba_get_buf(sbox)[2 * i] << 4 | ba_get_buf(sbox)[2 * i + 1]);
            *out = ba_alloc_from_uint8(packed, 64);
        }
        gost28147_free(c);
        return ret;
    }
    if (!strcmp(op, "gost3411")) {
        uint8_t zero[32] = {0};
        Gost34311Ctx *h = gost34_311_alloc_user_sbox(expanded(f[0]),
                                                    ba_alloc_from_uint8(zero, 32));
        if (!h) return -1;
        ret = gost34_311_update(h, field(nf > 1 ? f[1] : "-"));
        if (!ret) ret = gost34_311_final(h, out);
        gost34_311_free(h);
        return ret;
    }
    Gost28147Ctx *c = gost28147_alloc_user_sbox(expanded(f[0]));
    if (!c) return -1;
    if (!strcmp(op, "gost-ecb")) {
        ret = gost28147_init_ecb(c, field(f[1]));
        if (!ret) ret = gost28147_encrypt(c, field(f[2]), out);
    } else if (!strcmp(op, "gost-cfb") || !strcmp(op, "gost-cnt")) {
        ret = !strcmp(op, "gost-cfb") ? gost28147_init_cfb(c, field(f[1]), field(f[2]))
                                      : gost28147_init_ctr(c, field(f[1]), field(f[2]));
        if (!ret) ret = gost28147_encrypt(c, field(f[3]), out);
    } else if (!strcmp(op, "gost-mac")) {
        ret = gost28147_init_mac(c, field(f[1]));
        if (!ret) ret = gost28147_update_mac(c, field(nf > 2 ? f[2] : "-"));
        if (!ret) ret = gost28147_final_mac(c, out);
    } else {
        ret = -1;
    }
    gost28147_free(c);
    return ret;
}

static ByteArray *field(char *s) {
    static uint8_t buf[1 << 16];
    size_t n = 0;
    if (strcmp(s, "-") != 0)
        for (; s[0] && s[1]; s += 2) { unsigned v; sscanf(s, "%2x", &v); buf[n++] = (uint8_t)v; }
    return ba_alloc_from_uint8(buf, n);
}

int main(int argc, char **argv) {
    size_t block = (size_t)atoi(argv[1]) / 8;
    const char *op = argv[2];
    static char line[1 << 18];
    while (fgets(line, sizeof line, stdin)) {
        char *f[7] = {0};
        int nf = 0;
        for (char *t = strtok(line, " \n"); t && nf < 7; t = strtok(NULL, " \n")) f[nf++] = t;
        if (!strncmp(op, "dstu4145", 8)) {
            int r = dstu4145(op, f, nf);
            if (r) printf("error: %d\n", r);
            continue;
        }
        if (!strncmp(op, "gost", 4)) {
            ByteArray *out = NULL;
            int r = gost(op, f, nf, &out);
            if (r) printf("error: %d\n", r);
            else {
                for (size_t i = 0; i < ba_get_len(out); i++) printf("%02x", ba_get_buf(out)[i]);
                printf("\n");
            }
            continue;
        }
        if (!strcmp(op, "kmac")) {
            Dstu7564Ctx *k = dstu7564_alloc(DSTU7564_SBOX_1);
            ByteArray *mac = NULL;
            int r = dstu7564_init_kmac(k, field(f[0]), block);
            if (!r) r = dstu7564_update_kmac(k, field(nf > 1 ? f[1] : "-"));
            if (!r) r = dstu7564_final_kmac(k, &mac);
            if (r) printf("error: %d\n", r);
            else {
                for (size_t i = 0; i < ba_get_len(mac); i++) printf("%02x", ba_get_buf(mac)[i]);
                printf("\n");
            }
            dstu7564_free(k);
            continue;
        }
        Dstu7624Ctx *ctx = dstu7624_alloc(DSTU7624_SBOX_1);
        ByteArray *out = NULL;
        int ret;
        ByteArray *key = field(f[0]);
        if (!strcmp(op, "ecb")) {
            ret = dstu7624_init_ecb(ctx, key, block);
            if (!ret) ret = dstu7624_encrypt(ctx, field(f[1]), &out);
        } else if (!strcmp(op, "ctr") || !strcmp(op, "cbc") || !strcmp(op, "ofb") || !strcmp(op, "cfb")) {
            ByteArray *iv = field(f[1]);
            ret = !strcmp(op, "ctr") ? dstu7624_init_ctr(ctx, key, iv)
                : !strcmp(op, "cbc") ? dstu7624_init_cbc(ctx, key, iv)
                : !strcmp(op, "ofb") ? dstu7624_init_ofb(ctx, key, iv)
                : dstu7624_init_cfb(ctx, key, iv, block);
            if (!ret) ret = dstu7624_encrypt(ctx, field(f[2]), &out);
        } else if (!strcmp(op, "cmac")) {
            ret = dstu7624_init_cmac(ctx, key, block, (size_t)atoi(f[1]));
            if (!ret) ret = dstu7624_update_mac(ctx, field(nf > 2 ? f[2] : "-"));
            if (!ret) ret = dstu7624_final_mac(ctx, &out);
        } else if (!strcmp(op, "kw") || !strcmp(op, "unkw")) {
            ret = dstu7624_init_kw(ctx, key, block);
            if (!ret) ret = !strcmp(op, "kw") ? dstu7624_encrypt(ctx, field(f[1]), &out)
                                              : dstu7624_decrypt(ctx, field(f[1]), &out);
        } else if (!strcmp(op, "gcm") || !strcmp(op, "ccm")) {
            ByteArray *mac = NULL, *ct = NULL;
            int at = !strcmp(op, "ccm") ? 4 : 3;
            ret = !strcmp(op, "ccm")
                ? dstu7624_init_ccm(ctx, key, field(f[1]), (size_t)atoi(f[2]),
                                    (uint64_t)atoll(f[3]))
                : dstu7624_init_gcm(ctx, key, field(f[1]), (size_t)atoi(f[2]));
            if (!ret) ret = dstu7624_encrypt_mac(ctx, field(f[at]), field(f[at + 1]), &mac, &ct);
            if (!ret) out = !strcmp(op, "ccm") ? ct : ba_join(ct, mac);
        } else if (!strcmp(op, "ungcm")) {
            ret = dstu7624_init_gcm(ctx, key, field(f[1]), (size_t)atoi(f[2]));
            if (!ret) ret = dstu7624_decrypt_mac(ctx, field(f[3]), field(f[4]), field(f[5]), &out);
        } else if (!strcmp(op, "gmac")) {
            static uint8_t zeros[64];
            ByteArray *ct = NULL;
            ret = dstu7624_init_gcm(ctx, key, ba_alloc_from_uint8(zeros, block), (size_t)atoi(f[1]));
            if (!ret) ret = dstu7624_encrypt_mac(ctx, field(nf > 2 ? f[2] : "-"), field("-"),
                                                 &out, &ct);
        } else if (!strcmp(op, "xts") || !strcmp(op, "unxts")) {
            ret = dstu7624_init_xts(ctx, key, field(f[1]));
            if (!ret) ret = !strcmp(op, "xts") ? dstu7624_encrypt(ctx, field(f[2]), &out)
                                               : dstu7624_decrypt(ctx, field(f[2]), &out);
        } else {
            ret = -1;
        }
        if (ret) printf("error: %d\n", ret);
        else {
            for (size_t i = 0; i < ba_get_len(out); i++) printf("%02x", ba_get_buf(out)[i]);
            printf("\n");
        }
        dstu7624_free(ctx);
    }
    return 0;
}
