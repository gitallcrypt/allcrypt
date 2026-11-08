/* cryptonite-storage: PrivatBank cryptonite's key containers as a witness.
 *
 * One request per line, space-separated hex fields; one line out per
 * request, or "error: <code>". Passwords are the hex of their bytes, "-"
 * for the empty one.
 *
 *   pkcs8 DER                   a PrivateKeyInfo
 *   pbes2 PASSWORD DER          an EncryptedPrivateKeyInfo, opened with
 *                               pkcs5_decrypt_dstu (GOST 28147 and
 *                               HMAC-GOST 34.311, as IIT writes it)
 *   p12 PASSWORD KEYPASSWORD DER   a PKCS#12: every key, by alias
 *
 * Each key comes out as M:D:QX:QY:N - the field's degree, the private
 * key as stored, the public point cryptonite computes from it and the
 * group order, all big-endian hex - and, when the IIT key-agreement key
 * is in the attributes (1.3.6.1.4.1.19398.1.1.2.3), " kep:D" with that
 * key as pkcs8_get_kep_privatekey reads it, big-endian hex too. A PKCS#12 answers
 * "key ALIAS KEY" for each key, then "cert DER" for each certificate,
 * separated by " | ".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dstu4145.h"
#include "cryptonite_errors.h"
#include "pkcs8.h"
#include "pkcs5.h"
#include "pkcs12.h"
#include "aid.h"
#include "asn1_utils.h"

/* pkcs12.c's context, which keeps the selected key where no accessor
 * hands it out. As at cryptonite 3618d340. */
struct Pkcs12StorageCtx_st {
    void *owner;
    Pkcs12Keypair *kprs;
    size_t kprs_cnt;
    PrivateKeyInfo_t *genkey;
    PrivateKeyInfo_t *curr_key;
};

static ByteArray *field(const char *s) {
    if (!strcmp(s, "-")) return ba_alloc_by_len(0);
    size_t n = strlen(s) / 2;
    uint8_t *b = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &b[i]);
    ByteArray *a = ba_alloc_from_uint8(b, n);
    free(b);
    return a;
}

/* The password as a C string: its bytes, which may be UTF-8. */
static char *password(const char *hex) {
    ByteArray *a = field(hex);
    size_t n = ba_get_len(a);
    char *p = malloc(n + 1);
    memcpy(p, ba_get_buf(a), n);
    p[n] = 0;
    ba_free(a);
    return p;
}

static void print_be(const ByteArray *a) {
    for (size_t i = ba_get_len(a); i > 0; i--) printf("%02x", ba_get_buf(a)[i - 1]);
}

static void print_hex(const ByteArray *a) {
    for (size_t i = 0; i < ba_get_len(a); i++) printf("%02x", ba_get_buf(a)[i]);
}

static int print_key(const PrivateKeyInfo_t *key) {
    ByteArray *d = NULL, *qx = NULL, *qy = NULL, *b = NULL, *n = NULL, *px = NULL, *py = NULL;
    ByteArray *kep = NULL;
    Dstu4145Ctx *ctx = NULL;
    int *f = NULL, a = 0, ret;
    size_t f_len = 0;
    if ((ret = pkcs8_get_privatekey(key, &d))) return ret;
    if ((ret = aid_get_dstu4145_params(&key->privateKeyAlgorithm, &ctx))) return ret;
    if ((ret = dstu4145_get_pubkey(ctx, d, &qx, &qy))) return ret;
    if ((ret = dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py))) return ret;
    printf("%d:", f[0]);
    print_be(d); printf(":"); print_be(qx); printf(":"); print_be(qy); printf(":"); print_be(n);
    /* pkcs8_get_kep_privatekey answers big-endian, where
     * pkcs8_get_privatekey answers in the file's (little-endian) order. */
    if (pkcs8_get_kep_privatekey(key, &kep) == RET_OK) {
        printf(" kep:");
        print_hex(kep);
    }
    dstu4145_free(ctx);
    return 0;
}

static int pkcs8_der(const ByteArray *der) {
    PrivateKeyInfo_t *key = pkcs8_alloc();
    int ret = pkcs8_decode(key, der);
    if (!ret) ret = print_key(key);
    pkcs8_free(key);
    return ret;
}

static int pbes2(const char *pass, const ByteArray *der) {
    EncryptedPrivateKeyInfo_t *c = asn_decode_ba_with_alloc(&EncryptedPrivateKeyInfo_desc, der);
    ByteArray *plain = NULL;
    if (!c) return -2;
    int ret = pkcs5_decrypt_dstu(c, pass, &plain);
    if (!ret) ret = pkcs8_der(plain);
    return ret;
}

static int p12(const char *pass, const char *key_pass, const ByteArray *der) {
    Pkcs12Ctx *ctx = NULL;
    const Pkcs12Keypair *keys = NULL;
    size_t count = 0;
    ByteArray **certs = NULL;
    int ret = pkcs12_decode(NULL, der, pass, &ctx);
    if (ret) return ret;
    if ((ret = pkcs12_enum_keys(ctx, &keys, &count))) return ret;
    for (size_t i = 0; i < count; i++) {
        if ((ret = pkcs12_select_key(ctx, keys[i].alias, key_pass))) return ret;
        printf("%skey %s ", i ? " | " : "", keys[i].alias ? keys[i].alias : "-");
        if ((ret = print_key(ctx->curr_key))) return ret;
    }
    if (pkcs12_get_certificates(ctx, &certs) == RET_OK && certs) {
        for (size_t i = 0; certs[i]; i++) {
            printf(" | cert ");
            print_hex(certs[i]);
        }
    }
    return 0;
}

int main(void) {
    static char line[1 << 22];
    while (fgets(line, sizeof line, stdin)) {
        char *f[4];
        int nf = 0;
        for (char *t = strtok(line, " \n"); t && nf < 4; t = strtok(NULL, " \n")) f[nf++] = t;
        int ret = -1;
        if (nf == 2 && !strcmp(f[0], "pkcs8")) {
            ret = pkcs8_der(field(f[1]));
        } else if (nf == 3 && !strcmp(f[0], "pbes2")) {
            ret = pbes2(password(f[1]), field(f[2]));
        } else if (nf == 4 && !strcmp(f[0], "p12")) {
            ret = p12(password(f[1]), password(f[2]), field(f[3]));
        }
        if (ret) printf("error: %d", ret);
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
