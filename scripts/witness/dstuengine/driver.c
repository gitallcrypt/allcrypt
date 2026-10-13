/* dstuengine-witness FORMAT FILE PASSWORD [KEY_PASSWORD]
 *
 * Opens a Ukrainian key container with dstu-engine's keylib, through
 * OpenSSL with the dstu engine loaded from DSTU_ENGINE (a path to
 * dstu.so). FORMAT is
 *
 *   key6    IIT's Key-6.dat
 *   pkcs12  PKCS#12
 *   jks     JKS; KEY_PASSWORD is the second password
 *   pkcs8   DER: a plain PrivateKeyInfo when PASSWORD is "-", else an
 *           EncryptedPrivateKeyInfo that OpenSSL decrypts (PBES2 with
 *           the engine's GOST 28147 CFB and HMAC-GOST 34.311 among its
 *           schemes). Either way keylib's reader, which also takes the
 *           second key IIT keeps in the attributes.
 *
 * One line per key, in keylib's order:
 *
 *   key m=M poly=HEX a=HEX b=HEX n=HEX gx=HEX gy=HEX d=HEX qx=HEX qy=HEX
 *
 * every value big-endian hex (poly is the reduction polynomial with all
 * its terms; d as keylib holds it, which can exceed n), then "certs N"
 * and a line "cert HEX" with the SHA-256 of each certificate's DER.
 * "error: ..." when keylib refuses.
 *
 *   dstuengine-witness pbkdf2 PASSWORD SALT_HEX ITERATIONS LENGTH
 *   dstuengine-witness p12kdf PASSWORD SALT_HEX ITERATIONS LENGTH ID
 *
 * PBKDF2 with HMAC-GOST 34.311, and OpenSSL's PKCS#12 key derivation
 * (PKCS12_key_gen_utf8: the password made a BMPString with its two-byte
 * NUL), over the engine's GOST 34.311, as hex. PASSWORD is "-" for the
 * empty one.
 *
 *   dstuengine-witness x509 CERT ISSUER
 *
 * CERT's public key as "pub m=M poly=HEX a=HEX b=HEX n=HEX gx=HEX gy=HEX
 * qx=HEX qy=HEX", as above without d, then "verify 1" when X509_verify
 * accepts CERT's signature under ISSUER's key and "verify 0" when it does
 * not. OpenSSL's object table has no signature pairing for the
 * dstu4145le and dstu4145be OIDs, which name the key and the signature
 * both, so the driver adds the one the standard defines: DSTU 4145 over
 * GOST 34.311, whose S-box the engine takes from the verifying key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "keystore.h"
#include "key6.h"
#include "jks.h"
#include "pkcs12.h"
#include "utils.h"
#include "key.h"

static void hex_bn(const char *name, const BIGNUM *v) {
    char *h = BN_bn2hex(v);
    printf(" %s=%s", name, h);
    OPENSSL_free(h);
}

static unsigned char *unhex(const char *s, size_t *len) {
    size_t n = strlen(s) / 2;
    unsigned char *out = malloc(n + 1);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    *len = n;
    return out;
}

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n ? n : 1);
    *len = fread(buf, 1, n, f);
    fclose(f);
    return buf;
}

static void print_key_as(const char *label, const EVP_PKEY *pkey, int with_private) {
    const DSTU_KEY *key = EVP_PKEY_get0((EVP_PKEY *)pkey);
    const EC_KEY *ec = key->ec;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new(), *x = BN_new(), *y = BN_new();
    EC_GROUP_get_curve(group, p, a, b, ctx);
    printf("%s m=%d", label, EC_GROUP_get_degree(group));
    hex_bn("poly", p);
    hex_bn("a", a);
    hex_bn("b", b);
    hex_bn("n", EC_GROUP_get0_order(group));
    EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group), x, y, ctx);
    hex_bn("gx", x);
    hex_bn("gy", y);
    if (with_private) hex_bn("d", EC_KEY_get0_private_key(ec));
    EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(ec), x, y, ctx);
    hex_bn("qx", x);
    hex_bn("qy", y);
    printf("\n");
    BN_free(p); BN_free(a); BN_free(b); BN_free(x); BN_free(y);
    BN_CTX_free(ctx);
}

static void print_key(const EVP_PKEY *pkey) {
    print_key_as("key", pkey, 1);
}

static X509 *read_cert(const char *path) {
    size_t len;
    unsigned char *data = slurp(path, &len);
    const unsigned char *p = data;
    X509 *cert = data ? d2i_X509(NULL, &p, len) : NULL;
    free(data);
    return cert;
}

static int x509_verify(const char *cert_path, const char *issuer_path) {
    OBJ_add_sigid(NID_dstu4145le, NID_dstu34311, NID_dstu4145le);
    OBJ_add_sigid(NID_dstu4145be, NID_dstu34311, NID_dstu4145be);
    X509 *cert = read_cert(cert_path), *issuer = read_cert(issuer_path);
    EVP_PKEY *subject_key = cert ? X509_get0_pubkey(cert) : NULL;
    EVP_PKEY *issuer_key = issuer ? X509_get0_pubkey(issuer) : NULL;
    if (!subject_key || !issuer_key) {
        printf("error: cannot read the certificates or their keys\n");
        return 1;
    }
    print_key_as("pub", subject_key, 0);
    printf("verify %d\n", X509_verify(cert, issuer_key) == 1);
    X509_free(cert);
    X509_free(issuer);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: dstuengine-witness FORMAT FILE PASSWORD [KEY_PASSWORD]\n");
        return 2;
    }
    const char *so = getenv("DSTU_ENGINE");
    ENGINE_load_dynamic();
    ENGINE *e = ENGINE_by_id("dynamic");
    if (!so || !e || !ENGINE_ctrl_cmd_string(e, "SO_PATH", so, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0) || !ENGINE_init(e)) {
        printf("error: cannot load the dstu engine from DSTU_ENGINE\n");
        return 1;
    }
    ENGINE_set_default(e, ENGINE_METHOD_ALL);

    if (!strcmp(argv[1], "x509")) {
        return x509_verify(argv[2], argv[3]);
    }

    if (!strcmp(argv[1], "pbkdf2") || !strcmp(argv[1], "p12kdf")) {
        size_t salt_len;
        unsigned char *salt = unhex(argv[3], &salt_len);
        const char *pass = strcmp(argv[2], "-") ? argv[2] : "";
        int iterations = atoi(argv[4]), length = atoi(argv[5]);
        unsigned char out[256];
        const EVP_MD *md = EVP_get_digestbynid(NID_dstu34311);
        int ok = !strcmp(argv[1], "pbkdf2")
            ? PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, salt_len, iterations, md,
                                length, out)
            : PKCS12_key_gen_utf8(pass, strlen(pass), salt, salt_len, atoi(argv[6]),
                                  iterations, length, out, md);
        if (!ok) {
            printf("error: derivation failed\n");
            return 1;
        }
        for (int i = 0; i < length; i++) printf("%02x", out[i]);
        printf("\n");
        return 0;
    }

    size_t len;
    unsigned char *data = slurp(argv[2], &len);
    if (!data) {
        printf("error: cannot read %s\n", argv[2]);
        return 1;
    }
    KeyStore *ks = NULL;
    int ok;
    const char *pw = argv[3];
    if (!strcmp(argv[1], "key6")) {
        ok = parseKey6(data, len, pw, strlen(pw), &ks);
    } else if (!strcmp(argv[1], "pkcs12")) {
        ok = parsePKCS12(data, len, pw, strlen(pw), &ks);
    } else if (!strcmp(argv[1], "jks")) {
        const char *kp = argc > 4 ? argv[4] : pw;
        ok = parseJKS(data, len, pw, strlen(pw), kp, strlen(kp), &ks);
    } else if (!strcmp(argv[1], "pkcs8")) {
        if (!strcmp(pw, "-")) {
            ok = keysFromPKCS8(data, len, &ks);
        } else {
            const unsigned char *p = data;
            X509_SIG *sig = d2i_X509_SIG(NULL, &p, len);
            PKCS8_PRIV_KEY_INFO *info = sig ? PKCS8_decrypt(sig, pw, strlen(pw)) : NULL;
            unsigned char *der = NULL;
            int n = info ? i2d_PKCS8_PRIV_KEY_INFO(info, &der) : -1;
            ok = n > 0 && keysFromPKCS8(der, n, &ks);
            OPENSSL_free(der);
            PKCS8_PRIV_KEY_INFO_free(info);
            X509_SIG_free(sig);
        }
    } else {
        printf("error: unknown format %s\n", argv[1]);
        return 1;
    }
    if (!ok || !ks) {
        printf("error: keylib refused the container\n");
        return 1;
    }
    for (size_t i = 0; i < KeyStoreKeyNum(ks); i++) print_key(KeyStoreGetKey(ks, i));
    printf("certs %zu\n", KeyStoreCertNum(ks));
    for (size_t i = 0; i < KeyStoreCertNum(ks); i++) {
        unsigned char *der = NULL, digest[32];
        int n = i2d_X509((X509 *)KeyStoreGetCert(ks, i), &der);
        SHA256(der, n, digest);
        printf("cert ");
        for (int j = 0; j < 32; j++) printf("%02x", digest[j]);
        printf("\n");
        OPENSSL_free(der);
    }
    KeyStoreFree(ks);
    return 0;
}
