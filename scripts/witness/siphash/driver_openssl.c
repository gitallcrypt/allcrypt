/* OpenSSL 3.5's SipHash, through EVP_MAC with its c-rounds, d-rounds and
 * size parameters. Requests as driver_ref.c's, siphash only; see
 * ../oldhashes/slurp.h. The data goes in in pieces of 1, 2, 3 ... bytes. */
#include "slurp.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out) {
    char hex[64];
    unsigned c, d, bytes;
    unsigned char key[16];
    if (sscanf(name, "siphash-%u-%u-%u:%63s", &c, &d, &bytes, hex) != 4 || strlen(hex) != 32)
        return 0;
    for (size_t i = 0; i < 16; i++) sscanf(hex + 2 * i, "%2hhx", &key[i]);
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "SIPHASH", NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    size_t size = bytes, written = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size),
        OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &c),
        OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &d),
        OSSL_PARAM_construct_end(),
    };
    int ok = ctx && EVP_MAC_init(ctx, key, 16, params);
    for (size_t at = 0, step = 1; ok && at < len; at += step, step++)
        ok = EVP_MAC_update(ctx, data + at, step < len - at ? step : len - at);
    ok = ok && EVP_MAC_final(ctx, out, &written, 16) && written == bytes;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok ? bytes : 0;
}
