/* blake2-witness: BLAKE2b and BLAKE2s at any output length, through
 * OpenSSL 3.5's provider and its "size" parameter.
 *
 * One request per line on stdin, "ALGORITHM BYTES HEX" - ALGORITHM is
 * blake2b or blake2s, BYTES the output length, HEX the message ("-" for
 * the empty one) - and one line of hex out per request, or "error".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

static size_t unhex(const char *s, unsigned char *out) {
    if (!strcmp(s, "-")) return 0;
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

int main(void) {
    static char line[1 << 20];
    static unsigned char message[1 << 19];
    char name[16];
    unsigned int size;
    while (fgets(line, sizeof line, stdin)) {
        char *hex = malloc(strlen(line) + 1);
        if (sscanf(line, "%15s %u %s", name, &size, hex) != 3) {
            printf("error\n");
            free(hex);
            continue;
        }
        const char *fetch = !strcmp(name, "blake2b") ? "BLAKE2B-512"
                          : !strcmp(name, "blake2s") ? "BLAKE2S-256" : NULL;
        EVP_MD *md = fetch ? EVP_MD_fetch(NULL, fetch, NULL) : NULL;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_SIZE, &size), OSSL_PARAM_END };
        unsigned char out[64];
        unsigned int n = sizeof out;
        size_t len = unhex(hex, message);
        if (md && EVP_DigestInit_ex2(ctx, md, params) && EVP_DigestUpdate(ctx, message, len)
                && EVP_DigestFinal_ex(ctx, out, &n) && n == size) {
            for (unsigned int i = 0; i < n; i++) printf("%02x", out[i]);
            printf("\n");
        } else {
            printf("error\n");
        }
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        free(hex);
    }
    return 0;
}
