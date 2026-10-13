/* Strumok (DSTU 8845:2019) through UAPKI's dstu8845.c.
 *
 * One request per line on stdin:
 *
 *     <key hex> <iv hex> <n>[,<n>...]
 *
 * and one line back: the keystream, as hex, produced by encrypting zero
 * bytes in pieces of the given lengths, one dstu8845_crypt call each, so
 * that a piece boundary inside a word or a 128 byte block of keystream
 * is exercised. "error <code>" when the library refuses.
 *
 * "selftest" runs the library's own dstu8845_self_test and prints its
 * return code.
 *
 * The library's random generator and stack trace are not compiled in;
 * the three functions below stand in for them. Strumok needs neither:
 * the generator is only for dstu8845_generate_key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte-array.h"
#include "dstu8845.h"

int drbg_random(ByteArray *random) { (void)random; return -1; }
void stacktrace_create(const char *f, const size_t l, const int e, const char *m)
{ (void)f; (void)l; (void)e; (void)m; }
void stacktrace_add(const char *f, const size_t l, const int e) { (void)f; (void)l; (void)e; }

static size_t unhex(const char *s, unsigned char *out, size_t max)
{
    size_t n = 0;
    while (s[0] && s[1] && n < max) {
        unsigned int b;
        if (sscanf(s, "%2x", &b) != 1) break;
        out[n++] = (unsigned char)b;
        s += 2;
    }
    return n;
}

int main(void)
{
    static char line[1 << 16];
    while (fgets(line, sizeof line, stdin)) {
        if (strncmp(line, "selftest", 8) == 0) {
            printf("%d\n", dstu8845_self_test());
            fflush(stdout);
            continue;
        }
        char *key_hex = strtok(line, " \n");
        char *iv_hex = strtok(NULL, " \n");
        char *pieces = strtok(NULL, " \n");
        if (!key_hex || !iv_hex || !pieces) { printf("error request\n"); fflush(stdout); continue; }
        unsigned char key[128], iv[128];
        size_t key_len = unhex(key_hex, key, sizeof key);
        size_t iv_len = unhex(iv_hex, iv, sizeof iv);
        ByteArray *k = ba_alloc_from_uint8(key, key_len);
        ByteArray *v = ba_alloc_from_uint8(iv, iv_len);
        Dstu8845Ctx *ctx = dstu8845_alloc();
        int ret = dstu8845_init(ctx, k, v);
        if (ret != 0) {
            printf("error %d\n", ret);
        } else {
            for (char *p = strtok(pieces, ","); p; p = strtok(NULL, ",")) {
                size_t n = strtoul(p, NULL, 10);
                /* ba_alloc_by_len(0) may fail on malloc(0); an empty
                 * piece produces nothing anyway. */
                if (n == 0) continue;
                ByteArray *z = ba_alloc_by_len(n);
                memset(ba_get_buf(z), 0, n);
                ret = dstu8845_crypt(ctx, z);
                if (ret != 0) { printf("error %d", ret); ba_free(z); break; }
                const unsigned char *b = ba_get_buf_const(z);
                for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
                ba_free(z);
            }
            printf("\n");
        }
        dstu8845_free(ctx);
        ba_free(k);
        ba_free(v);
        fflush(stdout);
    }
    return 0;
}
