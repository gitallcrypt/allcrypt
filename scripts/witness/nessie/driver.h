/* The request loop every NESSIE witness shares. A driver defines
 *
 *     static int  set_key(const unsigned char *key, size_t len);  0 or -1
 *     static void encrypt(unsigned char *block);                  in place
 *     static void decrypt(unsigned char *block);
 *     static size_t block_size(void);
 *
 * and includes this. One request per line on stdin, one answer per line
 * on stdout, hex, or "error ..." when the lengths are refused:
 *
 *     enc <key hex> <block hex>          one block
 *     dec <key hex> <block hex>
 *     enc-n <key hex> <block hex> <n>    the block encrypted n times over,
 *     dec-n <key hex> <block hex> <n>    as NESSIE's "Iterated n times"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *s, unsigned char *out, size_t max) {
    size_t n = strlen(s) / 2;
    if (n > max || strlen(s) % 2) return (size_t)-1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return (size_t)-1;
        out[i] = (unsigned char)v;
    }
    return n;
}

int main(void) {
    char line[1024], op[16], k[512], b[512];
    unsigned char key[256], block[256];
    while (fgets(line, sizeof line, stdin)) {
        long count = 1;
        int fields = sscanf(line, "%15s %511s %511s %ld", op, k, b, &count);
        size_t klen = fields >= 3 ? unhex(k, key, sizeof key) : (size_t)-1;
        size_t blen = fields >= 3 ? unhex(b, block, sizeof block) : (size_t)-1;
        int iterated = !strcmp(op, "enc-n") || !strcmp(op, "dec-n");
        int decrypting = !strcmp(op, "dec") || !strcmp(op, "dec-n");
        if (!iterated && strcmp(op, "enc") && strcmp(op, "dec")) {
            printf("error op\n");
        } else if (blen != block_size() || (iterated && (fields != 4 || count < 1))
                   || klen == (size_t)-1 || set_key(key, klen)) {
            printf("error lengths\n");
        } else {
            if (!iterated) count = 1;
            for (long i = 0; i < count; i++) {
                if (decrypting) decrypt(block); else encrypt(block);
            }
            for (size_t i = 0; i < blen; i++) printf("%02x", block[i]);
            printf("\n");
        }
        fflush(stdout);
    }
    return 0;
}
