/* kalyna-witness BLOCK_BITS enc|dec
 * kalyna-witness sboxes
 *
 * Reads "KEY DATA" lines of hex on stdin and writes the reference
 * implementation's result for each, one block, one hex line per input
 * line; the key's length gives the key size. Words are read and written
 * little endian, as the reference keeps them. "sboxes" prints the four
 * encryption S-boxes, one hex line each. */
#include <stdio.h>
#include <string.h>
#include "kalyna.h"

extern uint8_t sboxes_enc[4][256];

static int unhex(const char *s, uint8_t *out, int max) {
    int n = 0;
    while (s[0] && s[1] && s[0] != ' ' && s[0] != '\n' && n < max) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "sboxes") == 0) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 256; j++) printf("%02x", sboxes_enc[i][j]);
            printf("\n");
        }
        return 0;
    }
    size_t block = (size_t)atoi(argv[1]);
    int decrypt = strcmp(argv[2], "dec") == 0;
    char line[1024];
    while (fgets(line, sizeof line, stdin)) {
        uint8_t key[64], data[64];
        char *space = strchr(line, ' ');
        if (!space) continue;
        int klen = unhex(line, key, 64);
        int dlen = unhex(space + 1, data, 64);
        kalyna_t *ctx = KalynaInit(block, (size_t)klen * 8);
        if (!ctx || (size_t)dlen * 8 != block) {
            printf("error: sizes\n");
            continue;
        }
        uint64_t k[8], in[8], out[8];
        memcpy(k, key, klen);
        memcpy(in, data, dlen);
        KalynaKeyExpand(k, ctx);
        if (decrypt) KalynaDecipher(in, ctx, out); else KalynaEncipher(in, ctx, out);
        const uint8_t *o = (const uint8_t *)out;
        for (int i = 0; i < dlen; i++) printf("%02x", o[i]);
        printf("\n");
        KalynaDelete(ctx);
    }
    return 0;
}
