/* kupyna-witness HASH_BITS
 * kupyna-witness MAC_BITS kmac
 *
 * Reads one message per line of hex on stdin ("-" for the empty one)
 * and writes the reference implementation's Kupyna hash of it, one hex
 * line each. HASH_BITS is any multiple of 8 from 8 to 512.
 *
 * With "kmac", each line is "KEY MESSAGE" and the answer is KupynaKmac's
 * MAC of MAC_BITS (256, 384 or 512). The reference takes a key of exactly
 * MAC_BITS, and it sizes its buffer as if the message had no whole block
 * - it adds the key's whole-block count where the message's belongs - so
 * it is asked about messages shorter than one block only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kupyna.h"

static size_t unhex(const char *s, uint8_t *out) {
    size_t n = 0;
    for (; s[0] && s[1] && s[0] != '\n' && s[0] != ' ' && s[0] != '-'; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

int main(int argc, char **argv) {
    size_t bits = (size_t)atoi(argv[1]);
    int kmac = argc > 2 && !strcmp(argv[2], "kmac");
    static char line[65536];
    static uint8_t msg[32768];
    static uint8_t key[128];
    while (fgets(line, sizeof line, stdin)) {
        char *text = line;
        size_t k = 0;
        if (kmac) {
            k = unhex(line, key);
            text = strchr(line, ' ');
            text = text ? text + 1 : "-";
        }
        size_t n = unhex(text, msg);
        kupyna_t ctx;
        uint8_t out[64];
        if (KupynaInit(bits, &ctx) != 0) {
            printf("error: size\n");
            continue;
        }
        if (kmac) {
            if (k != bits / 8 || n >= ctx.nbytes) {
                printf("error: the reference's MAC takes a %zu-byte key and less than a block\n",
                       bits / 8);
                continue;
            }
            if (KupynaKmac(&ctx, key, bits, msg, n * 8, out) != 0) {
                printf("error: kmac\n");
                continue;
            }
        } else {
            KupynaHash(&ctx, msg, n * 8, out);
        }
        for (size_t i = 0; i < bits / 8; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
