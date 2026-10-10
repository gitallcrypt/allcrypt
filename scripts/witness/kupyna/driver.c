/* kupyna-witness HASH_BITS
 *
 * Reads one message per line of hex on stdin ("-" for the empty one)
 * and writes the reference implementation's Kupyna hash of it, one hex
 * line each. HASH_BITS is any multiple of 8 from 8 to 512. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kupyna.h"

int main(int argc, char **argv) {
    size_t bits = (size_t)atoi(argv[1]);
    static char line[65536];
    static uint8_t msg[32768];
    while (fgets(line, sizeof line, stdin)) {
        size_t n = 0;
        for (char *s = line; s[0] && s[1] && s[0] != '\n' && s[0] != '-'; s += 2) {
            unsigned v;
            sscanf(s, "%2x", &v);
            msg[n++] = (uint8_t)v;
        }
        kupyna_t ctx;
        uint8_t out[64];
        if (KupynaInit(bits, &ctx) != 0) {
            printf("error: size\n");
            continue;
        }
        KupynaHash(&ctx, msg, n * 8, out);
        for (size_t i = 0; i < bits / 8; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
