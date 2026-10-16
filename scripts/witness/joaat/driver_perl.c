/* Perl 5.24's S_perl_hash_old_one_at_a_time, from hv_func.h, cut out
 * by build.sh into perl_oaat.h: the one-at-a-time hash Perl's hashes
 * used before 5.18, starting from the seed. One request per line on
 * stdin, "NAME KEY PATH", NAME joaat and KEY "seed:" and eight hex
 * digits; answered with the hash of the file's bytes as lowercase big
 * endian hex, or "error". The data goes in whole. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t U32;
typedef size_t STRLEN;
#define PERL_STATIC_INLINE static inline
PERL_STATIC_INLINE U32
#include "perl_oaat.h"

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
    *len = fread(buf, 1, n, f);
    fclose(f);
    return buf;
}

int main(void) {
    char line[8192], name[64], key[64], path[4000];
    while (fgets(line, sizeof line, stdin)) {
        size_t len;
        unsigned char *data;
        if (sscanf(line, "%63s %63s %3999s", name, key, path) != 3 || strcmp(name, "joaat")
                || strncmp(key, "seed:", 5) || strlen(key) != 13
                || !(data = slurp(path, &len))) {
            printf("error\n");
            continue;
        }
        /* Perl reads its seed as a native U32: this little endian. */
        U32 seed = (U32)strtoul(key + 5, NULL, 16);
        printf("%08x\n", S_perl_hash_old_one_at_a_time((const unsigned char *)&seed, data, len));
        fflush(stdout);
        free(data);
    }
    return 0;
}
