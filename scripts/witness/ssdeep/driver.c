/* ssdeep-witness: libfuzzy (ssdeep 2.14.1's fuzzy.c) over files.
 *
 * One request per line on stdin:
 *
 *   hash PATH          the digest of the file's bytes, fuzzy_hash_buf's -
 *                      which knows the length in advance - after checking
 *                      that hashing it in 4096-byte pieces without the
 *                      length gives the same
 *   compare SIG SIG    fuzzy_compare's score, 0 to 100, or -1
 *
 * One line out per request, "error" on a failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fuzzy.h"

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

int main(void) {
    char line[2 * FUZZY_MAX_RESULT + 4200];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (!strncmp(line, "hash ", 5)) {
            size_t len;
            unsigned char *data = slurp(line + 5, &len);
            char whole[FUZZY_MAX_RESULT], pieces[FUZZY_MAX_RESULT];
            struct fuzzy_state *state = fuzzy_new();
            int ok = data && fuzzy_hash_buf(data, (uint32_t)len, whole) == 0 && state;
            for (size_t at = 0; ok && at < len; at += 4096)
                ok = fuzzy_update(state, data + at, len - at < 4096 ? len - at : 4096) == 0;
            ok = ok && fuzzy_digest(state, pieces, 0) == 0 && !strcmp(whole, pieces);
            printf("%s\n", ok ? whole : "error");
            fuzzy_free(state);
            free(data);
        } else if (!strncmp(line, "compare ", 8)) {
            char *a = line + 8, *b = strchr(a, ' ');
            if (!b) { printf("error\n"); continue; }
            *b++ = 0;
            printf("%d\n", fuzzy_compare(a, b));
        } else {
            printf("error\n");
        }
        fflush(stdout);
    }
    return 0;
}
