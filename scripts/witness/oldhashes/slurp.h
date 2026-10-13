/* The request loop the C drivers share: one request per line on stdin,
 * "NAME PATH", answered with the lowercase hex digest of the file's bytes
 * under NAME, or "error" for a name the driver does not have. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Fills out (at most OUT_MAX bytes, 64 unless the driver says) and
 * returns its length, or 0 for a name the driver does not have. */
#ifndef OUT_MAX
#define OUT_MAX 64
#endif
static size_t hash(const char *name, const unsigned char *data, size_t len, unsigned char *out);

int main(void) {
    char line[4096], name[256], path[3800];
    while (fgets(line, sizeof line, stdin)) {
        size_t len, n;
        unsigned char *data, out[OUT_MAX];
        if (sscanf(line, "%255s %3799s", name, path) != 2 || !(data = slurp(path, &len))) {
            printf("error\n");
            continue;
        }
        n = hash(name, data, len, out);
        if (!n) printf("error");
        for (size_t i = 0; i < n; i++) printf("%02x", out[i]);
        printf("\n");
        fflush(stdout);
        free(data);
    }
    return 0;
}
