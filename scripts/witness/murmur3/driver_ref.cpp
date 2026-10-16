/* SMHasher's MurmurHash3.cpp, the reference. One request per line on
 * stdin, "NAME KEY PATH", NAME murmur3_32, murmur3_x86_128 or
 * murmur3_x64_128 and KEY "seed:" and eight hex digits; answered with
 * the hash of the file's bytes, each word big endian, first word first,
 * or "error". The reference has no streaming interface, so the data
 * goes in whole. */
#include "MurmurHash3.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

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

int main() {
    char line[8192], name[64], key[64], path[4000];
    while (fgets(line, sizeof line, stdin)) {
        size_t len;
        unsigned char *data;
        if (sscanf(line, "%63s %63s %3999s", name, key, path) != 3
                || strncmp(key, "seed:", 5) || strlen(key) != 13
                || !(data = slurp(path, &len))) {
            printf("error\n");
            continue;
        }
        uint32_t seed = (uint32_t)strtoul(key + 5, NULL, 16);
        if (!strcmp(name, "murmur3_32")) {
            uint32_t h;
            MurmurHash3_x86_32(data, (int)len, seed, &h);
            printf("%08x\n", h);
        } else if (!strcmp(name, "murmur3_x86_128")) {
            uint32_t h[4];
            MurmurHash3_x86_128(data, (int)len, seed, h);
            printf("%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3]);
        } else if (!strcmp(name, "murmur3_x64_128")) {
            uint64_t h[2];
            MurmurHash3_x64_128(data, (int)len, seed, h);
            printf("%016llx%016llx\n", (unsigned long long)h[0], (unsigned long long)h[1]);
        } else {
            printf("error\n");
        }
        fflush(stdout);
        free(data);
    }
    return 0;
}
