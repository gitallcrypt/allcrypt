/* Cisco's hash-sigs as a witness, under the request lines selftest.py
 * describes. Keys are made with the library's own key generation, fed
 * SEED || I as its randomness: with SECRET_METHOD 2, the RFC 8554 Appendix
 * A derivation, that is the top tree's SEED and I. To sign after `count`
 * signatures, the count is written into the private key's first eight
 * bytes, where the library keeps it, and the key is loaded again. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hss.h"
#include "hss_verify.h"

static unsigned char random_bytes[64];
static size_t random_len;
static unsigned char private_key[HSS_MAX_PRIVATE_KEY_LEN];
static size_t private_len;

static bool give_random(void *out, size_t len) {
    if (len != random_len) return false;
    memcpy(out, random_bytes, len);
    return true;
}

static bool keep_private(unsigned char *key, size_t len, void *context) {
    (void)context;
    if (len > sizeof private_key) return false;
    memcpy(private_key, key, len);
    private_len = len;
    return true;
}

static bool read_private(unsigned char *key, size_t len, void *context) {
    (void)context;
    if (len > private_len) return false;
    memcpy(key, private_key, len);
    return true;
}

static int unhex(const char *s, unsigned char *out, size_t max, size_t *len) {
    size_t n = strlen(s);
    if (strcmp(s, "-") == 0) { *len = 0; return 1; }
    if (n % 2 || n / 2 > max) return 0;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (unsigned char)v;
    }
    *len = n / 2;
    return 1;
}

static void hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

/* OFFSET moves every buffer handed to the library off its alignment, for
 * a sanitizer run: -DOFFSET=1. */
#ifndef OFFSET
#define OFFSET 0
#endif
static char line[1 << 22];
static unsigned char msg_buf[(1 << 20) + 8], sig_buf[(1 << 20) + 8], pub_buf[256 + 8];
#define msg (msg_buf + OFFSET)
#define sig (sig_buf + OFFSET)
#define pub (pub_buf + OFFSET)

/* hss <L> <lms> <ots> ... <seed||I hex> <count> <message hex>: public key
 * and signature, space separated. */
static void hss(char **f, int nf) {
    if (nf < 4) { printf("error request\n"); return; }
    unsigned levels = (unsigned)atoi(f[1]);
    if (levels < 1 || levels > 8 || nf != 2 + 2 * (int)levels + 3) {
        printf("error request\n"); return;
    }
    param_set_t lm[8], ots[8];
    for (unsigned i = 0; i < levels; i++) {
        lm[i] = (param_set_t)strtoul(f[2 + 2 * i], 0, 10);
        ots[i] = (param_set_t)strtoul(f[3 + 2 * i], 0, 10);
    }
    char *seed = f[2 + 2 * levels];
    unsigned long long count = strtoull(f[3 + 2 * levels], 0, 10);
    size_t msg_len;
    if (!unhex(seed, random_bytes, sizeof random_bytes, &random_len) ||
        !unhex(f[4 + 2 * levels], msg, 1 << 20, &msg_len)) {
        printf("error request\n"); return;
    }
    size_t pub_len = hss_get_public_key_len(levels, lm, ots);
    if (!pub_len || !hss_generate_private_key(give_random, levels, lm, ots, keep_private, 0,
                                              pub, pub_len, 0, 0, 0)) {
        printf("error unsupported\n"); return;
    }
    for (int i = 7; i >= 0; i--) { private_key[i] = (unsigned char)count; count >>= 8; }
    struct hss_working_key *w = hss_load_private_key(read_private, 0, 0, 0, 0, 0);
    if (!w) { printf("error load\n"); return; }
    size_t sig_len = hss_get_signature_len_from_working_key(w);
    struct hss_extra_info info;
    hss_init_extra_info(&info);
    bool ok = sig_len && sig_len <= (1 << 20) &&
        hss_generate_signature(w, keep_private, 0, msg, msg_len, sig, sig_len, &info);
    hss_free_working_key(w);
    if (!ok) { printf("error sign\n"); return; }
    for (size_t i = 0; i < pub_len; i++) printf("%02x", pub[i]);
    printf(" ");
    hex(sig, sig_len);
}

/* lms <lms> <ots> <seed||I hex> <q> <message hex>: the LMS public key and
 * signature, which are a one-level hierarchy's less its leading four
 * bytes. */
static void lms(char **f, int nf) {
    if (nf != 6) { printf("error request\n"); return; }
    char *g[8] = { "hss", "1", f[1], f[2], f[3], f[4], f[5], 0 };
    char *out = 0;
    size_t out_len = 0;
    FILE *saved = stdout;
    FILE *capture = open_memstream(&out, &out_len);
    stdout = capture;
    hss(g, 7);
    fflush(capture);
    stdout = saved;
    fclose(capture);
    char *space = strchr(out, ' ');
    if (strncmp(out, "error", 5) == 0 || !space || strlen(space) < 10) {
        printf("%s", out);
    } else {
        *space = 0;
        printf("%s %s", out + 8, space + 9);
    }
    free(out);
}

/* verify <public key> <message> <signature>: ok or bad. */
static void verify(char **f, int nf) {
    size_t pub_len, msg_len, sig_len;
    if (nf != 4 || !unhex(f[1], pub, 256, &pub_len) ||
        !unhex(f[2], msg, 1 << 20, &msg_len) || !unhex(f[3], sig, 1 << 20, &sig_len)) {
        printf("error request\n"); return;
    }
    printf("%s\n", hss_validate_signature(pub, msg, msg_len, sig, sig_len, 0) ? "ok" : "bad");
}

int main(void) {
    while (fgets(line, sizeof line, stdin)) {
        char *f[32];
        int nf = 0;
        for (char *t = strtok(line, " \n"); t && nf < 32; t = strtok(0, " \n")) f[nf++] = t;
        if (nf == 0) { printf("error request\n"); }
        else if (strcmp(f[0], "hss") == 0) hss(f, nf);
        else if (strcmp(f[0], "lms") == 0) lms(f, nf);
        else if (strcmp(f[0], "verify") == 0) verify(f, nf);
        else printf("error request\n");
        fflush(stdout);
    }
    return 0;
}
