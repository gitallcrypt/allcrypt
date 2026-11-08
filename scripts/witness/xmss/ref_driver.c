/* The XMSS reference implementation (XMSS/xmss-reference) as a witness,
 * under the request lines selftest.py describes. Keys come from
 * xmssmt_core_seed_keypair over SK_SEED || SK_PRF || SEED; to sign at index
 * idx, the index is written into the private key's first bytes, where the
 * reference keeps it. xmss_core.c is the plain variant, which computes
 * each signature's tree again. OFFSET moves every buffer handed to the
 * library off its alignment, for a sanitizer run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "xmss_core.h"

#ifndef OFFSET
#define OFFSET 0
#endif
static char line[1 << 22];
static unsigned char msg_buf[(1 << 20) + 8], sm_buf[(1 << 21) + 8], pk_buf[256 + 8],
    sk_buf[512 + 8], seed_buf[256 + 8];
#define msg (msg_buf + OFFSET)
#define sm (sm_buf + OFFSET)
#define pk (pk_buf + OFFSET)
#define sk (sk_buf + OFFSET)
#define seed (seed_buf + OFFSET)

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
}

static int params_for(xmss_params *params, const char *kind, uint32_t oid) {
    if (strcmp(kind, "xmss") == 0) return xmss_parse_oid(params, oid);
    if (strcmp(kind, "xmssmt") == 0) return xmssmt_parse_oid(params, oid);
    return -1;
}

/* sign <xmss|xmssmt> <oid> <SK_SEED||SK_PRF||SEED> <idx> <message>:
 * OID || root || SEED, and the signature. */
static void sign(char **f, int nf) {
    xmss_params params;
    size_t seed_len, msg_len;
    if (nf != 6) { printf("error request\n"); return; }
    uint32_t oid = (uint32_t)strtoul(f[2], 0, 10);
    if (params_for(&params, f[1], oid)) { printf("error unsupported\n"); return; }
    if (!unhex(f[3], seed, 256, &seed_len) || seed_len != 3 * params.n ||
        !unhex(f[5], msg, 1 << 20, &msg_len)) { printf("error request\n"); return; }
    unsigned long long idx = strtoull(f[4], 0, 10);
    if (params.full_height < 64 && idx >= (1ULL << params.full_height)) {
        printf("error index\n"); return;
    }
    /* XMSS is the one-layer case: the reference has no XMSS seed keypair
     * of its own and its xmss_core_keypair calls the XMSS^MT one. */
    xmssmt_core_seed_keypair(&params, pk, sk, seed);
    for (int i = (int)params.index_bytes - 1; i >= 0; i--) { sk[i] = (unsigned char)idx; idx >>= 8; }
    unsigned long long sm_len;
    int r = strcmp(f[1], "xmss") == 0
        ? xmss_core_sign(&params, sk, sm, &sm_len, msg, msg_len)
        : xmssmt_core_sign(&params, sk, sm, &sm_len, msg, msg_len);
    if (r) { printf("error sign\n"); return; }
    printf("%08x", oid);
    hex(pk, params.pk_bytes);
    printf(" ");
    hex(sm, params.sig_bytes);
    printf("\n");
}

/* verify <xmss|xmssmt> <OID || root || SEED> <message> <signature>. */
static void verify(char **f, int nf) {
    xmss_params params;
    size_t pk_len, msg_len, sig_len;
    if (nf != 5 || !unhex(f[2], pk, 256, &pk_len) || pk_len < 4) {
        printf("error request\n"); return;
    }
    uint32_t oid = (uint32_t)pk[0] << 24 | (uint32_t)pk[1] << 16 | (uint32_t)pk[2] << 8 | pk[3];
    if (params_for(&params, f[1], oid)) { printf("bad\n"); return; }
    if (!unhex(f[3], msg, 1 << 20, &msg_len) || !unhex(f[4], sm, 1 << 20, &sig_len)) {
        printf("error request\n"); return;
    }
    if (pk_len != 4 + params.pk_bytes || sig_len != params.sig_bytes) {
        printf("bad\n"); return;
    }
    memcpy(sm + sig_len, msg, msg_len);
    unsigned char *out = malloc(sig_len + msg_len + 1);
    unsigned long long out_len;
    int r = strcmp(f[1], "xmss") == 0
        ? xmss_core_sign_open(&params, out, &out_len, sm, sig_len + msg_len, pk + 4)
        : xmssmt_core_sign_open(&params, out, &out_len, sm, sig_len + msg_len, pk + 4);
    free(out);
    printf("%s\n", r == 0 ? "ok" : "bad");
}

int main(void) {
    while (fgets(line, sizeof line, stdin)) {
        char *f[16];
        int nf = 0;
        for (char *t = strtok(line, " \n"); t && nf < 16; t = strtok(0, " \n")) f[nf++] = t;
        if (nf && strcmp(f[0], "sign") == 0) sign(f, nf);
        else if (nf && strcmp(f[0], "verify") == 0) verify(f, nf);
        else printf("error request\n");
        fflush(stdout);
    }
    return 0;
}
