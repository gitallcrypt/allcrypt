/* Drives XKCP K12's TurboSHAKE and KangarooTwelve from stdin, a case a
 * line, every message and customization string RFC 9861's ptn(n):
 *
 *   ts SECURITY DOMAIN LENGTH MESSAGE_LEN      TurboSHAKE (DOMAIN in hex)
 *   kt SECURITY LENGTH MESSAGE_LEN CUSTOM_LEN  KT128 or KT256
 *
 * printing the output in hex. Inputs sit at the offset argv[1] gives in
 * their heap blocks, so 1 misaligns them; the message is fed in pieces of
 * argv[2] bytes (0: one call). */
#include "KangarooTwelve.c"
#include <stdio.h>

/* KangarooTwelve_Update calls this only with a thread pool, and the
 * driver passes none; defined so the threading files stay out. */
int KT_ProcessChunksThreaded(const KT_ThreadPool_API * api, void * handle, int threads,
                             const unsigned char * input, size_t chunks,
                             unsigned char * values, int security) {
    (void)api; (void)handle; (void)threads; (void)input; (void)chunks; (void)values;
    (void)security;
    return -1;
}
#include <stdlib.h>
#include <string.h>

static unsigned char * ptn(size_t n, size_t offset, unsigned char ** base) {
    *base = malloc(n + offset + 1);
    for (size_t i = 0; i < n; i++) (*base)[offset + i] = (unsigned char)(i % 251);
    return *base + offset;
}

int main(int argc, char ** argv) {
    size_t offset = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    size_t piece = argc > 2 ? (size_t)atoi(argv[2]) : 0;
    char kind[8];
    while (scanf("%7s", kind) == 1) {
        unsigned security, domain = 0;
        size_t length, mlen, clen = 0;
        if (!strcmp(kind, "ts")) {
            if (scanf("%u %x %zu %zu", &security, &domain, &length, &mlen) != 4) return 2;
        } else {
            if (scanf("%u %zu %zu %zu", &security, &length, &mlen, &clen) != 4) return 2;
        }
        unsigned char *mbase, *cbase, *out = malloc(length + 1);
        unsigned char *m = ptn(mlen, offset, &mbase), *c = ptn(clen, offset, &cbase);
        size_t step = piece ? piece : (mlen ? mlen : 1);
        if (!strcmp(kind, "ts")) {
            TurboSHAKE_Instance t;
            TurboSHAKE_Initialize(&t, 2 * security);
            for (size_t i = 0; i < mlen; i += step)
                TurboSHAKE_Absorb(&t, m + i, mlen - i < step ? mlen - i : step);
            TurboSHAKE_AbsorbDomainSeparationByte(&t, (unsigned char)domain);
            TurboSHAKE_Squeeze(&t, out, length);
        } else {
            KangarooTwelve_Instance k;
            if (KangarooTwelve_Initialize(&k, (int)security, length)) return 3;
            for (size_t i = 0; i < mlen; i += step)
                if (KangarooTwelve_Update(&k, m + i, mlen - i < step ? mlen - i : step)) return 3;
            if (KangarooTwelve_Final(&k, out, c, clen)) return 3;
        }
        for (size_t i = 0; i < length; i++) printf("%02x", out[i]);
        printf("%s\n", length ? "" : "-");
        fflush(stdout);
        free(out); free(mbase); free(cbase);
    }
    return 0;
}
