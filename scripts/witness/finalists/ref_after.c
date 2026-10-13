/* One SUPERCOP reference file, included whole so that its state can be
 * reached: IMPL_ref_after hashes in[0..inlen) with a context told it has
 * already taken `taken` bytes (whole blocks), which is how the counter's
 * high word is reached without hashing 512 MB. Compiled once per IMPL,
 * with WORD its word width. */
#include "hash.c"

#define CAT(a, b) a##b
#define XCAT(a, b) CAT(a, b)

int XCAT(IMPL, _ref_after)(unsigned char *out, const unsigned char *in, unsigned long long inlen,
                           unsigned long long taken) {
    state S;
    XCAT(IMPL, _init)(&S);
#if WORD == 32
    S.t[0] = (u32)(taken << 3);
    S.t[1] = (u32)(taken >> 29);
#else
    S.t[0] = taken << 3;
    S.t[1] = taken >> 61;
#endif
    XCAT(IMPL, _update)(&S, in, inlen * 8);
    XCAT(IMPL, _final)(&S, out);
    return 0;
}
