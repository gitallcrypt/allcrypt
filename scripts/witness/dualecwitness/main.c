/* OpenSSL FIPS module 2.0's Dual_EC_DRBG (fips_drbg_ec.c, unchanged),
 * driven one request a line for scripts/make_dual_ec_vectors.py:
 *
 *   new CURVE HASH ENTROPY NONCE PERS   CURVE: P-256 P-384 P-521
 *   gen NBYTES ADIN                     -> the bytes
 *   reseed ENTROPY ADIN
 *
 * Hex in and out; "-" is empty. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "fips_rand_lcl.h"
#include <openssl/fips_rand.h>

static size_t unhex(const char *s, unsigned char *out) {
	size_t n = 0;
	if (strcmp(s, "-") == 0) return 0;
	for (; s[0] && s[1]; s += 2) {
		unsigned int b; sscanf(s, "%2x", &b); out[n++] = (unsigned char)b;
	}
	return n;
}

int main(void) {
	static char line[1 << 20];
	static unsigned char a[1 << 18], b[1 << 18], c[1 << 18], out[1 << 18];
	DRBG_CTX ctx;
	int have = 0;
	OpenSSL_add_all_digests();
	while (fgets(line, sizeof line, stdin)) {
		char op[16], f1[1 << 16], f2[1 << 16], f3[1 << 16], f4[1 << 16], f5[1 << 16];
		if (sscanf(line, "%15s", op) != 1) continue;
		if (strcmp(op, "new") == 0) {
			int curve, md;
			sscanf(line, "%*s %s %s %s %s %s", f1, f2, f3, f4, f5);
			curve = strcmp(f1, "P-256") == 0 ? NID_X9_62_prime256v1 :
				strcmp(f1, "P-384") == 0 ? NID_secp384r1 : NID_secp521r1;
			md = OBJ_sn2nid(f2);
			if (have) ctx.uninstantiate(&ctx);
			memset(&ctx, 0, sizeof ctx);
			ctx.type = (curve << 16) | md;
			ctx.xflags = DRBG_FLAG_TEST;
			if (fips_drbg_ec_init(&ctx) != 1) { printf("ERR\n"); fflush(stdout); have = 0; continue; }
			have = 1;
			size_t na = unhex(f3, a), nb = unhex(f4, b), nc = unhex(f5, c);
			if (!ctx.instantiate(&ctx, a, na, nb ? b : NULL, nb, nc ? c : NULL, nc)) { printf("ERR\n"); }
			else printf("OK\n");
		} else if (strcmp(op, "gen") == 0) {
			size_t n; sscanf(line, "%*s %zu %s", &n, f1);
			size_t na = unhex(f1, a);
			if (!ctx.generate(&ctx, out, n, na ? a : NULL, na)) { printf("ERR\n"); }
			else { for (size_t i = 0; i < n; i++) printf("%02x", out[i]); printf("\n"); }
		} else if (strcmp(op, "reseed") == 0) {
			sscanf(line, "%*s %s %s", f1, f2);
			size_t na = unhex(f1, a), nb = unhex(f2, b);
			printf(ctx.reseed(&ctx, a, na, nb ? b : NULL, nb) ? "OK\n" : "ERR\n");
		}
		fflush(stdout);
	}
	return 0;
}
