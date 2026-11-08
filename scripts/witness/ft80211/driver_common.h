/* driver_common.h: the line protocol both drivers speak, one request a line on stdin and
 * one answer a line on stdout, hex throughout, "-" for empty:
 *
 *   kdf H KEY LABEL CONTEXT BYTES        KDF-SHA<H>, H 256, 384 or 512
 *   ptk384 PMK AA SPA ANONCE SNONCE      Suite B 192's PTK, GCMP-256 (hostapd)
 *   r0 XXKEY SSID MDID R0KH S0KH         PMK-R0 and PMKR0Name
 *   r1 PMKR0 PMKR0NAME R1KH S1KH         PMK-R1 and PMKR1Name
 *   ftptk CIPHER PMKR1 SNONCE ANONCE BSSID STA
 *                                        KCK || KEK || TK; CIPHER ccmp or gcmp256
 *
 * With MISALIGN=1 in the environment every input sits one byte past a
 * malloc'd boundary, for the sanitizer builds. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int misalign(void) {
    const char *m = getenv("MISALIGN");
    return m && *m == '1';
}

/* A hex field into a fresh buffer; *len gets its length. The buffer is
 * allocated exactly, so a read past the field is a read past the block. */
static unsigned char *unhex(const char *text, size_t *len) {
    size_t n = strcmp(text, "-") == 0 ? 0 : strlen(text) / 2;
    int off = misalign();
    unsigned char *raw = malloc(n + off + 1);
    if (!raw) exit(2);
    unsigned char *out = raw + off;
    for (size_t i = 0; i < n; i++) {
        unsigned int b;
        if (sscanf(text + 2 * i, "%2x", &b) != 1) { fprintf(stderr, "bad hex\n"); exit(2); }
        out[i] = (unsigned char)b;
    }
    *len = n;
    return out;
}

static void put(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

static char *field(char **save) {
    char *f = strtok_r(NULL, " \n", save);
    if (!f) { fprintf(stderr, "missing field\n"); exit(2); }
    return f;
}

/* KCK and KEK lengths by PMK-R1 length, TK by cipher name. */
static size_t kck_len(size_t pmk) { return pmk == 32 ? 16 : pmk == 48 ? 24 : 32; }
static size_t kek_len(size_t pmk) { return pmk == 32 ? 16 : 32; }
static size_t tk_len(const char *cipher) { return strcmp(cipher, "ccmp") == 0 ? 16 : 32; }
