/* Wireshark's (4.6's) 802.11 key derivations, from
 * epan/crypt/dot11decrypt_util.c, behind driver_common.h's line
 * protocol. It has no Suite B PTK function of its own (ptk384), and its
 * PMKR0Name and PMKR1Name are SHA-256 whatever the key's length. */
#include "config.h"
#include <gcrypt.h>
#include "dot11decrypt_int.h"
#include "dot11decrypt_util.h"
#include "driver_common.h"

static int algo(size_t len) {
    return len == 32 ? GCRY_MD_SHA256 : len == 48 ? GCRY_MD_SHA384 : GCRY_MD_SHA512;
}

int main(void) {
    char line[8192];
    while (fgets(line, sizeof line, stdin)) {
        char *save;
        char *cmd = strtok_r(line, " \n", &save);
        if (!cmd) continue;
        if (strcmp(cmd, "kdf") == 0) {
            int h = atoi(field(&save));
            size_t klen, llen, clen;
            unsigned char *key = unhex(field(&save), &klen);
            unsigned char *label = unhex(field(&save), &llen);
            unsigned char *context = unhex(field(&save), &clen);
            size_t bytes = (size_t)atoi(field(&save));
            char label_text[256];
            memcpy(label_text, label, llen);
            label_text[llen] = 0;
            unsigned char *out = malloc(bytes + 1);
            if (!dot11decrypt_kdf(key, klen, label_text, context, clen, algo(h / 8), out, bytes)) {
                printf("error\n"); continue;
            }
            put(out, bytes);
        } else if (strcmp(cmd, "r0") == 0) {
            size_t n[5];
            unsigned char *xxkey = unhex(field(&save), &n[0]);
            unsigned char *ssid = unhex(field(&save), &n[1]);
            unsigned char *mdid = unhex(field(&save), &n[2]);
            unsigned char *r0kh = unhex(field(&save), &n[3]);
            unsigned char *s0kh = unhex(field(&save), &n[4]);
            unsigned char pmk_r0[64], name[16];
            size_t len;
            if (!dot11decrypt_derive_pmk_r0(xxkey, n[0], ssid, n[1], mdid, r0kh, n[3], s0kh,
                                            algo(n[0]), pmk_r0, &len, name)) {
                printf("error\n"); continue;
            }
            put(pmk_r0, len); printf(" "); put(name, 16);
        } else if (strcmp(cmd, "r1") == 0) {
            size_t n[4];
            unsigned char *pmk_r0 = unhex(field(&save), &n[0]);
            unsigned char *r0name = unhex(field(&save), &n[1]);
            unsigned char *r1kh = unhex(field(&save), &n[2]);
            unsigned char *s1kh = unhex(field(&save), &n[3]);
            unsigned char pmk_r1[64], name[16];
            size_t len;
            if (!dot11decrypt_derive_pmk_r1(pmk_r0, n[0], r0name, r1kh, s1kh, algo(n[0]),
                                            pmk_r1, &len, name)) {
                printf("error\n"); continue;
            }
            put(pmk_r1, len); printf(" "); put(name, 16);
        } else if (strcmp(cmd, "ftptk") == 0) {
            const char *cipher = field(&save);
            size_t n[5];
            unsigned char *pmk_r1 = unhex(field(&save), &n[0]);
            unsigned char *snonce = unhex(field(&save), &n[1]);
            unsigned char *anonce = unhex(field(&save), &n[2]);
            unsigned char *bssid = unhex(field(&save), &n[3]);
            unsigned char *sta = unhex(field(&save), &n[4]);
            size_t len = kck_len(n[0]) + kek_len(n[0]) + tk_len(cipher);
            unsigned char ptk[128];
            if (!dot11decrypt_derive_ft_ptk(pmk_r1, n[0], NULL, snonce, anonce, bssid, sta,
                                            algo(n[0]), ptk, len, NULL)) {
                printf("error\n"); continue;
            }
            put(ptk, len);
        } else if (strcmp(cmd, "ptk384") == 0) {
            printf("unsupported");
        } else {
            fprintf(stderr, "unknown command %s\n", cmd);
            return 2;
        }
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
