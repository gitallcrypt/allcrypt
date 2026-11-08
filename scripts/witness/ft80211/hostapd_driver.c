/* hostapd's (wpa_supplicant 2.11's) 802.11 key derivations, from
 * src/common/wpa_common.c and its internal crypto, behind common.h's
 * line protocol. */
#include "includes.h"
#include "common.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/sha512.h"
#include "common/defs.h"
#include "common/wpa_common.h"
#include "driver_common.h"

static int ft_akm(size_t len) {
    return len == 32 ? WPA_KEY_MGMT_FT_PSK
         : len == 48 ? WPA_KEY_MGMT_FT_IEEE8021X_SHA384 : WPA_KEY_MGMT_FT_SAE_EXT_KEY;
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
            int r = h == 256 ? sha256_prf(key, klen, label_text, context, clen, out, bytes)
                  : h == 384 ? sha384_prf(key, klen, label_text, context, clen, out, bytes)
                  : sha512_prf(key, klen, label_text, context, clen, out, bytes);
            if (r) { printf("error\n"); continue; }
            put(out, bytes);
        } else if (strcmp(cmd, "ptk384") == 0) {
            size_t n[5];
            unsigned char *pmk = unhex(field(&save), &n[0]);
            unsigned char *aa = unhex(field(&save), &n[1]);
            unsigned char *spa = unhex(field(&save), &n[2]);
            unsigned char *anonce = unhex(field(&save), &n[3]);
            unsigned char *snonce = unhex(field(&save), &n[4]);
            struct wpa_ptk ptk;
            memset(&ptk, 0, sizeof ptk);
            if (wpa_pmk_to_ptk(pmk, n[0], "Pairwise key expansion", aa, spa, anonce, snonce,
                               &ptk, WPA_KEY_MGMT_IEEE8021X_SUITE_B_192, WPA_CIPHER_GCMP_256,
                               NULL, 0, 0)) { printf("error\n"); continue; }
            put(ptk.kck, ptk.kck_len); put(ptk.kek, ptk.kek_len); put(ptk.tk, ptk.tk_len);
        } else if (strcmp(cmd, "r0") == 0) {
            size_t n[5];
            unsigned char *xxkey = unhex(field(&save), &n[0]);
            unsigned char *ssid = unhex(field(&save), &n[1]);
            unsigned char *mdid = unhex(field(&save), &n[2]);
            unsigned char *r0kh = unhex(field(&save), &n[3]);
            unsigned char *s0kh = unhex(field(&save), &n[4]);
            unsigned char pmk_r0[64], name[16];
            if (wpa_derive_pmk_r0(xxkey, n[0], ssid, n[1], mdid, r0kh, n[3], s0kh, pmk_r0, name,
                                  ft_akm(n[0]))) { printf("error\n"); continue; }
            put(pmk_r0, n[0]); printf(" "); put(name, 16);
        } else if (strcmp(cmd, "r1") == 0) {
            size_t n[4];
            unsigned char *pmk_r0 = unhex(field(&save), &n[0]);
            unsigned char *r0name = unhex(field(&save), &n[1]);
            unsigned char *r1kh = unhex(field(&save), &n[2]);
            unsigned char *s1kh = unhex(field(&save), &n[3]);
            unsigned char pmk_r1[64], name[16];
            if (wpa_derive_pmk_r1(pmk_r0, n[0], r0name, r1kh, s1kh, pmk_r1, name)) {
                printf("error\n"); continue;
            }
            put(pmk_r1, n[0]); printf(" "); put(name, 16);
        } else if (strcmp(cmd, "ftptk") == 0) {
            const char *cipher = field(&save);
            size_t n[5];
            unsigned char *pmk_r1 = unhex(field(&save), &n[0]);
            unsigned char *snonce = unhex(field(&save), &n[1]);
            unsigned char *anonce = unhex(field(&save), &n[2]);
            unsigned char *bssid = unhex(field(&save), &n[3]);
            unsigned char *sta = unhex(field(&save), &n[4]);
            unsigned char r1name[16] = {0}, ptk_name[16];
            struct wpa_ptk ptk;
            memset(&ptk, 0, sizeof ptk);
            if (wpa_pmk_r1_to_ptk(pmk_r1, n[0], snonce, anonce, sta, bssid, r1name, &ptk,
                                  ptk_name, ft_akm(n[0]),
                                  strcmp(cipher, "ccmp") == 0 ? WPA_CIPHER_CCMP
                                                              : WPA_CIPHER_GCMP_256, 0)) {
                printf("error\n"); continue;
            }
            put(ptk.kck, ptk.kck_len); put(ptk.kek, ptk.kek_len); put(ptk.tk, ptk.tk_len);
        } else {
            fprintf(stderr, "unknown command %s\n", cmd);
            return 2;
        }
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
