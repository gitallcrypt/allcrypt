/* libtomcrypt 1.18.2's PMAC as a witness, built with LTC_NO_FAST (see
 * build.sh): `pmac <cipher> <key hex> <msg hex>` per line ("-" for
 * empty), the tag in hex, or "error ...". Ciphers: aes, des, 3des,
 * blowfish. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tomcrypt.h>

static size_t unhex(const char *s, unsigned char *out) {
    if (strcmp(s, "-") == 0) return 0;
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
    return n;
}

int main(void) {
    static char line[1 << 20];
    static unsigned char key[256], msg[1 << 19];
    register_cipher(&aes_desc);
    register_cipher(&des_desc);
    register_cipher(&des3_desc);
    register_cipher(&blowfish_desc);
    while (fgets(line, sizeof line, stdin)) {
        char op[16], cipher[32], k[1024], m[sizeof line];
        if (sscanf(line, "%15s %31s %1023s %s", op, cipher, k, m) != 4 || strcmp(op, "pmac")) {
            puts("error request"); fflush(stdout); continue;
        }
        const char *name = !strcmp(cipher, "aes") ? "aes" : !strcmp(cipher, "des") ? "des"
                         : !strcmp(cipher, "3des") ? "3des" : !strcmp(cipher, "blowfish") ? "blowfish" : NULL;
        if (!name) { puts("error unsupported"); fflush(stdout); continue; }
        size_t kl = unhex(k, key), ml = unhex(m, msg);
        /* An exact-size copy, so a read past the message is a sanitizer report. */
        unsigned char *exact = malloc(ml ? ml : 1);
        memcpy(exact, msg, ml);
        unsigned char tag[MAXBLOCKSIZE];
        unsigned long tl = sizeof tag;
        int err = pmac_memory(find_cipher(name), key, kl, exact, ml, tag, &tl);
        free(exact);
        if (err != CRYPT_OK) { printf("error %s\n", error_to_string(err)); fflush(stdout); continue; }
        for (unsigned long i = 0; i < tl; i++) printf("%02x", tag[i]);
        puts(""); fflush(stdout);
    }
    return 0;
}
