/*
 * A line protocol over MIT Kerberos's libk5crypto, for
 * scripts/check_kerberos.py. One request per line on standard input,
 * one answer per line on standard output; hex throughout, "-" for an
 * empty string.
 *
 *   s2k ENCTYPE PASSWORD SALT PARAMS        -> KEY
 *   encrypt ENCTYPE KEY USAGE PLAIN         -> CIPHER (random confounder)
 *   decrypt ENCTYPE KEY USAGE CIPHER        -> PLAIN, or "ERR <message>"
 *   checksum ENCTYPE KEY USAGE DATA         -> CKSUMTYPE CHECKSUM (the mandatory type)
 *   mkcksum CKSUMTYPE ENCTYPE KEY USAGE DATA -> CHECKSUM
 *   verify CKSUMTYPE ENCTYPE KEY USAGE DATA SUM -> "good" or "bad"
 *   prf ENCTYPE KEY INPUT                   -> OUTPUT
 *
 * Build against each installation it witnesses:
 *
 *   gcc -O2 main.c -I$PREFIX/include -L$PREFIX/lib -Wl,--disable-new-dtags,-rpath,$PREFIX/lib \
 *       -lkrb5 -lk5crypto -lcom_err -o krb5witness
 */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static krb5_context ctx;

/* MIT refuses a PBKDF2 count below the type's default unless this is
 * set, as its own t_str2key does; the published vectors use 1 and 2. */
extern krb5_boolean k5_allow_weak_pbkdf2iter;

static int unhex(const char *text, krb5_data *out)
{
    size_t len = strcmp(text, "-") == 0 ? 0 : strlen(text);
    if (len % 2)
        return -1;
    out->length = len / 2;
    out->data = malloc(out->length + 1);
    for (size_t i = 0; i < out->length; i++) {
        unsigned int b;
        if (sscanf(text + 2 * i, "%2x", &b) != 1)
            return -1;
        out->data[i] = (char)b;
    }
    return 0;
}

static void put_hex(const void *data, size_t len)
{
    const unsigned char *p = data;
    if (len == 0)
        fputs("-", stdout);
    for (size_t i = 0; i < len; i++)
        printf("%02x", p[i]);
}

static void fail(krb5_error_code code)
{
    const char *msg = krb5_get_error_message(ctx, code);
    printf("ERR %s\n", msg);
    fflush(stdout);
    krb5_free_error_message(ctx, msg);
}

static int keyblock(krb5_enctype enctype, const char *hex, krb5_keyblock *key)
{
    krb5_data d;
    if (unhex(hex, &d))
        return -1;
    key->magic = KV5M_KEYBLOCK;
    key->enctype = enctype;
    key->length = d.length;
    key->contents = (krb5_octet *)d.data;
    return 0;
}

int main(void)
{
    char line[1 << 16];
    k5_allow_weak_pbkdf2iter = 1;
    if (krb5_init_context(&ctx)) {
        fprintf(stderr, "krb5_init_context failed\n");
        return 1;
    }
    while (fgets(line, sizeof line, stdin)) {
        char *argv[8];
        int argc = 0;
        for (char *t = strtok(line, " \r\n"); t && argc < 8; t = strtok(NULL, " \r\n"))
            argv[argc++] = t;
        if (argc == 0)
            continue;
        krb5_error_code code;
        krb5_enctype enctype = argc > 1 ? atoi(argv[1]) : 0;
        if (strcmp(argv[0], "s2k") == 0 && argc == 5) {
            krb5_data password, salt, params;
            krb5_keyblock key;
            unhex(argv[2], &password);
            unhex(argv[3], &salt);
            unhex(argv[4], &params);
            code = krb5_c_string_to_key_with_params(ctx, enctype, &password, &salt,
                                                    params.length ? &params : NULL, &key);
            if (code) {
                fail(code);
                continue;
            }
            put_hex(key.contents, key.length);
            krb5_free_keyblock_contents(ctx, &key);
        } else if (strcmp(argv[0], "encrypt") == 0 && argc == 5) {
            krb5_keyblock key;
            krb5_data plain;
            krb5_enc_data out;
            size_t len;
            keyblock(enctype, argv[2], &key);
            unhex(argv[4], &plain);
            krb5_c_encrypt_length(ctx, enctype, plain.length, &len);
            out.ciphertext.length = len;
            out.ciphertext.data = malloc(len + 1);
            code = krb5_c_encrypt(ctx, &key, atoi(argv[3]), NULL, &plain, &out);
            if (code) {
                fail(code);
                continue;
            }
            put_hex(out.ciphertext.data, out.ciphertext.length);
        } else if (strcmp(argv[0], "decrypt") == 0 && argc == 5) {
            krb5_keyblock key;
            krb5_enc_data in;
            krb5_data out;
            keyblock(enctype, argv[2], &key);
            memset(&in, 0, sizeof in);
            in.enctype = enctype;
            unhex(argv[4], &in.ciphertext);
            out.length = in.ciphertext.length;
            out.data = malloc(out.length + 1);
            code = krb5_c_decrypt(ctx, &key, atoi(argv[3]), NULL, &in, &out);
            if (code) {
                fail(code);
                continue;
            }
            put_hex(out.data, out.length);
        } else if (strcmp(argv[0], "checksum") == 0 && argc == 5) {
            krb5_keyblock key;
            krb5_data data;
            krb5_checksum sum;
            keyblock(enctype, argv[2], &key);
            unhex(argv[4], &data);
            code = krb5_c_make_checksum(ctx, 0, &key, atoi(argv[3]), &data, &sum);
            if (code) {
                fail(code);
                continue;
            }
            printf("%d ", sum.checksum_type);
            put_hex(sum.contents, sum.length);
            krb5_free_checksum_contents(ctx, &sum);
        } else if (strcmp(argv[0], "mkcksum") == 0 && argc == 6) {
            krb5_keyblock key;
            krb5_data data;
            krb5_checksum sum;
            keyblock(atoi(argv[2]), argv[3], &key);
            unhex(argv[5], &data);
            code = krb5_c_make_checksum(ctx, atoi(argv[1]), &key, atoi(argv[4]), &data, &sum);
            if (code) {
                fail(code);
                continue;
            }
            put_hex(sum.contents, sum.length);
            krb5_free_checksum_contents(ctx, &sum);
        } else if (strcmp(argv[0], "verify") == 0 && argc == 7) {
            krb5_keyblock key;
            krb5_data data, value;
            krb5_checksum sum;
            krb5_boolean valid = 0;
            keyblock(atoi(argv[2]), argv[3], &key);
            unhex(argv[5], &data);
            unhex(argv[6], &value);
            sum.magic = KV5M_CHECKSUM;
            sum.checksum_type = atoi(argv[1]);
            sum.length = value.length;
            sum.contents = (krb5_octet *)value.data;
            code = krb5_c_verify_checksum(ctx, &key, atoi(argv[4]), &data, &sum, &valid);
            if (code) {
                fail(code);
                continue;
            }
            fputs(valid ? "good" : "bad", stdout);
        } else if (strcmp(argv[0], "prf") == 0 && argc == 4) {
            krb5_keyblock key;
            krb5_data input, out;
            size_t len;
            keyblock(enctype, argv[2], &key);
            unhex(argv[3], &input);
            code = krb5_c_prf_length(ctx, enctype, &len);
            if (code) {
                fail(code);
                continue;
            }
            out.length = len;
            out.data = malloc(len);
            code = krb5_c_prf(ctx, &key, &input, &out);
            if (code) {
                fail(code);
                continue;
            }
            put_hex(out.data, out.length);
        } else {
            printf("ERR bad request\n");
            fflush(stdout);
            continue;
        }
        putchar('\n');
        fflush(stdout);
    }
    krb5_free_context(ctx);
    return 0;
}
