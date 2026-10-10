/*
 * The C interface, driven from C through the header.
 *
 * Run by scripts/check_c_api.py, which compiles this file against
 * include/allcrypt.h, links it with the library built with `c-api`, and
 * runs it with a directory of key files it wrote with
 * python-cryptography. What can be checked here - round trips, streaming
 * against one call, refusals - is checked here and fails the run. What
 * needs a second implementation is printed as `label hex` lines, and
 * the script compares every one with hashlib and python-cryptography.
 *
 * Every function in the header is called at least once; the script
 * checks that too.
 */

#include "allcrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void fail(const char *what, const char *detail) {
    fprintf(stderr, "FAIL %s: %s\n", what, detail);
    failures++;
}

/* A call that must succeed. */
static int ok(int status, const char *what) {
    if (status != ALLCRYPT_OK) {
        fail(what, allcrypt_last_error());
        return 0;
    }
    return 1;
}

/* A call that must fail with ALLCRYPT_ERROR and say something. */
static void refused(int status, const char *what, const char *expect) {
    if (status != ALLCRYPT_ERROR) {
        fail(what, "was not refused");
    } else if (strstr(allcrypt_last_error(), expect) == NULL) {
        fprintf(stderr, "FAIL %s: the message \"%s\" does not mention \"%s\"\n", what,
                allcrypt_last_error(), expect);
        failures++;
    }
}

static void expect(int condition, const char *what) {
    if (!condition) {
        fail(what, "condition does not hold");
    }
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_buffer(const char *label, const allcrypt_buffer *buffer) {
    print_hex(label, buffer->data, buffer->len);
}

static int same(const allcrypt_buffer *a, const allcrypt_buffer *b) {
    return a->len == b->len && (a->len == 0 || memcmp(a->data, b->data, a->len) == 0);
}

static uint8_t *read_file(const char *dir, const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fail("read", path);
        exit(2);
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *data = malloc(size > 0 ? (size_t)size : 1);
    *len = fread(data, 1, (size_t)size, file);
    fclose(file);
    return data;
}

static size_t unhex(const char *text, uint8_t *out, size_t room) {
    size_t n = 0;
    while (text[0] && text[1] && text[0] != '\n' && n < room) {
        unsigned value;
        sscanf(text, "%2x", &value);
        out[n++] = (uint8_t)value;
        text += 2;
    }
    return n;
}

/* The bytes 0, 1, 2, ... as a message: every length from here is a
 * prefix of it, so the script rebuilds the same input from the length. */
static uint8_t message[1000];

static void general(void) {
    printf("version %s\n", allcrypt_version());
    const char *kinds[] = {"hashes", "block_ciphers", "modes", "stream_ciphers", "aeads",
                           "curves", "eddsa"};
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        const char *names = allcrypt_names(kinds[i]);
        expect(names != NULL && names[0] != '\0', kinds[i]);
        printf("names_%s %s\n", kinds[i], names ? names : "");
        /* Kept: the same pointer comes back. */
        expect(allcrypt_names(kinds[i]) == names, "names are kept");
    }
    expect(allcrypt_names("ciphers") == NULL, "an unknown kind of name is NULL");
    expect(allcrypt_names(NULL) == NULL, "a NULL kind is NULL");

    uint8_t a[32] = {0}, b[32] = {0}, zero[32] = {0};
    ok(allcrypt_random(a, sizeof a), "random");
    ok(allcrypt_random(b, sizeof b), "random");
    expect(memcmp(a, zero, 32) != 0 && memcmp(a, b, 32) != 0, "random bytes differ");
    ok(allcrypt_random(NULL, 0), "zero random bytes into NULL");
    refused(allcrypt_random(NULL, 4), "random into NULL", "NULL");

    allcrypt_buffer_free(NULL);
    allcrypt_buffer empty = {NULL, 0};
    allcrypt_buffer_free(&empty);
}

static void hashes(void) {
    /* Every hash by name, in one call and in uneven pieces. */
    char names[4096];
    snprintf(names, sizeof names, "%s", allcrypt_names("hashes"));
    for (char *name = strtok(names, ","); name != NULL; name = strtok(NULL, ",")) {
        allcrypt_buffer whole = {0}, pieces = {0};
        if (!ok(allcrypt_hash(name, message, 200, &whole), name)) {
            continue;
        }
        allcrypt_hash_state *hash = NULL;
        ok(allcrypt_hash_new(name, &hash), name);
        size_t at = 0, step = 1;
        while (at < 200) {
            size_t take = step < 200 - at ? step : 200 - at;
            ok(allcrypt_hash_update(hash, message + at, take), name);
            at += take;
            step = step * 3 + 1;
        }
        ok(allcrypt_hash_digest(hash, &pieces), name);
        expect(same(&whole, &pieces), "a hash in pieces equals one call");
        /* The digest does not end the hash. */
        allcrypt_buffer_free(&pieces);
        ok(allcrypt_hash_update(hash, message + 200, 50), name);
        ok(allcrypt_hash_digest(hash, &pieces), name);
        allcrypt_buffer longer = {0};
        ok(allcrypt_hash(name, message, 250, &longer), name);
        if (!same(&pieces, &longer)) {
            fail("a hash goes on after its digest", name);
        }
        allcrypt_hash_free(hash);
        char label[128];
        snprintf(label, sizeof label, "hash_%s", name);
        print_buffer(label, &whole);
        allcrypt_buffer_free(&whole);
        allcrypt_buffer_free(&pieces);
        allcrypt_buffer_free(&longer);
        expect(whole.data == NULL && whole.len == 0, "a freed buffer is empty");
    }
    allcrypt_hash_free(NULL);

    allcrypt_buffer digest = {0};
    refused(allcrypt_hash("sha-257", message, 3, &digest), "an unknown hash", "257");
    expect(digest.data == NULL, "a refusal writes nothing");
    refused(allcrypt_hash("sha256", NULL, 3, &digest), "NULL data", "NULL");
    ok(allcrypt_hash("sha256", NULL, 0, &digest), "NULL with no bytes");
    print_buffer("hash_empty_sha256", &digest);
    allcrypt_buffer_free(&digest);
    refused(allcrypt_hash(NULL, message, 3, &digest), "a NULL name", "NULL");
    refused(allcrypt_hash("sha256", message, 3, NULL), "a NULL buffer", "NULL");
    allcrypt_hash_state *never = NULL;
    refused(allcrypt_hash_new("nonsense", &never), "an unknown hash object", "nonsense");
    expect(never == NULL, "a refused object is not written");
    refused(allcrypt_hash_update(NULL, message, 1), "a NULL hash", "NULL");

    uint8_t shake[100];
    ok(allcrypt_shake("shake128", message, 200, shake, sizeof shake), "shake128");
    print_hex("shake128", shake, sizeof shake);
    ok(allcrypt_shake("shake256", message, 200, shake, 64), "shake256");
    print_hex("shake256", shake, 64);
}

static void hmac(void) {
    allcrypt_buffer whole = {0}, pieces = {0};
    ok(allcrypt_hmac("sha256", message, 100, message + 100, 300, &whole), "hmac");
    print_buffer("hmac_sha256", &whole);
    allcrypt_hmac_state *mac = NULL;
    ok(allcrypt_hmac_new("sha256", message, 100, &mac), "hmac_new");
    ok(allcrypt_hmac_update(mac, message + 100, 7), "hmac_update");
    ok(allcrypt_hmac_update(mac, message + 107, 293), "hmac_update");
    ok(allcrypt_hmac_digest(mac, &pieces), "hmac_digest");
    expect(same(&whole, &pieces), "an HMAC in pieces equals one call");
    allcrypt_hmac_free(mac);
    allcrypt_hmac_free(NULL);
    allcrypt_buffer_free(&whole);
    allcrypt_buffer_free(&pieces);
    /* A key longer than the block is hashed first. */
    ok(allcrypt_hmac("sha512", message, 200, message, 10, &whole), "hmac long key");
    print_buffer("hmac_sha512_longkey", &whole);
    allcrypt_buffer_free(&whole);
}

static void kdfs(void) {
    uint8_t out[64];
    ok(allcrypt_pbkdf2("sha256", message, 10, message + 10, 16, 1000, out, 40), "pbkdf2");
    print_hex("pbkdf2_sha256", out, 40);
    ok(allcrypt_hkdf("sha256", message, 13, message + 13, 22, message + 35, 10, out, 42),
       "hkdf");
    print_hex("hkdf_sha256", out, 42);
    ok(allcrypt_hkdf("sha256", NULL, 0, message + 13, 22, NULL, 0, out, 42), "hkdf no salt");
    print_hex("hkdf_sha256_nosalt", out, 42);
    ok(allcrypt_scrypt(message, 8, message + 8, 16, 1024, 8, 1, out, 64), "scrypt");
    print_hex("scrypt", out, 64);
    ok(allcrypt_argon2("argon2id", message, 16, message + 16, 16, 64, 3, 2, NULL, 0, NULL, 0,
                       out, 32), "argon2id");
    print_hex("argon2id", out, 32);
    ok(allcrypt_argon2("argon2id", message, 16, message + 16, 16, 64, 3, 2, message + 32, 8,
                       message + 40, 12, out, 32), "argon2id with secret and data");
    print_hex("argon2id_secret_ad", out, 32);
    refused(allcrypt_pbkdf2("sha256", message, 10, message, 16, 1000, NULL, 40),
            "a KDF into NULL", "NULL");
}

/* Encrypt in pieces of growing size, then finish. */
static void run_cipher(allcrypt_cipher *cipher, const uint8_t *data, size_t len,
                       allcrypt_buffer *out) {
    uint8_t *joined = malloc(len + 64);
    size_t have = 0, at = 0, step = 1;
    allcrypt_buffer piece = {0};
    while (at < len) {
        size_t take = step < len - at ? step : len - at;
        ok(allcrypt_cipher_update(cipher, data + at, take, &piece), "cipher_update");
        memcpy(joined + have, piece.data ? piece.data : joined, piece.len);
        have += piece.len;
        allcrypt_buffer_free(&piece);
        at += take;
        step = step * 2 + 1;
    }
    ok(allcrypt_cipher_finish(cipher, &piece), "cipher_finish");
    memcpy(joined + have, piece.data ? piece.data : joined, piece.len);
    have += piece.len;
    allcrypt_buffer_free(&piece);
    out->data = joined;
    out->len = have;
}

static void block_ciphers(void) {
    const uint8_t *key = message + 32, *iv = message + 64;
    allcrypt_buffer padded = {0}, sealed = {0}, opened = {0}, unpadded = {0};
    ok(allcrypt_pad_pkcs7(message, 100, 16, &padded), "pad");
    expect(padded.len == 112, "PKCS#7 pads 100 bytes to 112");

    allcrypt_cipher *cipher = NULL;
    ok(allcrypt_cipher_new("aes", key, 16, NULL, "cbc", iv, 16, 0, &cipher), "aes-cbc");
    run_cipher(cipher, padded.data, padded.len, &sealed);
    allcrypt_cipher_free(cipher);
    print_hex("aes128_cbc", sealed.data, sealed.len);

    ok(allcrypt_cipher_new("AES", key, 16, NULL, "CBC", iv, 16, 1, &cipher), "aes-cbc decrypt");
    run_cipher(cipher, sealed.data, sealed.len, &opened);
    allcrypt_cipher_free(cipher);
    ok(allcrypt_unpad_pkcs7(opened.data, opened.len, 16, &unpadded), "unpad");
    expect(unpadded.len == 100 && memcmp(unpadded.data, message, 100) == 0,
           "CBC decrypts and unpads to the message");
    free(sealed.data);
    free(opened.data);
    allcrypt_buffer_free(&unpadded);

    /* Unpadding refuses a block that is not padded. */
    refused(allcrypt_unpad_pkcs7(message, 16, 16, &unpadded), "bad padding", "pad");
    allcrypt_buffer_free(&padded);

    ok(allcrypt_cipher_new("aes", key, 32, NULL, "ctr", iv, 16, 0, &cipher), "aes-ctr");
    run_cipher(cipher, message, 333, &sealed);
    allcrypt_cipher_free(cipher);
    print_hex("aes256_ctr", sealed.data, sealed.len);
    free(sealed.data);

    ok(allcrypt_cipher_new("3des", key, 24, NULL, "ecb", NULL, 0, 0, &cipher), "3des-ecb");
    run_cipher(cipher, message, 64, &sealed);
    allcrypt_cipher_free(cipher);
    print_hex("tdes_ecb", sealed.data, sealed.len);
    free(sealed.data);

    /* RC2 with 40 effective bits, through the parameter. */
    ok(allcrypt_cipher_new("rc2", key, 16, "40", "cbc", iv, 8, 0, &cipher), "rc2-40");
    run_cipher(cipher, message, 64, &sealed);
    allcrypt_cipher_free(cipher);
    print_hex("rc2_40_cbc", sealed.data, sealed.len);
    free(sealed.data);
    allcrypt_cipher_free(NULL);

    /* ECB with a partial block is refused at the end, not padded. */
    ok(allcrypt_cipher_new("aes", key, 16, NULL, "ecb", NULL, 0, 0, &cipher), "aes-ecb");
    allcrypt_buffer piece = {0};
    ok(allcrypt_cipher_update(cipher, message, 20, &piece), "ecb update");
    expect(piece.len == 16, "ECB holds back the partial block");
    allcrypt_buffer_free(&piece);
    refused(allcrypt_cipher_finish(cipher, &piece), "ECB with a partial block", "block");
    allcrypt_cipher_free(cipher);

    allcrypt_cipher *never = NULL;
    refused(allcrypt_cipher_new("aes", key, 16, NULL, "xts", iv, 16, 0, &never),
            "an unknown mode", "xts");
    refused(allcrypt_cipher_new("aes", key, 16, NULL, "ecb", iv, 16, 0, &never),
            "an IV for ECB", "IV");
    refused(allcrypt_cipher_new("aes", key, 15, NULL, "cbc", iv, 16, 0, &never),
            "a 15 byte AES key", "15");
    expect(never == NULL, "a refused cipher is not written");
}

static void aeads(void) {
    const uint8_t *key = message + 32, *nonce = message + 64, *aad = message + 80;
    allcrypt_buffer ciphertext = {0}, tag = {0}, plaintext = {0};
    const char *names[] = {"aes-gcm", "chacha20-poly1305"};
    for (int i = 0; i < 2; i++) {
        ok(allcrypt_aead_encrypt(names[i], key, 32, nonce, 12, aad, 20, message, 150,
                                 &ciphertext, &tag), names[i]);
        char label[64];
        snprintf(label, sizeof label, "aead_%s_ct", names[i]);
        print_buffer(label, &ciphertext);
        snprintf(label, sizeof label, "aead_%s_tag", names[i]);
        print_buffer(label, &tag);
        ok(allcrypt_aead_decrypt(names[i], key, 32, nonce, 12, aad, 20, ciphertext.data,
                                 ciphertext.len, tag.data, tag.len, &plaintext), names[i]);
        expect(plaintext.len == 150 && memcmp(plaintext.data, message, 150) == 0,
               "an AEAD opens what it sealed");
        allcrypt_buffer_free(&plaintext);
        tag.data[0] ^= 1;
        refused(allcrypt_aead_decrypt(names[i], key, 32, nonce, 12, aad, 20, ciphertext.data,
                                      ciphertext.len, tag.data, tag.len, &plaintext),
                "a forged tag", "");
        expect(plaintext.data == NULL && plaintext.len == 0, "a forgery yields no plaintext");
        allcrypt_buffer_free(&ciphertext);
        allcrypt_buffer_free(&tag);
    }
}

static void stream_ciphers(void) {
    const uint8_t *key = message + 32, *nonce = message + 64;
    uint8_t data[300];
    memcpy(data, message, sizeof data);
    allcrypt_stream *stream = NULL;
    ok(allcrypt_stream_new("chacha20", key, 32, nonce, 12, &stream), "chacha20");
    ok(allcrypt_stream_apply(stream, data, 7), "apply");
    ok(allcrypt_stream_apply(stream, data + 7, 293), "apply");
    allcrypt_stream_free(stream);
    print_hex("chacha20", data, sizeof data);
    ok(allcrypt_stream_new("chacha20", key, 32, nonce, 12, &stream), "chacha20");
    ok(allcrypt_stream_apply(stream, data, sizeof data), "apply");
    allcrypt_stream_free(stream);
    expect(memcmp(data, message, sizeof data) == 0, "the keystream twice is the message");
    allcrypt_stream_free(NULL);
}

static void x25519(void) {
    uint8_t a_private[32], a_public[32], b_private[32], b_public[32], ab[32], ba[32];
    ok(allcrypt_x25519_generate(a_private, a_public), "x25519 generate");
    ok(allcrypt_x25519_generate(b_private, b_public), "x25519 generate");
    ok(allcrypt_x25519_exchange(a_private, b_public, ab), "x25519 exchange");
    ok(allcrypt_x25519_exchange(b_private, a_public, ba), "x25519 exchange");
    expect(memcmp(ab, ba, 32) == 0, "both ends of an X25519 exchange agree");
    uint8_t derived[32];
    ok(allcrypt_x25519_public_key(a_private, derived), "x25519 public");
    expect(memcmp(derived, a_public, 32) == 0, "the generated public key is derived");
    ok(allcrypt_x25519_public_key(message + 100, derived), "x25519 public");
    print_hex("x25519_public", derived, 32);
    uint8_t low_order[32] = {0};
    refused(allcrypt_x25519_exchange(a_private, low_order, ab), "a low-order point", "");
}

static void ec(const char *dir) {
    /* A fixed scalar, for the script to derive the same public key. */
    allcrypt_ec_key *key = NULL;
    allcrypt_buffer out = {0}, signature = {0};
    ok(allcrypt_ec_from_private("P-256", message + 1, 32, &key), "ec from_private");
    ok(allcrypt_ec_public_bytes(key, 0, &out), "ec public");
    print_buffer("ec_p256_public", &out);
    allcrypt_buffer_free(&out);
    ok(allcrypt_ec_public_bytes(key, 1, &out), "ec public compressed");
    print_buffer("ec_p256_public_compressed", &out);
    allcrypt_buffer_free(&out);
    ok(allcrypt_ec_private_bytes(key, &out), "ec private");
    expect(out.len == 32 && memcmp(out.data, message + 1, 32) == 0, "the scalar comes back");
    allcrypt_buffer_free(&out);
    allcrypt_ec_key_free(key);

    /* A key from a PKCS#8 file the script wrote: sign, and print it for
     * python-cryptography to verify. */
    size_t len;
    uint8_t *pem = read_file(dir, "ec.pem", &len);
    ok(allcrypt_ec_load(pem, len, NULL, 0, &key), "ec load");
    free(pem);
    allcrypt_buffer digest = {0}, public_key = {0};
    ok(allcrypt_hash("sha256", message, 300, &digest), "digest");
    ok(allcrypt_ec_sign(key, "sha256", digest.data, digest.len, &signature), "ec sign");
    print_buffer("ec_signature", &signature);
    ok(allcrypt_ec_public_bytes(key, 0, &public_key), "ec public");
    print_buffer("ec_loaded_public", &public_key);
    expect(allcrypt_ec_verify("P-256", public_key.data, public_key.len, digest.data,
                              digest.len, signature.data, signature.len) == ALLCRYPT_OK,
           "an ECDSA signature verifies");
    signature.data[5] ^= 1;
    expect(allcrypt_ec_verify("P-256", public_key.data, public_key.len, digest.data,
                              digest.len, signature.data, signature.len) == ALLCRYPT_INVALID,
           "an altered ECDSA signature is INVALID");
    expect(allcrypt_ec_verify("P-256", public_key.data, public_key.len, digest.data,
                              digest.len, signature.data, 10) == ALLCRYPT_ERROR,
           "a short ECDSA signature is an ERROR");

    /* ECDH both ways. */
    allcrypt_ec_key *other = NULL;
    allcrypt_buffer other_public = {0}, one = {0}, two = {0};
    ok(allcrypt_ec_generate("P-256", &other), "ec generate");
    ok(allcrypt_ec_public_bytes(other, 0, &other_public), "ec public");
    ok(allcrypt_ec_exchange(key, other_public.data, other_public.len, &one), "ecdh");
    ok(allcrypt_ec_exchange(other, public_key.data, public_key.len, &two), "ecdh");
    expect(same(&one, &two) && one.len == 32, "both ends of ECDH agree");
    other_public.data[40] ^= 1;
    refused(allcrypt_ec_exchange(key, other_public.data, other_public.len, &one),
            "a point off the curve", "");

    /* The wrong kind of file is refused by name. */
    allcrypt_ec_key *never = NULL;
    pem = read_file(dir, "ed25519.pem", &len);
    refused(allcrypt_ec_load(pem, len, NULL, 0, &never), "an EdDSA file as EC", "EdDSA");
    free(pem);
    refused(allcrypt_ec_generate("P-255", &never), "an unknown curve", "255");
    refused(allcrypt_ec_generate("P-256", NULL), "a NULL out", "NULL");

    allcrypt_ec_key_free(key);
    allcrypt_ec_key_free(other);
    allcrypt_ec_key_free(NULL);
    allcrypt_buffer_free(&digest);
    allcrypt_buffer_free(&public_key);
    allcrypt_buffer_free(&signature);
    allcrypt_buffer_free(&other_public);
    allcrypt_buffer_free(&one);
    allcrypt_buffer_free(&two);
}

static void eddsa(const char *dir) {
    allcrypt_eddsa_key *key = NULL;
    allcrypt_buffer public_key = {0}, signature = {0}, seed = {0};
    ok(allcrypt_eddsa_from_private("ed25519", message + 7, 32, &key), "eddsa from_private");
    ok(allcrypt_eddsa_public_bytes(key, &public_key), "eddsa public");
    print_buffer("ed25519_public", &public_key);
    ok(allcrypt_eddsa_sign(key, message, 123, NULL, 0, &signature), "ed25519 sign");
    print_buffer("ed25519_signature", &signature);
    expect(allcrypt_eddsa_verify("ed25519", public_key.data, public_key.len, message, 123,
                                 signature.data, signature.len, NULL, 0) == ALLCRYPT_OK,
           "an Ed25519 signature verifies");
    expect(allcrypt_eddsa_verify("ed25519", public_key.data, public_key.len, message, 122,
                                 signature.data, signature.len, NULL, 0) == ALLCRYPT_INVALID,
           "an Ed25519 signature over another message is INVALID");
    refused(allcrypt_eddsa_sign(key, message, 123, message, 3, &seed), "an Ed25519 context",
            "context");
    allcrypt_eddsa_key_free(key);
    allcrypt_buffer_free(&public_key);
    allcrypt_buffer_free(&signature);

    /* NULL is no password and a non-NULL empty one is the empty
     * password, which is a different request. */
    size_t len;
    uint8_t *pem = read_file(dir, "ed25519_empty_password.pem", &len);
    refused(allcrypt_eddsa_load(pem, len, NULL, 0, &key), "an encrypted key with no password",
            "encrypted");
    ok(allcrypt_eddsa_load(pem, len, (const uint8_t *)"", 0, &key), "the empty password");
    free(pem);
    ok(allcrypt_eddsa_public_bytes(key, &public_key), "eddsa public");
    print_buffer("ed25519_empty_password_public", &public_key);
    allcrypt_eddsa_key_free(key);
    allcrypt_buffer_free(&public_key);

    pem = read_file(dir, "ed448.pem", &len);
    ok(allcrypt_eddsa_load(pem, len, NULL, 0, &key), "ed448 load");
    free(pem);
    ok(allcrypt_eddsa_private_bytes(key, &seed), "eddsa private");
    print_buffer("ed448_loaded_seed", &seed);
    ok(allcrypt_eddsa_public_bytes(key, &public_key), "eddsa public");
    print_buffer("ed448_loaded_public", &public_key);
    ok(allcrypt_eddsa_sign(key, message, 77, message + 200, 5, &signature), "ed448 sign");
    print_buffer("ed448_signature", &signature);
    expect(allcrypt_eddsa_verify("ed448", public_key.data, public_key.len, message, 77,
                                 signature.data, signature.len, message + 200, 5)
           == ALLCRYPT_OK, "an Ed448 signature with a context verifies");
    expect(allcrypt_eddsa_verify("ed448", public_key.data, public_key.len, message, 77,
                                 signature.data, signature.len, NULL, 0) == ALLCRYPT_INVALID,
           "an Ed448 signature without its context is INVALID");
    allcrypt_eddsa_key_free(key);
    allcrypt_buffer_free(&seed);
    allcrypt_buffer_free(&public_key);
    allcrypt_buffer_free(&signature);

    ok(allcrypt_eddsa_generate("ed448", &key), "eddsa generate");
    allcrypt_eddsa_key_free(key);
    allcrypt_eddsa_key_free(NULL);
}

static void rsa(const char *dir) {
    size_t len;
    allcrypt_rsa_key *key = NULL;
    uint8_t *pem = read_file(dir, "rsa_encrypted.pem", &len);
    const uint8_t password[] = "correct horse";
    refused(allcrypt_rsa_load(pem, len, NULL, 0, &key), "an encrypted file without a password",
            "");
    refused(allcrypt_rsa_load(pem, len, (const uint8_t *)"wrong", 5, &key), "a wrong password",
            "");
    ok(allcrypt_rsa_load(pem, len, password, sizeof password - 1, &key), "rsa load");
    free(pem);

    allcrypt_buffer n = {0}, e = {0}, digest = {0}, signature = {0}, pss = {0};
    ok(allcrypt_rsa_public_numbers(key, &n, &e), "rsa numbers");
    print_buffer("rsa_n", &n);
    print_buffer("rsa_e", &e);
    ok(allcrypt_hash("sha256", message, 500, &digest), "digest");
    ok(allcrypt_rsa_sign(key, "sha256", digest.data, digest.len, &signature), "rsa sign");
    print_buffer("rsa_pkcs1_signature", &signature);
    ok(allcrypt_rsa_sign_pss(key, "sha256", digest.data, digest.len, &pss), "rsa pss");
    print_buffer("rsa_pss_signature", &pss);

    allcrypt_rsa_public_key *public_key = NULL, *rebuilt = NULL;
    ok(allcrypt_rsa_public_from_key(key, &public_key), "rsa public");
    ok(allcrypt_rsa_public_new(n.data, n.len, e.data, e.len, &rebuilt), "rsa public new");
    expect(allcrypt_rsa_verify(rebuilt, "sha256", digest.data, digest.len, signature.data,
                               signature.len) == ALLCRYPT_OK, "PKCS#1 v1.5 verifies");
    expect(allcrypt_rsa_verify_pss(rebuilt, "sha256", digest.data, digest.len, pss.data,
                                   pss.len) == ALLCRYPT_OK, "PSS verifies");
    pss.data[pss.len - 2] ^= 1;
    expect(allcrypt_rsa_verify_pss(public_key, "sha256", digest.data, digest.len, pss.data,
                                   pss.len) == ALLCRYPT_INVALID, "an altered PSS is INVALID");
    expect(allcrypt_rsa_verify(public_key, "sha1", digest.data, digest.len, signature.data,
                               signature.len) != ALLCRYPT_OK, "the wrong hash does not verify");

    allcrypt_buffer ciphertext = {0}, plaintext = {0};
    ok(allcrypt_rsa_encrypt_oaep(public_key, "sha256", message, 4, message + 9, 50,
                                 &ciphertext), "oaep encrypt");
    print_buffer("rsa_oaep_ciphertext", &ciphertext);
    ok(allcrypt_rsa_decrypt_oaep(key, "sha256", message, 4, ciphertext.data, ciphertext.len,
                                 &plaintext), "oaep decrypt");
    expect(plaintext.len == 50 && memcmp(plaintext.data, message + 9, 50) == 0,
           "OAEP decrypts what it encrypted");
    allcrypt_buffer_free(&plaintext);
    refused(allcrypt_rsa_decrypt_oaep(key, "sha256", NULL, 0, ciphertext.data, ciphertext.len,
                                      &plaintext), "OAEP under another label", "");
    allcrypt_buffer_free(&ciphertext);
    ok(allcrypt_rsa_encrypt(public_key, message + 9, 50, &ciphertext), "pkcs1 encrypt");
    print_buffer("rsa_pkcs1_ciphertext", &ciphertext);
    ok(allcrypt_rsa_decrypt(key, ciphertext.data, ciphertext.len, &plaintext), "pkcs1 decrypt");
    expect(plaintext.len == 50 && memcmp(plaintext.data, message + 9, 50) == 0,
           "PKCS#1 v1.5 decrypts what it encrypted");
    allcrypt_buffer_free(&plaintext);
    allcrypt_buffer_free(&ciphertext);
    ok(allcrypt_rsa_encrypt_raw(public_key, message + 9, 50, &ciphertext), "raw encrypt");
    print_buffer("rsa_raw_ciphertext", &ciphertext);
    ok(allcrypt_rsa_decrypt_raw(key, ciphertext.data, ciphertext.len, &plaintext),
       "raw decrypt");
    expect(plaintext.len == n.len && memcmp(plaintext.data + n.len - 50, message + 9, 50) == 0,
           "raw decryption returns the message at the key's size");
    allcrypt_buffer_free(&plaintext);
    allcrypt_buffer_free(&ciphertext);
    refused(allcrypt_rsa_encrypt_raw(public_key, n.data, n.len, &ciphertext),
            "a raw message equal to the modulus", "");

    /* The same key from its primes. */
    uint8_t *primes = read_file(dir, "rsa_primes.txt", &len);
    uint8_t p[512], q[512], exponent[8];
    char *line_q = strchr((char *)primes, '\n') + 1;
    char *line_e = strchr(line_q, '\n') + 1;
    size_t p_len = unhex((char *)primes, p, sizeof p);
    size_t q_len = unhex(line_q, q, sizeof q);
    size_t e_len = unhex(line_e, exponent, sizeof exponent);
    free(primes);
    allcrypt_rsa_key *from_primes = NULL;
    allcrypt_buffer n2 = {0}, e2 = {0}, signature2 = {0};
    ok(allcrypt_rsa_from_primes(p, p_len, q, q_len, exponent, e_len, &from_primes),
       "rsa from primes");
    ok(allcrypt_rsa_public_numbers(from_primes, &n2, &e2), "rsa numbers");
    expect(same(&n, &n2) && same(&e, &e2), "the primes make the file's key");
    ok(allcrypt_rsa_sign(from_primes, "sha256", digest.data, digest.len, &signature2),
       "rsa sign");
    expect(same(&signature, &signature2), "PKCS#1 v1.5 signing is deterministic");

    allcrypt_rsa_key *small = NULL;
    ok(allcrypt_rsa_generate(1024, &small), "rsa generate");
    allcrypt_rsa_key_free(small);

    allcrypt_rsa_key_free(key);
    allcrypt_rsa_key_free(from_primes);
    allcrypt_rsa_key_free(NULL);
    allcrypt_rsa_public_key_free(public_key);
    allcrypt_rsa_public_key_free(rebuilt);
    allcrypt_rsa_public_key_free(NULL);
    allcrypt_buffer *all[] = {&n, &e, &digest, &signature, &pss, &n2, &e2, &signature2};
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
        allcrypt_buffer_free(all[i]);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s KEY-DIRECTORY\n", argv[0]);
        return 2;
    }
    for (size_t i = 0; i < sizeof message; i++) {
        message[i] = (uint8_t)i;
    }
    general();
    hashes();
    hmac();
    kdfs();
    block_ciphers();
    aeads();
    stream_ciphers();
    x25519();
    ec(argv[1]);
    eddsa(argv[1]);
    rsa(argv[1]);
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    printf("done\n");
    return 0;
}
