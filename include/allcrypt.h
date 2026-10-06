/*
 * allcrypt.h - the C interface to allcrypt.
 *
 * Build the library with the `c-api` feature (docs/c.md):
 *
 *     cargo build --release --features c-api
 *         -> target/release/liballcrypt.so   (.dylib on macOS, .dll on Windows)
 *     cargo rustc --release --lib --features c-api --crate-type staticlib
 *         -> target/release/liballcrypt.a    (allcrypt.lib on Windows)
 *
 * and link with -lallcrypt. A static link also needs the system
 * libraries `cargo rustc ... --print native-static-libs` names.
 *
 * Conventions, the same for every function:
 *
 *  - A function that can fail returns int: ALLCRYPT_OK (0), or
 *    ALLCRYPT_ERROR, after which allcrypt_last_error() says why. The
 *    verifiers also return ALLCRYPT_INVALID for a well-formed signature
 *    that does not verify. Only 0 is success, so test a verifier with
 *    `== ALLCRYPT_OK`; it is not a boolean.
 *
 *  - Bytes in are a pointer and a length. The pointer may be NULL when
 *    the length is 0. Names (hashes, ciphers, curves) are NUL-terminated
 *    UTF-8 and case-insensitive, as in the Rust and Python interfaces.
 *
 *  - Output whose length the caller chooses (random bytes, a KDF) is
 *    written to the caller's memory. Output whose length the library
 *    decides is returned in an allcrypt_buffer, which the caller releases
 *    with allcrypt_buffer_free. A buffer is overwritten, not appended to,
 *    so free one before reusing it. On failure nothing is written to it.
 *
 *  - Objects are opaque. They are made by the _new, _generate, _from_
 *    and _load functions, which write the object through their last
 *    argument, and released by the matching _free, which accepts NULL.
 *    An object may be used by one thread at a time.
 *
 *  - Every pointer must point at what its type says for the duration of
 *    the call, and every object must have come from this library and not
 *    yet have been freed. Those are the only requirements; the library
 *    checks for NULL and returns ALLCRYPT_ERROR rather than crash.
 *
 * Nothing is deprecated and nothing is refused for being old: MD5, RC4,
 * DES and PKCS#1 v1.5 are all here, by name.
 */

#ifndef ALLCRYPT_H
#define ALLCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ALLCRYPT_OK 0
#define ALLCRYPT_ERROR (-1)
#define ALLCRYPT_INVALID (-2)

/* Bytes whose length the library decided. data is NULL when len is 0. */
typedef struct allcrypt_buffer {
    uint8_t *data;
    size_t len;
} allcrypt_buffer;

typedef struct allcrypt_hash_state allcrypt_hash_state;
typedef struct allcrypt_hmac_state allcrypt_hmac_state;
typedef struct allcrypt_cipher allcrypt_cipher;
typedef struct allcrypt_stream allcrypt_stream;
typedef struct allcrypt_ec_key allcrypt_ec_key;
typedef struct allcrypt_eddsa_key allcrypt_eddsa_key;
typedef struct allcrypt_rsa_key allcrypt_rsa_key;
typedef struct allcrypt_rsa_public_key allcrypt_rsa_public_key;

/* ------------------------------------------------------------ general */

/* The library's version. Static; never freed. */
const char *allcrypt_version(void);

/* Why the last failing call on this thread failed. Valid until the next
 * failing call on this thread; never freed by the caller. */
const char *allcrypt_last_error(void);

/* Zero and release a buffer's bytes and set it empty. NULL is fine. */
void allcrypt_buffer_free(allcrypt_buffer *buffer);

/* out_len bytes from the operating system's random source. */
int allcrypt_random(uint8_t *out, size_t out_len);

/* The names one family accepts, comma separated: kind is "hashes",
 * "block_ciphers", "modes", "stream_ciphers", "aeads", "curves" or
 * "eddsa". Static; never freed. NULL for an unknown kind. */
const char *allcrypt_names(const char *kind);

/* ------------------------------------------------------------- hashes */

/* name: "sha256", "sha3_512", "md5", "streebog256", "sm3", ...:
 * allcrypt_names("hashes"). */
int allcrypt_hash(const char *name, const uint8_t *data, size_t data_len,
                  allcrypt_buffer *digest);

int allcrypt_hash_new(const char *name, allcrypt_hash_state **out);
int allcrypt_hash_update(allcrypt_hash_state *hash, const uint8_t *data, size_t data_len);
/* The digest of everything so far; the hash can go on being updated. */
int allcrypt_hash_digest(allcrypt_hash_state *hash, allcrypt_buffer *digest);
void allcrypt_hash_free(allcrypt_hash_state *hash);

/* name: "shake128" or "shake256"; out_len bytes of output. */
int allcrypt_shake(const char *name, const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len);

/* --------------------------------------------------------------- HMAC */

int allcrypt_hmac(const char *hash_name, const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len, allcrypt_buffer *mac);

int allcrypt_hmac_new(const char *hash_name, const uint8_t *key, size_t key_len,
                      allcrypt_hmac_state **out);
int allcrypt_hmac_update(allcrypt_hmac_state *hmac, const uint8_t *data, size_t data_len);
/* The MAC of everything so far; the HMAC can go on being updated. */
int allcrypt_hmac_digest(allcrypt_hmac_state *hmac, allcrypt_buffer *mac);
void allcrypt_hmac_free(allcrypt_hmac_state *hmac);

/* --------------------------------------------------------------- KDFs */

int allcrypt_pbkdf2(const char *hash_name, const uint8_t *password, size_t password_len,
                    const uint8_t *salt, size_t salt_len, uint32_t iterations,
                    uint8_t *out, size_t out_len);

/* RFC 5869. An empty salt is the all-zero salt the RFC specifies. */
int allcrypt_hkdf(const char *hash_name, const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len);

int allcrypt_scrypt(const uint8_t *password, size_t password_len, const uint8_t *salt,
                    size_t salt_len, uint64_t n, uint32_t r, uint32_t p, uint8_t *out,
                    size_t out_len);

/* variant: "argon2d", "argon2i" or "argon2id". secret and
 * associated_data may be empty. */
int allcrypt_argon2(const char *variant, const uint8_t *password, size_t password_len,
                    const uint8_t *salt, size_t salt_len, uint32_t memory_kib,
                    uint32_t passes, uint32_t lanes, const uint8_t *secret,
                    size_t secret_len, const uint8_t *associated_data,
                    size_t associated_data_len, uint8_t *out, size_t out_len);

/* ------------------------------------------------------ block ciphers */

/* A block cipher in a mode, in one direction.
 *
 * cipher: "aes", "des", "3des", "blowfish", "camellia", "kuznyechik", ...:
 *         allcrypt_names("block_ciphers"). The key length decides the
 *         variant (AES-128, -192 or -256).
 * param:  the cipher's optional parameter (RC2's effective key bits, as
 *         text), or NULL.
 * mode:   "ecb", "cbc", "pcbc", "cfb", "ofb", "ctr", "ctr-le",
 *         "cbc-cs1", "cbc-cs2", "cbc-cs3". ECB takes no IV.
 * decrypt: 0 to encrypt, anything else to decrypt. */
int allcrypt_cipher_new(const char *cipher, const uint8_t *key, size_t key_len,
                        const char *param, const char *mode, const uint8_t *iv,
                        size_t iv_len, int decrypt, allcrypt_cipher **out);

/* Whatever output is ready. The block modes may hold back part of a
 * block until more input arrives or the stream is finished. */
int allcrypt_cipher_update(allcrypt_cipher *cipher, const uint8_t *data, size_t data_len,
                           allcrypt_buffer *out);

/* The rest of the output. No padding is added or removed: ECB and CBC
 * input must be whole blocks, so pad with allcrypt_pad_pkcs7 first. */
int allcrypt_cipher_finish(allcrypt_cipher *cipher, allcrypt_buffer *out);
void allcrypt_cipher_free(allcrypt_cipher *cipher);

/* PKCS#7 always adds 1 to block_size bytes: aligned input gains a whole
 * block. Unpadding refuses anything not validly padded. */
int allcrypt_pad_pkcs7(const uint8_t *data, size_t data_len, size_t block_size,
                       allcrypt_buffer *out);
int allcrypt_unpad_pkcs7(const uint8_t *data, size_t data_len, size_t block_size,
                         allcrypt_buffer *out);

/* --------------------------------------------------------------- AEAD */

/* name: "aes-gcm", "chacha20-poly1305", "aes-ccm", "aes-eax", "aes-ocb",
 * "kuznyechik-mgm", ...: allcrypt_names("aeads"). The tag's length
 * depends on the algorithm, and not every nonce is 12 bytes. */
int allcrypt_aead_encrypt(const char *name, const uint8_t *key, size_t key_len,
                          const uint8_t *nonce, size_t nonce_len, const uint8_t *aad,
                          size_t aad_len, const uint8_t *plaintext, size_t plaintext_len,
                          allcrypt_buffer *ciphertext, allcrypt_buffer *tag);

/* The plaintext, or ALLCRYPT_ERROR and no plaintext at all. */
int allcrypt_aead_decrypt(const char *name, const uint8_t *key, size_t key_len,
                          const uint8_t *nonce, size_t nonce_len, const uint8_t *aad,
                          size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *tag, size_t tag_len, allcrypt_buffer *plaintext);

/* ----------------------------------------------------- stream ciphers */

/* name: "chacha20", "xchacha20", "salsa20", "rc4", ...:
 * allcrypt_names("stream_ciphers"). */
int allcrypt_stream_new(const char *name, const uint8_t *key, size_t key_len,
                        const uint8_t *nonce, size_t nonce_len, allcrypt_stream **out);

/* XOR the keystream over data in place: encryption and decryption are
 * the same call. */
int allcrypt_stream_apply(allcrypt_stream *stream, uint8_t *data, size_t data_len);
void allcrypt_stream_free(allcrypt_stream *stream);

/* ------------------------------------------------------------- X25519 */

int allcrypt_x25519_generate(uint8_t private_key[32], uint8_t public_key[32]);
int allcrypt_x25519_public_key(const uint8_t private_key[32], uint8_t public_key[32]);

/* Refuses the all-zero result, which a low-order peer point produces. */
int allcrypt_x25519_exchange(const uint8_t private_key[32], const uint8_t peer[32],
                             uint8_t shared[32]);

/* ---------------------------------------------------- EC: ECDSA, ECDH */

/* curve: "P-256", "P-384", "P-521", "secp256k1", "sm2p256v1",
 * "gost256-a", ...: allcrypt_names("curves"). */
int allcrypt_ec_generate(const char *curve, allcrypt_ec_key **out);

/* The private scalar, big endian, in [1, n). */
int allcrypt_ec_from_private(const char *curve, const uint8_t *private_key,
                             size_t private_key_len, allcrypt_ec_key **out);

/* A PKCS#8, SEC1 or PEM file. password NULL means not encrypted; a
 * non-NULL password of length 0 is the empty password. */
int allcrypt_ec_load(const uint8_t *data, size_t data_len, const uint8_t *password,
                     size_t password_len, allcrypt_ec_key **out);

int allcrypt_ec_private_bytes(const allcrypt_ec_key *key, allcrypt_buffer *out);

/* SEC1: 04 || x || y, or 02/03 || x when compressed is not 0. */
int allcrypt_ec_public_bytes(const allcrypt_ec_key *key, int compressed,
                             allcrypt_buffer *out);

/* ECDSA over a digest, deterministic (RFC 6979). hash_name names the hash
 * that made the digest. The signature is r || s at fixed width, not DER. */
int allcrypt_ec_sign(const allcrypt_ec_key *key, const char *hash_name,
                     const uint8_t *digest, size_t digest_len, allcrypt_buffer *signature);

/* ECDH: the x coordinate, at full width. The peer's point is checked. */
int allcrypt_ec_exchange(const allcrypt_ec_key *key, const uint8_t *peer, size_t peer_len,
                         allcrypt_buffer *shared);
void allcrypt_ec_key_free(allcrypt_ec_key *key);

/* ALLCRYPT_OK, ALLCRYPT_INVALID or ALLCRYPT_ERROR. public_key is SEC1. */
int allcrypt_ec_verify(const char *curve, const uint8_t *public_key, size_t public_key_len,
                       const uint8_t *digest, size_t digest_len, const uint8_t *signature,
                       size_t signature_len);

/* -------------------------------------------------------------- EdDSA */

/* name: "ed25519" or "ed448". */
int allcrypt_eddsa_generate(const char *name, allcrypt_eddsa_key **out);

/* The private key as RFC 8032 defines it: the seed, not a scalar. */
int allcrypt_eddsa_from_private(const char *name, const uint8_t *private_key,
                                size_t private_key_len, allcrypt_eddsa_key **out);
int allcrypt_eddsa_load(const uint8_t *data, size_t data_len, const uint8_t *password,
                        size_t password_len, allcrypt_eddsa_key **out);
int allcrypt_eddsa_private_bytes(const allcrypt_eddsa_key *key, allcrypt_buffer *out);
int allcrypt_eddsa_public_bytes(const allcrypt_eddsa_key *key, allcrypt_buffer *out);

/* Signs the message itself, not a digest. context is Ed448's context
 * string, empty for none; Ed25519 has none and refuses one. */
int allcrypt_eddsa_sign(const allcrypt_eddsa_key *key, const uint8_t *message,
                        size_t message_len, const uint8_t *context, size_t context_len,
                        allcrypt_buffer *signature);
void allcrypt_eddsa_key_free(allcrypt_eddsa_key *key);

int allcrypt_eddsa_verify(const char *name, const uint8_t *public_key, size_t public_key_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *signature, size_t signature_len,
                          const uint8_t *context, size_t context_len);

/* ---------------------------------------------------------------- RSA */

int allcrypt_rsa_generate(size_t bits, allcrypt_rsa_key **out);

/* The two primes and the public exponent, big endian. */
int allcrypt_rsa_from_primes(const uint8_t *p, size_t p_len, const uint8_t *q, size_t q_len,
                             const uint8_t *e, size_t e_len, allcrypt_rsa_key **out);
int allcrypt_rsa_load(const uint8_t *data, size_t data_len, const uint8_t *password,
                      size_t password_len, allcrypt_rsa_key **out);

/* The modulus and the public exponent, big endian. */
int allcrypt_rsa_public_numbers(const allcrypt_rsa_key *key, allcrypt_buffer *n,
                                allcrypt_buffer *e);

/* PKCS#1 v1.5 over a digest made by hash_name. */
int allcrypt_rsa_sign(const allcrypt_rsa_key *key, const char *hash_name,
                      const uint8_t *digest, size_t digest_len, allcrypt_buffer *signature);

/* PSS with MGF1 over the same hash and a salt as long as the digest. */
int allcrypt_rsa_sign_pss(const allcrypt_rsa_key *key, const char *hash_name,
                          const uint8_t *digest, size_t digest_len,
                          allcrypt_buffer *signature);

/* PKCS#1 v1.5 decryption. Every failure is the same error. */
int allcrypt_rsa_decrypt(const allcrypt_rsa_key *key, const uint8_t *ciphertext,
                         size_t ciphertext_len, allcrypt_buffer *plaintext);

/* OAEP with MGF1 over the same hash. The label is usually empty. */
int allcrypt_rsa_decrypt_oaep(const allcrypt_rsa_key *key, const char *hash_name,
                              const uint8_t *label, size_t label_len,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              allcrypt_buffer *plaintext);
void allcrypt_rsa_key_free(allcrypt_rsa_key *key);

int allcrypt_rsa_public_new(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                            allcrypt_rsa_public_key **out);
int allcrypt_rsa_public_from_key(const allcrypt_rsa_key *key, allcrypt_rsa_public_key **out);

/* ALLCRYPT_OK, ALLCRYPT_INVALID or ALLCRYPT_ERROR. */
int allcrypt_rsa_verify(const allcrypt_rsa_public_key *key, const char *hash_name,
                        const uint8_t *digest, size_t digest_len, const uint8_t *signature,
                        size_t signature_len);
int allcrypt_rsa_verify_pss(const allcrypt_rsa_public_key *key, const char *hash_name,
                            const uint8_t *digest, size_t digest_len,
                            const uint8_t *signature, size_t signature_len);

/* Both encryptions are randomised. */
int allcrypt_rsa_encrypt(const allcrypt_rsa_public_key *key, const uint8_t *message,
                         size_t message_len, allcrypt_buffer *ciphertext);
int allcrypt_rsa_encrypt_oaep(const allcrypt_rsa_public_key *key, const char *hash_name,
                              const uint8_t *label, size_t label_len, const uint8_t *message,
                              size_t message_len, allcrypt_buffer *ciphertext);
void allcrypt_rsa_public_key_free(allcrypt_rsa_public_key *key);

#ifdef __cplusplus
}
#endif

#endif /* ALLCRYPT_H */
