/* Emit GOST test vectors from OpenSSL's gost-engine.
 *
 * `scripts/make_gost_vectors.py` drives `openssl enc` and `openssl
 * dgst` for everything the command line can reach. This program exists
 * for the three things it cannot:
 *
 *   * **MGM.** `openssl enc` refuses an AEAD outright, so there is no
 *     command line route to `kuznyechik-mgm` or `magma-mgm` at all.
 *   * **OMAC.** `openssl dgst -mac kuznyechik-mac` runs and prints
 *     something, which is worse than refusing. See below.
 *   * **KExp15.** A key-wrapping cipher whose input is a key, which
 *     `enc` has no way to say.
 *
 * ## Why the command line cannot be trusted for the MACs
 *
 * On OpenSSL 3.0 with this engine, `dgst -mac kuznyechik-mac` and
 * `dgst -mac magma-mac` print **the same bytes** for the same input,
 * and `-macopt size:16` is refused by `gost_pmeth.c:852` - which is
 * Magma's ctrl, where 8 is the maximum. The name `kuznyechik-mac`
 * resolves to Magma's method. On top of that the printed value carries
 * eight bytes past the MAC that change on every run, because `dgst`
 * prints a block's worth and the method wrote half of it:
 *
 *     kuznyechik-mac: f3daae40c3613e9e 81d5bf80957f0000
 *     kuznyechik-mac: f3daae40c3613e9e 8145358a547f0000
 *
 * A vector file built from that would have been half stack addresses
 * and half the wrong cipher, and every row would have looked fine.
 * So the MACs are taken through `EVP_PKEY_new_mac_key` here, and
 * `check()` asserts the two ciphers *disagree* and that Kuznyechik's
 * MAC is sixteen bytes - the two things the command line got wrong.
 *
 * ## Building and running
 *
 * The Python generator does both; this is what it runs:
 *
 *     cc -O2 -o gost_engine_probe scripts/gost_engine_probe.c -lcrypto
 *     OPENSSL_ENGINES=<gost-engine build/bin> ./gost_engine_probe
 *
 * It writes the vector file's MGM, OMAC and KExp15 sections to stdout
 * in the same `[section]` / `Name = hex` form as the rest, and exits
 * non-zero with a message on stderr if anything it asked for was not
 * there. **Nothing in the test gate builds or runs this.** It is a
 * development tool, like `scripts/check_live.py`; what ships is the
 * vector file it helped write.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The whole ENGINE API is deprecated in OpenSSL 3.0 and is also the
 * only way to reach this code: gost-engine's provider does not expose
 * MGM or the MACs on this OpenSSL. Silenced here rather than at the
 * build command, so the reason travels with the file. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <dlfcn.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

static ENGINE *gost;

/* Fail loudly and immediately.
 *
 * Every step here can fail in a way that leaves a plausible-looking
 * buffer behind - an uninitialised tag is still sixteen bytes - so
 * there is no path that carries on after an error and no default
 * value anywhere. A vector file is worthless if a row in it came from
 * a call that did not happen. */
static void die(const char *what)
{
    fprintf(stderr, "gost_engine_probe: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void put_hex(const char *name, const unsigned char *data, size_t len)
{
    printf("%s = ", name);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* Ask the **engine** for a cipher, by NID rather than by name.
 *
 * `EVP_get_cipherbyname` would answer from whatever is registered,
 * which on a build with a GOST provider loaded is a second
 * implementation - and then this file would be evidence about code
 * nobody asked about. `ENGINE_get_cipher` can only answer with the
 * engine's own. */
static const EVP_CIPHER *cipher_from_engine(const char *name)
{
    int nid = OBJ_sn2nid(name);
    if (nid == NID_undef)
        die("that cipher has no NID");
    const EVP_CIPHER *cipher = ENGINE_get_cipher(gost, nid);
    if (cipher == NULL)
        die("the engine does not have that cipher");
    return cipher;
}

/* A deterministic filler, so a regenerated file differs only where the
 * engine's answer differs. Nothing here is random: `rand` would make
 * every re-run a diff and hide the one line that mattered. */
static void fill(unsigned char *out, size_t len, unsigned seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (unsigned char)((i * 37u + seed * 101u + 11u) & 0xff);
}

/* ---------------------------------------------------------------- MGM */

/* One MGM row: encrypt, and take the tag.
 *
 * The nonce is a whole block - 16 bytes for Kuznyechik, 8 for Magma -
 * rather than the twelve every other AEAD on this machine takes, and
 * its **top bit must be clear**: that bit separates MGM's two counter
 * chains, so the engine rejects a nonce that sets it rather than
 * masking it. `fill` is masked at the call site for that reason.
 */
static void mgm_row(const char *cipher_name, size_t key_len, size_t nonce_len,
                    size_t ad_len, size_t msg_len, unsigned seed)
{
    const EVP_CIPHER *cipher = cipher_from_engine(cipher_name);

    unsigned char key[64], nonce[32], ad[512], msg[4096], out[4096 + 32];
    unsigned char tag[16];
    if (key_len > sizeof key || nonce_len > sizeof nonce
        || ad_len > sizeof ad || msg_len > sizeof msg)
        die("a row asked for more than the buffers hold");

    fill(key, key_len, seed);
    fill(nonce, nonce_len, seed + 7);
    nonce[0] &= 0x7f;                 /* MGM's chain separator bit. */
    fill(ad, ad_len, seed + 13);
    fill(msg, msg_len, seed + 29);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        die("EVP_CIPHER_CTX_new");
    if (EVP_EncryptInit_ex(ctx, cipher, gost, NULL, NULL) != 1)
        die("EVP_EncryptInit_ex (cipher)");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            (int)nonce_len, NULL) != 1)
        die("EVP_CTRL_AEAD_SET_IVLEN");
    if (EVP_EncryptInit_ex(ctx, NULL, gost, key, nonce) != 1)
        die("EVP_EncryptInit_ex (key and nonce)");

    int len = 0, total = 0;
    if (ad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, ad, (int)ad_len) != 1)
        die("EVP_EncryptUpdate (associated data)");
    if (msg_len > 0) {
        if (EVP_EncryptUpdate(ctx, out, &len, msg, (int)msg_len) != 1)
            die("EVP_EncryptUpdate (message)");
        total = len;
    }
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1)
        die("EVP_EncryptFinal_ex");
    total += len;
    if ((size_t)total != msg_len)
        die("MGM is a stream mode and must not change the length");

    /* The tag length is the cipher's block, which is also the only
     * length the engine will hand back for this mode. */
    size_t tag_len = nonce_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            (int)tag_len, tag) != 1)
        die("EVP_CTRL_AEAD_GET_TAG");

    printf("\n");
    put_hex("Key", key, key_len);
    put_hex("Nonce", nonce, nonce_len);
    put_hex("AD", ad, ad_len);
    put_hex("In", msg, msg_len);
    put_hex("Out", out, msg_len);
    put_hex("Tag", tag, tag_len);

    EVP_CIPHER_CTX_free(ctx);
}

/* --------------------------------------------------------------- OMAC */

static size_t omac_once(const char *mac_name, const unsigned char *key,
                        size_t key_len, const unsigned char *msg,
                        size_t msg_len, unsigned char *out, size_t out_cap)
{
    int nid = OBJ_sn2nid(mac_name);
    if (nid == NID_undef)
        die("that MAC has no NID");

    /* **The engine argument here does nothing and the pkey comes out
     * typeless without `ENGINE_set_default`.** Passing `gost` to both
     * of these calls builds a key whose `EVP_PKEY_get_id` is
     * `NID_undef`, and `EVP_DigestSignInit` then says "unsupported
     * algorithm" - the type is set from the *default* ASN1 method
     * table, which an explicit engine argument does not consult.
     * `main` registers the engine as the default before anything runs
     * and this asserts the type came back right, because a typeless
     * key is the failure that produced eight bytes of stack. */
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(nid, NULL, key, (int)key_len);
    if (pkey == NULL)
        die("EVP_PKEY_new_mac_key");
    if (EVP_PKEY_get_id(pkey) != nid)
        die("the MAC key came back as a different algorithm from the "
            "one asked for");

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        die("EVP_MD_CTX_new");
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1)
        die("EVP_DigestSignInit");
    if (msg_len > 0 && EVP_DigestSignUpdate(ctx, msg, msg_len) != 1)
        die("EVP_DigestSignUpdate");

    size_t len = out_cap;
    if (EVP_DigestSignFinal(ctx, out, &len) != 1)
        die("EVP_DigestSignFinal");
    if (len == 0 || len > out_cap)
        die("EVP_DigestSignFinal returned an impossible length");

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return len;
}

static void omac_row(const char *mac_name, size_t key_len, size_t msg_len,
                     unsigned key_seed, unsigned message_seed)
{
    unsigned char key[64], msg[4096], mac[64];
    if (key_len > sizeof key || msg_len > sizeof msg)
        die("a row asked for more than the buffers hold");
    fill(key, key_len, key_seed);
    fill(msg, msg_len, message_seed);

    size_t len = omac_once(mac_name, key, key_len, msg, msg_len,
                           mac, sizeof mac);
    printf("\n");
    put_hex("Key", key, key_len);
    put_hex("In", msg, msg_len);
    put_hex("Out", mac, len);
}

/* The two things `openssl dgst -mac` got wrong, asserted rather than
 * assumed. Both would be invisible in the output: a sixteen byte row
 * and an eight byte row look equally plausible, and two ciphers
 * agreeing looks like a coincidence until you try a second message. */
static void check_the_macs_are_the_ciphers_own(void)
{
    unsigned char key[32], msg[40], kuz[64], mag[64];
    fill(key, sizeof key, 5);
    fill(msg, sizeof msg, 9);

    size_t kuz_len = omac_once("kuznyechik-mac", key, sizeof key,
                               msg, sizeof msg, kuz, sizeof kuz);
    size_t mag_len = omac_once("magma-mac", key, sizeof key,
                               msg, sizeof msg, mag, sizeof mag);

    if (kuz_len != 16)
        die("Kuznyechik's OMAC is one block, so sixteen bytes - the "
            "command line's answer was eight, because it dispatched to "
            "Magma's method");
    if (mag_len != 8)
        die("Magma's OMAC is one block, so eight bytes");
    if (memcmp(kuz, mag, mag_len) == 0)
        die("the two MACs agree, which means both rows came from one "
            "cipher - exactly what `dgst -mac` did");
}

/* ------------------------------------------------------------- KExp15 */

/* KExp15 (R 1323565.1.017-2018): export a key under a key-encryption
 * key.
 *
 * **Not reached through EVP.** The engine registers `magma-kexp15` and
 * `kuznyechik-kexp15` as ciphers, but the encrypting half of each is
 * `#if 0`'d out in `gost_keyexpimp.c` and falls through to `return
 * -1`; only unwrapping works. Driving them through
 * `EVP_EncryptUpdate` returns success with zero bytes of output,
 * which is how the first version of this program wrote two empty
 * rows and said nothing.
 *
 * `gost_kexp15` itself is an exported symbol in `gost.so`, so it is
 * called directly. That is a liberty - it is the engine's internal
 * API - and it is taken because the alternative is no witness at all
 * for the one question KExp15 raises that no document answers:
 * **which half of a 64 byte key is the MAC key.** The engine's own
 * unwrap path settles it - `cctx->key` is the MAC key and
 * `cctx->key + 32` the cipher key - and these rows make that
 * checkable rather than a reading of somebody else's source.
 */
typedef int (*kexp15_fn)(const unsigned char *shared_key, int shared_len,
                         int cipher_nid, const unsigned char *cipher_key,
                         int mac_nid, unsigned char *mac_key,
                         const unsigned char *iv, size_t iv_len,
                         unsigned char *out, int *out_len);

/* One handle on the already-mapped engine, for the symbols EVP does not
 * reach.
 *
 * `RTLD_NOLOAD` first: the engine is loaded, and a second copy would
 * give functions operating on another copy's static tables - which for
 * something table-driven is a different implementation wearing the same
 * name. */
static void *engine_handle(const char *engines_dir)
{
    static void *handle;
    if (handle != NULL)
        return handle;

    char path[4096];
    int written = snprintf(path, sizeof path, "%s/gost.so", engines_dir);
    if (written <= 0 || (size_t)written >= sizeof path)
        die("the engine directory path is too long");

    handle = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
    if (handle == NULL)
        handle = dlopen(path, RTLD_LAZY);
    if (handle == NULL)
        die("cannot open gost.so to reach its internal symbols");
    return handle;
}

static void *engine_symbol(const char *engines_dir, const char *name)
{
    void *found = dlsym(engine_handle(engines_dir), name);
    if (found == NULL)
        die("gost.so does not export a symbol this program needs");
    return found;
}

static void kexp15_row(kexp15_fn kexp15, const char *cipher_name,
                       const char *mac_name, size_t iv_len,
                       size_t material_len, unsigned seed)
{
    int cipher_nid = OBJ_sn2nid(cipher_name);
    int mac_nid = OBJ_sn2nid(mac_name);
    if (cipher_nid == NID_undef || mac_nid == NID_undef)
        die("KExp15 needs both a CTR cipher and a MAC by name");

    unsigned char key[64], iv[16], material[64], out[128];
    if (iv_len > sizeof iv || material_len > sizeof material)
        die("a row asked for more than the buffers hold");
    fill(key, sizeof key, seed);
    fill(iv, iv_len, seed + 17);
    fill(material, material_len, seed + 23);

    int out_len = (int)sizeof out;
    /* `key` is `K_MAC || K_ENC`, in that order - the order the
     * engine's own unwrap uses, and the whole point of these rows. */
    if (kexp15(material, (int)material_len, cipher_nid, key + 32,
               mac_nid, key, iv, iv_len, out, &out_len) != 1)
        die("gost_kexp15 refused");
    if (out_len <= (int)material_len)
        die("a wrapped key is longer than the key inside it");

    printf("\n");
    put_hex("Key", key, sizeof key);
    put_hex("IV", iv, iv_len);
    put_hex("In", material, material_len);
    put_hex("Out", out, (size_t)out_len);
}

/* --------------------------------------------------- reported lengths */

/* Print each cipher's key, IV and block length **as the engine reports
 * them**, for the Python generator to build its command lines from.
 *
 * This exists because `openssl enc` **zero-extends a short `-iv`
 * silently**: a four byte IV given to a cipher that wants eight
 * produces a perfectly good vector for a different IV, and nothing
 * says so. Guessing the length from the cipher's name gets CTR wrong -
 * the engine's CTR modes take half a block, so Kuznyechik-CTR wants
 * eight bytes where Kuznyechik-CBC wants sixteen. Asking is the only
 * way that cannot drift. */
static void report_lengths(void)
{
    static const char *names[] = {
        "gost89", "gost89-cnt", "gost89-cnt-12", "gost89-cbc",
        "kuznyechik-ecb", "kuznyechik-cbc", "kuznyechik-cfb",
        "kuznyechik-ofb", "kuznyechik-ctr", "kuznyechik-ctr-acpkm",
        "magma-ecb", "magma-cbc", "magma-ctr", "magma-ctr-acpkm",
        "kuznyechik-mgm", "magma-mgm",
        "kuznyechik-kexp15", "magma-kexp15",
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        const EVP_CIPHER *cipher = cipher_from_engine(names[i]);
        printf("%s key=%d iv=%d block=%d\n", names[i],
               EVP_CIPHER_get_key_length(cipher),
               EVP_CIPHER_get_iv_length(cipher),
               EVP_CIPHER_get_block_size(cipher));
    }
}

/* -------------------------------------------------------------- TLSTREE */

/* `gost_tlstree`, RFC 9189 section 4.2.4 - also by `dlsym`.
 *
 * Reached this way rather than through EVP because there is no EVP
 * surface for it at all: the engine calls it from inside its record
 * layer. Unlike the CryptoPro key wrap and key meshing, which are also
 * exported and also unverified here, `gost_tlstree` takes only plain
 * types - so it needs none of the engine's private headers, and this
 * program keeps compiling against an installed libcrypto alone.
 *
 * **Only two of the six constant sets.** The engine supports
 * `magma-cbc` and `kuznyechik-cbc`, which are RFC 9189's two TLS 1.2
 * sets; RFC 9367's four TLS 1.3 sets have no entry and return 0. Those
 * stay on the two RFCs' own tables, which `kdf::gost::document_tests`
 * parses.
 *
 * Worth having anyway, because **every mask is all ones at sequence
 * number zero**: a mistyped constant agrees with the world on the first
 * record of a connection and diverges later, which is the failure mode
 * that takes a day. These rows bracket each level's boundary.
 */
typedef int (*tlstree_fn)(int cipher_nid, const unsigned char *in,
                          unsigned char *out, const unsigned char *tlsseq);

static void tlstree_row(tlstree_fn tlstree, const char *cipher_name,
                        uint64_t sequence, unsigned seed)
{
    int nid = OBJ_sn2nid(cipher_name);
    if (nid == NID_undef)
        die("that TLSTREE cipher has no NID");

    unsigned char root[32], out[32], wire[8];
    fill(root, sizeof root, seed);
    /* **The sequence number goes out big endian**, which is RFC 9189's
     * `STR_8`. The same document defines a little-endian `str_8` and
     * uses both, so this is a choice; the engine reads these eight
     * bytes back into a `uint64_t` the other way round and masks with
     * byte-reversed constants, which comes to the same seed. That two
     * implementations reach it by opposite routes is the useful part. */
    for (int i = 0; i < 8; i++)
        wire[i] = (unsigned char)((sequence >> (8 * (7 - i))) & 0xff);

    if (tlstree(nid, root, out, wire) != 1)
        die("gost_tlstree refused - the engine has no constants for that "
            "cipher");

    printf("\n");
    put_hex("Key", root, sizeof root);
    put_hex("Seq", wire, sizeof wire);
    put_hex("Out", out, sizeof out);
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    const char *engines_dir = getenv("OPENSSL_ENGINES");
    if (engines_dir == NULL)
        engines_dir = ".";
    ERR_load_crypto_strings();
    ENGINE_load_builtin_engines();

    gost = ENGINE_by_id("gost");
    if (gost == NULL)
        die("no engine called \"gost\" - is OPENSSL_ENGINES set to the "
            "directory holding gost.so?");
    if (ENGINE_init(gost) != 1)
        die("ENGINE_init");
    /* Required, not tidiness: the MAC path below reads the *default*
     * ASN1 method table to give a key its type, and without this every
     * MAC key is `NID_undef`. The ciphers are still taken from the
     * engine by hand through `cipher_from_engine`. */
    if (ENGINE_set_default(gost, ENGINE_METHOD_ALL) != 1)
        die("ENGINE_set_default");

    if (argc == 2 && strcmp(argv[1], "--lengths") == 0) {
        report_lengths();
        ENGINE_finish(gost);
        ENGINE_free(gost);
        return 0;
    }
    if (argc != 1)
        die("usage: gost_engine_probe [--lengths]");

    check_the_macs_are_the_ciphers_own();

    printf("# The sections below come from scripts/gost_engine_probe.c,\n"
           "# which reaches what the openssl command line cannot. See\n"
           "# that file for why the MACs in particular are not taken\n"
           "# from `openssl dgst -mac`.\n");

    /* MGM. The lengths are chosen for what each is the only one to
     * reach: an empty message with associated data and the reverse
     * (the two halves of the tag, separately), a message that is not a
     * whole number of blocks, and one long enough that the counters
     * have stepped many times. Both empty at once is refused by the
     * mode and is not offered - RFC 9058 section 6. */
    static const struct { size_t ad, msg; } mgm_lengths[] = {
        { 0, 16 }, { 16, 0 }, { 16, 16 }, { 1, 1 }, { 13, 37 },
        { 32, 64 }, { 7, 129 }, { 64, 255 }, { 0, 1023 }, { 100, 1000 },
    };
    const size_t mgm_rows = sizeof mgm_lengths / sizeof mgm_lengths[0];

    printf("\n[kuznyechik-mgm]\n");
    for (size_t i = 0; i < mgm_rows; i++)
        mgm_row("kuznyechik-mgm", 32, 16,
                mgm_lengths[i].ad, mgm_lengths[i].msg, (unsigned)i);

    printf("\n[magma-mgm]\n");
    for (size_t i = 0; i < mgm_rows; i++)
        mgm_row("magma-mgm", 32, 8,
                mgm_lengths[i].ad, mgm_lengths[i].msg, (unsigned)(i + 50));

    /* OMAC. Zero and a whole block matter because CMAC pads the empty
     * message - so it uses K2, where an exact block uses K1 - and both
     * mistakes give a MAC that is self-consistent. */
    static const size_t omac_lengths[] = {
        0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 1000,
    };
    const size_t omac_rows = sizeof omac_lengths / sizeof omac_lengths[0];

    static const char *macs[] = {
        "kuznyechik-mac", "magma-mac", "gost-mac", "gost-mac-12",
    };
    /* **The message seed is the row index alone**, so all four MAC
     * sections are over the same messages. That is what lets
     * `test_the_two_omacs_are_different_ciphers` compare them: the
     * command line prints the same bytes for `kuznyechik-mac` and
     * `magma-mac`, and two sections over *different* messages could
     * not tell that apart from two ciphers disagreeing. The key still
     * varies per section so the rows are not otherwise identical. */
    for (size_t m = 0; m < sizeof macs / sizeof macs[0]; m++) {
        printf("\n[%s]\n", macs[m]);
        for (size_t i = 0; i < omac_rows; i++)
            omac_row(macs[m], 32, omac_lengths[i],
                     (unsigned)(m * 100 + i), (unsigned)i);
    }

    /* KExp15. The material is a 256 bit key and a 512 bit one, which
     * are the two things anybody wraps with it. */
    /* The key is **two** keys - KExp15 runs OMAC under one half and
     * CTR under the other - and the IV is half a block, which is what
     * `--lengths` reports and not what the name suggests. */
    kexp15_fn kexp15 = (kexp15_fn)engine_symbol(engines_dir, "gost_kexp15");

    printf("\n[kuznyechik-kexp15]\n");
    kexp15_row(kexp15, "kuznyechik-ctr", "kuznyechik-mac", 8, 32, 200);
    kexp15_row(kexp15, "kuznyechik-ctr", "kuznyechik-mac", 8, 64, 201);

    printf("\n[magma-kexp15]\n");
    kexp15_row(kexp15, "magma-ctr", "magma-mac", 4, 32, 210);
    kexp15_row(kexp15, "magma-ctr", "magma-mac", 4, 64, 211);

    /* TLSTREE. The sequence numbers bracket every level boundary for
     * both suites: Kuznyechik re-keys level 3 every 2^6 records, level 2
     * every 2^19 and level 1 every 2^32; Magma's are 2^12, 2^25 and
     * 2^38, because a 64 bit block wears out faster and it re-keys the
     * lower levels more often and the top one less. Zero is here
     * because every mask is all ones there and every constant set
     * agrees - a row nothing else can fail on, and the reason the
     * others are needed. */
    tlstree_fn tlstree = (tlstree_fn)engine_symbol(engines_dir,
                                                   "gost_tlstree");
    static const uint64_t sequences[] = {
        0, 1, 63, 64, 65, 4095, 4096, 4097,
        (1ULL << 19) - 1, 1ULL << 19, (1ULL << 25) - 1, 1ULL << 25,
        (1ULL << 32) - 1, 1ULL << 32, (1ULL << 38) - 1, 1ULL << 38,
        0x0123456789abcdefULL,
    };
    const size_t tlstree_rows = sizeof sequences / sizeof sequences[0];

    printf("\n[tlstree-kuznyechik]\n");
    for (size_t i = 0; i < tlstree_rows; i++)
        tlstree_row(tlstree, "kuznyechik-cbc", sequences[i], (unsigned)i);

    printf("\n[tlstree-magma]\n");
    for (size_t i = 0; i < tlstree_rows; i++)
        tlstree_row(tlstree, "magma-cbc", sequences[i], (unsigned)(i + 70));

    ENGINE_finish(gost);
    ENGINE_free(gost);
    return 0;
}
