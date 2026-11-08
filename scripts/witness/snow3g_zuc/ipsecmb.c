/* Intel's intel-ipsec-mb 2.0.3 under driver.h: the direct functions for
 * KASUMI's UEA1 and UIA1 (IMB_KASUMI_F8_1_BUFFER_BIT,
 * IMB_KASUMI_F9_1_BUFFER_USER, with kasumi_f8_iv_gen and kasumi_f9_iv_gen),
 * SNOW 3G (IMB_SNOW3G_F8_1_BUFFER_BIT, IMB_SNOW3G_F9_1_BUFFER) and 128-EEA3
 * and 128-EIA3 (IMB_ZUC_EEA3_1_BUFFER, IMB_ZUC_EIA3_1_BUFFER), the job API
 * for ZUC-256, and the library's own snow3g_f8_iv_gen, snow3g_f9_iv_gen,
 * zuc_eea3_iv_gen and zuc_eia3_iv_gen for the mode IVs.
 *
 * The library loads a SNOW 3G key and IV as UEA2 lays them out, the first
 * 32 bits of CK into K3, so the raw keystream's K0..K3 and IV0..IV3 are
 * handed over with their words reversed. ZUC-256's 25 byte IV is handed
 * over as it is, and again packed into 23 bytes, and the two answers must
 * agree. A refusal is reported, never an unwritten output. EEA3 is byte
 * granular here; the driver clears the bits past the
 * length. */
#include "driver.h"
#include <intel-ipsec-mb.h>

static IMB_MGR *mgr;

static IMB_MGR *get_mgr(void) {
    if (!mgr) {
        mgr = alloc_mb_mgr(0);
        init_mb_mgr_auto(mgr, NULL);
    }
    return mgr;
}

/* The direct functions return nothing and report a refusal - an empty
 * message to UIA2 or 128-EIA3 is one - through the library's process-wide
 * error number, leaving the output unwritten. Not every function clears
 * it on success (SNOW 3G's f9 does not), so it is cleared before each
 * call; the variable is the library's own, not in its public header. */
extern volatile int imb_errno;

static void clear_errno(void) {
    imb_errno = 0;
}

static const char *refused(void) {
    return imb_errno ? "error refused" : 0;
}

static void reverse_words(const uint8_t in[16], uint8_t out[16]) {
    for (int i = 0; i < 16; i++) out[i] = in[(3 - i / 4) * 4 + i % 4];
}

static int iv_ok(const uint8_t *iv, size_t ivlen) {
    if (ivlen != 25) return 0;
    for (int i = 17; i < 25; i++)
        if (iv[i] & 0xc0) return 0;
    return 1;
}

static void pack_iv(const uint8_t iv[25], uint8_t out[23]) {
    memcpy(out, iv, 17);
    uint64_t bits = 0;
    for (int i = 17; i < 25; i++) bits = bits << 6 | (iv[i] & 0x3f);
    for (int i = 0; i < 6; i++) out[17 + i] = (uint8_t)(bits >> (40 - 8 * i));
}

static int run_job(IMB_JOB *job) {
    IMB_JOB *done = IMB_SUBMIT_JOB(get_mgr());
    if (!done) done = IMB_FLUSH_JOB(get_mgr());
    return done == job && done->status == IMB_STATUS_COMPLETED;
}

static int zuc256_stream(const uint8_t *key, const uint8_t *iv, uint64_t ivlen, uint8_t *out,
                         size_t n) {
    uint8_t *zero = calloc(n + 1, 1);
    IMB_JOB *job = IMB_GET_NEXT_JOB(get_mgr());
    memset(out, 0, n);
    job->cipher_direction = IMB_DIR_ENCRYPT;
    job->chain_order = IMB_ORDER_CIPHER_HASH;
    job->cipher_mode = IMB_CIPHER_ZUC_EEA3;
    job->hash_alg = IMB_AUTH_NULL;
    job->src = zero;
    job->dst = out;
    job->iv = iv;
    job->iv_len_in_bytes = ivlen;
    job->enc_keys = key;
    job->key_len_in_bytes = 32;
    job->cipher_start_src_offset_in_bytes = 0;
    job->msg_len_to_cipher_in_bytes = n;
    int ok = run_job(job);
    free(zero);
    return ok;
}

static const char *w_stream(const char *cipher, const uint8_t *key, size_t klen,
                            const uint8_t *iv, size_t ivlen, uint8_t *out, size_t n) {
    if (strcmp(cipher, "snow3g") == 0) {
        if (klen != 16 || ivlen != 16) return "error key or iv length";
        uint8_t k[16], v[16];
        snow3g_key_schedule_t ks;
        reverse_words(key, k);
        reverse_words(iv, v);
        if (IMB_SNOW3G_INIT_KEY_SCHED(get_mgr(), k, &ks)) return "error key schedule";
        if (n == 0) return 0;
        uint8_t *zero = calloc(n, 1);
        IMB_SNOW3G_F8_1_BUFFER(get_mgr(), &ks, v, zero, out, n);
        free(zero);
        return 0;
    }
    if (strcmp(cipher, "zuc128") == 0) {
        if (klen != 16 || ivlen != 16) return "error key or iv length";
        if (n == 0) return 0;
        uint8_t *zero = calloc(n, 1);
        IMB_ZUC_EEA3_1_BUFFER(get_mgr(), key, iv, zero, out, (uint32_t)n);
        free(zero);
        return 0;
    }
    if (strcmp(cipher, "zuc256") == 0) {
        if (klen != 32 || !iv_ok(iv, ivlen)) return "error key or iv length";
        if (n == 0) return 0;
        uint8_t packed[23], *other = malloc(n);
        pack_iv(iv, packed);
        int ok = zuc256_stream(key, iv, 25, out, n) && zuc256_stream(key, packed, 23, other, n);
        int same = ok && memcmp(out, other, n) == 0;
        free(other);
        if (!ok) return "error job";
        return same ? 0 : "error the 23 and 25 byte IVs disagree";
    }
    return "error unsupported";
}

static const char *w_f8(const char *alg, const uint8_t *key, uint32_t count, uint32_t bearer,
                        uint32_t dir, uint8_t *data, uint32_t bits) {
    uint8_t iv[16];
    if (bits == 0) return 0;
    if (strcmp(alg, "uea1") == 0) {
        kasumi_key_sched_t *ks = malloc(IMB_KASUMI_KEY_SCHED_SIZE(get_mgr()));
        const char *err = 0;
        uint64_t iv64;
        if (kasumi_f8_iv_gen(count, (uint8_t)bearer, (uint8_t)dir, &iv64)) err = "error iv";
        else if (IMB_KASUMI_INIT_F8_KEY_SCHED(get_mgr(), key, ks)) err = "error key schedule";
        else {
            clear_errno();
            IMB_KASUMI_F8_1_BUFFER_BIT(get_mgr(), ks, iv64, data, data, bits, 0);
            err = refused();
        }
        free(ks);
        return err;
    }
    if (strcmp(alg, "uea2") == 0) {
        snow3g_key_schedule_t ks;
        if (snow3g_f8_iv_gen(count, (uint8_t)bearer, (uint8_t)dir, iv)) return "error iv";
        if (IMB_SNOW3G_INIT_KEY_SCHED(get_mgr(), key, &ks)) return "error key schedule";
        clear_errno();
        IMB_SNOW3G_F8_1_BUFFER_BIT(get_mgr(), &ks, iv, data, data, bits, 0);
        return refused();
    }
    if (strcmp(alg, "eea3") == 0) {
        if (zuc_eea3_iv_gen(count, (uint8_t)bearer, (uint8_t)dir, iv)) return "error iv";
        clear_errno();
        IMB_ZUC_EEA3_1_BUFFER(get_mgr(), key, iv, data, data, (bits + 7) / 8);
        return refused();
    }
    return "error unsupported";
}

static const char *w_f9(const char *alg, const uint8_t *key, uint32_t count, uint32_t fresh,
                        uint32_t dir, const uint8_t *data, uint32_t bits, uint8_t mac[4]) {
    uint8_t iv[16];
    if (strcmp(alg, "uia1") == 0) {
        kasumi_key_sched_t *ks = malloc(IMB_KASUMI_KEY_SCHED_SIZE(get_mgr()));
        const char *err = 0;
        uint64_t iv64;
        if (kasumi_f9_iv_gen(count, fresh, &iv64)) err = "error iv";
        else if (IMB_KASUMI_INIT_F9_KEY_SCHED(get_mgr(), key, ks)) err = "error key schedule";
        else {
            clear_errno();
            IMB_KASUMI_F9_1_BUFFER_USER(get_mgr(), ks, iv64, data, bits, mac, dir);
            err = refused();
        }
        free(ks);
        return err;
    }
    if (strcmp(alg, "uia2") == 0 || strcmp(alg, "eia1") == 0) {
        snow3g_key_schedule_t ks;
        uint32_t value = strcmp(alg, "eia1") == 0 ? fresh << 27 : fresh;
        if (snow3g_f9_iv_gen(count, value, (uint8_t)dir, iv)) return "error iv";
        if (IMB_SNOW3G_INIT_KEY_SCHED(get_mgr(), key, &ks)) return "error key schedule";
        clear_errno();
        IMB_SNOW3G_F9_1_BUFFER(get_mgr(), &ks, iv, data, bits, mac);
        return refused();
    }
    if (strcmp(alg, "eia3") == 0) {
        if (zuc_eia3_iv_gen(count, (uint8_t)fresh, (uint8_t)dir, iv)) return "error iv";
        clear_errno();
        IMB_ZUC_EIA3_1_BUFFER(get_mgr(), key, iv, data, bits, (uint32_t *)mac);
        return refused();
    }
    return "error unsupported";
}

static int zuc256_mac(int tagbits, const uint8_t *key, const uint8_t *iv, int iv23,
                      const uint8_t *data, uint32_t bits, uint8_t *tag) {
    IMB_JOB *job = IMB_GET_NEXT_JOB(get_mgr());
    job->cipher_direction = IMB_DIR_ENCRYPT;
    job->chain_order = IMB_ORDER_CIPHER_HASH;
    job->cipher_mode = IMB_CIPHER_NULL;
    job->hash_alg = IMB_AUTH_ZUC256_EIA3_BITLEN;
    job->src = data;
    job->u.ZUC_EIA3._key = key;
    job->u.ZUC_EIA3._iv = iv23 ? NULL : iv;
    job->u.ZUC_EIA3._iv23 = iv23 ? iv : NULL;
    job->hash_start_src_offset_in_bytes = 0;
    job->msg_len_to_hash_in_bits = bits;
    job->auth_tag_output = tag;
    job->auth_tag_output_len_in_bytes = (uint64_t)tagbits / 8;
    return run_job(job);
}

static const char *w_zucmac(int tagbits, const uint8_t *key, size_t klen, const uint8_t *iv,
                            size_t ivlen, const uint8_t *data, uint32_t bits, uint8_t *tag) {
    if (klen == 16) {
        if (ivlen != 16) return "error iv length";
        if (tagbits != 32) return "error unsupported";
        clear_errno();
        IMB_ZUC_EIA3_1_BUFFER(get_mgr(), key, iv, data, bits, (uint32_t *)tag);
        return refused();
    }
    if (klen != 32 || !iv_ok(iv, ivlen)) return "error key or iv length";
    uint8_t packed[23], other[16];
    pack_iv(iv, packed);
    if (!zuc256_mac(tagbits, key, iv, 0, data, bits, tag) ||
        !zuc256_mac(tagbits, key, packed, 1, data, bits, other))
        return "error job";
    return memcmp(tag, other, (size_t)tagbits / 8) == 0 ? 0 : "error the 23 and 25 byte IVs disagree";
}
