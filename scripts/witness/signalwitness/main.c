/*
 * A witness for the Signal example: libsignal-protocol-c, driven one line
 * at a time over standard input. Development tool only; see
 * docs/building.md for the build line.
 *
 *     signalwitness SEED REGISTRATION_ID NAME PEER
 *
 * SEED is hex. Every random byte the library asks for comes from the
 * stream SHA-256(SEED || 0) || SHA-256(SEED || 1) || ..., the counter
 * eight bytes big endian, so a run is reproducible and an implementation
 * that draws the same amounts in the same order produces the same bytes.
 * The identity key is the first 32 bytes of that stream.
 *
 * Commands, one per line, all binary values in hex:
 *
 *     identity                      -> identity PUB
 *     prekeys PREKEY_ID SPK_ID      -> bundle REGID DEVICE PREKEY_ID PREKEY SPK_ID SPK SIG IDENTITY
 *     process REGID DEVICE PREKEY_ID|- PREKEY|- SPK_ID SPK SIG IDENTITY -> ok
 *     encrypt PLAINTEXT             -> message TYPE BYTES
 *     decrypt TYPE BYTES            -> plaintext BYTES
 *     group-create GROUP            -> distribution BYTES
 *     group-process GROUP BYTES     -> ok
 *     group-encrypt GROUP PLAINTEXT -> message 4 BYTES
 *     group-decrypt GROUP BYTES     -> plaintext BYTES
 *     sign PRIVATE MESSAGE RANDOM   -> signature BYTES     (curve25519_sign)
 *     xsign PRIVATE MESSAGE RANDOM  -> signature BYTES     (xed25519_sign)
 *     verify PUBLIC MESSAGE SIG     -> verified 0|1        (curve25519_verify)
 *     xverify PUBLIC MESSAGE SIG    -> verified 0|1        (xed25519_verify)
 *
 * A failure prints "error CODE" with libsignal's negative code and the
 * process carries on, so a check can confirm a refusal and continue.
 * PUBLIC in sign/verify is the bare 32-byte Montgomery u; everywhere
 * else a public key is libsignal's 33-byte form with the 0x05 prefix.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "signal_protocol.h"
#include "curve.h"
#include "key_helper.h"
#include "session_builder.h"
#include "session_cipher.h"
#include "session_pre_key.h"
#include "group_cipher.h"
#include "group_session_builder.h"
#include "protocol.h"
#include "ratchet.h"
#include "test_common.h"
#include "curve25519/ed25519/additions/curve_sigs.h"
#include "curve25519/ed25519/additions/xeddsa.h"

/* ------------------------------------------------------- random stream -- */

static uint8_t seed[64];
static size_t seed_len;
static uint64_t block_counter;
static uint8_t block[32];
static size_t block_used = 32;

int test_random_generator(uint8_t *data, size_t len, void *user_data)
{
    (void)user_data;
    for(size_t i = 0; i < len; i++) {
        if(block_used == 32) {
            uint8_t input[72];
            memcpy(input, seed, seed_len);
            for(int b = 0; b < 8; b++) {
                input[seed_len + b] = (uint8_t)(block_counter >> (56 - 8 * b));
            }
            SHA256(input, seed_len + 8, block);
            block_counter++;
            block_used = 0;
        }
        data[i] = block[block_used++];
    }
    return 0;
}

/* ------------------------------------------------------------- hex I/O -- */

static int unhex(const char *text, uint8_t **out, size_t *out_len)
{
    size_t n = strlen(text);
    if(n % 2) return -1;
    uint8_t *bytes = malloc(n / 2 + 1);
    for(size_t i = 0; i < n / 2; i++) {
        unsigned int v;
        if(sscanf(text + 2 * i, "%2x", &v) != 1) { free(bytes); return -1; }
        bytes[i] = (uint8_t)v;
    }
    *out = bytes;
    *out_len = n / 2;
    return 0;
}

static void put_hex(const uint8_t *data, size_t len)
{
    for(size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

static void put_buffer(signal_buffer *buffer)
{
    put_hex(signal_buffer_data(buffer), signal_buffer_len(buffer));
}

static void put_key(ec_public_key *key)
{
    signal_buffer *buffer = 0;
    ec_public_key_serialize(&buffer, key);
    put_buffer(buffer);
    signal_buffer_free(buffer);
}

/* ------------------------------------------------------ identity store -- */

static signal_buffer *identity_public;
static signal_buffer *identity_private;
static uint32_t registration_id;
static signal_buffer *trusted_peer;

static int get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data)
{
    (void)user_data;
    *public_data = signal_buffer_copy(identity_public);
    *private_data = signal_buffer_copy(identity_private);
    return 0;
}

static int get_local_registration_id(void *user_data, uint32_t *id)
{
    (void)user_data;
    *id = registration_id;
    return 0;
}

static int save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    (void)address; (void)user_data;
    signal_buffer_free(trusted_peer);
    trusted_peer = signal_buffer_create(key_data, key_len);
    return 0;
}

static int is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    (void)address; (void)user_data;
    if(!trusted_peer) return 1;
    return signal_buffer_len(trusted_peer) == key_len
        && memcmp(signal_buffer_data(trusted_peer), key_data, key_len) == 0;
}

/* ---------------------------------------------------------------- main -- */

int main(int argc, char **argv)
{
    if(argc != 5) {
        fprintf(stderr, "usage: signalwitness SEED REGISTRATION_ID NAME PEER\n");
        return 2;
    }
    uint8_t *seed_bytes;
    if(unhex(argv[1], &seed_bytes, &seed_len) || seed_len > sizeof(seed)) {
        fprintf(stderr, "SEED must be at most 64 bytes of hex\n");
        return 2;
    }
    memcpy(seed, seed_bytes, seed_len);
    free(seed_bytes);
    registration_id = (uint32_t)strtoul(argv[2], 0, 10);
    const char *name = argv[3];
    const char *peer = argv[4];

    signal_context *context;
    signal_context_create(&context, 0);
    setup_test_crypto_provider(context);

    ec_key_pair *identity;
    curve_generate_key_pair(context, &identity);
    ec_public_key_serialize(&identity_public, ec_key_pair_get_public(identity));
    ec_private_key_serialize(&identity_private, ec_key_pair_get_private(identity));
    ratchet_identity_key_pair *identity_pair;
    ratchet_identity_key_pair_create(&identity_pair,
            ec_key_pair_get_public(identity), ec_key_pair_get_private(identity));

    signal_protocol_store_context *store;
    signal_protocol_store_context_create(&store, context);
    setup_test_session_store(store);
    setup_test_pre_key_store(store);
    setup_test_signed_pre_key_store(store);
    setup_test_sender_key_store(store, context);
    signal_protocol_identity_key_store identity_store = {
        .get_identity_key_pair = get_identity_key_pair,
        .get_local_registration_id = get_local_registration_id,
        .save_identity = save_identity,
        .is_trusted_identity = is_trusted_identity,
        .destroy_func = 0,
        .user_data = 0
    };
    signal_protocol_store_context_set_identity_key_store(store, &identity_store);

    signal_protocol_address peer_address = { peer, strlen(peer), 1 };
    signal_protocol_address own_address = { name, strlen(name), 1 };

    char line[1 << 17];
    while(fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        char *words[12];
        int count = 0;
        for(char *word = strtok(line, " "); word && count < 12; word = strtok(0, " ")) {
            words[count++] = word;
        }
        if(count == 0) continue;
        const char *command = words[0];
        int result = 0;

        if(!strcmp(command, "identity")) {
            printf("identity ");
            put_key(ec_key_pair_get_public(identity));
            printf("\n");
        }
        else if(!strcmp(command, "prekeys") && count == 3) {
            uint32_t pre_key_id = (uint32_t)strtoul(words[1], 0, 10);
            uint32_t signed_id = (uint32_t)strtoul(words[2], 0, 10);
            signal_protocol_key_helper_pre_key_list_node *head = 0;
            result = signal_protocol_key_helper_generate_pre_keys(&head, pre_key_id, 1, context);
            session_signed_pre_key *signed_pre_key = 0;
            if(result >= 0) {
                result = signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key,
                        identity_pair, signed_id, 0, context);
            }
            if(result >= 0) {
                session_pre_key *pre_key = signal_protocol_key_helper_key_list_element(head);
                signal_protocol_pre_key_store_key(store, pre_key);
                signal_protocol_signed_pre_key_store_key(store, signed_pre_key);
                printf("bundle %u 1 %u ", registration_id, session_pre_key_get_id(pre_key));
                put_key(ec_key_pair_get_public(session_pre_key_get_key_pair(pre_key)));
                printf(" %u ", signed_id);
                put_key(ec_key_pair_get_public(session_signed_pre_key_get_key_pair(signed_pre_key)));
                printf(" ");
                put_hex(session_signed_pre_key_get_signature(signed_pre_key),
                        session_signed_pre_key_get_signature_len(signed_pre_key));
                printf(" ");
                put_key(ec_key_pair_get_public(identity));
                printf("\n");
                signal_protocol_key_helper_key_list_free(head);
                SIGNAL_UNREF(signed_pre_key);
            }
        }
        else if(!strcmp(command, "process") && count == 9) {
            uint8_t *raw[4]; size_t raw_len[4];
            const char *fields[4] = { words[4], words[6], words[7], words[8] };
            int has_pre_key = strcmp(words[3], "-") != 0;
            for(int i = 0; i < 4; i++) {
                raw[i] = 0;
                raw_len[i] = 0;
                if(strcmp(fields[i], "-") && unhex(fields[i], &raw[i], &raw_len[i])) result = SG_ERR_INVAL;
            }
            ec_public_key *pre_key = 0, *signed_key = 0, *identity_key = 0;
            if(result >= 0 && has_pre_key) result = curve_decode_point(&pre_key, raw[0], raw_len[0], context);
            if(result >= 0) result = curve_decode_point(&signed_key, raw[1], raw_len[1], context);
            if(result >= 0) result = curve_decode_point(&identity_key, raw[3], raw_len[3], context);
            session_pre_key_bundle *bundle = 0;
            if(result >= 0) {
                result = session_pre_key_bundle_create(&bundle,
                        (uint32_t)strtoul(words[1], 0, 10), atoi(words[2]),
                        has_pre_key ? (uint32_t)strtoul(words[3], 0, 10) : 0, pre_key,
                        (uint32_t)strtoul(words[5], 0, 10), signed_key,
                        raw[2], raw_len[2], identity_key);
            }
            if(result >= 0) {
                session_builder *builder;
                session_builder_create(&builder, store, &peer_address, context);
                result = session_builder_process_pre_key_bundle(builder, bundle);
                session_builder_free(builder);
            }
            if(result >= 0) printf("ok\n");
            SIGNAL_UNREF(bundle);
            SIGNAL_UNREF(pre_key);
            SIGNAL_UNREF(signed_key);
            SIGNAL_UNREF(identity_key);
            for(int i = 0; i < 4; i++) free(raw[i]);
        }
        else if(!strcmp(command, "encrypt") && count == 2) {
            uint8_t *plaintext; size_t plaintext_len;
            if(unhex(words[1], &plaintext, &plaintext_len)) { result = SG_ERR_INVAL; }
            else {
                session_cipher *cipher;
                ciphertext_message *message = 0;
                session_cipher_create(&cipher, store, &peer_address, context);
                result = session_cipher_encrypt(cipher, plaintext, plaintext_len, &message);
                if(result >= 0) {
                    printf("message %d ", ciphertext_message_get_type(message));
                    put_buffer(ciphertext_message_get_serialized(message));
                    printf("\n");
                }
                SIGNAL_UNREF(message);
                session_cipher_free(cipher);
                free(plaintext);
            }
        }
        else if(!strcmp(command, "decrypt") && count == 3) {
            uint8_t *bytes; size_t bytes_len;
            if(unhex(words[2], &bytes, &bytes_len)) { result = SG_ERR_INVAL; }
            else {
                session_cipher *cipher;
                signal_buffer *plaintext = 0;
                session_cipher_create(&cipher, store, &peer_address, context);
                if(atoi(words[1]) == CIPHERTEXT_PREKEY_TYPE) {
                    pre_key_signal_message *message = 0;
                    result = pre_key_signal_message_deserialize(&message, bytes, bytes_len, context);
                    if(result >= 0) result = session_cipher_decrypt_pre_key_signal_message(cipher, message, 0, &plaintext);
                    SIGNAL_UNREF(message);
                }
                else {
                    signal_message *message = 0;
                    result = signal_message_deserialize(&message, bytes, bytes_len, context);
                    if(result >= 0) result = session_cipher_decrypt_signal_message(cipher, message, 0, &plaintext);
                    SIGNAL_UNREF(message);
                }
                if(result >= 0) {
                    printf("plaintext ");
                    put_buffer(plaintext);
                    printf("\n");
                }
                signal_buffer_free(plaintext);
                session_cipher_free(cipher);
                free(bytes);
            }
        }
        else if(!strcmp(command, "group-create") && count == 2) {
            signal_protocol_sender_key_name key_name = { words[1], strlen(words[1]), own_address };
            group_session_builder *builder;
            sender_key_distribution_message *message = 0;
            group_session_builder_create(&builder, store, context);
            result = group_session_builder_create_session(builder, &message, &key_name);
            if(result >= 0) {
                printf("distribution ");
                put_buffer(ciphertext_message_get_serialized((ciphertext_message *)message));
                printf("\n");
            }
            SIGNAL_UNREF(message);
            group_session_builder_free(builder);
        }
        else if(!strcmp(command, "group-process") && count == 3) {
            signal_protocol_sender_key_name key_name = { words[1], strlen(words[1]), peer_address };
            uint8_t *bytes; size_t bytes_len;
            if(unhex(words[2], &bytes, &bytes_len)) { result = SG_ERR_INVAL; }
            else {
                sender_key_distribution_message *message = 0;
                result = sender_key_distribution_message_deserialize(&message, bytes, bytes_len, context);
                if(result >= 0) {
                    group_session_builder *builder;
                    group_session_builder_create(&builder, store, context);
                    result = group_session_builder_process_session(builder, &key_name, message);
                    group_session_builder_free(builder);
                }
                if(result >= 0) printf("ok\n");
                SIGNAL_UNREF(message);
                free(bytes);
            }
        }
        else if(!strcmp(command, "group-encrypt") && count == 3) {
            signal_protocol_sender_key_name key_name = { words[1], strlen(words[1]), own_address };
            uint8_t *plaintext; size_t plaintext_len;
            if(unhex(words[2], &plaintext, &plaintext_len)) { result = SG_ERR_INVAL; }
            else {
                group_cipher *cipher;
                ciphertext_message *message = 0;
                group_cipher_create(&cipher, store, &key_name, context);
                result = group_cipher_encrypt(cipher, plaintext, plaintext_len, &message);
                if(result >= 0) {
                    printf("message %d ", ciphertext_message_get_type(message));
                    put_buffer(ciphertext_message_get_serialized(message));
                    printf("\n");
                }
                SIGNAL_UNREF(message);
                group_cipher_free(cipher);
                free(plaintext);
            }
        }
        else if(!strcmp(command, "group-decrypt") && count == 3) {
            signal_protocol_sender_key_name key_name = { words[1], strlen(words[1]), peer_address };
            uint8_t *bytes; size_t bytes_len;
            if(unhex(words[2], &bytes, &bytes_len)) { result = SG_ERR_INVAL; }
            else {
                sender_key_message *message = 0;
                signal_buffer *plaintext = 0;
                result = sender_key_message_deserialize(&message, bytes, bytes_len, context);
                if(result >= 0) {
                    group_cipher *cipher;
                    group_cipher_create(&cipher, store, &key_name, context);
                    result = group_cipher_decrypt(cipher, message, 0, &plaintext);
                    group_cipher_free(cipher);
                }
                if(result >= 0) {
                    printf("plaintext ");
                    put_buffer(plaintext);
                    printf("\n");
                }
                signal_buffer_free(plaintext);
                SIGNAL_UNREF(message);
                free(bytes);
            }
        }
        else if((!strcmp(command, "sign") || !strcmp(command, "xsign")) && count == 4) {
            uint8_t *key, *message, *random; size_t key_len, message_len, random_len;
            if(unhex(words[1], &key, &key_len) || unhex(words[2], &message, &message_len)
                    || unhex(words[3], &random, &random_len) || key_len != 32 || random_len != 64) {
                result = SG_ERR_INVAL;
            }
            else {
                uint8_t signature[64];
                if(!strcmp(command, "sign")) result = curve25519_sign(signature, key, message, message_len, random);
                else result = xed25519_sign(signature, key, message, message_len, random);
                if(result == 0) {
                    printf("signature ");
                    put_hex(signature, 64);
                    printf("\n");
                }
                free(key); free(message); free(random);
            }
        }
        else if((!strcmp(command, "verify") || !strcmp(command, "xverify")) && count == 4) {
            uint8_t *key, *message, *signature; size_t key_len, message_len, signature_len;
            if(unhex(words[1], &key, &key_len) || unhex(words[2], &message, &message_len)
                    || unhex(words[3], &signature, &signature_len) || key_len != 32 || signature_len != 64) {
                result = SG_ERR_INVAL;
            }
            else {
                int verified;
                if(!strcmp(command, "verify")) verified = curve25519_verify(signature, key, message, message_len) == 0;
                else verified = xed25519_verify(signature, key, message, message_len) == 0;
                printf("verified %d\n", verified);
                free(key); free(message); free(signature);
            }
        }
        else {
            result = SG_ERR_INVAL;
        }

        if(result < 0) printf("error %d\n", result);
        fflush(stdout);
    }
    return 0;
}
