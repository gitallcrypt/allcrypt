"""GCM and CCM over the other 128 bit ciphers, and named tag lengths.

OpenSSL offers GCM and CCM over AES alone through python-cryptography,
so for Camellia, SM4 and ARIA the reference is GCM and CCM written here
from SP 800-38D and RFC 3610 over a raw block function. That reference
is first required to agree with python-cryptography's AES-GCM and
AES-CCM at every tag length they take, so it cannot be wrong in a way
those would not notice. Its block functions are python-cryptography's
Camellia and SM4; ARIA, which python-cryptography lacks, is this
library's own ECB, so for ARIA only the mode is under test. The SM4 rows
are also checked against RFC 8998's worked examples in
`tests/test_rfc8998.rs`.
"""

import os

import pytest

import allcrypt

cryptography = pytest.importorskip("cryptography")
from cryptography.exceptions import InvalidTag                    # noqa: E402
from cryptography.hazmat.primitives.ciphers import (              # noqa: E402
    Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import (         # noqa: E402
    AESCCM, AESGCM)


def block_function(name, key):
    if name == "aria":
        cipher = allcrypt.Cipher("aria", key)
        # Whatever ECB does about padding, its first block is E(block).
        return lambda block: cipher.encrypt("ecb", block)[:16]
    algorithm = {"aes": algorithms.AES, "camellia": algorithms.Camellia,
                 "sm4": algorithms.SM4}[name](key)
    encryptor = Cipher(algorithm, modes.ECB()).encryptor()
    return encryptor.update


# ------------------------------------------------- reference, SP 800-38D ---

def _gf_mul(x, y):
    """GF(2^128) under GCM's bit order: bit 0 is the most significant."""
    r = 0xe1 << 120
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def _pad16(data):
    return data + bytes(-len(data) % 16)


def reference_gcm(encrypt_block, nonce, aad, plaintext, tag_len):
    h = int.from_bytes(encrypt_block(bytes(16)), "big")
    if len(nonce) == 12:
        j0 = nonce + b"\x00\x00\x00\x01"
    else:
        j0 = _ghash(h, _pad16(nonce) + bytes(8)
                    + (8 * len(nonce)).to_bytes(8, "big")).to_bytes(16, "big")
    counter = int.from_bytes(j0[12:], "big")
    ciphertext = bytearray()
    for i in range(0, len(plaintext), 16):
        counter = (counter + 1) % 2**32
        stream = encrypt_block(j0[:12] + counter.to_bytes(4, "big"))
        ciphertext += bytes(a ^ b for a, b in zip(plaintext[i:i + 16], stream))
    s = _ghash(h, _pad16(aad) + _pad16(bytes(ciphertext))
               + (8 * len(aad)).to_bytes(8, "big")
               + (8 * len(ciphertext)).to_bytes(8, "big"))
    tag = (s ^ int.from_bytes(encrypt_block(j0), "big")).to_bytes(16, "big")
    return bytes(ciphertext), tag[:tag_len]


# ---------------------------------------------------- reference, RFC 3610 ---

def reference_ccm(encrypt_block, nonce, aad, plaintext, tag_len):
    q = 15 - len(nonce)
    flags = (0x40 if aad else 0) | ((tag_len - 2) // 2) << 3 | (q - 1)
    b = bytes([flags]) + nonce + len(plaintext).to_bytes(q, "big")
    if aad:
        if len(aad) < 0xff00:
            header = len(aad).to_bytes(2, "big")
        else:
            header = b"\xff\xfe" + len(aad).to_bytes(4, "big")
        b += _pad16(header + aad)
    b += _pad16(plaintext)
    x = bytes(16)
    for i in range(0, len(b), 16):
        x = encrypt_block(bytes(a ^ c for a, c in zip(x, b[i:i + 16])))

    def counter_block(i):
        return bytes([q - 1]) + nonce + i.to_bytes(q, "big")
    ciphertext = bytearray()
    for i in range(0, len(plaintext), 16):
        stream = encrypt_block(counter_block(i // 16 + 1))
        ciphertext += bytes(a ^ c for a, c in zip(plaintext[i:i + 16], stream))
    s0 = encrypt_block(counter_block(0))
    return bytes(ciphertext), bytes(a ^ c for a, c in zip(x[:tag_len], s0))


GCM_TAGS = [4, 8, 12, 13, 14, 15, 16]
CCM_TAGS = [4, 6, 8, 10, 12, 14, 16]
LENGTHS = [0, 1, 15, 16, 17, 33, 100]


@pytest.mark.parametrize("tag_len", GCM_TAGS)
@pytest.mark.parametrize("nonce_len", [12, 8, 16])
def test_the_gcm_reference_is_openssls(tag_len, nonce_len):
    for length in LENGTHS:
        key, nonce = os.urandom(16), os.urandom(nonce_len)
        aad, message = os.urandom(length % 23), os.urandom(length)
        theirs = AESGCM(key).encrypt(nonce, message, aad)
        ciphertext, tag = reference_gcm(block_function("aes", key), nonce, aad,
                                        message, tag_len)
        assert ciphertext == theirs[:-16]
        assert tag == theirs[-16:][:tag_len]


@pytest.mark.parametrize("tag_len", CCM_TAGS)
def test_the_ccm_reference_is_openssls(tag_len):
    for length in LENGTHS:
        key, nonce = os.urandom(16), os.urandom(7 + length % 7)
        aad, message = os.urandom(length % 23), os.urandom(length)
        theirs = AESCCM(key, tag_length=tag_len).encrypt(nonce, message, aad)
        ciphertext, tag = reference_ccm(block_function("aes", key), nonce, aad,
                                        message, tag_len)
        assert ciphertext + tag == theirs


CIPHERS = [("camellia", [16, 24, 32]), ("sm4", [16]), ("aria", [16, 24, 32])]


@pytest.mark.parametrize("cipher,key_sizes", CIPHERS, ids=[c for c, _ in CIPHERS])
@pytest.mark.parametrize("tag_len", [None] + GCM_TAGS)
def test_gcm_over_other_ciphers(cipher, key_sizes, tag_len):
    name = f"{cipher}-gcm" + (f"-{tag_len}" if tag_len else "")
    for key_size in key_sizes:
        for length in LENGTHS:
            key = os.urandom(key_size)
            nonce = os.urandom(12 if length % 3 else 1 + length % 20)
            aad, message = os.urandom(length % 19), os.urandom(length)
            ours = allcrypt.Aead(key, name).encrypt(nonce, message, aad)
            ciphertext, tag = reference_gcm(block_function(cipher, key), nonce, aad,
                                            message, tag_len or 16)
            assert ours == ciphertext + tag, (name, key_size, length)
            assert allcrypt.Aead(key, name).decrypt(nonce, ours, aad) == message


@pytest.mark.parametrize("cipher,key_sizes", CIPHERS, ids=[c for c, _ in CIPHERS])
@pytest.mark.parametrize("tag_len", [None] + CCM_TAGS)
def test_ccm_over_other_ciphers(cipher, key_sizes, tag_len):
    name = f"{cipher}-ccm" + (f"-{tag_len}" if tag_len else "")
    for key_size in key_sizes:
        for length in LENGTHS:
            key = os.urandom(key_size)
            nonce = os.urandom(7 + length % 7)
            aad, message = os.urandom(length % 19), os.urandom(length)
            ours = allcrypt.Aead(key, name).encrypt(nonce, message, aad)
            ciphertext, tag = reference_ccm(block_function(cipher, key), nonce, aad,
                                            message, tag_len or 16)
            assert ours == ciphertext + tag, (name, key_size, length)
            assert allcrypt.Aead(key, name).decrypt(nonce, ours, aad) == message


@pytest.mark.parametrize("tag_len", GCM_TAGS)
def test_aes_gcm_with_a_named_tag_length_against_openssl(tag_len):
    """OpenSSL's GCM decryption takes a truncated tag when told the
    shortest it may accept; its encryption gives the full tag, of which
    ours is the prefix."""
    key, nonce = os.urandom(32), os.urandom(12)
    message, aad = os.urandom(50), b"header"
    name = f"aes-gcm-{tag_len}"
    ours = allcrypt.Aead(key, name).encrypt(nonce, message, aad)
    full = AESGCM(key).encrypt(nonce, message, aad)
    assert ours == full[:len(message) + tag_len]

    decryptor = Cipher(algorithms.AES(key),
                       modes.GCM(nonce, ours[-tag_len:], min_tag_length=4)).decryptor()
    decryptor.authenticate_additional_data(aad)
    assert decryptor.update(ours[:-tag_len]) + decryptor.finalize() == message

    assert allcrypt.Aead(key, name).decrypt(nonce, full[:len(message) + tag_len],
                                            aad) == message


@pytest.mark.parametrize("tag_len", CCM_TAGS)
def test_aes_ccm_with_a_named_tag_length_against_openssl(tag_len):
    key, nonce = os.urandom(16), os.urandom(13)
    message, aad = os.urandom(40), b"header"
    name = f"aes-ccm-{tag_len}"
    ours = allcrypt.Aead(key, name).encrypt(nonce, message, aad)
    assert ours == AESCCM(key, tag_length=tag_len).encrypt(nonce, message, aad)
    theirs = AESCCM(key, tag_length=tag_len).encrypt(nonce, message, None)
    assert allcrypt.Aead(key, name).decrypt(nonce, theirs) == message
    # Another length's tag is another CCM's, and fails both ways.
    other = 16 if tag_len != 16 else 8
    with pytest.raises(InvalidTag):
        AESCCM(key, tag_length=other).decrypt(nonce, ours[:-tag_len] + bytes(other), aad)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, f"aes-ccm-{other}").decrypt(nonce, ours, aad)


def test_a_named_gcm_tag_length_opens_that_length_only():
    """Unnamed, a GCM tag can be cut to 12 bytes and still open, because
    the length arrives with the message. Named, only that length opens:
    `aes-gcm-12` given 16 bytes of tag reads the last four as
    ciphertext, and fails."""
    key, nonce = os.urandom(16), os.urandom(12)
    full = allcrypt.Aead(key, "aes-gcm").encrypt(nonce, b"m" * 20)
    assert allcrypt.Aead(key, "aes-gcm-12").decrypt(nonce, full[:-4]) == b"m" * 20
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, "aes-gcm-12").decrypt(nonce, full)

    stream = allcrypt.Aead(key, "aes-gcm-8").decryptor(nonce)
    stream.update(full[:20])
    with pytest.raises(allcrypt.CryptoError):
        stream.verify(full[20:])


@pytest.mark.parametrize("name", ["aes-gcm-5", "aes-gcm-17", "aes-ccm-7", "aes-ccm-2",
                                  "aes-eax-0", "aes-ocb-17", "aes-mgm-3",
                                  "des-gcm", "kalyna-128-gcm-7", "kalyna-128-ccm-12",
                                  "chacha20-poly1305-8"])
def test_a_tag_length_a_mode_does_not_have_is_refused(name):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(bytes(16 if not name.startswith("des") else 8), name)


@pytest.mark.parametrize("name,key_len,nonce,tag_len",
                         [("aes-eax-8", 16, bytes(12), 8), ("des-eax-4", 8, bytes(12), 4),
                          ("aes-ocb-12", 16, bytes(12), 12), ("aes-mgm-8", 16, bytes(16), 8),
                          ("magma-mgm-4", 32, bytes(8), 4)])
def test_eax_ocb_and_mgm_take_a_named_tag_length(name, key_len, nonce, tag_len):
    """EAX's and MGM's short tag is the full tag's prefix. OCB's is not,
    and neither is its ciphertext: RFC 7253 writes the tag length into
    the nonce block every offset comes from, and its own 96-bit vectors
    in the Rust tests are what check that."""
    key = bytes(range(key_len))
    full_name = name.rsplit("-", 1)[0]
    ours = allcrypt.Aead(key, name).encrypt(nonce, b"message!", b"hdr")
    full = allcrypt.Aead(key, full_name).encrypt(nonce, b"message!", b"hdr")
    assert len(ours) == 8 + tag_len
    if "-ocb" in name:
        assert ours[:8] != full[:8]
        assert ours[8:] != full[8:8 + tag_len]
    else:
        assert ours == full[:8 + tag_len]
    assert allcrypt.Aead(key, name).decrypt(nonce, ours, b"hdr") == b"message!"
