"""The primitives under the AEADs and stream ciphers, reached on their own.

GHASH and GMAC against OpenSSL's AES-GCM; Poly1305 against
python-cryptography's; ChaCha20's starting counter and seeking against
OpenSSL's ChaCha20, which takes the counter as the first four bytes of a
16 byte nonce; HChaCha20 against the worked example in the vendored
XChaCha draft; and the Salsa20 core against Salsa20 written here from
the specification, which is first held to hashlib's scrypt - scrypt's
BlockMix is the Salsa20/8 core and nothing else of Salsa20.
"""

import hashlib
import os
import pathlib
import re
import struct

import pytest

import allcrypt

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.ciphers import (              # noqa: E402
    Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM    # noqa: E402
from cryptography.hazmat.primitives.poly1305 import Poly1305      # noqa: E402

RFCS = pathlib.Path(__file__).resolve().parent.parent / "rfcs"


def aes_block(key, block):
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)


# ------------------------------------------------------------- GHASH, GMAC ---

@pytest.mark.parametrize("aad_len", [0, 1, 15, 16, 17, 64, 100])
def test_ghash_and_an_aes_block_are_openssls_gmac(aad_len):
    """GCM's tag over empty plaintext is GHASH(H, A || lengths) masked
    with E_K(J0). OpenSSL computes the whole tag; GHASH here supplies the
    middle, so a GHASH that is wrong anywhere gives a different tag."""
    key, nonce, aad = os.urandom(16), os.urandom(12), os.urandom(aad_len)
    h = aes_block(key, bytes(16))
    blocks = aad + bytes(-aad_len % 16) + struct.pack(">QQ", 8 * aad_len, 0)
    s = allcrypt.ghash(h, blocks)
    mask = aes_block(key, nonce + b"\x00\x00\x00\x01")
    theirs = AESGCM(key).encrypt(nonce, b"", aad)
    assert bytes(a ^ b for a, b in zip(s, mask)) == theirs
    assert allcrypt.gmac(key, nonce, aad) == theirs


@pytest.mark.parametrize("tag_size", [4, 8, 12, 13, 14, 15, 16])
@pytest.mark.parametrize("nonce_len", [12, 8, 16, 60])
def test_gmac_against_openssl(tag_size, nonce_len):
    for key_len in (16, 24, 32):
        key, nonce = os.urandom(key_len), os.urandom(nonce_len)
        data = os.urandom(nonce_len * 3)
        theirs = AESGCM(key).encrypt(nonce, b"", data)
        assert allcrypt.gmac(key, nonce, data, tag_size=tag_size) == theirs[:tag_size]


def test_gmac_over_another_cipher_is_that_ciphers_gcm():
    key, nonce = os.urandom(16), os.urandom(12)
    assert allcrypt.gmac(key, nonce, b"data", cipher="camellia") == \
        allcrypt.Aead(key, "camellia-gcm").encrypt(nonce, b"", b"data")


def test_ghash_takes_whole_blocks_only():
    with pytest.raises(allcrypt.CryptoError, match="whole 16 byte blocks"):
        allcrypt.ghash(bytes(16), bytes(17))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.ghash(bytes(15), bytes(16))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.gmac(bytes(8), bytes(12), b"", cipher="des")


# ---------------------------------------------------------------- Poly1305 ---

@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 63, 64, 65, 1000])
def test_poly1305_against_cryptography(length):
    for _ in range(5):
        key, message = os.urandom(32), os.urandom(length)
        theirs = Poly1305.generate_tag(key, message)
        assert allcrypt.poly1305(key, message) == theirs
        assert allcrypt.poly1305_verify(key, message, theirs)
        assert not allcrypt.poly1305_verify(key, message, theirs[:-1] + bytes([theirs[-1] ^ 1]))
        assert not allcrypt.poly1305_verify(key, message, theirs[:15])


def test_poly1305_key_edges_against_cryptography():
    """r with every clamped bit set and s at its largest: the clamp and
    the final addition mod 2^128 are where Poly1305 is easy to get wrong."""
    for key in (b"\xff" * 32, bytes(32), bytes(16) + b"\xff" * 16, b"\xff" * 16 + bytes(16)):
        for message in (b"", b"\xff" * 16, b"\xff" * 17, bytes(33)):
            assert allcrypt.poly1305(key, message) == Poly1305.generate_tag(key, message)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.poly1305(bytes(31), b"")


# ---------------------------------------------------- ChaCha20 counter, seek ---

def openssl_chacha(key, nonce, counter, length):
    full_nonce = struct.pack("<I", counter) + nonce
    return Cipher(algorithms.ChaCha20(key, full_nonce), None).encryptor().update(bytes(length))


@pytest.mark.parametrize("counter", [0, 1, 2, 7, 1000, 2**31, 2**32 - 5])
def test_chacha20_starting_counter_against_openssl(counter):
    key, nonce = os.urandom(32), os.urandom(12)
    length = min(300, (2**32 - counter) * 64)
    ours = allcrypt.StreamCipher("chacha20", key, nonce, counter=counter).update(bytes(length))
    assert ours == openssl_chacha(key, nonce, counter, length)


@pytest.mark.parametrize("offset", [0, 1, 63, 64, 65, 1000, 64 * 2**20 + 7])
def test_chacha20_seek_against_openssl(offset):
    key, nonce = os.urandom(32), os.urandom(12)
    stream = allcrypt.StreamCipher("chacha20", key, nonce)
    stream.update(bytes(100))
    stream.seek(offset)
    block, within = divmod(offset, 64)
    assert stream.update(bytes(200)) == openssl_chacha(key, nonce, block, within + 200)[within:]


def test_the_32_bit_counter_ends_and_the_others_cannot_seek():
    key, nonce = os.urandom(32), os.urandom(12)
    last = allcrypt.StreamCipher("chacha20", key, nonce, counter=2**32 - 1)
    assert last.update(bytes(64)) == openssl_chacha(key, nonce, 2**32 - 1, 64)
    with pytest.raises(allcrypt.CryptoError):
        last.update(b"x")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.StreamCipher("chacha20", key, nonce, counter=2**32)
    for name in ("rc4", "zipcrypto"):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.StreamCipher(name, key).seek(0)
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.StreamCipher(name, key, counter=1)


# --------------------------------------------------------------- HChaCha20 ---

def test_hchacha20_against_the_draft():
    """Section 2.2.1's worked example, read out of the document. The key
    runs over two lines and ends at a full stop; the subkey is the two
    lines above its caption."""
    text = (RFCS / "draft-irtf-cfrg-xchacha-03.txt").read_text(encoding="utf-8-sig")
    section = text[text.index("\n2.2.1.  Test Vector for the HChaCha20 Block Function"):]
    key = bytes.fromhex(re.search(r"Key = ([0-9a-f:\s]+?)\.", section).group(1)
                        .replace(":", "").replace(" ", "").replace("\n", ""))
    nonce = bytes.fromhex(re.search(r"Nonce = \(([0-9a-f:]+)\)", section).group(1)
                          .replace(":", ""))
    lines = section[:section.index("Resultant HChaCha20 subkey")].rstrip().splitlines()
    subkey = bytes.fromhex("".join(lines[-2:]).replace(" ", ""))
    assert (len(key), len(nonce), len(subkey)) == (32, 16, 32)
    assert allcrypt.hchacha20(key, nonce) == subkey
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.hchacha20(key, nonce[:15])


# ------------------------------------------------------------ Salsa20 core ---

def _rotl(v, c):
    return ((v << c) | (v >> (32 - c))) & 0xffffffff


def reference_salsa20_core(block, rounds):
    """The Salsa20 core from the specification's quarterround, rowround
    and columnround, written as the specification writes them."""
    x = list(struct.unpack("<16I", block))
    z = x[:]

    def quarter(a, b, c, d):
        z[b] ^= _rotl((z[a] + z[d]) & 0xffffffff, 7)
        z[c] ^= _rotl((z[b] + z[a]) & 0xffffffff, 9)
        z[d] ^= _rotl((z[c] + z[b]) & 0xffffffff, 13)
        z[a] ^= _rotl((z[d] + z[c]) & 0xffffffff, 18)
    for _ in range(rounds // 2):
        quarter(0, 4, 8, 12)
        quarter(5, 9, 13, 1)
        quarter(10, 14, 2, 6)
        quarter(15, 3, 7, 11)
        quarter(0, 1, 2, 3)
        quarter(5, 6, 7, 4)
        quarter(10, 11, 8, 9)
        quarter(15, 12, 13, 14)
    return struct.pack("<16I", *((a + b) & 0xffffffff for a, b in zip(z, x)))


def scrypt_on(core, password, salt, n, r, p, length):
    """RFC 7914's scrypt with the Salsa20/8 core passed in."""
    def block_mix(b):
        x = b[-64:]
        ys = []
        for i in range(2 * r):
            x = core(bytes(a ^ c for a, c in zip(x, b[64 * i:64 * i + 64])), 8)
            ys.append(x)
        return b"".join(ys[0::2] + ys[1::2])

    blocks = hashlib.pbkdf2_hmac("sha256", password, salt, 1, p * 128 * r)
    out = b""
    for i in range(p):
        x = blocks[128 * r * i:128 * r * (i + 1)]
        v = []
        for _ in range(n):
            v.append(x)
            x = block_mix(x)
        for _ in range(n):
            j = struct.unpack("<Q", x[-64:-56])[0] % n
            x = block_mix(bytes(a ^ c for a, c in zip(x, v[j])))
        out += x
    return hashlib.pbkdf2_hmac("sha256", password, out, 1, length)


def test_the_salsa20_reference_is_hashlibs_scrypt():
    for n, r, p in ((2, 1, 1), (4, 2, 2), (16, 1, 3)):
        theirs = hashlib.scrypt(b"password", salt=b"salt", n=n, r=r, p=p, dklen=48)
        assert scrypt_on(reference_salsa20_core, b"password", b"salt", n, r, p, 48) == theirs
        assert scrypt_on(allcrypt.salsa20_core, b"password", b"salt", n, r, p, 48) == theirs


@pytest.mark.parametrize("rounds", [0, 2, 8, 12, 20])
def test_salsa20_core_against_the_reference(rounds):
    for _ in range(20):
        block = os.urandom(64)
        assert allcrypt.salsa20_core(block, rounds) == reference_salsa20_core(block, rounds)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.salsa20_core(bytes(64), 7)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.salsa20_core(bytes(63))


@pytest.mark.parametrize("counter", [0, 1, 2**32 - 1, 2**32, 2**57 + 3, 2**64 - 1])
def test_salsa20_counter_against_the_reference(counter):
    """Salsa20's keystream block is the core on constants, key, nonce and
    a 64 bit counter in words 8 and 9 - so a counter past 32 bits, which
    no stream reaches by running, is checked by building the block."""
    key, nonce = os.urandom(32), os.urandom(8)
    k = struct.unpack("<8I", key)
    sigma = struct.unpack("<4I", b"expand 32-byte k")
    words = [sigma[0], *k[:4], sigma[1], *struct.unpack("<2I", nonce),
             counter & 0xffffffff, counter >> 32, sigma[2], *k[4:], sigma[3]]
    expected = reference_salsa20_core(struct.pack("<16I", *words), 20)
    ours = allcrypt.StreamCipher("salsa20", key, nonce, counter=counter).update(bytes(64))
    assert ours == expected
    if counter * 64 < 2**64:
        stream = allcrypt.StreamCipher("salsa20", key, nonce)
        stream.seek(counter * 64 + 10)
        assert stream.update(bytes(54)) == expected[10:]
