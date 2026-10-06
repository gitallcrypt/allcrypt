"""Tests for the Python bindings.

The Rust suite already proves the algorithms are correct. What is worth
testing here is the binding layer: that the Python API behaves the way a
Python programmer expects, that state carries across calls, and that errors
surface as exceptions rather than wrong bytes.

The hash tests are differential against the standard library, which makes
them a real check of the bindings rather than a restatement of them.

    python3 scripts/build_python.py
    python3 -m pytest
    pytest
"""

import hashlib
import os

import pytest

import allcrypt

# hashlib and allcrypt use the same names, except SHA-0 which hashlib lacks.
HASHLIB_EQUIVALENT = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha512_224": "sha512_224",
    "sha512_256": "sha512_256",
}

# Lengths that straddle every padding boundary for both the 64 and 128 byte
# block hashes, including the 48..55 mod 64 window that was once broken.
HASH_LENGTHS = [0, 1, 47, 48, 49, 55, 56, 57, 63, 64, 65, 111, 112, 113,
                119, 120, 121, 127, 128, 129, 1000]


def data(n):
    return bytes(((i * 167 + 13) & 0xFF) for i in range(n))


# ----------------------------------------------------------------- hashes ---

@pytest.mark.parametrize("name", sorted(HASHLIB_EQUIVALENT))
@pytest.mark.parametrize("n", HASH_LENGTHS)
def test_hash_matches_hashlib(name, n):
    msg = data(n)
    ours = allcrypt.new(name, msg)
    theirs = hashlib.new(HASHLIB_EQUIVALENT[name], msg)
    assert ours.hexdigest() == theirs.hexdigest()
    assert ours.digest() == theirs.digest()
    assert ours.digest_size == theirs.digest_size
    assert ours.block_size == theirs.block_size


def test_hash_convenience_constructors():
    for name in HASHLIB_EQUIVALENT:
        constructor = getattr(allcrypt, name)
        assert constructor(b"abc").hexdigest() == hashlib.new(name, b"abc").hexdigest()
        # and with no argument, fed afterwards
        h = constructor()
        h.update(b"abc")
        assert h.hexdigest() == hashlib.new(name, b"abc").hexdigest()


def test_hash_streaming_carries_state():
    """Repeated update() must equal one call - across many small pieces."""
    msg = data(500)
    h = allcrypt.sha256()
    i, step = 0, 1
    while i < len(msg):
        end = min(len(msg), i + step)
        h.update(msg[i:end])
        i, step = end, step * 2 + 1
    assert h.hexdigest() == hashlib.sha256(msg).hexdigest()


def test_hash_digest_is_repeatable():
    h = allcrypt.sha256(b"abc")
    assert h.digest() == h.digest()
    # and updating afterwards continues rather than restarting
    h.update(b"def")
    assert h.hexdigest() == hashlib.sha256(b"abcdef").hexdigest()


def test_hash_copy_forks_state():
    h = allcrypt.sha256(b"hello ")
    forked = h.copy()
    h.update(b"world")
    forked.update(b"there")
    assert h.hexdigest() == hashlib.sha256(b"hello world").hexdigest()
    assert forked.hexdigest() == hashlib.sha256(b"hello there").hexdigest()


def test_sha0_is_not_sha1():
    """SHA-0 has no hashlib equivalent; pin it to its published vectors."""
    assert allcrypt.sha0(b"").hexdigest() == "f96cea198ad1dd5617ac084a3d92c6107708c0ef"
    assert allcrypt.sha0(b"abc").hexdigest() == "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"
    assert allcrypt.sha0(b"abc").hexdigest() != allcrypt.sha1(b"abc").hexdigest()


def test_unknown_hash_raises():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.new("md6")
    assert issubclass(allcrypt.CryptoError, ValueError)


# ---------------------------------------------------------- block ciphers ---

KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CTRBLK = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

# NIST SP 800-38A appendix F, the same vectors the Rust suite asserts.
SP800_38A = {
    "ecb": "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
           "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
    "cbc": "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
           "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
    "cfb": "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
           "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
    "ofb": "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
           "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
    "ctr": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
           "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
}


def iv_for(mode):
    if mode == "ecb":
        return None
    return CTRBLK if mode == "ctr" else IV


@pytest.mark.parametrize("mode", sorted(SP800_38A))
def test_aes_known_vectors(mode):
    c = allcrypt.Cipher("aes", KEY128)
    assert c.encrypt(mode, PT, iv_for(mode)).hex() == SP800_38A[mode]
    assert c.decrypt(mode, bytes.fromhex(SP800_38A[mode]), iv_for(mode)) == PT


@pytest.mark.parametrize("mode", sorted(SP800_38A))
def test_encryptor_streaming_matches_one_shot(mode):
    """State must carry across update() calls, at awkward split points."""
    c = allcrypt.Cipher("aes", KEY128)
    one_shot = c.encrypt(mode, PT, iv_for(mode))

    for first in (1, 3, 7, 15, 16, 17, 33):
        enc = c.encryptor(mode, iv_for(mode))
        out, i, step = b"", 0, first
        while i < len(PT):
            end = min(len(PT), i + step)
            out += enc.update(PT[i:end])
            i, step = end, step * 2 + 1
        out += enc.finalize()
        assert out == one_shot, "split starting at %d" % first


def test_one_cipher_drives_many_streams():
    """A Cipher holds no mode state, so streams must be independent."""
    c = allcrypt.Cipher("aes", KEY128)
    a = c.encryptor("ctr", CTRBLK)
    b = c.encryptor("ctr", CTRBLK)
    assert a.update(PT[:16]) == b.update(PT[:16])
    # interleaving must not cross-contaminate
    assert a.update(PT[16:32]) == b.update(PT[16:32])


def test_update_into_is_in_place():
    c = allcrypt.Cipher("aes", KEY128)
    expected = c.encrypt("ctr", PT, CTRBLK)

    buf = bytearray(PT)
    c.encryptor("ctr", CTRBLK).update_into(buf)
    assert bytes(buf) == expected


@pytest.mark.parametrize("mode", ["ecb", "cbc"])
def test_update_into_refused_for_block_modes(mode):
    c = allcrypt.Cipher("aes", KEY128)
    buf = bytearray(PT)
    with pytest.raises(allcrypt.CryptoError):
        c.encryptor(mode, iv_for(mode)).update_into(buf)


def test_partial_block_reported_at_finalize():
    c = allcrypt.Cipher("aes", KEY128)
    enc = c.encryptor("cbc", IV)
    out = enc.update(PT[:20])
    assert len(out) == 16, "only the completed block should come out"
    with pytest.raises(allcrypt.CryptoError):
        enc.finalize()


def test_stream_cannot_be_reused_after_finalize():
    c = allcrypt.Cipher("aes", KEY128)
    enc = c.encryptor("ctr", CTRBLK)
    enc.update(b"hello")
    enc.finalize()
    with pytest.raises(allcrypt.CryptoError):
        enc.update(b"more")


def test_iv_requirements():
    c = allcrypt.Cipher("aes", KEY128)
    with pytest.raises(allcrypt.CryptoError):
        c.encryptor("cbc")            # missing
    with pytest.raises(allcrypt.CryptoError):
        c.encryptor("ecb", IV)        # not wanted
    with pytest.raises(allcrypt.CryptoError):
        c.encryptor("cbc", IV[:8])    # wrong length
    with pytest.raises(allcrypt.CryptoError):
        c.encryptor("gcm", IV)        # not implemented


def test_bad_keys_raise_rather_than_crash():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("aes", b"tooshort")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("blowfish", b"")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("rot13", KEY128)


def test_gost_uses_its_own_counter():
    key = bytes.fromhex(
        "be5ec2006cff9dcf52354959f1ff0cbf"
        "e95061b5a648c10387069c25997c0672")
    out = allcrypt.Cipher("gost", key).encrypt("ctr", bytes(15), bytes([1, 2, 3, 4, 5, 6, 7, 8]))
    assert out.hex() == "3b234515ad4fa0405d2f3cf1677697"


# --------------------------------------------------------- stream ciphers ---

def test_rc4_rfc6229():
    c = allcrypt.StreamCipher("rc4", bytes.fromhex("0102030405"))
    assert c.update(bytes(16)).hex() == "b2396305f03dc027ccc3524a0a1118a8"


def test_chacha20_rfc8439_keystream():
    c = allcrypt.StreamCipher("chacha20", bytes(32), bytes(12))
    assert c.update(bytes(3)).hex() == "76b8e0"


def test_stream_cipher_keeps_position():
    """Byte at a time must equal one call - this is what used to break."""
    key, nonce = bytes(32), bytes(12)
    one_shot = allcrypt.StreamCipher("chacha20", key, nonce).update(bytes(200))

    c = allcrypt.StreamCipher("chacha20", key, nonce)
    streamed = b"".join(c.update(bytes(1)) for _ in range(200))
    assert streamed == one_shot


def test_stream_cipher_roundtrip():
    key, nonce = bytes(range(32)), bytes(range(12))
    ct = allcrypt.StreamCipher("chacha20", key, nonce).update(PT)
    assert allcrypt.StreamCipher("chacha20", key, nonce).update(ct) == PT


def test_rc4_takes_no_nonce():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.StreamCipher("rc4", b"key", b"nonce")


# ZipCrypto against CPython's zipfile, the other implementation on every
# machine that runs these tests. zipfile only decrypts, so ours encrypts
# and zipfile must get the plaintext back, and both decrypt the same
# bytes. Passwords and lengths cross the 12-byte ZIP header and the
# CRC table's 256.

def _zipfile_decrypt(password, data):
    import zipfile
    return zipfile._ZipDecrypter(password)(data)


@pytest.mark.parametrize("password", [b"", b"a", b"secret", bytes(range(256)) * 2])
def test_zipcrypto_against_cpython_zipfile(password):
    for n in (0, 1, 11, 12, 13, 255, 256, 1000):
        data = bytes((i * 167 + 13) & 0xff for i in range(n))
        ct = allcrypt.StreamCipher("zipcrypto", password).encrypt(data)
        assert _zipfile_decrypt(password, ct) == data
        assert (allcrypt.StreamCipher("zipcrypto", password).decrypt(data)
                == _zipfile_decrypt(password, data))


def test_office_xor():
    # msoffcrypto-tool's documented value for Excel's default password.
    assert allcrypt.office_xor_verifier(b"VelvetSweatshop") == 0x9a0a
    data = bytes(range(40))
    for index in (0, 3, 16):
        ct = allcrypt.office_xor_encrypt(b"secret", data, index)
        assert ct != data
        assert allcrypt.office_xor_decrypt(b"secret", ct, index) == data
    # The array repeats every 16 bytes: index 3 and 19 are the same.
    assert (allcrypt.office_xor_encrypt(b"secret", data, 3)
            == allcrypt.office_xor_encrypt(b"secret", data, 19))
    for bad in (b"", b"x" * 16):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.office_xor_verifier(bad)


def test_blowfish_le_is_blowfish_with_its_words_reversed():
    key = b"TrueCrypt"
    block = bytes(range(1, 9))
    swap = lambda b: b[3::-1] + b[7:3:-1]
    le = allcrypt.Cipher("blowfish-le", key).encrypt("ecb", block)
    be = allcrypt.Cipher("blowfish", key).encrypt("ecb", swap(block))
    assert le == swap(be) != be


# Ciphertext stealing: RFC 3962 appendix B's six vectors, read out of the
# vendored document, are CS3; CS1 and CS2 differ from CS3 only in the
# order of the last two pieces. `scripts/diff_check.py block` checks all
# three against OpenSSL's CBC-CTS at every length.

def _rfc3962_cts_vectors():
    """The key, and each vector's IV, input and output: every label line
    (`IV:`, `Input:`, ...) is followed by `0000:`-style hex lines."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "rfcs", "rfc3962.txt")
    text = open(path).read()
    text = text[text.index("Some test vectors for CBC with ciphertext stealing"):]
    fields, label = [], None
    for line in text.splitlines():
        tokens = line.split()
        if tokens and len(tokens[0]) == 5 and tokens[0].endswith(":") and label:
            fields[-1][1].extend(bytes.fromhex("".join(tokens[1:])))
        elif line.strip().endswith(":"):
            label = line.strip()[:-1]
            fields.append((label, bytearray()))
        elif line.strip() and "[Page" not in line and not line.startswith("RFC "):
            label = None
    key = bytes(fields[0][1])
    assert fields[0][0] == "AES 128-bit key"
    vectors = []
    for (a, iv), (b, data), (c, out) in zip(fields[1::4], fields[2::4], fields[3::4]):
        assert (a, b, c) == ("IV", "Input", "Output")
        vectors.append((bytes(iv), bytes(data), bytes(out)))
    return key, vectors


def test_cbc_cs3_is_rfc_3962():
    key, vectors = _rfc3962_cts_vectors()
    assert len(vectors) == 6
    cipher = allcrypt.Cipher("aes", key)
    for iv, data, out in vectors:
        assert cipher.encrypt("cbc-cs3", data, iv) == out
        assert cipher.decrypt("cbc-cs3", out, iv) == data


@pytest.mark.parametrize("variant", ["cs1", "cs2", "cs3"])
def test_cbc_ciphertext_stealing_orders_the_last_two(variant):
    key, iv = bytes(range(16)), bytes(range(100, 116))
    cipher = allcrypt.Cipher("aes", key)
    for n in (16, 17, 31, 32, 33, 48, 100):
        data = bytes((i * 7 + 1) & 0xff for i in range(n))
        ct = cipher.encrypt(f"cbc-{variant}", data, iv)
        cs3 = cipher.encrypt("cbc-cs3", data, iv)
        assert len(ct) == n
        d = n - 16 * ((n - 1) // 16)                 # the last piece's length
        head, swapped = cs3[:n - 16 - d], cs3[n - 16 - d:]
        unswapped = head + swapped[16:] + swapped[:16]
        whole = n % 16 == 0
        if n == 16:
            assert ct == cs3
        elif variant == "cs1" or (variant == "cs2" and whole):
            assert ct == unswapped
        else:
            assert ct == cs3
        assert cipher.decrypt(f"cbc-{variant}", ct, iv) == data
    with pytest.raises(allcrypt.CryptoError, match="at least one"):
        cipher.encrypt(f"cbc-{variant}", bytes(15), iv)


def test_cbc_ciphertext_stealing_streams():
    key, iv = bytes(16), bytes(16)
    data = bytes(range(200)) * 3
    whole = allcrypt.Cipher("aes", key).encrypt("cbc-cs3", data, iv)
    e = allcrypt.Cipher("aes", key).encryptor("cbc-cs3", iv)
    pieces = b"".join(e.update(data[i:i + 13]) for i in range(0, len(data), 13))
    assert pieces + e.finalize() == whole


def test_ctr_little_endian_counter():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = bytes(range(16))
    iv = (2**64 - 1).to_bytes(16, "little")       # a carry into the ninth byte
    data = bytes(range(70))
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    stream = b"".join(ecb.update((2**64 - 1 + i).to_bytes(16, "little")) for i in range(5))
    want = bytes(a ^ b for a, b in zip(data, stream))
    assert allcrypt.Cipher("aes", key).encrypt("ctr-le", data, iv) == want


def test_cmac_and_cbc_mac_against_python_cryptography():
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = bytes(range(16))
    for n in (0, 1, 15, 16, 17, 64):
        data = bytes(range(n))
        c = CMAC(algorithms.AES(key))
        c.update(data)
        assert allcrypt.cmac("aes", key, data) == c.finalize()
    data = bytes(range(48))
    enc = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    assert allcrypt.cbc_mac("aes", key, data) == (enc.update(data) + enc.finalize())[-16:]
    assert allcrypt.cbc_mac("aes", key, bytes(range(40)), zero_pad=True) == \
        allcrypt.cbc_mac("aes", key, bytes(range(40)) + bytes(8))
    with pytest.raises(allcrypt.CryptoError, match="whole number"):
        allcrypt.cbc_mac("aes", key, bytes(17))


# CMS's older key wraps against their RFCs' own examples, read out of the
# vendored documents.

def _rfc_hex(doc, start, label):
    """The hex after `label` (after `start`) and on the lines under it, in
    four- or two-digit groups, up to a line that is not all hex."""
    import os
    text = open(os.path.join(os.path.dirname(__file__), "..", "rfcs", doc)).read()
    at = text.index(label, text.index(start))
    out = ""
    for i, line in enumerate(text[at:].splitlines()):
        tokens = (line[len(label):] if i == 0 else line).split()
        if not tokens or not all(all(c in "0123456789abcdefABCDEF" for c in t) for t in tokens):
            break
        out += "".join(tokens)
    return bytes.fromhex(out)


def test_rfc_3217_key_wraps():
    start = "3.4  Triple-DES Key Wrap Example"
    cek, kek, iv, result = (_rfc_hex("rfc3217.txt", start, l)
                            for l in ("CEK:", "KEK:", "IV:", "RESULT:"))
    assert allcrypt.cms_3des_key_wrap(kek, cek, iv) == result
    assert allcrypt.cms_3des_key_unwrap(kek, result) == cek
    random = allcrypt.cms_3des_key_wrap(kek, cek)
    assert len(random) == 40 and random != result
    assert allcrypt.cms_3des_key_unwrap(kek, random) == cek
    # The RC2 example's key-encryption key is used at 40 effective bits.
    start = "4.4  RC2 Key Wrap Example"
    cek, kek, pad, iv, result = (_rfc_hex("rfc3217.txt", start, l)
                                 for l in ("CEK:", "KEK:", "PAD:", "IV:", "RESULT:"))
    assert allcrypt.cms_rc2_key_wrap(kek, 40, cek, pad, iv) == result
    assert allcrypt.cms_rc2_key_unwrap(kek, 40, result) == cek
    with pytest.raises(allcrypt.CryptoError, match="Wrong key-encryption key"):
        allcrypt.cms_rc2_key_unwrap(kek, 128, result)


def test_rfc_3211_password_recipient_wrap():
    start = "The following values are obtained when wrapping"
    key, cek, padding, iv = (_rfc_hex("rfc3211.txt", start, l)
                             for l in ("output key:", "CEK:", "padding:", "IV:"))
    second = _rfc_hex("rfc3211.txt", start, "second encr.")
    assert allcrypt.pwri_key_wrap("des", key, iv, cek, padding) == second
    assert allcrypt.pwri_key_unwrap("des", key, iv, second) == cek
    assert allcrypt.pwri_key_unwrap("aes", bytes(16), bytes(16),
                                    allcrypt.pwri_key_wrap("aes", bytes(16), bytes(16),
                                                           bytes(range(16)))) == bytes(range(16))
    with pytest.raises(allcrypt.CryptoError, match="Wrong password"):
        allcrypt.pwri_key_unwrap("des", bytes(8), iv, second)


def test_zipcrypto_has_a_direction():
    z = allcrypt.StreamCipher("zipcrypto", b"pw")
    assert not z.keystream
    with pytest.raises(allcrypt.CryptoError, match="encrypt or decrypt"):
        z.update(b"x")
    # Encrypting in pieces carries the state, as one call does.
    whole = allcrypt.StreamCipher("zipcrypto", b"pw").encrypt(PT)
    pieces = allcrypt.StreamCipher("zipcrypto", b"pw")
    assert b"".join(pieces.encrypt(PT[i:i + 7]) for i in range(0, len(PT), 7)) == whole
    assert allcrypt.StreamCipher("chacha20", bytes(32), bytes(12)).keystream
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.StreamCipher("zipcrypto", b"pw", bytes(12))


# ---------------------------------------------------------------- padding ---

@pytest.mark.parametrize("block_size", [8, 16])
@pytest.mark.parametrize("n", list(range(0, 33)))
def test_pkcs7_roundtrip(block_size, n):
    padded = allcrypt.pad_pkcs7(data(n), block_size)
    assert len(padded) % block_size == 0
    assert len(padded) > n, "padding always adds at least one byte"
    assert allcrypt.unpad_pkcs7(padded, block_size) == data(n)


def test_pkcs7_rejects_bad_padding():
    for bad in (b"", bytes(16), bytes([17] * 16), bytes(17)):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.unpad_pkcs7(bad, 16)


def test_padding_lets_cbc_take_any_length():
    c = allcrypt.Cipher("aes", KEY128)
    message = b"a message of awkward length"
    ct = c.encrypt("cbc", allcrypt.pad_pkcs7(message, c.block_size), IV)
    assert allcrypt.unpad_pkcs7(c.decrypt("cbc", ct, IV), c.block_size) == message


# -------------------------------------------------------------- catalogue ---

def test_catalogue_entries_all_work():
    for name in allcrypt.algorithms_available:
        assert allcrypt.new(name).digest_size > 0
    # **Every key length, and at least one must work.** This was a table
    # of "which cipher takes which key size" and it was wrong three
    # times: when DES arrived, when IDEA, SEED, SM4 and CAST5 did, and
    # when TEA and XTEA did. A table beside the catalogue is a second
    # copy of the catalogue, and the claim being made here is only
    # "this name is usable" - which trying the lengths says without
    # recording anything. Same reasoning, and the same fix, as the AEAD
    # loop in `test_name_enums.py`.
    for name in allcrypt.block_ciphers_available:
        sizes = []
        for length in (5, 8, 16, 24, 32, 56):
            try:
                sizes.append(allcrypt.Cipher(name, bytes(length)).block_size)
            except allcrypt.CryptoError:
                pass
        assert sizes, f"{name} constructs at no key length"
        assert set(sizes) <= {8, 16}, f"{name} reports {set(sizes)}"
    # The nonce each stream cipher takes, which they do not agree on:
    # RC4 has none, Salsa20 wants exactly 8 bytes, ChaCha 12 and XChaCha20
    # 24. Spelled out rather than assumed, so a cipher with a different
    # nonce fails here loudly instead of being handed the wrong length.
    nonce_length = {"rc4": None, "zipcrypto": None, "salsa20": 8, "salsa12": 8, "salsa8": 8,
                    "xchacha20": 24}
    for name in allcrypt.stream_ciphers_available:
        size = nonce_length.get(name, 12)
        nonce = None if size is None else bytes(size)
        assert allcrypt.StreamCipher(name, bytes(32), nonce).encrypt(b"x")
    for mode in allcrypt.modes_available:
        c = allcrypt.Cipher("aes", KEY128)
        assert c.encryptor(mode, iv_for(mode)).mode == mode


def test_repr_is_informative():
    assert "sha256" in repr(allcrypt.sha256())
    assert "aes" in repr(allcrypt.Cipher("aes", KEY128))
    assert "ctr" in repr(allcrypt.Cipher("aes", KEY128).encryptor("ctr", CTRBLK))


# ------------------------------------------------------------- concurrency ---

def _loop_rate(seconds=0.15):
    """Iterations per second of a bare Python loop in this thread."""
    import time
    count, begin = 0, time.perf_counter()
    while time.perf_counter() - begin < seconds:
        count += 1
    return count / (time.perf_counter() - begin)


def _rate_while(work):
    """Iterations per second of this thread's loop while `work` runs in another.

    No handshake before the timer starts, deliberately. An earlier version
    of this had the child set a `threading.Event` immediately before its
    work so the measurement could begin at the right moment, and that
    silently inverted the whole test: the main thread waits on the event
    with the GIL released, the child sets it and then takes the GIL for
    the duration of the work, so the main thread only reacquires the GIL
    *after* the work has finished, and measured a loop that had nothing
    to compete with. Without the handshake the main thread merely gets a
    head start of at most one switch interval, 5 ms against a window of
    a couple of hundred, which is why the work here is sized to be long.
    """
    import threading, time
    thread = threading.Thread(target=work)
    count, begin = 0, time.perf_counter()
    thread.start()
    while thread.is_alive():
        count += 1
    window = time.perf_counter() - begin
    thread.join()
    return count / window


def test_concurrent_hashing_stays_correct():
    """Four threads hashing the same buffer must all get the right answer."""
    import threading

    buf = bytes(8 * 1024 * 1024)
    expected = hashlib.sha256(buf).hexdigest()
    results, errors = [], []

    def work():
        try:
            results.append(allcrypt.sha256(buf).hexdigest())
        except Exception as exc:          # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert results == [expected] * 4


def test_releases_the_gil():
    """Bulk work must not hold the GIL, measured directly rather than by wall clock.

    What is measured is how fast *this* thread can run a plain Python loop
    while a hash runs in another thread. An extension holding the GIL
    blocks this thread outright, so the rate collapses; one that releases
    it leaves this thread running at a good fraction of its unimpeded
    speed. Measured here: 0.3%-1.5% of baseline when the GIL is held
    against 27%-49% when it is released, a separation of nineteen times in
    the worst of twenty trials.

    **This replaces a wall-clock test that was wrong in both
    directions.** The previous version timed four threads against one
    hash and required the four to take under 3.5x the one, reasoning that
    four threads holding the GIL would take 4x. The flaw is that four
    threads take about 4x on any machine with fewer than four free cores
    *whether or not* the GIL is released, so the quantity it asserted on
    was mostly a measure of how many cores happened to be idle. Both
    error rates were then measured on this two-core machine rather than
    argued about:

    * with the GIL correctly released it sat at 2.0x-2.4x but reached
      3.7x under load, and **failed about 2 runs in 40** - the
      intermittent failure that went unexplained for two sessions
      because bare `pytest -q` does not name which test failed;
    * with the GIL deliberately held - `py.allow_threads` removed from
      `Hash::build` in `src/python.rs` and the module rebuilt - the ratio
      ranged 3.38x to 4.85x and the test **passed 2 runs in 10**. A 20%
      miss rate on the one thing it existed to detect.

    So no threshold could rescue it: the distributions overlap. Its own
    docstring claimed the threshold was "deliberately loose so it does
    not flake on a busy or single-core machine", which was backwards -
    on a single-core machine that test must fail, GIL or no GIL.

    The replacement was checked against the same deliberate break, and
    reported 0.012 of baseline against the control's 0.013: not a
    borderline call but the two being indistinguishable, which is exactly
    what a held GIL should look like.

    The control below is what makes this one trustworthy:
    `math.factorial` is a C call that holds the GIL throughout, so it
    shows what a failure looks like on this machine, now, rather than
    relying on an argument that it would look different. Without it the
    subject's "27% of baseline" would be a number with nothing to compare
    against.
    """
    import math

    buf = bytes(32 * 1024 * 1024)
    expected = hashlib.sha256(buf).hexdigest()

    baseline = _loop_rate()
    assert baseline > 10_000, "the loop is too slow to measure anything with"

    # The control: a long C call that is known to hold the GIL.
    held = _rate_while(lambda: math.factorial(120_000)) / baseline
    assert held < 0.05, (
        "the control did not block this thread (%.3f of baseline), so this "
        "test cannot tell a held GIL from a released one and the result "
        "below means nothing" % held)

    # The subject.
    result = []
    freed = _rate_while(lambda: result.append(allcrypt.sha256(buf).hexdigest()))
    freed /= baseline
    assert result == [expected], "the hash under test did not even run"
    assert freed > 0.10, (
        "this thread ran at %.3f of baseline while hashing, against %.3f for "
        "a call known to hold the GIL: the GIL is probably not being released"
        % (freed, held))


def test_independent_objects_do_not_share_state():
    """Two streams from one Cipher, driven from two threads, must not interfere."""
    import threading

    c = allcrypt.Cipher("aes", KEY128)
    expected = c.encrypt("ctr", PT, CTRBLK)
    out = {}

    def work(tag):
        enc = c.encryptor("ctr", CTRBLK)
        acc = b""
        for i in range(0, len(PT), 7):
            acc += enc.update(PT[i:i + 7])
        out[tag] = acc + enc.finalize()

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert list(out.values()) == [expected] * 4


# ------------------------------------------------------------- MAC and KDF ---

import hmac as pyhmac


@pytest.mark.parametrize("digestmod", ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
@pytest.mark.parametrize("n", [0, 1, 63, 64, 65, 127, 128, 129, 1000])
def test_hmac_matches_python_hmac(digestmod, n):
    key, msg = data(32), data(n)
    ours = allcrypt.Hmac(key, msg, digestmod)
    theirs = pyhmac.new(key, msg, getattr(hashlib, digestmod))
    assert ours.hexdigest() == theirs.hexdigest()
    assert ours.digest() == theirs.digest()
    assert ours.digest_size == theirs.digest_size


@pytest.mark.parametrize("keylen", [0, 1, 63, 64, 65, 128, 129, 200])
def test_hmac_key_lengths(keylen):
    """Keys longer than the block size get hashed first."""
    key, msg = data(keylen), b"message"
    assert (allcrypt.Hmac(key, msg, "sha256").hexdigest()
            == pyhmac.new(key, msg, hashlib.sha256).hexdigest())


def test_hmac_streaming():
    key, msg = b"k", data(500)
    h = allcrypt.Hmac(key, digestmod="sha256")
    i, step = 0, 1
    while i < len(msg):
        end = min(len(msg), i + step)
        h.update(msg[i:end])
        i, step = end, step * 2 + 1
    assert h.hexdigest() == pyhmac.new(key, msg, hashlib.sha256).hexdigest()
    assert h.digest() == h.digest(), "digest must be repeatable"


def test_hmac_unknown_hash_raises():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Hmac(b"key", b"msg", "md6")


def test_hkdf_rfc5869():
    """RFC 5869 test case 1."""
    okm = allcrypt.hkdf(bytes([0x0b]) * 22, 42,
                        salt=bytes(range(13)), info=bytes(range(0xf0, 0xfa)))
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
                         "ecc4c5bf34007208d5b887185865")


def test_hkdf_no_salt_uses_zeros():
    """RFC 5869 test case 3: no salt, no info."""
    assert allcrypt.hkdf(bytes([0x0b]) * 22, 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8")


def test_hkdf_length_limit():
    allcrypt.hkdf(b"ikm", 255 * 32)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.hkdf(b"ikm", 255 * 32 + 1)


def test_tls_prfs_are_length_prefixes():
    """Asking for fewer bytes must give a prefix of asking for more."""
    secret, seed = data(48), data(64)
    long12 = allcrypt.tls12_prf(secret, b"master secret", seed, 200)
    long10 = allcrypt.tls10_prf(secret, b"master secret", seed, 200)
    for n in (1, 31, 32, 33, 48, 104):
        assert allcrypt.tls12_prf(secret, b"master secret", seed, n) == long12[:n]
        assert allcrypt.tls10_prf(secret, b"master secret", seed, n) == long10[:n]


def test_tls12_prf_matches_rfc_construction():
    """P_hash written straight from RFC 5246 section 5."""
    def p_hash(mod, secret, seed, length):
        out, a = b"", seed
        while len(out) < length:
            a = pyhmac.new(secret, a, mod).digest()
            out += pyhmac.new(secret, a + seed, mod).digest()
        return out[:length]

    secret, seed = data(48), data(64)
    for mod, name in ((hashlib.sha256, "sha256"), (hashlib.sha384, "sha384")):
        assert allcrypt.tls12_prf(secret, b"master secret", seed, 104, name) == \
               p_hash(mod, secret, b"master secret" + seed, 104)


# ------------------------------------------------------------ DES and 3DES ---
#
# `DES-CBC3-SHA` is one of the most common things on equipment nobody is
# going to upgrade, which is why this is here at all. Both are thoroughly
# broken - 56 bits was brute-forced in public in 1998, and Triple DES buys
# back key length and nothing else, leaving a 64 bit block that Sweet32
# attacks after a few hundred gigabytes on one connection.
#
# OpenSSL has removed both from TLS entirely (this build offers 158 suites
# and not one uses either) but keeps the raw ciphers in its `decrepit`
# module - which is the same position this library takes, so the primitives
# can still be compared directly.


def _triple_des():
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        return TripleDES
    except ImportError:
        pytest.skip("this cryptography has no TripleDES to compare against")


@pytest.mark.parametrize("mode", ["ecb", "cbc", "cfb", "ofb"])
@pytest.mark.parametrize("length", [8, 16, 64, 800])
def test_triple_des_matches_openssl(mode, length):
    from cryptography.hazmat.primitives.ciphers import Cipher, modes as m
    TripleDES = _triple_des()

    key, iv = os.urandom(24), os.urandom(8)
    message = os.urandom(length)

    # ECB has no IV and refuses one, which is the point of it having its
    # own branch rather than a `None` here.
    ours = (allcrypt.Cipher("3des", key).encrypt(mode, message)
            if mode == "ecb"
            else allcrypt.Cipher("3des", key).encrypt(mode, message, iv))

    reference = m.ECB() if mode == "ecb" else {
        "cbc": lambda: m.CBC(iv),
        "cfb": lambda: m.CFB(iv),
        "ofb": lambda: m.OFB(iv),
    }[mode]()
    encryptor = Cipher(TripleDES(key), reference).encryptor()
    theirs = encryptor.update(message) + encryptor.finalize()

    assert ours == theirs, f"3des-{mode} at {length} bytes"
    back = (allcrypt.Cipher("3des", key).decrypt(mode, ours)
            if mode == "ecb"
            else allcrypt.Cipher("3des", key).decrypt(mode, ours, iv))
    assert back == message


@pytest.mark.parametrize("length", [8, 64, 800])
def test_triple_des_ctr(length):
    """OpenSSL refuses 3DES in CTR mode - a policy restriction, not a
    mathematical one, since CTR is *defined* in terms of the block
    function and works over any block cipher.

    So the reference is built the way the definition says: encrypt the
    counter blocks with ECB, which OpenSSL will do, and XOR. The same
    approach this suite already uses for Blowfish-CTR, and for the same
    reason - the restriction is in the library, not in the algorithm.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, modes as m
    TripleDES = _triple_des()

    key, nonce = os.urandom(24), os.urandom(8)
    message = os.urandom(length)
    ours = allcrypt.Cipher("3des", key).encrypt("ctr", message, nonce)

    blocks = (length + 7) // 8
    counters = b""
    counter = int.from_bytes(nonce, "big")
    for _ in range(blocks):
        counters += counter.to_bytes(8, "big")
        counter = (counter + 1) % (1 << 64)

    encryptor = Cipher(TripleDES(key), m.ECB()).encryptor()
    keystream = encryptor.update(counters) + encryptor.finalize()
    theirs = bytes(a ^ b for a, b in zip(message, keystream))

    assert ours == theirs, f"3des-ctr at {length} bytes"
    assert allcrypt.Cipher("3des", key).decrypt("ctr", ours, nonce) == message


@pytest.mark.parametrize("length", [8, 64, 800])
def test_single_des_matches_openssl(length):
    """There is no single-DES type left anywhere, so the comparison goes
    through TripleDES with the key repeated - which is not a workaround
    but the definition: EDE with three equal keys *is* DES, and that
    compatibility is the only reason the middle operation is a decryption."""
    from cryptography.hazmat.primitives.ciphers import Cipher, modes as m
    TripleDES = _triple_des()

    key, iv = os.urandom(8), os.urandom(8)
    message = os.urandom(length)

    ours = allcrypt.Cipher("des", key).encrypt("cbc", message, iv)
    encryptor = Cipher(TripleDES(key * 3), m.CBC(iv)).encryptor()
    assert ours == encryptor.update(message) + encryptor.finalize()
    assert allcrypt.Cipher("des", key).decrypt("cbc", ours, iv) == message


def test_des_key_lengths():
    for length in [0, 1, 7, 9, 16, 24]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Cipher("des", os.urandom(length))
    assert allcrypt.Cipher("des", os.urandom(8)).block_size == 8

    for length in [0, 7, 9, 15, 17, 23, 25]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Cipher("3des", os.urandom(length))
    for length in [8, 16, 24]:
        assert allcrypt.Cipher("3des", os.urandom(length)).block_size == 8


def test_three_equal_keys_reduce_to_des():
    """The only reason Triple DES is EDE rather than EEE."""
    key = os.urandom(8)
    message = os.urandom(32)
    iv = os.urandom(8)

    from_des = allcrypt.Cipher("des", key).encrypt("cbc", message, iv)
    for repeats in [1, 2, 3]:
        from_triple = allcrypt.Cipher("3des", key * repeats) \
            .encrypt("cbc", message, iv)
        assert from_triple == from_des, f"{repeats * 8} byte key"


def test_the_parity_bits_are_not_part_of_the_key():
    """A DES key is eight bytes but only 56 bits. The low bit of each byte
    is parity and is dropped, so flipping any of them changes nothing -
    surprising, true, and worth pinning so nobody "fixes" it."""
    key = bytearray(os.urandom(8))
    message = os.urandom(16)
    iv = bytes(8)
    base = allcrypt.Cipher("des", bytes(key)).encrypt("cbc", message, iv)

    for index in range(8):
        altered = bytearray(key)
        altered[index] ^= 0x01
        assert allcrypt.Cipher("des", bytes(altered)) \
            .encrypt("cbc", message, iv) == base, f"parity bit {index} mattered"

    # And a non-parity bit must change everything.
    altered = bytearray(key)
    altered[0] ^= 0x02
    assert allcrypt.Cipher("des", bytes(altered)).encrypt("cbc", message, iv) \
        != base
