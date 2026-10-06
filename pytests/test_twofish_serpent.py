"""Twofish and Serpent through the generic modes.

**Nothing on this machine implements either.** Not OpenSSL, not
python-cryptography. So the independent reference is the vendored Botan
vector files, and those are read by the Rust tests - 723 Twofish cases
and 1047 Serpent, across all three key sizes, both directions.

What those cannot cover is everything above ECB, and that is what this
file is for. It is **not** a differential check and does not pretend to
be: every assertion here is about this library agreeing with itself. It
earns its place because the property it checks is one a wrong answer
breaks - streaming in irregular pieces must equal one call, and a
round-trip must return the plaintext - and because the mode code is
shared, so a cipher that works in ECB and fails in CBC is a bug in how
it was plugged in rather than in the mode.

The modes are generic by design: a cipher implements `blocksize`,
`block_encrypt` and `block_decrypt` and gets all five. These tests are
what says that actually happened for these two.
"""

import pytest

import allcrypt


CIPHERS = [("twofish", 16), ("twofish", 24), ("twofish", 32),
           ("serpent", 16), ("serpent", 24), ("serpent", 32)]

IDS = [f"{name}-{length * 8}" for name, length in CIPHERS]


def key_of(length):
    return bytes((i * 37 + 11) % 256 for i in range(length))


def data_of(length):
    return bytes((i * 167 + 13) % 256 for i in range(length))


@pytest.mark.parametrize("name,key_len", CIPHERS, ids=IDS)
def test_both_are_in_the_catalogue(name, key_len):
    assert name in allcrypt.block_ciphers_available
    assert allcrypt.Cipher(name, key_of(key_len))


@pytest.mark.parametrize("name,key_len", CIPHERS, ids=IDS)
@pytest.mark.parametrize("mode", ["ecb", "cbc", "cfb", "ofb", "ctr"])
def test_every_mode_round_trips(name, key_len, mode):
    cipher = allcrypt.Cipher(name, key_of(key_len))
    # ECB and CBC need whole blocks; the stream-shaped modes take any
    # length, and the ragged ones are where a partial final block goes
    # wrong.
    lengths = [16, 32, 64] if mode in ("ecb", "cbc") else [1, 15, 16, 17, 63, 100]
    for length in lengths:
        plain = data_of(length)
        if mode == "ecb":
            out = cipher.encrypt(mode, plain)
            assert cipher.decrypt(mode, out) == plain
        else:
            out = cipher.encrypt(mode, plain, iv=bytes(16))
            assert cipher.decrypt(mode, out, iv=bytes(16)) == plain
        assert len(out) == length
        assert out != plain


@pytest.mark.parametrize("name,key_len", CIPHERS, ids=IDS)
def test_a_different_key_gives_a_different_ciphertext(name, key_len):
    plain = data_of(64)
    first = allcrypt.Cipher(name, key_of(key_len)).encrypt("ecb", plain)
    other = bytearray(key_of(key_len))
    other[0] ^= 0x01
    second = allcrypt.Cipher(name, bytes(other)).encrypt("ecb", plain)
    assert first != second


@pytest.mark.parametrize("name,key_len", CIPHERS, ids=IDS)
def test_a_different_iv_gives_a_different_ciphertext(name, key_len):
    cipher = allcrypt.Cipher(name, key_of(key_len))
    plain = data_of(64)
    first = cipher.encrypt("cbc", plain, iv=bytes(16))
    second = cipher.encrypt("cbc", plain, iv=bytes([1] + [0] * 15))
    assert first != second


@pytest.mark.parametrize("name,key_len", CIPHERS, ids=IDS)
@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
@pytest.mark.parametrize("chunk", [1, 3, 7, 16, 17, 31])
def test_streaming_in_pieces_equals_one_call(name, key_len, mode, chunk):
    """The shape of bug that cost this repository two algorithms.

    ChaCha desynchronised its keystream from the third `crypt()` call and
    passed every one-shot test; SHA-1 padded with a 16 byte length field
    and hashed every message of 48..55 mod 64 wrongly. Both produced
    plausible output. See the testing checklist in docs/extending.md.
    """
    total = 96 if mode == "cbc" else 100
    plain = data_of(total)
    cipher = allcrypt.Cipher(name, key_of(key_len))
    whole = cipher.encrypt(mode, plain, iv=bytes(16))

    stream = cipher.encryptor(mode, iv=bytes(16))
    pieces = b"".join(stream.update(plain[i:i + chunk])
                      for i in range(0, len(plain), chunk))
    pieces += stream.finalize()
    if mode == "cbc" and total % 16:
        pytest.skip("CBC needs whole blocks")
    assert pieces == whole


@pytest.mark.parametrize("name,key_len", CIPHERS, ids=IDS)
def test_the_block_size_is_128_bits(name, key_len):
    """Both are 128 bit block ciphers, which is what makes XTS and key
    wrap available to them - those two are 128-bit-only, and a cipher
    reporting the wrong block size would be refused there rather than
    silently misused."""
    cipher = allcrypt.Cipher(name, key_of(key_len))
    # A 15 byte ECB input must be refused, and a 16 byte one accepted.
    with pytest.raises(ValueError):
        cipher.encrypt("ecb", data_of(15))
    assert len(cipher.encrypt("ecb", data_of(16))) == 16


@pytest.mark.parametrize("name", ["twofish", "serpent"])
@pytest.mark.parametrize("length", [0, 1, 8, 15, 17, 23, 25, 31, 33, 64])
def test_a_wrong_key_length_is_refused(name, length):
    with pytest.raises(ValueError, match="16, 24 or 32"):
        allcrypt.Cipher(name, bytes(length))


@pytest.mark.parametrize("name,key_len", CIPHERS, ids=IDS)
def test_key_wrap_works_with_them(name, key_len):
    """The point of a generic mode. `Camellia-XTS` and `SM4` key wrap
    exist here and nowhere else; so do these."""
    wrapped = allcrypt.key_wrap(key_of(key_len), data_of(32), cipher=name)
    assert allcrypt.key_unwrap(key_of(key_len), wrapped, cipher=name) == data_of(32)
    assert len(wrapped) == 40


@pytest.mark.parametrize("name", ["twofish", "serpent"])
def test_xts_works_with_them(name):
    key = key_of(32) + key_of(32)[::-1]
    sector = data_of(512)
    out = allcrypt.xts_encrypt(key, 0, sector, cipher=name)
    assert allcrypt.xts_decrypt(key, 0, out, cipher=name) == sector
    # A different sector number is a different ciphertext, which is the
    # whole reason XTS exists.
    assert allcrypt.xts_encrypt(key, 1, sector, cipher=name) != out


def test_the_two_are_not_each_other():
    """Both are 128 bit block, 128/192/256 bit key AES finalists with the
    same interface. A dispatch table with one wrong entry produces
    something that passes every structural test in this file."""
    plain = data_of(16)
    key = key_of(32)
    assert (allcrypt.Cipher("twofish", key).encrypt("ecb", plain)
            != allcrypt.Cipher("serpent", key).encrypt("ecb", plain))
    for other in ("aes", "camellia"):
        assert (allcrypt.Cipher("twofish", key).encrypt("ecb", plain)
                != allcrypt.Cipher(other, key).encrypt("ecb", plain))
