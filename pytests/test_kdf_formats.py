"""The file formats' own key derivations: OpenPGP's S2K, 7-Zip's AES key,
KeePass's AES-KDF and LUKS's anti-forensic splitter, each against the
definition written out with hashlib and python-cryptography."""

import hashlib

import pytest

import allcrypt

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _s2k(name, passphrase, salt, count, length):
    unit = salt + passphrase
    total = max(count, len(unit)) if unit else 0
    string = (unit * (total // max(len(unit), 1) + 1))[:total]
    out, preload = b"", 0
    while len(out) < length:
        out += hashlib.new(name, bytes(preload) + string).digest()
        preload += 1
    return out[:length]


@pytest.mark.parametrize("name", ["md5", "sha1", "sha256", "sha512"])
@pytest.mark.parametrize("count", [0, 7, 1024, 65536 + 5, 100_001])
def test_openpgp_s2k_against_its_definition(name, count):
    for salt in (b"", b"8 bytes!"):
        for length in (16, 32, 70):
            assert allcrypt.openpgp_s2k(name, b"passphrase", salt, count, length) == \
                _s2k(name, b"passphrase", salt, count, length)


def test_openpgp_s2k_count():
    assert allcrypt.openpgp_s2k_count(0) == 1024
    assert allcrypt.openpgp_s2k_count(0xff) == 65_011_712
    assert allcrypt.openpgp_s2k_count(0x60) == 65536


def test_openpgp_s2k_unknown_hash():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.openpgp_s2k("md6", b"pw", b"", 0, 16)


@pytest.mark.parametrize("cycles", [0, 1, 7, 13])
def test_sevenzip_key_against_its_definition(cycles):
    password, salt = "pässword".encode("utf-16-le"), bytes(range(16))
    h = hashlib.sha256()
    for i in range(1 << cycles):
        h.update(salt + password + i.to_bytes(8, "little"))
    assert allcrypt.sevenzip_aes_key(password, salt, cycles) == h.digest()


def test_sevenzip_raw_key_and_range():
    assert allcrypt.sevenzip_aes_key(b"a\0b\0", b"\x09", 0x3f) == b"\x09a\0b\0" + bytes(27)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.sevenzip_aes_key(b"pw", b"", 0x40)


@pytest.mark.parametrize("rounds", [0, 1, 6000])
def test_keepass_aes_kdf_against_python_cryptography(rounds):
    key, seed = bytes(range(32)), bytes(range(100, 132))
    enc = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
    block = key
    for _ in range(rounds):
        block = enc.update(block)
    assert allcrypt.keepass_aes_kdf(key, seed, rounds) == hashlib.sha256(block).digest()
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.keepass_aes_kdf(key[:16], seed, rounds)


def _af_merge(material, key_len, stripes, name):
    size = hashlib.new(name).digest_size

    def diffuse(block):
        pieces = [block[i:i + size] for i in range(0, len(block), size)]
        return b"".join(hashlib.new(name, i.to_bytes(4, "big") + p).digest()[:len(p)]
                        for i, p in enumerate(pieces))

    d = bytes(key_len)
    for j in range(stripes - 1):
        d = diffuse(bytes(a ^ b for a, b in zip(d, material[j * key_len:(j + 1) * key_len])))
    last = material[(stripes - 1) * key_len:stripes * key_len]
    return bytes(a ^ b for a, b in zip(d, last))


@pytest.mark.parametrize("name", ["sha1", "sha256", "sha512"])
def test_luks_af_against_its_definition(name):
    key = bytes(range(33))
    material = allcrypt.luks_af_split(key, 50, name)
    assert len(material) == 33 * 50
    assert _af_merge(material, 33, 50, name) == key
    assert allcrypt.luks_af_merge(material, 33, 50, name) == key
    other = bytes((i * 7) & 0xff for i in range(33 * 9))
    assert allcrypt.luks_af_merge(other, 33, 9, name) == _af_merge(other, 33, 9, name)


def test_luks_af_defaults_are_luks_s():
    key = bytes(32)
    material = allcrypt.luks_af_split(key)
    assert len(material) == 32 * 4000
    assert allcrypt.luks_af_merge(material, 32) == key
    # The random stripes are random: two splits of one key differ.
    assert allcrypt.luks_af_split(key, 3) != allcrypt.luks_af_split(key, 3)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.luks_af_merge(material[:-1], 32)
