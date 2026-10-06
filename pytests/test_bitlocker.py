"""BitLocker's sector encryption and key stretching, through the binding.

The sector methods are checked against python-cryptography where it has
them - XTS, and CBC under the encrypted byte offset - and Elephant for
its own properties; `scripts/diff_check.py bitlocker` checks Elephant
against OpenSSL's AES with the diffusers in dm-crypt's shape, and the
BitLocker example opens volumes Windows made."""

import hashlib

import pytest

import allcrypt

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_LEN = {"aes-cbc-elephant-128": 32, "aes-cbc-elephant-256": 64, "aes-cbc-128": 16,
           "aes-cbc-256": 32, "aes-xts-128": 32, "aes-xts-256": 64}


def _key(n):
    return bytes((i * 89 + 7) & 0xff for i in range(n))


def _sector(n):
    return bytes((i * 167 + 13) & 0xff for i in range(n))


@pytest.mark.parametrize("method", sorted(KEY_LEN))
@pytest.mark.parametrize("size", [512, 4096])
def test_every_method_round_trips(method, size):
    key, plain = _key(KEY_LEN[method]), _sector(size)
    sealed = allcrypt.bitlocker_encrypt_sector(method, key, 1 << 20, plain)
    assert sealed != plain and len(sealed) == size
    assert allcrypt.bitlocker_decrypt_sector(method, key, 1 << 20, sealed) == plain
    assert allcrypt.bitlocker_encrypt_sector(method, key, (1 << 20) + size, plain) != sealed


@pytest.mark.parametrize("method", ["aes-xts-128", "aes-xts-256"])
def test_xts_against_python_cryptography(method):
    key, plain = _key(KEY_LEN[method]), _sector(4096)
    tweak = (7).to_bytes(16, "little")
    enc = Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor()
    assert allcrypt.bitlocker_encrypt_sector(method, key, 7 * 4096, plain) == \
        enc.update(plain) + enc.finalize()


@pytest.mark.parametrize("method", ["aes-cbc-128", "aes-cbc-256"])
def test_cbc_under_the_encrypted_offset(method):
    key, plain, offset = _key(KEY_LEN[method]), _sector(512), 0x1234_5600
    iv = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(
        offset.to_bytes(8, "little") + bytes(8))
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    assert allcrypt.bitlocker_encrypt_sector(method, key, offset, plain) == \
        enc.update(plain) + enc.finalize()


def test_elephant_spreads_one_flipped_bit_over_the_sector():
    key, plain = _key(32), _sector(512)
    sealed = bytearray(allcrypt.bitlocker_encrypt_sector("aes-cbc-elephant-128", key, 0, plain))
    sealed[3] ^= 1
    back = allcrypt.bitlocker_decrypt_sector("aes-cbc-elephant-128", key, 0, bytes(sealed))
    # CBC alone would change only the first two blocks.
    assert back[496:] != plain[496:]


def test_bad_arguments_are_refused():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.bitlocker_encrypt_sector("aes-ctr-128", _key(16), 0, bytes(512))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.bitlocker_encrypt_sector("aes-xts-256", _key(32), 0, bytes(512))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.bitlocker_encrypt_sector("aes-cbc-128", _key(16), 0, bytes(100))


def _stretch(initial, salt):
    last = bytes(32)
    for count in range(1 << 20):
        last = hashlib.sha256(last + initial + salt + count.to_bytes(8, "little")).digest()
    return last


def test_password_and_recovery_keys_against_their_definition():
    salt = bytes(range(16))
    once = hashlib.sha256("pässword".encode("utf-16-le")).digest()
    assert allcrypt.bitlocker_password_key("pässword", salt) == \
        _stretch(hashlib.sha256(once).digest(), salt)
    recovery = "000011-000022-720885-000000-000110-011011-000033-000044"
    words = [1, 2, 65535, 0, 10, 1001, 3, 4]
    key = b"".join(w.to_bytes(2, "little") for w in words)
    assert allcrypt.bitlocker_recovery_password_key(recovery, salt) == \
        _stretch(hashlib.sha256(key).digest(), salt)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.bitlocker_recovery_password_key(recovery.replace("000011", "000012"), salt)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.bitlocker_password_key("pw", bytes(15))
