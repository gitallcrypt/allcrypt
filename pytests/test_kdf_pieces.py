"""BLAKE2's parameter block, the narrower password derivations, HKDF's
halves, and 802.11's pieces, against answers not ours.

hashlib for BLAKE2 and the hashes PBKDF1, the JDK's PBE and BitLocker's
stretch iterate; python-cryptography's HKDFExpand and the `hmac` module
for HKDF and 802.11's PRF and KDF; OpenSSL's PKCS12KDF through
`vectors/pkcs12_kdf.vec`; the keys OpenSSH's ssh-keygen encrypted in
`vectors/ssh_keys.vec` for bcrypt_pbkdf; and python-cryptography's RC4 with `zlib.crc32` for a
TKIP frame, keyed by the per-frame keys `vectors/tkip.vec` holds from
Linux's mac80211.
"""

import base64
import hashlib
import hmac
import os
import pathlib
import struct
import zlib

import pytest

import allcrypt

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes                       # noqa: E402
from cryptography.hazmat.primitives.ciphers import (                    # noqa: E402
    Cipher, algorithms, modes)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand          # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ BLAKE2 ---

@pytest.mark.parametrize("variant,max_len,param_len", [("blake2b", 64, 16), ("blake2s", 32, 8)])
def test_blake2_against_hashlib(variant, max_len, param_len):
    ours_fn, theirs_fn = getattr(allcrypt, variant), getattr(hashlib, variant)
    for digest_size in (1, 16, max_len // 2 + 1, max_len):
        for key in (b"", os.urandom(1), os.urandom(max_len)):
            for salt in (b"", os.urandom(param_len), b"short"):
                for person in (b"", os.urandom(param_len), b"app"):
                    data = os.urandom(digest_size * 3)
                    theirs = theirs_fn(data, digest_size=digest_size, key=key, salt=salt,
                                       person=person).digest()
                    ours = ours_fn(data, digest_size=digest_size, key=key, salt=salt,
                                   person=person)
                    assert ours.digest() == theirs
                    streamed = ours_fn(digest_size=digest_size, key=key, salt=salt,
                                       person=person)
                    streamed.update(data[:5])
                    streamed.update(data[5:])
                    assert streamed.digest() == theirs


def test_blake2_refuses_what_hashlib_refuses():
    for kwargs in ({"digest_size": 65}, {"digest_size": 0}, {"key": bytes(65)},
                   {"salt": bytes(17)}, {"person": bytes(17)}):
        with pytest.raises(ValueError):
            hashlib.blake2b(**kwargs)
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.blake2b(**kwargs)


# -------------------------------------------------------------------- HKDF ---

@pytest.mark.parametrize("digestmod", ["sha256", "sha384", "sha1"])
def test_hkdf_halves_against_hmac_and_cryptography(digestmod):
    for salt in (None, b"", os.urandom(13), os.urandom(200)):
        ikm = os.urandom(40)
        prk = hmac.new(salt or bytes(hashlib.new(digestmod).digest_size), ikm,
                       digestmod).digest()
        assert allcrypt.hkdf_extract(ikm, salt=salt, digestmod=digestmod) == prk
        for length in (1, 32, 100):
            theirs = HKDFExpand(getattr(hashes, digestmod.upper())(), length,
                                b"info").derive(prk)
            assert allcrypt.hkdf_expand(prk, length, info=b"info", digestmod=digestmod) == theirs


# ------------------------------------------------- the password derivations ---

@pytest.mark.parametrize("hash_name", ["md5", "sha1", "md2"])
def test_pbkdf1_against_hashlib(hash_name):
    if hash_name not in hashlib.algorithms_available:
        hash_name = "sha256"
    for iterations in (1, 2, 1000):
        password, salt = os.urandom(10), os.urandom(8)
        t = password + salt
        for _ in range(iterations):
            t = hashlib.new(hash_name, t).digest()
        assert allcrypt.pbkdf1(hash_name, password, salt, iterations) == t
        assert allcrypt.pbkdf1(hash_name, password, salt, iterations, 8) == t[:8]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.pbkdf1(hash_name, b"pw", b"saltsalt", 1, len(t) + 1)


@pytest.mark.parametrize("name,count", [("pkcs12_kdf.vec", 45), ("pkcs12_kdf_gost.vec", 55)])
def test_pkcs12_kdf_against_openssl(name, count):
    """The second file is GOST 34.311, whose 32-byte block is the KDF's v."""
    rows = [line for line in (ROOT / "vectors" / name).read_text().splitlines()
            if line and not line.startswith("#")]
    assert len(rows) == count
    for row in rows:
        f = dict(field.split("=", 1) for field in row.split())
        password = b"" if f["password"] == "-" else bytes.fromhex(f["password"])
        out = bytes.fromhex(f["out"])
        assert allcrypt.pkcs12_kdf(f["hash"], password, bytes.fromhex(f["salt"]), int(f["id"]),
                                   int(f["iterations"]), len(out)) == out


def test_pkcs12_bmp_password():
    for text in ("smeg", "пароль", "😀 x", "a"):
        assert allcrypt.pkcs12_bmp_password(text) == text.encode("utf-16-be") + b"\0\0"


def test_jdk_pbe_md5_3des_against_hashlib():
    """The JDK's PBES1Core.deriveCipherKey: each salt half chained through
    MD5 with the password, the first half reversed if the halves match;
    the two 16 byte results are the 3DES key then the IV."""
    def theirs(password, salt, iterations):
        halves = [bytearray(salt[:4]), bytearray(salt[4:])]
        if halves[0] == halves[1]:
            halves[0].reverse()
        out = b""
        for half in halves:
            t = bytes(half)
            for _ in range(iterations):
                t = hashlib.md5(t + password).digest()
            out += t
        return out[:24], out[24:]
    for salt in (os.urandom(8), b"abcdabcd", b"\0" * 8):
        for iterations in (1, 2, 20):
            assert allcrypt.jdk_pbe_md5_3des(b"password", salt, iterations) == \
                theirs(b"password", salt, iterations)


def test_openpgp_s2k_coded_count_is_rfc_4880s_inverse():
    def count(c):
        return (16 + (c & 15)) << ((c >> 4) + 6)
    for octets in (0, 1, 1024, 1025, 65536, 65537, 1 << 20, 65011712, 65011713):
        coded = allcrypt.openpgp_s2k_coded_count(octets)
        smallest = next((c for c in range(256) if count(c) >= octets), 255)
        assert coded == smallest, octets


def _ssh_string(blob, offset):
    (length,) = struct.unpack(">I", blob[offset:offset + 4])
    return blob[offset + 4:offset + 4 + length], offset + 4 + length


def openssh_encrypted_keys():
    """The `[encrypted]` records of vectors/ssh_keys.vec: private keys
    OpenSSH's ssh-keygen wrote under a passphrase."""
    text = (ROOT / "vectors" / "ssh_keys.vec").read_text()
    body = text.split("\n[encrypted]\n", 1)[1].split("\n[", 1)[0]
    return [dict(line.split(" = ", 1) for line in chunk.splitlines())
            for chunk in body.strip().split("\n\n")]


def test_bcrypt_pbkdf_opens_what_openssh_encrypted():
    """bcrypt_pbkdf's output is the cipher's key then its IV, and the
    private section they open starts with two equal check integers -
    which a wrong key gives with probability 2^-32."""
    opened = 0
    for record in openssh_encrypted_keys():
        cipher_name = record["cipher"]
        if not cipher_name.startswith("aes") or cipher_name.endswith("gcm@openssh.com"):
            continue
        armour = base64.b64decode(record["private"]).decode()
        body = base64.b64decode("".join(armour.strip().splitlines()[1:-1]))
        offset = len(b"openssh-key-v1\0")
        cipher, offset = _ssh_string(body, offset)
        kdf, offset = _ssh_string(body, offset)
        options, offset = _ssh_string(body, offset)
        assert (cipher.decode(), kdf) == (cipher_name, b"bcrypt")
        salt, after = _ssh_string(options, 0)
        (rounds,) = struct.unpack(">I", options[after:after + 4])
        assert rounds == int(record["rounds"])
        offset += 4                                   # the number of keys
        _public, offset = _ssh_string(body, offset)
        private, _ = _ssh_string(body, offset)

        key_len = int(cipher_name[3:6]) // 8
        derived = allcrypt.bcrypt_pbkdf(record["passphrase"].encode(), salt, rounds,
                                        key_len + 16)
        mode = modes.CTR(derived[key_len:]) if cipher_name.endswith("ctr") \
            else modes.CBC(derived[key_len:])
        first = Cipher(algorithms.AES(derived[:key_len]), mode).decryptor() \
            .update(private[:16])
        check1, check2 = struct.unpack(">II", first[:8])
        assert check1 == check2, record["name"]
        opened += 1
    assert opened >= 6


def test_bitlocker_stretch_against_hashlib():
    """2^20 rounds of SHA-256 over the previous hash, the initial hash,
    the salt and the round number as 64 bits little endian."""
    initial, salt = os.urandom(32), os.urandom(16)
    last = bytes(32)
    for i in range(1 << 20):
        last = hashlib.sha256(last + initial + salt + struct.pack("<Q", i)).digest()
    assert allcrypt.bitlocker_stretch(initial, salt) == last


# ----------------------------------------------------------------- 802.11 ---

def test_ieee80211_prf_against_hmac():
    for bits in (128, 160, 256, 384, 512):
        key, label, data = os.urandom(32), b"Pairwise key expansion", os.urandom(76)
        out = b""
        i = 0
        while len(out) * 8 < bits:
            out += hmac.new(key, label + b"\0" + data + bytes([i]), "sha1").digest()
            i += 1
        assert allcrypt.ieee80211_prf(key, label, data, bits) == out[:bits // 8]


def test_ieee80211_kdf_sha256_against_hmac():
    for bits in (128, 256, 384, 512, 704):
        key, label, context = os.urandom(32), b"Pairwise key expansion", os.urandom(76)
        out = b""
        i = 1
        while len(out) * 8 < bits:
            out += hmac.new(key, struct.pack("<H", i) + label + context +
                            struct.pack("<H", bits), "sha256").digest()
            i += 1
        assert allcrypt.ieee80211_kdf_sha256(key, label, context, bits) == out[:bits // 8]


def tkip_rows():
    text = (ROOT / "vectors" / "tkip.vec").read_text()
    rows = []
    for chunk in text.split("\n\n"):
        fields = dict(line.split(" = ") for line in chunk.splitlines()
                      if " = " in line and not line.startswith("#"))
        if fields:
            rows.append({k: bytes.fromhex(v) for k, v in fields.items()})
    return rows


def test_tkip_frames_against_rc4_and_crc32():
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
    rows = tkip_rows()
    assert len(rows) >= 10
    for row in rows:
        tsc = int.from_bytes(row["tsc"], "big")
        plaintext = os.urandom(1 + tsc % 300)
        with_icv = plaintext + struct.pack("<I", zlib.crc32(plaintext))
        theirs = Cipher(ARC4(row["rc4_key"]), None).encryptor().update(with_icv)
        assert allcrypt.tkip_encrypt(row["tk"], row["ta"], tsc, plaintext) == theirs
        assert allcrypt.tkip_decrypt(row["tk"], row["ta"], tsc, theirs) == plaintext
        damaged = bytearray(theirs)
        damaged[0] ^= 1
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.tkip_decrypt(row["tk"], row["ta"], tsc, bytes(damaged))


def test_tkip_msdu_mic_is_michael_over_the_header():
    da, sa, data = os.urandom(6), os.urandom(6), os.urandom(100)
    key = os.urandom(8)
    for priority in (0, 5, 7):
        assert allcrypt.tkip_msdu_mic(key, da, sa, priority, data) == \
            allcrypt.michael(key, da + sa + bytes([priority, 0, 0, 0]) + data)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.tkip_encrypt(bytes(16), bytes(6), 1 << 48, b"x")
