"""Kerberos RC4-HMAC (RFC 4757) through the Python bindings, against
vectors/rc4_hmac.vec (written by scripts/make_rc4_hmac_vectors.py: MIT
Kerberos, Apache Kerby and impacket agreeing). The Rust tests hold every
row too; this checks the binding's names, its keyword arguments and its
refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "rc4_hmac.vec")


def rows(kind):
    out = []
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                out.append(dict(w.split("=", 1) for w in line.split()[1:]))
    return out


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def test_every_ciphertext():
    count = 0
    for r in rows("encrypt"):
        export = r["enctype"] == "24"
        key, usage = unhex(r["key"]), int(r["usage"])
        plain, cipher = unhex(r["plain"]), unhex(r["cipher"])
        made = allcrypt.kerberos_rc4_hmac_encrypt(key, usage, plain,
                                                  confounder=unhex(r["confounder"]),
                                                  export=export)
        assert made == cipher
        assert allcrypt.kerberos_rc4_hmac_decrypt(key, usage, cipher, export=export) == plain
        count += 1
    assert count == 364


def test_checksums_prf_and_keys():
    for r in rows("checksum"):
        assert allcrypt.kerberos_rc4_hmac_checksum(unhex(r["key"]), int(r["usage"]),
                                                   unhex(r["data"])) == unhex(r["checksum"])
    for r in rows("prf"):
        assert allcrypt.kerberos_rc4_hmac_prf(unhex(r["key"]), unhex(r["input"])) \
            == unhex(r["output"])
    for r in rows("s2k"):
        password = unhex(r["password"]).decode()
        assert allcrypt.kerberos_rc4_hmac_string_to_key(password) == unhex(r["key"])
    # The key is the NT hash.
    assert allcrypt.kerberos_rc4_hmac_string_to_key("pw") == allcrypt.nt_hash("pw")


def test_refusals():
    key = allcrypt.kerberos_rc4_hmac_string_to_key("password")
    sealed = allcrypt.kerberos_rc4_hmac_encrypt(key, 2, b"payload")
    assert allcrypt.kerberos_rc4_hmac_decrypt(key, 2, sealed) == b"payload"
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kerberos_rc4_hmac_decrypt(key, 2, sealed, export=True)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kerberos_rc4_hmac_decrypt(key, 8, sealed)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kerberos_rc4_hmac_encrypt(key[:8], 2, b"")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kerberos_rc4_hmac_encrypt(key, 2, b"", confounder=b"short")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kerberos_rc4_hmac_decrypt(key, 2, bytes(23))
