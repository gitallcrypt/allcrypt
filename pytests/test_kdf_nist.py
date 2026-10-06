"""SP 800-108, the Concat KDF and X9.63 against python-cryptography, and
RFC 3961's building blocks against the RFC's own appendix, read out of
the vendored text."""

import itertools
import os
import re

import pytest

import allcrypt

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import (CounterLocation, KBKDFCMAC, KBKDFHMAC,
                                                      Mode)
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF


def _kbkdf(prf, key, length, label, context):
    common = dict(mode=Mode.CounterMode, length=length, rlen=4, llen=4,
                  location=CounterLocation.BeforeFixed, label=label, context=context,
                  fixed=None)
    if prf.startswith("hmac-"):
        return KBKDFHMAC(algorithm=getattr(hashes, prf[5:].upper())(), **common).derive(key)
    return KBKDFCMAC(algorithm=algorithms.AES, **common).derive(key)


@pytest.mark.parametrize("prf", ["hmac-sha1", "hmac-sha256", "hmac-sha512", "cmac-aes"])
@pytest.mark.parametrize("length", [1, 16, 20, 33, 64, 100])
def test_kbkdf_counter_against_python_cryptography(prf, length):
    key = bytes(range(16)) if prf == "cmac-aes" else bytes(range(37))
    label, context = b"a label", bytes(range(9))
    assert allcrypt.kbkdf_counter(prf, key, length, label=label, context=context) == \
        _kbkdf(prf, key, length, label, context)


def test_kbkdf_counter_defaults_are_empty():
    assert allcrypt.kbkdf_counter("hmac-sha256", b"k", 32) == \
        allcrypt.kbkdf_counter("hmac-sha256", b"k", 32, label=b"", context=b"")


def test_kbkdf_feedback_first_block_by_hand():
    """K(1) = PRF(key, IV || [1]_32 || label || 00 || context || [L]_32),
    and K(2) chains on K(1)."""
    import hmac
    import hashlib
    key, iv, label, context = b"key", bytes(32), b"L", b"C"
    fixed = label + b"\0" + context + (48 * 8).to_bytes(4, "big")
    k1 = hmac.new(key, iv + (1).to_bytes(4, "big") + fixed, hashlib.sha256).digest()
    k2 = hmac.new(key, k1 + (2).to_bytes(4, "big") + fixed, hashlib.sha256).digest()
    out = allcrypt.kbkdf_feedback("hmac-sha256", key, 48, iv=iv, label=label, context=context)
    assert out == (k1 + k2)[:48]


def test_kbkdf_refuses_an_unknown_prf():
    for prf in ("sha256", "hmac-nosuch"):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.kbkdf_counter(prf, b"k", 16)


@pytest.mark.parametrize("hash_name", ["sha1", "sha256", "sha384", "sha512"])
@pytest.mark.parametrize("length", [1, 32, 65, 129])
def test_concat_and_x963_against_python_cryptography(hash_name, length):
    algorithm = getattr(hashes, hash_name.upper())
    z, info = bytes(range(40)), b"other info"
    assert allcrypt.concat_kdf(z, length, other_info=info, hash=hash_name) == \
        ConcatKDFHash(algorithm(), length, info).derive(z)
    assert allcrypt.x963_kdf(z, length, shared_info=info, hash=hash_name) == \
        X963KDF(algorithm(), length, info).derive(z)


def test_concat_and_x963_differ():
    assert allcrypt.concat_kdf(b"z", 32) != allcrypt.x963_kdf(b"z", 32)


# RFC 3961's appendix A.

def _rfc3961(start, end):
    path = os.path.join(os.path.dirname(__file__), "..", "rfcs", "rfc3961.txt")
    text = open(path).read()
    at = text.index("\n" + start + "  ")
    return text[at:text.index("\n" + end + "  ", at)]


def test_rfc_3961_nfold():
    text = " ".join(_rfc3961("A.1.", "A.2.").split())
    found = 0
    for m in re.finditer(r"(\d+)-fold\(([^)]*)\)\s*=", text):
        bits, inner = int(m[1]), m[2]
        # The result is the whole tokens of hex after `=`; `64-fold(` is
        # the next line's start, not a result.
        output = "".join(itertools.takewhile(lambda t: re.fullmatch("[0-9a-fA-F]+", t),
                                             text[m.end():].split()))
        if not output:
            continue
        if inner.startswith('"'):
            data = inner.strip('"').encode()
        else:
            data = bytes.fromhex("".join(inner.split()))
        assert allcrypt.kerberos_nfold(data, bits // 8) == bytes.fromhex(output), m[0]
        found += 1
    assert found == 11


def test_rfc_3961_des3_derive_random_and_key():
    found = 0
    for line in _rfc3961("A.3.", "A.4.").splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] == "key:":
            key = bytes.fromhex(tokens[1])
        elif tokens[0] == "usage:":
            usage = bytes.fromhex(tokens[1])
        elif tokens[0] == "DR:":
            dr = allcrypt.kerberos_derive_random("3des", key, usage, 21)
            assert dr == bytes.fromhex(tokens[1])
        elif tokens[0] == "DK:":
            assert allcrypt.kerberos_random_to_key("3des", dr) == bytes.fromhex(tokens[1])
            found += 1
    assert found == 9


def test_rfc_3961_des_string_to_key():
    lines = _rfc3961("A.2.", "A.3.").split("This trace")[0].splitlines()

    def value(i):
        last = lines[i].split()[-1]
        if all(c in "0123456789abcdefABCDEF" for c in last) and not lines[i].rstrip().endswith('"'):
            return bytes.fromhex(last)
        return bytes.fromhex(lines[i + 1].strip())

    found = 0
    for i, line in enumerate(lines):
        line = line.lstrip()
        if line.startswith("salt:"):
            salt = value(i)
        elif line.startswith("password:"):
            password = value(i)
        elif line.startswith("DES key:"):
            assert allcrypt.kerberos_des_string_to_key(password, salt) == value(i)
            found += 1
    assert found == 6


def test_random_to_key_lengths_and_names():
    assert allcrypt.kerberos_random_to_key("des", bytes(7)) == bytes([1] * 7 + [0xf1])
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kerberos_random_to_key("des", bytes(8))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kerberos_random_to_key("aes", bytes(16))
