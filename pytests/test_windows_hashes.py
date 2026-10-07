"""The NT and LM password hashes through the Python surface, against
`vectors/windows_hashes.vec` (Samba's and impacket's LM hashes, OpenSSL's
MD4 for NT), and the two rules the Rust tests also pin: ASCII-only
uppercasing for LM, and a refusal past fourteen bytes."""

import pathlib

import pytest

import allcrypt

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "windows_hashes.vec"


def rows():
    section, password, out = None, None, []
    for line in VECTORS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.strip("[]")
            continue
        key, value = line.split(" = ")
        value = b"" if value == "-" else bytes.fromhex(value)
        if key == "password":
            password = value
        else:
            out.append((section, password, value))
    return out


def test_the_vectors():
    lm = [(p, h) for s, p, h in rows() if s == "LM"]
    nt = [(p, h) for s, p, h in rows() if s == "NT"]
    assert (len(lm), len(nt)) == (78, 10)
    for password, hash_ in lm:
        assert allcrypt.lm_hash(password) == hash_, password
    for password, hash_ in nt:
        assert allcrypt.nt_hash(password.decode("utf-8")) == hash_, password


def test_lm_uppercases_ascii_letters_only():
    assert allcrypt.lm_hash(b"secret") == allcrypt.lm_hash(b"SECRET")
    # e-acute and its uppercase in code page 850: different bytes, and
    # which is the uppercase of which is the code page's business.
    assert allcrypt.lm_hash(b"\xe9") != allcrypt.lm_hash(b"\x90")
    assert allcrypt.lm_hash("\xe9".upper().encode("cp850")) == allcrypt.lm_hash(b"\x90")


def test_lm_refuses_a_password_it_has_no_hash_for():
    allcrypt.lm_hash(b"a" * 14)
    with pytest.raises(ValueError, match="at most 14 bytes"):
        allcrypt.lm_hash(b"a" * 15)


def test_lm_takes_any_bytes_like():
    assert allcrypt.lm_hash(bytearray(b"pw")) == allcrypt.lm_hash(memoryview(b"pw"))
