"""Database and forum password hashes through the Python bindings,
against vectors/app_passwords.vec (MariaDB's hash_password, WordPress's
phpass, PHP's md5/sha1), recorded by scripts/make_app_password_vectors.py.
Offline."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "app_passwords.vec")


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def rows():
    out = []
    with open(VECTORS) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            scheme, *words = line.split()
            out.append((scheme, dict(w.split("=", 1) for w in words)))
    assert len(out) > 100
    return out


ROWS = rows()


def test_vectors():
    seen = {}
    for scheme, f in ROWS:
        pw = unhex(f["password"])
        if scheme == "mysql_old":
            got = allcrypt.mysql_old_password(pw)
        elif scheme == "mysql_password":
            got = allcrypt.mysql_password(pw)
        elif scheme == "postgres_md5":
            got = allcrypt.postgres_md5(pw, unhex(f["user"]))
        elif scheme == "vbulletin":
            got = allcrypt.vbulletin_password(pw, unhex(f["salt"]))
        elif scheme == "phpass":
            got = allcrypt.phpass(pw, f["setting"])
            assert allcrypt.phpass_verify(pw, f["hash"]), f
        else:
            raise AssertionError(scheme)
        assert got == f["hash"], (scheme, f)
        seen[scheme] = seen.get(scheme, 0) + 1
    assert set(seen) == {"mysql_old", "mysql_password", "postgres_md5", "vbulletin", "phpass"}


def test_phpass_rejects_bad_settings():
    with pytest.raises(ValueError):
        allcrypt.phpass(b"x", "$1$saltsalt")      # not $P$/$H$
    with pytest.raises(ValueError):
        allcrypt.phpass(b"x", "$P$0saltsalt")      # cost 0 < 7
    assert allcrypt.phpass_verify(b"x", "short") is False


def test_mysql_old_skips_whitespace():
    assert allcrypt.mysql_old_password(b"my pass") == allcrypt.mysql_old_password(b"mypass")
