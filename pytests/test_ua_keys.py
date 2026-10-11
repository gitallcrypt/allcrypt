"""Ukrainian key containers through the Python surface: the files in
`tests/keys/ua/` open to the keys dstu-engine's keylib found in them
(`vectors/ua_keys.vec`, recorded by `scripts/check_ua_keys.py`), and the
containers Python writes read back."""

import pathlib

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "keys" / "ua"


def rows():
    out = []
    for line in (ROOT / "vectors" / "ua_keys.vec").read_text().splitlines():
        if line and not line.startswith("#"):
            fields = dict(word.split("=", 1) for word in line.split(" "))
            password = b"" if fields["password"] == "-" else bytes.fromhex(fields["password"])
            out.append((fields["file"], fields["format"], password, fields["keys"].split(",")))
    return out


ROWS = rows()


def numbers(key):
    m = int(key.curve.rsplit("m", 1)[1])
    width = (m + 7) // 8 * 2
    q = key.public_key().public_bytes()
    half = len(q) // 2
    d = int.from_bytes(key.private_bytes(), "big")
    qx, qy = int.from_bytes(q[:half], "big"), int.from_bytes(q[half:], "big")
    return f"{m}:{d:0{width}x}:{qx:0{width}x}:{qy:0{width}x}"


def test_the_record_is_whole():
    assert len(ROWS) == 24


@pytest.mark.parametrize("name,fmt,password,keys", ROWS, ids=[r[0] for r in ROWS])
def test_container_opens_to_the_keys_keylib_found(name, fmt, password, keys):
    data = (FIXTURES / name).read_bytes()
    assert [numbers(k) for k in allcrypt.dstu4145_keys_open(data, password)] == keys
    if fmt != "pkcs8":
        with pytest.raises(Exception, match="Wrong password" if fmt == "key6" else None):
            allcrypt.dstu4145_keys_open(data, password + b"x")


@pytest.mark.parametrize("certificate,key", [
    ("SELF_SIGNED1.cer", "PRIV1.cer"),
    ("SELF_SIGNED_ENC_40A0.cer", "Key40A0.cer"),
    ("SELF_SIGNED_ENC_6929.cer", "Key6929.cer"),
    ("SELF_SIGNED_ENC_E54B.cer", "KeyE54B.cer")])
def test_key_id_is_the_certificates_subject_key_identifier(certificate, key):
    der = (FIXTURES / certificate).read_bytes()
    # The extension found by its OID: these certificates' authority key
    # identifiers are malformed, so no strict parser takes them whole.
    at = der.index(bytes.fromhex("0603551d0e"))
    inner = der.index(b"\x04\x20", at + 5)
    ski = der[inner + 2:inner + 34]
    found = allcrypt.dstu4145_keys_open((FIXTURES / key).read_bytes(), b"")[0]
    assert found.key_id() == ski
    assert found.public_key().key_id() == ski


@pytest.mark.parametrize("second_curve", [None, "dstu4145-m431"])
def test_written_containers_read_back(second_curve):
    key = allcrypt.Dstu4145Key.generate("dstu4145-m173")
    second = allcrypt.Dstu4145Key.generate(second_curve) if second_curve else None
    expected = [numbers(key)] + ([numbers(second)] if second else [])
    password = "пароль".encode()
    plain = key.private_key_info(second)
    encrypted = allcrypt.encrypt_private_key(plain, password, "gost28147-cfb", iterations=3)
    pem = allcrypt.encrypt_private_key(plain, password, "gost28147-cfb", iterations=3, pem=True)
    key6 = allcrypt.dstu4145_key6(key, password, second)
    for data, pw in [(plain, b""), (encrypted, password), (pem, password), (key6, password)]:
        assert [numbers(k) for k in allcrypt.dstu4145_keys_open(data, pw)] == expected
    # The writer has no randomness: the same keys, the same bytes.
    assert key.private_key_info(second) == plain
    assert allcrypt.dstu4145_key6(key, password, second) == key6
