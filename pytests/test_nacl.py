"""NaCl's boxes through the Python bindings, against vectors/nacl.vec:
NaCl's own examples and libsodium's answers, with golang.org/x/crypto
agreeing where it can. scripts/make_nacl_vectors.py writes the file."""

import os

import pytest

import allcrypt

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(os.path.dirname(HERE), "vectors", "nacl.vec")


def load():
    rows = {}
    with open(VECTORS) as handle:
        for line in handle:
            if line.startswith("#") or not line.strip():
                continue
            kind, *fields = line.split()
            row = {}
            for field in fields:
                name, value = field.split("=", 1)
                if value == "-":
                    row[name] = b""
                elif value == "refused" or name in ("construction", "source", "block",
                                                     "length"):
                    row[name] = value
                else:
                    row[name] = bytes.fromhex(value)
            rows.setdefault(kind, []).append(row)
    return rows


ROWS = load()

COUNTS = {"hsalsa20": 26, "xsalsa20": 5, "xsalsa20_sha256": 1, "secretbox": 175,
          "beforenm": 47, "box": 33, "box_open": 1, "seal": 32, "box_seed_keypair": 16,
          "kx_seed_keypair": 16, "kx": 16, "auth": 8, "sign": 8, "ed25519_to_x25519": 16,
          "ed25519_public_to_x25519": 33}


def test_every_kind_is_present_and_counted():
    # A loader that finds nothing turns every test below into a pass.
    assert {kind: len(rows) for kind, rows in ROWS.items()} == COUNTS


def test_box_constructions_are_listed():
    assert allcrypt.box_constructions_available == [
        "xsalsa20poly1305", "xchacha20poly1305",
        "curve25519xsalsa20poly1305", "curve25519xchacha20poly1305"]


def test_hsalsa20():
    for row in ROWS["hsalsa20"]:
        assert allcrypt.hsalsa20(row["key"], row["input"]) == row["out"]


def test_secretbox():
    for row in ROWS["secretbox"]:
        c, key, nonce = row["construction"], row["key"], row["nonce"]
        assert allcrypt.secretbox_encrypt(key, nonce, row["message"], c) == row["boxed"]
        assert allcrypt.secretbox_decrypt(key, nonce, row["boxed"], c) == row["message"]
        ciphertext, tag = allcrypt.secretbox_encrypt_detached(key, nonce, row["message"], c)
        assert tag + ciphertext == row["boxed"]
        assert allcrypt.secretbox_decrypt_detached(key, nonce, ciphertext, tag, c) == \
            row["message"]


def test_the_default_construction_is_nacls():
    row = next(r for r in ROWS["secretbox"] if r.get("source") == "nacl")
    assert allcrypt.secretbox_encrypt(row["key"], row["nonce"], row["message"]) == row["boxed"]


def test_a_tampered_box_raises_and_returns_nothing():
    row = ROWS["secretbox"][40]
    bad = bytearray(row["boxed"])
    bad[-1] ^= 1
    with pytest.raises(allcrypt.CryptoError, match="did not authenticate"):
        allcrypt.secretbox_decrypt(row["key"], row["nonce"], bytes(bad), row["construction"])


def test_beforenm_and_low_order_refusals():
    for row in ROWS["beforenm"]:
        if row["key"] == "refused":
            with pytest.raises(allcrypt.CryptoError):
                allcrypt.box_beforenm(row["public"], row["private"], row["construction"])
        else:
            assert allcrypt.box_beforenm(row["public"], row["private"],
                                         row["construction"]) == row["key"]


def test_box():
    for row in ROWS["box"]:
        args = (row["public"], row["private"], row["nonce"])
        assert allcrypt.box_encrypt(*args, row["message"], row["construction"]) == row["boxed"]
        assert allcrypt.box_decrypt(*args, row["boxed"], row["construction"]) == row["message"]
    row = ROWS["box_open"][0]
    assert allcrypt.box_decrypt(row["public"], row["private"], row["nonce"], row["boxed"]) \
        == row["message"]


def test_sealed_boxes_from_libsodium_open():
    for row in ROWS["seal"]:
        assert allcrypt.box_seal_open(row["public"], row["private"], row["sealed"],
                                      row["construction"]) == row["message"]


def test_our_sealed_boxes_open_and_differ_each_time():
    private, public = allcrypt.box_keypair()
    for construction in ("xsalsa20poly1305", "xchacha20poly1305"):
        first = allcrypt.box_seal(public, b"secret", construction)
        second = allcrypt.box_seal(public, b"secret", construction)
        assert first != second
        assert len(first) == 48 + 6
        for sealed in (first, second):
            assert allcrypt.box_seal_open(public, private, sealed, construction) == b"secret"


def test_key_pairs_and_session_keys():
    for kind, derive in (("box_seed_keypair", allcrypt.box_seed_keypair),
                         ("kx_seed_keypair", allcrypt.kx_seed_keypair)):
        for row in ROWS[kind]:
            assert derive(row["seed"]) == (row["private"], row["public"])
    for row in ROWS["kx"]:
        rx, tx = allcrypt.kx_client_session_keys(row["client_public"], row["client_private"],
                                                 row["server_public"])
        assert (rx, tx) == (row["client_rx"], row["client_tx"])
        assert allcrypt.kx_server_session_keys(row["server_public"], row["server_private"],
                                               row["client_public"]) == (tx, rx)


def test_auth_and_combined_signatures():
    for row in ROWS["auth"]:
        assert allcrypt.nacl_auth(row["key"], row["message"]) == row["tag"]
        assert allcrypt.nacl_auth_verify(row["key"], row["message"], row["tag"])
        assert not allcrypt.nacl_auth_verify(row["key"], row["message"] + b"x", row["tag"])
    for row in ROWS["sign"]:
        assert allcrypt.nacl_sign(row["seed"], row["message"]) == row["signed"]
        assert allcrypt.nacl_sign_open(row["public"], row["signed"]) == row["message"]


def test_ed25519_conversion():
    for row in ROWS["ed25519_to_x25519"]:
        assert allcrypt.ed25519_private_to_x25519(row["seed"]) == row["x_private"]
        assert allcrypt.ed25519_public_to_x25519(row["ed_public"]) == row["x_public"]
    for row in ROWS["ed25519_public_to_x25519"]:
        if row["x_public"] == "refused":
            with pytest.raises(allcrypt.CryptoError):
                allcrypt.ed25519_public_to_x25519(row["ed_public"])
        else:
            assert allcrypt.ed25519_public_to_x25519(row["ed_public"]) == row["x_public"]


def test_the_aead_name_is_refused_with_a_pointer():
    with pytest.raises(allcrypt.CryptoError, match="AEAD"):
        allcrypt.secretbox_encrypt(bytes(32), bytes(24), b"", "xchacha20-poly1305")


def test_xsalsa20_is_a_stream_cipher():
    row = next(r for r in ROWS["xsalsa20"] if r["block"] == "0")
    stream = allcrypt.StreamCipher("xsalsa20", row["key"], row["nonce"])
    assert stream.encrypt(bytes(192)) == row["out"]
