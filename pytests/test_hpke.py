"""HPKE (RFC 9180, with draft-ietf-hpke-pq's KEMs) through the Python
bindings.

The bindings are translation only; the scheme is checked in
`src/publickey_ciphers/hpke.rs` against RFC 9180's appendix, the CFRG's
and the PQ draft's vector files, and transcripts from pyhpke and
filippo.io/hpke. These tests are for the surface: that the published
vectors are reachable from Python - `randomness` makes a sender
deterministic - that the mode follows from the arguments, and that a
context keeps its order.
"""

import pathlib

import pytest

import allcrypt

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "hpke.vec"


def _vectors():
    out = []
    for line in VECTORS.read_text().splitlines():
        if line.startswith("#"):
            continue
        fields = dict(part.split("=", 1) for part in line.split(" "))
        out.append(fields)
    return out


def _b(text):
    return b"" if text in ("-", "") else bytes.fromhex(text)


def test_the_vector_file_through_python():
    vectors = _vectors()
    assert len(vectors) == 141
    checked = 0
    for v in vectors:
        suite = allcrypt.HpkeSuite.from_ids(int(v["kem_id"]), int(v["kdf_id"]), int(v["aead_id"]))
        sk_r, pk_r = suite.derive_key_pair(_b(v["ikmR"]))
        assert pk_r == _b(v["pkRm"])
        sender = suite.derive_key_pair(_b(v["ikmS"])) if v.get("ikmS", "-") != "-" else None
        psk = (_b(v["psk"]), _b(v["psk_id"])) if v.get("psk", "-") != "-" else None
        info = _b(v.get("info", "-"))
        enc, sealer = suite.setup_sender(pk_r, info, psk, sender[0] if sender else None,
                                         _b(v["ikmE"]))
        assert enc == _b(v["enc"])
        opener = suite.setup_receiver(enc, sk_r, info, psk, sender[1] if sender else None)
        if v["encryptions"] != "-":
            seq, aad, pt, ct = v["encryptions"].split(",")[0].split(":")
            assert seq == "0"
            assert sealer.seal(_b(pt), _b(aad)) == _b(ct)
            assert opener.open(_b(ct), _b(aad)) == _b(pt)
            assert (sealer.sequence, opener.sequence) == (1, 1)
        context, length, value = v["exports"].split(",")[0].split(":")
        assert opener.export(_b(context), int(length)) == _b(value)
        checked += 1
    assert checked == 141


def test_names_and_modes():
    kems, kdfs, aeads = allcrypt.hpke_names()
    assert "MLKEM768-X25519" in kems and "SHAKE256" in kdfs and "export only" in aeads
    suite = allcrypt.HpkeSuite("X25519", "HKDF-SHA256", "ChaCha20Poly1305")
    assert suite.ids == (0x20, 1, 3)
    assert suite.names == ("DHKEM(X25519, HKDF-SHA256)", "HKDF-SHA256", "ChaCha20Poly1305")
    assert allcrypt.HpkeSuite("x-wing", "shake256", "aes-256-gcm").ids == (0x647A, 0x11, 2)
    sk, pk = suite.generate_key_pair()
    assert suite.public_key(sk) == pk
    sender_sk, sender_pk = suite.generate_key_pair()
    psk = (b"a pre-shared key, 32 bytes long.", b"its id")
    for options_send, options_open in [({}, {}), ({"psk": psk}, {"psk": psk}),
                                       ({"sender_private": sender_sk},
                                        {"sender_public": sender_pk}),
                                       ({"psk": psk, "sender_private": sender_sk},
                                        {"psk": psk, "sender_public": sender_pk})]:
        enc, ct = suite.seal(pk, b"message", info=b"info", aad=b"aad", **options_send)
        assert suite.open(enc, sk, ct, info=b"info", aad=b"aad", **options_open) == b"message"
        with pytest.raises(ValueError):
            suite.open(enc, sk, ct, info=b"other", aad=b"aad", **options_open)
    # A sender key on one side only is a different mode, and does not open.
    enc, ct = suite.seal(pk, b"message", sender_private=sender_sk)
    with pytest.raises(ValueError):
        suite.open(enc, sk, ct)
    with pytest.raises(ValueError):
        allcrypt.HpkeSuite("ML-KEM-768", "HKDF-SHA256", "AES-128-GCM").seal(
            b"\0" * 1184, b"m", sender_private=b"\0" * 64)
    # The TurboSHAKE KDFs, by name and by id; an unknown KDF is refused.
    turbo = allcrypt.HpkeSuite("X25519", "TurboSHAKE128", "AES-128-GCM")
    assert allcrypt.HpkeSuite.from_ids(0x20, 0x13, 1) is not None
    sk, pk = turbo.generate_key_pair()
    enc, ct = turbo.seal(pk, b"message", info=b"info")
    assert turbo.open(enc, sk, ct, info=b"info") == b"message"
    with pytest.raises(ValueError):
        allcrypt.HpkeSuite("X25519", "TurboSHAKE512", "AES-128-GCM")


def test_a_context_keeps_its_order():
    suite = allcrypt.HpkeSuite("P-256", "HKDF-SHA256", "AES-128-GCM")
    sk, pk = suite.derive_key_pair(b"\x07" * 32)
    enc, sealer = suite.setup_sender(pk, b"info")
    opener = suite.setup_receiver(enc, sk, b"info")
    first, second = sealer.seal(b"one"), sealer.seal(b"two")
    with pytest.raises(ValueError):
        opener.open(second)
    assert opener.sequence == 0
    assert opener.open(first) == b"one" and opener.open(second) == b"two"
    assert sealer.export(b"label", 16) == opener.export(b"label", 16)
    exporter = allcrypt.HpkeSuite("X25519", "SHAKE128", "export only")
    sk, pk = exporter.generate_key_pair()
    enc, context = exporter.setup_sender(pk)
    with pytest.raises(ValueError):
        context.seal(b"x")
    assert exporter.setup_receiver(enc, sk).export(b"", 70) == context.export(b"", 70)
