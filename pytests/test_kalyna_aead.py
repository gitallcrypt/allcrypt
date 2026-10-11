"""DSTU 7624's GCM, GMAC, CCM and XTS over Kalyna through the Python
bindings. The Rust tests hold every row of vectors/kalyna_aead.vec in
both directions; this checks the binding - the catalogue names, a sample
of rows through `Aead` and the functions, and the refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "kalyna_aead.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                fields = dict(w.split("=", 1) for w in line.split()[1:])
                yield {k: (bytes.fromhex(v) if k not in ("block", "q", "nb", "source")
                           and v != "-" else (b"" if v == "-" else v))
                       for k, v in fields.items()}


def test_the_names_are_in_the_catalogue():
    for bits in (128, 256, 512):
        for mode in ("gcm", "ccm"):
            assert f"kalyna-{bits}-{mode}" in allcrypt.aeads_available


def test_gcm_rows_through_aead():
    count = 0
    for r in rows("gcm"):
        name = f"kalyna-{8 * int(r['block'])}-gcm-{r['q']}"
        aead = allcrypt.Aead(r["key"], name)
        assert aead.encrypt(r["iv"], r["pt"], r["aad"]) == r["ct"] + r["tag"]
        assert aead.decrypt(r["iv"], r["ct"] + r["tag"], r["aad"]) == r["pt"]
        count += 1
    assert count >= 150


def test_gcm_tag_does_not_cover_the_iv():
    """The tag is E(B xor lengths): another IV opens with the same tag
    and gives another plaintext. That is the mode, as both witnesses and
    the standard's examples have it."""
    r = next(r for r in rows("gcm") if r["source"] == "standard")
    aead = allcrypt.Aead(r["key"], f"kalyna-{8 * int(r['block'])}-gcm")
    other_iv = bytes([r["iv"][0] ^ 1]) + r["iv"][1:]
    opened = aead.decrypt(other_iv, r["ct"] + r["tag"], r["aad"])
    assert opened != r["pt"] and len(opened) == len(r["pt"])


def test_gmac_rows():
    count = 0
    for r in rows("gmac"):
        cipher = f"kalyna-{8 * int(r['block'])}"
        assert allcrypt.kalyna_gmac(cipher, r["key"], r["msg"], int(r["q"])) == r["tag"]
        count += 1
    assert count >= 50


def test_ccm_rows():
    count = 0
    for r in rows("ccm"):
        cipher = f"kalyna-{8 * int(r['block'])}"
        q, nb = int(r["q"]), int(r["nb"])
        assert allcrypt.kalyna_ccm_encrypt(cipher, r["key"], r["iv"], r["aad"], r["pt"], q,
                                           nb) == r["sealed"]
        assert allcrypt.kalyna_ccm_decrypt(cipher, r["key"], r["iv"], r["aad"], r["sealed"], q,
                                           nb) == r["pt"]
        if nb == 4:
            aead = allcrypt.Aead(r["key"], f"{cipher}-ccm-{q}")
            assert aead.encrypt(r["iv"], r["pt"], r["aad"]) == r["sealed"]
        count += 1
    assert count >= 200


def test_ccm_refuses_an_altered_message():
    r = next(rows("ccm"))
    cipher, q, nb = f"kalyna-{8 * int(r['block'])}", int(r["q"]), int(r["nb"])
    sealed = bytearray(r["sealed"])
    sealed[0] ^= 1
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kalyna_ccm_decrypt(cipher, r["key"], r["iv"], r["aad"], bytes(sealed), q, nb)


def test_xts_rows():
    count = 0
    for r in rows("xts"):
        cipher = f"kalyna-{8 * int(r['block'])}"
        assert allcrypt.kalyna_xts_encrypt(cipher, r["key"], r["iv"], r["pt"]) == r["ct"]
        assert allcrypt.kalyna_xts_decrypt(cipher, r["key"], r["iv"], r["ct"]) == r["pt"]
        count += 1
    assert count >= 40


@pytest.mark.parametrize("call", [
    lambda: allcrypt.Aead(bytes(16), "kalyna-128-gcm").encrypt(bytes(12), b"m"),
    lambda: allcrypt.Aead(bytes(16), "kalyna-128-gcm-7"),
    lambda: allcrypt.Aead(bytes(16), "kalyna-128-ccm-12"),
    lambda: allcrypt.kalyna_gmac("kalyna-128", bytes(16), b"", 7),
    lambda: allcrypt.kalyna_ccm_encrypt("kalyna-128", bytes(16), bytes(16), b"", b"m", 16, 0),
    lambda: allcrypt.kalyna_xts_encrypt("kalyna-128", bytes(16), bytes(16), bytes(15)),
    lambda: allcrypt.kalyna_xts_encrypt("aes", bytes(16), bytes(16), bytes(16)),
])
def test_refusals(call):
    with pytest.raises(allcrypt.CryptoError):
        call()
