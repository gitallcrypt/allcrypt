"""FEAL through the Python bindings. The Rust tests hold NTT's FEAL-NX data
and the rows of vectors/feal.vec, on which zilijonas/FEAL-NX's Java and
Donaldduck8's Python agree; this checks the binding: the two names, the
round count as the cipher's parameter, the single blocks through
`Cipher`, NTT's first blocks, every mode, the AEADs, and the refused key
lengths and round counts."""

import os

import pytest

import allcrypt

HERE = os.path.dirname(__file__)
VECTORS = os.path.join(HERE, "..", "vectors", "feal.vec")
NTT = os.path.join(HERE, "..", "vectors", "feal_nx_ntt.txt")
# Each name: its key length and its default round count.
NAMES = {"feal": (8, 8), "feal-nx": (16, 32)}


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_feal_is_in_the_catalogues():
    for name in NAMES:
        assert name in allcrypt.block_ciphers_available
        for suffix in ("-eax", "-mgm"):
            assert name + suffix in allcrypt.aeads_available
    assert "feal-ocb" not in allcrypt.aeads_available


@pytest.mark.parametrize("name", NAMES)
def test_vectors_through_cipher(name):
    _, default = NAMES[name]
    count, counts = 0, set()
    for fields in rows(name):
        key, pt = bytes.fromhex(fields["key"]), bytes.fromhex(fields["pt"])
        rounds = int(fields["rounds"])
        cipher = (allcrypt.Cipher(name, key) if rounds == default
                  else allcrypt.Cipher(name, key, str(rounds)))
        assert cipher.encrypt("ecb", pt).hex() == fields["ct"], fields
        assert cipher.decrypt("ecb", bytes.fromhex(fields["ct"])) == pt, fields
        count += 1
        counts.add(rounds)
    assert count >= 700
    assert len(counts) == 4


def test_ntt_first_blocks():
    with open(NTT, "rb") as f:
        lines = [line.strip() for line in f.read().split(b"\n")]
    at = lines.index(b"KEY = 000102030405060708090A0B0C0D0E0F")
    cipher = allcrypt.Cipher("feal-nx", bytes.fromhex("000102030405060708090A0B0C0D0E0F"))
    checked = 0
    for line in lines[at + 1:at + 65]:
        pt, ct = line.decode().replace("PT: ", "").replace("CT: ", "").split(",")
        assert cipher.encrypt("ecb", bytes.fromhex(pt)).hex() == ct.strip().lower()
        checked += 1
    assert checked == 64


@pytest.mark.parametrize("name", NAMES)
def test_every_mode_round_trips(name):
    keylen, _ = NAMES[name]
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher(name, bytes(range(keylen)))
        iv = None if mode == "ecb" else bytes(8)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


@pytest.mark.parametrize("name,suffix", [(n, s) for n in NAMES for s in ("-eax", "-mgm")])
def test_aeads_round_trip(name, suffix):
    keylen, _ = NAMES[name]
    key, nonce = bytes(keylen), bytes(8)
    sealed = allcrypt.Aead(key, name + suffix).encrypt(nonce, b"message", b"header")
    assert allcrypt.Aead(key, name + suffix).decrypt(nonce, sealed, b"header") == b"message"


@pytest.mark.parametrize("name,length", [(n, length) for n, (k, _) in NAMES.items()
                                         for length in (0, 7, 8, 9, 15, 16, 17, 24)
                                         if length != k])
def test_other_key_lengths_are_refused(name, length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, bytes(length))


@pytest.mark.parametrize("rounds", [0, 1, 7, 1025, 2000])
def test_other_round_counts_are_refused(rounds):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("feal", bytes(8), str(rounds))
