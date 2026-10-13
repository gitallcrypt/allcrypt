"""Ukraine's ten GOST S-boxes through the Python bindings. The Rust tests
hold every row of vectors/dstu_dke.vec; this checks the names reach the
cipher, the MAC, the hash and gost_sbox."""

import os

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "dstu_dke.vec")


def rows(kind):
    with open(VECTORS) as f:
        for line in f:
            if line.startswith(kind + " "):
                yield dict(w.split("=", 1) for w in line.split()[1:])


def test_the_tables_by_name():
    tables = list(rows("dke"))
    assert len(tables) == 10
    assert allcrypt.gost_sbox("dstu-dke-1") == allcrypt.gost_sbox("dstu4145-default-dke")
    boxes = [allcrypt.gost_sbox(f"dstu-dke-{n}") for n in range(1, 11)]
    assert len({str(b) for b in boxes}) == 10


def test_cipher_mac_and_hash():
    seen = set()
    for r in rows("gost-ecb"):
        cipher = allcrypt.Cipher("gost", bytes.fromhex(r["key"]), f"dstu-dke-{r['dke']}")
        assert cipher.encrypt("ecb", bytes.fromhex(r["pt"])).hex() == r["ct"]
        seen.add(r["dke"])
    for r in rows("gost-cfb"):
        cipher = allcrypt.Cipher("gost", bytes.fromhex(r["key"]), f"dstu-dke-{r['dke']}")
        ct = cipher.encryptor("cfb", bytes.fromhex(r["iv"])).update(bytes.fromhex(r["pt"]))
        assert ct.hex() == r["ct"]
    for r in rows("gost-mac"):
        tag = allcrypt.gost28147_mac(bytes.fromhex(r["key"]), bytes.fromhex(r["msg"]),
                                     sbox=f"dstu-dke-{r['dke']}")
        assert tag.hex() == r["tag"]
    for r in rows("gost34311"):
        name = f"gost34311_dke{r['dke']}"
        assert name in allcrypt.algorithms_available
        assert allcrypt.new(name, bytes.fromhex(r["msg"])).hexdigest() == r["digest"]
    assert seen == {str(n) for n in range(2, 11)}
