"""The GOST pieces reached on their own, against answers not ours.

gost-engine's answers in `vectors/gost_engine.vec` for the GOST
28147-89 MAC, CTR-ACPKM, KExp15 and TLSTREE; gost89's and Bouncy
Castle's in `vectors/dstu_gost.vec` for GOST 28147-89 and its MAC under
the DSTU 4145 default DKE; RFC 7836's worked examples for its two KDFs,
read out of the vendored document. Custom S-boxes and CryptoPro key
meshing are checked against GOST 28147-89 written here from the
standard, which is first held to the DSTU rows - and meshing's constant
`C` is read out of RFC 4357 rather than copied.
"""

import os
import pathlib
import random
import re
import struct

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent


def engine_section(name):
    """Records of one `[section]` of gost_engine.vec, as dicts of bytes
    (and `Section` as an int)."""
    text = (ROOT / "vectors" / "gost_engine.vec").read_text()
    body = text.split(f"\n[{name}]\n", 1)[1].split("\n[", 1)[0]
    records = []
    for chunk in body.strip().split("\n\n"):
        record = {}
        for line in chunk.splitlines():
            key, _, value = line.partition(" = ")
            record[key.strip()] = int(value) if key.strip() == "Section" \
                else bytes.fromhex(value.strip())
        records.append(record)
    return records


def dstu_rows(kind):
    text = (ROOT / "vectors" / "dstu_gost.vec").read_text()
    rows = []
    for line in text.splitlines():
        if line.startswith(kind + " "):
            rows.append({k: bytes.fromhex(v) for k, v in
                         (field.split("=", 1) for field in line.split()[1:])})
    return rows


def dke():
    (row,) = dstu_rows("dke")
    return row["value"]


# ---------------------------------------- GOST 28147-89, from the standard ---

def rows_from_dke(packed):
    """Row by row, high nibble first: the DKE's packing."""
    return [[n for b in packed[8 * r:8 * r + 8] for n in (b >> 4, b & 15)] for r in range(8)]


def reference_gost(key, rows, block, decrypt=False):
    k = struct.unpack("<8I", key)
    schedule = (list(k) + list(reversed(k)) * 3) if decrypt else (list(k) * 3 + list(reversed(k)))
    n1, n2 = struct.unpack("<2I", block)
    for i, subkey in enumerate(schedule):
        source = n1 if i % 2 == 0 else n2
        t = (source + subkey) & 0xffffffff
        s = 0
        for j in range(8):
            s |= rows[j][(t >> (4 * j)) & 15] << (4 * j)
        s = ((s << 11) | (s >> 21)) & 0xffffffff
        if i % 2 == 0:
            n2 ^= s
        else:
            n1 ^= s
    return struct.pack("<2I", n2, n1)


def test_the_reference_is_the_dstu_witnesses():
    rows = rows_from_dke(dke())
    checked = 0
    for row in dstu_rows("gost-ecb"):
        for i in range(0, len(row["pt"]), 8):
            pt, ct = row["pt"][i:i + 8], row["ct"][i:i + 8]
            assert reference_gost(row["key"], rows, pt) == ct
            assert reference_gost(row["key"], rows, ct, decrypt=True) == pt
            checked += 1
    assert checked == 22


def test_a_dke_given_to_cipher_is_the_dstu_witnesses():
    for row in dstu_rows("gost-ecb"):
        length = len(row["pt"])
        cipher = allcrypt.Cipher("gost", row["key"], dke=dke())
        assert cipher.encrypt("ecb", row["pt"])[:length] == row["ct"]
        assert allcrypt.Cipher("gost", row["key"], "dstu4145-default-dke") \
            .encrypt("ecb", row["pt"])[:length] == row["ct"]


def test_a_custom_sbox_against_the_reference():
    for seed in range(10):
        rng = random.Random(seed)
        rows = [rng.sample(range(16), 16) for _ in range(8)]
        key, block = os.urandom(32), os.urandom(8)
        cipher = allcrypt.Cipher("gost", key, sbox=rows)
        assert cipher.encrypt("ecb", block)[:8] == reference_gost(key, rows, block)
        # And in a mode, which builds the cipher again from the rows.
        assert cipher.decrypt("cbc", cipher.encrypt("cbc", block * 3, bytes(8)),
                              bytes(8)) == block * 3


def test_sbox_and_dke_are_refused_where_they_do_not_belong():
    rows = allcrypt.gost_sbox("id-tc26-gost-28147-param-Z")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("aes", bytes(16), sbox=rows)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("gost", bytes(32), "id-tc26-gost-28147-param-Z", sbox=rows)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("gost", bytes(32), sbox=rows, dke=dke())
    broken = [list(r) for r in rows]
    broken[2][0] = broken[2][1]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("gost", bytes(32), sbox=broken)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("gost", bytes(32), dke=dke()[:63])


def test_cryptopro_key_mesh_against_the_reference():
    text = (ROOT / "rfcs" / "rfc4357.txt").read_text(encoding="utf-8-sig")
    c_text = text[text.index("Where C = {"):].split("}", 1)[0]
    c = bytes(int(value, 16) for value in re.findall(r"0x([0-9A-Fa-f]{2})", c_text))
    assert len(c) == 32
    for name in ("id-Gost28147-89-CryptoPro-A-ParamSet", "id-tc26-gost-28147-param-Z"):
        rows = allcrypt.gost_sbox(name)
        for _ in range(5):
            key, iv = os.urandom(32), os.urandom(8)
            new_key = b"".join(reference_gost(key, rows, c[i:i + 8], decrypt=True)
                               for i in range(0, 32, 8))
            new_iv = reference_gost(new_key, rows, iv)
            assert allcrypt.cryptopro_key_mesh(key, iv, sbox=name) == (new_key, new_iv)
    assert allcrypt.cryptopro_key_mesh(key, iv) == \
        allcrypt.cryptopro_key_mesh(key, iv, sbox="id-Gost28147-89-CryptoPro-A-ParamSet")


# ------------------------------------------------------------------- MAC ---

@pytest.mark.parametrize("section,sbox", [("gost-mac", "id-Gost28147-89-CryptoPro-A-ParamSet"),
                                          ("gost-mac-12", "id-tc26-gost-28147-param-Z")])
def test_gost28147_mac_against_the_engine(section, sbox):
    records = engine_section(section)
    assert len(records) == 16
    for record in records:
        assert allcrypt.gost28147_mac(record["Key"], record["In"], sbox=sbox) == record["Out"]
        if section == "gost-mac":
            # CryptoPro-A and a zero IV are the defaults, as the engine's.
            assert allcrypt.gost28147_mac(record["Key"], record["In"]) == record["Out"]
        eight = allcrypt.gost28147_mac(record["Key"], record["In"], sbox=sbox, tag_size=8)
        assert eight[:4] == record["Out"]


def test_gost28147_mac_under_the_dstu_dke_against_the_witnesses():
    rows = dstu_rows("gost-mac")
    assert len(rows) == 9
    for row in rows:
        assert allcrypt.gost28147_mac(row["key"], row["msg"], sbox="dstu4145-default-dke",
                                      tag_size=len(row["tag"])) == row["tag"]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.gost28147_mac(bytes(32), b"m", tag_size=9)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.gost28147_mac(bytes(32), b"m", iv=bytes(7))


# ------------------------------------------------------- ACPKM, KExp15, TLSTREE ---

@pytest.mark.parametrize("cipher,count", [("kuznyechik", 5), ("magma", 6)])
def test_ctr_acpkm_against_the_engine(cipher, count):
    records = engine_section(f"{cipher}-ctr-acpkm")
    assert len(records) == count
    for r in records:
        assert allcrypt.ctr_acpkm(cipher, r["Key"], r["IV"], r["In"], r["Section"]) == r["Out"]
        assert allcrypt.ctr_acpkm(cipher, r["Key"], r["IV"], r["Out"], r["Section"]) == r["In"]


def test_acpkm_next_is_the_constant_under_the_key():
    """RFC 8645 4.1's D is 0x80 to 0x9f; the next key is it encrypted."""
    d = bytes(range(0x80, 0xa0))
    key = os.urandom(32)
    assert allcrypt.acpkm_next("kuznyechik", key) == \
        allcrypt.Cipher("kuznyechik", key).encrypt("ecb", d)[:32]
    assert allcrypt.acpkm_next("magma", key) == \
        allcrypt.Cipher("magma", key).encrypt("ecb", d)[:32]


@pytest.mark.parametrize("cipher", ["kuznyechik", "magma"])
def test_kexp15_against_the_engine(cipher):
    records = engine_section(f"{cipher}-kexp15")
    assert len(records) == 2
    for r in records:
        mac_key, enc_key = r["Key"][:32], r["Key"][32:]
        assert allcrypt.kexp15(cipher, r["In"], mac_key, enc_key, r["IV"]) == r["Out"]
        assert allcrypt.kimp15(cipher, r["Out"], mac_key, enc_key, r["IV"]) == r["In"]
        altered = bytearray(r["Out"])
        altered[-1] ^= 1
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.kimp15(cipher, bytes(altered), mac_key, enc_key, r["IV"])


@pytest.mark.parametrize("cipher", ["kuznyechik", "magma"])
def test_tlstree_against_the_engine(cipher):
    records = engine_section(f"tlstree-{cipher}")
    assert len(records) == 17
    for r in records:
        sequence = int.from_bytes(r["Seq"], "big")
        assert allcrypt.tlstree(f"{cipher}-ctr-omac", r["Key"], sequence) == r["Out"]
    assert f"{cipher}-ctr-omac" in allcrypt.tlstree_suites


# --------------------------------------------------------------- RFC 7836 ---

def rfc7836_example(number):
    """Fields of one numbered example in RFC 7836 appendix A.1: a label
    line ending in a colon, then hex lines, which may follow blank lines
    and a page break."""
    text = (ROOT / "rfcs" / "rfc7836.txt").read_text(encoding="utf-8-sig")
    start = re.search(rf"\n   {number}\)   ", text).start()
    end = re.search(rf"\n   {number + 1}\)   ", text).start()
    fields, label = {}, None
    for line in text[start:end].splitlines():
        stripped = line.strip()
        if re.fullmatch(r"([0-9a-f]{2} ?)+", stripped) and label:
            fields[label] += bytes.fromhex(stripped)
        elif stripped.endswith(":"):
            label = stripped[:-1]
            fields[label] = b""
        elif stripped and label and fields[label]:
            label = None
    return fields


def test_kdf_gostr3411_2012_256_against_rfc_7836():
    example = rfc7836_example(9)
    assert [len(example[k]) for k in ("K_in key", "Label", "Seed")] == [32, 4, 8]
    assert allcrypt.kdf_gostr3411_2012_256(example["K_in key"], example["Label"],
                                           example["Seed"]) == \
        example["KDF(K_in, label, seed) value"]


def test_kdf_tree_gostr3411_2012_256_against_rfc_7836():
    example = rfc7836_example(10)
    text = (ROOT / "rfcs" / "rfc7836.txt").read_text(encoding="utf-8-sig")
    section = text[text.index("10)   Key derivation function KDF_TREE"):]
    bits = int(re.search(r"Output size of L:\s+(\d+)", section).group(1))
    r = int(re.search(r"\n   R:\s+(\d+)", section).group(1))
    assert (bits, r) == (512, 1)
    out = allcrypt.kdf_tree_gostr3411_2012_256(example["K_in key"], example["Label"],
                                               example["Seed"], bits // 8, counter_bytes=r)
    assert len(example["K1"]) == len(example["K2"]) == 32
    assert out == example["K1"] + example["K2"]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kdf_tree_gostr3411_2012_256(b"k", b"l", b"s", 32, counter_bytes=5)
