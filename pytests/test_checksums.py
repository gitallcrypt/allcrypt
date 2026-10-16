"""The checksums against `vectors/checksums.vec` (PHP, Go, java.util.zip,
and zlib or the SSE 4.2 instruction; the R package fletcher's C,
hashlib-additional and the fletcher crate; fnv-es, fnv-plus,
hashlib-additional, PHP and Go; written by
`scripts/make_checksum_vectors.py`)."""

import pathlib
import zlib

import pytest

import allcrypt

LINES = (pathlib.Path(__file__).resolve().parent.parent / "vectors"
         / "checksums.vec").read_text().splitlines()
MESSAGES = [bytes.fromhex(f["fill"]) * int(f["len"]) if "fill" in f
            else b"" if f["data"] == "-" else bytes.fromhex(f["data"])
            for f in (dict(w.split("=", 1) for w in line.split()[1:])
                      for line in LINES if line.startswith("msg "))]
ROWS = [dict(w.split("=", 1) for w in line.split()[1:])
        for line in LINES if line.startswith("sum ")]


def test_the_file():
    assert len(MESSAGES) == 31
    assert len(ROWS) == 744
    # The rest are the fast hashes, in test_xxhash.py, test_murmur3.py and
    # test_joaat.py.
    assert len(allcrypt.checksums_available) == 32
    assert allcrypt.checksums_available[24:] == ["xxh32", "xxh64", "xxh3", "xxh128",
                                                 "murmur3_32", "murmur3_x86_128",
                                                 "murmur3_x64_128", "joaat"]
    assert not set(allcrypt.checksums_available) & set(allcrypt.algorithms_available)


@pytest.mark.parametrize("name", sorted({r["name"] for r in ROWS}))
def test_each_checksum(name):
    assert name in allcrypt.checksums_available
    rows = [r for r in ROWS if r["name"] == name]
    assert len(rows) == 31
    for row in rows:
        message = MESSAGES[int(row["msg"])]
        h = allcrypt.new(name, message)
        assert h.name == name
        assert h.digest_size == len(row["value"]) // 2
        assert h.hexdigest() == row["value"]
        pieces = allcrypt.new(name)
        for at in range(0, len(message), 7):
            pieces.update(memoryview(message)[at:at + 7])
        assert pieces.hexdigest() == row["value"]
        number = int(row["value"], 16)
        if name == "crc32":
            assert zlib.crc32(message) == number
        elif name == "adler32":
            assert zlib.adler32(message) == number
        elif name == "crc32c":
            assert allcrypt.crc32c(message) == number
            half = len(message) // 2
            assert allcrypt.crc32c(message[half:], allcrypt.crc32c(message[:half])) == number


def test_phps_name_for_crc32():
    assert allcrypt.new("crc32b", b"123456789").name == "crc32"


def test_crc32c_takes_only_a_32_bit_value():
    with pytest.raises(OverflowError):
        allcrypt.crc32c(b"", 1 << 32)


def test_phps_names_for_fnv():
    row = next(r for r in ROWS if r["name"] == "fnv1a_64" and r["msg"] == "0")
    h = allcrypt.new("fnv1a64", MESSAGES[0])
    assert h.name == "fnv1a_64"
    assert h.hexdigest() == row["value"]
