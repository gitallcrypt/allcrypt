"""RIPEMD-128/256/320, HAS-160, Whirlpool-0, Whirlpool-T and MD6 through
the Python surface, against `vectors/legacy_hashes.vec`: digests on which
the reference implementations agree (the file's header lists them), and
streaming in pieces against one call."""

import pathlib

import allcrypt

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "legacy_hashes.vec"
NAMES = ["ripemd128", "ripemd256", "ripemd320", "has160", "whirlpool_0", "whirlpool_t",
         "md6_128", "md6_224", "md6_256", "md6_384", "md6_512"]


def records():
    out = []
    for line in VECTORS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split(" = ")
        if key == "message":
            out.append((b"" if value == "-" else bytes.fromhex(value), {}))
        elif key == "pattern":
            out.append((bytes((i * 167 + 29) & 0xff for i in range(int(value))), {}))
        elif key == "repeat":
            byte, count = value.split()
            out.append((bytes([int(byte, 16)]) * int(count), {}))
        else:
            out[-1][1][key] = value
    return out


def test_the_vectors():
    all_ = records()
    assert len(all_) == 317
    for data, digests in all_:
        assert sorted(digests) == sorted(NAMES)
        for name, want in digests.items():
            assert allcrypt.new(name, data).hexdigest() == want, (name, len(data))


def test_the_names_are_available_and_streaming_agrees():
    data = bytes(range(256)) * 3
    for name in NAMES:
        assert name in allcrypt.algorithms_available
        whole = allcrypt.new(name, data)
        pieces = allcrypt.new(name)
        for at in range(0, len(data), 37):
            pieces.update(data[at:at + 37])
        assert pieces.hexdigest() == whole.hexdigest(), name
        assert whole.digest_size == len(whole.digest())
