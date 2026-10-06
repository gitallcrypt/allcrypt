#!/usr/bin/env python3
"""Write vectors/umac_nettle.vec: Nettle's UMAC tags over many lengths.

RFC 4418 publishes eight messages, and one of the eight rows was
printed wrong (erratum 3507). Nettle implements UMAC independently and
completely - including POLY's 128 bit stage past 2^24 bytes, which
OpenSSH's `umac.c` leaves out - so it is the second opinion here, at
every tag length, across the boundaries the layers care about: the 32
byte NH padding, the 1024 byte L1 chunk, and the 2^24 byte switch from
the 64 bit to the 128 bit polynomial.

    python3 scripts/make_umac_vectors.py

Nettle is reached through `ctypes` on the system's `libnettle.so.8`;
no headers or build are needed. **A development tool, not a test**:
nothing in the build or the gate runs it, and the test that reads the
file needs no Nettle.

Every input is deterministic, so re-running it changes nothing unless
Nettle's answer changed:

  * the key of record `i` is the first 16 bytes of
    SHA-256("umac key" || i), `i` a 4 byte big-endian integer;
  * its nonce is the first `nonce_len` bytes of SHA-256("umac nonce" ||
    i), except the `ssh` rows, whose nonce is an 8 byte big-endian
    sequence number as SSH uses it;
  * its message is `length` bytes, byte `i` being the top byte of
    `(i + seed) * 0x9E3779B1 mod 2^32` - Fibonacci hashing, cheap to
    rebuild and with no period short enough to make two 1024 byte
    chunks equal. Rows of one length share a seed, so a reader can
    build each long message once.
"""

import ctypes
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(os.path.dirname(HERE), "vectors", "umac_nettle.vec")

TAG_LENGTHS = [4, 8, 12, 16]

SMALL = sorted(set(list(range(0, 81)) + list(range(81, 2200, 23)) + [
    255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 1055, 1056, 1057,
    2047, 2048, 2049, 3071, 3072, 3073, 4096, 8191, 8192, 32768, 35000,
    65536]))

# 2^14 L1 words is 2^24 bytes: up to there POLY is 64 bit only, and one
# byte more starts the 128 bit stage with a single padded word.
# Past it, the rest is padded with 0x80 to 16 bytes: one, two and three
# leftover words reach each padding case.
LARGE = [(1 << 20) + 3, 1 << 24, (1 << 24) + 1, (1 << 24) + 1025,
         (1 << 24) + 2049, (1 << 25) + 11]


def be32(n):
    return n.to_bytes(4, "big")


def message(seed, length):
    return bytes(((i + seed) * 0x9E3779B1 & 0xFFFFFFFF) >> 24
                 for i in range(length))


class Nettle:
    def __init__(self):
        self.lib = ctypes.CDLL("libnettle.so.8")
        major = self.lib.nettle_version_major()
        minor = self.lib.nettle_version_minor()
        self.version = f"Nettle {major}.{minor} (libnettle.so.8)"

    def tag(self, tag_len, key, nonce, data):
        bits = tag_len * 8
        call = lambda name: getattr(self.lib, f"nettle_umac{bits}_{name}")
        # sizeof(struct umac128_ctx) is under 3 KB; this is room to spare.
        context = ctypes.create_string_buffer(1 << 16)
        call("set_key")(context, key)
        call("set_nonce")(context, ctypes.c_size_t(len(nonce)), nonce)
        call("update")(context, ctypes.c_size_t(len(data)), data)
        out = ctypes.create_string_buffer(tag_len)
        call("digest")(context, ctypes.c_size_t(tag_len), out)
        return out.raw


def main():
    nettle = Nettle()
    # Nettle agrees with RFC 4418's printed rows before it is believed
    # about anything else; the 2^25 row is checked against erratum 3507.
    key, nonce = b"abcdefghijklmnop", b"bcdefghi"
    for data, expected in [(b"", "113145FB6E155FAD26900BE1"),
                           (b"abc" * 500, "ABEB3C8BD4CF26DDEFD5C01A"),
                           (b"a" * (1 << 25), "85EE5CAEFACA46F856E9B45F")]:
        got = (nettle.tag(4, key, nonce, data) + nettle.tag(8, key, nonce, data)).hex().upper()
        assert got == expected, (len(data), got)

    rows = []
    index = 0

    def add(tag_len, length, seed, nonce=None, kind="umac"):
        nonlocal index
        key = hashlib.sha256(b"umac key" + be32(index)).digest()[:16]
        if nonce is None:
            nonce_len = 1 + index % 16
            nonce = hashlib.sha256(b"umac nonce" + be32(index)).digest()[:nonce_len]
        rows.append((kind, [("bytes", str(tag_len)), ("key", key.hex()),
                            ("nonce", nonce.hex()), ("length", str(length)),
                            ("seed", str(seed)),
                            ("tag", nettle.tag(tag_len, key, nonce,
                                               message(seed, length)).hex())]))
        index += 1

    for length in SMALL:
        for tag_len in TAG_LENGTHS:
            add(tag_len, length, length)
    for length in LARGE:
        for tag_len in TAG_LENGTHS:
            add(tag_len, length, length)
    # SSH: consecutive sequence numbers as nonces, which for 4 and 8
    # byte tags share PDF blocks.
    for sequence in list(range(9)) + [0xffffffff, 0x100000000]:
        for tag_len in (8, 16):
            add(tag_len, 100 + sequence % 7, 100 + sequence % 7,
                nonce=sequence.to_bytes(8, "big"), kind="ssh")

    counts = {}
    for kind, _ in rows:
        counts[kind] = counts.get(kind, 0) + 1
    with open(OUTPUT, "w") as out:
        out.write(
            "# UMAC (RFC 4418) tags from Nettle.\n"
            "#\n"
            "# Generated by scripts/make_umac_vectors.py. Do not edit: every\n"
            "# tag here is Nettle's answer.\n"
            "#\n"
            f"# {nettle.version}\n"
            "#\n"
            "# Keys, nonces and messages are derived as the script's\n"
            "# docstring says; `length` and `seed` describe the\n"
            "# message rather than carrying it, because the longest is 32 MB.\n"
            "#\n"
            "# Counts, asserted by the test that reads this:\n")
        for kind in sorted(counts):
            out.write(f"#   {kind:24} {counts[kind]}\n")
        for kind in sorted(counts):
            out.write(f"\n[{kind}]\n")
            for row_kind, fields in rows:
                if row_kind != kind:
                    continue
                out.write("\n")
                for name, value in fields:
                    out.write(f"{name} = {value}\n")
    print(f"wrote {OUTPUT}: " + ", ".join(f"{counts[k]} {k}" for k in sorted(counts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
