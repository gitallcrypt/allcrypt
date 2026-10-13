#!/usr/bin/env python3
"""Write vectors/checksums.vec: the checksums, from several
implementations each.

    scripts/witness/checksums/build.sh /opt/checksumwitness
    python3 scripts/make_checksum_vectors.py

**A development tool, not a test.** `tests/test_checksums.rs` and
`pytests/test_checksums.py` read the file offline.

The witnesses (`scripts/witness/checksums`), each fed its message in
pieces of 1, 2, 3 ... bytes:

    crc32, adler32  PHP, Go, java.util.zip, zlib
    crc32c          PHP, Go, java.util.zip, the SSE 4.2 instruction
    fletcher16, fletcher32, fletcher64
                    the R package fletcher's C, hashlib-additional, the
                    fletcher crate
    fnv1_32 ... fnv1a_64
                    PHP, Go, fnv-es, fnv-plus, hashlib-additional
    fnv1_128, fnv1a_128
                    Go, fnv-es, fnv-plus, hashlib-additional
    fnv1_256 ... fnv1a_1024
                    fnv-es, fnv-plus, and hashlib-additional except at
                    512 bits, where its offset basis is wrong
    fnv0_32 ... fnv0_1024
                    fnv-es, hashlib-additional

Every witness that has a name must agree on every message, or the script
stops. The messages are the CRC catalogue's check input, "123456789",
and random bytes at lengths from 0 to 1000 and around Adler-32's run of
5552 bytes between reductions, from a fixed seed, written
once each as `msg` rows that the `sum` rows name by index; and long runs
of one byte, described by the byte and the length rather than written
out:

    msg n= data=
    msg n= fill= len=
    sum name= msg= value=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "checksums.vec")
WITNESS = os.environ.get("CHECKSUM_WITNESS", "/opt/checksumwitness")

SIZES = [32, 64, 128, 256, 512, 1024]
WITNESSES = {"crc32": ["php", "go", "java", "c"],
             "crc32c": ["php", "go", "java", "c"],
             "adler32": ["php", "go", "java", "c"],
             **{f"fletcher{bits}": ["rpkg", "py", "rust"] for bits in (16, 32, 64)},
             **{f"fnv0_{bits}": ["fnves", "py"] for bits in SIZES},
             **{f"fnv{v}_{bits}": (["php", "go"] if bits < 128 else ["go"] if bits == 128 else [])
                + ["fnves", "fnvplus"] + (["py"] if bits != 512 else [])
                for v in ("1", "1a") for bits in SIZES}}
LENGTHS = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 256,
           257, 1000, 5551, 5552, 5553]
# (byte, length): long runs of the largest byte, which bring Adler-32's
# sums closest to overflowing between reductions, and of zero.
FILLS = [(0xff, 100_000), (0xff, 5552), (0xff, 5553), (0x00, 4096)]


def ask(witness, requests):
    """The witness's answers to [(name, path)], in order."""
    lines = "".join(f"{name} {path}\n" for name, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out}")
    return out


def main():
    rng = random.Random(0xC5C5)
    messages = [b"123456789"] + [rng.randbytes(n) for n in LENGTHS] + \
        [bytes([byte]) * length for byte, length in FILLS]
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, message in enumerate(messages):
            paths.append(os.path.join(tmp, f"m{i}"))
            with open(paths[-1], "wb") as f:
                f.write(message)
        answers = {}
        for witness in sorted({w for who in WITNESSES.values() for w in who}):
            requests = [(name, path) for name, who in WITNESSES.items() if witness in who
                        for path in paths]
            for (name, path), value in zip(requests, ask(witness, requests)):
                answers.setdefault((name, paths.index(path)), {})[witness] = value
    rows = []
    for name, who in WITNESSES.items():
        for i, message in enumerate(messages):
            given = answers[(name, i)]
            if sorted(given) != sorted(who) or len(set(given.values())) != 1:
                sys.exit(f"the witnesses disagree on {name} of {len(message)} bytes: {given}")
            rows.append(f"sum name={name} msg={i} value={given[who[0]]}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# Checksums, as big endian hex. Written by\n"
                  "# scripts/make_checksum_vectors.py; do not edit. Every witness that\n"
                  "# has a name agrees on every row: PHP, Go and java.util.zip on every\n"
                  "# one, zlib on CRC-32 and Adler-32 and the SSE 4.2 instruction on\n"
                  "# CRC-32C; the R package fletcher's C, hashlib-additional and the\n"
                  "# fletcher crate on Fletcher's; fnv-es and hashlib-additional on\n"
                  "# FNV-0; fnv-es and fnv-plus on FNV-1 and FNV-1a, with PHP and Go\n"
                  "# where they have the size and hashlib-additional except at 512\n"
                  "# bits.\n")
        for i, message in enumerate(messages[:len(messages) - len(FILLS)]):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for i, (byte, length) in enumerate(FILLS, len(messages) - len(FILLS)):
            out.write(f"msg n={i} fill={byte:02x} len={length}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(rows)} rows")


if __name__ == "__main__":
    main()
