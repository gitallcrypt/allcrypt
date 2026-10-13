#!/usr/bin/env python3
"""Write vectors/strumok.vec: Strumok (DSTU 8845:2019) known answers.

    scripts/witness/strumok/build.sh /opt/strumok
    python3 scripts/make_strumok_vectors.py

**A development tool, not a test.** It needs both witnesses built (the
build fetches their sources once); `tests/test_strumok.rs` and
`pytests/test_strumok.py` read `vectors/strumok.vec` offline.

Two implementations that share no code: UAPKI's `dstu8845.c`, in C, and
uacrypt's `hazmat/strumok.rs`, in Rust (scripts/witness/strumok has
both). Every row is written only where both give the same keystream,
and every keystream is asked of each in uneven pieces as well as whole,
which must agree too. In order:

1. The published examples `scripts/witness/strumok/published.py` reads:
   the standard's Annex D (source=standard), UAPKI's self-test
   (source=uapki) and the conformance letter's two (source=letter).
2. For each key length, the all-zero and all-one key and IV, every
   key with a single bit set and every IV with a single bit set, with
   32 bytes of keystream: each key and IV word reaches the register in
   its own place, and these rows pin each place.
3. For each key length, random keys and IVs with keystreams of lengths
   around a word and the 128 byte block both witnesses compute at once.
4. For each key length, one keystream of 1 MiB, recorded by its
   SHA-256.

Byte order: key, IV and keystream are bytes with each 64-bit word
little endian and word 0 first (published.py converts the standard's
printed words to that). Row formats, hex fields:

    strumok key=<hex> iv=<hex> keystream=<hex> source=<standard|uapki|letter|both>
    strumok key=<hex> iv=<hex> length=<n> sha256=<hex> source=both
"""

import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "strumok.vec")
OUT = os.environ.get("STRUMOK_WITNESS", "/opt/strumok")
sys.path.insert(0, os.path.join(HERE, "witness", "strumok"))
import published  # noqa: E402

PIECES = [1, 7, 8, 9, 3, 64, 5, 128, 75, 120]


def uneven(n):
    """`n` split into the PIECES lengths, cycling, the last cut short."""
    out, i = [], 0
    while n > 0:
        p = min(PIECES[i % len(PIECES)], n)
        out.append(p)
        n -= p
        i += 1
    return out or [0]


def both(requests):
    """Keystreams for (key, iv, length) requests, where both witnesses
    agree, whole and in pieces."""
    asked = [(k, v, [n]) for k, v, n in requests] + [(k, v, uneven(n)) for k, v, n in requests]
    answers = {who: published.run(program, asked)
               for who, program in published.witnesses(OUT).items()}
    a, b = answers["uapki"], answers["uacrypt"]
    for (k, v, pieces), x, y in zip(asked, a, b):
        if x != y:
            sys.exit(f"the witnesses disagree: key={k.hex()} iv={v.hex()} pieces={pieces}")
    whole, split = a[:len(requests)], a[len(requests):]
    for (k, v, n), x, y in zip(requests, whole, split):
        if x != y or len(x) != n:
            sys.exit(f"a keystream depends on its pieces: key={k.hex()} iv={v.hex()}")
    return whole


def bit(nbytes, i):
    b = bytearray(nbytes)
    b[i // 8] = 0x80 >> (i % 8)
    return bytes(b)


def main():
    rows = []
    pub = published.all_published(os.path.join(OUT, "src"))
    for (source, label, k, v, z), got in zip(pub, both([(k, v, len(z))
                                                         for _, _, k, v, z in pub])):
        if got != z:
            sys.exit(f"the witnesses miss {source} {label}")
        rows.append(f"strumok key={k.hex()} iv={v.hex()} keystream={z.hex()} source={source}")

    requests = []
    for klen in (32, 64):
        zero_iv = bytes(32)
        requests += [(bytes(klen), zero_iv, 32), (b"\xff" * klen, b"\xff" * 32, 32)]
        requests += [(bit(klen, i), zero_iv, 32) for i in range(klen * 8)]
        requests += [(bytes(klen), bit(32, i), 32) for i in range(256)]
    rng = random.Random(0x5354524D)
    for klen in (32, 64):
        for n in (1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257, 1000):
            requests.append((rng.randbytes(klen), rng.randbytes(32), n))
    for (k, v, _), z in zip(requests, both(requests)):
        rows.append(f"strumok key={k.hex()} iv={v.hex()} keystream={z.hex()} source=both")

    long = [(rng.randbytes(klen), rng.randbytes(32), 1 << 20) for klen in (32, 64)]
    for (k, v, n), z in zip(long, both(long)):
        rows.append(f"strumok key={k.hex()} iv={v.hex()} length={n} "
                    f"sha256={hashlib.sha256(z).hexdigest()} source=both")

    with open(OUTPUT, "w") as f:
        f.write("# Strumok (DSTU 8845:2019). Written by scripts/make_strumok_vectors.py;\n"
                "# do not edit. Key, IV and keystream as bytes, each 64-bit word little\n"
                "# endian, word 0 first. source=standard: Annex D's examples;\n"
                "# source=uapki: UAPKI's self-test; source=letter: the conformance\n"
                "# letter's examples uacrypt carries; source=both: UAPKI's dstu8845.c and\n"
                "# uacrypt's hazmat/strumok.rs in agreement. Every row is one both\n"
                "# reproduce, whole and in uneven pieces.\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
