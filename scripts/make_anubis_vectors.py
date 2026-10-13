#!/usr/bin/env python3
"""Write vectors/anubis.vec: Anubis (the tweaked cipher, whose S-box is
Khazad's) as libtomcrypt 1.18.2 built with LTC_ANUBIS_TWEAK, the Linux
kernel's crypto/anubis.c and the designers' reference code compute it.

    scripts/witness/nessie/build.sh /opt/nessie
    python3 scripts/make_anubis_vectors.py

**A development tool, not a test.** `tests/test_anubis.rs` reads the
file offline.

First the published tests libtomcrypt and the kernel carry, read out of
their sources, which the build has already required all three to
reproduce. Then, at every key length from 16 to 40 bytes, every
single-bit key under a zero block, random keys and blocks, and blocks
encrypted 100 and 1,000 times over, as NESSIE's iterated tests; and at
16 bytes every single-bit block under a zero key and key and block one
byte repeated, for every byte. All three witnesses answer every
request, decryption included, and a row is written only where they
agree and decryption gives the block back.

    anubis key=<hex> pt=<hex> ct=<hex>             one block
    anubis-iter key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "anubis.vec")
WITNESS = os.environ.get("NESSIE_WITNESS", "/opt/nessie")
sys.path.insert(0, os.path.join(HERE, "witness", "nessie"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

PROGRAMS = ("anubis-libtomcrypt", "anubis-linux", "anubis-reference")
LENGTHS = range(16, 41, 4)


def ask(requests):
    """Every request to every witness; the answers, which must agree."""
    answers = []
    for name in PROGRAMS:
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(requests) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, *each in zip(requests, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the witnesses disagree on {request}: {each}")
    return answers[0]


def main():
    rng = random.Random(0x616e75626973)  # "anubis"
    single = []    # (key, pt, src)
    published = list(selftest.vectors(WITNESS, "anubis"))
    for key, pt, _ in published:
        single.append((key, pt, "published"))
    for length in LENGTHS:
        for bit in range(8 * length):
            single.append(((1 << (8 * length - 1 - bit)).to_bytes(length, "big"), bytes(16),
                           None))
        for _ in range(16):
            single.append((rng.randbytes(length), rng.randbytes(16), None))
        single.append((b"\xff" * length, b"\xff" * 16, None))
    for bit in range(128):
        single.append((bytes(16), (1 << (127 - bit)).to_bytes(16, "big"), None))
    for byte in range(256):
        single.append((bytes([byte]) * 16, bytes([byte]) * 16, None))

    cts = ask([f"enc {k.hex()} {p.hex()}" for k, p, _ in single])
    back = ask([f"dec {k.hex()} {c}" for (k, _, _), c in zip(single, cts)])
    for (key, pt, _), again in zip(single, back):
        if again != pt.hex():
            sys.exit(f"decryption does not give the block back: {key.hex()} {pt.hex()}")
    for (key, pt, src), ct in zip(single, cts):
        if src == "published":
            expected = next(c for k, p, c in published if (k, p) == (key, pt))
            if ct != expected.hex():
                sys.exit(f"a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for length in LENGTHS:
        key, pt = rng.randbytes(length), rng.randbytes(16)
        for n in (100, 1000):
            iterated.append((key, pt, n))
    ict = ask([f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated])
    iback = ask([f"dec-n {k.hex()} {c} {n}" for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{n} decryptions do not give the block back: {key.hex()}")

    rows = []
    for (key, pt, src), ct in zip(single, cts):
        rows.append(f"anubis key={key.hex()} pt={pt.hex()} ct={ct}"
                    + (" src=published" if src else ""))
    for (key, pt, n), ct in zip(iterated, ict):
        rows.append(f"anubis-iter key={key.hex()} pt={pt.hex()} ct={ct} n={n}")
    with open(OUTPUT, "w") as out:
        out.write("# Anubis (the tweaked cipher), every key length from 16 to 40 bytes.\n"
                  "# libtomcrypt 1.18.2 with LTC_ANUBIS_TWEAK, the Linux kernel's\n"
                  "# crypto/anubis.c and the designers' reference code agree on every\n"
                  "# row, both directions; src=published marks the tests libtomcrypt and\n"
                  "# the kernel carry.\n"
                  "# Written by scripts/make_anubis_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
