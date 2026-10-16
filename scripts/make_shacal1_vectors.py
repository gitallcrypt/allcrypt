#!/usr/bin/env python3
"""Write vectors/shacal1.vec: SHACAL-1 as two SHA-1 compression
functions, Crypto++ 8.9.0's and OpenSSL's, compute it once their
feed-forward is taken off.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_shacal1_vectors.py

**A development tool, not a test.** `tests/test_shacal1.rs` reads the
file offline.

Both witnesses encrypt only - a compression function has no inverse -
so every row is an encryption both agree on; the tests require
decryption to give each row's block back, which makes it the inverse
of a witnessed encryption there.

First the published tests: the two SHACAL-1 vectors Project Nayuki's
library carries, which the build has already required both witnesses
to reproduce. Then every single-bit key at 64 and at 16 bytes under a
zero block, every single-bit block under a zero key, key and block both
one byte repeated for every byte, a seeded generator's keys and blocks
at every key length from 16 to 64 bytes, and blocks encrypted 100 and
1,000 times over. A key shorter than 64 bytes is zero-padded to 64 by
the witnesses' drivers, which is SHACAL's definition of a shorter key.

    shacal1 key=<hex> pt=<hex> ct=<hex>             one block
    shacal1-iter key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "shacal1.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

BLOCK = 20
SOURCES = ("cryptopp", "openssl")


def ask(requests):
    """Every request to both witnesses; the answers, which must agree."""
    answers = []
    for source in SOURCES:
        name = f"shacal1-{source}"
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(requests) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, *each in zip(requests, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the SHACAL-1 witnesses disagree on {request}: {each}")
    return answers[0]


def main():
    rng = random.Random(0x73686163616c31)  # "shacal1"
    published = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "shacal1")]
    single = [(k, p, True) for k, p, _ in published]
    for keylen in (64, 16):
        for bit in range(8 * keylen):
            single.append(((1 << (8 * keylen - 1 - bit)).to_bytes(keylen, "big"), bytes(BLOCK), False))
    for bit in range(8 * BLOCK):
        single.append((bytes(64), (1 << (8 * BLOCK - 1 - bit)).to_bytes(BLOCK, "big"), False))
    for byte in range(256):
        single.append((bytes([byte]) * 64, bytes([byte]) * BLOCK, False))
    for keylen in range(16, 65):
        for _ in range(4):
            single.append((rng.randbytes(keylen), rng.randbytes(BLOCK), False))

    cts = ask([f"enc {k.hex()} {p.hex()}" for k, p, _ in single])
    answer = {(k, p): c for (k, p, _), c in zip(single, cts)}
    for key, pt, ct in published:
        if answer[(key, pt)] != ct.hex():
            sys.exit(f"a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for keylen in (16, 40, 64):
        for _ in range(2):
            key, pt = rng.randbytes(keylen), rng.randbytes(BLOCK)
            iterated += [(key, pt, 100), (key, pt, 1000)]
    iterated.append((bytes(64), bytes(BLOCK), 1000))
    ict = ask([f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated])

    rows = [f"shacal1 key={k.hex()} pt={p.hex()} ct={c}" + (" src=published" if src else "")
            for (k, p, src), c in zip(single, cts)]
    rows += [f"shacal1-iter key={k.hex()} pt={p.hex()} ct={c} n={n}"
             for (k, p, n), c in zip(iterated, ict)]
    with open(OUTPUT, "w") as out:
        out.write("# SHACAL-1. Crypto++ 8.9.0's and OpenSSL's SHA-1 compression functions,\n"
                  "# less their feed-forward, agree on every row; both encrypt only. Keys\n"
                  "# shorter than 64 bytes are zero-padded. src=published marks Project\n"
                  "# Nayuki's tests.\n"
                  "# Written by scripts/make_shacal1_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
