#!/usr/bin/env python3
"""Write vectors/shacal2.vec: SHACAL-2 as Crypto++ 8.9.0 and Bouncy
Castle 1.77 compute it.

    scripts/witness/nessie/build.sh /opt/nessie
    python3 scripts/make_shacal2_vectors.py

**A development tool, not a test.** `tests/test_shacal2.rs` reads the
file offline.

First the published tests: the NESSIE submission's 1,024 vectors that
Crypto++'s TestVectors/shacal2.txt carries, and Botan's shacal2.vec,
whose short-key tests NESSIE did not have, each block once. The build
has already required both witnesses to reproduce them. NESSIE's sets
already include every single-bit key and block at 512 bits, so what
follows covers the rest: every key length from 16 to 64 bytes with
random keys and blocks, every single-bit key of 16 bytes, and blocks
encrypted and decrypted 100 and 1,000 times over at several lengths.
Bouncy Castle takes keys in multiples of 8 bytes, and its driver pads
the others to 64, which is SHACAL-2's definition of a shorter key; so
at those lengths the rows are Crypto++'s key as given against Bouncy
Castle's padded. A row is written only where both agree and decryption
gives the block back.

    shacal2 key=<hex> pt=<hex> ct=<hex>             one block
    shacal2-iter key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "shacal2.vec")
WITNESS = os.environ.get("NESSIE_WITNESS", "/opt/nessie")
sys.path.insert(0, os.path.join(HERE, "witness", "nessie"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

PROGRAMS = ("shacal2-cryptopp", "shacal2-bc")


def ask(requests):
    """Every request to both witnesses; the answers, which must agree."""
    answers = []
    for name in PROGRAMS:
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(requests) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, a, b in zip(requests, *answers):
        if a != b:
            sys.exit(f"the witnesses disagree on {request}: {a} {b}")
    return answers[0]


def main():
    rng = random.Random(0x73686163616c32)  # "shacal2"
    single, seen = [], set()
    published = list(selftest.vectors(WITNESS, "shacal2"))
    for key, pt, _ in published:
        if (key, pt) not in seen:
            seen.add((key, pt))
            single.append((key, pt, "published"))
    for length in range(16, 65):
        for _ in range(4):
            single.append((rng.randbytes(length), rng.randbytes(32), None))
    for bit in range(128):
        single.append(((1 << (127 - bit)).to_bytes(16, "big"), bytes(32), None))

    cts = ask([f"enc {k.hex()} {p.hex()}" for k, p, _ in single])
    back = ask([f"dec {k.hex()} {c}" for (k, _, _), c in zip(single, cts)])
    for (key, pt, _), again in zip(single, back):
        if again != pt.hex():
            sys.exit(f"decryption does not give the block back: {key.hex()} {pt.hex()}")
    expected = {(k, p): c for k, p, c in published}
    for (key, pt, src), ct in zip(single, cts):
        if src == "published" and ct != expected[(key, pt)].hex():
            sys.exit(f"a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for length in (16, 20, 33, 48, 64):
        key, pt = rng.randbytes(length), rng.randbytes(32)
        for n in (100, 1000):
            iterated.append((key, pt, n))
    ict = ask([f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated])
    iback = ask([f"dec-n {k.hex()} {c} {n}" for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{n} decryptions do not give the block back: {key.hex()}")

    rows = [f"shacal2 key={k.hex()} pt={p.hex()} ct={c}" + (" src=published" if s else "")
            for (k, p, s), c in zip(single, cts)]
    rows += [f"shacal2-iter key={k.hex()} pt={p.hex()} ct={c} n={n}"
             for (k, p, n), c in zip(iterated, ict)]
    with open(OUTPUT, "w") as out:
        out.write("# SHACAL-2, every key length from 16 to 64 bytes. Crypto++ 8.9.0 and\n"
                  "# Bouncy Castle 1.77 (given the key zero-padded to 64 bytes) agree on\n"
                  "# every row, both directions; src=published marks the NESSIE vectors\n"
                  "# Crypto++ carries and Botan's tests.\n"
                  "# Written by scripts/make_shacal2_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
