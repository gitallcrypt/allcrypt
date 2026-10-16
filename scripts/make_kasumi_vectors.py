#!/usr/bin/env python3
"""Write vectors/kasumi.vec: KASUMI as libtomcrypt 1.18.2 and Botan 1.10.17
compute it.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_kasumi_vectors.py

**A development tool, not a test.** `tests/test_kasumi.rs` reads the
file offline.

First the published tests the two carry - libtomcrypt's self-test and
Botan's validate.dat, which take them from the 3GPP's conformance tests,
read out of their sources - which the build has
already required both to reproduce. Then the shape of NESSIE's own test
sets: every single-bit key under a zero block, every single-bit block
under a zero key, and key and block both one byte repeated, for every
byte; a seeded generator's keys and blocks; and blocks encrypted and
decrypted 100 and 1,000 times over, as NESSIE's "Iterated" lines. Both
witnesses answer every request, decryption included, and a row is
written only where they agree with each other and decryption gives the
block back.

    kasumi key=<hex> pt=<hex> ct=<hex>             one block
    kasumi-iter key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "kasumi.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

PROGRAMS = ("kasumi-libtomcrypt", "kasumi-botan")


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
    rng = random.Random(0x6b6173756d69)  # "kasumi"
    single = []    # (key, pt, src)
    published = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "kasumi")]
    for key, pt, _ in published:
        single.append((key, pt, "published"))
    for bit in range(128):
        single.append(((1 << (127 - bit)).to_bytes(16, "big"), bytes(8), None))
    for bit in range(64):
        single.append((bytes(16), (1 << (63 - bit)).to_bytes(8, "big"), None))
    for byte in range(256):
        single.append((bytes([byte]) * 16, bytes([byte]) * 8, None))
    for _ in range(64):
        single.append((rng.randbytes(16), rng.randbytes(8), None))

    cts = ask([f"enc {k.hex()} {p.hex()}" for k, p, _ in single])
    back = ask([f"dec {k.hex()} {c}" for (k, _, _), c in zip(single, cts)])
    for (key, pt, src), ct, again in zip(single, cts, back):
        if again != pt.hex():
            sys.exit(f"decryption does not give the block back: {key.hex()} {pt.hex()}")
    for (key, pt, src), ct in zip(single, cts):
        if src == "published":
            expected = next(c for k, p, c in published if (k, p) == (key, pt))
            if ct != expected.hex():
                sys.exit(f"a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for _ in range(8):
        key, pt = rng.randbytes(16), rng.randbytes(8)
        for n in (100, 1000):
            iterated.append((key, pt, n))
    iterated.append((bytes(16), bytes(8), 1000))
    ict = ask([f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated])
    iback = ask([f"dec-n {k.hex()} {c} {n}" for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{n} decryptions do not give the block back: {key.hex()}")

    rows = []
    for (key, pt, src), ct in zip(single, cts):
        rows.append(f"kasumi key={key.hex()} pt={pt.hex()} ct={ct}"
                    + (" src=published" if src else ""))
    for (key, pt, n), ct in zip(iterated, ict):
        rows.append(f"kasumi-iter key={key.hex()} pt={pt.hex()} ct={ct} n={n}")
    with open(OUTPUT, "w") as out:
        out.write("# KASUMI. libtomcrypt 1.18.2 and Botan 1.10.17 agree on every row, both\n"
                  "# directions; src=published marks the tests the two carry.\n"
                  "# Written by scripts/make_kasumi_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
