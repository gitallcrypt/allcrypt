#!/usr/bin/env python3
"""Write vectors/present.vec: PRESENT with 80 and 128 bit keys, as
Nirusu/PRESENT.go, kurtfu/present and OpenTitan's Python PRESENT compute
it.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_present_vectors.py

**A development tool, not a test.** `tests/test_present.rs` reads the
file offline.

Every witness speaks the specification's byte order, most significant
byte first; kurtfu/present reads the reverse, which its driver undoes.

The published tests - the paper's four with an 80 bit key and
PRESENT.go's five with a 128 bit one, which the build has already
required every witness to reproduce - and NESSIE's test sets in
shape: every single-bit key at each key length under a zero block,
every single-bit block and key and block both one byte repeated for
every byte with the shortest key, and a seeded generator's keys and
blocks at each length; then blocks encrypted and decrypted 100 and
1,000 times over. Every witness of the cipher answers every request,
decryption included, and a row is written only where all of them agree
and decryption gives the block back.

    <cipher> key=<hex> pt=<hex> ct=<hex>             one block
    <cipher>-iter key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "present.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

# The cipher: its block size, its key lengths and the programs that
# compute it.
CIPHERS = {"present": (8, (10, 16), ("presentgo", "kurtfu", "opentitan"))}


def ask(cipher, sources, requests):
    """Every request to every source; the answers, which must agree."""
    answers = []
    for source in sources:
        name = f"{cipher}-{source}"
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(requests) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, *each in zip(requests, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the {cipher} witnesses disagree on {request}: {each}")
    return answers[0]


def rows_for(cipher, rng):
    block, lengths, sources = CIPHERS[cipher]
    published = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, cipher)]
    single = []
    for key, pt, _ in published:
        if (key, pt, "published") not in single:
            single.append((key, pt, "published"))
    for keylen in lengths:
        for bit in range(8 * keylen):
            single.append(((1 << (8 * keylen - 1 - bit)).to_bytes(keylen, "big"), bytes(block), None))
    short = lengths[0]
    for bit in range(8 * block):
        single.append((bytes(short), (1 << (8 * block - 1 - bit)).to_bytes(block, "big"), None))
    for byte in range(256):
        single.append((bytes([byte]) * short, bytes([byte]) * block, None))
    for keylen in lengths:
        for _ in range(32):
            single.append((rng.randbytes(keylen), rng.randbytes(block), None))

    cts = ask(cipher, sources, [f"enc {k.hex()} {p.hex()}" for k, p, _ in single])
    back = ask(cipher, sources, [f"dec {k.hex()} {c}" for (k, _, _), c in zip(single, cts)])
    for (key, pt, _), again in zip(single, back):
        if again != pt.hex():
            sys.exit(f"{cipher}: decryption does not give the block back: {key.hex()} {pt.hex()}")
    answer = {(k, p): c for (k, p, _), c in zip(single, cts)}
    for key, pt, ct in published:
        if answer[(key, pt)] != ct.hex():
            sys.exit(f"{cipher}: a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for keylen in lengths:
        for _ in range(4):
            key, pt = rng.randbytes(keylen), rng.randbytes(block)
            iterated += [(key, pt, 100), (key, pt, 1000)]
        iterated.append((bytes(keylen), bytes(block), 1000))
    ict = ask(cipher, sources, [f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated])
    iback = ask(cipher, sources, [f"dec-n {k.hex()} {c} {n}" for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{cipher}: {n} decryptions do not give the block back: {key.hex()}")

    rows = [f"{cipher} key={k.hex()} pt={p.hex()} ct={c}" + (" src=published" if src else "")
            for (k, p, src), c in zip(single, cts)]
    rows += [f"{cipher}-iter key={k.hex()} pt={p.hex()} ct={c} n={n}"
             for (k, p, n), c in zip(iterated, ict)]
    return rows


def main():
    rng = random.Random(0x70726573656e74)  # "present"
    rows = []
    for cipher in CIPHERS:
        rows += rows_for(cipher, rng)
    with open(OUTPUT, "w") as out:
        out.write("# PRESENT with 80 and 128 bit keys. Nirusu/PRESENT.go, kurtfu/present and\n"
                  "# OpenTitan's Python PRESENT agree on every row, both directions; keys\n"
                  "# and blocks most significant byte first. src=published marks the\n"
                  "# paper's tests and PRESENT.go's.\n"
                  "# Written by scripts/make_present_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
