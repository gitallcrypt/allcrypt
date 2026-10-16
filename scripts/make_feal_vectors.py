#!/usr/bin/env python3
"""Write vectors/feal.vec: FEAL-N and FEAL-NX at several round counts, as
zilijonas/FEAL-NX's Java and Donaldduck8's Python compute them, and copy
NTT's FEAL-NX test data to vectors/feal_nx_ntt.txt.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_feal_vectors.py

**A development tool, not a test.** `tests/test_feal.rs` reads both
files offline.

NTT's data - ten keys, each with 4,096 blocks, at FEAL-NX's 32 rounds,
which the build has already required both witnesses to reproduce both
ways - is copied as NTT published it, in Shift JIS, after its hash is
checked against the build's manifest. It covers one key schedule and
one round count, so the rows here cover the others: FEAL-N with its 8
byte key at 4, 8, 16 and 32 rounds - FEAL-4 and FEAL-8 among them - and
FEAL-NX at 2, 8, 32 and 64. At each: every single-bit key under a zero
block, every single-bit block under a zero key, key and block both one
byte repeated for sixteen bytes, and a seeded generator's keys and
blocks; then blocks encrypted and decrypted 100 and 1,000 times over.
Both witnesses take FEAL-N's key as FEAL-NX's with the right half zero,
which is how the FEAL-NX specification defines FEAL-N. A row is written
only where both agree, both ways.

    <cipher> key=<hex> pt=<hex> ct=<hex> rounds=<N>             one block
    <cipher>-iter key=<hex> pt=<hex> ct=<hex> rounds=<N> n=<n>  pt encrypted n times

where <cipher> is feal or feal-nx.
"""

import hashlib
import os
import random
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "feal.vec")
NTT = os.path.join(ROOT, "vectors", "feal_nx_ntt.txt")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
MANIFEST = os.path.join(HERE, "witness", "oldciphers", "oldciphers.sha256")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's way of asking the witnesses)

SOURCES = ("zilijonas", "donaldduck8")
# Each name: its key length and its round counts.
CIPHERS = {"feal": (8, (4, 8, 16, 32)), "feal-nx": (16, (2, 8, 32, 64))}


def ask(requests, rounds):
    """Every request to both witnesses at `rounds`; the answers, which
    must agree."""
    answers = []
    for source in SOURCES:
        name = f"feal-nx-{source}"
        out = selftest.ask(os.path.join(WITNESS, name), requests, rounds)
        if len(out) != len(requests) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, *each in zip(requests, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the FEAL witnesses disagree at {rounds} rounds on {request}: {each}")
    return answers[0]


def rows_for(cipher, rounds, rng):
    keylen, _ = CIPHERS[cipher]
    single = []
    for bit in range(8 * keylen):
        single.append(((1 << (8 * keylen - 1 - bit)).to_bytes(keylen, "big"), bytes(8)))
    for bit in range(64):
        single.append((bytes(keylen), (1 << (63 - bit)).to_bytes(8, "big")))
    for byte in range(0, 256, 17):
        single.append((bytes([byte]) * keylen, bytes([byte]) * 8))
    for _ in range(32):
        single.append((rng.randbytes(keylen), rng.randbytes(8)))
    cts = ask([f"enc {k.hex()} {p.hex()}" for k, p in single], rounds)
    back = ask([f"dec {k.hex()} {c}" for (k, _), c in zip(single, cts)], rounds)
    for (key, pt), again in zip(single, back):
        if again != pt.hex():
            sys.exit(f"{cipher}: decryption does not give the block back: {key.hex()} {pt.hex()}")

    iterated = []
    for _ in range(2):
        key, pt = rng.randbytes(keylen), rng.randbytes(8)
        iterated += [(key, pt, 100), (key, pt, 1000)]
    ict = ask([f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated], rounds)
    iback = ask([f"dec-n {k.hex()} {c} {n}" for (k, _, n), c in zip(iterated, ict)], rounds)
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{cipher}: {n} decryptions do not give the block back: {key.hex()}")
    rows = [f"{cipher} key={k.hex()} pt={p.hex()} ct={c} rounds={rounds}"
            for (k, p), c in zip(single, cts)]
    rows += [f"{cipher}-iter key={k.hex()} pt={p.hex()} ct={c} rounds={rounds} n={n}"
             for (k, p, n), c in zip(iterated, ict)]
    return rows


def main():
    pinned = dict(reversed(line.split()) for line in open(MANIFEST))
    source = os.path.join(WITNESS, "src", "feal", "test-vectors.txt")
    if hashlib.sha256(open(source, "rb").read()).hexdigest() != pinned["feal/test-vectors.txt"]:
        sys.exit("feal/test-vectors.txt is not the file the manifest pins; rebuild the witness")
    shutil.copyfile(source, NTT)

    rng = random.Random(0x6665616c)  # "feal"
    rows = []
    for cipher, (_, counts) in CIPHERS.items():
        for rounds in counts:
            rows += rows_for(cipher, rounds, rng)
    with open(OUTPUT, "w") as out:
        out.write("# FEAL-N (feal, an 8 byte key) and FEAL-NX (feal-nx, 16 bytes) at several\n"
                  "# round counts. zilijonas/FEAL-NX's Java and Donaldduck8's Python agree on\n"
                  "# every row, both directions; NTT's own FEAL-NX data at 32 rounds is\n"
                  "# feal_nx_ntt.txt.\n"
                  "# Written by scripts/make_feal_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT} and copied NTT's data to {NTT}")


if __name__ == "__main__":
    main()
