#!/usr/bin/env python3
"""Write vectors/misty1.vec: MISTY1 as Botan 1.10.17 and Crypt::Misty1
1.1.3 compute it.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_misty1_vectors.py

**A development tool, not a test.** `tests/test_misty1.rs` reads the
file offline.

`src/block_ciphers/misty1.rs` parses S7 and S9 out of RFC 2994 itself.
Before anything else this requires the two witnesses' tables, read out
of their sources, to be the RFC's as well, so a vector cannot come from
a witness whose tables differ from the document's. Then the published
tests Botan's validate.dat carries, the RFC's example among them, which
the build has already required both to reproduce, and NESSIE's test sets
in shape: every single-bit key under a zero block, every single-bit
block under a zero key, key and block both one byte repeated for every
byte, and a seeded generator's keys and blocks; then blocks encrypted
and decrypted 100 and 1,000 times over. Both witnesses answer every
request, decryption included, and a row is written only where they
agree with each other and decryption gives the block back.

    misty1 key=<hex> pt=<hex> ct=<hex>             one block
    misty1-iter key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "misty1.vec")
RFC = os.path.join(ROOT, "rfcs", "rfc2994.txt")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

PROGRAMS = ("misty1-botan", "misty1-reference")


def c_array(path, opening, count):
    text = open(os.path.join(WITNESS, "src", path)).read()
    at = text.index(opening) + len(opening)
    values = [int(v, 0) for v in
              re.findall(r"0[xX][0-9a-fA-F]+|\d+", text[at:text.index("}", at)])]
    if len(values) != count:
        sys.exit(f"{path}: {len(values)} entries under {opening!r}, not {count}")
    return values


def rfc_table(heading, count):
    """The table RFC 2994 prints under `heading`: rows of a hex label,
    a colon and sixteen entries, each label the index of its first."""
    text = open(RFC).read()
    values = []
    for line in text[text.index(heading) + len(heading):].split("\n"):
        match = re.fullmatch(r"\s*([0-9a-f]+):((?:\s+[0-9a-f]+){16})\s*", line)
        if match:
            if int(match.group(1), 16) != len(values):
                sys.exit(f"RFC 2994's {heading} has a row out of place")
            values += [int(v, 16) for v in match.group(2).split()]
            if len(values) == count:
                return values
    sys.exit(f"RFC 2994's {heading}: {len(values)} entries, not {count}")


def check_tables():
    for heading, count, botan, reference in [
            ("S7TABLE:", 128, "static const byte MISTY1_SBOX_S7[128] = {",
             "static unsigned char s7[128] = {"),
            ("S9TABLE:", 512, "static const u16bit MISTY1_SBOX_S9[512] = {",
             "static unsigned short s9[512] = {")]:
        rfc = rfc_table(heading, count)
        if c_array("botan/misty1.cpp", botan, count) != rfc:
            sys.exit(f"Botan's {heading[:2]} is not RFC 2994's")
        if c_array("reference/_misty1.c", reference, count) != rfc:
            sys.exit(f"Crypt::Misty1's {heading[:2]} is not RFC 2994's")


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
    check_tables()
    rng = random.Random(0x6d6973747931)  # "misty1"
    single = []    # (key, pt, src)
    published = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "misty1")]
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
        rows.append(f"misty1 key={key.hex()} pt={pt.hex()} ct={ct}"
                    + (" src=published" if src else ""))
    for (key, pt, n), ct in zip(iterated, ict):
        rows.append(f"misty1-iter key={key.hex()} pt={pt.hex()} ct={ct} n={n}")
    with open(OUTPUT, "w") as out:
        out.write("# MISTY1. Botan 1.10.17 and Crypt::Misty1 1.1.3 agree on every row, both\n"
                  "# directions, and their S7 and S9 are RFC 2994's; src=published marks\n"
                  "# the tests Botan's validate.dat carries, the RFC's example among them.\n"
                  "# Written by scripts/make_misty1_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
