#!/usr/bin/env python3
"""Write vectors/simon_speck.vec: Speck and Simon at every block size,
32, 48, 64, 96 and 128 bits, as Crypto++ 8.9.0 (64 and 128), the Linux
kernel (v4.19, Speck at 64 and 128), jedisct1/rust-lwbc (32 to 96, one
key length each) and inmcm's Python reference (all) compute them.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_simon_speck_vectors.py

**A development tool, not a test.** `tests/test_simon_speck.rs` reads
the file offline.

Every witness reads a key and a block as the little-endian encoding of
the paper's numbers - each word little-endian, the block's y first, the
key's first word first - which is the encoding the designers gave and
the one the published tests here are written in.

For each cipher: the published tests - Crypto++'s at 64 and 128 bits,
the paper's as inmcm's tests carry them at the others, which the build
has already required every witness to reproduce - and NESSIE's test sets in
shape: every single-bit key at each key length under a zero block,
every single-bit block and key and block both one byte repeated for
every byte with the shortest key, and a seeded generator's keys and
blocks at each length; then blocks encrypted and decrypted 100 and
1,000 times over. Every witness that takes a row's key length answers
it, decryption included, and a row is written only where all of them
agree and decryption gives the block back. lwbc has one key length at
each of the 32, 48 and 96 bit sizes, so at Speck48/72, Speck96/96,
Simon48/72 and Simon96/96 inmcm is the only witness, and those rows end
`witnesses=1`.

    <cipher> key=<hex> pt=<hex> ct=<hex>             one block
    <cipher>-iter key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "simon_speck.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

# Each cipher: its block size, its key lengths and the programs that
# compute it, each with the key lengths it takes, or None for all.
# The 64 and 128 bit sizes come first, as they did before the others
# were added, so their rows are the same.
CIPHERS = {
    "speck64": (8, (12, 16), {"cryptopp": None, "kernel": None, "inmcm": None, "lwbc": (16,)}),
    "speck128": (16, (16, 24, 32), {"cryptopp": None, "kernel": None, "inmcm": None}),
    "simon64": (8, (12, 16), {"cryptopp": None, "inmcm": None, "lwbc": (16,)}),
    "simon128": (16, (16, 24, 32), {"cryptopp": None, "inmcm": None}),
    "speck32": (4, (8,), {"inmcm": None, "lwbc": None}),
    "speck48": (6, (9, 12), {"inmcm": None, "lwbc": (12,)}),
    "speck96": (12, (12, 18), {"inmcm": None, "lwbc": (18,)}),
    "simon32": (4, (8,), {"inmcm": None, "lwbc": None}),
    "simon48": (6, (9, 12), {"inmcm": None, "lwbc": (12,)}),
    "simon96": (12, (12, 18), {"inmcm": None, "lwbc": (18,)}),
}


def witnesses(cipher, keylen):
    """The programs that take a key of `keylen` bytes."""
    return [source for source, lengths in CIPHERS[cipher][2].items()
            if lengths is None or keylen in lengths]


def ask(cipher, requests):
    """Every request to every source that takes its key; the answers,
    which must agree."""
    answers = [None] * len(requests)
    for keylen in sorted({len(r.split()[1]) // 2 for r in requests}):
        at = [i for i, r in enumerate(requests) if len(r.split()[1]) // 2 == keylen]
        some = [requests[i] for i in at]
        outs = []
        for source in witnesses(cipher, keylen):
            name = f"{cipher}-{source}"
            out = selftest.ask(os.path.join(WITNESS, name), some)
            if len(out) != len(some) or any(a.startswith("error") for a in out):
                sys.exit(f"{name} did not answer every request")
            outs.append(out)
        for i, request, *each in zip(at, some, *outs):
            if len(set(each)) != 1:
                sys.exit(f"the {cipher} witnesses disagree on {request}: {each}")
            answers[i] = each[0]
    return answers


def rows_for(cipher, rng):
    block, lengths, _ = CIPHERS[cipher]
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

    cts = ask(cipher, [f"enc {k.hex()} {p.hex()}" for k, p, _ in single])
    back = ask(cipher, [f"dec {k.hex()} {c}" for (k, _, _), c in zip(single, cts)])
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
    ict = ask(cipher, [f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated])
    iback = ask(cipher, [f"dec-n {k.hex()} {c} {n}" for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{cipher}: {n} decryptions do not give the block back: {key.hex()}")

    alone = lambda key: " witnesses=1" if len(witnesses(cipher, len(key))) == 1 else ""  # noqa: E731
    rows = [f"{cipher} key={k.hex()} pt={p.hex()} ct={c}" + (" src=published" if src else "")
            + alone(k) for (k, p, src), c in zip(single, cts)]
    rows += [f"{cipher}-iter key={k.hex()} pt={p.hex()} ct={c} n={n}" + alone(k)
             for (k, p, n), c in zip(iterated, ict)]
    return rows


def main():
    rng = random.Random(0x73696d6f6e)  # "simon"
    rows = []
    for cipher in CIPHERS:
        rows += rows_for(cipher, rng)
    with open(OUTPUT, "w") as out:
        out.write("# Speck and Simon at every block size. Every witness that takes a row's\n"
                  "# key length agrees on it, both directions: Crypto++ 8.9.0 and inmcm's\n"
                  "# Python at 64 and 128 bits, with the Linux kernel (v4.19) for Speck and\n"
                  "# lwbc at 64 bits with a 16 byte key; inmcm and lwbc at 32, 48 and 96\n"
                  "# bits, lwbc at one key length each. witnesses=1 marks the rows inmcm\n"
                  "# alone computes. Keys and blocks are the little-endian encoding of the\n"
                  "# paper's numbers. src=published marks Crypto++'s tests and the paper's.\n"
                  "# Written by scripts/make_simon_speck_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
