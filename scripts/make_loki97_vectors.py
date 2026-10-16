#!/usr/bin/env python3
"""Write vectors/loki97.vec: LOKI97 as its designers' reference C
computes it, and as libmcrypt 2.5.8 does.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_loki97_vectors.py

**A development tool, not a test.** `tests/test_loki97.rs` reads the
file offline.

The reference is the C Crypt::Loki97 1.0.1 carries, built with its word
halves 32 bits wide (see the build script). libmcrypt computes another
function under the same name: every 32-bit word of the key, the block
and the result byte-swapped, and only the 32 byte key schedule, so a
shorter key is the 32 byte one with zeros after it. Its cipher on
`(key, block)` is the reference's on `(swap(key) + zeros, swap(block))`,
swapped back, and every libmcrypt request here is put to the reference
in that form as well.

    loki97 key=<hex> pt=<hex> ct=<hex>                   one block
    loki97-mcrypt key=<hex> pt=<hex> ct=<hex>            libmcrypt's form
    loki97-iter key=<hex> pt=<hex> ct=<hex> n=<n>        pt encrypted n times
    loki97-mcrypt-iter key=<hex> pt=<hex> ct=<hex> n=<n>

The inputs: the published tests - the reference's self-test, Crypt::
Loki97's tests and libmcrypt's self-test, which the build has already
required the witnesses to reproduce - and NESSIE's test sets in shape:
every single-bit key at each length, 16, 24 and 32 bytes, under a zero
block, every single-bit block and key and block both one byte repeated
for every byte with a 16 byte key, and a seeded generator's keys and
blocks at each length; then blocks encrypted and decrypted 100 and
1,000 times over. Every answer is checked by decrypting it again.

**Where libmcrypt cannot give a second answer, the row says so.**
libmcrypt has no 16 or 24 byte LOKI97, so a `loki97` row with such a key
is the reference's alone and ends `witnesses=1`; every other row was
given by both and agreed. Each row ends `src=published` when it is one
of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "loki97.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

REFERENCE = "loki97-reference"
MCRYPT = "loki97-mcrypt-mcrypt"
swap = selftest.swap_word_bytes


def as_reference(key):
    """The reference's key for libmcrypt's `key`."""
    return swap(key) + bytes(32 - len(key))


def run(program, op, rows):
    requests = [" ".join([op, r[0].hex(), r[1].hex()] + [str(n) for n in r[2:]]) for r in rows]
    out = selftest.ask(os.path.join(WITNESS, program), requests)
    if len(out) != len(rows) or any(a.startswith("error") for a in out):
        sys.exit(f"{program} did not answer every request")
    return [bytes.fromhex(a) for a in out]


def straight(op, rows):
    """`op` on (key, block[, n]) rows in the reference's own form: the
    reference's answers, and libmcrypt's, swapped, where the key is 32
    bytes and it can give one - which must agree."""
    answers = run(REFERENCE, op, rows)
    long_rows = [i for i, r in enumerate(rows) if len(r[0]) == 32]
    if long_rows:
        theirs = run(MCRYPT, op, [(swap(rows[i][0]), swap(rows[i][1]), *rows[i][2:])
                                  for i in long_rows])
        for i, answer in zip(long_rows, theirs):
            if swap(answer) != answers[i]:
                sys.exit(f"the witnesses disagree on {op} {rows[i][0].hex()} {rows[i][1].hex()}")
    return answers


def mcrypt(op, rows):
    """`op` on (key, block[, n]) rows in libmcrypt's form: its answers,
    which the reference's on the transformed rows must equal."""
    answers = run(MCRYPT, op, rows)
    theirs = run(REFERENCE, op, [(as_reference(r[0]), swap(r[1]), *r[2:]) for r in rows])
    for row, a, b in zip(rows, answers, theirs):
        if a != swap(b):
            sys.exit(f"the witnesses disagree on {op} {row[0].hex()} {row[1].hex()} "
                     "in libmcrypt's form")
    return answers


def checked(ask, single):
    """Ciphertexts for (key, pt) rows, each decrypted again."""
    cts = ask("enc", single)
    back = ask("dec", [(k, c) for (k, _), c in zip(single, cts)])
    for (key, pt), again in zip(single, back):
        if again != pt:
            sys.exit(f"decryption does not give the block back: {key.hex()} {pt.hex()}")
    return cts


def iterated_rows(ask, rows):
    cts = ask("enc-n", rows)
    back = ask("dec-n", [(k, c, n) for (k, _, n), c in zip(rows, cts)])
    for (key, pt, n), again in zip(rows, back):
        if again != pt:
            sys.exit(f"{n} decryptions do not give the block back: {key.hex()}")
    return cts


def main():
    rng = random.Random(0x6c6f6b693937)  # "loki97"
    published = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "loki97")]
    mpublished = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "loki97-mcrypt")]

    single = [(k, p, "published") for k, p, _ in published]
    for keylen in (16, 24, 32):
        for bit in range(8 * keylen):
            single.append(((1 << (8 * keylen - 1 - bit)).to_bytes(keylen, "big"), bytes(16), None))
    for bit in range(128):
        single.append((bytes(16), (1 << (127 - bit)).to_bytes(16, "big"), None))
    for byte in range(256):
        single.append((bytes([byte]) * 16, bytes([byte]) * 16, None))
    for keylen in (16, 24, 32):
        for _ in range(32):
            single.append((rng.randbytes(keylen), rng.randbytes(16), None))
    cts = checked(straight, [(k, p) for k, p, _ in single])
    answer = dict(zip([(k, p) for k, p, _ in single], cts))
    for key, pt, ct in published:
        if answer[(key, pt)] != ct:
            sys.exit(f"a published test fails: {key.hex()} {pt.hex()}")

    msingle = [(k, p, "published") for k, p, _ in mpublished]
    for keylen in (16, 24, 32):
        for _ in range(32):
            msingle.append((rng.randbytes(keylen), rng.randbytes(16), None))
    mcts = checked(mcrypt, [(k, p) for k, p, _ in msingle])
    for (key, pt, ct), got in zip(mpublished, mcts):
        if got != ct:
            sys.exit(f"a published test fails in libmcrypt's form: {key.hex()} {pt.hex()}")

    iterated, miterated = [], []
    for keylen in (16, 24, 32):
        for target in (iterated, miterated):
            for _ in range(4):
                key, pt = rng.randbytes(keylen), rng.randbytes(16)
                target.extend([(key, pt, 100), (key, pt, 1000)])
            target.append((bytes(keylen), bytes(16), 1000))
    # Swapping between every step cancels, so n encryptions in one form
    # are n in the other with the ends swapped.
    icts = iterated_rows(straight, iterated)
    micts = iterated_rows(mcrypt, miterated)

    def tail(key, src):
        return (" src=published" if src else "") + (" witnesses=1" if len(key) != 32 else "")

    rows = []
    for (key, pt, src), ct in zip(single, cts):
        rows.append(f"loki97 key={key.hex()} pt={pt.hex()} ct={ct.hex()}" + tail(key, src))
    for (key, pt, src), ct in zip(msingle, mcts):
        rows.append(f"loki97-mcrypt key={key.hex()} pt={pt.hex()} ct={ct.hex()}"
                    + (" src=published" if src else ""))
    for (key, pt, n), ct in zip(iterated, icts):
        rows.append(f"loki97-iter key={key.hex()} pt={pt.hex()} ct={ct.hex()} n={n}"
                    + tail(key, None))
    for (key, pt, n), ct in zip(miterated, micts):
        rows.append(f"loki97-mcrypt-iter key={key.hex()} pt={pt.hex()} ct={ct.hex()} n={n}")
    with open(OUTPUT, "w") as out:
        out.write("# LOKI97. loki97 rows are the designers' reference C's; loki97-mcrypt rows\n"
                  "# are libmcrypt 2.5.8's, every 32-bit word byte-swapped and the key\n"
                  "# zero-padded to 32 bytes. Both witnesses agree on every row, both\n"
                  "# directions, except those marked witnesses=1: libmcrypt has no 16 or 24\n"
                  "# byte LOKI97, so those are the reference's alone. src=published marks\n"
                  "# the reference's self-test, Crypt::Loki97's tests and libmcrypt's.\n"
                  "# Written by scripts/make_loki97_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
