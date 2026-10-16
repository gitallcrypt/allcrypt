#!/usr/bin/env python3
"""Write vectors/saferplus.vec: SAFER+ as libtomcrypt 1.18.2 computes it,
and in the word order libmcrypt 2.5.8 uses.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_saferplus_vectors.py

**A development tool, not a test.** `tests/test_saferplus.rs` reads the
file offline.

The two orders are one cipher: libmcrypt reverses the order of the
32-bit words of the key, the block and the result, leaving each word's
bytes alone. So every request goes to both witnesses - to libtomcrypt as
it is, to libmcrypt with every string's words reversed - and a row is
written only where the two agree, decryption included. The inputs:
libtomcrypt's published tests, which the build has already required both
to reproduce, and NESSIE's test sets in shape - every single-bit key at
each key length, 16, 24 and 32 bytes, under a zero block, and with a
16-byte key every single-bit block under a zero key and key and block
both one byte repeated for every byte - and a seeded generator's keys
and blocks at each length; then blocks encrypted and decrypted 100 and
1,000 times over. The reversed-words rows repeat the published tests,
the random blocks and the iterated runs in libmcrypt's order; the rest
are the same inputs again, and the order is a fixed rearrangement.

    saferplus key=<hex> pt=<hex> ct=<hex>                     one block
    saferplus-reversed-words key=<hex> pt=<hex> ct=<hex>      the same, libmcrypt's order
    saferplus-iter key=<hex> pt=<hex> ct=<hex> n=<n>          pt encrypted n times
    saferplus-reversed-words-iter key=<hex> pt=<hex> ct=<hex> n=<n>

Each row ends `src=published` when it is one of libtomcrypt's tests, in
the order of its kind.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "saferplus.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

STRAIGHT = "saferplus-libtomcrypt"
REVERSED = "saferplus-reversed-words-mcrypt"
rev = selftest.reverse_words


def ask(op, rows):
    """`op` on every (key, block[, n]) in libtomcrypt's order, from both
    witnesses; the answers, which must agree."""
    answers = []
    for name in (STRAIGHT, REVERSED):
        flip = name == REVERSED
        requests = [" ".join([op, (rev(r[0]) if flip else r[0]).hex(),
                              (rev(r[1]) if flip else r[1]).hex()] + [str(n) for n in r[2:]])
                    for r in rows]
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(rows) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append([rev(bytes.fromhex(a)) if flip else bytes.fromhex(a) for a in out])
    for row, a, b in zip(rows, *answers):
        if a != b:
            sys.exit(f"the witnesses disagree on {op} {row[0].hex()} {row[1].hex()}: "
                     f"{a.hex()} {b.hex()}")
    return answers[0]


def main():
    rng = random.Random(0x7361666572706c)  # "saferpl"
    published = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "saferplus")]
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
            single.append((rng.randbytes(keylen), rng.randbytes(16), "random"))
    # Each input in the other order too, so that the reversed rows have
    # the same inputs as the straight ones.
    inputs = [(k, p) for k, p, _ in single] + [(rev(k), rev(p)) for k, p, _ in single]
    cts = ask("enc", inputs)
    back = ask("dec", [(k, c) for (k, _), c in zip(inputs, cts)])
    for (key, pt), again in zip(inputs, back):
        if again != pt:
            sys.exit(f"decryption does not give the block back: {key.hex()} {pt.hex()}")
    answer = dict(zip(inputs, cts))
    for key, pt, ct in published:
        if answer[(key, pt)] != ct:
            sys.exit(f"a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for keylen in (16, 24, 32):
        for _ in range(4):
            key, pt = rng.randbytes(keylen), rng.randbytes(16)
            for n in (100, 1000):
                iterated.append((key, pt, n))
        iterated.append((bytes(keylen), bytes(16), 1000))
    ict = ask("enc-n", iterated)
    iback = ask("dec-n", [(k, c, n) for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt:
            sys.exit(f"{n} decryptions do not give the block back: {key.hex()}")
    # Reversing between every step cancels, so n encryptions in the
    # reversed order are n in libtomcrypt's order, reversed.
    riterated = [(rev(k), rev(p), n) for k, p, n in iterated]
    rict = ask("enc-n", riterated)

    rows = []
    for key, pt, src in single:
        rows.append(f"saferplus key={key.hex()} pt={pt.hex()} ct={answer[(key, pt)].hex()}"
                    + (" src=published" if src == "published" else ""))
    for key, pt, src in single:
        if src is None:
            continue
        # libmcrypt's cipher on (key, pt) is libtomcrypt's on the
        # word-reversed strings, its result word-reversed.
        rkey, rpt, ct = rev(key), rev(pt), rev(answer[(key, pt)])
        rows.append(f"saferplus-reversed-words key={rkey.hex()} pt={rpt.hex()} ct={ct.hex()}"
                    + (" src=published" if src == "published" else ""))
    for (key, pt, n), ct in zip(iterated, ict):
        rows.append(f"saferplus-iter key={key.hex()} pt={pt.hex()} ct={ct.hex()} n={n}")
    for (key, pt, n), ct in zip(riterated, rict):
        rows.append(f"saferplus-reversed-words-iter key={rev(key).hex()} pt={rev(pt).hex()} "
                    f"ct={rev(ct).hex()} n={n}")
    with open(OUTPUT, "w") as out:
        out.write("# SAFER+. saferplus rows are libtomcrypt 1.18.2's byte order;\n"
                  "# saferplus-reversed-words rows are libmcrypt 2.5.8's, the 32-bit words of\n"
                  "# key, block and result reversed. The two agree on every row once the order\n"
                  "# is accounted for, both directions; src=published marks libtomcrypt's\n"
                  "# tests.\n"
                  "# Written by scripts/make_saferplus_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
