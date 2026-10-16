#!/usr/bin/env python3
"""Write vectors/skipjack.vec: Skipjack in the specification's byte order,
as libtomcrypt 1.18.2 and Bouncy Castle 1.77 compute it, and in the
reversed order Crypto++ 8.9.0 and Botan 1.10.17 use.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_skipjack_vectors.py

**A development tool, not a test.** `tests/test_skipjack.rs` reads the
file offline.

The two orders are one cipher: Crypto++ and Botan read the key, the
block and the result each in reverse byte order. So every request goes
to all four witnesses - to libtomcrypt and Bouncy Castle as it is, to
Crypto++ and Botan with every string reversed - and a row is written
only where all four agree, decryption included. The inputs are the
published tests the four carry, which the build has already required
each to reproduce, and NESSIE's test sets in shape: every single-bit key
under a zero block, every single-bit block under a zero key, key and
block both one byte repeated for every byte, and a seeded generator's
keys and blocks; then blocks encrypted and decrypted 100 and 1,000 times
over.

    skipjack key=<hex> pt=<hex> ct=<hex>                    one block
    skipjack-reversed key=<hex> pt=<hex> ct=<hex>           the same, reversed order
    skipjack-iter key=<hex> pt=<hex> ct=<hex> n=<n>         pt encrypted n times
    skipjack-reversed-iter key=<hex> pt=<hex> ct=<hex> n=<n>

Each row ends `src=published` when it is one of the published tests, in
the order its project prints it.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "skipjack.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

STRAIGHT = ("skipjack-libtomcrypt", "skipjack-bc")
REVERSED = ("skipjack-reversed-cryptopp", "skipjack-reversed-botan")


def rev(data):
    return bytes(reversed(data))


def ask(op, rows):
    """`op` on every (key, block[, n]) in the specification's order, from
    all four witnesses; the answers, which must agree."""
    answers = []
    for name in STRAIGHT + REVERSED:
        flip = name in REVERSED
        requests = [" ".join([op, (rev(r[0]) if flip else r[0]).hex(),
                              (rev(r[1]) if flip else r[1]).hex()] + [str(n) for n in r[2:]])
                    for r in rows]
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(rows) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append([rev(bytes.fromhex(a)) if flip else bytes.fromhex(a) for a in out])
    for row, *each in zip(rows, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the witnesses disagree on {op} {row[0].hex()} {row[1].hex()}: "
                     + " ".join(a.hex() for a in each))
    return answers[0]


def main():
    rng = random.Random(0x736b69706a61)  # "skipja"
    straight = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "skipjack")]
    backwards = [(k, p, c) for k, p, c, _ in selftest.vectors(WITNESS, "skipjack-reversed")]
    # (key, block, published) in the specification's order; a reversed
    # project's test enters reversed.
    single = [(k, p, "straight") for k, p, _ in straight]
    single += [(rev(k), rev(p), "reversed") for k, p, _ in backwards]
    for bit in range(80):
        single.append(((1 << (79 - bit)).to_bytes(10, "big"), bytes(8), None))
    for bit in range(64):
        single.append((bytes(10), (1 << (63 - bit)).to_bytes(8, "big"), None))
    for byte in range(256):
        single.append((bytes([byte]) * 10, bytes([byte]) * 8, None))
    for _ in range(64):
        single.append((rng.randbytes(10), rng.randbytes(8), None))
    # Each input in the other order too, so that the reversed rows have
    # the same inputs as the straight ones.
    inputs = [(k, p) for k, p, _ in single]
    inputs += [(rev(k), rev(p)) for k, p, _ in single]
    cts = ask("enc", inputs)
    back = ask("dec", [(k, c) for (k, _), c in zip(inputs, cts)])
    for (key, pt), again in zip(inputs, back):
        if again != pt:
            sys.exit(f"decryption does not give the block back: {key.hex()} {pt.hex()}")
    answer = dict(zip(inputs, cts))
    for key, pt, ct in straight:
        if answer[(key, pt)] != ct:
            sys.exit(f"a published test fails: {key.hex()} {pt.hex()}")
    for key, pt, ct in backwards:
        if rev(answer[(rev(key), rev(pt))]) != ct:
            sys.exit(f"a published reversed test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for _ in range(8):
        key, pt = rng.randbytes(10), rng.randbytes(8)
        for n in (100, 1000):
            iterated.append((key, pt, n))
    iterated.append((bytes(10), bytes(8), 1000))
    ict = ask("enc-n", iterated)
    iback = ask("dec-n", [(k, c, n) for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt:
            sys.exit(f"{n} decryptions do not give the block back: {key.hex()}")
    # Reversing between every step cancels, so n encryptions in the
    # reversed order are n in the specification's order, reversed.
    riterated = [(rev(k), rev(p), n) for k, p, n in iterated]
    rict = ask("enc-n", riterated)

    rows = []
    for key, pt, src in single:
        rows.append(f"skipjack key={key.hex()} pt={pt.hex()} ct={answer[(key, pt)].hex()}"
                    + (" src=published" if src == "straight" else ""))
    for key, pt, src in single:
        # The reversed cipher on (key, pt) is the specification's on the
        # reversed strings, reversed; a reversed project's published test
        # is written as that project prints it.
        rkey, rpt = rev(key), rev(pt)
        ct = rev(answer[(key, pt)])
        rows.append(f"skipjack-reversed key={rkey.hex()} pt={rpt.hex()} ct={ct.hex()}"
                    + (" src=published" if src == "reversed" else ""))
    for (key, pt, n), ct in zip(iterated, ict):
        rows.append(f"skipjack-iter key={key.hex()} pt={pt.hex()} ct={ct.hex()} n={n}")
    for (key, pt, n), ct in zip(riterated, rict):
        rows.append(f"skipjack-reversed-iter key={rev(key).hex()} pt={rev(pt).hex()} "
                    f"ct={rev(ct).hex()} n={n}")
    with open(OUTPUT, "w") as out:
        out.write("# Skipjack. skipjack rows are the specification's byte order, on which\n"
                  "# libtomcrypt 1.18.2 and Bouncy Castle 1.77 agree; skipjack-reversed rows\n"
                  "# are Crypto++ 8.9.0's and Botan 1.10.17's, every string reversed, on\n"
                  "# which those two agree - and all four agree on every row, both\n"
                  "# directions. src=published marks the tests the four carry.\n"
                  "# Written by scripts/make_skipjack_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
