#!/usr/bin/env python3
"""Write vectors/safer.vec: SAFER K-64, K-128, SK-64 and SK-128 as
libtomcrypt 1.18.2 and Crypto++ 8.9.0 compute them, and SK-128 as Botan
1.10.17 does too, at every round count the witnesses share.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_safer_vectors.py

**A development tool, not a test.** `tests/test_safer.rs` reads the file
offline.

libtomcrypt takes 6 to 13 rounds, Crypto++ and Botan 1 to 13, so every
variant is written at 6 to 13 rounds and SK-128, which Botan has too, at
1 to 13; a round count only one witness takes is not written. The inputs
are the published tests the three carry, at the round counts their
projects run them - which the build has already required each to
reproduce - and NESSIE's test sets in shape at the variant's usual round
count: every single-bit key under a zero block, every single-bit block
under a zero key, key and block both one byte repeated for every byte,
and a seeded generator's keys and blocks; random blocks at every other
round count; and blocks encrypted and decrypted 100 and 1,000 times
over. Every witness answers every request, decryption included, and a
row is written only where they agree and decryption gives the block
back.

    <variant> rounds=<r> key=<hex> pt=<hex> ct=<hex>             one block
    <variant>-iter rounds=<r> key=<hex> pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "safer.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

# variant: (key length, usual rounds, {source: the round counts it takes})
VARIANTS = {
    "safer-k64": (8, 6, {"libtomcrypt": range(6, 14), "cryptopp": range(1, 14)}),
    "safer-k128": (16, 10, {"libtomcrypt": range(6, 14), "cryptopp": range(1, 14)}),
    "safer-sk64": (8, 8, {"libtomcrypt": range(6, 14), "cryptopp": range(1, 14)}),
    "safer-sk128": (16, 10, {"libtomcrypt": range(6, 14), "cryptopp": range(1, 14),
                             "botan": range(1, 14)}),
}


def witnesses(variant, rounds):
    return [s for s, taken in VARIANTS[variant][2].items() if rounds in taken]


def ask(variant, rounds, op, rows):
    """`op` on every (key, block[, n]) from every witness that takes
    `rounds`; the answers, which must agree."""
    names = witnesses(variant, rounds)
    requests = [" ".join([op] + [x.hex() if isinstance(x, bytes) else str(x) for x in r])
                for r in rows]
    answers = []
    for source in names:
        out = selftest.ask(os.path.join(WITNESS, f"{variant}-{source}"), requests, rounds)
        if len(out) != len(rows) or any(a.startswith("error") for a in out):
            sys.exit(f"{variant}-{source} did not answer every request at {rounds} rounds")
        answers.append(out)
    for request, *each in zip(requests, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the witnesses disagree at {rounds} rounds on {request}: {each}")
    return [bytes.fromhex(a) for a in answers[0]]


def main():
    rng = random.Random(0x7361666572)  # "safer"
    rows = []
    published_count = 0
    for variant, (keylen, usual, taken) in VARIANTS.items():
        counts = sorted(r for r in range(1, 14) if len(witnesses(variant, r)) >= 2)
        # (rounds, key, block, published)
        single = []
        published = list(selftest.vectors(WITNESS, variant))
        for key, pt, _, rounds in published:
            single.append((rounds, key, pt, True))
        for bit in range(8 * keylen):
            single.append((usual, (1 << (8 * keylen - 1 - bit)).to_bytes(keylen, "big"),
                           bytes(8), False))
        for bit in range(64):
            single.append((usual, bytes(keylen), (1 << (63 - bit)).to_bytes(8, "big"), False))
        for byte in range(256):
            single.append((usual, bytes([byte]) * keylen, bytes([byte]) * 8, False))
        for _ in range(32):
            single.append((usual, rng.randbytes(keylen), rng.randbytes(8), False))
        for rounds in counts:
            if rounds != usual:
                for _ in range(24):
                    single.append((rounds, rng.randbytes(keylen), rng.randbytes(8), False))
        answer = {}
        for rounds in counts:
            these = [(k, p) for r, k, p, _ in single if r == rounds]
            cts = ask(variant, rounds, "enc", these)
            back = ask(variant, rounds, "dec", [(k, c) for (k, _), c in zip(these, cts)])
            for (key, pt), ct, again in zip(these, cts, back):
                if again != pt:
                    sys.exit(f"decryption does not give the block back: {variant} {key.hex()}")
                answer[(rounds, key, pt)] = ct
        for key, pt, ct, rounds in published:
            if answer[(rounds, key, pt)] != ct:
                sys.exit(f"a published test fails: {variant} {rounds} {key.hex()} {pt.hex()}")
        for rounds, key, pt, src in single:
            rows.append(f"{variant} rounds={rounds} key={key.hex()} pt={pt.hex()} "
                        f"ct={answer[(rounds, key, pt)].hex()}" + (" src=published" if src else ""))
            published_count += src

        iterated = [(usual, rng.randbytes(keylen), rng.randbytes(8), n)
                    for _ in range(4) for n in (100, 1000)]
        iterated.append((usual, bytes(keylen), bytes(8), 1000))
        iterated.append((max(counts), rng.randbytes(keylen), rng.randbytes(8), 1000))
        iterated.append((min(counts), rng.randbytes(keylen), rng.randbytes(8), 1000))
        for rounds, key, pt, n in iterated:
            [ct] = ask(variant, rounds, "enc-n", [(key, pt, n)])
            [again] = ask(variant, rounds, "dec-n", [(key, ct, n)])
            if again != pt:
                sys.exit(f"{n} decryptions do not give the block back: {variant} {key.hex()}")
            rows.append(f"{variant}-iter rounds={rounds} key={key.hex()} pt={pt.hex()} "
                        f"ct={ct.hex()} n={n}")
    with open(OUTPUT, "w") as out:
        out.write("# SAFER K-64, K-128, SK-64 and SK-128. libtomcrypt 1.18.2 and Crypto++\n"
                  "# 8.9.0 agree on every row from 6 to 13 rounds, and Botan 1.10.17 with them\n"
                  "# on SK-128, at 1 to 13 with Crypto++; both directions. src=published marks\n"
                  "# the tests the three carry.\n"
                  "# Written by scripts/make_safer_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows, {published_count} published, to {OUTPUT}")


if __name__ == "__main__":
    main()
