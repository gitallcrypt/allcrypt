#!/usr/bin/env python3
"""Write vectors/threefish.vec: Threefish-256, -512 and -1024 as tweakable
block ciphers, as Crypto++ 8.9.0, Bouncy Castle 1.77 and Skein3Fish's C
compute them.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_threefish_vectors.py

**A development tool, not a test.** `tests/test_threefish.rs` reads the
file offline.

Every witness takes the key alone, with a tweak of zero, or the key
followed by the 16 byte tweak, as the catalogue does; each row says
which it was asked.

For each size: the published tests - Crypto++'s, from the Skein team's
known answers and Botan, which the build has already required every
witness to reproduce - then a key with one bit set in each of its
bytes, a tweak with each of its bits set, a block with one bit set in
each of its bytes, the bit moving through the byte's eight places, all
under the zero key or block; key, tweak and block each one byte repeated
for sixteen bytes; and a seeded generator's keys and blocks without a
tweak and with one; then blocks encrypted and decrypted 100 and 1,000
times over. A single bit in every byte rather than every bit keeps a
Threefish-1024 file small, and still moves through every word and every
place in a byte. Every witness answers every request, decryption
included, and a row is written only where all of them agree and
decryption gives the block back.

    <cipher> key=<hex> [tweak=<hex>] pt=<hex> ct=<hex>             one block
    <cipher>-iter key=<hex> [tweak=<hex>] pt=<hex> ct=<hex> n=<n>  pt encrypted n times

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "threefish.vec")
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
sys.path.insert(0, os.path.join(HERE, "witness", "oldciphers"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

CIPHERS = {"threefish256": 32, "threefish512": 64, "threefish1024": 128}
SOURCES = ("cryptopp", "bc", "skein3fish")


def ask(cipher, requests):
    """Every request to every source; the answers, which must agree."""
    answers = []
    for source in SOURCES:
        name = f"{cipher}-{source}"
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(requests) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, *each in zip(requests, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the {cipher} witnesses disagree on {request}: {each}")
    return answers[0]


def one_bit_per_byte(length):
    """`length` strings, string i with bit i mod 8 of its byte i set."""
    return [bytes(i) + bytes([0x80 >> (i % 8)]) + bytes(length - i - 1) for i in range(length)]


def row(cipher, key, tweak, pt, ct, extra=""):
    fields = f"key={key.hex()}" + (f" tweak={tweak.hex()}" if tweak is not None else "")
    return f"{cipher} {fields} pt={pt.hex()} ct={ct}{extra}"


def rows_for(cipher, rng):
    block = CIPHERS[cipher]
    published = []
    for k, p, c, _ in selftest.vectors(WITNESS, cipher):
        key, tweak = (k, None) if len(k) == block else (k[:block], k[block:])
        published.append((key, tweak, p, c))
    # (key, tweak or None, block, published)
    single = []
    for key, tweak, pt, _ in published:
        if (key, tweak, pt, True) not in single:
            single.append((key, tweak, pt, True))
    zero_key, zero_block = bytes(block), bytes(block)
    for key in one_bit_per_byte(block):
        single.append((key, None, zero_block, False))
    for bit in range(128):
        single.append((zero_key, (1 << (127 - bit)).to_bytes(16, "big"), zero_block, False))
    for pt in one_bit_per_byte(block):
        single.append((zero_key, None, pt, False))
    for byte in range(0, 256, 17):
        single.append((bytes([byte]) * block, bytes([byte]) * 16, bytes([byte]) * block, False))
    for _ in range(32):
        single.append((rng.randbytes(block), None, rng.randbytes(block), False))
        single.append((rng.randbytes(block), rng.randbytes(16), rng.randbytes(block), False))

    joined = lambda key, tweak: key + (tweak or b"")  # noqa: E731
    cts = ask(cipher, [f"enc {joined(k, t).hex()} {p.hex()}" for k, t, p, _ in single])
    back = ask(cipher, [f"dec {joined(k, t).hex()} {c}" for (k, t, _, _), c in zip(single, cts)])
    for (key, tweak, pt, _), again in zip(single, back):
        if again != pt.hex():
            sys.exit(f"{cipher}: decryption does not give the block back: {key.hex()} {pt.hex()}")
    answer = {(k, t, p): c for (k, t, p, _), c in zip(single, cts)}
    for key, tweak, pt, ct in published:
        if answer[(key, tweak, pt)] != ct.hex():
            sys.exit(f"{cipher}: a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for _ in range(3):
        key, tweak, pt = rng.randbytes(block), rng.randbytes(16), rng.randbytes(block)
        iterated += [(key, tweak, pt, 100), (key, tweak, pt, 1000)]
    iterated.append((zero_key, None, zero_block, 1000))
    ict = ask(cipher, [f"enc-n {joined(k, t).hex()} {p.hex()} {n}" for k, t, p, n in iterated])
    iback = ask(cipher, [f"dec-n {joined(k, t).hex()} {c} {n}"
                         for (k, t, _, n), c in zip(iterated, ict)])
    for (key, _, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{cipher}: {n} decryptions do not give the block back: {key.hex()}")

    rows = [row(cipher, k, t, p, c, " src=published" if src else "")
            for (k, t, p, src), c in zip(single, cts)]
    rows += [row(cipher + "-iter", k, t, p, c, f" n={n}") for (k, t, p, n), c in zip(iterated, ict)]
    return rows


def main():
    rng = random.Random(0x7468726565666973)  # "threefis"
    rows = []
    for cipher in CIPHERS:
        rows += rows_for(cipher, rng)
    with open(OUTPUT, "w") as out:
        out.write("# Threefish-256, -512 and -1024. Crypto++ 8.9.0, Bouncy Castle 1.77 and\n"
                  "# Skein3Fish's C agree on every row, both directions. A row without a\n"
                  "# tweak was asked with the key alone, a tweak of zero; one with a tweak,\n"
                  "# with the key followed by it. src=published marks Crypto++'s tests.\n"
                  "# Written by scripts/make_threefish_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for line in rows:
            out.write(line + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
