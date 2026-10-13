#!/usr/bin/env python3
"""Write vectors/noekeon.vec: Noekeon in both key modes. Direct-key mode
as libtomcrypt 1.18.2 and Bouncy Castle 1.77's NoekeonEngine compute it;
indirect-key mode as Botan 1.10.17 computes it and as Bouncy Castle's
engine does by the mode's definition - the key encrypted under the zero
key, then used directly.

    scripts/witness/nessie/build.sh /opt/nessie
    python3 scripts/make_noekeon_vectors.py

**A development tool, not a test.** `tests/test_noekeon.rs` reads the
file offline.

For each mode, first the published tests - libtomcrypt's for the direct
mode, Botan's from the NESSIE reference code for the indirect - which
the build has already required every witness to reproduce. Then every
single-bit key under a zero block, every single-bit block under a zero
key, key and block one byte repeated for every byte, random keys and
blocks, and blocks encrypted and decrypted 100 and 1,000 times over.
Both witnesses of a mode answer every request, decryption included, and
a row is written only where they agree and decryption gives the block
back.

    noekeon key=<hex> pt=<hex> ct=<hex>                   direct, one block
    noekeon-iter key=<hex> pt=<hex> ct=<hex> n=<n>        direct, n times
    noekeon-indirect ..., noekeon-indirect-iter ...       the same, indirect

Each row ends `src=published` when it is one of the published tests.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "noekeon.vec")
WITNESS = os.environ.get("NESSIE_WITNESS", "/opt/nessie")
sys.path.insert(0, os.path.join(HERE, "witness", "nessie"))
import selftest  # noqa: E402  (the build's own reader of the published tests)

MODES = {"noekeon": ("noekeon-libtomcrypt", "noekeon-bc"),
         "noekeon-indirect": ("noekeon-indirect-botan", "noekeon-indirect-bc")}


def ask(programs, requests):
    """Every request to each witness; the answers, which must agree."""
    answers = []
    for name in programs:
        out = selftest.ask(os.path.join(WITNESS, name), requests)
        if len(out) != len(requests) or any(a.startswith("error") for a in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, *each in zip(requests, *answers):
        if len(set(each)) != 1:
            sys.exit(f"the witnesses disagree on {request}: {each}")
    return answers[0]


def mode_rows(mode, programs, rng):
    single = []
    published = list(selftest.vectors(WITNESS, mode))
    for key, pt, _ in published:
        single.append((key, pt, "published"))
    for bit in range(128):
        single.append(((1 << (127 - bit)).to_bytes(16, "big"), bytes(16), None))
    for bit in range(128):
        single.append((bytes(16), (1 << (127 - bit)).to_bytes(16, "big"), None))
    for byte in range(256):
        single.append((bytes([byte]) * 16, bytes([byte]) * 16, None))
    for _ in range(64):
        single.append((rng.randbytes(16), rng.randbytes(16), None))

    cts = ask(programs, [f"enc {k.hex()} {p.hex()}" for k, p, _ in single])
    back = ask(programs, [f"dec {k.hex()} {c}" for (k, _, _), c in zip(single, cts)])
    for (key, pt, _), again in zip(single, back):
        if again != pt.hex():
            sys.exit(f"{mode}: decryption does not give the block back: {key.hex()}")
    for (key, pt, src), ct in zip(single, cts):
        if src == "published":
            expected = next(c for k, p, c in published if (k, p) == (key, pt))
            if ct != expected.hex():
                sys.exit(f"{mode}: a published test fails: {key.hex()} {pt.hex()}")

    iterated = []
    for _ in range(8):
        key, pt = rng.randbytes(16), rng.randbytes(16)
        for n in (100, 1000):
            iterated.append((key, pt, n))
    ict = ask(programs, [f"enc-n {k.hex()} {p.hex()} {n}" for k, p, n in iterated])
    iback = ask(programs, [f"dec-n {k.hex()} {c} {n}" for (k, _, n), c in zip(iterated, ict)])
    for (key, pt, n), again in zip(iterated, iback):
        if again != pt.hex():
            sys.exit(f"{mode}: {n} decryptions do not give the block back: {key.hex()}")

    rows = [f"{mode} key={k.hex()} pt={p.hex()} ct={c}" + (" src=published" if s else "")
            for (k, p, s), c in zip(single, cts)]
    rows += [f"{mode}-iter key={k.hex()} pt={p.hex()} ct={c} n={n}"
             for (k, p, n), c in zip(iterated, ict)]
    return rows


def main():
    rng = random.Random(0x6e6f656b656f6e)  # "noekeon"
    rows = []
    for mode, programs in MODES.items():
        rows += mode_rows(mode, programs, rng)
    with open(OUTPUT, "w") as out:
        out.write("# Noekeon. Direct-key mode (noekeon): libtomcrypt 1.18.2 and Bouncy\n"
                  "# Castle 1.77 agree on every row. Indirect-key mode (noekeon-indirect):\n"
                  "# Botan 1.10.17 and Bouncy Castle under the mode's definition agree on\n"
                  "# every row. Both directions; src=published marks libtomcrypt's tests\n"
                  "# and Botan's from the NESSIE reference code.\n"
                  "# Written by scripts/make_noekeon_vectors.py. Do not edit.\n"
                  f"# rows: {len(rows)}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
