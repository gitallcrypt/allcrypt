#!/usr/bin/env python3
"""Write vectors/mars.vec: MARS, with the tweaked key schedule, as
Crypto++ 8.9.0 and Botan 1.10.17 compute it.

    scripts/witness/mars/build.sh /opt/mars
    python3 scripts/make_mars_vectors.py

**A development tool, not a test.** `tests/test_mars.rs` reads the file
offline.

The build script has already required both witnesses to reproduce
Crypto++'s TestVectors/mars.txt; this script asks again, and writes those
sixteen tests as the file's first rows. Then, for every key length from
16 to 56 bytes in steps of 4, keys and blocks from a seeded generator
and the all-zero and all-ones key and block, and Monte Carlo tests in
each direction: Crypto++'s full one, 400 keys of 10,000 blocks, and a
short one of 8 keys of 5,000 blocks, which is the same procedure with
the counts changed. Both witnesses answer every request, decryption
included, and a row is written only where they agree with each other
and decryption gives the block back.

    mars key=<hex> pt=<hex> ct=<hex>        one block
    mars-mct key=<hex> pt=<hex> ct=<hex> outer=<n> inner=<n>
                                            Crypto++'s EncryptionMCT
    mars-mct-dec ...                        DecryptionMCT: ct to pt

Each row ends `src=published` when it is one of mars.txt's.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "mars.vec")
WITNESS = os.environ.get("MARS_WITNESS", "/opt/mars")
sys.path.insert(0, os.path.join(HERE, "witness", "mars"))
import selftest  # noqa: E402  (the build's own reader of mars.txt)


def ask(request_lines):
    """Every request to both witnesses; the answers, which must agree."""
    stdin = "".join(r + "\n" for r in request_lines)
    answers = []
    for name in ("mars-cryptopp", "mars-botan"):
        out = subprocess.run([os.path.join(WITNESS, name)], input=stdin, check=True,
                             capture_output=True, text=True).stdout.split("\n")
        out = out[:len(request_lines)]
        if len(out) != len(request_lines) or any(not line or line.startswith("error")
                                                 for line in out):
            sys.exit(f"{name} did not answer every request")
        answers.append(out)
    for request, a, b in zip(request_lines, *answers):
        if a != b:
            sys.exit(f"the witnesses disagree on {request}: {a} {b}")
    return [bytes.fromhex(a) for a in answers[0]]


def main():
    rows = []  # (kind, key, pt, ct, counts, published)
    full = (400, 10000)
    for test, key, pt, ct in selftest.read(os.path.join(WITNESS, "cryptopp", "mars.txt")):
        kind = {"Encrypt": "mars", "EncryptionMCT": "mars-mct",
                "DecryptionMCT": "mars-mct-dec"}[test]
        rows.append((kind, key, pt, ct, None if kind == "mars" else full, True))

    rng = random.Random(0x3A125)
    for n in range(16, 57, 4):
        pairs = [(rng.randbytes(n), rng.randbytes(16)) for _ in range(60)]
        pairs += [(bytes(n), bytes(16)), (b"\xff" * n, b"\xff" * 16)]
        cts = ask([f"enc {k.hex()} {p.hex()}" for k, p in pairs])
        rows += [("mars", k, p, c, None, False) for (k, p), c in zip(pairs, cts)]
        for counts in (full, (8, 5000)):
            o, i = counts
            key, block = rng.randbytes(n), rng.randbytes(16)
            enc, = ask([f"mct-enc {key.hex()} {block.hex()} {o} {i}"])
            rows.append(("mars-mct", key, block, enc, counts, False))
            key, block = rng.randbytes(n), rng.randbytes(16)
            dec, = ask([f"mct-dec {key.hex()} {block.hex()} {o} {i}"])
            rows.append(("mars-mct-dec", key, dec, block, counts, False))

    # Every row once more, in the direction it does not state.
    checks = []
    for kind, key, pt, ct, counts, _ in rows:
        if kind == "mars":
            checks += [(f"enc {key.hex()} {pt.hex()}", ct), (f"dec {key.hex()} {ct.hex()}", pt)]
        elif kind == "mars-mct":
            checks.append((f"mct-enc {key.hex()} {pt.hex()} {counts[0]} {counts[1]}", ct))
        else:
            checks.append((f"mct-dec {key.hex()} {ct.hex()} {counts[0]} {counts[1]}", pt))
    for (request, want), got in zip(checks, ask([r for r, _ in checks])):
        if got != want:
            sys.exit(f"{request}: {got.hex()}, not {want.hex()}")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# MARS with the tweaked key schedule, every key length from 16 to 56\n"
                "# bytes. Crypto++ 8.9.0 and Botan 1.10.17 agree on every row, both\n"
                "# directions; src=published marks Crypto++'s TestVectors/mars.txt.\n"
                "# Written by scripts/make_mars_vectors.py. Do not edit.\n"
                f"# rows: {len(rows)}\n")
        for kind, key, pt, ct, counts, published in rows:
            tail = f" outer={counts[0]} inner={counts[1]}" if counts else ""
            tail += " src=published" if published else ""
            f.write(f"{kind} key={key.hex()} pt={pt.hex()} ct={ct.hex()}{tail}\n")
    print(f"{len(rows)} rows to {OUTPUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
