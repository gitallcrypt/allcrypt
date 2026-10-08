#!/usr/bin/env python3
"""Write vectors/cast256.vec: CAST-256 (RFC 2612) known answers from
Bouncy Castle.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    python3 scripts/make_cast256_vectors.py

**A development tool, not a test.** It needs the Bouncy Castle witness;
`tests/test_cast256.rs` reads `vectors/cast256.vec` offline. The RFC's own
Appendix A is parsed by `src/block_ciphers/cast256.rs` from the vendored
`rfcs/rfc2612.txt`; this script first requires Bouncy Castle to give the
appendix's three ciphertexts, read from the same file, and then records
its CAST6Engine over all five key lengths with keys and plaintexts from
a seeded generator. Each row is `cast256 key=<hex> pt=<hex> ct=<hex>`,
one block.
"""

import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "cast256.vec")
RFC = os.path.join(ROOT, "rfcs", "rfc2612.txt")
WITNESS = os.environ.get("BC_WITNESS", "/opt/bcwitness")


def bouncycastle(rows):
    stdin = "".join(f"{k.hex()} {p.hex()}\n" for k, p in rows)
    out = subprocess.run(["java", "-cp", f"{WITNESS}/bcprov.jar:{WITNESS}",
                          "BlockWitness", "cast256"], input=stdin, check=True,
                         capture_output=True, text=True).stdout.split("\n")[:len(rows)]
    for line in out:
        if line.startswith("error"):
            sys.exit(f"Bouncy Castle refused a row: {line}")
    return [bytes.fromhex(line) for line in out]


def rfc_vectors():
    text = open(RFC).read()
    text = text[text.index("Appendix A: Test Vectors"):]
    rows = []
    for section in text.split("KEYSIZE=")[2:]:
        key = re.search(r"\bKEY=([0-9a-f]+)", section).group(1)
        pt = re.search(r"\bPT=([0-9a-f]+)", section).group(1)
        ct = re.search(r"\bCT=([0-9a-f]+)", section).group(1)
        rows.append(tuple(bytes.fromhex(x) for x in (key, pt, ct)))
    assert len(rows) == 3, rows
    return rows


def main():
    rfc = rfc_vectors()
    for (k, p, c), got in zip(rfc, bouncycastle([(k, p) for k, p, _ in rfc])):
        if got != c:
            sys.exit(f"Bouncy Castle disagrees with RFC 2612: {k.hex()}: {got.hex()}")

    rng = random.Random(0x2612)
    pairs = []
    for n in (16, 20, 24, 28, 32):
        for _ in range(80):
            pairs.append((rng.randbytes(n), rng.randbytes(16)))
        for fill in (0x00, 0xFF):
            pairs.append((bytes([fill]) * n, bytes([fill]) * 16))
    cts = bouncycastle(pairs)
    with open(OUTPUT, "w") as f:
        f.write("# CAST-256 (RFC 2612). Written by scripts/make_cast256_vectors.py; do not\n"
                "# edit. Bouncy Castle 1.77's CAST6Engine, which reproduces RFC 2612's\n"
                "# Appendix A first.\n")
        for (k, p), c in zip(pairs, cts):
            f.write(f"cast256 key={k.hex()} pt={p.hex()} ct={c.hex()}\n")
    print(f"{len(pairs)} rows")


if __name__ == "__main__":
    main()
