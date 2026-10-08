#!/usr/bin/env python3
"""Write vectors/rc6.vec: RC6-32/20/b known answers.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    python3 scripts/make_rc6_vectors.py

**A development tool, not a test.** It fetches the submission's six
vectors once (as Crypto++ carries them, `TestData/rc6val.dat`, checked
against its SHA-256) and needs the Bouncy Castle witness;
`tests/test_rc6.rs` reads `vectors/rc6.vec` offline.

Bouncy Castle must reproduce the six published vectors before anything
is written, and then supplies the rest: every key length from 1 to 64
bytes, a spread of lengths up to the maximum of 255, and plaintexts
drawn from a seeded generator so the file is reproducible. Each row is
`rc6 source=<paper|bouncycastle> key=<hex> pt=<hex> ct=<hex>`, one block.
"""

import hashlib
import os
import random
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "rc6.vec")
WITNESS = os.environ.get("BC_WITNESS", "/opt/bcwitness")
PAPER_URL = "https://raw.githubusercontent.com/weidai11/cryptopp/master/TestData/rc6val.dat"
PAPER_SHA256 = "6168ea5f7593a532361505be1ba40c1b49c890966807d3541944756394b87369"


def bouncycastle(rows):
    """Bouncy Castle's ciphertext for each (key, plaintext) pair."""
    stdin = "".join(f"{k.hex()} {p.hex()}\n" for k, p in rows)
    out = subprocess.run(["java", "-cp", f"{WITNESS}/bcprov.jar:{WITNESS}",
                          "BlockWitness", "rc6"], input=stdin, check=True,
                         capture_output=True, text=True).stdout.split("\n")
    out = out[:len(rows)]
    for line in out:
        if line.startswith("error"):
            sys.exit(f"Bouncy Castle refused a row: {line}")
    return [bytes.fromhex(line) for line in out]


def paper_vectors():
    with urllib.request.urlopen(PAPER_URL) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != PAPER_SHA256:
        sys.exit("rc6val.dat changed upstream; read it before trusting it")
    words = data.decode().split()
    assert len(words) == 18, len(words)
    return [tuple(bytes.fromhex(w) for w in words[i:i + 3]) for i in range(0, 18, 3)]


def main():
    paper = paper_vectors()
    got = bouncycastle([(k, p) for k, p, _ in paper])
    for (k, p, c), g in zip(paper, got):
        if g != c:
            sys.exit(f"Bouncy Castle disagrees with the paper: key {k.hex()}: {g.hex()} != {c.hex()}")

    rng = random.Random(0x5236)
    pairs = []
    for n in range(1, 65):
        for _ in range(6):
            pairs.append((rng.randbytes(n), rng.randbytes(16)))
    for n in sorted(rng.sample(range(65, 256), 40)) + [255]:
        for _ in range(3):
            pairs.append((rng.randbytes(n), rng.randbytes(16)))
    # The all-zero and all-one corners at the AES key lengths.
    for n in (16, 24, 32):
        for fill in (0x00, 0xFF):
            pairs.append((bytes([fill]) * n, bytes([fill]) * 16))
    cts = bouncycastle(pairs)

    with open(OUTPUT, "w") as f:
        f.write("# RC6-32/20/b. Written by scripts/make_rc6_vectors.py; do not edit.\n"
                "# source=paper: the submission's vectors (Crypto++ TestData/rc6val.dat),\n"
                "# which Bouncy Castle 1.77 reproduces; source=bouncycastle: its RC6Engine.\n")
        for k, p, c in paper:
            f.write(f"rc6 source=paper key={k.hex()} pt={p.hex()} ct={c.hex()}\n")
        for (k, p), c in zip(pairs, cts):
            f.write(f"rc6 source=bouncycastle key={k.hex()} pt={p.hex()} ct={c.hex()}\n")
    print(f"{len(paper) + len(pairs)} rows")


if __name__ == "__main__":
    main()
