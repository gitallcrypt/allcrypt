#!/usr/bin/env python3
"""Write vectors/gost94_readings.vec: GOST R 34.11-94 under its three
parameter sets as Bouncy Castle 1.77 and gost89 compute it, the empty
message included.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/gost89/build.sh /opt/gost89
    PYTHONPATH=python python3 scripts/make_gost94_vectors.py

**A development tool, not a test.** `tests/test_gost94_readings.rs`
reads the file offline.

The empty message has two readings. RFC 5831's step 2 runs for any
remainder of 256 bits or fewer, zero included, and this library's
`gost94` and today's gost-engine compress a block of zeros for it.
Bouncy Castle, gost89 and the gost engine of OpenSSL 1.0 compress
nothing when nothing is left; that reading is `gost94_bc` here. Every
non-empty message hashes the same under both, so the rows with a message
check that each witness was handed the parameter set meant - the S-box
goes to both as a DKE, packed from this library's table - and the empty
rows are the ones that separate the readings.

A row is written only where both witnesses agree; a disagreement stops
the script.

    gost94 params=<name> msg=<hex or -> digest=<hex>
"""

import os
import random
import subprocess
import sys

import allcrypt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "gost94_readings.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
GOST89 = os.environ.get("GOST89_WITNESS", "/opt/gost89")
DRIVER = os.path.join(HERE, "witness", "gost89", "driver.js")

PARAMS = ["id-GostR3411-94-CryptoProParamSet", "id-GostR3411-94-TestParamSet",
          "dstu4145-default-dke"]


def h(b):
    return b.hex() or "-"


def dke(name):
    """The table packed as a DSTU 4145 DKE: row by row, two entries to a
    byte, high nibble first - the form both witnesses take."""
    return bytes((row[i] << 4) | row[i + 1]
                 for row in allcrypt.gost_sbox(name) for i in range(0, 16, 2))


def witness(command, rows):
    stdin = "".join(" ".join(h(x) for x in r) + "\n" for r in rows)
    out = subprocess.run(command, input=stdin, check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(rows)]
    if len(out) != len(rows):
        sys.exit(f"{command[0]} answered {len(out)} of {len(rows)}")
    return [bytes.fromhex(line.strip()) for line in out]


def main():
    rng = random.Random(9411)
    messages = [b"", b"abc", b"message digest", bytes(32), b"\xff" * 33]
    messages += [rng.randbytes(n) for n in (1, 31, 64, 100)]
    rows = []
    for name in PARAMS:
        packed = dke(name)
        jobs = [(packed, m) for m in messages]
        bc = witness(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness", "gost3411"], jobs)
        js = witness(["node", DRIVER, GOST89, "gost3411"], jobs)
        for m, a, b in zip(messages, bc, js):
            if a != b:
                sys.exit(f"{name}: the witnesses disagree on {h(m)}")
            rows.append(f"gost94 params={name} msg={h(m)} digest={a.hex()}")
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# GOST R 34.11-94 under its three parameter sets, the empty message\n"
                "# included, as Bouncy Castle 1.77 and gost89 compute it; they agree on\n"
                "# every row. Written by scripts/make_gost94_vectors.py. Do not edit.\n"
                f"# rows: {len(rows)}\n")
        for row in rows:
            f.write(row + "\n")
    print(f"{len(rows)} rows to {OUTPUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
