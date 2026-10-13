#!/usr/bin/env python3
"""Write vectors/blake2_named.vec: the BLAKE2 output lengths the catalogue
names - BLAKE2b at 128, 160, 256 and 384 bits and BLAKE2s at 128 and 160 -
from three implementations.

    scripts/witness/blake2/build.sh /opt/blake2witness
    python3 scripts/make_blake2_vectors.py

**A development tool, not a test.** `tests/test_blake2_named.rs` and
`pytests/test_blake2_named.py` read the file offline.

The output length is part of BLAKE2's parameter block, so each of these
is its own function rather than the full digest cut short. Three
implementations compute them: Python's `hashlib` (`digest_size`), OpenSSL
3.5's provider through its `size` parameter (`scripts/witness/blake2`),
and, for BLAKE2b, GNU coreutils' `b2sum -l`. They must agree on every
message - seventeen lengths around the block boundaries of both, the
bytes from a fixed seed - or the script stops. One row per message:

    hash name= msg= digest=
"""

import hashlib
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "blake2_named.vec")
WITNESS = os.environ.get("BLAKE2_WITNESS", "/opt/blake2witness") + "/blake2-witness"

NAMES = [("blake2b", 128), ("blake2b", 160), ("blake2b", 256), ("blake2b", 384),
         ("blake2s", 128), ("blake2s", 160)]
LENGTHS = [0, 1, 2, 3, 31, 32, 33, 55, 63, 64, 65, 127, 128, 129, 255, 256, 1000]


def openssl(requests):
    lines = "".join(f"{family} {bits // 8} {message.hex() or '-'}\n"
                    for family, bits, message in requests)
    out = subprocess.run([WITNESS], input=lines, capture_output=True, text=True,
                         check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"the OpenSSL driver refused: {out}")
    return out


def b2sum(bits, message):
    out = subprocess.run(["b2sum", "-l", str(bits)], input=message, capture_output=True,
                         check=True).stdout.decode()
    return out.split()[0]


def main():
    rng = random.Random(0xB1A4E2)
    messages = [rng.randbytes(n) for n in LENGTHS]
    requests = [(family, bits, m) for family, bits in NAMES for m in messages]
    theirs = openssl(requests)
    rows = []
    for (family, bits, message), from_openssl in zip(requests, theirs):
        which = hashlib.blake2b if family == "blake2b" else hashlib.blake2s
        digest = which(message, digest_size=bits // 8).hexdigest()
        if from_openssl != digest:
            sys.exit(f"hashlib and OpenSSL disagree on {family}_{bits} of {len(message)} bytes")
        if family == "blake2b" and b2sum(bits, message) != digest:
            sys.exit(f"hashlib and b2sum disagree on {family}_{bits} of {len(message)} bytes")
        rows.append(f"hash name={family}_{bits} msg={message.hex() or '-'} digest={digest}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# The BLAKE2 output lengths the catalogue names. Written by\n"
                  "# scripts/make_blake2_vectors.py; do not edit. hashlib and OpenSSL 3.5\n"
                  "# agree on every row, and b2sum on the BLAKE2b ones.\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
