#!/usr/bin/env python3
"""Write vectors/rijndael.vec: Rijndael known answers at every block and
key size.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/rijndaelphp/build.sh /opt/rijndaelphp
    python3 scripts/make_rijndael_vectors.py

**A development tool, not a test.** It needs both witnesses built (the
second fetches phpseclib's two files once) and a PHP interpreter;
`tests/test_rijndael.rs` reads `vectors/rijndael.vec` offline.

Two implementations that share no code supply every answer: Bouncy
Castle 1.77's `RijndaelEngine` and phpseclib 1.0.23's pure-PHP
`Crypt_Rijndael`. A row is written only where they agree, and any
disagreement stops the script. Both must first reproduce FIPS 197's
Appendix C vectors, the 128 bit block under each AES key size.

For each of the 25 pairs of block and key size (16, 20, 24, 28 and 32
bytes each): the all-zero and all-one corners, the counting key and
plaintext, and plaintexts and keys from a seeded generator so the file
is reproducible. Each row is
`rijndael block=<bytes> key=<hex> pt=<hex> ct=<hex>`, one block.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "rijndael.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
PHP = os.environ.get("RIJNDAEL_PHP_WITNESS", "/opt/rijndaelphp")
DRIVER = os.path.join(HERE, "witness", "rijndaelphp", "driver.php")
SIZES = (16, 20, 24, 28, 32)

# FIPS 197 Appendix C: the 128 bit block, plaintext 00112233..ff, key
# 000102.. at each AES key length.
FIPS197 = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "8ea2b7ca516745bfeafc49904b496089"),
]


def bouncycastle(block, rows):
    stdin = "".join(f"{k.hex()} {p.hex()}\n" for k, p in rows)
    out = subprocess.run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "BlockWitness",
                          f"rijndael{8 * block}"], input=stdin, check=True,
                         capture_output=True, text=True).stdout.split("\n")[:len(rows)]
    for line in out:
        if line.startswith("error"):
            sys.exit(f"Bouncy Castle refused a row: {line}")
    return [bytes.fromhex(line) for line in out]


def phpseclib(block, rows):
    stdin = "".join(f"{8 * block} {k.hex()} {p.hex()}\n" for k, p in rows)
    out = subprocess.run(["php", DRIVER, PHP], input=stdin, check=True,
                         capture_output=True, text=True).stdout.split("\n")[:len(rows)]
    return [bytes.fromhex(line) for line in out]


def both(block, rows):
    a, b = bouncycastle(block, rows), phpseclib(block, rows)
    for (k, p), x, y in zip(rows, a, b):
        if x != y:
            sys.exit(f"the witnesses disagree: block {block} key {k.hex()} pt {p.hex()}: "
                     f"{x.hex()} != {y.hex()}")
    return a


def main():
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    for key, ct in FIPS197:
        if both(16, [(bytes.fromhex(key), pt)])[0].hex() != ct:
            sys.exit(f"a witness misses FIPS 197's vector for a {len(key) * 4} bit key")

    rng = random.Random(0x52494A)
    rows = []
    for block in SIZES:
        for klen in SIZES:
            pairs = [(bytes(klen), bytes(block)),
                     (b"\xff" * klen, b"\xff" * block),
                     (bytes(range(klen)), bytes(range(block)))]
            pairs += [(rng.randbytes(klen), rng.randbytes(block)) for _ in range(8)]
            for (k, p), c in zip(pairs, both(block, pairs)):
                rows.append(f"rijndael block={block} key={k.hex()} pt={p.hex()} ct={c.hex()}")

    with open(OUTPUT, "w") as f:
        f.write("# Rijndael at every block and key size. Written by\n"
                "# scripts/make_rijndael_vectors.py; do not edit. Every row is\n"
                "# Bouncy Castle 1.77's RijndaelEngine and phpseclib 1.0.23's\n"
                "# Crypt_Rijndael in agreement; both reproduce FIPS 197 Appendix C.\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
