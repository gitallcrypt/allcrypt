#!/usr/bin/env python3
"""Write vectors/isaac.vec: ISAAC, ISAAC-64 and Bouncy Castle's reading of
ISAAC.

    sh scripts/witness/isaac/build.sh /opt/isaacwitness
    python3 scripts/make_isaac_vectors.py [/opt/isaacwitness]

**A development tool, not a test.** `tests/test_isaac.rs` and
`pytests/test_isaac.py` read the file offline.

Every witness in scripts/witness/isaac gives the generator's blocks in
index order (driver.h); a row is written only when every witness that can
answer agrees on them, and the row's stream is then those blocks read the
way the row's cipher reads them:

    isaac               block 0 on, each block's words from index 255 down
    isaac64             to 0, each word little endian
    isaac-bouncycastle  block 1 on, words in index order, each big endian

Rows, hex fields, "-" for an empty key:

    <cipher> key= skip= stream= source= witnesses=

`skip` is the number of keystream bytes before `stream`. In order:

1. the values rand_isaac's tests give as the reference implementation's,
   read out of the crate's source (`source=rand_isaac`), as ISAAC and
   ISAAC-64 rows;
2. random keys of every length class up to the whole seed array, the
   empty key among them, each with its first two blocks (`source=random`);
3. keys with a single bit set, at either end of a word and of the seed
   (`source=single-bit`);
4. a stream from block 40, past any start-up effect (`source=deep`).

Each class is written for all three ciphers; Bouncy Castle is a witness
for its own rows whenever it can take the key - it throws on a key of odd
length - and the other witnesses always.
"""

import glob
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "isaac.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "isaac"))
from selftest import published  # noqa: E402

WITNESSES = {32: ["ref-isaac", "coreutils-isaac", "rust-isaac", "bc-isaac"],
             64: ["ref-isaac64", "coreutils-isaac64", "rust-isaac"]}


class Witness:
    def __init__(self, out, name):
        self.name = name
        self.proc = subprocess.Popen([os.path.join(out, name)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)

    def blocks(self, bits, key, first, count):
        self.proc.stdin.write(f"isaac {bits} {key.hex() or '-'} {first} {count}\n")
        self.proc.stdin.flush()
        answer = self.proc.stdout.readline().strip()
        if answer.startswith("error"):
            return answer
        raw = bytes.fromhex(answer)
        n = bits // 8
        if len(raw) != count * 256 * n:
            sys.exit(f"{self.name} gave {len(raw)} bytes for {count} blocks")
        return [int.from_bytes(raw[i:i + n], "little") for i in range(0, len(raw), n)]

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def agreed(witnesses, bits, key, first, count):
    """The blocks first .. first + count - 1 and the witnesses that gave
    them; every witness that answers must agree, Bouncy Castle refusing
    only block 0 and the key lengths it throws on."""
    given = {}
    for w in witnesses[bits]:
        answer = w.blocks(bits, key, first, count)
        if isinstance(answer, str):
            if w.name == "bc-isaac" and (first == 0 or len(key) % 2):
                continue
            sys.exit(f"{w.name} refused {bits} {key.hex()[:40]} {first} {count}: {answer}")
        given[w.name] = answer
    if len({tuple(v) for v in given.values()}) != 1:
        sys.exit(f"the {bits} bit witnesses disagree on {key.hex()[:40]} from block {first}")
    if len(given) < 2:
        sys.exit(f"fewer than two witnesses for {key.hex()[:40]}")
    return next(iter(given.values())), sorted(given)


def reference_order(blocks, bits):
    n = bits // 8
    return b"".join(w.to_bytes(n, "little")
                    for b in range(0, len(blocks), 256) for w in reversed(blocks[b:b + 256]))


def bc_order(blocks):
    return b"".join(w.to_bytes(4, "big") for w in blocks)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/isaacwitness"
    found = glob.glob(os.path.expanduser(
        "~/.cargo/registry/src/*/rand_isaac-0.3.0/src/isaac.rs"))
    if not found:
        sys.exit("rand_isaac 0.3.0's source is not in cargo's registry; build first")
    src = os.path.dirname(found[0])
    witnesses = {bits: [Witness(out, n) for n in names] for bits, names in WITNESSES.items()}
    lines = []

    def emit(cipher, key, skip, stream, source, names):
        lines.append(f"{cipher} key={key.hex() or '-'} skip={skip} stream={stream.hex()} "
                     f"source={source} witnesses={','.join(names)}")

    def rows(key, first, count, source):
        """The three ciphers' rows for one key from block `first`."""
        for bits, cipher in ((32, "isaac"), (64, "isaac64")):
            if len(key) > 256 * bits // 8:
                continue
            blocks, names = agreed(witnesses, bits, key, first, count)
            emit(cipher, key, first * 256 * bits // 8, reference_order(blocks, bits), source,
                 names)
        if len(key) <= 1024:
            start = max(first, 1)
            blocks, names = agreed(witnesses, 32, key, start, count)
            emit("isaac-bouncycastle", key, (start - 1) * 1024, bc_order(blocks), source,
                 names)

    tests = {32: published(open(os.path.join(src, "isaac.rs")).read(),
                           "test_isaac_true_values_32"),
             64: published(open(os.path.join(src, "isaac64.rs")).read(),
                           "test_isaac64_true_values_64")}
    for bits, cipher in ((32, "isaac"), (64, "isaac64")):
        n = bits // 8
        if len(tests[bits]) != 2:
            sys.exit(f"read {len(tests[bits])} cases from rand_isaac's {bits} bit test")
        for seed, skip, expected in tests[bits]:
            first, last = skip // 256, (skip + len(expected) - 1) // 256
            blocks, names = agreed(witnesses, bits, seed, first, last - first + 1)
            stream = reference_order(blocks, bits)
            at = (skip - first * 256) * n
            value = b"".join(v.to_bytes(n, "little") for v in expected)
            if stream[at:at + len(value)] != value:
                sys.exit(f"the witnesses do not give rand_isaac's values for {seed.hex()}")
            emit(cipher, seed, skip * n, value, "rand_isaac", names)

    rng = random.Random(19960327)
    for length in (0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 257,
                   512, 1000, 1023, 1024, 1025, 1500, 2047, 2048):
        rows(rng.randbytes(length), 0, 2, "random")
    for bit in (0, 7, 31, 32, 8191):
        key = bytearray(bit // 8 + 1)
        key[bit // 8] = 1 << (bit % 8)
        rows(bytes(key), 0, 1, "single-bit")
    for length in (16, 1024):
        rows(rng.randbytes(length), 40, 1, "deep")
    for group in witnesses.values():
        for w in group:
            w.close()

    header = [
        "# ISAAC, ISAAC-64 and Bouncy Castle's reading of ISAAC. Written by",
        "# scripts/make_isaac_vectors.py; do not edit. key: little-endian words of the",
        "# seed, zero-padded; skip: keystream bytes before stream. isaac and isaac64: block",
        "# 0 on, each block's words from the last to the first, little endian;",
        "# isaac-bouncycastle: block 1 on, words in order, big endian. source=rand_isaac:",
        "# the values rand_isaac's tests give as the reference's; random, single-bit, deep:",
        "# generated. witnesses: every implementation that took the key, all agreeing.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
