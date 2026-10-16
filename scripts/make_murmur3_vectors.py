#!/usr/bin/env python3
"""Write vectors/murmur3.vec: MurmurHash3's x86_32, x86_128 and x64_128,
seeded, from several implementations each.

    scripts/witness/murmur3/build.sh /opt/murmur3witness
    python3 scripts/make_murmur3_vectors.py

**A development tool, not a test.** `tests/test_murmur3.rs` and
`pytests/test_murmur3.py` read the file offline.

The witnesses (`scripts/witness/murmur3`), fed each message in pieces of
1, 2, 3 ... bytes where they stream:

    murmur3_32, murmur3_x64_128
            PHP (PMurHash), SMHasher's reference, the murmur3 crate,
            murmurhash3js, spaolacci/murmur3, twmb/murmur3
    murmur3_x86_128
            PHP, the reference, the murmur3 crate, murmurhash3js

Every witness that has a name must agree on every message, or the
script stops. The messages are random bytes from a fixed seed at every
length from 0 to 33 and either side of larger multiples of 16, and two
long runs of one byte described rather than written out; the seeds are
0, 1, the top bit, all ones and two others.

    msg n= data=  |  msg n= fill= len=
    hash name= msg= seed= value=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "murmur3.vec")
WITNESS = os.environ.get("MURMUR3_WITNESS", "/opt/murmur3witness")

WITNESSES = {"murmur3_32": ["php", "ref", "rust", "js", "spaolacci", "twmb"],
             "murmur3_x86_128": ["php", "ref", "rust", "js"],
             "murmur3_x64_128": ["php", "ref", "rust", "js", "spaolacci", "twmb"]}
LENGTHS = list(range(34)) + [47, 48, 49, 63, 64, 65, 100, 255, 256, 257, 1000, 4095, 4096, 4097]
FILLS = [(0x00, 100_000), (0xff, 65_537)]
SEEDS = [0, 1, 0x9747B28C, 0x80000000, 0xFFFFFFFF, 0xDEADBEEF]


def ask(witness, requests):
    """The witness's answers to [(name, key, path)], in order."""
    lines = "".join(f"{name} {key} {path}\n" for name, key, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out[:5]}")
    return out


def main():
    rng = random.Random(0x3333)
    messages = [rng.randbytes(n) for n in LENGTHS] + \
        [bytes([byte]) * length for byte, length in FILLS]
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, message in enumerate(messages):
            paths.append(os.path.join(tmp, f"m{i}"))
            with open(paths[-1], "wb") as f:
                f.write(message)
        answers = {}
        for witness in sorted({w for who in WITNESSES.values() for w in who}):
            wanted = [(name, i, seed) for name, who in WITNESSES.items() if witness in who
                      for seed in SEEDS for i in range(len(paths))]
            requests = [(name, f"seed:{seed:08x}", paths[i]) for name, i, seed in wanted]
            for row, value in zip(wanted, ask(witness, requests)):
                answers.setdefault(row, {})[witness] = value
    rows = []
    for (name, i, seed), given in answers.items():
        if sorted(given) != sorted(WITNESSES[name]) or len(set(given.values())) != 1:
            sys.exit(f"the witnesses disagree on {name} of {len(messages[i])} bytes, seed "
                     f"{seed:08x}: {given}")
        rows.append(f"hash name={name} msg={i} seed={seed:08x} value={given['php']}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# MurmurHash3, each word big endian, first word first, as PHP prints it.\n"
                  "# Written by scripts/make_murmur3_vectors.py; do not edit. Every witness\n"
                  "# that has a name agrees on every row: PHP, SMHasher's reference, the\n"
                  "# murmur3 crate and murmurhash3js on all three, with spaolacci/murmur3\n"
                  "# and twmb/murmur3 on x86_32 and x64_128.\n")
        for i, message in enumerate(messages[:len(LENGTHS)]):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for i, (byte, length) in enumerate(FILLS, len(LENGTHS)):
            out.write(f"msg n={i} fill={byte:02x} len={length}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(rows)} rows")


if __name__ == "__main__":
    main()
