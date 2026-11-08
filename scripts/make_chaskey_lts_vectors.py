#!/usr/bin/env python3
"""Write vectors/chaskey_lts.vec: the Chaskey-LTS block cipher.

    sh scripts/witness/macs/build.sh /opt/macwitness
    python3 scripts/make_chaskey_lts_vectors.py [/opt/macwitness]

**A development tool, not a test.** `tests/test_chaskey_lts.rs` and
`pytests/test_chaskey_lts.py` read the file offline.

`pi(x ^ K) ^ K` over Chaskey-LTS's 16 round permutation, from the two
implementations of it that share no code: sacundim's Rust crate
(`sacundim`, `chaskey::cipher::encrypt` and `decrypt`) and volexity's
pure Python package (`volexity`, its private `_chaskey_block` both ways,
which its CTR mode calls). Every row
is written only when both give the same block and both decrypt it back.
In order:

1. the FELIX block in sacundim's tests (`source=felix`);
2. every single-bit key under the zero block, and every single-bit block
   under the zero key - the second is the permutation itself, the key
   being zero (`source=single-bit`);
3. key and block one byte repeated, for every byte (`source=repeated`);
4. seeded random keys and blocks (`source=random`);
5. seventeen blocks encrypted 100 or 1,000 times over under one key each,
   NESSIE's iterated tests (`source=iterated`, `times=`).

Rows, hex fields:

    chaskey-lts key= block= out= source= [times=] witnesses=
"""

import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "chaskey_lts.vec")
PROGRAMS = {"sacundim": "rust-chaskey", "volexity": "volexity-chaskey"}


class Witness:
    """One witness process, asked a request at a time."""

    def __init__(self, out, name):
        self.name = name
        self.proc = subprocess.Popen([os.path.join(out, PROGRAMS[name])], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(self, request):
        self.proc.stdin.write(request + "\n")
        self.proc.stdin.flush()
        answer = self.proc.stdout.readline().strip()
        if not re.fullmatch(r"[0-9a-f]{32}", answer):
            sys.exit(f"{self.name} answered {answer!r} to {request}")
        return answer

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def agreed(witnesses, key, block):
    """The block's encryption, agreed by both, each decrypting it back."""
    outs = {w.ask(f"cipher 16 {key.hex()} {block.hex()}") for w in witnesses}
    if len(outs) != 1:
        sys.exit(f"the witnesses disagree on {key.hex()} {block.hex()}")
    out = outs.pop()
    for w in witnesses:
        if w.ask(f"decipher 16 {key.hex()} {out}") != block.hex():
            sys.exit(f"{w.name} does not decrypt {out} under {key.hex()} back")
    return out


def felix(out):
    """The FELIX Chaskey-LTS block in sacundim's `cipher.rs` tests: key,
    block and expected output, as its byte arrays give them."""
    path = os.path.join(out, "src", "chaskey", "src", "cipher.rs")
    with open(path) as handle:
        text = handle.read()
    found = {}
    for name in ("KEY", "PLAINTEXT", "CIPHERTEXT"):
        body = re.search(rf"const {name}: \[u8; 16\] = \[(.*?)\];", text, re.S).group(1)
        found[name] = bytes(int(b, 16) for b in body.split(",") if b.strip())
        if len(found[name]) != 16:
            sys.exit(f"{path}: {name} is {len(found[name])} bytes")
    return found["KEY"], found["PLAINTEXT"], found["CIPHERTEXT"]


def single_bit(i):
    b = bytearray(16)
    b[i // 8] = 0x80 >> (i % 8)
    return bytes(b)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/macwitness"
    witnesses = [Witness(out, name) for name in PROGRAMS]
    names = ",".join(PROGRAMS)
    lines = []

    def row(key, block, source, times=None):
        result = block
        for _ in range(times or 1):
            result = bytes.fromhex(agreed(witnesses, key, result))
        extra = f" times={times}" if times else ""
        lines.append(f"chaskey-lts key={key.hex()} block={block.hex()} out={result.hex()} "
                     f"source={source}{extra} witnesses={names}")

    key, block, expected = felix(out)
    if agreed(witnesses, key, block) != expected.hex():
        sys.exit("the witnesses do not reproduce the FELIX block")
    row(key, block, "felix")
    for i in range(128):
        row(single_bit(i), bytes(16), "single-bit")
    for i in range(128):
        row(bytes(16), single_bit(i), "single-bit")
    for v in range(256):
        row(bytes([v]) * 16, bytes([v]) * 16, "repeated")
    rng = random.Random(20261106)
    for _ in range(64):
        row(rng.randbytes(16), rng.randbytes(16), "random")
    for k in range(17):
        row(rng.randbytes(16), rng.randbytes(16), "iterated", 1000 if k % 4 == 0 else 100)
    for w in witnesses:
        w.close()

    header = [
        "# The Chaskey-LTS block cipher, pi(block ^ key) ^ key over Chaskey-LTS's 16",
        "# round permutation, words little endian. Written by",
        "# scripts/make_chaskey_lts_vectors.py; do not edit. source=felix: the block in",
        "# sacundim's tests; single-bit, repeated, random: generated; iterated: the",
        "# block encrypted `times` times over. witnesses: sacundim's Rust crate and",
        "# volexity's Python package, both giving out and both decrypting it back.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
