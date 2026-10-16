#!/usr/bin/env python3
"""Write vectors/joaat.vec: Jenkins's one-at-a-time hash, from zero and
seeded, from three implementations.

    scripts/witness/joaat/build.sh /opt/joaatwitness
    python3 scripts/make_joaat_vectors.py

**A development tool, not a test.** `tests/test_joaat.rs` and
`pytests/test_joaat.py` read the file offline.

The witnesses (`scripts/witness/joaat`): PHP's `joaat`, which starts
from zero only, and Perl 5.24's and gVisor's, which start from a seed;
PHP and gVisor are fed each message in pieces of 1, 2, 3 ... bytes.
Every witness asked must agree on every message, or the script stops.
The messages are random bytes from a fixed seed at a run of short
lengths and some longer ones, and two long runs of one byte described
rather than written out; the seeds are 0, 1, the top bit, all ones and
one other.

    msg n= data=  |  msg n= fill= len=
    hash msg= seed= value=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "joaat.vec")
WITNESS = os.environ.get("JOAAT_WITNESS", "/opt/joaatwitness")

LENGTHS = list(range(17)) + [31, 32, 33, 64, 100, 255, 256, 1000, 4096]
FILLS = [(0x00, 100_000), (0xff, 65_537)]
SEEDS = [0, 1, 0x80000000, 0xFFFFFFFF, 0xDEADBEEF]


def ask(witness, requests):
    """The witness's answers to [(key, path)], in order."""
    lines = "".join(f"joaat {key} {path}\n" for key, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out[:5]}")
    return out


def main():
    rng = random.Random(0x0AA7)
    messages = [rng.randbytes(n) for n in LENGTHS] + \
        [bytes([byte]) * length for byte, length in FILLS]
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, message in enumerate(messages):
            paths.append(os.path.join(tmp, f"m{i}"))
            with open(paths[-1], "wb") as f:
                f.write(message)
        answers = {}
        for witness in ("php", "perl", "gvisor"):
            seeds = [0] if witness == "php" else SEEDS
            wanted = [(i, seed) for seed in seeds for i in range(len(paths))]
            requests = [(f"seed:{seed:08x}", paths[i]) for i, seed in wanted]
            for row, value in zip(wanted, ask(witness, requests)):
                answers.setdefault(row, {})[witness] = value
    rows = []
    for (i, seed), given in answers.items():
        expected = {"php", "perl", "gvisor"} if seed == 0 else {"perl", "gvisor"}
        if set(given) != expected or len(set(given.values())) != 1:
            sys.exit(f"the witnesses disagree on {len(messages[i])} bytes, seed {seed:08x}: "
                     f"{given}")
        rows.append(f"hash msg={i} seed={seed:08x} value={given['perl']}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# Jenkins's one-at-a-time, big endian. Written by\n"
                  "# scripts/make_joaat_vectors.py; do not edit. PHP, Perl 5.24 and gVisor\n"
                  "# agree on every row from zero, Perl and gVisor on every seeded one.\n")
        for i, message in enumerate(messages[:len(LENGTHS)]):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for i, (byte, length) in enumerate(FILLS, len(LENGTHS)):
            out.write(f"msg n={i} fill={byte:02x} len={length}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(rows)} rows")


if __name__ == "__main__":
    main()
