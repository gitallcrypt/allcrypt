#!/usr/bin/env python3
"""Checks /opt/isaacwitness before any vector is written from it.

    python3 scripts/witness/isaac/selftest.py [/opt/isaacwitness]

1. The values rand_isaac 0.3.0's tests give as the reference
   implementation's - `test_isaac_true_values_32` and
   `test_isaac64_true_values_64`, two seeds each, the first ten words and
   ten words from the 10,000th - read out of the crate's source as cargo
   fetched it, and reproduced by every witness for that size from its own
   blocks. Bouncy Castle never outputs block 0, so it is held to the
   second seed of each pair only.
2. Every witness for a size agreeing on blocks 0 to 3 (1 to 4 for Bouncy
   Castle) under random keys of every length class: empty, short, whole
   words, a partial word, the whole seed array. Bouncy Castle throws on a
   key of odd length, and is required to.
"""

import glob
import os
import random
import re
import subprocess
import sys

WITNESSES = {32: ["ref-isaac", "coreutils-isaac", "rust-isaac", "bc-isaac"],
             64: ["ref-isaac64", "coreutils-isaac64", "rust-isaac"]}


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)], input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def words(hexed, bits):
    """A witness's blocks as integers in index order."""
    raw = bytes.fromhex(hexed)
    n = bits // 8
    return [int.from_bytes(raw[i:i + n], "little") for i in range(0, len(raw), n)]


def rand_order(blocks, bits, first=0):
    """The words in the reference's rand() order: each block from index 255
    down to 0, blocks in turn."""
    out = []
    for b in range(0, len(blocks), 256):
        out.extend(reversed(blocks[b:b + 256]))
    return out


def published(source, test):
    """(seed bytes, words skipped, expected words) for each case in one of
    rand_isaac's tests."""
    body = re.search(rf"fn {test}\(\) \{{(.*?)\n    \}}", source, re.S).group(1)
    cases = []
    for part in body.split("let seed = ")[1:]:
        seed = bytes(int(x) for x in re.match(r"\[([^\]]*)\]", part).group(1).split(","))
        expected = [int(x) for x in
                    re.search(r"let expected = \[([^\]]*)\]", part).group(1).split(",")
                    if x.strip()]
        skip = int(re.search(r"for _ in 0\.\.(\d+)", part).group(1)) if "for _ in 0.." in \
            part.split("let expected")[0] else 0
        cases.append((seed, skip, expected))
    return cases


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/isaacwitness"
    found = glob.glob(os.path.expanduser(
        "~/.cargo/registry/src/*/rand_isaac-0.3.0/src/isaac.rs"))
    if not found:
        sys.exit("rand_isaac 0.3.0's source is not in cargo's registry; build first")
    here = os.path.dirname(found[0])
    tests = {32: published(open(os.path.join(here, "isaac.rs")).read(),
                           "test_isaac_true_values_32"),
             64: published(open(os.path.join(here, "isaac64.rs")).read(),
                           "test_isaac64_true_values_64")}
    for bits, cases in tests.items():
        if len(cases) != 2 or [len(e) for _, _, e in cases] != [10, 10]:
            sys.exit(f"read {cases} from rand_isaac's {bits} bit test")
        for seed, skip, expected in cases:
            first = (skip // 256)
            count = (skip + len(expected)) // 256 - first + 1
            for w in WITNESSES[bits]:
                if w == "bc-isaac" and first == 0:
                    continue
                answer = ask(out, w, [f"isaac {bits} {seed.hex()} {first} {count}"])[0]
                stream = rand_order(words(answer, bits), bits)
                at = skip - first * 256
                if stream[at:at + len(expected)] != expected:
                    sys.exit(f"{w} does not reproduce rand_isaac's {bits} bit values "
                             f"for {seed.hex()}")

    rng = random.Random(1996)
    for bits, names in WITNESSES.items():
        size = 256 * bits // 8
        keys = [b"", bytes(1), rng.randbytes(2), rng.randbytes(4), rng.randbytes(16), rng.randbytes(32),
                rng.randbytes(bits // 8 * 3), rng.randbytes(size)]
        requests = {w: [f"isaac {bits} {(k.hex() or '-')} {1 if w == 'bc-isaac' else 0} 4"
                        for k in keys] for w in names}
        answers = {w: ask(out, w, requests[w]) for w in names}
        for i, key in enumerate(keys):
            given = {}
            for w in names:
                a = answers[w][i]
                if w == "bc-isaac" and len(key) % 2:
                    # ISAACEngine pads such a key to a length that is not a
                    # whole number of words and reads past it.
                    if a != "error ArrayIndexOutOfBoundsException":
                        sys.exit(f"bc-isaac took a {len(key)} byte key: {a[:40]}")
                    given[w] = None
                    continue
                if a.startswith("error"):
                    sys.exit(f"{w} refused {requests[w][i][:60]}: {a}")
                blocks = words(a, bits)
                given[w] = blocks if w != "bc-isaac" else None
                if w == "bc-isaac":
                    ref = words(answers[names[0]][i], bits)[256:]
                    if blocks[:768] != ref:
                        sys.exit(f"bc-isaac disagrees on {key.hex()[:32]}")
            if len({tuple(v) for v in given.values() if v is not None}) != 1:
                sys.exit(f"the {bits} bit witnesses disagree on {key.hex()[:32]}")
    print(f"isaac witnesses: rand_isaac's published values reproduced at 32 and 64 bits; "
          f"{', '.join(WITNESSES[32])} agree at 32, {', '.join(WITNESSES[64])} at 64")


if __name__ == "__main__":
    main()
