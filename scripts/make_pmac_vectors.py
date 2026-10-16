#!/usr/bin/env python3
"""Write vectors/pmac.vec: PMAC over 64 and 128 bit block ciphers.

    sh scripts/witness/macs/build.sh /opt/macwitness
    python3 scripts/make_pmac_vectors.py [/opt/macwitness]

**A development tool, not a test.** `tests/test_pmac.rs` reads the file
offline.

Three implementations that share no code: libtomcrypt 1.18.2 (built with
LTC_NO_FAST - its fast path is wrong over 64 bit ciphers, see
`scripts/witness/macs/build.sh`), RustCrypto's `pmac` 0.7.1, and
miscreant.go, which has AES alone. In order:

1. Rogaway's published PMAC-AES-128 and PMAC-AES-256 tests, read out of
   miscreant.go's `vectors/aes_pmac.tjson` in the pinned tree
   (`source=rogaway`); every witness must reproduce them.
2. Rows from a seeded generator (`source=generated`) over AES at all
   three key lengths, DES, 3DES and Blowfish: messages either side of
   one, two and three blocks, and long ones that pass 32 blocks and
   reach an index whose trailing zero count is 6. Each row is written
   only when every witness that has the cipher gives the same tag.

Rows, hex fields, "-" for empty:

    pmac cipher= key= msg= tag= source= witnesses=
"""

import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "pmac.vec")

#: cipher: (block bytes, key lengths, witnesses)
CIPHERS = {
    "aes": (16, [16, 24, 32], ["ltc", "rust", "go"]),
    "des": (8, [8], ["ltc", "rust"]),
    "3des": (8, [24], ["ltc", "rust"]),
    "blowfish": (8, [8, 16, 56], ["ltc", "rust"]),
}
PROGRAMS = {"ltc": "ltc-pmac", "rust": "rust-pmac", "go": "go-pmac"}


def h(data):
    return data.hex() or "-"


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, PROGRAMS[witness])],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    for request, answer in zip(requests, answers):
        if answer.startswith("error"):
            sys.exit(f"{witness} refused {request[:80]}: {answer}")
    return answers


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/macwitness"
    lines = []

    path = os.path.join(out, "src", "miscreant.go", "vectors", "aes_pmac.tjson")
    published = json.load(open(path))["examples:A<O>"]
    if len(published) != 14:
        sys.exit(f"{path}: expected fourteen tests, read {len(published)}")
    for row in published:
        key, msg, tag = (bytes.fromhex(row[k]) for k in ("key:d16", "message:d16", "tag:d16"))
        request = f"pmac aes {h(key)} {h(msg)}"
        for witness in CIPHERS["aes"][2]:
            if ask(out, witness, [request]) != [tag.hex()]:
                sys.exit(f"{witness} does not reproduce {row['name:s']}")
        lines.append(f"pmac cipher=aes key={h(key)} msg={h(msg)} tag={tag.hex()} "
                     f"source=rogaway witnesses={','.join(CIPHERS['aes'][2])}")

    rng = random.Random(20261016)
    rows = []
    for cipher, (block, key_lengths, _) in CIPHERS.items():
        b = block
        lengths = [0, 1, b - 1, b, b + 1, 2 * b - 1, 2 * b, 2 * b + 1, 3 * b + 3,
                   33 * b, 64 * b + 5, 130 * b - 1]
        for i, length in enumerate(lengths):
            for key_len in (key_lengths if i < 3 else [key_lengths[i % len(key_lengths)]]):
                rows.append((cipher, rng.randbytes(key_len), rng.randbytes(length)))

    answers = {}
    for witness in PROGRAMS:
        mine = [i for i, (c, _, _) in enumerate(rows) if witness in CIPHERS[c][2]]
        got = ask(out, witness, [f"pmac {rows[i][0]} {h(rows[i][1])} {h(rows[i][2])}"
                                 for i in mine])
        answers[witness] = dict(zip(mine, got))
    for i, (cipher, key, msg) in enumerate(rows):
        witnesses = CIPHERS[cipher][2]
        given = {answers[w][i] for w in witnesses}
        if len(given) != 1:
            sys.exit(f"the witnesses disagree on pmac {cipher} {h(key)} ({len(msg)} bytes)")
        lines.append(f"pmac cipher={cipher} key={h(key)} msg={h(msg)} tag={given.pop()} "
                     f"source=generated witnesses={','.join(witnesses)}")

    header = [
        "# PMAC (Black and Rogaway). Written by scripts/make_pmac_vectors.py; do not",
        "# edit. source=rogaway: Rogaway's published PMAC-AES tests, which every",
        "# witness reproduces; generated: seeded random inputs. witnesses: who gave",
        "# the tag, every one that has the cipher agreeing - ltc is libtomcrypt",
        "# 1.18.2 (LTC_NO_FAST), rust is RustCrypto's pmac 0.7.1, go is miscreant.go.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
