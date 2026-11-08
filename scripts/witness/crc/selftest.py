#!/usr/bin/env python3
"""Checks /opt/crcwitness before anything is written from it.

    python3 scripts/witness/crc/selftest.py [/opt/crcwitness]

The two transcriptions of the catalogue must agree on every entry both
carry, and every witness must give every agreed entry's check value, the
CRC of "123456789" - pycrc's table-driven algorithm and crcmod where they
take the entry.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from catalogue import entries, request  # noqa: E402

WITNESSES = ["pycrc-bbb", "pycrc-bbf", "pycrc-tbl", "crccheck", "crcmod", "rust-crc"]
# These take every width and both reflections; the other two take some.
EVERYTHING = ["pycrc-bbb", "pycrc-bbf", "crccheck", "rust-crc"]


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/crcwitness"
    agreed, missing = entries(out)
    requests = [request(f, b"123456789") for _, f in agreed]
    counts = {}
    for w in WITNESSES:
        counts[w] = 0
        for (name, f), answer in zip(agreed, ask(out, w, requests)):
            if answer == "error unsupported" and w not in EVERYTHING:
                continue
            if int(answer, 16) != f["check"]:
                sys.exit(f"{w} gives {answer} for {name}, whose check is {f['check']:x}")
            counts[w] += 1
    print(f"crc witnesses: {len(agreed)} catalogue entries in both transcriptions "
          f"(only one has {', '.join(missing) or 'none'}); check values reproduced: "
          + ", ".join(f"{w} {n}" for w, n in counts.items()))


if __name__ == "__main__":
    main()
