#!/usr/bin/env python3
"""Check the wide-block CMAC and EAX witnesses before anything uses them.

    python3 scripts/witness/widemac/selftest.py /opt/widemac

Two things, each a reason to stop rather than write vectors:

  * Botan's published tests over Threefish-512 - `CMAC(Threefish-512)` in
    src/tests/data/mac/cmac.vec and `Threefish-512/EAX` in
    src/tests/data/aead/eax.vec, read out of the pinned tree - reproduced by
    every witness that has Threefish-512, which is all three.
  * Agreement, on a short message and a long one, between every witness
    that has each cipher.
"""

import os
import subprocess
import sys

CIPHERS = {
    "threefish256": 32, "threefish512": 64, "threefish1024": 128,
    "shacal2": 64, "kalyna-256": 32, "kalyna-512": 64,
    "rijndael-160": 20, "rijndael-192": 24, "rijndael-224": 28,
    "rijndael-256": 32,
}
WITNESSES = ["cryptopp-witness", "botan-witness", "bc-witness"]


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)], input="\n".join(requests) + "\n",
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def sections(path):
    """`{section: [ {field: value} ]}` from a Botan .vec file."""
    out, current, row = {}, None, {}
    for line in open(path):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            out[current] = []
            row = {}
        elif "=" in line and current is not None:
            key, value = (part.strip() for part in line.split("=", 1))
            row[key] = value.lower()
            if key == "Out":
                out[current].append(row)
                row = {}
    return out


def published(out):
    data = os.path.join(out, "src", "botan", "src", "tests", "data")
    cmac = sections(os.path.join(data, "mac", "cmac.vec"))["CMAC(Threefish-512)"]
    eax = sections(os.path.join(data, "aead", "eax.vec"))["Threefish-512/EAX"]
    if len(cmac) != 1 or len(eax) != 1:
        sys.exit(f"expected one published row of each, found {len(cmac)} and {len(eax)}")
    requests, expected = [], []
    for row in cmac:
        requests.append(f"cmac threefish512 {row['Key']} {row['In'] or '-'}")
        expected.append(row["Out"])
    for row in eax:
        requests.append(f"eax threefish512 {row['Key']} {row['Nonce'] or '-'} "
                        f"{row.get('AD') or '-'} {row['In'] or '-'}")
        size = len(row["In"])
        expected.append(f"{row['Out'][:size] or '-'} {row['Out'][size:]}")
    return requests, expected


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/widemac"
    requests, expected = published(out)
    for witness in WITNESSES:
        if ask(out, witness, requests) != expected:
            sys.exit(f"{witness} does not reproduce Botan's published Threefish-512 tests")

    requests = []
    for cipher, key_len in CIPHERS.items():
        key = bytes(range(1, key_len + 1)).hex()
        requests.append(f"cmac {cipher} {key} 61")
        requests.append(f"cmac {cipher} {key} {bytes(range(200)).hex()}")
        requests.append(f"eax {cipher} {key} 00 0102 {bytes(range(150)).hex()}")
    answers = {w: ask(out, w, requests) for w in WITNESSES}
    for i, request in enumerate(requests):
        given = {answers[w][i] for w in WITNESSES
                 if answers[w][i] != "error unsupported"}
        if len(given) != 1 or any(a.startswith("error") for a in given):
            sys.exit(f"the witnesses disagree on {request}: {given}")
    print("widemac witnesses: Botan's published tests reproduced, and every "
          "cipher agreed by all that have it")


if __name__ == "__main__":
    main()
