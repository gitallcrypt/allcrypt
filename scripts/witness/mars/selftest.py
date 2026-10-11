"""Require each MARS witness to reproduce every vector in Crypto++'s
TestVectors/mars.txt: the single blocks both ways, and the Monte Carlo
tests in the direction each names.

    python3 selftest.py <mars.txt> <witness>...
"""

import re
import subprocess
import sys


def read(path):
    """The file's tests as (test, key, plaintext, ciphertext), in order."""
    text = open(path, encoding="utf-8").read()
    rows = re.findall(r"Key: ([0-9A-F]+)\s+Plaintext: ([0-9A-F]+)\s+"
                      r"Ciphertext: ([0-9A-F]+)\s+Test: (\w+)", text)
    if len(rows) != text.count("Test:"):
        sys.exit(f"{path}: read {len(rows)} of {text.count('Test:')} tests")
    return [(t, bytes.fromhex(k), bytes.fromhex(p), bytes.fromhex(c)) for k, p, c, t in rows]


def requests(rows):
    """Each row as the request that checks it and the answer it expects."""
    out = []
    for test, key, pt, ct in rows:
        if test == "Encrypt":
            out.append((f"enc {key.hex()} {pt.hex()}", ct))
            out.append((f"dec {key.hex()} {ct.hex()}", pt))
        elif test == "EncryptionMCT":
            out.append((f"mct-enc {key.hex()} {pt.hex()}", ct))
        elif test == "DecryptionMCT":
            out.append((f"mct-dec {key.hex()} {ct.hex()}", pt))
        else:
            sys.exit(f"unknown test {test}")
    return out


def main():
    path, witnesses = sys.argv[1], sys.argv[2:]
    rows = read(path)
    checks = requests(rows)
    for witness in witnesses:
        stdin = "".join(r + "\n" for r, _ in checks)
        got = subprocess.run([witness], input=stdin, capture_output=True, text=True,
                             check=True).stdout.split("\n")[:len(checks)]
        wrong = [r for (r, want), line in zip(checks, got) if line != want.hex()]
        if len(got) != len(checks) or wrong:
            sys.exit(f"{witness} fails {len(wrong)} of {len(checks)}: {wrong[:3]}")
        print(f"{witness}: {len(rows)} tests of mars.txt reproduced")


if __name__ == "__main__":
    main()
