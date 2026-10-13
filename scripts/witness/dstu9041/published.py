#!/usr/bin/env python3
"""DSTU 9041's worked examples, read out of the witnesses' sources.

    python3 published.py <witness dir>          list them
    python3 published.py --check <witness dir>  require both witnesses
                                                to reproduce every one

The standard's Annex Г works one encryption through for each field
size; Г.1 (E256/1) and Г.3 (E512/1) are the curves here. uacrypt's
tests/vectors/dstu9041/g1-worked-example.json and g3-worked-example.json
transcribe them: the private key `e`, the public key `Q`, the message,
the one-time key `ε` and the ciphertext `C = r || t`. The printed `t`
of Г.1 has a digit missing, which uacrypt restores and notes; li0ard's
dstu9041/index.spec.ts carries the same two examples, and the two
transcriptions must agree before either is used.

Scalars, coordinates and the message are big endian, as printed.
"""

import json
import os
import re
import subprocess
import sys

CURVES = {256: "dstu9041-e256-1", 512: "dstu9041-e512-1"}


def examples(src):
    out = []
    spec = open(os.path.join(src, "li0ard/src/dstu9041/index.spec.ts"), encoding="utf-8").read()
    li0ard = re.findall(r'test\("#\d", \(\) => performTest\(\s*dstu9041_(\d+),\s*privateKey,\s*'
                        r'hexToBytes\("([0-9A-Fa-f]+)"\),\s*rand,\s*hexToBytes\("([0-9A-Fa-f]+)"\),'
                        r'\s*hexToBytes\("([0-9A-Fa-f]+)"\)', spec)
    li0ard = {int(bits): (m.lower(), q.lower(), c.lower()) for bits, m, q, c in li0ard}
    keys = re.search(r'privateKey = hexToBytes\("([0-9A-Fa-f]+)"\).*?rand = hexToBytes\("([0-9A-Fa-f]+)"\)',
                     spec, re.S)
    for name, bits in (("g1", 256), ("g3", 512)):
        with open(os.path.join(src, f"uacrypt/vectors/{name}-worked-example.json")) as f:
            j = json.load(f)
        width = bits // 8
        e = bytes.fromhex(j["private_key_e_hex"].rjust(2 * width, "0"))
        eps = bytes.fromhex(j["ephemeral_key_epsilon_hex"].rjust(2 * width, "0"))
        q = (j["public_key_Q"]["x_hex"] + j["public_key_Q"]["y_hex"]).lower()
        m = j["message_M_hex"].lower()
        c = j["ciphertext_C_hex"].lower()
        if int(j["message_M_bits"]) != 4 * len(m):
            sys.exit(f"{name}: the message is not whole bytes")
        if (m, q, c) != li0ard.get(bits):
            sys.exit(f"{name}: uacrypt's and li0ard's transcriptions differ")
        if int(keys.group(1), 16) != int.from_bytes(e, "big") or \
                int(keys.group(2), 16) != int.from_bytes(eps, "big"):
            sys.exit(f"{name}: uacrypt's and li0ard's keys differ")
        out.append((CURVES[bits], bits, e, bytes.fromhex(q), eps, bytes.fromhex(m),
                    8 * len(m) // 2, bytes.fromhex(c)))
    return out


def witnesses(out_dir):
    bun = os.environ.get("BUN") or "bun"
    return {"uacrypt": [os.path.join(out_dir, "dstu9041-uacrypt")],
            "li0ard": [bun, os.path.join(out_dir, "src", "li0ard", "driver.ts")]}


def run(program, lines):
    """One answer per request line; `None` for a refusal."""
    out = subprocess.run(program, input="".join(l + "\n" for l in lines), capture_output=True,
                         text=True, check=True).stdout.split("\n")[:len(lines)]
    if len(out) != len(lines):
        sys.exit(f"{program[-1]} answered {len(out)} of {len(lines)} requests")
    return [None if a.startswith("error") else a.split(" ")[0] for a in out]


def check(out_dir):
    rows = examples(os.path.join(out_dir, "src"))
    for who, program in witnesses(out_dir).items():
        requests = []
        for _, bits, e, q, eps, m, mbits, c in rows:
            requests += [f"pub {bits} {e.hex()}", f"enc {bits} {q.hex()} {eps.hex()} {m.hex()}",
                         f"dec {bits} {e.hex()} {c.hex()}"]
        answers = run(program, requests)
        for i, (name, _, _, q, _, m, _, c) in enumerate(rows):
            if answers[3 * i:3 * i + 3] != [q.hex(), c.hex(), m.hex()]:
                sys.exit(f"{who} misses the worked example on {name}")
    print(f"both witnesses reproduce the standard's {len(rows)} worked examples")


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        check(sys.argv[2])
    else:
        for row in examples(os.path.join(sys.argv[1], "src")):
            print(row[0], *(x.hex() if isinstance(x, bytes) else x for x in row[2:]))
