#!/usr/bin/env python3
"""Write vectors/siphash.vec: SipHash and HalfSipHash at several round
counts and both output lengths, from three implementations.

    scripts/witness/siphash/build.sh /opt/siphashwitness
    python3 scripts/make_siphash_vectors.py

**A development tool, not a test.** `tests/test_siphash.rs` and
`pytests/test_siphash.py` read the file offline. The designers' own
vectors are `rfcs/siphash-vectors.h`, which the same tests read.

The witnesses (`scripts/witness/siphash`) are the designers' reference
code, compiled once per pair of round counts, OpenSSL 3.5's SIPHASH
MAC, and Bouncy Castle's SipHash and SipHash128; all three must agree on
every SipHash row, or the script stops. HalfSipHash is the reference's
alone - neither library has it. Messages of every length from 0 to 40
bytes, then 63, 64, 65, 100 and 1000, from a fixed seed, under two
keys; written once each:

    msg n= data=
    key n= data=
    mac kind= c= d= size= key= msg= tag=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "siphash.vec")
WITNESS = os.environ.get("SIPHASH_WITNESS", "/opt/siphashwitness")

PAIRS = [(1, 3), (2, 4), (3, 5), (4, 8)]
LENGTHS = list(range(41)) + [63, 64, 65, 100, 1000]


def ask(witness, requests):
    lines = "".join(f"{name} {path}\n" for name, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out[:5]}")
    return out


def main():
    rng = random.Random(0x51F)
    messages = [rng.randbytes(n) for n in LENGTHS]
    keys = [rng.randbytes(16) for _ in range(2)]
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, message in enumerate(messages):
            paths.append(os.path.join(tmp, f"m{i}"))
            with open(paths[-1], "wb") as f:
                f.write(message)
        cases = []
        for kind, sizes, key_len in [("siphash", (8, 16), 16), ("halfsiphash", (4, 8), 8)]:
            for c, d in PAIRS:
                for size in sizes:
                    for k in range(len(keys)):
                        for m in range(len(messages)):
                            cases.append((kind, c, d, size, k, m, keys[k][:key_len].hex()))
        requests = [(f"{kind}-{c}-{d}-{size}:{key}", paths[m])
                    for kind, c, d, size, k, m, key in cases]
        reference = ask("ref", requests)
        sip = [i for i, case in enumerate(cases) if case[0] == "siphash"]
        others = {w: ask(w, [requests[i] for i in sip]) for w in ("openssl", "bc")}
        for w, answers in others.items():
            for i, answer in zip(sip, answers):
                if answer != reference[i]:
                    sys.exit(f"{w} and the reference disagree on {requests[i][0]}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# SipHash and HalfSipHash. Written by scripts/make_siphash_vectors.py;\n"
                  "# do not edit. The designers' reference, OpenSSL 3.5 and Bouncy Castle\n"
                  "# 1.77 agree on every siphash row; halfsiphash rows are the\n"
                  "# reference's. A HalfSipHash key is the first 8 bytes of the key named.\n")
        for i, message in enumerate(messages):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for i, key in enumerate(keys):
            out.write(f"key n={i} data={key.hex()}\n")
        for (kind, c, d, size, k, m, _), tag in zip(cases, reference):
            out.write(f"mac kind={kind} c={c} d={d} size={size} key={k} msg={m} tag={tag}\n")
    print(f"{len(messages)} messages, {len(cases)} rows")


if __name__ == "__main__":
    main()
