#!/usr/bin/env python3
"""Write vectors/turboshake_k12.vec: TurboSHAKE128 and TurboSHAKE256 at
every domain separation byte, and KT128 and KT256 either side of every
chunk boundary, answered by the Keccak team's XKCP K12 and, where it
implements the function, pycryptodome 3.24.1 - both must agree.

    sh scripts/witness/k12/build.sh /opt/k12witness
    pip install --target /opt/k12witness pycryptodome==3.24.1
    python3 scripts/make_turboshake_k12_vectors.py [--witness /opt/k12witness]

Every message and customization string is RFC 9861's ptn(n), so a row
records lengths, not bytes. The rows: TurboSHAKE at every message length
from 0 to 400 bytes and at all 127 domain bytes, outputs crossing the
rate (168 and 136 bytes); KT with messages from 0 to 300 bytes and at
8192 +- 4, 16384 +- 2, 24576 +- 1 and 40960 + 7, and customization
strings that carry S across those boundaries by themselves.

XKCP is run three ways - its plain build, its sanitizer build on
misaligned buffers, and fed in pieces of 1000 bytes - and must give one
answer. pycryptodome has TurboSHAKE128, TurboSHAKE256 and KT128 (its
KangarooTwelve) but no KT256. **A development tool, not a test.**
"""

import argparse
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "vectors", "turboshake_k12.vec")


def ptn(n):
    return bytes(i % 251 for i in range(n))


def cases(rng):
    rows = []
    for security in (128, 256):
        rate = 168 if security == 128 else 136
        for n in range(401):
            domain = 0x1F if n % 3 == 0 else 1 + (n * 37 + security) % 127
            length = rng.choice([1, 16, 32, rate - 1, rate, rate + 1, 2 * rate + 5,
                                 rng.randrange(1, 400)])
            rows.append((f"turboshake{security}", dict(domain=domain, length=length,
                                                       message_len=n)))
        for domain in range(1, 128):
            rows.append((f"turboshake{security}", dict(domain=domain, length=rng.randrange(1, 80),
                                                       message_len=rng.randrange(0, 600))))
    boundaries = [8192 + d for d in range(-4, 5)] + [16384 + d for d in range(-2, 3)]
    boundaries += [24576 + d for d in (-1, 0, 1)] + [40960 + 7]
    for security in (128, 256):
        for n in range(301):
            rows.append((f"kt{security}", dict(length=rng.randrange(1, 140), message_len=n,
                                               custom_len=rng.choice([0, 0, 1, n % 50]))))
        for n in boundaries:
            for custom in (0, 1, 41):
                rows.append((f"kt{security}", dict(length=rng.randrange(1, 140), message_len=n,
                                                   custom_len=custom)))
        # The customization string alone carries S over the first chunk.
        for m, c in [(8100, 85), (8100, 89), (8100, 92), (0, 8192), (0, 8189), (100, 16300)]:
            rows.append((f"kt{security}", dict(length=64, message_len=m, custom_len=c)))
    return rows


def xkcp(binary, rows, *args):
    lines = []
    for kind, f in rows:
        if kind.startswith("turboshake"):
            lines.append(f"ts {kind[10:]} {f['domain']:x} {f['length']} {f['message_len']}")
        else:
            lines.append(f"kt {kind[2:]} {f['length']} {f['message_len']} {f['custom_len']}")
    result = subprocess.run([binary, *args], input="\n".join(lines) + "\n",
                            capture_output=True, text=True)
    if result.returncode != 0 or result.stderr.strip():
        sys.exit(f"{binary} {args}: {result.returncode} {result.stderr[-2000:]}")
    return result.stdout.split()


def pycryptodome(kind, f):
    from Crypto.Hash import KangarooTwelve, TurboSHAKE128, TurboSHAKE256
    if kind == "turboshake128":
        return TurboSHAKE128.new(data=ptn(f["message_len"]), domain=f["domain"]).read(f["length"])
    if kind == "turboshake256":
        return TurboSHAKE256.new(data=ptn(f["message_len"]), domain=f["domain"]).read(f["length"])
    if kind == "kt128":
        return KangarooTwelve.new(data=ptn(f["message_len"]),
                                  custom=ptn(f["custom_len"])).read(f["length"])
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness", default="/opt/k12witness")
    args = parser.parse_args()
    sys.path.insert(0, args.witness)
    rng = random.Random(0x9861)
    rows = cases(rng)
    plain = xkcp(os.path.join(args.witness, "k12-witness"), rows)
    for other in [(os.path.join(args.witness, "k12-witness-san"), "1", "0"),
                  (os.path.join(args.witness, "k12-witness"), "0", "1000")]:
        if xkcp(*other[:1], rows, *other[1:]) != plain:
            sys.exit(f"XKCP disagrees with itself: {other}")
    counts = {}
    with open(OUT, "w") as handle:
        handle.write(
            "# TurboSHAKE128/256 and KT128/256 (RFC 9861), from the Keccak team's XKCP\n"
            "# K12 (f95b0b7) and pycryptodome 3.24.1, which agree where both implement\n"
            "# it (pycryptodome has no KT256). Written by\n"
            "# scripts/make_turboshake_k12_vectors.py; do not edit. message_len and\n"
            "# custom_len are lengths of RFC 9861's ptn(n); domain is in hex.\n"
            "# witnesses: who gave the output.\n")
        for (kind, f), answer in zip(rows, plain):
            out = bytes.fromhex(answer)
            witnesses = ["xkcp"]
            other = pycryptodome(kind, f)
            if other is not None:
                if other != out:
                    sys.exit(f"pycryptodome and XKCP disagree: {kind} {f}")
                witnesses.append("pycryptodome")
            fields = [f"message_len={f['message_len']}"]
            if "domain" in f:
                fields.append(f"domain={f['domain']:02x}")
            if "custom_len" in f:
                fields.append(f"custom_len={f['custom_len']}")
            fields += [f"length={f['length']}", f"output={out.hex()}",
                       f"witnesses={','.join(witnesses)}"]
            handle.write(f"{kind} {' '.join(fields)}\n")
            counts[kind] = counts.get(kind, 0) + 1
    print(f"wrote {OUT}: {counts}")


if __name__ == "__main__":
    main()
