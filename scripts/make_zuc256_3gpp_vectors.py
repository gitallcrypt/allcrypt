#!/usr/bin/env python3
"""Write vectors/zuc256_3gpp.vec: 256-NEA6, 256-NIA6 and 256-NCA6 over
3GPP's ZUC-256, every answer from TS 35.246 V20.0.0's Annex A reference
code under scripts/witness/zuc256_3gpp.

    sh scripts/witness/zuc256_3gpp/build.sh /opt/zuc256witness
    python3 scripts/make_zuc256_3gpp_vectors.py [--witness /opt/zuc256witness]

The rows sweep the lengths the published test data leaves out: NEA6 at
every length from 0 to 600 bits, NIA6 at every one from 0 to 400 with
each MAC size from 4 to 16 bytes in turn, NCA6 with the AAD and the data
each partial and whole, 32 and 16 byte keys (the latter zero-extended,
LK set), EXTRA_IV given and not. NCA6 decryption rows give a MAC with one
bit changed, which the reference refuses, and ciphertexts with junk past
their last bit, which it ignores when it authenticates.

The inputs come from a fixed seed, so the file is the same each run. The
witness is run on misaligned buffers as well, under the sanitizer build,
and must agree with itself. **A development tool, not a test.**
"""

import argparse
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "vectors", "zuc256_3gpp.vec")


def hexor(data):
    return data.hex() if data else "-"


def message(rng, bits):
    data = bytearray(rng.randbytes((bits + 7) // 8))
    return bytes(data)


def cases(rng):
    rows = []

    def common():
        key = rng.randbytes(16 if rng.random() < 0.25 else 32)
        extra = rng.randbytes(6) if rng.random() < 0.5 else b""
        return key, rng.getrandbits(32), rng.randrange(32), rng.randrange(2), extra

    for bits in range(601):
        key, count, bearer, direction, extra = common()
        rows.append(("nea", dict(key=key, count=count, bearer=bearer, direction=direction,
                                 extra_iv=extra, bits=bits, data=message(rng, bits))))
    for bits in range(401):
        key, count, bearer, direction, extra = common()
        rows.append(("nia", dict(key=key, count=count, bearer=bearer, direction=direction,
                                 extra_iv=extra, mac_bytes=4 + bits % 13, bits=bits,
                                 data=message(rng, bits))))
    for n in range(300):
        key, count, bearer, direction, extra = common()
        aad_bits = rng.choice([0, 0, rng.randrange(1, 300), 8 * rng.randrange(1, 40)])
        bits = rng.choice([0, rng.randrange(1, 700), 8 * rng.randrange(1, 80)])
        rows.append(("nca", dict(key=key, count=count, bearer=bearer, direction=direction,
                                 extra_iv=extra, mac_bytes=4 + n % 13, aad_bits=aad_bits,
                                 aad=message(rng, aad_bits), bits=bits,
                                 data=message(rng, bits))))
    return rows


def line(kind, f):
    head = (f"{kind} {hexor(f['key'])} {f['count']} {f['bearer']} {f['direction']} "
            f"{hexor(f['extra_iv'])}")
    if kind == "nea":
        return f"{head} {f['bits']} {hexor(f['data'])}"
    if kind == "nia":
        return f"{head} {f['mac_bytes']} {f['bits']} {hexor(f['data'])}"
    if kind == "nca":
        return (f"{head} {f['mac_bytes']} {f['aad_bits']} {hexor(f['aad'])} {f['bits']} "
                f"{hexor(f['data'])}")
    return (f"{head} {f['aad_bits']} {hexor(f['aad'])} {f['bits']} {hexor(f['data'])} "
            f"{hexor(f['mac'])}")


def run(binary, lines, offset):
    result = subprocess.run([binary, str(offset)], input="\n".join(lines) + "\n",
                            capture_output=True, text=True,
                            env={**os.environ, "UBSAN_OPTIONS": "print_stacktrace=1"})
    if result.returncode != 0 or result.stderr.strip():
        sys.exit(f"{binary} {offset}: {result.stderr[-2000:]}")
    return result.stdout.splitlines()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness", default="/opt/zuc256witness")
    args = parser.parse_args()
    plain = os.path.join(args.witness, "zuc256-3gpp")
    sanitized = os.path.join(args.witness, "zuc256-3gpp-san")
    rng = random.Random(0x3524_6020)
    rows = cases(rng)
    answers = run(plain, [line(k, f) for k, f in rows], 0)
    for (kind, f), answer in zip(rows, answers):
        if kind == "nea":
            f["out"] = bytes.fromhex(answer) if answer != "-" else b""
        elif kind == "nia":
            f["mac"] = bytes.fromhex(answer)
        else:
            out, mac = answer.split()
            f["out"] = bytes.fromhex(out) if out != "-" else b""
            f["mac"] = bytes.fromhex(mac)
    # Decryption: each NCA6 ciphertext back, then with a MAC bit changed,
    # then with junk in its last byte's unused bits.
    extra_rows = []
    for kind, f in rows:
        if kind != "nca":
            continue
        back = dict(f, data=f["out"])
        extra_rows.append(("ncad", dict(back, expect="plain")))
        bent = bytearray(f["mac"])
        bent[rng.randrange(len(bent))] ^= 1 << rng.randrange(8)
        extra_rows.append(("ncad", dict(back, mac=bytes(bent), expect="refused")))
        if f["bits"] % 8:
            junk = bytearray(f["out"])
            junk[-1] |= 0xFF >> (f["bits"] % 8)
            extra_rows.append(("ncad", dict(back, data=bytes(junk), expect="plain")))
    answers = run(plain, [line(k, f) for k, f in extra_rows], 0)
    for (kind, f), answer in zip(extra_rows, answers):
        f["out"] = b"" if answer in ("-", "refused") else bytes.fromhex(answer)
        f["refused"] = answer == "refused"
        if f.pop("expect") == "refused" and not f["refused"]:
            sys.exit("the reference accepted a MAC with a bit changed")
    rows += extra_rows
    # The sanitizer build, aligned and not, must give the same answers.
    every = [line(k, f) for k, f in rows]
    first = run(plain, every, 0)
    for offset in (0, 1):
        if run(sanitized, every, offset) != first:
            sys.exit(f"the sanitizer build disagrees at offset {offset}")

    counts = {}
    with open(OUT, "w") as handle:
        handle.write(
            "# 256-NEA6, 256-NIA6 and 256-NCA6 over 3GPP's ZUC-256: answers from TS\n"
            "# 35.246 V20.0.0 Annex A's reference code (scripts/witness/zuc256_3gpp).\n"
            "# Written by scripts/make_zuc256_3gpp_vectors.py; do not edit. Byte strings\n"
            "# in hex, - for none; lengths in bits. ncad is NCA6 decryption: out is the\n"
            "# plaintext, or refused=1 when the MAC did not match. The published test\n"
            "# data is rfcs/35247-k00.txt and rfcs/35248-k00.txt.\n")
        for kind, f in rows:
            counts[kind] = counts.get(kind, 0) + 1
            fields = []
            for name in ("key", "count", "bearer", "direction", "extra_iv", "mac_bytes",
                         "aad_bits", "aad", "bits", "data", "out", "mac", "refused"):
                if name not in f:
                    continue
                value = f[name]
                if kind == "ncad" and name == "mac_bytes":
                    continue
                if isinstance(value, bool):
                    value = int(value)
                fields.append(f"{name}={hexor(value) if isinstance(value, bytes) else value}")
            handle.write(f"{kind} {' '.join(fields)}\n")
    print(f"wrote {OUT}: {counts}")


if __name__ == "__main__":
    main()
