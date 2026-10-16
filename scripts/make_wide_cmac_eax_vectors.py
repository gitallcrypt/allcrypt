#!/usr/bin/env python3
"""Write vectors/cmac_eax_wide.vec: CMAC and EAX over 160 to 1024 bit blocks.

    sh scripts/witness/widemac/build.sh /opt/widemac
    python3 scripts/make_wide_cmac_eax_vectors.py [/opt/widemac]

**A development tool, not a test.** `tests/test_cmac_eax_wide.rs` reads
the file offline.

SP 800-38B defines CMAC's field for 64 and 128 bit blocks only. Wider
blocks take the polynomial `scripts/make_cmac_polynomials.py` computes,
and three implementations that share no code use the same ones: Botan
3.6.1, Crypto++ 8.9.0 and Bouncy Castle 1.77. Between them they cover:

    cipher                     Botan  Crypto++  Bouncy Castle
    Threefish-512, SHACAL-2      x       x           x
    Threefish-256 and -1024              x           x
    Kalyna-256 and -512                  x           x
    Rijndael-160 to -256                             x

So the Rijndaels rest on one witness, and say so. `build.sh` checks
before this runs that every witness reproduces Botan's published
Threefish-512 tests and that they agree wherever they overlap.

In order:

1. Botan's published tests over the wide blocks, read out of the pinned
   tree - `CMAC(Threefish-512)` in `src/tests/data/mac/cmac.vec` and
   `Threefish-512/EAX` in `src/tests/data/aead/eax.vec` - with
   `source=botan-tests`, and every witness must reproduce them.
2. For each cipher, CMAC over messages either side of one, two and three
   blocks, and EAX over nonces, associated data and messages of lengths
   around the block, under keys of every length the witnesses share.
   Keys and contents come from a seeded generator, so the file is the
   same every time. Each row is written only when every witness that has
   the cipher gives the same answer, and `witnesses=` names them.

Rows, hex fields, "-" for empty:

    cmac cipher= key= msg= tag= source= witnesses=
    eax cipher= key= nonce= ad= pt= ct= tag= source= witnesses=

`cipher` is the library's name for it; a tag is a whole block.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "cmac_eax_wide.vec")

#: cipher: (block bytes, key lengths every witness that has it takes,
#: the witnesses that have it).
CIPHERS = {
    "threefish256": (32, [32], ["cryptopp", "bc"]),
    "threefish512": (64, [64], ["botan", "cryptopp", "bc"]),
    "threefish1024": (128, [128], ["cryptopp", "bc"]),
    # Bouncy Castle takes a multiple of 8 bytes, the others any length.
    "shacal2": (32, [16, 24, 32, 48, 64], ["botan", "cryptopp", "bc"]),
    "kalyna-256": (32, [32, 64], ["cryptopp", "bc"]),
    "kalyna-512": (64, [64], ["cryptopp", "bc"]),
    "rijndael-160": (20, [16, 20, 24, 28, 32], ["bc"]),
    "rijndael-192": (24, [16, 20, 24, 28, 32], ["bc"]),
    "rijndael-224": (28, [16, 20, 24, 28, 32], ["bc"]),
    "rijndael-256": (32, [16, 20, 24, 28, 32], ["bc"]),
}
PROGRAMS = {"botan": "botan-witness", "cryptopp": "cryptopp-witness", "bc": "bc-witness"}


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
    """Botan's own tests over the wide blocks: `(kind, fields, request)`."""
    data = os.path.join(out, "src", "botan", "src", "tests", "data")
    rows = []
    for row in sections(os.path.join(data, "mac", "cmac.vec"))["CMAC(Threefish-512)"]:
        fields = {"key": bytes.fromhex(row["Key"]), "msg": bytes.fromhex(row["In"]),
                  "tag": bytes.fromhex(row["Out"])}
        rows.append(("cmac", "threefish512", fields))
    for row in sections(os.path.join(data, "aead", "eax.vec"))["Threefish-512/EAX"]:
        pt = bytes.fromhex(row["In"])
        out_bytes = bytes.fromhex(row["Out"])
        fields = {"key": bytes.fromhex(row["Key"]), "nonce": bytes.fromhex(row["Nonce"]),
                  "ad": bytes.fromhex(row.get("AD", "")), "pt": pt,
                  "ct": out_bytes[:len(pt)], "tag": out_bytes[len(pt):]}
        rows.append(("eax", "threefish512", fields))
    if len(rows) != 2:
        sys.exit(f"expected one published CMAC and one EAX test, found {len(rows)}")
    return rows


def request(kind, cipher, fields):
    if kind == "cmac":
        return f"cmac {cipher} {h(fields['key'])} {h(fields['msg'])}"
    return (f"eax {cipher} {h(fields['key'])} {h(fields['nonce'])} "
            f"{h(fields['ad'])} {h(fields['pt'])}")


def answer_fields(kind, answer):
    if kind == "cmac":
        return {"tag": bytes.fromhex(answer)}
    ct, tag = answer.split()
    return {"ct": bytes.fromhex(ct) if ct != "-" else b"", "tag": bytes.fromhex(tag)}


def generated(rng):
    """The rows to ask about: `(kind, cipher, inputs)`."""
    rows = []
    for cipher, (block, key_lengths, _) in CIPHERS.items():
        keys = iter(rng.randbytes(key_lengths[i % len(key_lengths)]) for i in range(10**6))
        b = block
        for length in [0, 1, b - 1, b, b + 1, 2 * b - 1, 2 * b, 2 * b + 1, 3 * b + 5]:
            rows.append(("cmac", cipher, {"key": next(keys), "msg": rng.randbytes(length)}))
        for nonce, ad, pt in [(16, 0, 0), (0, 0, 5), (16, 0, 1), (16, 5, b - 1), (b, b, b),
                              (1, b + 1, b + 1), (12, 2 * b, 2 * b + 3), (b + 3, 3, 3 * b + 7)]:
            rows.append(("eax", cipher, {"key": next(keys), "nonce": rng.randbytes(nonce),
                                         "ad": rng.randbytes(ad), "pt": rng.randbytes(pt)}))
    return rows


def line(kind, cipher, fields, source, witnesses):
    names = ["key", "msg", "tag"] if kind == "cmac" else ["key", "nonce", "ad", "pt", "ct", "tag"]
    return (f"{kind} cipher={cipher} " + " ".join(f"{n}={h(fields[n])}" for n in names)
            + f" source={source} witnesses={','.join(witnesses)}")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/widemac"
    lines = []

    # 1. Botan's published tests: every witness with the cipher reproduces them.
    for kind, cipher, fields in published(out):
        witnesses = CIPHERS[cipher][2]
        for witness in witnesses:
            got = answer_fields(kind, ask(out, witness, [request(kind, cipher, fields)])[0])
            if any(got[k] != fields[k] for k in got):
                sys.exit(f"{witness} does not reproduce Botan's published {kind} test")
        lines.append(line(kind, cipher, fields, "botan-tests", witnesses))

    # 2. Generated rows, agreed by every witness that has the cipher.
    rows = generated(random.Random(20261016))
    by_witness = {}
    for witness in PROGRAMS:
        mine = [i for i, (_, cipher, _) in enumerate(rows) if witness in CIPHERS[cipher][2]]
        answers = ask(out, witness, [request(*rows[i]) for i in mine])
        by_witness[witness] = dict(zip(mine, answers))
    for i, (kind, cipher, fields) in enumerate(rows):
        witnesses = CIPHERS[cipher][2]
        answers = {by_witness[w][i] for w in witnesses}
        if len(answers) != 1:
            sys.exit(f"the witnesses disagree on {request(kind, cipher, fields)[:80]}")
        fields = dict(fields, **answer_fields(kind, answers.pop()))
        lines.append(line(kind, cipher, fields, "generated", witnesses))

    counts = {}
    for text in lines:
        cipher = text.split()[1][len("cipher="):]
        counts[cipher] = counts.get(cipher, 0) + 1
    header = [
        "# CMAC and EAX over 160 to 1024 bit blocks. Written by",
        "# scripts/make_wide_cmac_eax_vectors.py; do not edit. source=botan-tests:",
        "# Botan 3.6.1's published tests, which every witness reproduces;",
        "# generated: seeded random inputs. witnesses: who gave the answer, every",
        "# one that has the cipher agreeing - botan is Botan 3.6.1, cryptopp is",
        "# Crypto++ 8.9.0, bc is Bouncy Castle 1.77. Tags are a whole block.",
        f"# rows: {len(lines)}, " + ", ".join(f"{c}: {n}" for c, n in counts.items()),
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
