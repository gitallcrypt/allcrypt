#!/usr/bin/env python3
"""Write vectors/sha3_finalists.vec: the SHA-3 finalists as their teams
finally submitted them, every name the catalogue gives them, from
several implementations each.

    scripts/witness/finalists/build.sh /opt/finalists
    python3 scripts/make_finalist_vectors.py

**A development tool, not a test.** `tests/test_sha3_finalists.rs` and
`pytests/test_sha3_finalists.py` read the file offline.

The witnesses (`scripts/witness/finalists`), each fed its message in
pieces of 1, 2, 3 ... bytes except the reference code, which is one-shot:

    blake224, blake384          sphlib, dchest's Go
    blake256, blake512          sphlib, dchest's Go, the BLAKE team's reference
    groestl224 ... groestl512   sphlib, the Grøstl team's 32 bit code
    jh224 ... jh512             sphlib, the designer's bitsliced code
    skein256_128 ... skein1024_1024, and skein256_8, skein512_1032 and
    skein1024_2056              the Skein team's code, Bouncy Castle
    skein512_224 ... skein512_512  and sphlib

Every witness that has a name must agree on every message, or the
script stops. The messages are random bytes at lengths around the 64
and 128 byte blocks and their padding limits - BLAKE-256 has one byte
free before its length field at 55 bytes, BLAKE-512 at 111, Grøstl-256
and -512 run into a second block from 56 and 120, JH always adds at
least one block of padding, Skein's blocks are 32, 64 and 128 bytes and
its last one is processed differently - up to
1000, from a fixed seed, and the zeros of the BLAKE submission's worked
examples (1 and 72 bytes for BLAKE-256, 1 and 144 for BLAKE-512),
written once each as `msg` rows that the `hash` rows name by index:

    msg n= data=
    hash name= msg= digest=

and, for BLAKE's counter past 32 bits, the digest sphlib and the
reference give when their context is told it has already taken `taken`
bytes, which `blake.rs`'s own tests reproduce:

    after name= taken= msg= digest=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "sha3_finalists.vec")
WITNESS = os.environ.get("FINALISTS_WITNESS", "/opt/finalists")

WITNESSES = {"blake224": ["sph", "go"], "blake256": ["sph", "go", "ref"],
             "blake384": ["sph", "go"], "blake512": ["sph", "go", "ref"],
             **{f"groestl{bits}": ["sph", "groestl"] for bits in (224, 256, 384, 512)},
             **{f"jh{bits}": ["sph", "ref"] for bits in (224, 256, 384, 512)},
             # Every size the Skein submission names, and three it does not:
             # one byte, and outputs longer than the state, which take
             # several output blocks.
             **{f"skein{state}_{bits}": ["skein", "bc"] + (["sph"] if state == 512
                                                         and bits in (224, 256, 384, 512)
                                                         else [])
                for state, sizes in [(256, (128, 160, 224, 256, 8)),
                                     (512, (128, 160, 224, 256, 384, 512, 1032)),
                                     (1024, (384, 512, 1024, 2056))]
                for bits in sizes}}
LENGTHS = [0, 1, 2, 3, 31, 32, 33, 54, 55, 56, 57, 63, 64, 65, 95, 96, 97,
           110, 111, 112, 113, 119, 120, 127, 128, 129, 191, 192, 255, 256, 1000]
ZEROS = [1, 72, 144]
# BLAKE's counter past 32 bits, which no message here reaches: whole
# blocks a context is told it has already taken, at which BLAKE-256's
# counter carries into its high word during the message, or wraps past
# 2^64 bits, and BLAKE-512's high word is already set. (The BLAKE-512
# reference does not carry into its high word, so no row crosses 2^64
# bits there.)
AFTER = {"blake256": [2**29 - 64, 2**61 - 64], "blake512": [2**61, 2**61 + 2**60]}
AFTER_LENGTHS = [0, 55, 64, 111, 128, 1000]


def ask(witness, requests):
    """The witness's answers to [(name, path)], in order."""
    lines = "".join(f"{name} {path}\n" for name, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out}")
    return out


def main():
    rng = random.Random(0x5A3F17)
    messages = [rng.randbytes(n) for n in LENGTHS] + [bytes(n) for n in ZEROS]
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, message in enumerate(messages):
            paths.append(os.path.join(tmp, f"m{i}"))
            with open(paths[-1], "wb") as f:
                f.write(message)
        answers = {}
        for witness in sorted({w for who in WITNESSES.values() for w in who}):
            requests = [(name, path) for name, who in WITNESSES.items() if witness in who
                        for path in paths]
            for (name, path), digest in zip(requests, ask(witness, requests)):
                answers.setdefault((name, paths.index(path)), {})[witness] = digest
        after_rows = []
        for name, takens in AFTER.items():
            requests = [(f"{name}_after_{taken}", paths[LENGTHS.index(n)])
                        for taken in takens for n in AFTER_LENGTHS]
            for (request, path), a, b in zip(requests, ask("sph", requests),
                                             ask("ref", requests)):
                if a != b:
                    sys.exit(f"sphlib and the reference disagree on {request}")
                taken = request.split("_after_")[1]
                after_rows.append(f"after name={name} taken={taken} "
                                  f"msg={paths.index(path)} digest={a}")
    rows = []
    for name, who in WITNESSES.items():
        for i, message in enumerate(messages):
            given = answers[(name, i)]
            if sorted(given) != sorted(who) or len(set(given.values())) != 1:
                sys.exit(f"the witnesses disagree on {name} of {len(message)} bytes: {given}")
            rows.append(f"hash name={name} msg={i} digest={given[who[0]]}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# The SHA-3 finalists as finally submitted. Written by\n"
                  "# scripts/make_finalist_vectors.py; do not edit. Every witness that\n"
                  "# has a name agrees on every row: sphlib and dchest's Go on BLAKE,\n"
                  "# and the BLAKE team's reference on blake256 and blake512; sphlib\n"
                  "# and the Grøstl team's code on Grøstl; sphlib and the designer's\n"
                  "# bitsliced code on JH; the Skein team's code and Bouncy Castle on\n"
                  "# Skein, and sphlib on Skein-512 from 224 bits. An after row is the\n"
                  "# message hashed by a context told it has already taken that many\n"
                  "# bytes, where sphlib and the BLAKE team's reference agree.\n")
        for i, message in enumerate(messages):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for row in rows + after_rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(rows)} rows")


if __name__ == "__main__":
    main()
