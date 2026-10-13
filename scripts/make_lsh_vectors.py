#!/usr/bin/env python3
"""Write vectors/lsh.vec: LSH (KS X 3262) at the six sizes the standard
names and at others, from several implementations each.

    scripts/witness/lsh/build.sh /opt/lshwitness
    python3 scripts/make_lsh_vectors.py

**A development tool, not a test.** `tests/test_lsh.rs` and
`pytests/test_lsh.py` read the file offline.

The witnesses (`scripts/witness/lsh`), each fed its message in pieces of
1, 2, 3 ... bytes:

    lsh256_224, lsh256_256, lsh512_224 ... lsh512_512
                    KISA's reference, Crypto++, go-krypto
    lsh256_8, lsh256_120, lsh512_8, lsh512_200, lsh512_504
                    KISA's reference, Crypto++

Every witness that has a name must agree on every message, or the script
stops. The messages are random bytes at lengths around the 128 and 256
byte blocks - the padding is a 1 bit and zeros, with no length, so a
message one byte short of a block still fits in it - up to 1000, from a
fixed seed, written once each as `msg` rows that the `hash` rows name by
index:

    msg n= data=
    hash name= msg= digest=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "lsh.vec")
WITNESS = os.environ.get("LSH_WITNESS", "/opt/lshwitness")

NAMED = ["lsh256_224", "lsh256_256", "lsh512_224", "lsh512_256", "lsh512_384", "lsh512_512"]
# Lengths the standard allows and does not name: one byte, and lengths
# that are not whole words of the output.
OTHERS = ["lsh256_8", "lsh256_120", "lsh512_8", "lsh512_200", "lsh512_504"]
WITNESSES = {**{name: ["kisa", "cryptopp", "go"] for name in NAMED},
             **{name: ["kisa", "cryptopp"] for name in OTHERS}}
LENGTHS = [0, 1, 2, 3, 31, 32, 33, 63, 64, 65, 127, 128, 129, 191, 255, 256, 257,
           383, 384, 511, 512, 513, 1000]


def ask(witness, requests):
    """The witness's answers to [(name, path)], in order."""
    lines = "".join(f"{name} {path}\n" for name, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out}")
    return out


def main():
    rng = random.Random(0x15A256)
    messages = [rng.randbytes(n) for n in LENGTHS]
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
    rows = []
    for name, who in WITNESSES.items():
        for i, message in enumerate(messages):
            given = answers[(name, i)]
            if sorted(given) != sorted(who) or len(set(given.values())) != 1:
                sys.exit(f"the witnesses disagree on {name} of {len(message)} bytes: {given}")
            digest = given[who[0]]
            if len(digest) != int(name.split("_")[1]) // 4:
                sys.exit(f"{name} gave {len(digest) // 2} bytes")
            rows.append(f"hash name={name} msg={i} digest={digest}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# LSH (KS X 3262). Written by scripts/make_lsh_vectors.py; do not\n"
                  "# edit. KISA's reference and Crypto++ agree on every row, and\n"
                  "# go-krypto on the six sizes the standard names.\n")
        for i, message in enumerate(messages):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(rows)} rows")


if __name__ == "__main__":
    main()
