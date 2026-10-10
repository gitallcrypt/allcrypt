#!/usr/bin/env python3
"""Write vectors/kalyna.vec: Kalyna (DSTU 7624:2014) known answers for
all five variants.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/kalyna/build.sh /opt/kalyna
    python3 scripts/make_kalyna_vectors.py

**A development tool, not a test.** It needs both witnesses built (the
second fetches the reference implementation once and compiles it);
`tests/test_kalyna.rs` reads `vectors/kalyna.vec` offline.

Two implementations that share no code: the reference implementation by
the cipher's authors (Roman-Oliynykov/Kalyna-reference), driven through
`scripts/witness/kalyna/driver.c`, and Bouncy Castle 1.77's
`DSTU7624Engine`. In order:

1. Their S-boxes must be identical; the four go in the file as `sbox`
   rows, which `src/block_ciphers/kalyna.rs`'s copy is tested against.
2. The standard's ten examples, five encryptions and five decryptions,
   are read out of the reference's `main.c`, where they are written as
   little-endian 64-bit words; both witnesses must reproduce them.
3. Then, for each variant, rows where the two agree: the all-zero and
   all-one corners, the counting key and block, and keys and blocks from
   a seeded generator so the file is reproducible.

A disagreement anywhere stops the script. Row formats, hex fields:

    sbox index=<0..3> table=<256 bytes>
    kalyna block=<bytes> key= pt= ct= source=<standard|both>
"""

import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "kalyna.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
REF = os.environ.get("KALYNA_WITNESS", "/opt/kalyna")
VARIANTS = [(16, 16), (16, 32), (32, 32), (32, 64), (64, 64)]


def reference(block, rows, decrypt=False):
    stdin = "".join(f"{k.hex()} {d.hex()}\n" for k, d in rows)
    out = subprocess.run([f"{REF}/kalyna-witness", str(8 * block), "dec" if decrypt else "enc"],
                         input=stdin, check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(rows)]
    return checked("the reference", out)


def bouncycastle(block, rows):
    stdin = "".join(f"{k.hex()} {d.hex()}\n" for k, d in rows)
    out = subprocess.run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness",
                          f"kalyna-{8 * block}"], input=stdin, check=True,
                         capture_output=True, text=True).stdout.split("\n")[:len(rows)]
    return checked("Bouncy Castle", out)


def checked(who, out):
    for line in out:
        if line.startswith("error"):
            sys.exit(f"{who} refused a row: {line}")
    return [bytes.fromhex(line) for line in out]


def both(block, rows):
    a, b = reference(block, rows), bouncycastle(block, rows)
    for (k, p), x, y in zip(rows, a, b):
        if x != y:
            sys.exit(f"the witnesses disagree: block {block} key {k.hex()} pt {p.hex()}: "
                     f"{x.hex()} != {y.hex()}")
    return a


def sboxes():
    ref = subprocess.run([f"{REF}/kalyna-witness", "sboxes"], check=True,
                         capture_output=True, text=True).stdout.split()
    bc = subprocess.run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness", "kalyna-sboxes"],
                        check=True, capture_output=True, text=True).stdout.split()
    if ref != bc or len(ref) != 4:
        sys.exit("the witnesses' S-boxes differ")
    return [bytes.fromhex(t) for t in ref]


def standard_examples():
    """(block, key, input, output, decrypt) from the reference's main.c."""
    text = open(os.path.join(REF, "main.c")).read()
    arrays = {}
    for name, body in re.findall(r"uint64_t (\w+)\[\d+\] = \{([^}]*)\}", text):
        words = re.findall(r"0x([0-9a-fA-F]{16})ULL", body)
        arrays[name] = b"".join(int(w, 16).to_bytes(8, "little") for w in words)
    out = []
    for tag in ("22", "24", "44", "48", "88"):
        out.append((arrays[f"key{tag}_e"], arrays[f"pt{tag}_e"], arrays[f"expect{tag}_e"], False))
        out.append((arrays[f"key{tag}_d"], arrays[f"ct{tag}_d"], arrays[f"expect{tag}_d"], True))
    if len(out) != 10:
        sys.exit(f"expected ten examples in main.c, found {len(out)}")
    return out


def main():
    rows = [f"sbox index={i} table={t.hex()}" for i, t in enumerate(sboxes())]

    for key, data, want, decrypt in standard_examples():
        block = len(data)
        got_ref = reference(block, [(key, data)], decrypt)[0]
        if got_ref != want:
            sys.exit(f"the reference misses its own example: {key.hex()}")
        if decrypt:
            # Bouncy Castle's driver encrypts; the example's plaintext
            # must encrypt back to its ciphertext.
            if bouncycastle(block, [(key, want)])[0] != data:
                sys.exit(f"Bouncy Castle misses a decryption example: {key.hex()}")
            pt, ct = want, data
        else:
            if bouncycastle(block, [(key, data)])[0] != want:
                sys.exit(f"Bouncy Castle misses an encryption example: {key.hex()}")
            pt, ct = data, want
        rows.append(f"kalyna block={block} key={key.hex()} pt={pt.hex()} ct={ct.hex()} "
                    f"source=standard")

    rng = random.Random(0x4B4C59)
    for block, klen in VARIANTS:
        pairs = [(bytes(klen), bytes(block)), (b"\xff" * klen, b"\xff" * block),
                 (bytes(range(klen)), bytes(range(block)))]
        pairs += [(rng.randbytes(klen), rng.randbytes(block)) for _ in range(12)]
        for (k, p), c in zip(pairs, both(block, pairs)):
            rows.append(f"kalyna block={block} key={k.hex()} pt={p.hex()} ct={c.hex()} source=both")

    with open(OUTPUT, "w") as f:
        f.write("# Kalyna (DSTU 7624:2014). Written by scripts/make_kalyna_vectors.py;\n"
                "# do not edit. The S-boxes and every row are the reference\n"
                "# implementation and Bouncy Castle 1.77's DSTU7624Engine in\n"
                "# agreement; source=standard rows are the standard's own examples.\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
