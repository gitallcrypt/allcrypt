#!/usr/bin/env python3
"""Write vectors/xxhash.vec: XXH32, XXH64, XXH3-64 and XXH3-128, seeded
and with secrets, from several implementations each.

    scripts/witness/xxhash/build.sh /opt/xxhashwitness
    python3 scripts/make_xxhash_vectors.py

**A development tool, not a test.** `tests/test_xxhash.rs` and
`pytests/test_xxhash.py` read the file offline.

The witnesses (`scripts/witness/xxhash`), each fed its message in pieces
of 1, 2, 3 ... bytes (twox-hash takes a secret in one piece):

    xxh32   PHP, the reference C, twox-hash, OneOfOne/xxhash, pierrec/xxHash
    xxh64   PHP, the reference C, twox-hash, OneOfOne/xxhash, cespare/xxhash,
            pierrec/xxHash
    xxh3, xxh128, seeded
            PHP, the reference C, twox-hash, zeebo/xxh3
    xxh3, xxh128, with a secret
            PHP, the reference C, twox-hash

PHP's is the reference code built into PHP; the other five are written
separately. PHP keeps only the first 256 bytes of a longer secret (with
a warning), so it is not asked about the secret of 1000 bytes. Every witness that has a name must agree on every message,
or the script stops; and every one that takes a secret must refuse one
of 135 bytes.

The messages are random bytes from a fixed seed at every length where
one of the four changes path - XXH32's and XXH64's stripes, XXH3's
cases at 0, 1-3, 4-8, 9-16, 17-128, 129-240 and beyond, and the blocks
of 576, 1024, 1088, 1536 and 7488 bytes that the secrets below give -
and two long runs of one byte described rather than written out. The
seeds are 0, 1, the top values at 32 and 64 bits and two others; XXH32
takes those that fit in 32 bits. The secrets are random, of 136 bytes
(the shortest), 137, 192 (the default's length), 200, 256 and 1000.

    msg n= data=  |  msg n= fill= len=
    secret n= data=
    seeded name= msg= seed= value=
    keyed name= msg= secret= value=
    refused name= secret=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "xxhash.vec")
WITNESS = os.environ.get("XXHASH_WITNESS", "/opt/xxhashwitness")

SEEDED = {"xxh32": ["php", "c", "twox", "oneofone", "pierrec"],
          "xxh64": ["php", "c", "twox", "oneofone", "cespare", "pierrec"],
          "xxh3": ["php", "c", "twox", "zeebo"],
          "xxh128": ["php", "c", "twox", "zeebo"]}
KEYED = {"xxh3": ["php", "c", "twox"], "xxh128": ["php", "c", "twox"]}
LENGTHS = [0, 1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 96, 127,
           128, 129, 159, 160, 200, 239, 240, 241, 255, 256, 257, 511, 512, 575, 576, 577,
           1000, 1023, 1024, 1025, 1087, 1088, 1089, 1535, 1536, 1537, 2047, 2048, 2049, 3000,
           4096, 7487, 7488, 7489, 15000]
FILLS = [(0x00, 100_000), (0xff, 65_537)]
SEEDS = [0, 1, 0x9E3779B1, 0xFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
         0x0123456789ABCDEF]
SECRET_LENGTHS = [136, 137, 192, 200, 256, 1000]


def ask(witness, requests):
    """The witness's answers to [(name, key, path)], in order."""
    lines = "".join(f"{name} {key} {path}\n" for name, key, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests):
        sys.exit(f"{witness} answered {len(out)} of {len(requests)}")
    return out


def main():
    rng = random.Random(0x5A5A)
    messages = [rng.randbytes(n) for n in LENGTHS] + \
        [bytes([byte]) * length for byte, length in FILLS]
    secrets = [rng.randbytes(n) for n in SECRET_LENGTHS]
    short = rng.randbytes(135)
    with tempfile.TemporaryDirectory() as tmp:
        def write(name, data):
            path = os.path.join(tmp, name)
            with open(path, "wb") as f:
                f.write(data)
            return path
        paths = [write(f"m{i}", m) for i, m in enumerate(messages)]
        secret_paths = [write(f"s{i}", s) for i, s in enumerate(secrets)]
        short_path = write("short", short)

        requests = {}  # witness -> [(row key, (name, key, path))]
        for name, who in SEEDED.items():
            for seed in SEEDS:
                if name == "xxh32" and seed > 0xFFFFFFFF:
                    continue
                for i, path in enumerate(paths):
                    for w in who:
                        requests.setdefault(w, []).append(
                            (("seeded", name, i, seed), (name, f"seed:{seed:016x}", path)))
        for name, who in KEYED.items():
            for j, secret_path in enumerate(secret_paths):
                for i, path in enumerate(paths):
                    for w in who:
                        # PHP keeps 256 bytes of a longer secret.
                        if w == "php" and SECRET_LENGTHS[j] > 256:
                            continue
                        requests.setdefault(w, []).append(
                            (("keyed", name, i, j), (name, f"secret:{secret_path}", path)))
            for w in who:
                requests.setdefault(w, []).append(
                    (("refused", name), (name, f"secret:{short_path}", paths[0])))
        answers = {}
        for witness, wanted in sorted(requests.items()):
            for (row, _), value in zip(wanted, ask(witness, [r for _, r in wanted])):
                answers.setdefault(row, {})[witness] = value

    rows = []
    for row, given in answers.items():
        values = set(given.values())
        if row[0] == "refused":
            if values != {"error"}:
                sys.exit(f"a 135 byte secret was not refused by all of {row[1]}'s: {given}")
            rows.append(f"refused name={row[1]} secret=short")
            continue
        if len(values) != 1 or "error" in values:
            sys.exit(f"the witnesses disagree on {row}: {given}")
        value = values.pop()
        if row[0] == "seeded":
            _, name, i, seed = row
            rows.append(f"seeded name={name} msg={i} seed={seed:016x} value={value}")
        else:
            _, name, i, j = row
            rows.append(f"keyed name={name} msg={i} secret={j} value={value}")

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# xxHash, as big endian hex. Written by scripts/make_xxhash_vectors.py;\n"
                  "# do not edit. Every witness that has a name agrees on every row: PHP,\n"
                  "# the reference C and twox-hash on all of them, with OneOfOne/xxhash and\n"
                  "# pierrec/xxHash on XXH32 and XXH64, cespare/xxhash on XXH64 and\n"
                  "# zeebo/xxh3 on seeded XXH3 - except that PHP keeps only 256 bytes of\n"
                  "# a secret, so it is not asked about the secret of 1000. A refused row\n"
                  "# is a secret every witness that takes one refuses.\n")
        for i, message in enumerate(messages[:len(LENGTHS)]):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for i, (byte, length) in enumerate(FILLS, len(LENGTHS)):
            out.write(f"msg n={i} fill={byte:02x} len={length}\n")
        for j, secret in enumerate(secrets):
            out.write(f"secret n={j} data={secret.hex()}\n")
        out.write(f"secret n=short data={short.hex()}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(secrets)} secrets, {len(rows)} rows")


if __name__ == "__main__":
    main()
