#!/usr/bin/env python3
"""Write vectors/tiger_haval_snefru.vec: Tiger, Tiger2, HAVAL and Snefru,
every name the catalogue gives them, from two to four implementations
each.

    scripts/witness/oldhashes/build.sh /opt/oldhashes
    python3 scripts/make_tiger_haval_snefru_vectors.py

**A development tool, not a test.** `tests/test_tiger_haval_snefru.rs`
and `pytests/test_tiger_haval_snefru.py` read the file offline.

The witnesses (`scripts/witness/oldhashes`), each fed its message in
pieces of 1, 2, 3 ... bytes:

    tiger                       PHP, sphlib, RHash, Botan 1.10.17
    tiger128_3 ... tiger192_4   PHP, Botan 1.10.17
    tiger192_5, tiger160_6      Botan 1.10.17
    tiger2                      sphlib, RHash
    haval128_3 ... haval256_5   PHP, sphlib, mhash
    snefru256                   PHP, RHash, mhash
    snefru128                   RHash, mhash

Every witness that has a name must agree on every message, or the
script stops. mhash's Tiger is not among them: it writes each 64 bit
word of the digest big endian, which the script checks and then leaves
out (pitfalls 7zzzd). The messages are lengths around each hash's block
and padding boundaries - Tiger's 64 byte block with its 56 byte limit,
HAVAL's 128 byte block with its 118 byte one, Snefru-256's 32 data bytes
per block and Snefru-128's 48 - up to 1000, the bytes from a fixed seed,
written once each as `msg` rows that the `hash` rows name by index:

    msg n= data=
    hash name= msg= digest=

and, for Snefru's length block past 2^32 bits, the digest RHash and
mhash give when told they have taken `bytes` without hashing anything,
which `snefru.rs`'s own tests reproduce:

    length name= bytes= digest=
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "tiger_haval_snefru.vec")
WITNESS = os.environ.get("OLDHASHES_WITNESS", "/opt/oldhashes")

TIGERS = ["tiger128_3", "tiger160_3", "tiger128_4", "tiger160_4", "tiger192_4"]
HAVALS = [f"haval{bits}_{passes}" for passes in (3, 4, 5) for bits in (128, 160, 192, 224, 256)]
WITNESSES = {"tiger": ["php", "sph", "rhash", "botan"], "tiger2": ["sph", "rhash"],
             **{name: ["php", "botan"] for name in TIGERS},
             **{name: ["php", "sph", "mhash"] for name in HAVALS},
             "snefru256": ["php", "rhash", "mhash"], "snefru128": ["rhash", "mhash"],
             # Not in the catalogue, but reachable by name: Tiger at five
             # and six passes, where the loop after the third runs more
             # than once. Botan is the only witness that takes them.
             "tiger192_5": ["botan"], "tiger160_6": ["botan"]}
# Whole numbers of blocks at both lengths (96 bytes), from 2^32 bits up,
# the last past 2^64 bits, which wraps.
LONG = [3 * 2**30, 96 * 0x123456789, 96 * (2**56 + 1)]
LENGTHS = [0, 1, 2, 3, 31, 32, 33, 47, 48, 49, 55, 56, 57, 63, 64, 65, 95, 96, 97,
           117, 118, 119, 127, 128, 129, 191, 192, 255, 256, 1000]


def ask(witness, requests):
    """The witness's answers to [(name, path)], in order."""
    command = (["php", os.path.join(WITNESS, "driver.php")] if witness == "php"
               else [os.path.join(WITNESS, f"{witness}-witness")])
    # PHP and Botan name Tiger by its length and passes alone.
    spell = (lambda name: "tiger192_3" if name == "tiger" else name) \
        if witness in ("php", "botan") else (lambda name: name)
    lines = "".join(f"{spell(name)} {path}\n" for name, path in requests)
    out = subprocess.run(command, input=lines, capture_output=True, text=True,
                         check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out}")
    return out


def main():
    rng = random.Random(0x7193E5)
    messages = [rng.randbytes(n) for n in LENGTHS]
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, message in enumerate(messages):
            paths.append(os.path.join(tmp, f"m{i}"))
            with open(paths[-1], "wb") as f:
                f.write(message)
        answers = {}
        for witness in ["php", "sph", "rhash", "mhash", "botan"]:
            requests = [(name, path) for name, who in WITNESSES.items() if witness in who
                        for path in paths]
            for (name, path), digest in zip(requests, ask(witness, requests)):
                answers.setdefault((name, paths.index(path)), {})[witness] = digest
        # mhash's Tiger writes each 64 bit word big endian; it must be the
        # others' digest in that order, and is otherwise left out.
        for i, digest in enumerate(ask("mhash", [("tiger", path) for path in paths])):
            words = [bytes.fromhex(digest)[j:j + 8][::-1] for j in range(0, 24, 8)]
            if b"".join(words).hex() != answers[("tiger", i)]["sph"]:
                sys.exit(f"mhash's Tiger of {LENGTHS[i]} bytes is not the others' word-swapped")
        # Snefru's length block past 2^32 bits, which no message here
        # reaches: RHash and mhash told they have taken that many bytes
        # without hashing them, and finishing.
        requests = [(f"snefru{bits}_length_{n}", paths[0]) for bits in (128, 256)
                    for n in LONG]
        long_rows = []
        for (name, _), digest, other in zip(requests, ask("rhash", requests),
                                            ask("mhash", requests)):
            if digest != other:
                sys.exit(f"RHash and mhash disagree on {name}")
            long_rows.append((name, digest))
    rows = []
    for name, who in WITNESSES.items():
        for i in range(len(messages)):
            given = answers[(name, i)]
            if sorted(given) != sorted(who) or len(set(given.values())) != 1:
                sys.exit(f"the witnesses disagree on {name} of {LENGTHS[i]} bytes: {given}")
            rows.append(f"hash name={name} msg={i} digest={given[who[0]]}")
    for request, digest in long_rows:
        name, n = request.split("_length_")
        rows.append(f"length name={name} bytes={n} digest={digest}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# Tiger, Tiger2, HAVAL and Snefru. Written by\n"
                  "# scripts/make_tiger_haval_snefru_vectors.py; do not edit. Every\n"
                  "# witness that has a name agrees on every row: PHP, sphlib, RHash and\n"
                  "# Botan on tiger; PHP and Botan on Tiger's other lengths and pass\n"
                  "# counts; sphlib and RHash on tiger2; PHP, sphlib and mhash on HAVAL;\n"
                  "# PHP, RHash and mhash on snefru256; RHash and mhash on snefru128;\n"
                  "# Botan alone on tiger192_5 and tiger160_6. A length row is Snefru\n"
                  "# with nothing hashed but told it has taken that many bytes, where\n"
                  "# RHash and mhash agree.\n")
        for i, message in enumerate(messages):
            out.write(f"msg n={i} data={message.hex() or '-'}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(rows)} rows")


if __name__ == "__main__":
    main()
