#!/usr/bin/env python3
"""Write src/hash_functions/skein_tables.rs: Threefish's rotation
distances, for each of its three widths.

    python3 scripts/make_skein_tables.py

**A development tool, not a test.** It needs the network once.

The Skein team chose the distances by search, so there is nothing to
compute them from; this reads them out of two places, fetched at pinned
commits and SHA-256 checked, and requires both to agree on every one:
the team's own `skein.h` as SUPERCOP carries it (its `R_256_d_j`,
`R_512_d_j` and `R1024_d_j`), and Bouncy Castle's `ThreefishEngine.java`
(its `ROTATION_d_j` in each of the three cipher classes).
"""

import hashlib
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "hash_functions", "skein_tables.rs")

SKEIN_H = ("https://raw.githubusercontent.com/floodyberry/supercop/"
           "a351f2c29235512a042d4b6989d241a67e86ad23/crypto_hash/skein512512/opt/skein.h")
THREEFISH = ("https://raw.githubusercontent.com/bcgit/bc-java/"
             "47dc38fa0e7e4ad000f37f66474788d74dce8c93/core/src/main/java/"
             "org/bouncycastle/crypto/engines/ThreefishEngine.java")
DIGESTS = {
    SKEIN_H: "2ccbb3afccc7d1b5f71824f87a014720964f9782472fc803696f53e30c4268fe",
    THREEFISH: "dbab9b57d49f842ed85c06b3c91bd3fd73cb42982a9c602b532161a71b8de7ee",
}
WIDTHS = {"R256": ("R_256", 2), "R512": ("R_512", 4), "R1024": ("R1024", 8)}


def fetch(url):
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != DIGESTS[url]:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data.decode("latin-1")


def from_skein_h(text):
    found = {f"{m[0]}_{m[1]}_{m[2]}": int(m[3])
             for m in re.findall(r"\b(R_256|R_512|R1024)_(\d)_(\d)\s*=\s*(\d+)", text)}
    return {name: [[found[f"{prefix}_{d}_{j}"] for j in range(pairs)] for d in range(8)]
            for name, (prefix, pairs) in WIDTHS.items()}


def from_bouncy_castle(text):
    """Each cipher class's ROTATION_d_j, in the order the classes appear:
    256, 512, 1024."""
    tables = {}
    for name, cls in [("R256", "Threefish256Cipher"), ("R512", "Threefish512Cipher"),
                      ("R1024", "Threefish1024Cipher")]:
        body = text[text.index(f"class {cls}"):]
        nxt = re.search(r"\n    private static final class ", body[1:])
        body = body[:nxt.start() + 1] if nxt else body
        found = {(int(d), int(j)): int(v)
                 for d, j, v in re.findall(r"ROTATION_(\d)_(\d)\s*=\s*(\d+)", body)}
        pairs = WIDTHS[name][1]
        tables[name] = [[found[(d, j)] for j in range(pairs)] for d in range(8)]
    return tables


def main():
    team = from_skein_h(fetch(SKEIN_H))
    bc = from_bouncy_castle(fetch(THREEFISH))
    if team != bc:
        sys.exit("the Skein team's and Bouncy Castle's rotation distances differ")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("// Threefish's rotation distances: [round mod 8][pair]. Written by\n"
                  "// scripts/make_skein_tables.py from the Skein team's skein.h and Bouncy\n"
                  "// Castle's ThreefishEngine, which agree on every one; do not edit.\n")
        for name, (_, pairs) in WIDTHS.items():
            out.write(f"\npub(crate) const {name}: [[u32; {pairs}]; 8] = [\n")
            for row in team[name]:
                out.write("    [" + ", ".join(str(v) for v in row) + "],\n")
            out.write("];\n")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
