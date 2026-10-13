#!/usr/bin/env python3
"""Write src/hash_functions/jh_tables.rs: JH's 42 round constants, in the
bitsliced form `jh.rs` uses.

    python3 scripts/make_jh_tables.py

**A development tool, not a test.** It needs the network once.

The designer generated the constants from the first 256 bits of the
fraction of the square root of two, through a smaller JH round; the
bitsliced implementations carry them already rearranged, 32 bytes a
round. This reads them out of two implementations, fetched at pinned
commits and SHA-256 checked, and requires both to agree on every byte:
the JH code SUPERCOP carries (`crypto_hash/round3jh256/simple`, from the
designer's bitsliced code) and sphlib's `jh.c`, which writes each eight
bytes as a big-endian 64 bit constant.
"""

import hashlib
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "hash_functions", "jh_tables.rs")

SUPERCOP = ("https://raw.githubusercontent.com/floodyberry/supercop/"
            "a351f2c29235512a042d4b6989d241a67e86ad23/crypto_hash/round3jh256/simple/hash.c")
SPHLIB = ("https://raw.githubusercontent.com/pornin/sphlib/"
          "15b6b8d8f3e4a43c58ba102d712fa6b8a3317035/c/jh.c")
DIGESTS = {
    SUPERCOP: "adde096232227e53d9657403b12576b869e5a117e4ba0bfd2a9d5ceda004547b",
    SPHLIB: "b170783396835c430d7d2e546fbf5ddf02ac9eceffe89eba9945e2e126f81298",
}


def fetch(url):
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != DIGESTS[url]:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data.decode("latin-1")


def between(text, start):
    at = text.index(start) + len(start)
    return text[at:text.index("};", at)]


def main():
    supercop = bytes(int(b, 16) for b in
                     re.findall(r"0x([0-9a-fA-F]{1,2})\b", between(fetch(SUPERCOP), "c[42][32]={")))
    sphlib = b"".join(int(w, 16).to_bytes(8, "big") for w in
                      re.findall(r"C64e\(0x([0-9a-fA-F]{16})\)",
                                 between(fetch(SPHLIB), "static const sph_u64 C[] = {")))
    if len(supercop) != 42 * 32 or len(sphlib) != 42 * 32:
        sys.exit(f"found {len(supercop)} and {len(sphlib)} bytes, not 1344")
    if supercop != sphlib:
        sys.exit("SUPERCOP's and sphlib's round constants differ")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("// JH's 42 round constants, bitsliced: each round's 32 bytes as four\n"
                  "// little-endian 64 bit words. Written by scripts/make_jh_tables.py from\n"
                  "// SUPERCOP's JH and sphlib, which agree on every byte; do not edit.\n\n"
                  "pub(crate) const C: [[u64; 4]; 42] = [\n")
        for r in range(42):
            words = [int.from_bytes(supercop[32 * r + 8 * k:32 * r + 8 * k + 8], "little")
                     for k in range(4)]
            out.write("    [" + ", ".join(f"0x{w:016x}" for w in words) + "],\n")
        out.write("];\n")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
