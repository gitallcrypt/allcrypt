#!/usr/bin/env python3
"""Write src/hash_functions/lsh_tables.rs: the first step's eight step
constants of LSH-256 and LSH-512.

    python3 scripts/make_lsh_tables.py

**A development tool, not a test.** It needs the network once.

The standard prints all the step constants, and says how each step's
follow from the step before's: the words plus themselves rotated left by
eight. This reads the whole tables out of two implementations, fetched
at pinned commits and SHA-256 checked - KISA's reference C (`lsh256.c`
and `lsh512.c`, from the distribution as noloader/cryptopp-test keeps
it) and Crypto++ 8.9.0's `lsh256.cpp` and `lsh512.cpp` - requires them
to agree on every word and every row after the first to follow from the
one before, and writes the first row only; `lsh.rs` generates the rest.
"""

import hashlib
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "hash_functions", "lsh_tables.rs")

KISA = ("https://raw.githubusercontent.com/noloader/cryptopp-test/"
        "dea05da60fec57ba3ca72d9ac95d405e66f47f0b/lsh/source/c/no_arch/src/")
CRYPTOPP = "https://raw.githubusercontent.com/weidai11/cryptopp/CRYPTOPP_8_9_0/"
SOURCES = {
    # (width, url, table name, sha256)
    "kisa256": (32, KISA + "lsh256.c", "g_StepConstants",
               "97f3bf9bc5c39bfdad448d8cc132044dbc593d69a1415dd5de4aad2e034545f3"),
    "kisa512": (64, KISA + "lsh512.c", "g_StepConstants",
               "1c281ad0da50fb4732a2b72d3e389bfc233b148ffe9f1b52eaa87cd56ccbaf50"),
    "cryptopp256": (32, CRYPTOPP + "lsh256.cpp", "LSH256_StepConstants",
                   "495252ce164edc27c10937ca54320be97ba0bc0a278022f41abdecce30208ce2"),
    "cryptopp512": (64, CRYPTOPP + "lsh512.cpp", "LSH512_StepConstants",
                   "be2a5fd2c36c84e58c2fe13f7c9c0df1bdf1708bc1accfc7fc0fa313e7d77a1a"),
}
STEPS = {32: 26, 64: 28}


def fetch(url, digest):
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data.decode("latin-1")


def table(text, name, width):
    start = text.index("{", re.search(rf"\b{name}\s*\[[^\]]*\]\s*=", text).end() - 1)
    words = [int(w, 16) for w in
             re.findall(r"0x([0-9a-fA-F]+)", text[start:text.index("};", start)])]
    if len(words) != 8 * STEPS[width]:
        sys.exit(f"{name}: {len(words)} words, not {8 * STEPS[width]}")
    mask = (1 << width) - 1
    for i in range(8, len(words)):
        prev = words[i - 8]
        if words[i] != (((prev << 8) | (prev >> (width - 8))) + prev) & mask:
            sys.exit(f"{name}: word {i} does not follow from the step before")
    return words


def main():
    tables = {key: table(fetch(url, digest), name, width)
              for key, (width, url, name, digest) in SOURCES.items()}
    for width in (32, 64):
        if tables[f"kisa{width * 8}"] != tables[f"cryptopp{width * 8}"]:
            sys.exit(f"KISA's and Crypto++'s LSH-{width * 8} constants differ")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("// LSH's first-step constants; every later step's follow from them.\n"
                  "// Written by scripts/make_lsh_tables.py from KISA's reference and\n"
                  "// Crypto++ 8.9.0, which agree on every step; do not edit.\n")
        for width, ty in ((32, "u32"), (64, "u64")):
            words = tables[f"kisa{width * 8}"][:8]
            digits = width // 4
            out.write(f"\npub(crate) const SC0_{width * 8}: [{ty}; 8] = [\n")
            for row in range(0, 8, 4):
                out.write("    " + " ".join(f"0x{w:0{digits}x}," for w in words[row:row + 4])
                          + "\n")
            out.write("];\n")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
