#!/usr/bin/env python3
"""Write src/hash_functions/snefru_tables.rs: Snefru's sixteen S-boxes.

    python3 scripts/make_snefru_tables.py

**A development tool, not a test.** It needs the network once.

Merkle drew the 16 x 256 words from RAND's book of random digits, so
there is nothing to compute them from; this reads them out of three
implementations, fetched at pinned commits and SHA-256 checked, and
requires all three to agree on every word: RHash's `librhash/snefru.c`,
PHP's `ext/hash/php_hash_snefru_tables.h` and mhash's `lib/snefru.c` (as
vendored by Sembiance/mhash). Two boxes per pass, eight passes, in the
order the three store them.
"""

import hashlib
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "hash_functions", "snefru_tables.rs")

SOURCES = [
    ("RHash", "https://raw.githubusercontent.com/rhash/RHash/"
              "6562de382954d9893442b89b0e8b5c513eea6a88/librhash/snefru.c"),
    ("PHP", "https://raw.githubusercontent.com/php/php-src/php-8.4.21/"
            "ext/hash/php_hash_snefru_tables.h"),
    ("mhash", "https://raw.githubusercontent.com/Sembiance/mhash/"
              "f4f4ed092ac9272829aa40a27a4761efac4d88b7/deps/mhash/lib/snefru.c"),
]
DIGESTS = {
    "RHash": "42354742b1c77637b7a1811d140c1dce37ee9e4ae460dcc5d9387df7b0a8c2cc",
    "PHP": "5db6c74002e439363e58b5f5b8a9339eb72394a75f9c3c994b4d7518a8a163be",
    "mhash": "9075dd696bf9d86f6f050250e7efa7ba84709f0740b9862d01f8bf4a178e8bd0",
}


def fetch(url):
    with urllib.request.urlopen(url) as response:
        return response.read()


def words(text):
    """The table's words: every 32 bit hexadecimal constant from the
    table's opening brace to its closing one."""
    start = text.index("{", re.search(r"(sbox|SBOX|tables)\s*\[", text).end())
    end = text.index("};", start)
    found = [int(w, 16) for w in re.findall(r"0x([0-9a-fA-F]{8})", text[start:end])]
    if len(found) != 16 * 256:
        sys.exit(f"found {len(found)} words, not 4096")
    return found


def main():
    tables = {}
    for name, url in SOURCES:
        data = fetch(url)
        digest = hashlib.sha256(data).hexdigest()
        if DIGESTS[name] != digest:
            sys.exit(f"{url} changed upstream; read it before trusting it")
        tables[name] = words(data.decode("latin-1"))
    first, *rest = tables.values()
    for name, table in tables.items():
        if table != first:
            sys.exit(f"{name}'s S-boxes differ from RHash's")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("// Snefru's sixteen S-boxes, two per pass. Written by\n"
                  "// scripts/make_snefru_tables.py from RHash, PHP and mhash, which agree on\n"
                  "// every word; do not edit.\n\n"
                  "pub(crate) const SBOXES: [[u32; 256]; 16] = [\n")
        for box in range(16):
            out.write("    [\n")
            for row in range(0, 256, 6):
                values = first[256 * box + row:256 * box + min(row + 6, 256)]
                out.write("        " + " ".join(f"0x{v:08x}," for v in values) + "\n")
            out.write("    ],\n")
        out.write("];\n")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
