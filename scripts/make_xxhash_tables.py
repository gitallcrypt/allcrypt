#!/usr/bin/env python3
"""Write src/checksum/xxhash_tables.rs: xxHash's primes and XXH3's default
secret.

    python3 scripts/make_xxhash_tables.py

**A development tool, not a test.** It needs the network once.

None of these can be computed: the primes were picked for their mix of
bits, and the 192 byte secret is a fixed pseudorandom string. So each is
read out of three sources, fetched at pinned commits and SHA-256 checked,
which must agree:

  * the primes PRIME32_1 to PRIME32_5 and PRIME64_1 to PRIME64_5: the
    reference `xxhash.h` (v0.8.3), twox-hash 2.1.5's Rust and
    OneOfOne/xxhash's Go;
  * PRIME_MX1 and PRIME_MX2, which only XXH3 uses: `xxhash.h`, twox-hash
    and the specification, `doc/xxhash_spec.md`, from the same release
    as the header but written separately;
  * the default secret: `xxhash.h`, twox-hash and zeebo/xxh3 1.1.0's Go.
"""

import hashlib
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "checksum", "xxhash_tables.rs")

XXHASH = ("https://raw.githubusercontent.com/Cyan4973/xxHash/"
          "e626a72bc2321cd320e953a0ccf1584cad60f363/")
TWOX = ("https://raw.githubusercontent.com/shepmaster/twox-hash/"
        "0222275b9e2faaa0a09eead8057753609ff891d1/src/")
ONEOFONE = ("https://raw.githubusercontent.com/OneOfOne/xxhash/"
            "73388e8298b5e5a3611e6b62c2fc41b1b108491e/")
ZEEBO = "https://raw.githubusercontent.com/zeebo/xxh3/84cc04fc61771ea2a564c57277a19f83217a84ff/"
SOURCES = {
    "xxhash.h": (XXHASH + "xxhash.h",
                 "17973c0dc49d9854ca26caa191f0e12f7a424b68858d9a78de3860d959d85e4b"),
    "spec": (XXHASH + "doc/xxhash_spec.md",
             "61c47af338b2feefcc7621700ef6b941bcf9b1dd33899c503f68cb797e7ef333"),
    "twox3": (TWOX + "xxhash3.rs",
              "948804e18cb439066f85eec62aebe8a91ced857ff5bbffc454633e235cdeb982"),
    "twox32": (TWOX + "xxhash32.rs",
               "4370cc7dcc5d4c5b13cd3ac40c4816dc920ae83cfb118886c00453d9c7fd18c9"),
    "oneofone": (ONEOFONE + "xxhash.go",
                 "7b2f7e4c75cbc7fa5a18b112028202385dcdcdf297d0e8b10be55236deca6585"),
    "zeebo": (ZEEBO + "consts.go",
              "e9b9760176baaa15546cf1ae9ad9e513e35ba99cd6287379f110796e21d3e45a"),
}

PRIMES32 = [f"PRIME32_{i}" for i in range(1, 6)]
PRIMES64 = [f"PRIME64_{i}" for i in range(1, 6)]
MIXERS = ["PRIME_MX1", "PRIME_MX2"]


def fetch(name):
    url, digest = SOURCES[name]
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data.decode("utf-8")


def constant(text, name, source):
    """The value of `name` in `text`, hexadecimal or decimal, as a C
    #define, a C, Rust or Go constant."""
    pattern = (rf"(?:#define\s+{name}\s+|\b{name}\s*(?::\s*\w+\s*)?(?:\w+\s*)?=\s*)"
               r"(0[xX][0-9a-fA-F]+|\d+)")
    found = {int(value, 0) for value in re.findall(pattern, text)}
    if len(found) != 1:
        sys.exit(f"{source}: {name} is {sorted(found) or 'missing'}")
    return found.pop()


def secret(text, anchor, source, brackets="{}"):
    """The 192 bytes between the first of `brackets` after `anchor` and the
    closing one."""
    start = text.index(brackets[0], text.index(anchor))
    body = re.sub(r"/\*.*?\*/", "", text[start:text.index(brackets[1], start)], flags=re.S)
    values = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})\b", body)]
    if len(values) != 192:
        sys.exit(f"{source}: the secret has {len(values)} bytes, not 192")
    return bytes(values)


def main():
    text = {name: fetch(name) for name in SOURCES}
    # OneOfOne writes the primes as prime32x1 and prime64x1.
    go_name = {**{f"PRIME32_{i}": f"prime32x{i}" for i in range(1, 6)},
               **{f"PRIME64_{i}": f"prime64x{i}" for i in range(1, 6)}}
    values = {}
    for name in PRIMES32 + PRIMES64 + MIXERS:
        readings = {"xxhash.h": constant(text["xxhash.h"], "XXH_" + name
                                         if name not in MIXERS else name, "xxhash.h")}
        twox = "twox32" if name in ("PRIME32_4", "PRIME32_5") else "twox3"
        readings[twox] = constant(text[twox], name, twox)
        if name in MIXERS:
            readings["spec"] = constant(text["spec"], name, "spec")
        else:
            readings["oneofone"] = constant(text["oneofone"], go_name[name], "oneofone")
        if len(set(readings.values())) != 1:
            sys.exit(f"{name}: the sources disagree: {readings}")
        values[name] = readings["xxhash.h"]
    for name in PRIMES32:
        if values[name] >= 1 << 32:
            sys.exit(f"{name} is wider than 32 bits")
    secrets = {"xxhash.h": secret(text["xxhash.h"], "XXH3_kSecret[XXH_SECRET_DEFAULT_SIZE]",
                                  "xxhash.h"),
               "twox3": secret(text["twox3"], "DEFAULT_SECRET_RAW: DefaultSecret", "twox3",
                             "[]"),
               "zeebo": secret(text["zeebo"], "var key = ptr(", "zeebo")}
    if len(set(secrets.values())) != 1:
        sys.exit("the sources disagree on the default secret")
    default = secrets["xxhash.h"]

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("// xxHash's primes and XXH3's default secret. Written by\n"
                  "// scripts/make_xxhash_tables.py from the reference xxhash.h 0.8.3,\n"
                  "// twox-hash 2.1.5, OneOfOne/xxhash, zeebo/xxh3 1.1.0 and the\n"
                  "// specification, three of which agree on each; do not edit.\n\n")
        for name in PRIMES32:
            out.write(f"pub(crate) const {name}: u32 = 0x{values[name]:08x};\n")
        for name in PRIMES64 + MIXERS:
            out.write(f"pub(crate) const {name}: u64 = 0x{values[name]:016x};\n")
        out.write("\n/// XXH3's secret when none is given.\n"
                  "pub(crate) const DEFAULT_SECRET: [u8; 192] = [\n")
        for row in range(0, 192, 12):
            out.write("    " + " ".join(f"0x{b:02x}," for b in default[row:row + 12]) + "\n")
        out.write("];\n")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
