#!/usr/bin/env python3
"""Write the wallet example's Unicode normalization tables
(`examples/products/wallet/unicode_tables.rs`) from the Unicode Character
Database, and its conformance test (`fixtures/wallet/NormalizationTest.zlib`).

    python3 scripts/make_unicode_tables.py --ucd DIR

DIR holds UnicodeData.txt, DerivedNormalizationProps.txt and
NormalizationTest.txt of one version, as published under
https://www.unicode.org/Public/<version>/ucd/ and mirrored in
unicode-org/unicodetools (`unicodetools/data/ucd/<version>/`). The tables
are the data, not a computation: each decomposition as UnicodeData.txt
gives it (one level, compatibility ones tagged), each non-zero canonical
combining class, and Full_Composition_Exclusion's ranges. Hangul
syllables are left to the algorithm in UAX #15 section 3.12.
"""

import argparse
import os
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WALLET = os.path.join(ROOT, "examples", "products", "wallet")
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures", "wallet")


def version(path):
    first = open(path, encoding="utf-8").readline()
    return first.split("-")[-1].replace(".txt", "").strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ucd", required=True)
    args = parser.parse_args()
    data = os.path.join(args.ucd, "UnicodeData.txt")
    props = os.path.join(args.ucd, "DerivedNormalizationProps.txt")
    tests = os.path.join(args.ucd, "NormalizationTest.txt")
    ucd_version = version(props)
    assert version(tests) == ucd_version, "the files are of different versions"

    ccc, decompositions = [], []
    for line in open(data, encoding="utf-8"):
        fields = line.split(";")
        code = int(fields[0], 16)
        if fields[3] != "0":
            ccc.append((code, int(fields[3])))
        mapping = fields[5].strip()
        if mapping:
            compat = mapping.startswith("<")
            if compat:
                mapping = mapping.split(">", 1)[1].strip()
            decompositions.append((code, compat, [int(c, 16) for c in mapping.split()]))

    excluded = []
    for line in open(props, encoding="utf-8"):
        line = line.split("#")[0].strip()
        if not line:
            continue
        codes, prop = [f.strip() for f in line.split(";")[:2]]
        if prop != "Full_Composition_Exclusion":
            continue
        first, _, last = codes.partition("..")
        excluded.append((int(first, 16), int(last or first, 16)))

    out = [f"// Unicode {ucd_version} normalization data, written by",
           "// scripts/make_unicode_tables.py from UnicodeData.txt and",
           "// DerivedNormalizationProps.txt. Not edited by hand.",
           "",
           f"pub const VERSION: &str = \"{ucd_version}\";",
           "",
           "/// Non-zero canonical combining classes, by code point.",
           "pub const CCC: &[(u32, u8)] = &["]
    out += [f"    (0x{c:04X}, {v})," for c, v in ccc]
    out += ["];", "",
            "/// UnicodeData.txt's decompositions, by code point: whether it is a",
            "/// compatibility one, and the mapping, one level deep.",
            "pub const DECOMPOSITIONS: &[(u32, bool, &[u32])] = &["]
    for code, compat, mapping in decompositions:
        body = ", ".join(f"0x{m:04X}" for m in mapping)
        out.append(f"    (0x{code:04X}, {'true' if compat else 'false'}, &[{body}]),")
    out += ["];", "",
            "/// Full_Composition_Exclusion: never the result of composition.",
            "pub const COMPOSITION_EXCLUDED: &[(u32, u32)] = &["]
    out += [f"    (0x{a:04X}, 0x{b:04X})," for a, b in excluded]
    out += ["];", ""]
    with open(os.path.join(WALLET, "unicode_tables.rs"), "w") as f:
        f.write("\n".join(out))

    os.makedirs(FIXTURES, exist_ok=True)
    with open(tests, "rb") as f:
        packed = zlib.compress(f.read(), 9)
    with open(os.path.join(FIXTURES, "NormalizationTest.zlib"), "wb") as f:
        f.write(packed)
    print(f"Unicode {ucd_version}: {len(ccc)} combining classes, {len(decompositions)} "
          f"decompositions, {len(excluded)} exclusion ranges; the test is {len(packed)} bytes")


if __name__ == "__main__":
    main()
