#!/usr/bin/env python3
"""Write the constant tables of the older block ciphers, each read out of
several implementations that must agree on every entry:

  * src/block_ciphers/skipjack_table.rs: Skipjack's F-table, from
    libtomcrypt 1.18.2, Crypto++ 8.9.0, Botan 1.10.17 and Bouncy Castle
    1.77, which are four separate transcriptions of the 256 bytes the
    NSA's specification prints;
  * src/block_ciphers/square_table.rs: Square's S-box, from Crypto++ and
    Botan, whose inverse tables must each be its inverse too;
  * src/block_ciphers/kasumi_table.rs: KASUMI's S7 and S9 and its key
    schedule's eight constants, from libtomcrypt and Botan;
  * src/block_ciphers/lea_table.rs: LEA's eight key schedule constants,
    from Crypto++ and go-krypto, which both store each one with its 35
    left rotations after it - all of which are checked - and which must
    also be the rule the standard gives: the hexadecimal digits after the
    point of the square root of 766965 - "LEA" in decimal ASCII, 76 69
    65 - computed here;
  * src/block_ciphers/simon_table.rs: Simon's five 62-bit sequences z0
    to z4, from inmcm's Python reference, which keeps all five as binary
    literals; Crypto++, which keeps z2, z3 and z4 each as a 64-bit word
    consumed from its low bit - the sequence and its first two bits
    again - in the key expansion of each variant, and must have its
    variant's sequence, the variant named by the round count of the
    function it is in; and jedisct1/rust-lwbc, which keeps z0, z1 and z3
    as binary literals in the variants that use them. Every sequence
    must come from at least two of them, and all must agree;
  * src/block_ciphers/present_table.rs: PRESENT's 4-bit S-box, from
    Nirusu/PRESENT.go, kurtfu/present and OpenTitan's Python PRESENT,
    the first two with an inverse table that must invert it.

    scripts/witness/oldciphers/build.sh /opt/oldciphers
    python3 scripts/make_oldcipher_tables.py

**A development tool, not a test.** It reads the sources the witness
build fetched, and checks each against the build's manifest
(`scripts/witness/oldciphers/oldciphers.sha256`) first, so a table can
only come from the pinned files.
"""

import hashlib
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WITNESS = os.environ.get("OLDCIPHERS_WITNESS", "/opt/oldciphers")
MANIFEST = os.path.join(HERE, "witness", "oldciphers", "oldciphers.sha256")

# Each table: where it is written, its Rust declaration, its length, and
# the array in each source - the file under the witness's src/ and the
# text that opens the initialiser. Tables with the same output are
# written to that one file, in order.
TABLES = [
    {
        "output": "src/block_ciphers/skipjack_table.rs",
        "doc": ["Skipjack's F-table, the specification's 256-byte substitution."],
        "rust": "pub(crate) const F: [u8; 256]",
        "count": 256,
        "sources": [
            ("libtomcrypt/skipjack.c", "static const unsigned char sbox[256] = {"),
            ("cryptopp/skipjack.cpp", "const byte SKIPJACK::Base::fTable[256] = {"),
            ("botan/skipjack.cpp", "static const byte F[256] = {"),
            ("bc/SkipjackEngine.java", "static short ftable[] =\n    { "),
        ],
    },
    {
        "output": "src/block_ciphers/square_table.rs",
        "doc": ["Square's S-box."],
        "rust": "pub(crate) const S: [u8; 256]",
        "count": 256,
        "sources": [
            ("cryptopp/squaretb.cpp", "const byte Square::Enc::Se[256] = {"),
            ("botan/sqr_tab.cpp", "const byte Square::SE[256] = {"),
        ],
        # Each source's inverse table, which must invert the S-box.
        "inverses": [
            ("cryptopp/squaretb.cpp", "const byte Square::Dec::Sd[256] = {"),
            ("botan/sqr_tab.cpp", "const byte Square::SD[256] = {"),
        ],
    },
    {
        "output": "src/block_ciphers/kasumi_table.rs",
        "doc": ["KASUMI's seven-bit S-box, S7."],
        "rust": "pub(crate) const S7: [u8; 128]",
        "count": 128,
        "sources": [
            ("libtomcrypt/kasumi.c", "static const u16 S7[128] = {"),
            ("botan/kasumi.cpp", "const byte KASUMI_SBOX_S7[128] = {"),
        ],
    },
    {
        "output": "src/block_ciphers/kasumi_table.rs",
        "doc": ["KASUMI's nine-bit S-box, S9."],
        "rust": "pub(crate) const S9: [u16; 512]",
        "count": 512,
        "sources": [
            ("libtomcrypt/kasumi.c", "static const u16 S9[512] = {"),
            ("botan/kasumi.cpp", "const u16bit KASUMI_SBOX_S9[512] = {"),
        ],
    },
    {
        "output": "src/block_ciphers/kasumi_table.rs",
        "doc": ["The constants the key schedule XORs into the key words for K'."],
        "rust": "pub(crate) const C: [u16; 8]",
        "count": 8,
        "sources": [
            ("libtomcrypt/kasumi.c", "static const u16 C[8] = {"),
            ("botan/kasumi.cpp", "static const u16bit RC[] = {"),
        ],
    },
    {
        "output": "src/block_ciphers/lea_table.rs",
        "doc": ["LEA's key schedule constants: the square root of 766965, after the",
                "point, in 32-bit words."],
        "rust": "pub(crate) const DELTA: [u32; 8]",
        "count": 8,
        # Each source stores a constant followed by its rotations left by
        # 1 to 35; the first of each 36 is the constant.
        "stride": 36,
        "sources": [
            ("cryptopp/lea.cpp", "const word32 delta[8][36] = {"),
            ("go-krypto/lea/generic_const.go", "var delta = [8][36]uint32{"),
        ],
        "computed": "lea_delta",
    },
    {
        "output": "src/block_ciphers/simon_table.rs",
        "doc": ["Simon's 62-bit constant sequences z0 to z4, consumed from the low",
                "bit, one bit per round key after the key's own words."],
        "rust": "pub(crate) const Z: [u64; 5]",
        "count": 5,
        "reader": "simon_z",
        "sources": [
            ("inmcm/simon.py", None),
            ("cryptopp/simon.cpp", None),
            ("lwbc/simon32.rs", None),
            ("lwbc/simon48.rs", None),
            ("lwbc/simon64.rs", None),
            ("lwbc/simon96.rs", None),
        ],
    },
    {
        "output": "src/block_ciphers/present_table.rs",
        "doc": ["PRESENT's 4-bit S-box."],
        "rust": "pub(crate) const S: [u8; 16]",
        "count": 16,
        "sources": [
            ("presentgo/block.go", "sBox    = []byte{"),
            ("kurtfu/present.c", "static uint8_t const g_sbox[] = {"),
            ("opentitan/Present.py", "Sbox = ["),
        ],
        "inverses": [
            ("presentgo/block.go", "sBoxInv = []byte{"),
            ("kurtfu/present.c", "static uint8_t const g_sbox_inv[] = {"),
        ],
    },
]


def lea_delta():
    """The fractional part of the square root of "LEA" in decimal ASCII,
    766965, its first 256 bits, as eight 32-bit words."""
    whole = math.isqrt(int("".join(str(ord(c)) for c in "LEA")) << 512)
    fraction = whole & ((1 << 256) - 1)
    return [(fraction >> (32 * (7 - i))) & 0xffffffff for i in range(8)]


COMPUTED = {"lea_delta": lea_delta}


def simon_z_cryptopp(text, where):
    """z2, z3 and z4 from Crypto++'s key expansions: each function
    `SIMON64_ExpandKey_3W(word32 key[42], ...)` and the like declares
    `word64 z = W64LIT(0x...)`, and its round count names its variant's
    sequence. A 64-bit constant must be the 62-bit sequence with its own
    first two bits above it, since the sequence has period 62."""
    sequence_of = {42: 2, 44: 3, 68: 2, 69: 3, 72: 4}
    found = {}
    for rounds, value in re.findall(
            r"ExpandKey_\dW\(word(?:32|64) key\[(\d+)\][^{]*\{[^}]*?\bz = W64LIT\(0x([0-9a-fA-F]+)\)",
            text):
        z = int(value, 16)
        low = z & ((1 << 62) - 1)
        if z >> 62 != low & 3:
            sys.exit(f"{where}: {value} is not a 62-bit sequence with its start repeated")
        index = sequence_of[int(rounds)]
        if found.setdefault(index, low) != low:
            sys.exit(f"{where}: two different z{index}")
    if sorted(found) != [2, 3, 4]:
        sys.exit(f"{where}: found the sequences {sorted(found)}, not 2, 3 and 4")
    return found


def simon_z_python(text, where):
    """z0 to z4 from inmcm's simon.py: `zN = 0b...`, 62 digits."""
    found = {int(n): int(bits, 2) for n, bits in re.findall(r"^\s*z(\d) = 0b([01]{62})\s*$", text, re.M)}
    if sorted(found) != [0, 1, 2, 3, 4]:
        sys.exit(f"{where}: found the sequences {sorted(found)}, not z0 to z4")
    return found


def simon_z_lwbc(text, where):
    """The one sequence a lwbc Simon file keeps: `const ZN: u64 = 0b...;`,
    62 digits."""
    found = {int(n): int(bits, 2) for n, bits in re.findall(r"const Z(\d): u64 = 0b([01]{62});", text)}
    if len(found) != 1:
        sys.exit(f"{where}: found the sequences {sorted(found)}, not one")
    return found


READERS = {"simon_z": {"cryptopp/simon.cpp": simon_z_cryptopp, "inmcm/simon.py": simon_z_python,
                       "lwbc/simon32.rs": simon_z_lwbc, "lwbc/simon48.rs": simon_z_lwbc,
                       "lwbc/simon64.rs": simon_z_lwbc, "lwbc/simon96.rs": simon_z_lwbc}}


def strided(values, stride, where):
    """The first of every `stride` values, each group required to be that
    value's rotations left by 0 to stride - 1."""
    out = []
    for group in range(0, len(values), stride):
        first = values[group]
        for r, value in enumerate(values[group:group + stride]):
            if value != ((first << (r % 32)) | (first >> (32 - r % 32))) & 0xffffffff:
                sys.exit(f"{where}: entry {group + r} is not a rotation of {first:#010x}")
        out.append(first)
    return out


def pinned():
    """The manifest: path under src/ -> SHA-256."""
    out = {}
    for line in open(MANIFEST):
        digest, path = line.split()
        out[path] = digest
    return out


def read(path, hashes):
    data = open(os.path.join(WITNESS, "src", path), "rb").read()
    if hashlib.sha256(data).hexdigest() != hashes[path]:
        sys.exit(f"{path} is not the file the manifest pins; rebuild the witness")
    return data.decode()


def array(text, opening, count, where):
    """The `count` numbers of the initialiser that `opening` starts, a C,
    Java or Go one in braces or a Python list in brackets."""
    at = text.index(opening) + len(opening)
    # The initialiser's own closing brace: an array of arrays nests.
    pair = {"[": 1, "]": -1} if opening.endswith("[") else {"{": 1, "}": -1}
    depth, end = 1, at
    while depth:
        depth += pair.get(text[end], 0)
        end += 1
    body = text[at:end - 1]
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    body = re.sub(r"//[^\n]*", " ", body)
    values = [int(v, 0) for v in re.findall(r"0[xX][0-9a-fA-F]+|\d+", body)]
    if len(values) != count:
        sys.exit(f"{where}: {len(values)} entries, not {count}")
    return values


def rust(tables):
    """One output file: its tables, each with the values read."""
    paths = []
    for table, _ in tables:
        paths += [p for p, _ in table["sources"] if p not in paths]
    lines = ["// Written by scripts/make_oldcipher_tables.py from the witness sources"]
    lines += [f"// {path}" for path in paths]
    lines += ["// which agree on every entry; do not edit."]
    for table, values in tables:
        digits, per_line = ((16, 2) if "u64" in table["rust"] else (8, 8) if "u32" in table["rust"]
                            else (4, 8) if "u16" in table["rust"] else (2, 12))
        lines.append("")
        lines += [f"/// {line}" for line in table["doc"]]
        lines.append(f"{table['rust']} = [")
        for i in range(0, len(values), per_line):
            lines.append("    " + " ".join(f"0x{v:0{digits}x}," for v in values[i:i + per_line]))
        lines.append("];")
    return "\n".join(lines) + "\n"


def main():
    hashes = pinned()
    outputs = {}
    for table in TABLES:
        stride = table.get("stride", 1)
        if "reader" in table:
            # Each reader gives the entries its source has; every entry
            # must come from two sources at least, and all must agree.
            readers = READERS[table["reader"]]
            found = [(path, readers[path](read(path, hashes), path)) for path, _ in table["sources"]]
            merged = []
            for i in range(table["count"]):
                values = [(path, entries[i]) for path, entries in found if i in entries]
                if len(values) < 2:
                    sys.exit(f"{table['output']}: entry {i} has {len(values)} source, not two")
                for path, value in values[1:]:
                    if value != values[0][1]:
                        sys.exit(f"{path} disagrees with {values[0][0]} on entry {i}")
                merged.append(values[0][1])
            outputs.setdefault(table["output"], []).append((table, merged))
            print(f"{table['output']}: {table['rust']}, {len(found)} sources agree, "
                  "two or more on every entry")
            continue
        else:
            readings = [array(read(path, hashes), opening, table["count"] * stride, path)
                        for path, opening in table["sources"]]
        if stride > 1:
            readings = [strided(values, stride, path)
                        for values, (path, _) in zip(readings, table["sources"])]
        if "computed" in table and readings[0] != COMPUTED[table["computed"]]():
            sys.exit(f"{table['sources'][0][0]} is not {table['computed']}'s rule")
        for (path, _), values in zip(table["sources"][1:], readings[1:]):
            if values != readings[0]:
                sys.exit(f"{path} disagrees with {table['sources'][0][0]}")
        for path, opening in table.get("inverses", []):
            inverse = array(read(path, hashes), opening, table["count"], path)
            if any(inverse[v] != x for x, v in enumerate(readings[0])):
                sys.exit(f"{path}'s inverse table does not invert the table")
        outputs.setdefault(table["output"], []).append((table, readings[0]))
        print(f"{table['output']}: {table['rust']}, {len(readings)} sources agree")
    for output, tables in outputs.items():
        with open(os.path.join(ROOT, output), "w") as f:
            f.write(rust(tables))


if __name__ == "__main__":
    main()
