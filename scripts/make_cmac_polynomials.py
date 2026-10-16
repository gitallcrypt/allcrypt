#!/usr/bin/env python3
"""Write src/mac/cmac_polynomials.rs: the field polynomial CMAC doubles
in, for every block size the library's ciphers have from 64 bits up.

    python3 scripts/make_cmac_polynomials.py [--sources /opt/widemac/src]

CMAC multiplies by x in GF(2^n), and the field is fixed by a polynomial
of degree n. SP 800-38B gives two, for 64 and 128 bits. Every wider
block takes the convention of Seroussi's "Table of Low-Weight Binary
Irreducible Polynomials" (HP Labs, 1998): **the irreducible polynomial
of degree n with the fewest terms, and of those the one whose exponents,
read from the top, are smallest** - a trinomial x^n + x^k + 1 with the
least k if there is one, and otherwise the pentanomial
x^n + x^a + x^b + x^c + 1 with the least a, then b, then c. That is the
rule SP 800-38B's two follow, and what Botan, Crypto++ and Bouncy Castle
use.

So nothing is typed. Each polynomial is **computed** from the rule here,
with Ben-Or's irreducibility test (gcd(x^(2^i) - x, f) = 1 for every i
up to n/2), and then **compared** with the tables in three pinned
sources, read out of their text:

  * Botan 3.6.1, src/lib/utils/poly_dbl/poly_dbl.cpp (64 to 1024 bits);
  * Crypto++ 8.9.0, cmac.cpp (64 to 1024, powers of two);
  * Bouncy Castle 1.77, macs/CMac.java (64 to 2048).

Every source's entry for a size must equal the rule's, and every size
written must have at least one source; the sizes only Bouncy Castle has,
160 and 224 bits, are named in the output. scripts/witness/widemac/build.sh
fetches the sources. The test in src/mac/cmac.rs checks each written
polynomial is irreducible again, in Rust.
"""

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "mac", "cmac_polynomials.rs")

#: Every block size, in bits, of a cipher here that is 64 bits or wider:
#: 64 and 128 for most, 160 to 256 for Rijndael, 256 for SHACAL-2,
#: Kalyna and Threefish-256, 512 for Kalyna and Threefish-512, and 1024
#: for Threefish-1024. Simon's and Speck's 32, 48 and 96 bit blocks are
#: left out: no implementation found defines CMAC over them.
SIZES = [64, 128, 160, 192, 224, 256, 512, 1024]


# ------------------------------------------------------------- the rule ---

def _square(p):
    """p^2 over GF(2): bit i moves to bit 2i, so a zero goes between bits."""
    return int("0".join(format(p, "b")), 2)


def _reduce(p, n, low):
    """p mod (x^n + sum(x^e for e in low)), for a sparse modulus."""
    mask = (1 << n) - 1
    while p >> n:
        high = p >> n
        p &= mask
        for e in low:
            p ^= high << e
    return p


def _gcd(a, b):
    while b:
        while a and a.bit_length() >= b.bit_length():
            a ^= b << (a.bit_length() - b.bit_length())
        a, b = b, a
    return a


def irreducible(n, low):
    """Ben-Or's test for x^n + sum(x^e for e in low) over GF(2): f is
    irreducible exactly when gcd(x^(2^i) - x, f) = 1 for i up to n/2, and
    a reducible f usually shows it at a small i."""
    f = (1 << n) | sum(1 << e for e in low)
    p = 2                                       # the polynomial x
    for _ in range(n // 2):
        p = _reduce(_square(p), n, low)
        if _gcd(f, p ^ 2) != 1:
            return False
    return True


def by_rule(n):
    """The exponents below x^n, highest first, ending in 0."""
    for k in range(1, n):
        if irreducible(n, [k, 0]):
            return (k, 0)
    for a in range(3, n):
        for b in range(2, a):
            for c in range(1, b):
                if irreducible(n, [a, b, c, 0]):
                    return (a, b, c, 0)
    raise ValueError(f"no irreducible trinomial or pentanomial of degree {n}")


def low_value(exponents):
    return sum(1 << e for e in exponents)


# ------------------------------------------------------------ the sources ---

def botan(root):
    path = os.path.join(root, "botan", "src", "lib", "utils", "poly_dbl", "poly_dbl.cpp")
    text = open(path).read()
    found = {int(bits): int(value, 16)
             for bits, value in re.findall(r"\bP(\d+)\s*=\s*0x([0-9A-Fa-f]+)", text)}
    if sorted(found) != [64, 128, 192, 256, 512, 1024]:
        sys.exit(f"{path}: expected six polynomials, read {sorted(found)}")
    return found


def cryptopp(root):
    path = os.path.join(root, "cryptopp", "cmac.cpp")
    text = open(path).read()
    # The wide-block switch: `case N:` then `k[i] ^= v;` lines, N in bytes.
    switch = text[text.index("switch (len)"):text.index("default:")]
    found = {}
    for case in re.split(r"\bcase\s+", switch)[1:]:
        length = int(re.match(r"(\d+)\s*:", case).group(1))
        value = 0
        for index, byte in re.findall(r"k\[(\d+)\]\s*\^=\s*(0x[0-9A-Fa-f]+|\d+)", case):
            value |= int(byte, 0) << (8 * (length - 1 - int(index)))
        found[length * 8] = value
    if sorted(found) != [64, 128, 256, 512, 1024]:
        sys.exit(f"{path}: expected five polynomials, read {sorted(found)}")
    return found


def bouncycastle(root):
    path = os.path.join(root, "bc", "core", "src", "main", "java", "org",
                        "bouncycastle", "crypto", "macs", "CMac.java")
    text = open(path).read()
    found = {int(bits): int(value, 16) for bits, value in
             re.findall(r"case\s+(\d+):\s*xor\s*=\s*0x([0-9A-Fa-f]+);", text)}
    if len(found) != 13:
        sys.exit(f"{path}: expected thirteen polynomials, read {sorted(found)}")
    return found


# ---------------------------------------------------------------- output ---

def render(rows):
    lines = [
        "// GENERATED by scripts/make_cmac_polynomials.py - do not edit.",
        "//",
        "// The polynomial CMAC's doubling reduces by, per block size: the",
        "// irreducible polynomial of that degree with the fewest terms, and of",
        "// those the one whose exponents, read from the top, are smallest.",
        "// Computed from that rule and compared with Botan 3.6.1's, Crypto++",
        "// 8.9.0's and Bouncy Castle 1.77's tables; the script says how.",
        "",
        "/// `(block size in bytes, the exponents below the top one, highest",
        "/// first)`. The top term is the block size in bits and is implicit.",
        "pub const POLYNOMIALS: &[(usize, &[u32])] = &[",
    ]
    for bits, exponents, sources in rows:
        lines.append(f"    // x^{bits} + " + " + ".join(
            "1" if e == 0 else ("x" if e == 1 else f"x^{e}") for e in exponents)
            + f"; {', '.join(sources)}")
        lines.append(f"    ({bits // 8}, &[{', '.join(str(e) for e in exponents)}]),")
    lines.append("];")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sources", default="/opt/widemac/src")
    parser.add_argument("--check", action="store_true",
                        help="compare with the file instead of writing it")
    args = parser.parse_args()

    tables = {"Botan": botan(args.sources), "Crypto++": cryptopp(args.sources),
              "Bouncy Castle": bouncycastle(args.sources)}
    # Every entry every source has is checked, including the sizes nothing
    # here uses, so a source that disagrees with the rule anywhere is seen.
    for name, table in tables.items():
        for bits, value in sorted(table.items()):
            ours = low_value(by_rule(bits))
            if ours != value:
                sys.exit(f"{name} gives {value:#x} for {bits} bits; the rule gives {ours:#x}")

    rows = []
    for bits in SIZES:
        exponents = by_rule(bits)
        sources = [name for name, table in tables.items() if bits in table]
        if not sources:
            sys.exit(f"no source has a polynomial for {bits} bits")
        rows.append((bits, exponents, sources))
        print(f"{bits:5} bits: {low_value(exponents):#x}  ({', '.join(sources)})")

    text = render(rows)
    if args.check:
        if open(OUTPUT).read() != text:
            sys.exit(f"{OUTPUT} differs from what the rule and the sources give")
        print(f"{OUTPUT} is current")
        return
    with open(OUTPUT, "w") as handle:
        handle.write(text)
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
