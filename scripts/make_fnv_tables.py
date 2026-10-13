#!/usr/bin/env python3
"""Write src/checksum/fnv_tables.rs: the FNV primes, at 32 to 1024 bits.

    python3 scripts/make_fnv_tables.py

**A development tool, not a test.** It needs the network once.

An FNV prime is 256^t + 2^8 + b, with t = floor((5 + n) / 12) for n
bits, and b the smallest byte with four or five one bits for which the
number is prime and, modulo 2^40 - 2^24 - 1, above 2^24 + 2^8 + 2^7.
This computes b by that rule - primality by Miller-Rabin with 64 bases
from a fixed seed - and requires the primes it gives to be the ones
three implementations carry, fetched at pinned commits and SHA-256
checked: Landon Curt Noll's C (`hash_32.c`, `hash_64.c`), fnvhash's
libfnv (`fnv128mp.c` to `fnv1024mp.c`) and hugoalh's fnv-es
(`base.ts`), which has all six. It writes t and b; `checksum.rs` builds
the primes, and the offset bases are hashed with FNV-0 there.
"""

import hashlib
import os
import random
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "checksum", "fnv_tables.rs")

NOLL = "https://raw.githubusercontent.com/lcn2/fnv/6f5d7fa29f92987311223e71ecf8b13f7c5551f2/"
LIBFNV = ("https://raw.githubusercontent.com/fnvhash/libfnv/"
          "c8d4fbe1138b93f6413557f24b346111f67081f5/libfnv/")
FNVES = ("https://raw.githubusercontent.com/hugoalh/fnv-es/"
         "93430810c7f1d6f060d7bc20bd589e7dc9d5fd08/")
SOURCES = {
    "hash_32.c": (NOLL, "432988d0219bef510b234b4cec16d249b45273a89adfcfce08a1a3924c356723"),
    "hash_64.c": (NOLL, "f31f66d24a84766667c9779f4907acc2821b37335216a6bd53e383471a648371"),
    "fnv128mp.c": (LIBFNV, "d51789a6326ad75c00197c2720f0285de4e9d9253229b5ec0a628b40eda55223"),
    "fnv256mp.c": (LIBFNV, "e3df1e95a79b6866b186b2235da9daa454d83b73aea0868c430356c71642f0c4"),
    "fnv512mp.c": (LIBFNV, "22083bacf14ef9b243f8604403d4fb249da9ebeaff2d940da752adc81b1df82e"),
    "fnv1024mp.c": (LIBFNV, "ed57928b05067aaf8b2b5ab25afcb8de529ff2b3179ed3865bebe778557cb9ce"),
    "base.ts": (FNVES, "8b68aa003798ad88068cc0d00e355aa303abc7569ff2f3172e7751e1ef1c978a"),
}
SIZES = [32, 64, 128, 256, 512, 1024]


def fetch(name):
    base, digest = SOURCES[name]
    with urllib.request.urlopen(base + name) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{name} changed upstream; read it before trusting it")
    return data.decode("utf-8")


def is_prime(n, rng):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(64):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def by_rule(bits):
    """(t, b) for an FNV prime of `bits` bits, by the rule."""
    rng = random.Random(0xF1F)
    t = (5 + bits) // 12
    for b in range(1, 256):
        p = 256 ** t + 2 ** 8 + b
        if (bin(b).count("1") in (4, 5) and p % (2 ** 40 - 2 ** 24 - 1) > 2 ** 24 + 2 ** 8 + 2 ** 7
                and is_prime(p, rng)):
            return t, b
    sys.exit(f"no FNV prime at {bits} bits")


def carried():
    """{bits: [primes]} as the three implementations write them."""
    primes = {bits: [] for bits in SIZES}
    for bits in (32, 64):
        text = fetch(f"hash_{bits}.c")
        primes[bits].append(int(re.search(rf"#define FNV_{bits}_PRIME \(\(Fnv{bits}_t\)"
                                          r"(0x[0-9a-fA-F]+)", text).group(1), 16))
    for bits in (128, 256, 512, 1024):
        text = fetch(f"fnv{bits}mp.c")
        primes[bits].append(int(re.search(rf"fnv{bits}_prime,\s*\"(\d+)\"", text).group(1)))
    text = fetch("base.ts")
    for bits in SIZES:
        block = re.search(rf"\[{bits},\s*{{(.*?)}}", text, re.S).group(1)
        primes[bits].append(int(re.search(r"prime:\s*([\d_]+)n", block).group(1)
                                .replace("_", "")))
    return primes


def main():
    primes = carried()
    rows = []
    for bits in SIZES:
        t, b = by_rule(bits)
        p = 256 ** t + 2 ** 8 + b
        # Noll's or libfnv's, and fnv-es's.
        if len(primes[bits]) != 2 or any(q != p for q in primes[bits]):
            sys.exit(f"the {bits} bit prime by the rule is not the one carried: {primes[bits]}")
        rows.append((bits, 8 * t, b))
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("// The FNV primes, 2^TOP + 2^8 + LOW, for each size in bits.\n"
                  "// Written by scripts/make_fnv_tables.py, which finds them by the\n"
                  "// rule that defines them and requires Landon Curt Noll's C, libfnv\n"
                  "// and fnv-es to carry the same; do not edit.\n\n"
                  "/// (bits, TOP, LOW).\n"
                  f"pub(crate) const PRIMES: [(usize, u32, u8); {len(rows)}] = [\n")
        for bits, top, low in rows:
            out.write(f"    ({bits}, {top}, 0x{low:02x}),\n")
        out.write("];\n")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
