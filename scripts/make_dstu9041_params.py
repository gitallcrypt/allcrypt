#!/usr/bin/env python3
"""Write src/ec/dstu9041_params.rs: DSTU 9041:2020's curves E256/1 and
E512/1, from two independent sources that must agree.

    scripts/witness/dstu9041/build.sh /opt/dstu9041
    python3 scripts/make_dstu9041_params.py

**A development tool, not a test.** It reads the two witnesses' sources,
which build.sh fetched and checked against their SHA-256: uacrypt's
`hazmat/dstu9041/` (the modulus as 64-bit limbs, `a` and `d` as the
bytes their constructors set, `n` and the base point as byte arrays,
`l_max(p)` and `l_H` as constants of its message modules) and li0ard's
`src/dstu9041/` (every curve value a BigInt literal, the lengths in its
scheme's switch). For each curve the two must give the same `p`, `a`,
`d`, `n`, base point, `l_max(p)` and `l_H`, or the script stops; the values are written
from what they agree on, nothing typed. `src/ec/dstu9041.rs` checks
each curve's base point is on it and of order `n` and that `p` is 5
modulo 8.

These are the first curve of each of the standard's Tables В.1 and В.3,
the ones its worked examples Г.1 and Г.3 use, and the only ones both
implementations carry.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "ec", "dstu9041_params.rs")
SRC = os.path.join(os.environ.get("DSTU9041_WITNESS", "/opt/dstu9041"), "src")


def read(path):
    with open(os.path.join(SRC, path), encoding="utf-8") as f:
        return f.read()


def byte_array(text, name):
    m = re.search(r"const %s: \[u8; \d+\] = \[([^\]]*)\]" % name, text)
    if not m:
        sys.exit(f"uacrypt: no {name}")
    return int("".join(re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1))), 16)


def set_bytes(text, function, width):
    """The value a uacrypt constructor builds by setting bytes of a
    zeroed big-endian array."""
    m = re.search(r"fn %s\(\) -> FieldElement \{(.*?)\n\}" % function, text, re.S)
    if not m:
        sys.exit(f"uacrypt: no {function}")
    value = bytearray(width)
    for index, byte in re.findall(r"bytes\[(\d+)\] = (0x[0-9A-Fa-f]+|\d+);", m.group(1)):
        value[int(index)] = int(byte, 0)
    return int.from_bytes(value, "big")


def uacrypt(bits):
    fp = read(f"uacrypt/hazmat/dstu9041/fp{bits}.rs")
    curve = read(f"uacrypt/hazmat/dstu9041/curve{bits}.rs")
    m = re.search(r"const P_LIMBS: \[u64; \d+\] = \[([^\]]*)\]", fp)
    limbs = [int(x.replace("_", ""), 16) for x in re.findall(r"0x([0-9A-Fa-f_]+)", m.group(1))]
    p = sum(limb << (64 * i) for i, limb in enumerate(limbs))
    message = read(f"uacrypt/hazmat/dstu9041/message{'' if bits == 256 else bits}.rs")
    l_max = int(re.search(r"pub const L_MAX_P: usize = (\d+);", message).group(1))
    l_h = 8 * int(re.search(r"const L_H_BYTES: usize = (\d+);", message).group(1))
    return {"l_max": l_max, "l_h": l_h,
            "p": p, "a": set_bytes(curve, "curve_a", bits // 8),
            "d": set_bytes(curve, "curve_d", bits // 8), "n": byte_array(curve, "ORDER_N"),
            "gx": byte_array(curve, "BASE_X"), "gy": byte_array(curve, "BASE_Y")}


def li0ard(bits):
    text = read("li0ard/src/dstu9041/curve.ts")
    m = re.search(r"export const curve%d = dstu9041Curve\(\{(.*?)\}\);" % bits, text, re.S)
    if not m:
        sys.exit(f"li0ard: no curve{bits}")
    fields = {k: int(v, 16) for k, v in re.findall(r"(\w+): 0x([0-9A-Fa-f]+)n", m.group(1))}
    fields.update({k: int(v) for k, v in re.findall(r"(\w+): (\d+)n", m.group(1))})
    scheme = read("li0ard/src/dstu9041/index.ts")
    m = re.search(r"case %d:(.*?)break;" % bits, scheme, re.S)
    l_max = int(re.search(r"MAX_LENGTH = (\d+);", m.group(1)).group(1))
    l_h = 8 * int(re.search(r"HASH_LENGTH_BYTES = (\d+);", m.group(1)).group(1))
    return {"l_max": l_max, "l_h": l_h,
            "p": fields["p"], "a": fields["a"], "d": fields["d"], "n": fields["n"],
            "gx": fields["Gx"], "gy": fields["Gy"]}


def main():
    curves = []
    for bits in (256, 512):
        u, l = uacrypt(bits), li0ard(bits)
        for k in u:
            if u[k] != l[k]:
                sys.exit(f"E{bits}/1: the two disagree on {k}: {u[k]:x} != {l[k]:x}")
        if u["a"] != 2:
            sys.exit(f"E{bits}/1: a is {u['a']}, and the standard fixes it at 2")
        curves.append((bits, u))
    with open(OUTPUT, "w") as f:
        f.write("// DSTU 9041:2020's curves E256/1 and E512/1. Written by\n"
                "// scripts/make_dstu9041_params.py from uacrypt's hazmat/dstu9041 and\n"
                "// li0ard's dstu9041/curve.ts, which agree on every value; do not edit.\n\n"
                "/// One curve, x^2 + a·y^2 = 1 + d·x^2·y^2 over GF(p) with a = 2: the\n"
                "/// field's bits, the longest message `l_max(p)` and the hash's kept\n"
                "/// length `l_H` in bits (the standard's Table 1), then `p`, `d`, the\n"
                "/// base point's order `n` and its coordinates, big-endian hexadecimal.\n"
                "pub(crate) struct Params {\n"
                "    pub(crate) bits: usize,\n"
                "    pub(crate) l_max: usize,\n"
                "    pub(crate) l_h: usize,\n"
                "    pub(crate) p: &'static str,\n"
                "    pub(crate) d: &'static str,\n"
                "    pub(crate) n: &'static str,\n"
                "    pub(crate) gx: &'static str,\n"
                "    pub(crate) gy: &'static str,\n"
                "}\n\n"
                "/// E256/1 and E512/1, the first curves of Tables В.1 and В.3.\n"
                "pub(crate) const CURVES: [Params; 2] = [\n")
        for bits, c in curves:
            f.write(f"    Params {{ bits: {bits}, l_max: {c['l_max']}, l_h: {c['l_h']},\n"
                    f"             p: \"{c['p']:x}\",\n"
                    f"             d: \"{c['d']:x}\",\n"
                    f"             n: \"{c['n']:x}\",\n"
                    f"             gx: \"{c['gx']:x}\",\n"
                    f"             gy: \"{c['gy']:x}\" }},\n")
        f.write("];\n")
    print("2 curves")


if __name__ == "__main__":
    main()
