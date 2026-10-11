#!/usr/bin/env python3
"""Write src/ec/dstu4145_params.rs: DSTU 4145-2002's ten named curves in a
polynomial basis, from two independent sources that must agree.

    python3 scripts/make_dstu4145_params.py

**A development tool, not a test.** It fetches two files once, each
checked against its SHA-256: Bouncy Castle 1.77's
`DSTU4145NamedCurves.java` and PrivatBank cryptonite's
`dstu4145_params_internal.c`. For every curve - the field's degree and
reduction polynomial, `a`, `b`, the order `n` and the base point - the
two must give the same values, read from their own formats (Bouncy
Castle's big-endian hexadecimal, cryptonite's little-endian byte
arrays), or the script stops. The cofactor is Bouncy Castle's; cryptonite
does not carry one, and `src/ec/dstu4145.rs` checks it against the
field's size.

Nothing in the output is typed: the Rust file is written from the values
the two files agree on.
"""

import hashlib
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "ec", "dstu4145_params.rs")
BC_URL = ("https://raw.githubusercontent.com/bcgit/bc-java/r1rv77/core/src/main/java/"
          "org/bouncycastle/asn1/ua/DSTU4145NamedCurves.java")
BC_SHA256 = "c32f0de6183cfee632564c4097296aac689a393dce7d05336698933043aad9a9"
CN_URL = ("https://raw.githubusercontent.com/privat-it/cryptonite/master/src/cryptonite/c/"
          "dstu4145_params_internal.c")
CN_SHA256 = "6831fbb24060b427dec60771bbc7a9adb0e595dfc389cfc391501ff8ce8fa016"


def fetch(url, digest):
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data.decode()


def bouncy_castle(text):
    n = {int(i): int(v, 16) for i, v in re.findall(r'n_s\[(\d)\] = new BigInteger\("(\w+)", 16\)', text)}
    h = {int(i): int(v) for i, v in re.findall(r'h_s\[(\d)\] = BigInteger\.valueOf\((\d+)\)', text)}
    curves = {}
    for i, args in re.findall(r'curves\[(\d)\] = new ECCurve\.F2m\((.*?)\);', text):
        args = re.sub(r'new BigInteger\("(\w+)", 16\)', r"0x\1", args)
        parts = [p.strip() for p in args.split(",")]
        m = int(parts[0])
        ks = [int(p) for p in parts[1:-4]]
        a = {"ONE": 1, "ZERO": 0}[parts[-4]]
        b = int(parts[-3], 16)
        curves[int(i)] = (m, sorted(ks + [0], reverse=True), a, b)
    points = {int(i): (int(x, 16), int(y, 16)) for i, x, y in re.findall(
        r'points\[(\d)\] = curves\[\d\]\.createPoint\(new BigInteger\("(\w+)", 16\), '
        r'new BigInteger\("(\w+)", 16\)\);', text)}
    if not (len(n) == len(h) == len(curves) == len(points) == 10):
        sys.exit(f"read {len(n)} orders, {len(h)} cofactors, {len(curves)} curves and "
                 f"{len(points)} points from Bouncy Castle")
    return [dict(m=curves[i][0], terms=curves[i][1], a=curves[i][2], b=curves[i][3], n=n[i],
                 h=h[i], gx=points[i][0], gy=points[i][1]) for i in range(10)]


def cryptonite(text):
    out = []
    for m in (163, 167, 173, 179, 191, 233, 257, 307, 367, 431):
        start = text.index(f"DSTU4145_PARAMS_M{m}_PB = {{")
        body = text[start:text.index("};", start)]
        f = [int(x) for x in re.search(r"\{\s*([\d,\s]+)\}", body).group(1).replace(",", " ").split()]
        rest = body[body.index("}", body.index("{", body.index("{") + 1)) + 1:]
        a = int(re.search(r"^\s*,\s*(\d+)\s*,", rest, re.M).group(1))
        arrays = [bytes(int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", blk))
                  for blk in re.findall(r"\{([^{}]*)\}", rest)]
        if len(arrays) != 4:
            sys.exit(f"M{m}: read {len(arrays)} byte arrays from cryptonite")
        b, n, gx, gy = (int.from_bytes(x, "little") for x in arrays)
        terms = sorted({t for t in f[1:]} | {0}, reverse=True)
        if f[0] != m:
            sys.exit(f"M{m}: cryptonite's polynomial is {f}")
        out.append(dict(m=m, terms=terms, a=a, b=b, n=n, gx=gx, gy=gy))
    return out


def main():
    bc = bouncy_castle(fetch(BC_URL, BC_SHA256))
    cn = cryptonite(fetch(CN_URL, CN_SHA256))
    for i, (x, y) in enumerate(zip(bc, cn)):
        for key in ("m", "terms", "a", "b", "n", "gx", "gy"):
            if x[key] != y[key]:
                sys.exit(f"curve {i}: Bouncy Castle and cryptonite disagree on {key}: "
                         f"{x[key]} != {y[key]}")
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("// DSTU 4145-2002's named curves in a polynomial basis. Written by\n"
                "// scripts/make_dstu4145_params.py from Bouncy Castle 1.77's\n"
                "// DSTU4145NamedCurves and cryptonite's dstu4145_params_internal.c, which\n"
                "// agree on every value; do not edit.\n\n"
                "/// One curve: `m`, the reduction polynomial's exponents below `m`, `a`,\n"
                "/// and `b`, `n`, the base point's coordinates and the cofactor as\n"
                "/// big-endian hexadecimal.\n"
                "pub(crate) struct Params {\n"
                "    pub(crate) m: usize,\n"
                "    pub(crate) terms: &'static [usize],\n"
                "    pub(crate) a: u8,\n"
                "    pub(crate) b: &'static str,\n"
                "    pub(crate) n: &'static str,\n"
                "    pub(crate) gx: &'static str,\n"
                "    pub(crate) gy: &'static str,\n"
                "    pub(crate) h: u8,\n"
                "}\n\n"
                "/// The curves by their number, 0 to 9, which is the last arc of their\n"
                "/// object identifiers, 1.2.804.2.1.1.1.1.3.1.1.2.0 to .9.\n"
                "pub(crate) const CURVES: [Params; 10] = [\n")
        for c in bc:
            f.write(f"    Params {{ m: {c['m']}, terms: &{c['terms']}, a: {c['a']},\n"
                    f"             b: \"{c['b']:x}\",\n"
                    f"             n: \"{c['n']:x}\",\n"
                    f"             gx: \"{c['gx']:x}\",\n"
                    f"             gy: \"{c['gy']:x}\",\n"
                    f"             h: {c['h']} }},\n")
        f.write("];\n")
    print(f"10 curves to {OUTPUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
