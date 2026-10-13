#!/usr/bin/env python3
"""Write vectors/dstu4145_onb.vec: DSTU 4145-2002 on its five curves in an
optimal normal basis.

    scripts/witness/cryptonite/build.sh /opt/cryptonite
    scripts/witness/li0ard/build.sh /opt/li0ard
    python3 scripts/make_dstu4145_onb_vectors.py

**A development tool, not a test.** It needs both witnesses built (the
second runs under bun); `tests/test_dstu4145_onb.rs` and
`pytests/test_dstu4145.py` read `vectors/dstu4145_onb.vec` offline.

Two implementations that share no code: PrivatBank's cryptonite, whose
curve tables 11 to 15 are these curves (through the driver
`scripts/make_dstu4145_vectors.py` uses), and li0ard's TypeScript
(`scripts/witness/li0ard`). Bouncy Castle has no normal basis. Each
field element is written in the normal basis, big endian, as both write
it. For each curve, `dstu4145-m173-onb` to `dstu4145-m431-onb`:

1. Public keys for d = 1, n - 1 and random d, on which both agree, and
   their compressions, which both give and both read back.
2. Signatures by li0ard, which signs with a given e, over 32-byte hashes
   (the length cryptonite takes) and one of another length; each
   verified by both, or by li0ard alone for the other length. Changed
   copies of each - r, s, the hash or the key - which both refuse.
3. Shared points with and without the cofactor: cryptonite's whole
   point, whose x li0ard must give too.

A disagreement anywhere stops the script. Row formats as
`vectors/dstu4145.vec`'s, hex, big endian, `hash` read little endian:

    pub curve= d= qx= qy= source=both
    compress curve= qx= qy= packed= source=both
    sign curve= d= e= hash= r= s= source=<both|li0ard>
    verify curve= qx= qy= hash= r= s= ok=<0|1> source=<both|li0ard>
    dh curve= d= qx= qy= cofactor=<0|1> zx= zy= source=both
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "dstu4145_onb.vec")
CRYPTONITE = os.environ.get("CRYPTONITE_WITNESS", "/opt/cryptonite")
LI0ARD = os.environ.get("LI0ARD_WITNESS", "/opt/li0ard")
BUN = os.environ.get("BUN") or "bun"

# allcrypt's numbers, 10 to 14; cryptonite's driver takes one less than
# its own table number, which is the same.
CURVES = [(10, "dstu4145-m173-onb", 173), (11, "dstu4145-m179-onb", 179),
          (12, "dstu4145-m191-onb", 191), (13, "dstu4145-m233-onb", 233),
          (14, "dstu4145-m431-onb", 431)]
ORDERS = {}


def run(program, lines):
    out = subprocess.run(program, input="".join(l + "\n" for l in lines), capture_output=True,
                         text=True, check=True).stdout.split("\n")[:len(lines)]
    for line in out:
        if line.startswith("error"):
            sys.exit(f"{program[-1]} refused: {line}")
    return [line.split() for line in out]


def cryptonite(op, lines):
    return run([f"{CRYPTONITE}/cryptonite-witness", "64", f"dstu4145-{op}"], lines)


def li0ard(op, lines):
    return run([BUN, f"{LI0ARD}/run/driver.ts"], [f"{op} {l}" for l in lines])


def both(op, lines):
    a, b = cryptonite(op, lines), li0ard(op, lines)
    for line, x, y in zip(lines, a, b):
        if [int(t, 16) for t in x] != [int(t, 16) for t in y]:
            sys.exit(f"the witnesses disagree on {op} {line}: {x} != {y}")
    return a


def h(b):
    return b.hex() or "-"


def order(number):
    """n, read back from the parameters file both witnesses' tables were
    checked against."""
    if not ORDERS:
        import re
        text = open(os.path.join(ROOT, "src", "ec", "dstu4145_params.rs")).read()
        onb = text[text.index("ONB_CURVES"):]
        for i, n in enumerate(re.findall(r'n: "([0-9a-f]+)"', onb)):
            ORDERS[10 + i] = int(n, 16)
    return ORDERS[number]


def main():
    rng = random.Random(0x0B4145)
    rows = []
    for number, name, m in CURVES:
        n = order(number)
        width = (m + 7) // 8
        fe = lambda v: f"{v:0{2 * width}x}"  # noqa: E731
        scalar = lambda v: f"{v:x}".zfill((v.bit_length() + 7) // 8 * 2 or 2)  # noqa: E731
        ds = [1, n - 1] + [rng.randrange(1, n) for _ in range(4)]
        keys = both("pub", [f"{number} {scalar(d)}" for d in ds])
        for d, (qx, qy) in zip(ds, keys):
            rows.append(f"pub curve={name} d={scalar(d)} qx={fe(int(qx, 16))} "
                        f"qy={fe(int(qy, 16))} source=both")
        packed = both("compress", [f"{number} {qx} {qy}" for qx, qy in keys])
        back = both("decompress", [f"{number} {fe(int(p[0], 16))}" for p in packed])
        for (qx, qy), p, q in zip(keys, packed, back):
            if [int(t, 16) for t in q] != [int(qx, 16), int(qy, 16)]:
                sys.exit(f"a compression on {name} does not read back")
            rows.append(f"compress curve={name} qx={fe(int(qx, 16))} qy={fe(int(qy, 16))} "
                        f"packed={fe(int(p[0], 16))} source=both")

        bits = n.bit_length() - 1
        signatures = []
        for i in range(4):
            d, (qx, qy) = ds[2 + i], keys[2 + i]
            e = rng.randrange(1, 1 << bits)
            message = rng.randbytes(32 if i < 3 else [20, 64, 0, 77, 1][number - 10])
            s, r = (int(t, 16) for t in li0ard("sign", [f"{number} {scalar(d)} {h(message)} "
                                                         f"{scalar(e)}"])[0])
            signatures.append((d, e, message, r, s, qx, qy))

        def verdict(qx, qy, message, r, s):
            line = f"{number} {qx} {qy} {h(message)} {r:0{2 * width}x} {s:0{2 * width}x}"
            witness = both if len(message) == 32 else li0ard
            return witness("verify", [line])[0] == ["01"]

        for i, (d, e, message, r, s, qx, qy) in enumerate(signatures):
            source = "both" if len(message) == 32 else "li0ard"
            if not verdict(qx, qy, message, r, s):
                sys.exit(f"a signature on {name} does not verify")
            rows.append(f"sign curve={name} d={scalar(d)} e={scalar(e)} hash={h(message)} "
                        f"r={scalar(r)} s={scalar(s)} source={source}")
            rows.append(f"verify curve={name} qx={fe(int(qx, 16))} qy={fe(int(qy, 16))} "
                        f"hash={h(message)} r={scalar(r)} s={scalar(s)} ok=1 source={source}")
            other = signatures[(i + 1) % len(signatures)]
            changed = [(qx, qy, message, r ^ 1, s), (qx, qy, message, r, (s + 1) % n),
                       (qx, qy, bytes([message[0] ^ 0x80]) + message[1:] if message
                        else b"\x02", r, s),
                       (other[5], other[6], message, r, s)][i]
            if changed[3] and changed[4]:
                if verdict(*changed):
                    sys.exit(f"a changed signature on {name} verifies")
                cx, cy, cm, cr, cs = changed
                rows.append(f"verify curve={name} qx={fe(int(cx, 16))} qy={fe(int(cy, 16))} "
                            f"hash={h(cm)} r={scalar(cr)} s={scalar(cs)} ok=0 "
                            f"source={'both' if len(cm) == 32 else 'li0ard'}")

        for cofactor in (0, 1):
            d, (qx, qy) = ds[2 + cofactor], keys[4 + cofactor]
            line = f"{number} {scalar(d)} {qx} {qy} {cofactor}"
            zx, zy = cryptonite("dh", [line])[0]
            if int(li0ard("dh", [line])[0][0], 16) != int(zx, 16):
                sys.exit(f"the witnesses disagree on a shared point on {name}")
            rows.append(f"dh curve={name} d={scalar(d)} qx={fe(int(qx, 16))} "
                        f"qy={fe(int(qy, 16))} cofactor={cofactor} zx={fe(int(zx, 16))} "
                        f"zy={fe(int(zy, 16))} source=both")

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# DSTU 4145-2002 on its five curves in an optimal normal basis. Written by\n"
                  "# scripts/make_dstu4145_onb_vectors.py; do not edit. Field elements in the\n"
                  "# normal basis, big endian. source=both: cryptonite and li0ard agree\n"
                  "# (li0ard signs, both verify; a shared point's y is cryptonite's, its x\n"
                  "# both's); source=li0ard: a hash of a length cryptonite does not take.\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
