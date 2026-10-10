#!/usr/bin/env python3
"""Write vectors/dstu_gost.vec: GOST 28147-89 and GOST 34.311-95 under
Ukraine's S-box, the DSTU 4145 default DKE, and the DSTU key wrap.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/gost89/build.sh /opt/gost89
    python3 scripts/make_dstu_gost_vectors.py

**A development tool, not a test.** It needs both witnesses built (the
second fetches four files of gost89 once) plus Java and Node;
`tests/test_dstu_gost.rs` reads `vectors/dstu_gost.vec` offline.

Two implementations that share no code: Bouncy Castle 1.77 (its GOST
engine, CFB, GOFB, GOST28147Mac and GOST3411Digest, given the S-box as
its own DSTU 4145 code expands a DKE) and gost89 (Ilya Petrov's
JavaScript, the code behind the dstucrypt tools, which unpacks the DKE
with its own `unpackSbox`). The DKE itself is the first thing checked:
Bouncy Castle's `DSTU4145Params.getDefaultDKE` and gost89's
`packSbox(defaultSbox)` must be the same 64 bytes. A row is written only
where both witnesses give it, and a disagreement stops the script,
except for two operations only one of them has:

- `gost-cnt`, GOST's counter mode (gamma), is Bouncy Castle's alone;
  gost89 has no counter mode.
- `wrap` is gost89's alone; Bouncy Castle has no DSTU GOST key wrap.
  Each row is also unwrapped by gost89, which must give the key back.

What is left out, and why:

- **The empty message to GOST 34.311-95.** Both witnesses skip the
  padded block when nothing is left; this library compresses a zero
  block, as gost-engine does for GOST R 34.11-94. Every non-empty
  length agrees. `docs/pitfalls.md` records the split.
- **MACs of one block or less.** GOST 28147-89 defines the MAC for two
  blocks or more. Bouncy Castle MACs one block as it is, gost89 adds a
  zero block only to an exact 8-byte message, and this library pads to
  two blocks as gost-engine does. The rows start at 9 bytes.

Row formats, hex fields:

    dke value=<64 bytes>
    gost-ecb key= pt= ct=
    gost-cfb key= iv= pt= ct=
    gost-cnt key= iv= pt= ct=
    gost-mac key= msg= tag=<4 bytes>
    gost34311 msg= digest=
    wrap kek= iv= cek= wrapped=<44 bytes>
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "dstu_gost.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
GOST89 = os.environ.get("GOST89_WITNESS", "/opt/gost89")
DRIVER = os.path.join(HERE, "witness", "gost89", "driver.js")


def h(b):
    return b.hex() or "-"


def bouncycastle(op, rows):
    stdin = "".join(" ".join(h(x) for x in r) + "\n" for r in rows)
    out = subprocess.run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness", op],
                         input=stdin, check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(rows)]
    return checked("Bouncy Castle", op, out)


def gost89(op, rows):
    stdin = "".join(" ".join(h(x) for x in r) + "\n" for r in rows)
    out = subprocess.run(["node", DRIVER, GOST89, op], input=stdin, check=True,
                         capture_output=True, text=True).stdout.split("\n")[:len(rows)]
    return checked("gost89", op, out)


def checked(who, op, out):
    for line in out:
        if line.startswith("error"):
            sys.exit(f"{who} refused a {op} row: {line}")
    return [bytes.fromhex(line) for line in out]


def both(op, rows):
    a, b = bouncycastle(op, rows), gost89(op, rows)
    for r, x, y in zip(rows, a, b):
        if x != y:
            sys.exit(f"the witnesses disagree on {op} {[h(f) for f in r]}: {x.hex()} != {y.hex()}")
    return a


def default_dke():
    bc = subprocess.run(
        ["jshell", "-q", "--class-path", f"{BC}/bcprov.jar"],
        input="System.out.println(org.bouncycastle.util.encoders.Hex.toHexString("
              "org.bouncycastle.asn1.ua.DSTU4145Params.getDefaultDKE()));\n/exit\n",
        check=True, capture_output=True, text=True).stdout
    bc = [w for w in bc.split() if len(w) == 128][0]
    js = subprocess.run(
        ["node", "-e", f"const d=require('{GOST89}/lib/dstu.js');"
                       "console.log(d.packSbox(d.defaultSbox).toString('hex'))"],
        check=True, capture_output=True, text=True).stdout.strip()
    if bc != js:
        sys.exit(f"the witnesses' default DKEs differ:\n  {bc}\n  {js}")
    return bytes.fromhex(bc)


def main():
    dke = default_dke()
    rng = random.Random(0x445354)
    rows = [f"dke value={dke.hex()}"]

    def key():
        return rng.randbytes(32)

    ecb = [(dke, bytes(32), bytes(8)), (dke, b"\xff" * 32, b"\xff" * 8),
           (dke, bytes(range(32)), bytes(range(8)))]
    ecb += [(dke, key(), rng.randbytes(8 * n)) for n in (1, 1, 2, 3, 4, 8)]
    for (_, k, p), c in zip(ecb, both("gost-ecb", ecb)):
        rows.append(f"gost-ecb key={k.hex()} pt={p.hex()} ct={c.hex()}")

    lengths = [1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100]
    cfb = [(dke, key(), rng.randbytes(8), rng.randbytes(n)) for n in lengths]
    for (_, k, iv, p), c in zip(cfb, both("gost-cfb", cfb)):
        rows.append(f"gost-cfb key={k.hex()} iv={iv.hex()} pt={p.hex()} ct={c.hex()}")

    cnt = [(dke, key(), rng.randbytes(8), rng.randbytes(n)) for n in lengths]
    for (_, k, iv, p), c in zip(cnt, bouncycastle("gost-cnt", cnt)):
        rows.append(f"gost-cnt key={k.hex()} iv={iv.hex()} pt={p.hex()} ct={c.hex()}")

    mac = [(dke, key(), rng.randbytes(n)) for n in (9, 15, 16, 17, 24, 32, 33, 64, 100)]
    for (_, k, m), t in zip(mac, both("gost-mac", mac)):
        rows.append(f"gost-mac key={k.hex()} msg={m.hex()} tag={t.hex()}")

    messages = [b"abc", b"message digest", bytes(32), b"\xff" * 32,
                b"This is message, length=32 bytes",
                b"Suppose the original message has length = 50 bytes"]
    messages += [rng.randbytes(n) for n in (1, 31, 33, 63, 64, 65, 100, 1000)]
    hashed = [(dke, m) for m in messages]
    for (_, m), d in zip(hashed, both("gost3411", hashed)):
        rows.append(f"gost34311 msg={m.hex()} digest={d.hex()}")

    wraps = [(bytes(32), bytes(8), bytes(32))]
    wraps += [(key(), rng.randbytes(8), key()) for _ in range(10)]
    wrapped = gost89("wrap", wraps)
    back = gost89("unwrap", [(k, w) for (k, _, _), w in zip(wraps, wrapped)])
    for (k, iv, cek), w, b in zip(wraps, wrapped, back):
        if b != cek or len(w) != 44:
            sys.exit(f"gost89 does not unwrap its own wrap of {cek.hex()}")
        rows.append(f"wrap kek={k.hex()} iv={iv.hex()} cek={cek.hex()} wrapped={w.hex()}")

    with open(OUTPUT, "w") as f:
        f.write("# GOST 28147-89 and GOST 34.311-95 under the DSTU 4145 default DKE,\n"
                "# and the DSTU key wrap. Written by scripts/make_dstu_gost_vectors.py;\n"
                "# do not edit. Bouncy Castle 1.77 and gost89 agree on every row except\n"
                "# gost-cnt (Bouncy Castle's alone) and wrap (gost89's alone).\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
