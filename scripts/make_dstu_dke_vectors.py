#!/usr/bin/env python3
"""Write src/block_ciphers/dstu_dke.rs and vectors/dstu_dke.vec: the ten
Ukrainian S-boxes ("DKE No. 1 from supplements 1 to 10 to instruction
114"), and GOST 28147-89 and GOST 34.311-95 under each.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/gost89/build.sh /opt/gost89
    scripts/witness/cryptonite/build.sh /opt/cryptonite
    python3 scripts/make_dstu_dke_vectors.py

**A development tool, not a test.** It needs the three witnesses of
`scripts/make_dstu_gost_vectors.py` built, and fetches one file once,
checked against its SHA-256; `tests/test_dstu_dke.rs` reads what it
writes offline.

The tables come from two sources that must agree: cryptonite's own
tables 1 to 10 (`gost-sbox 1` to `10`, which its header names as the
supplements to instruction 114), and li0ard's `DKE_1` to `DKE_10`
(li0ard/dstu's `src/dstu9311/const.ts`, packed as a DKE is). Table 1 is
the DSTU 4145 default DKE that `vectors/dstu_gost.vec` already holds,
and must be that too. Under tables 2 to 10, Bouncy Castle 1.77, gost89
and cryptonite - each given the table as a DKE - must agree on GOST
28147-89 in ECB and CFB, its MAC and GOST 34.311-95, and Bouncy Castle
and cryptonite on the counter mode, as for the default table.

Row formats, hex fields:

    dke number=<1..10> value=<64 bytes>
    gost-ecb dke=<n> key= pt= ct=
    gost-cfb dke=<n> key= iv= pt= ct=
    gost-cnt dke=<n> key= iv= pt= ct=
    gost-mac dke=<n> key= msg= tag=<4 bytes>
    gost34311 dke=<n> msg= digest=
"""

import hashlib
import os
import random
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import make_dstu_gost_vectors as witnesses  # noqa: E402

VECTORS = os.path.join(ROOT, "vectors", "dstu_dke.vec")
TABLES = os.path.join(ROOT, "src", "block_ciphers", "dstu_dke.rs")
LI0ARD_URL = ("https://raw.githubusercontent.com/li0ard/dstu/"
              "6c277c8906588a11f0d21a844347e83574ca325a/src/dstu9311/const.ts")
LI0ARD_SHA256 = "2e4b2718663ec39eb926fe21202c4155eeb701f74d5c1f4776029a432ed47553"


def li0ard():
    with urllib.request.urlopen(LI0ARD_URL) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != LI0ARD_SHA256:
        sys.exit("li0ard's const.ts is not the one pinned")
    text = data.decode()
    tables = {int(n): bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body))
              for n, body in re.findall(r"export const DKE_(\d+) = new Uint8Array\(\[([^\]]*)\]",
                                        text)}
    if sorted(tables) != list(range(1, 11)) or any(len(t) != 64 for t in tables.values()):
        sys.exit("expected li0ard's DKE_1 to DKE_10, 64 bytes each")
    return tables


def main():
    theirs = li0ard()
    ours = {n: witnesses.cryptonite("gost-sbox", [(str(n),)])[0] for n in range(1, 11)}
    for n in range(1, 11):
        if ours[n] != theirs[n]:
            sys.exit(f"cryptonite's table {n} and li0ard's DKE_{n} differ")
    if ours[1] != witnesses.default_dke():
        sys.exit("table 1 is not the default DKE")
    if len(set(ours.values())) != 10:
        sys.exit("two tables are the same")

    rng = random.Random(0x444B45)
    rows = [f"dke number={n} value={ours[n].hex()}" for n in range(1, 11)]
    lengths = [1, 8, 9, 17, 64]
    for n in range(2, 11):
        dke = ours[n]
        key = lambda: rng.randbytes(32)  # noqa: E731
        ecb = [(dke, bytes(32), bytes(8))] + [(dke, key(), rng.randbytes(8 * m)) for m in (1, 3)]
        for (_, k, p), c in zip(ecb, witnesses.both("gost-ecb", ecb)):
            rows.append(f"gost-ecb dke={n} key={k.hex()} pt={p.hex()} ct={c.hex()}")
        cfb = [(dke, key(), rng.randbytes(8), rng.randbytes(m)) for m in lengths]
        for (_, k, iv, p), c in zip(cfb, witnesses.both("gost-cfb", cfb)):
            rows.append(f"gost-cfb dke={n} key={k.hex()} iv={iv.hex()} pt={p.hex()} ct={c.hex()}")
        cnt = [(dke, key(), rng.randbytes(8), rng.randbytes(m)) for m in lengths]
        for (_, k, iv, p), c in zip(cnt, witnesses.agreed(
                "gost-cnt", cnt, (witnesses.bouncycastle, witnesses.cryptonite))):
            rows.append(f"gost-cnt dke={n} key={k.hex()} iv={iv.hex()} pt={p.hex()} ct={c.hex()}")
        mac = [(dke, key(), rng.randbytes(m)) for m in (9, 16, 33)]
        for (_, k, m), t in zip(mac, witnesses.both("gost-mac", mac)):
            rows.append(f"gost-mac dke={n} key={k.hex()} msg={m.hex()} tag={t.hex()}")
        hashed = [(dke, m) for m in (b"abc", bytes(32), rng.randbytes(100))]
        for (_, m), d in zip(hashed, witnesses.both("gost3411", hashed)):
            rows.append(f"gost34311 dke={n} msg={m.hex()} digest={d.hex()}")

    with open(VECTORS, "w") as f:
        f.write("# The ten Ukrainian S-boxes, DKE No. 1 from supplements 1 to 10 to\n"
                "# instruction 114, and GOST 28147-89 and GOST 34.311-95 under 2 to 10.\n"
                "# Written by scripts/make_dstu_dke_vectors.py; do not edit. cryptonite and\n"
                "# li0ard agree on the tables; Bouncy Castle 1.77, gost89 and cryptonite on\n"
                "# every row but gost-cnt (Bouncy Castle's and cryptonite's).\n")
        for r in rows:
            f.write(r + "\n")
    with open(TABLES, "w") as f:
        f.write("// The ten Ukrainian S-boxes, \"DKE No. 1 from supplements 1 to 10 to\n"
                "// instruction 114\", packed as a DSTU 4145 DKE. Written by\n"
                "// scripts/make_dstu_dke_vectors.py from cryptonite's tables 1 to 10 and\n"
                "// li0ard's DKE_1 to DKE_10, which agree; do not edit. The first is the\n"
                "// default DKE.\n\n"
                "pub(crate) const DSTU_DKE: [[u8; 64]; 10] = [\n")
        for n in range(1, 11):
            f.write("    [\n")
            for i in range(0, 64, 16):
                f.write("        " + ", ".join(f"0x{b:02x}" for b in ours[n][i:i + 16]) + ",\n")
            f.write("    ],\n")
        f.write("];\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
