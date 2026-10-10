#!/usr/bin/env python3
"""Write vectors/kalyna_modes.vec: DSTU 7624:2014's modes over Kalyna -
CBC, CFB, OFB, its counter mode, its MAC and its key wrap.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/cryptonite/build.sh /opt/cryptonite
    python3 scripts/make_kalyna_mode_vectors.py

**A development tool, not a test.** It needs both witnesses built, and
fetches the standard's examples once, as Bouncy Castle's
`DSTU7624Test.java` carries them (checked against its SHA-256).
`tests/test_kalyna_modes.rs` reads `vectors/kalyna_modes.vec` offline.

Two implementations that share no code: Bouncy Castle 1.77 (the generic
CBC, CFB and OFB, `KCTRBlockCipher`, `DSTU7624Mac`, `DSTU7624WrapEngine`)
and PrivatBank's cryptonite, driven through
`scripts/witness/cryptonite/driver.c`. In order:

1. Every standard example in the test file - CBC, CFB, OFB, counter
   mode, MAC, key wrap - must be reproduced by both.
2. Then rows where both agree: the four streaming modes at every
   variant, counter mode and OFB at lengths around the block, CBC and CFB
   in whole blocks (on a short last block cryptonite's CFB takes the
   last bytes of the encrypted feedback, Bouncy Castle's the first; the
   standard's counter-mode and OFB examples, which end in short blocks,
   take the first); MACs of whole blocks, the empty
   message among them; key wraps of whole blocks, up to twenty, where
   cryptonite's one-byte step counter and Bouncy Castle's 32-bit one
   coincide.
3. Then each alone where the other stops. cryptonite: MACs of messages
   that are not whole blocks, and wraps of data that is not, which
   Bouncy Castle refuses. Bouncy Castle: wraps of 24 blocks, past
   cryptonite's counter.

A disagreement anywhere stops the script. Row formats, hex fields, "-"
for empty:

    stream mode=<cbc|cfb|ofb|ctr> block=<bytes> key= iv= pt= ct= source=
    mac block= key= q=<bytes> msg= tag= source=
    kw block= key= data= wrapped= source=

`source` is `standard`, `both`, `cryptonite` or `bouncycastle`.
"""

import hashlib
import os
import random
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "kalyna_modes.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
CRYPTONITE = os.environ.get("CRYPTONITE_WITNESS", "/opt/cryptonite")
EXAMPLES_URL = ("https://raw.githubusercontent.com/bcgit/bc-java/r1rv77/core/src/test/java/"
                "org/bouncycastle/crypto/test/DSTU7624Test.java")
EXAMPLES_SHA256 = "e1131a41401617ab4e1fe40c196aa103f2bbd41c686758dae973f6ad04db5924"
VARIANTS = [(16, 16), (16, 32), (32, 32), (32, 64), (64, 64)]


def h(b):
    return b.hex() or "-"


def lines_of(rows):
    return "".join(" ".join(x if isinstance(x, str) else h(x) for x in r) + "\n" for r in rows)


def checked(who, out):
    for line in out:
        if line.startswith("error"):
            sys.exit(f"{who} refused a row: {line}")
    return [bytes.fromhex(line) for line in out]


def bouncycastle(op, rows):
    out = subprocess.run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness", op],
                         input=lines_of(rows), check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(rows)]
    return checked("Bouncy Castle " + op, out)


def cryptonite(block, op, rows):
    out = subprocess.run([f"{CRYPTONITE}/cryptonite-witness", str(8 * block), op],
                         input=lines_of(rows), check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(rows)]
    return checked("cryptonite " + op, out)


def bc_stream(mode, block, rows):
    return bouncycastle(f"kalyna-{mode}-{8 * block}", rows)


def both_stream(mode, block, rows):
    a, b = cryptonite(block, mode, rows), bc_stream(mode, block, rows)
    for r, x, y in zip(rows, a, b):
        if x != y:
            sys.exit(f"the witnesses disagree on {mode}: {[h(f) for f in r]}")
    return a


def examples():
    with urllib.request.urlopen(EXAMPLES_URL) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != EXAMPLES_SHA256:
        sys.exit("DSTU7624Test.java changed upstream; read it before trusting it")
    text = data.decode()

    def method(name):
        start = text.index(f"private void {name}()")
        return text[start:text.index("private void", start + 10)]

    def hexes(s):
        return {name: "".join(re.findall(r'"([0-9A-Fa-f]*)"', body)).lower()
                for name, body in re.findall(
                    r'(\w+) = Hex\.decode\(((?:"[0-9A-Fa-f]*"\s*\+?\s*)+)\)', s)}

    streams = set()
    for mode, bits, key, iv, pt, ct in re.findall(
            r'new (CBC|CFB|OFB|KCTR)BlockCipher\(new DSTU7624Engine\((\d+)\)(?:, \d+)?\), '
            r'new ParametersWithIV\(new KeyParameter\(Hex\.decode\("(\w+)"\)\), '
            r'Hex\.decode\("(\w+)"\)\), "(\w+)", "(\w+)"\)', text):
        name = {"CBC": "cbc", "CFB": "cfb", "OFB": "ofb", "KCTR": "ctr"}[mode]
        streams.add((name, int(bits) // 8, key.lower(), iv.lower(), pt.lower(), ct.lower()))

    macs = []
    for chunk in re.split(r"//test \d+", method("MacTests"))[1:]:
        v, m = hexes(chunk), re.search(r"new DSTU7624Mac\((\d+), (\d+)\)", chunk)
        macs.append((int(m.group(1)) // 8, v["key"], int(m.group(2)) // 8, v["authtext"],
                     v["expectedMac"]))

    wraps, bits = [], None
    for chunk in re.split(r"//test \d+", method("KeyWrapTests"))[1:]:
        v, m = hexes(chunk), re.search(r"new DSTU7624WrapEngine\((\d+)\)", chunk)
        bits = int(m.group(1)) if m else bits
        data = v.get("textToWrap") or "".join(re.findall(
            r'concatenate\(new byte\[\]\[\]\{ textA, Hex\.decode\("([0-9A-Fa-f]+)"\)', chunk)).lower()
        wraps.append((bits // 8, v["key"], data, v["expectedWrappedText"]))
    if len(streams) < 20 or len(macs) < 2 or len(wraps) < 5:
        sys.exit(f"found {len(streams)} stream, {len(macs)} MAC, {len(wraps)} wrap examples")
    return sorted(streams), macs, wraps


def main():
    rows = []
    streams, macs, wraps = examples()
    for mode, block, key, iv, pt, ct in streams:
        k, i, p, c = (bytes.fromhex(x) for x in (key, iv, pt, ct))
        if cryptonite(block, mode, [(k, i, p)])[0] != c:
            sys.exit(f"cryptonite misses the standard's {mode} example under {key}")
        if bc_stream(mode, block, [(k, i, p)])[0] != c:
            sys.exit(f"Bouncy Castle misses the standard's {mode} example under {key}")
        rows.append(f"stream mode={mode} block={block} key={key} iv={iv} pt={pt} ct={ct} "
                    f"source=standard")
    for block, key, q, msg, tag in macs:
        k, m = bytes.fromhex(key), bytes.fromhex(msg)
        for who, got in (("cryptonite", cryptonite(block, "cmac", [(k, str(q), m)])[0]),
                         ("Bouncy Castle", bouncycastle(f"kalyna-mac-{8 * block}",
                                                        [(k, str(q), m)])[0])):
            if got.hex() != tag:
                sys.exit(f"{who} misses the standard's MAC example under {key}")
        rows.append(f"mac block={block} key={key} q={q} msg={msg} tag={tag} source=standard")
    for block, key, data, wrapped in wraps:
        k, d = bytes.fromhex(key), bytes.fromhex(data)
        for who, got in (("cryptonite", cryptonite(block, "kw", [(k, d)])[0]),
                         ("Bouncy Castle", bouncycastle(f"kalyna-kw-{8 * block}", [(k, d)])[0])):
            if got.hex() != wrapped:
                sys.exit(f"{who} misses the standard's key wrap example under {key}")
        rows.append(f"kw block={block} key={key} data={data} wrapped={wrapped} source=standard")
    # The standard's padded example, from the unpadded data: its first 18
    # bytes and a bit length of 144 say so, and cryptonite pads them to it.
    padded = [w for w in wraps if w[2].startswith("101112131415161718191a1b1c1d1e1f2021900000")]
    for block, key, data, wrapped in padded:
        raw = bytes.fromhex(data)[:18]
        if cryptonite(block, "kw", [(bytes.fromhex(key), raw)])[0].hex() != wrapped:
            sys.exit("cryptonite does not pad the standard's 18-byte example to its wrapping")
        rows.append(f"kw block={block} key={key} data={raw.hex()} wrapped={wrapped} "
                    f"source=standard")

    rng = random.Random(0x4B4D4F44)
    for block, klen in VARIANTS:
        for mode in ("cbc", "cfb", "ofb", "ctr"):
            # CFB in whole blocks only: on a short last block cryptonite
            # takes the last bytes of the encrypted feedback and Bouncy
            # Castle the first. The standard's counter-mode and OFB
            # examples end in short blocks and take the first bytes,
            # which both reproduce; CFB has no such example.
            lengths = (block, 2 * block, 3 * block) if mode in ("cbc", "cfb") else \
                      (1, block - 1, block, block + 1, 3 * block + 5)
            chosen = [(rng.randbytes(klen), rng.randbytes(block), rng.randbytes(n)) for n in lengths]
            for (k, i, p), c in zip(chosen, both_stream(mode, block, chosen)):
                rows.append(f"stream mode={mode} block={block} key={k.hex()} iv={i.hex()} "
                            f"pt={h(p)} ct={c.hex()} source=both")

        whole = [(rng.randbytes(klen), str(q), rng.randbytes(n))
                 for n in (0, block, 2 * block, 5 * block) for q in (block, block // 2, 4)]
        a = cryptonite(block, "cmac", whole)
        b = bouncycastle(f"kalyna-mac-{8 * block}", whole)
        for r, x, y in zip(whole, a, b):
            if x != y:
                sys.exit(f"the witnesses disagree on a MAC: {[h(f) if not isinstance(f, str) else f for f in r]}")
            rows.append(f"mac block={block} key={r[0].hex()} q={r[1]} msg={h(r[2])} tag={x.hex()} "
                        f"source=both")
        partial = [(rng.randbytes(klen), str(block), rng.randbytes(n))
                   for n in (1, block - 1, block + 1, 3 * block - 7)]
        for r, x in zip(partial, cryptonite(block, "cmac", partial)):
            rows.append(f"mac block={block} key={r[0].hex()} q={r[1]} msg={h(r[2])} tag={x.hex()} "
                        f"source=cryptonite")

        kw = [(rng.randbytes(klen), rng.randbytes(n * block)) for n in (1, 2, 3, 7, 20)]
        a = cryptonite(block, "kw", kw)
        b = bouncycastle(f"kalyna-kw-{8 * block}", kw)
        for (k, d), x, y in zip(kw, a, b):
            if x != y:
                sys.exit(f"the witnesses disagree on a key wrap under {k.hex()}")
            rows.append(f"kw block={block} key={k.hex()} data={d.hex()} wrapped={x.hex()} source=both")
        odd = [(rng.randbytes(klen), rng.randbytes(n))
               for n in (1, block // 2 - 1, block // 2, block // 2 + 1, block - 1, 2 * block + 3)]
        for (k, d), x in zip(odd, cryptonite(block, "kw", odd)):
            rows.append(f"kw block={block} key={k.hex()} data={d.hex()} wrapped={x.hex()} "
                        f"source=cryptonite")
        long = [(rng.randbytes(klen), rng.randbytes(24 * block))]
        for (k, d), x in zip(long, bouncycastle(f"kalyna-kw-{8 * block}", long)):
            rows.append(f"kw block={block} key={k.hex()} data={d.hex()} wrapped={x.hex()} "
                        f"source=bouncycastle")

    with open(OUTPUT, "w") as f:
        f.write("# DSTU 7624:2014's modes over Kalyna. Written by\n"
                "# scripts/make_kalyna_mode_vectors.py; do not edit. source=standard:\n"
                "# the standard's examples, both witnesses reproducing them;\n"
                "# source=both: Bouncy Castle 1.77 and cryptonite in agreement;\n"
                "# source=cryptonite or bouncycastle: what only that one does.\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
