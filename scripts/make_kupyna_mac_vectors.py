#!/usr/bin/env python3
"""Write vectors/kupyna_mac.vec: DSTU 7564:2014's MAC over Kupyna.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/cryptonite/build.sh /opt/cryptonite
    scripts/witness/kupyna/build.sh /opt/kupyna
    python3 scripts/make_kupyna_mac_vectors.py

**A development tool, not a test.** It fetches two files once, each
checked against its SHA-256 - cryptonite's acceptance tests for Kupyna
(`atest_dstu7564.c`) and Bouncy Castle's `DSTU7564Test.java` - and
`tests/test_kupyna_mac.rs` reads `vectors/kupyna_mac.vec` offline.

Three implementations that share no code: Bouncy Castle 1.77's
`DSTU7564Mac`, PrivatBank's cryptonite, and the reference
implementation by the hash's authors (`KupynaKmac`). The reference takes
a key as long as the MAC, and sizes its buffer as if the message had no
whole block, so it is asked only about messages shorter than one block.
cryptonite treats the padded key as one block, so it is asked only about
keys that leave room for the padding in one. In order:

1. The examples: the three in cryptonite's tests, which are the
   standard's and which Bouncy Castle's test file also carries
   (`source=standard`), and the others in Bouncy Castle's file - a
   short message under another key and two messages of 1023 and 1024
   bytes (`source=bouncycastle-tests`). Every witness that takes an
   example must reproduce it.
2. Rows all three agree on (`source=all`): a key as long as the MAC and
   a message shorter than a block.
3. Rows Bouncy Castle and cryptonite agree on (`source=both`): keys of
   other lengths and messages of several blocks.
4. Keys longer than one padded block, from Bouncy Castle alone
   (`source=bouncycastle`).

Rows, hex fields, "-" for empty:

    kmac bits= key= msg= mac= source=
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
OUTPUT = os.path.join(ROOT, "vectors", "kupyna_mac.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
CRYPTONITE = os.environ.get("CRYPTONITE_WITNESS", "/opt/cryptonite")
REF = os.environ.get("KUPYNA_WITNESS", "/opt/kupyna")
ATEST_URL = ("https://raw.githubusercontent.com/privat-it/cryptonite/master/src/"
             "cryptoniteAtest/c/atest_dstu7564.c")
ATEST_SHA256 = "358ca1bf6a7b5a47bc6a63d2ba131e4d9357e41de112860013dfa0431eed86d5"
BC_URL = ("https://raw.githubusercontent.com/bcgit/bc-java/r1rv77/core/src/test/java/"
          "org/bouncycastle/crypto/test/DSTU7564Test.java")
BC_SHA256 = "99c1eb9f564d60e948ac9f3981b82452cc7285ee84b900c2914ea65099fb04a8"


def h(b):
    return b.hex() or "-"


def run(command, rows, who):
    stdin = "".join(" ".join(h(x) for x in r) + "\n" for r in rows)
    out = subprocess.run(command, input=stdin, check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(rows)]
    if len(out) != len(rows):
        sys.exit(f"{who} answered {len(out)} of {len(rows)}")
    for line in out:
        if line.startswith("error"):
            sys.exit(f"{who} refused a row: {line}")
    return [bytes.fromhex(line) for line in out]


def bc(bits, rows):
    return run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness", f"kupyna-mac-{bits}"], rows,
               "Bouncy Castle")


def cn(bits, rows):
    return run([f"{CRYPTONITE}/cryptonite-witness", str(bits), "kmac"], rows, "cryptonite")


def ref(bits, rows):
    return run([f"{REF}/kupyna-witness", str(bits), "kmac"], rows, "the reference")


def block_of(bits):
    return 64 if bits <= 256 else 128


def fetch(url, digest=None):
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if digest and hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data


def main():
    atest = fetch(ATEST_URL, ATEST_SHA256).decode()
    bc_text = fetch(BC_URL, BC_SHA256).decode()
    rows = []

    # 1. The examples.
    body = atest[atest.index("kmac_data[] = {"):]
    body = body[:body.index("\n};")]
    standard = [(int(size) * 8, bytes.fromhex(k), bytes.fromhex(m), bytes.fromhex(t))
                for k, m, t, size in re.findall(
                    r'\{\s*"(\w+)",\s*"(\w+)",\s*"(\w+)",\s*(\d+)\s*\}', body)]
    published = []
    tests = bc_text[bc_text.index("private void macTests()"):]
    tests = tests[:tests.index("private void", 10)]
    size = None
    for chunk in re.split(r"(?=macBitSize = \d+;)|(?=input = Hex)", tests):
        if m := re.search(r"macBitSize = (\d+);", chunk):
            size = int(m.group(1))
        fields = dict(re.findall(r'(input|key|expectedMac) = Hex\.decode\("(\w+)"\)', chunk))
        if len(fields) == 3:
            published.append((size, bytes.fromhex(fields["key"]), bytes.fromhex(fields["input"]),
                              bytes.fromhex(fields["expectedMac"])))
    # The first two overflow tests are MACs; the rest are digests.
    overflow = bc_text[bc_text.index("private void overflowTest()"):]
    overflow = overflow[:overflow.index("DSTU7564Digest digest")]
    for length, key, expected in re.findall(
            r'input = new byte\[(\d+)\];.*?key = Hex\.decode\("(\w+)"\);.*?'
            r'expectedMac = Hex\.decode\("(\w+)"\);', overflow, re.S):
        message = bytes(i & 0xff for i in range(int(length)))
        published.append((256, bytes.fromhex(key), message, bytes.fromhex(expected)))
    if len(standard) != 3 or len(published) != 6:
        sys.exit(f"read {len(standard)} examples from cryptonite and {len(published)} from "
                 "Bouncy Castle")
    seen = set()
    for bits, key, msg, mac in standard + published:
        if (bits, key, msg) in seen:
            continue
        seen.add((bits, key, msg))
        witnesses = [("Bouncy Castle", bc)]
        if len(key) + 13 <= block_of(bits):
            witnesses.append(("cryptonite", cn))
        if len(key) * 8 == bits and len(msg) < block_of(bits):
            witnesses.append(("the reference", ref))
        for who, f in witnesses:
            if f(bits, [(key, msg)])[0] != mac:
                sys.exit(f"{who} misses the {bits}-bit MAC example under {key.hex()}")
        source = "standard" if any(s[1:] == (key, msg, mac) for s in standard) \
            else "bouncycastle-tests"
        rows.append(f"kmac bits={bits} key={key.hex()} msg={h(msg)} mac={mac.hex()} "
                    f"source={source}")
    examples = len(rows)

    rng = random.Random(0x7564)
    for bits in (256, 384, 512):
        block = block_of(bits)
        # 2. All three.
        reqs = [(rng.randbytes(bits // 8), rng.randbytes(n))
                for n in (0, 1, 31, 32, 33, block // 2, block - 13, block - 12, block - 1)]
        a, b, c = bc(bits, reqs), cn(bits, reqs), ref(bits, reqs)
        for r, x, y, z in zip(reqs, a, b, c):
            if not x == y == z:
                sys.exit(f"the witnesses disagree at {bits} bits under {r[0].hex()}")
            rows.append(f"kmac bits={bits} key={r[0].hex()} msg={h(r[1])} mac={x.hex()} "
                        f"source=all")
        # 3. Bouncy Castle and cryptonite.
        reqs = [(rng.randbytes(k), rng.randbytes(n))
                for k in (0, 1, 16, bits // 8 - 1, bits // 8 + 1, block - 13)
                for n in (0, block - 1, block, block + 1, 3 * block + 5, 1000)]
        reqs = [(k, m) for k, m in reqs if len(k) + 13 <= block]
        for r, x, y in zip(reqs, bc(bits, reqs), cn(bits, reqs)):
            if x != y:
                sys.exit(f"Bouncy Castle and cryptonite disagree at {bits} bits, a "
                         f"{len(r[0])}-byte key and a {len(r[1])}-byte message")
            rows.append(f"kmac bits={bits} key={h(r[0])} msg={h(r[1])} mac={x.hex()} "
                        f"source=both")
        # 4. Bouncy Castle alone.
        reqs = [(rng.randbytes(k), rng.randbytes(n))
                for k in (block - 12, block, block + 1, 3 * block) for n in (0, 77)]
        for r, x in zip(reqs, bc(bits, reqs)):
            rows.append(f"kmac bits={bits} key={r[0].hex()} msg={h(r[1])} mac={x.hex()} "
                        f"source=bouncycastle")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# DSTU 7564:2014's MAC over Kupyna. Written by\n"
                "# scripts/make_kupyna_mac_vectors.py; do not edit. source=standard: the\n"
                "# standard's examples as cryptonite's and Bouncy Castle's tests carry them;\n"
                "# bouncycastle-tests: Bouncy Castle's other examples; all: Bouncy Castle\n"
                "# 1.77, cryptonite and the reference agree; both: the first two agree;\n"
                "# bouncycastle: that one alone.\n"
                f"# rows: {len(rows)}, examples: {examples}\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows, {examples} examples", file=sys.stderr)


if __name__ == "__main__":
    main()
