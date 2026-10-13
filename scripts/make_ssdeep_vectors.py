#!/usr/bin/env python3
"""Write vectors/ssdeep.vec: ssdeep digests and scores, and the CTPH of
ctph.js, from the implementations that define them.

    scripts/witness/ssdeep/build.sh /opt/ssdeepwitness
    python3 scripts/make_ssdeep_vectors.py

**A development tool, not a test.** It needs the witnesses built (node
runs ctph.js); `tests/test_ssdeep.rs` and `pytests/test_ssdeep.py` read
the file offline.

The messages are described rather than stored, by a rule all three
readers share (`message` below):

    random:SEED:LEN            SHA-256("allcrypt ssdeep" || SEED || i),
                               SEED and the counter i 32 bit big endian,
                               concatenated and cut to LEN bytes; a
                               shorter one is a prefix of a longer one
    zeros:LEN
    repeat:HEX:LEN             the bytes HEX repeated, cut to LEN
    counting:LEN               "0\\n1\\n2\\n..." cut to LEN
    edited:SEED:LEN:AT:N:SEED2 random:SEED:LEN with bytes AT to AT+N
                               replaced by random:SEED2:N
    spliced:SEED:LEN:AT:HEX    random:SEED:LEN with the bytes HEX written
                               over it from AT

Witnesses:

* ssdeep digests: libfuzzy (ssdeep 2.14.1, which also checks that
  hashing in pieces without the length gives the same) and ppdeep, which
  hashes the input once per block size as spamsum did. They must agree.
* ssdeep scores: libfuzzy, whose `fuzzy_compare` defines them, between
  digests of related and unrelated messages and on malformed ones; ppdeep
  agrees on a row or the row says libfuzzy alone.
* CTPH digests and similarities: ctph.js 0.0.5, which defines CTPH; there
  is no second implementation.

Rows:

    hash msg= ssdeep= ctph=
    compare a= b= score=<n|error> source=<both|libfuzzy>
    similarity a= b= score=<number|NaN|error>
"""

import hashlib
import itertools
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "ssdeep.vec")
OUT = os.environ.get("SSDEEP_WITNESS", "/opt/ssdeepwitness")

FOX = b"the quick brown fox jumps over the lazy dog ".hex()
MESSAGES = (
    [f"random:1:{n}" for n in (0, 1, 2, 3, 6, 7, 8, 63, 64, 65, 191, 192, 193, 200, 383, 384,
                               385, 1000, 4096, 10000, 65536, 100000, 300000, 1000000)]
    + [f"random:2:{n}" for n in (150000, 200000, 3000000)]
    + [f"zeros:{n}" for n in (1, 100, 5000, 70000, 1000000)]
    + [f"repeat:{FOX}:{n}" for n in (1000, 50000, 500000)]
    + [f"repeat:41:{n}" for n in (1000, 50000)]
    + [f"repeat:00ff:{n}" for n in (999, 100001)]
    + [f"counting:{n}" for n in (10000, 200000, 2000000)]
    + ["edited:2:200000:50000:100:3", "edited:2:200000:0:5000:4", "edited:2:200000:150000:40000:5",
       "edited:2:200000:100000:1:6", "edited:2:3000000:1000000:200000:7"]
    # Seven bytes whose rolling hash is 0xffffffff, where the sum plus one
    # is zero and ends no piece; and seven zeros at the end, where it is
    # zero and the digest takes the characters already written - the last
    # two, found by search, where the string the digest uses is full.
    + ["spliced:9:5000:2000:031f1f1f1895f2", "spliced:9:300:293:031f1f1f1895f2",
       "spliced:8:10000:9993:00000000000000", "spliced:8:100000:99993:00000000000000",
       "spliced:10:199:192:00000000000000", "spliced:16:1000:993:00000000000000"]
    # Found by search: inputs whose string at some block size ends with
    # exactly 31 characters, one short of the 32 that decide a block size,
    # and one whose CTPH string does the same.
    + ["random:124:210", "random:100:195", "random:101:230"]
)
# Related messages, every pair of which is scored.
FAMILIES = [
    ["random:2:150000", "random:2:200000", "edited:2:200000:50000:100:3",
     "edited:2:200000:0:5000:4", "edited:2:200000:150000:40000:5",
     "edited:2:200000:100000:1:6"],
    ["random:2:3000000", "edited:2:3000000:1000000:200000:7"],
    ["counting:10000", "counting:200000", "counting:2000000"],
    [f"repeat:{FOX}:1000", f"repeat:{FOX}:50000", f"repeat:{FOX}:500000",
     "repeat:41:1000", "repeat:41:50000"],
    ["random:1:191", "random:1:192", "random:1:193", "random:1:200", "random:1:383",
     "random:1:384", "random:1:385"],
]
# Digests libfuzzy refuses, or reads oddly, and the comparisons that
# reach each of its branches with strings of our own.
CRAFTED = [
    ("3:abc", "3:abc"), ("x:a:b", "3:a:b"), ("3:a:b", "x:a:b"), (":a:b", "3:a:b"),
    ("3:abcdefgh:abcdefgh", "3:abcdefgh:abcdefgh,file"),
    ("3:" + "A" * 65 + ":B", "3:A:B"), ("3:" + "AB" * 33 + ":B", "3:A:B"),
    ("6:abcdefgh:ijklmnop", "3:xbcdefgh:abcdefgh"), ("3:abcdefgh:ijklmnop", "6:ijklmnop:qrstuvwx"),
    ("12:abcdefghi:jklmnopqr", "48:abcdefghi:jklmnopqr"),
    ("3:abcdefghijklmnop:x", "3:abcdefghijklmnoq:y"), ("3:abcdefg:x", "3:abcdefg:x"),
    ("96:abcdefghijklmnopqrstuvwxyz:x", "96:abcdefghijklmnopqrstuvwxyA:x"),
    ("24:aaaaaaaaaabcdefghij:x", "24:aaabcdefghij:x"),
    ("9223372036854775808:abcdefgh:x", "9223372036854775808:abcdefgh:y"),
    ("18446744073709551614:abcdefgh:x", "9223372036854775807:abcdefgh:abcdefgh"),
    ("3:abcdefghij:abcdefghij", "12:abcdefghij:abcdefghij"),
    ("3:" + ("AB" * 33)[:65] + ":B", "3:A:B"), ("3:" + ("AB" * 32) + ":B", "3:A:B"),
    ("3:" + "A" * 70 + ":B", "12:x:y"), ("6:abcdefghij:klmnopqrst", "3:zzz:abcdefghij"),
]
CRAFTED_CTPH = [("A::", "A::"), ("B:abc:de", "A:x:abc"), ("A:x:y", "E:x:y"), ("::", "::"),
                ("x", "a"), ("D:abcdef:abc", "D:abcdeg:abd"), ("C:abc:de", "D:de:fg"),
                ("D:abc", "D:abc"), ("B:abc", "A:xyz"), ("", "B:x:y"), ("", "A:x:y"),
                ("A::x", "A:abc:y")]


def random_bytes(seed, length):
    out, i = bytearray(), 0
    while len(out) < length:
        out += hashlib.sha256(b"allcrypt ssdeep" + seed.to_bytes(4, "big")
                              + i.to_bytes(4, "big")).digest()
        i += 1
    return bytes(out[:length])


def message(spec):
    kind, *f = spec.split(":")
    if kind == "random":
        return random_bytes(int(f[0]), int(f[1]))
    if kind == "zeros":
        return bytes(int(f[0]))
    if kind == "repeat":
        unit, length = bytes.fromhex(f[0]), int(f[1])
        return (unit * (length // len(unit) + 1))[:length]
    if kind == "counting":
        length, text, i = int(f[0]), bytearray(), 0
        while len(text) < length:
            text += f"{i}\n".encode()
            i += 1
        return bytes(text[:length])
    if kind == "edited":
        base = bytearray(random_bytes(int(f[0]), int(f[1])))
        at, n = int(f[2]), int(f[3])
        base[at:at + n] = random_bytes(int(f[4]), n)
        return bytes(base)
    if kind == "spliced":
        base = bytearray(random_bytes(int(f[0]), int(f[1])))
        patch = bytes.fromhex(f[3])
        base[int(f[2]):int(f[2]) + len(patch)] = patch
        return bytes(base)
    sys.exit(f"no message {spec}")


def ask(program, lines):
    out = subprocess.run(program, input="".join(l + "\n" for l in lines), capture_output=True,
                         text=True, check=True).stdout.split("\n")[:len(lines)]
    if len(out) != len(lines):
        sys.exit(f"{program} answered {len(out)} of {len(lines)}")
    return out


LIBFUZZY = [f"{OUT}/ssdeep-witness"]
PPDEEP = ["python3", "-I", f"{OUT}/ppdeep_driver.py", f"{OUT}/src/ppdeep"]
CTPH = ["node", f"{OUT}/driver.js", f"{OUT}/src/ctph.js/ctph.js"]


def main():
    rows, digests, ctphs = [], {}, {}
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, spec in enumerate(MESSAGES):
            path = os.path.join(tmp, str(i))
            with open(path, "wb") as f:
                f.write(message(spec))
            paths.append(path)
        requests = [f"hash {p}" for p in paths]
        from_libfuzzy, from_ppdeep, from_ctph = (ask(LIBFUZZY, requests), ask(PPDEEP, requests),
                                                 ask(CTPH, requests))
    for spec, a, b, c in zip(MESSAGES, from_libfuzzy, from_ppdeep, from_ctph):
        if a != b or a == "error":
            sys.exit(f"libfuzzy and ppdeep disagree on {spec}: {a} {b}")
        if c == "error":
            sys.exit(f"ctph.js refused {spec}")
        digests[spec], ctphs[spec] = a, c
        rows.append(f"hash msg={spec} ssdeep={a} ctph={c}")

    pairs = [(digests[x], digests[y]) for family in FAMILIES
             for x, y in itertools.product(family, repeat=2)]
    rng = random.Random(0x55DEE9)
    unrelated = [digests[s] for s in MESSAGES]
    pairs += [(rng.choice(unrelated), rng.choice(unrelated)) for _ in range(40)] + CRAFTED
    requests = [f"compare {a} {b}" for a, b in pairs]
    alone = 0
    for (a, b), score, other in zip(pairs, ask(LIBFUZZY, requests), ask(PPDEEP, requests)):
        score = "error" if score == "-1" else score
        source = "both" if other == score else "libfuzzy"
        alone += source == "libfuzzy"
        rows.append(f"compare a={a} b={b} score={score} source={source}")

    similar = [(ctphs[x], ctphs[y]) for family in FAMILIES
               for x, y in itertools.product(family, repeat=2)]
    unrelated = [ctphs[s] for s in MESSAGES]
    similar += [(rng.choice(unrelated), rng.choice(unrelated)) for _ in range(40)] + CRAFTED_CTPH
    for (a, b), score in zip(similar, ask(CTPH, [f"similarity {a} {b}" for a, b in similar])):
        rows.append(f"similarity a={a} b={b} score={score}")

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# ssdeep digests (libfuzzy 2.14.1 and ppdeep agree) and scores (libfuzzy;\n"
                  "# source=both where ppdeep agrees), and the CTPH digests and similarities\n"
                  "# of ctph.js 0.0.5. Written by scripts/make_ssdeep_vectors.py; do not edit.\n"
                  "# Messages are described by the rule in that script.\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(rows)} rows; {alone} scores libfuzzy's alone")


if __name__ == "__main__":
    main()
