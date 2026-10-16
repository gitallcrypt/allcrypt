#!/usr/bin/env python3
"""Write vectors/estream.vec: Rabbit, HC-128, HC-256 and SOSEMANUK.

    sh scripts/witness/estream/build.sh /opt/estreamwitness
    python3 scripts/make_estream_vectors.py [/opt/estreamwitness]

**A development tool, not a test.** `tests/test_estream.rs` reads the
file offline; RFC 4503's own vectors are read out of `rfcs/rfc4503.txt`
by `src/stream_ciphers/rabbit.rs`'s tests.

The witnesses, built by `scripts/witness/estream` (its build.sh says
from what): the eSTREAM submissions as SUPERCOP carries them - every
version of each - Crypto++ 8.9.0, libtomcrypt's develop branch, Bouncy
Castle 1.77 and RustCrypto. In order:

1. The published rows `scripts/witness/estream/published.py` reads out
   of Crypto++'s TestVectors (`source=` the file's own Source line),
   each reproduced by every witness that takes the cipher. Crypto++'s
   own 286 HC-256 rows are left out: nothing but Crypto++ reproduces
   them, its HC-256 reading key and IV words rotated by a byte.
2. Generated rows (`source=generated`): every cipher with random keys
   and IVs - SOSEMANUK at every key length from 1 to 32 bytes - and
   keystreams either side of the ciphers' block and table sizes, written
   only when every witness that takes the cipher gives the same bytes.

Rows, hex, "-" for an empty IV; a keystream is the cipher's output over
zeros:

    stream cipher= key= iv= keystream= source= witnesses=
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "estream.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "estream"))
import published  # noqa: E402


def witnesses(cipher):
    return [p for p in published.PROGRAMS if published.takes(p, cipher)]


def line(cipher, key, iv, keystream, source, who):
    # The vector file has one name for Rabbit; an empty IV is the IV-less
    # form.
    name = "rabbit" if cipher == "rabbit-iv" else cipher
    return (f"stream cipher={name} key={key.hex()} iv={iv.hex() or '-'} "
            f"keystream={keystream.hex()} source={source.replace(' ', '_')} "
            f"witnesses={','.join(published.short(p) for p in who)}")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/estreamwitness"
    lines = []
    rows = [r for r in published.rows(out) if not published.cryptopp_only(r)]
    for cipher in ("rabbit", "rabbit-iv", "hc128", "hc256", "sosemanuk"):
        mine = [r for r in rows if r[0] == cipher]
        who = witnesses(cipher)
        for program in who:
            got = published.ask(out, program, [published.request(c, k, v, len(s))
                                               for c, k, v, s, _ in mine])
            if got != [r[3].hex() for r in mine]:
                sys.exit(f"{program} does not reproduce the published {cipher} rows")
        lines += [line(c, k, v, s, src, who) for c, k, v, s, src in mine]

    rng = random.Random(20261016)
    plan = {
        "rabbit": [(16, 0)] * 6,
        "rabbit-iv": [(16, 8)] * 6,
        "hc128": [(16, 16)] * 6,
        "hc256": [(32, 32)] * 6,
        "sosemanuk": [(k, 16) for k in range(1, 33)],
    }
    lengths = [1, 15, 16, 17, 63, 64, 65, 2048 + 3, 4096 + 5, 8192 + 7]
    generated = []
    for cipher, shapes in plan.items():
        for i, (key_len, iv_len) in enumerate(shapes):
            n = lengths[i % len(lengths)] if cipher != "sosemanuk" else [16, 17, 100][i % 3]
            generated.append((cipher, rng.randbytes(key_len), rng.randbytes(iv_len), n))
        # The longer lengths for every cipher, past HC-256's 2048 step
        # cycle of P and Q.
        for n in lengths[6:]:
            key_len, iv_len = shapes[0]
            generated.append((cipher, rng.randbytes(key_len), rng.randbytes(iv_len), n))
    for cipher in plan:
        mine = [g for g in generated if g[0] == cipher]
        requests = [published.request(*g) for g in mine]
        who = witnesses(cipher)
        answers = {p: published.ask(out, p, requests) for p in who}
        for i, g in enumerate(mine):
            given = {answers[p][i] for p in who}
            if len(given) != 1:
                sys.exit(f"the {cipher} witnesses disagree on {requests[i][:90]}")
            lines.append(line(g[0], g[1], g[2], bytes.fromhex(given.pop()), "generated", who))

    header = [
        "# Rabbit, HC-128, HC-256 and SOSEMANUK keystreams. Written by",
        "# scripts/make_estream_vectors.py; do not edit. source: the Source line of",
        "# the Crypto++ TestVectors row it came from, or generated (seeded random",
        "# inputs). witnesses: who gave the keystream, every one that takes the cipher",
        "# agreeing - ref-* are the eSTREAM submissions as SUPERCOP carries them, then",
        "# Crypto++ 8.9.0, libtomcrypt's develop branch, Bouncy Castle 1.77 and",
        "# RustCrypto. A keystream is the cipher over zeros; Rabbit with iv=- is",
        "# Rabbit without its IV setup.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
