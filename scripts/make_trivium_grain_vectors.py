#!/usr/bin/env python3
"""Write vectors/trivium_grain.vec: Trivium, Grain v1 and Grain-128.

    sh scripts/witness/trivium_grain/build.sh /opt/hwwitness
    python3 scripts/make_trivium_grain_vectors.py [/opt/hwwitness]

**A development tool, not a test.** `tests/test_trivium_grain.rs` reads
the file offline, and reads the eSTREAM vectors in `vectors/estream/`
itself.

The witnesses, built by `scripts/witness/trivium_grain` (its build.sh
says from what): the eSTREAM Trivium submission, pedroalbanese/trivium,
the trivium crate, the Grain v1 reference, gSTREAM's word-wide Grain v1,
Bouncy Castle 1.77 and the grain128 crate. Before anything is written
every one must reproduce every eSTREAM vector it takes. Then the rows,
random keys and IVs at keystream lengths either side of the 8, 2 and 4
byte steps the three ciphers are computed in here and far past their
set-up, each written only when every witness that can answer gives the
same bytes - a Trivium IV shorter than ten bytes put to the witnesses
that take only ten with zero bytes in front, so those rows have three
witnesses and not one:

    stream cipher= key= iv= keystream= witnesses=
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "trivium_grain.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "trivium_grain"))
import published  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/hwwitness"
    rows = published.published()
    for cipher in ("trivium", "grainv1", "grain128"):
        mine = [v for c, v, _ in rows if c == cipher]
        for v, given in zip(mine, published.ask_all(
                out, cipher, [(v["key"], v["iv"], v["length"]) for v in mine])):
            for program, got in given.items():
                if got.startswith("error") or not published.matches(v, bytes.fromhex(got)):
                    sys.exit(f"{program} does not reproduce {cipher} vector "
                             f"{v['set']}/{v['vector']}")

    rng = random.Random(20261105)
    lengths = [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 1000, 4099]
    shapes = {"trivium": [(10, 10), (10, 8), (10, 6), (10, 4)], "grainv1": [(10, 8)],
              "grain128": [(16, 12)]}
    lines = []
    for cipher, sizes in shapes.items():
        inputs = []
        for key_len, iv_len in sizes:
            chosen = lengths if (key_len, iv_len) == sizes[0] else lengths[::4] + [4099]
            inputs += [(rng.randbytes(key_len), rng.randbytes(iv_len), n) for n in chosen]
        # The all-zero and all-one keys and IVs, whose registers start
        # sparse or full.
        k, v = sizes[0]
        inputs += [(bytes(k), bytes(v), 100), (b"\xff" * k, b"\xff" * v, 100)]
        for (key, iv, n), given in zip(inputs, published.ask_all(out, cipher, inputs)):
            if len(given) < 2 or len(set(given.values())) != 1 or \
                    next(iter(given.values())).startswith("error"):
                sys.exit(f"the {cipher} witnesses disagree on {key.hex()} {iv.hex()} {n}: "
                         f"{sorted(given)}")
            lines.append(f"stream cipher={cipher} key={key.hex()} iv={iv.hex()} "
                         f"keystream={next(iter(given.values()))} "
                         f"witnesses={','.join(published.short(p) for p in given)}")

    header = [
        "# Trivium, Grain v1 and Grain-128 keystreams. Written by",
        "# scripts/make_trivium_grain_vectors.py; do not edit. Random keys and IVs,",
        "# and the all-zero and all-one ones. witnesses: who gave the keystream, every",
        "# one that can answer agreeing - ref-* are the eSTREAM submissions and",
        "# reference implementations, then pedroalbanese/trivium, gSTREAM, Bouncy",
        "# Castle 1.77 and the trivium and grain128 crates. A keystream is the cipher",
        "# over zeros. The eSTREAM vectors themselves are in vectors/estream/.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
