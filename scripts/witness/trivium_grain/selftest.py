#!/usr/bin/env python3
"""Check the Trivium and Grain witnesses before anything uses them.

    python3 scripts/witness/trivium_grain/selftest.py /opt/hwwitness

  * Every eSTREAM vector in `vectors/estream/` reproduced - every
    stretch and the xor-digest, so every byte - by every witness that
    takes its key and IV, a Trivium IV shorter than ten bytes put to the
    ten-byte-only witnesses with zero bytes in front.
  * The witnesses agreeing over random keys and IVs at several lengths.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import published  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/hwwitness"
    rows = published.published()
    counts = {}
    for cipher in ("trivium", "grainv1", "grain128"):
        mine = [v for c, v, _ in rows if c == cipher]
        answers = published.ask_all(out, cipher, [(v["key"], v["iv"], v["length"]) for v in mine])
        for v, given in zip(mine, answers):
            if len(given) < 2:
                sys.exit(f"{cipher} {v['set']}/{v['vector']}: only {sorted(given)} answer")
            for program, got in given.items():
                if got.startswith("error") or not published.matches(v, bytes.fromhex(got)):
                    sys.exit(f"{program} does not reproduce {cipher} vector "
                             f"{v['set']}/{v['vector']} (IV of {len(v['iv'])} bytes)")
                counts[program] = counts.get(program, 0) + 1

    rng = random.Random(1)
    shapes = {"trivium": [(10, 10), (10, 8), (10, 6), (10, 4)], "grainv1": [(10, 8)],
              "grain128": [(16, 12)]}
    for cipher, sizes in shapes.items():
        inputs = [(rng.randbytes(k), rng.randbytes(v), n) for k, v in sizes
                  for n in (1, 7, 8, 9, 63, 64, 65, 1000, 5000)]
        for (key, iv, n), given in zip(inputs, published.ask_all(out, cipher, inputs)):
            if len(given) < 2 or len(set(given.values())) != 1:
                sys.exit(f"the {cipher} witnesses disagree on a {len(iv)} byte IV at {n} "
                         f"bytes: {sorted(given)}")

    print("trivium_grain witnesses: " + ", ".join(f"{published.short(p)} {n}"
                                                  for p, n in counts.items())
          + " eSTREAM vectors reproduced; they agree over random keys")


if __name__ == "__main__":
    main()
