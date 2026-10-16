#!/usr/bin/env python3
"""Check the eSTREAM witnesses before anything uses them.

    python3 scripts/witness/estream/selftest.py /opt/estreamwitness

  * Every published row Crypto++'s TestVectors carry for Rabbit, HC-128,
    HC-256 and SOSEMANUK reproduced by every witness that takes the
    cipher, except Crypto++'s own 286 HC-256 rows, which must be
    reproduced by Crypto++ and by neither HC-256 submission - if a
    future Crypto++ fixes its HC-256, this says so.
  * The witnesses agreeing over random keys and IVs at several lengths,
    Crypto++'s HC-256 excepted for the same reason.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import published  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/estreamwitness"
    rows = published.rows(out)
    counts = {}
    for program, ciphers in published.PROGRAMS.items():
        mine = [r for r in rows if r[0] in ciphers and not published.cryptopp_only(r)]
        got = published.ask(out, program, [published.request(c, k, v, len(s))
                                           for c, k, v, s, _ in mine])
        wrong = [r[4] for r, g in zip(mine, got) if g != r[3].hex()]
        if wrong:
            sys.exit(f"{program} does not reproduce {len(wrong)} published rows: {wrong[:3]}")
        counts[program] = len(mine)
    only = [r for r in rows if published.cryptopp_only(r)]
    if len(only) != 286:
        sys.exit(f"expected Crypto++'s 286 generated HC-256 rows, read {len(only)}")
    asked = [published.request(c, k, v, len(s)) for c, k, v, s, _ in only]
    if published.ask(out, "cryptopp-stream", asked) != [r[3].hex() for r in only]:
        sys.exit("Crypto++ no longer reproduces its own generated HC-256 rows")
    for program in ("ref-hc256-200511", "ref-hc256-200701"):
        agree = sum(g == r[3].hex() for g, r in zip(published.ask(out, program, asked), only))
        if agree:
            sys.exit(f"{program} reproduces {agree} of Crypto++'s generated HC-256 rows; "
                     "the rotated word reading may be fixed, or misread here")

    rng = random.Random(1)
    sizes = {"rabbit": (16, 0), "rabbit-iv": (16, 8), "hc128": (16, 16), "hc256": (32, 32),
             "sosemanuk": (16, 16)}
    for cipher, (key_len, iv_len) in sizes.items():
        requests = [published.request(cipher, rng.randbytes(key_len), rng.randbytes(iv_len), n)
                    for n in (1, 15, 16, 17, 64, 100, 1000, 5000)]
        if cipher == "sosemanuk":
            requests += [published.request(cipher, rng.randbytes(k), rng.randbytes(16), 100)
                         for k in (1, 5, 17, 31, 32)]
        answers = {p: published.ask(out, p, requests) for p in published.PROGRAMS
                   if published.takes(p, cipher)}
        if len({tuple(a) for a in answers.values()}) != 1:
            sys.exit(f"the {cipher} witnesses disagree: {sorted(answers)}")
    hc256 = [published.request("hc256", rng.randbytes(32), rng.randbytes(32), 32)
             for _ in range(4)]
    if published.ask(out, "cryptopp-stream", hc256) == published.ask(out, "ref-hc256-200701",
                                                                       hc256):
        sys.exit("Crypto++'s HC-256 now agrees with the submission over random keys")

    print("estream witnesses: " + ", ".join(f"{published.short(p)} {n}"
                                             for p, n in counts.items())
          + " published rows reproduced; they agree over random keys; Crypto++'s HC-256 "
          "differs from the submissions, as expected")


if __name__ == "__main__":
    main()
