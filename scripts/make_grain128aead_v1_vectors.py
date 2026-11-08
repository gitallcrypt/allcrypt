#!/usr/bin/env python3
"""Write vectors/grain128aead_v1.vec: Grain-128AEAD v1, as submitted to
the first two rounds of NIST's lightweight cryptography process, before
the round 3 tweak that made v2.

    sh scripts/witness/grain128aead/build.sh /opt/grainaeadwitness
    python3 scripts/make_grain128aead_v1_vectors.py [/opt/grainaeadwitness]

**A development tool, not a test.** `tests/test_grain128aead.rs` and
`pytests/test_grain128aead.py` read the file offline.

Rows, hex fields, "-" for empty:

    grain128aeadv1 key= nonce= ad= pt= ct= tag= source= witnesses=

In order:

1. the designers' 1,089 known answers, from their repository
   (`source=designers`);
2. random inputs at associated data lengths across the DER length forms
   - 0 to 127 in one byte, 128 to 255 in two, 256 and up in three, 65,536
   in four - and plaintext lengths either side of the two bytes a 32 clock
   step produces, to 1,000 bytes (`source=random`).

Every row is agreed by all three witnesses: the designers' reference and
optimised implementations and lightweight-crypto, each of which also
decrypts its answer back and refuses it with the tag's last bit flipped.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "grain128aead_v1.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "grain128aead"))
from selftest import WITNESSES_V1, ask, kat, request  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/grainaeadwitness"
    inputs = []
    for key, nonce, pt, ad, sealed in kat(out, v1=True):
        inputs.append((key, nonce, ad, pt, "designers", sealed))
    if len(inputs) != 1089:
        sys.exit(f"read {len(inputs)} known answers, not 1089")
    rng = random.Random(20190329)
    for adlen in (0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 258, 1000, 65536):
        for ptlen in (0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 100, 1000):
            if adlen == 65536 and ptlen not in (0, 17):
                continue
            inputs.append((rng.randbytes(16), rng.randbytes(12), rng.randbytes(adlen),
                           rng.randbytes(ptlen), "random", None))

    requests = [request(k, n, ad, pt) for k, n, ad, pt, _, _ in inputs]
    answers = {w: ask(out, w, requests) for w in WITNESSES_V1}
    lines = []
    for i, (key, nonce, ad, pt, source, sealed) in enumerate(inputs):
        given = {w: answers[w][i] for w in WITNESSES_V1}
        for w in WITNESSES_V1:
            if given[w].startswith("error"):
                sys.exit(f"{w} refused {requests[i][:80]}: {given[w]}")
        if len(set(given.values())) != 1:
            sys.exit(f"the witnesses disagree on {requests[i][:80]}")
        answer = bytes.fromhex(given[WITNESSES_V1[0]])
        if sealed is not None and answer != sealed:
            sys.exit(f"the witnesses do not give known answer {i + 1}")
        ct, tag = answer[:-8], answer[-8:]
        lines.append(f"grain128aeadv1 key={key.hex()} nonce={nonce.hex()} ad={ad.hex() or '-'} "
                     f"pt={pt.hex() or '-'} ct={ct.hex() or '-'} tag={tag.hex()} "
                     f"source={source} witnesses={','.join(WITNESSES_V1)}")

    header = [
        "# Grain-128AEAD v1, before the round 3 tweak. Written by",
        "# scripts/make_grain128aead_v1_vectors.py; do not edit.",
        "# source=designers: the designers' known answers; random: generated. witnesses:",
        "# the designers' reference and optimised implementations and lightweight-crypto,",
        "# all agreeing.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
