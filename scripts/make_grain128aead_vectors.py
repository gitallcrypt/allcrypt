#!/usr/bin/env python3
"""Write vectors/grain128aead.vec: Grain-128AEADv2.

    sh scripts/witness/grain128aead/build.sh /opt/grainaeadwitness
    python3 scripts/make_grain128aead_vectors.py [/opt/grainaeadwitness]

**A development tool, not a test.** `tests/test_grain128aead.rs` and
`pytests/test_grain128aead.py` read the file offline.

Rows, hex fields, "-" for empty:

    grain128aeadv2 key= nonce= ad= pt= ct= tag= source= witnesses=

In order:

1. the NIST final round's 1,089 known answers, as lwc-finalists carries
   them (`source=nist`);
2. random inputs at associated data lengths across the DER length forms
   - 0 to 127 in one byte, 128 to 255 in two, 256 and up in three, 65,536
   in four - and plaintext lengths either side of the two bytes a 32 clock
   step produces, to 1,000 bytes (`source=random`).

Every row is agreed by every witness that answers it: lwc-finalists and
the grain-128aeadv2 crate always, each of which also decrypts its answer
back, and Bouncy Castle 1.77 where its little-endian length bytes are the
DER encoding - below 256 bytes of associated data, and at lengths whose
bytes read the same both ways.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "grain128aead.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "grain128aead"))
from selftest import WITNESSES, ask, der_length, kat, request  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/grainaeadwitness"
    inputs = []
    for key, nonce, pt, ad, sealed in kat(out):
        inputs.append((key, nonce, ad, pt, "nist", sealed))
    if len(inputs) != 1089:
        sys.exit(f"read {len(inputs)} known answers, not 1089")
    rng = random.Random(20210517)
    for adlen in (0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 258, 1000, 65536):
        for ptlen in (0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 100, 1000):
            if adlen == 65536 and ptlen not in (0, 17):
                continue
            inputs.append((rng.randbytes(16), rng.randbytes(12), rng.randbytes(adlen),
                           rng.randbytes(ptlen), "random", None))

    requests = [request(k, n, ad, pt) for k, n, ad, pt, _, _ in inputs]
    answers = {w: ask(out, w, requests) for w in WITNESSES}
    lines = []
    for i, (key, nonce, ad, pt, source, sealed) in enumerate(inputs):
        given = {w: answers[w][i] for w in WITNESSES}
        bc_reads_der = der_length(len(ad)) == der_length(len(ad), little=True)
        names = [w for w in WITNESSES if w != "bc-grain" or bc_reads_der]
        for w in WITNESSES:
            if given[w].startswith("error"):
                sys.exit(f"{w} refused {requests[i][:80]}: {given[w]}")
        if len({given[w] for w in names}) != 1:
            sys.exit(f"the witnesses disagree on {requests[i][:80]}")
        if not bc_reads_der and given["bc-grain"] == given["rweather-grain"]:
            sys.exit(f"bc-grain agrees at {len(ad)} bytes of associated data")
        answer = bytes.fromhex(given[names[0]])
        if sealed is not None and answer != sealed:
            sys.exit(f"the witnesses do not give known answer {i + 1}")
        ct, tag = answer[:-8], answer[-8:]
        lines.append(f"grain128aeadv2 key={key.hex()} nonce={nonce.hex()} ad={ad.hex() or '-'} "
                     f"pt={pt.hex() or '-'} ct={ct.hex() or '-'} tag={tag.hex()} "
                     f"source={source} witnesses={','.join(names)}")

    header = [
        "# Grain-128AEADv2. Written by scripts/make_grain128aead_vectors.py; do not edit.",
        "# source=nist: the NIST final round's known answers; random: generated. witnesses:",
        "# lwc-finalists and the grain-128aeadv2 crate, and Bouncy Castle 1.77 where its",
        "# length encoding is DER's, all agreeing.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
