#!/usr/bin/env python3
"""Write vectors/gost_keywrap.vec: CryptoPro's key diversification and key
wrap (RFC 4357 sections 6.5 and 6.3) under every GOST 28147-89 parameter
set a key transport message can name.

    sh scripts/witness/gost_keywrap/build.sh /opt/gostwrapwitness
    python3 scripts/make_gost_keywrap_vectors.py [/opt/gostwrapwitness]

**A development tool, not a test.** `src/tls/gost_kex_28147.rs`'s tests
read the file offline.

The witness is gost-engine's own `keyDiversifyCryptoPro` and
`keyWrapCryptoPro`, the functions its key transport runs, with the
context initialised under each of RFC 4357's five sets and TC 26's
`param-Z` - as its server initialises it from the message's
`encryptionParamSet`. RFC 9189 Appendix A.2.2 pins the diversification
under `param-Z` alone; these rows are the other five. The UKMs include
all zeros, all ones and alternating bits, since CPDivers branches on the
UKM's bits.

Rows, hex:

    diversify set= kek= ukm= key=
    wrap set= kek= ukm= cek= wrapped=        (wrapped: UKM, key, MAC)
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(os.path.dirname(HERE), "vectors", "gost_keywrap.vec")
SETS = ["test", "a", "b", "c", "d", "z"]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/gostwrapwitness"
    rng = random.Random(20261019)
    ukms = [bytes(8), b"\xff" * 8, b"\x55\xaa" * 4] + [rng.randbytes(8) for _ in range(3)]
    requests, rows = [], []
    for s in SETS:
        for i, ukm in enumerate(ukms):
            kek = rng.randbytes(32)
            if i % 2 == 0:
                requests.append(f"diversify {s} {kek.hex()} {ukm.hex()}")
                rows.append(("diversify", s, kek, ukm, None))
            else:
                cek = rng.randbytes(32)
                requests.append(f"wrap {s} {kek.hex()} {ukm.hex()} {cek.hex()}")
                rows.append(("wrap", s, kek, ukm, cek))
    done = subprocess.run([os.path.join(out, "gost-keywrap")],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.split()
    if len(answers) != len(rows) or any(a.startswith("error") for a in answers):
        sys.exit(f"the witness answered {answers[:3]}")
    lines = []
    for (kind, s, kek, ukm, cek), answer in zip(rows, answers):
        if kind == "diversify":
            lines.append(f"diversify set={s} kek={kek.hex()} ukm={ukm.hex()} key={answer}")
        else:
            if answer[:16] != ukm.hex():
                sys.exit("the wrapped key does not begin with its UKM")
            lines.append(f"wrap set={s} kek={kek.hex()} ukm={ukm.hex()} cek={cek.hex()} "
                         f"wrapped={answer}")
    header = [
        "# CryptoPro key diversification and key wrap (RFC 4357 6.5 and 6.3) under each",
        "# GOST 28147-89 parameter set: test, CryptoPro-A to -D, and TC 26's param-Z.",
        "# Written by scripts/make_gost_keywrap_vectors.py from gost-engine's own",
        "# keyDiversifyCryptoPro and keyWrapCryptoPro (e0a500a); do not edit.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
