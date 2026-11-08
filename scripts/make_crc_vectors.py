#!/usr/bin/env python3
"""Write vectors/crc.vec: CRCs from their parameters, the catalogue's and
random ones.

    sh scripts/witness/crc/build.sh /opt/crcwitness
    python3 scripts/make_crc_vectors.py [/opt/crcwitness]

**A development tool, not a test.** `tests/test_crc.rs` and
`pytests/test_crc.py` read the file offline.

Messages first, then models, then rows, hex fields, "-" for empty:

    msg n= data=
    model n= name= width= poly= init= refin= refout= xorout=
    crc model= msg= value= witnesses=

The models are every entry of the catalogue of parametrised CRC
algorithms that its two transcriptions agree on (`name` the catalogue's,
lowercase), each over every message, then two random parameter sets at
every width from 1 to 128 (`name=-`), each over eight of the messages -
polynomials odd and, one set in eight, even; init and xorout zero, all
ones or random; refin and refout in all four combinations.

Witnesses, from scripts/witness/crc: pycrc 0.10.0's bit-by-bit and
bit-by-bit-fast algorithms, crccheck 1.3.0 and the crc 3.4.0 crate answer
every row and must agree; pycrc's table-driven algorithm, which refuses a
width below 8, and crcmod 1.7, which takes widths 8, 16, 24, 32 and 64
reflected in and out alike, are witnesses where they answer, and must
agree too - except pycrc's bit-by-bit algorithm under an even polynomial
with a non-zero init. That algorithm feeds the message through the register
followed by `width` zero bits, so it starts from the register that the
same steps would take to init, which it finds by running them backwards; a
step backwards reads whether the polynomial went in from the register's low
bit, which only an odd polynomial sets, so under an even one the start it
finds is the wrong one, and its answer is wrong without a word. Those rows
leave it out, and it must disagree on every one of them.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "crc.vec")
WITNESS = os.path.join(HERE, "witness", "crc")
sys.path.insert(0, WITNESS)
from catalogue import entries, request  # noqa: E402
from selftest import EVERYTHING, WITNESSES, ask  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/crcwitness"
    subprocess.run([sys.executable, os.path.join(WITNESS, "selftest.py"), out], check=True)
    agreed, _ = entries(out)
    if len(agreed) != 112:
        sys.exit(f"{len(agreed)} catalogue entries agreed, not 112")
    rng = random.Random(19930819)
    messages = [b"123456789", b"", bytes(64), b"\xff" * 64]
    for length in (1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
                   255, 256, 1000):
        messages.append(rng.randbytes(length))
    models = [(name.lower(), f) for name, f in agreed]
    for width in range(1, 129):
        top = (1 << width) - 1
        for k in range(2):
            poly = rng.getrandbits(width) | 1
            if rng.randrange(8) == 0 and width > 1:
                poly &= ~1
            fixed = rng.choice([0, top, rng.getrandbits(width)]), rng.choice(
                [0, top, rng.getrandbits(width)])
            refin, refout = [(False, False), (True, True), (True, False),
                             (False, True)][(width + 2 * k + rng.randrange(2)) % 4]
            models.append(("-", {"width": width, "poly": poly, "init": fixed[0],
                                 "refin": refin, "refout": refout, "xorout": fixed[1]}))
    some = [0, 1, 4, 6, 18, 19, 21, 25]
    cases = [(m, n) for m, (name, _) in enumerate(models)
             for n in (range(len(messages)) if name != "-" else some)]
    requests = [request(models[m][1], messages[n]) for m, n in cases]
    answers = {w: ask(out, w, requests) for w in WITNESSES}
    rows = []
    for i, (m, n) in enumerate(cases):
        given = {}
        f = models[m][1]
        backwards = f["poly"] % 2 == 0 and f["init"] != 0
        for w in WITNESSES:
            if w == "pycrc-bbb" and backwards:
                continue
            a = answers[w][i]
            if a.startswith("error"):
                if w in EVERYTHING:
                    sys.exit(f"{w} refused {requests[i][:80]}: {a}")
                continue
            given[w] = a
        if backwards and answers["pycrc-bbb"][i] in given.values():
            sys.exit(f"pycrc-bbb agrees on {requests[i][:80]}")
        if len(set(given.values())) != 1:
            sys.exit(f"the witnesses disagree on {requests[i][:80]}: {given}")
        if n == 0 and models[m][0] != "-" and int(given["rust-crc"], 16) != f["check"]:
            sys.exit(f"{models[m][0]}'s check value is not reproduced")
        rows.append(f"crc model={m} msg={n} value={given['rust-crc']} "
                    f"witnesses={','.join(given)}")

    lines = [
        "# CRCs from their parameters. Written by scripts/make_crc_vectors.py; do not edit.",
        "# model: the catalogue of parametrised CRC algorithms' entries (name lowercase), then",
        "# random parameters at every width (name=-); poly, init and xorout hex, unreflected.",
        "# value: the CRC in ceil(width / 8) bytes, big endian. witnesses: pycrc's three",
        "# algorithms, crccheck, crcmod and the crc crate - every one that took the row, all",
        "# agreeing.",
        f"# messages: {len(messages)}, models: {len(models)}, rows: {len(rows)}",
    ]
    lines += [f"msg n={n} data={m.hex() or '-'}" for n, m in enumerate(messages)]
    for m, (name, f) in enumerate(models):
        d = (f["width"] + 3) // 4
        lines.append(f"model n={m} name={name} width={f['width']} poly={f['poly']:0{d}x} "
                     f"init={f['init']:0{d}x} refin={int(f['refin'])} "
                     f"refout={int(f['refout'])} xorout={f['xorout']:0{d}x}")
    lines += rows
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"wrote {OUTPUT}: {len(messages)} messages, {len(models)} models, {len(rows)} rows")


if __name__ == "__main__":
    main()
