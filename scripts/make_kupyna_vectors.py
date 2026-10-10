#!/usr/bin/env python3
"""Write vectors/kupyna.vec: Kupyna (DSTU 7564:2014) known answers.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/kupyna/build.sh /opt/kupyna
    python3 scripts/make_kupyna_vectors.py

**A development tool, not a test.** It needs both witnesses built (the
second fetches the reference implementation once and compiles it);
`tests/test_kupyna.rs` reads `vectors/kupyna.vec` offline.

Two implementations that share no code: the reference implementation by
the hash's authors (Roman-Oliynykov/Kupyna-reference), driven through
`scripts/witness/kupyna/driver.c`, and Bouncy Castle 1.77's
`DSTU7564Digest`, which offers the 256, 384 and 512-bit hashes. In
order:

1. The standard's example hashes, read out of the reference's `main.c`
   with the call each one checks. Those over whole bytes are recorded,
   and both witnesses must reproduce each one Bouncy Castle has a size
   for; the reference must reproduce all of them. The examples over
   510, 655, 33 and 1 bits are left out: this library hashes bytes.
2. For 256, 384 and 512 bits, messages of lengths around both block
   sizes (64 and 128 bytes) where both witnesses agree.
3. For the other sizes the standard allows (any multiple of 8 bits up
   to 512), a few messages each from the reference alone, since Bouncy
   Castle does not offer them; `source=reference` marks those rows.

A disagreement anywhere stops the script. Row format, hex fields:

    kupyna bits=<n> msg=<hex, - if empty> digest=<hex> source=<standard|both|reference>
"""

import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "kupyna.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
REF = os.environ.get("KUPYNA_WITNESS", "/opt/kupyna")
BC_SIZES = (256, 384, 512)


def h(b):
    return b.hex() or "-"


def reference(bits, messages):
    stdin = "".join(h(m) + "\n" for m in messages)
    out = subprocess.run([f"{REF}/kupyna-witness", str(bits)], input=stdin, check=True,
                         capture_output=True, text=True).stdout.split("\n")[:len(messages)]
    return checked("the reference", out)


def bouncycastle(bits, messages):
    stdin = "".join(h(m) + "\n" for m in messages)
    out = subprocess.run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness",
                          f"kupyna-{bits}"], input=stdin, check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(messages)]
    return checked("Bouncy Castle", out)


def checked(who, out):
    for line in out:
        if line.startswith("error"):
            sys.exit(f"{who} refused a row: {line}")
    return [bytes.fromhex(line) for line in out]


def both(bits, messages):
    a, b = reference(bits, messages), bouncycastle(bits, messages)
    for m, x, y in zip(messages, a, b):
        if x != y:
            sys.exit(f"the witnesses disagree: kupyna-{bits} of {m.hex()}: {x.hex()} != {y.hex()}")
    return a


def standard_examples():
    """(hash bits, message, digest) for each byte-aligned example."""
    text = open(os.path.join(REF, "main.c")).read()
    arrays = {name: bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", body))
              for name, body in re.findall(r"uint8_t (\w+)\[[^\]]*\] = \{([^}]*)\}", text)}
    out = []
    bits = None
    calls = re.finditer(r"KupynaInit\((\d+), &ctx\)|KupynaHash\(&ctx, (\w+), (\d+), hash_code\);"
                        r"|CHECK\((\w+), (\d+)\)", text)
    pending = None
    for m in calls:
        if m.group(1):
            bits = int(m.group(1))
        elif m.group(2):
            pending = (m.group(2), int(m.group(3)))
        else:
            source, nbits = pending
            if nbits % 8 == 0:
                out.append((bits, arrays[source][:nbits // 8], arrays[m.group(4)]))
            pending = None
    if len(out) < 14:
        sys.exit(f"expected the standard's examples in main.c, found {len(out)}")
    return out


def main():
    rows = []
    for bits, msg, digest in standard_examples():
        if reference(bits, [msg])[0] != digest:
            sys.exit(f"the reference misses its own example: kupyna-{bits} of {len(msg)} bytes")
        if bits in BC_SIZES and bouncycastle(bits, [msg])[0] != digest:
            sys.exit(f"Bouncy Castle misses an example: kupyna-{bits} of {len(msg)} bytes")
        rows.append(f"kupyna bits={bits} msg={h(msg)} digest={digest.hex()} source=standard")

    rng = random.Random(0x4B5550)
    lengths = [0, 1, 3, 51, 52, 53, 63, 64, 65, 115, 116, 117, 127, 128, 129, 200, 1000]
    for bits in BC_SIZES:
        messages = [rng.randbytes(n) for n in lengths] + [bytes(64), b"\xff" * 128]
        for m, d in zip(messages, both(bits, messages)):
            rows.append(f"kupyna bits={bits} msg={h(m)} digest={d.hex()} source=both")

    for bits in (8, 48, 128, 160, 224, 248, 264, 304, 448, 504):
        messages = [b"", rng.randbytes(1), rng.randbytes(64), rng.randbytes(130)]
        for m, d in zip(messages, reference(bits, messages)):
            rows.append(f"kupyna bits={bits} msg={h(m)} digest={d.hex()} source=reference")

    with open(OUTPUT, "w") as f:
        f.write("# Kupyna (DSTU 7564:2014). Written by scripts/make_kupyna_vectors.py;\n"
                "# do not edit. source=standard: the standard's examples, which both\n"
                "# witnesses reproduce where they have the size; source=both: the\n"
                "# reference implementation and Bouncy Castle 1.77 in agreement;\n"
                "# source=reference: sizes Bouncy Castle does not offer.\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
