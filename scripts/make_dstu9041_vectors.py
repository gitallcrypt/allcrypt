#!/usr/bin/env python3
"""Write vectors/dstu9041.vec: DSTU 9041:2020 known answers.

    scripts/witness/dstu9041/build.sh /opt/dstu9041
    python3 scripts/make_dstu9041_vectors.py

**A development tool, not a test.** It needs both witnesses built (the
build fetches their sources once, and runs li0ard's with bun);
`tests/test_dstu9041.rs` and `pytests/test_dstu9041.py` read
`vectors/dstu9041.vec` offline.

Two implementations that share no code: uacrypt's `hazmat::dstu9041`,
in Rust, and li0ard's `dstu9041`, in TypeScript over @noble/curves
(scripts/witness/dstu9041 has both). In order, for each of E256/1 and
E512/1:

1. The standard's worked example (Г.1, Г.3), as
   `scripts/witness/dstu9041/published.py` reads it: the public key and
   the ciphertext, which both witnesses must reproduce
   (source=standard).
2. Public keys for private keys 2, 3, n - 2 and random ones, where both
   agree.
3. Ciphertexts of messages of every whole number of bytes from 1 to
   `l_max(p)/8`, of all zeros and all ones at full length, and under
   the one-time keys 2 and n - 2, each written only where both
   witnesses give the same ciphertext and both decrypt it.
4. Messages that are not whole bytes (`bits=` below a multiple of 8),
   which li0ard does not encrypt: uacrypt's ciphertext, which li0ard
   must decrypt to the same bytes (source=uacrypt).
5. Ciphertexts both refuse to decrypt: `r` of 0, 1, `p - 1`, `p` and
   above, `r` with no point, `r` of a point outside the group of order
   `n` (made here with the curve's arithmetic in Python: the inputs are
   built here, the verdicts are the witnesses'), a damaged `t`, the
   wrong private key and the wrong length.

Each witness decrypts every ciphertext written, so a row of
source=both is one both encrypt to and both decrypt.

A disagreement anywhere stops the script. Row formats, hex fields,
scalars and coordinates big endian:

    dstu9041 curve=<name> private=<e> public=<x || y> source=<standard|both>
    dstu9041 curve=<name> private=<e> public=<Q> epsilon=<ε> message=<M> bits=<l(M)> ciphertext=<r || t> source=<standard|both|uacrypt>
    dstu9041 curve=<name> private=<e> ciphertext=<C> refused=<why> source=both
"""

import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "dstu9041.vec")
OUT = os.environ.get("DSTU9041_WITNESS", "/opt/dstu9041")
sys.path.insert(0, os.path.join(HERE, "witness", "dstu9041"))
import published  # noqa: E402

PARAMS = os.path.join(ROOT, "src", "ec", "dstu9041_params.rs")


def curves():
    """The parameters src/ec/dstu9041_params.rs holds, by field bits."""
    text = open(PARAMS).read()
    out = {}
    for block in re.findall(r"    Params \{(.*?)\}", text, re.S):
        fields = dict(re.findall(r"(\w+): \"?([0-9a-f]+)\"?", block))
        bits = int(fields["bits"])
        out[bits] = {k: int(fields[k], 16) for k in ("p", "d", "n", "gx", "gy")}
        out[bits].update(l_max=int(fields["l_max"]), name=published.CURVES[bits])
    return out


# --- the curve, for building refusals' inputs only ---------------------

def add(c, P, Q):
    """x^2 + 2y^2 = 1 + d x^2 y^2, affine; None for an exceptional pair."""
    p, d = c["p"], c["d"]
    (x1, y1), (x2, y2) = P, Q
    t = d * x1 * x2 * y1 * y2 % p
    if t in (1, p - 1):
        return None
    x3 = (x1 * x2 - 2 * y1 * y2) * pow(1 - t, -1, p) % p
    y3 = (x1 * y2 + y1 * x2) * pow(1 + t, -1, p) % p
    return x3, y3


def recoverable(c, r):
    """Whether `r` gives a curve point, `v` a nonzero square."""
    p, d = c["p"], c["d"]
    if r in (0, 1, p - 1) or r >= p or (2 - d * r * r) % p == 0:
        return False
    v = (1 - r * r) * pow(2 - d * r * r, -1, p) % p
    return v != 0 and pow(v, (p - 1) // 2, p) == 1


def outside(c):
    """An `x` whose point is on the curve but not of order n: the base
    point plus the point of order 2, (p - 1, 0)."""
    return add(c, (c["gx"], c["gy"]), (c["p"] - 1, 0))[0]


def no_point(c, rng):
    while True:
        r = rng.randrange(2, c["p"] - 1)
        if not recoverable(c, r) and (2 - c["d"] * r * r) % c["p"]:
            return r


# --- the witnesses -----------------------------------------------------

def ask(lines):
    """Both witnesses' answers; a disagreement on any stops the script."""
    answers = {who: published.run(program, lines)
               for who, program in published.witnesses(OUT).items()}
    return answers["uacrypt"], answers["li0ard"]


def agreed(lines, what):
    a, b = ask(lines)
    for line, x, y in zip(lines, a, b):
        if x != y or x is None:
            sys.exit(f"{what}: the witnesses disagree or refuse: {line[:80]} -> {x} / {y}")
    return a


def main():
    rng = random.Random(0x9041)
    params = curves()
    rows = []

    for name, bits, e, q, eps, m, mbits, c in published.examples(os.path.join(OUT, "src")):
        rows.append(f"dstu9041 curve={name} private={e.hex()} public={q.hex()} source=standard")
        rows.append(f"dstu9041 curve={name} private={e.hex()} public={q.hex()} epsilon={eps.hex()} "
                    f"message={m.hex()} bits={mbits} ciphertext={c.hex()} source=standard")

    for bits, c in params.items():
        width, n, name = bits // 8, c["n"], c["name"]
        scalar = lambda v: v.to_bytes(width, "big").hex()  # noqa: E731
        privates = [2, 3, n - 2] + [rng.randrange(2, n - 1) for _ in range(9)]
        publics = agreed([f"pub {bits} {scalar(k)}" for k in privates], "public keys")
        for k, q in zip(privates, publics):
            rows.append(f"dstu9041 curve={name} private={scalar(k)} public={q} source=both")

        # Messages: every byte length, the extremes, the edge one-time keys.
        cases = []
        for length in range(1, c["l_max"] // 8 + 1):
            cases.append((rng.randbytes(length), rng.randrange(2, n - 1)))
        cases += [(bytes(c["l_max"] // 8), rng.randrange(2, n - 1)),
                  (b"\xff" * (c["l_max"] // 8), rng.randrange(2, n - 1)),
                  (b"\x00", 2), (b"\x01", n - 2)]
        keys = [(k, q) for k, q in zip(privates, publics)]
        enc = []
        for i, (m, eps) in enumerate(cases):
            k, q = keys[i % len(keys)]
            enc.append((k, q, eps, m))
        cts = agreed([f"enc {bits} {q} {scalar(eps)} {m.hex()}" for k, q, eps, m in enc],
                     "encryption")
        back = agreed([f"dec {bits} {scalar(k)} {ct}" for (k, _, _, _), ct in zip(enc, cts)],
                      "decryption")
        for (k, q, eps, m), ct, plain in zip(enc, cts, back):
            if plain != m.hex():
                sys.exit(f"a round trip lost the message on {name}")
            rows.append(f"dstu9041 curve={name} private={scalar(k)} public={q} epsilon={scalar(eps)} "
                        f"message={m.hex()} bits={8 * len(m)} ciphertext={ct} source=both")

        # Lengths in bits: uacrypt encrypts, li0ard decrypts.
        uacrypt, li0ard = (published.witnesses(OUT)[w] for w in ("uacrypt", "li0ard"))
        for mbits in (1, 2, 7, 9, 13, 63, c["l_max"] - 1):
            nbytes = (mbits + 7) // 8
            m = rng.getrandbits(mbits).to_bytes(nbytes, "big")
            k, q = keys[mbits % len(keys)]
            eps = rng.randrange(2, n - 1)
            ct = published.run(uacrypt, [f"enc {bits} {q} {scalar(eps)} {m.hex()} {mbits}"])[0]
            plain = published.run(li0ard, [f"dec {bits} {scalar(k)} {ct}"])[0]
            if ct is None or plain != m.hex():
                sys.exit(f"li0ard does not decrypt uacrypt's {mbits}-bit message on {name}")
            rows.append(f"dstu9041 curve={name} private={scalar(k)} public={q} epsilon={scalar(eps)} "
                        f"message={m.hex()} bits={mbits} ciphertext={ct} source=uacrypt")

        # Refusals.
        good = bytes.fromhex(cts[0])
        r, t = good[:width], good[width:]
        enc_key = enc[0][0]
        damaged_t = bytearray(t)
        damaged_t[rng.randrange(len(t))] ^= 1 << rng.randrange(8)
        refusals = [
            ("r-zero", bytes(width) + t),
            ("r-one", (1).to_bytes(width, "big") + t),
            ("r-p-minus-one", (c["p"] - 1).to_bytes(width, "big") + t),
            ("r-p", c["p"].to_bytes(width, "big") + t),
            ("r-all-ones", b"\xff" * width + t),
            ("r-no-point", no_point(c, rng).to_bytes(width, "big") + t),
            ("r-outside-the-group", outside(c).to_bytes(width, "big") + t),
            ("t-damaged", r + bytes(damaged_t)),
            ("short", good[:-1]),
        ]
        lines = [f"dec {bits} {scalar(enc_key)} {ct.hex()}" for _, ct in refusals]
        wrong_key = next(key for key, _ in keys if key != enc_key)
        refusals.append(("wrong-key", good))
        lines.append(f"dec {bits} {scalar(wrong_key)} {good.hex()}")
        a, b = ask(lines)
        for (why, ct), x, y, line in zip(refusals, a, b, lines):
            if x is not None or y is not None:
                sys.exit(f"{why} on {name}: a witness decrypted it: {x} / {y}")
            key = line.split(" ")[2]
            rows.append(f"dstu9041 curve={name} private={key} ciphertext={ct.hex()} "
                        f"refused={why} source=both")

    with open(OUTPUT, "w") as f:
        f.write("# DSTU 9041:2020. Written by scripts/make_dstu9041_vectors.py; do not edit.\n"
                "# Scalars, coordinates, messages and ciphertexts big endian. source=standard:\n"
                "# the worked examples Г.1 and Г.3, which both witnesses reproduce;\n"
                "# source=both: uacrypt's hazmat::dstu9041 and li0ard's dstu9041 in\n"
                "# agreement, each decrypting the other's ciphertexts; source=uacrypt: a\n"
                "# message of a length in bits li0ard does not encrypt, uacrypt's\n"
                "# ciphertext, which li0ard decrypts; refused=: both refuse.\n")
        for row in rows:
            f.write(row + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
