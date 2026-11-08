#!/usr/bin/env python3
"""Write vectors/snow3g_zuc.vec: SNOW 3G, ZUC-128, ZUC-256 and their modes.

    sh scripts/witness/snow3g_zuc/build.sh /opt/gppwitness
    python3 scripts/make_snow3g_zuc_vectors.py [/opt/gppwitness]

**A development tool, not a test.** `tests/test_snow3g_zuc.rs` reads the
file offline, and reads the published test data itself, from `rfcs/` and
`vectors/zuc256/`.

The witnesses, built by `scripts/witness/snow3g_zuc` (its build.sh says
from what): the SNOW 3G and ZUC reference implementations as CryptoMobile
carries them, Intel's intel-ipsec-mb, GmSSL, free5gc, Bouncy Castle 1.77,
the zuc crate and oxirush-security. Before anything is written every one
must reproduce every published test set it implements. Then the rows,
random inputs at lengths either side of the word, byte and block steps,
each written only when every witness that implements it gives the same
answer, and at least two do - the one exception, 128-EIA1 of an empty
message, is named in published.py:

    stream cipher= key= iv= keystream= witnesses=
    f8 alg= key= count= bearer= direction= bits= data= result= witnesses=
    f9 alg= key= count= fresh= direction= bits= data= mac= witnesses=
    zucmac tag= key= iv= bits= data= mac= witnesses=

An f8 `data` and an f9 `data` carry random bits past `bits` in their last
byte, which an f9 must ignore; an f8 `result` has them cleared. A
ZUC-256 IV is 25 bytes, the last eight holding six bits each. An f9 of
`alg=uia2` takes `fresh`; `eia1` and `eia3` take the bearer there.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "snow3g_zuc.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "snow3g_zuc"))
import published  # noqa: E402
import selftest  # noqa: E402


def zuc256_iv(rng):
    return rng.randbytes(17) + bytes(rng.randrange(64) for _ in range(8))


def requests(rng):
    reqs = []
    lengths = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 256,
               257, 1000, 4099]
    for cipher, key_len in (("snow3g", 16), ("zuc128", 16), ("zuc256", 32)):
        for n in lengths:
            iv = zuc256_iv(rng) if cipher == "zuc256" else rng.randbytes(16)
            reqs.append(published.stream(cipher, rng.randbytes(key_len), iv, n))
        # The all-zero and all-one keys and IVs.
        iv_len = 25 if cipher == "zuc256" else 16
        ones = b"\xff" * 17 + b"\x3f" * 8 if cipher == "zuc256" else b"\xff" * 16
        reqs.append(published.stream(cipher, bytes(key_len), bytes(iv_len), 64))
        reqs.append(published.stream(cipher, b"\xff" * key_len, ones, 64))
    bit_lengths = [0, 1, 2, 7, 8, 9, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 191,
                   192, 193, 255, 256, 257, 511, 512, 513, 1000, 4095, 4096, 4097, 20000]
    for bits in bit_lengths:
        data = rng.randbytes((bits + 7) // 8)
        for alg in ("uea2", "eea3"):
            reqs.append(published.f8(alg, rng.randbytes(16), rng.getrandbits(32),
                                     rng.randrange(32), rng.randrange(2), bits, data))
        if bits:
            reqs.append(published.f9("uia2", rng.randbytes(16), rng.getrandbits(32),
                                     rng.getrandbits(32), rng.randrange(2), bits, data))
        for alg in ("eia1", "eia3"):
            reqs.append(published.f9(alg, rng.randbytes(16), rng.getrandbits(32),
                                     rng.randrange(32), rng.randrange(2), bits, data))
        reqs.append(published.zucmac(32, rng.randbytes(16), rng.randbytes(16), bits, data))
        for tag in (32, 64, 128):
            reqs.append(published.zucmac(tag, rng.randbytes(32), zuc256_iv(rng), bits, data))
    # Every bearer and both directions, which move bits of the IV.
    for bearer in range(32):
        for direction in (0, 1):
            data = rng.randbytes(8)
            key, count = rng.randbytes(16), rng.getrandbits(32)
            for alg in ("uea2", "eea3"):
                reqs.append(published.f8(alg, key, count, bearer, direction, 61, data))
            for alg in ("eia1", "eia3"):
                reqs.append(published.f9(alg, key, count, bearer, direction, 61, data))
    return reqs


def row(request, answer, witnesses):
    f = request.split()
    names = ",".join(dict.fromkeys(published.short(p) for p in witnesses))
    if f[0] == "stream":
        return (f"stream cipher={f[1]} key={f[2]} iv={f[3]} keystream={answer or '-'} "
                f"witnesses={names}")
    if f[0] == "f8":
        return (f"f8 alg={f[1]} key={f[2]} count={f[3]} bearer={f[4]} direction={f[5]} "
                f"bits={f[6]} data={f[7]} result={answer or '-'} witnesses={names}")
    if f[0] == "f9":
        return (f"f9 alg={f[1]} key={f[2]} count={f[3]} fresh={f[4]} direction={f[5]} "
                f"bits={f[6]} data={f[7]} mac={answer} witnesses={names}")
    return (f"zucmac tag={f[1]} key={f[2]} iv={f[3]} bits={f[4]} data={f[5]} mac={answer} "
            f"witnesses={names}")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/gppwitness"
    selftest.check_published(out)
    reqs = requests(random.Random(20261105))
    agreed = selftest.check_agreement(out, reqs)
    lines = [row(r, *agreed[r]) for r in reqs]
    header = [
        "# SNOW 3G, ZUC-128 and ZUC-256 keystreams, UEA2 (= 128-EEA1), 128-EEA3,",
        "# UIA2, 128-EIA1, 128-EIA3 and the ZUC MACs with a raw IV. Written by",
        "# scripts/make_snow3g_zuc_vectors.py; do not edit. Random inputs, and the",
        "# all-zero and all-one keys and IVs. witnesses: who gave the answer, every",
        "# one that implements it agreeing - ref is the ETSI/SAGE reference code as",
        "# CryptoMobile carries it, then intel-ipsec-mb, GmSSL, free5gc, Bouncy Castle",
        "# 1.77, the zuc crate and oxirush-security. A keystream is the cipher over",
        "# zeros, its words big endian. The published test data is in rfcs/ and",
        "# vectors/zuc256/.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
