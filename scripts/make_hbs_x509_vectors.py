#!/usr/bin/env python3
"""Write vectors/hbs_x509.vec: HSS, XMSS and XMSS^MT certificates (RFC
9802), both ways between this library and Bouncy Castle 1.85.

    sh scripts/witness/hbsx509/build.sh /opt/hbswitness
    cargo build --release -p allcrypt-tools --bin hbs_certs
    python3 scripts/make_hbs_x509_vectors.py [/opt/hbswitness]

**A development tool, not a test.** `tests/test_hbs_x509.rs` reads the
file offline.

Rows, hex fields:

    bc scheme= params= cert= witnesses=bc-hbs
    ours scheme=hss levels= seed= id= count= cert= witnesses=bc-hbs
    ours scheme=xmss set= sk_seed= sk_prf= seed= idx= cert= witnesses=bc-hbs

A `bc` row is a self-signed certificate Bouncy Castle made with a key it
generated, `params` in its witness's form; the test reads and verifies
it. An `ours` row is a self-signed certificate this library's builder
made with the key the row's seeds and index give (`hbs_certs`), which
Bouncy Castle verified, and which the test makes again byte for byte -
HSS and XMSS signing are deterministic. Bouncy Castle is also required
to refuse each `ours` certificate with a byte of its signature changed.
"""

import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "hbs_x509.vec")
TOOL = os.path.join(ROOT, "target", "release", "hbs_certs")
sys.path.insert(0, os.path.join(HERE, "witness", "hbsx509"))
from selftest import Bc  # noqa: E402

# Bouncy Castle's keys: every hash family it has, one and two levels.
BC_HSS = [["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8"],
          ["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W4", "LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8"],
          ["LMS_SHA256_M24_H5/LMOTS_SHA256_N24_W8"],
          ["LMS_SHAKE_M32_H5/LMOTS_SHAKE_N32_W8"],
          ["LMS_SHAKE_M24_H5/LMOTS_SHAKE_N24_W4", "LMS_SHAKE_M24_H5/LMOTS_SHAKE_N24_W8"]]
BC_XMSS = [("xmss", "10/SHA256"), ("xmss", "10/SHAKE128"), ("xmss", "10/SHA512"),
           ("xmss", "10/SHAKE256/256"),
           ("xmssmt", "20/4/SHA256"), ("xmssmt", "20/2/SHA256"), ("xmssmt", "20/4/SHAKE256")]

# This library's: RFC 8554's, SP 800-208's and RFC 9858's hash families,
# up to three levels, at a fresh key and part way through it; and the
# XMSS and XMSS^MT families Bouncy Castle agrees on, at index 0 and later.
# Not SP 800-208's 192 bit sets: Bouncy Castle 1.85 pads their domain
# separator to n bytes where SP 800-208 has 4, so its signatures fail
# under the XMSS reference, Botan and this library, and ours under it.
# vectors/xmss.vec covers those sets with the reference and Botan.
OURS_HSS = [(["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8"], 0),
            (["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W1"], 31),
            (["LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W4", "LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W2"], 100),
            (["LMS_SHA256_M24_H5/LMOTS_SHA256_N24_W4"], 7),
            (["LMS_SHAKE_M32_H5/LMOTS_SHAKE_N32_W8", "LMS_SHAKE_M32_H5/LMOTS_SHAKE_N32_W8",
              "LMS_SHAKE_M32_H5/LMOTS_SHAKE_N32_W8"], 1000),
            (["LMS_SHAKE_M24_H5/LMOTS_SHAKE_N24_W8"], 1)]
OURS_XMSS = [("XMSS-SHA2_10_256", 0), ("XMSS-SHA2_10_256", 513), ("XMSS-SHAKE_10_256", 5),
             ("XMSS-SHA2_10_512", 2), ("XMSS-SHAKE256_10_256", 3), ("XMSSMT-SHA2_20/4_256", 33),
             ("XMSSMT-SHA2_20/2_256", 1024), ("XMSSMT-SHAKE_20/4_256", 0),
             ("XMSSMT-SHA2_40/8_256", 123456789)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/hbswitness"
    bc = Bc(out)
    codes = dict(line.split() for line in subprocess.run(
        [TOOL, "--types"], capture_output=True, text=True, check=True).stdout.splitlines())
    lines = []

    for levels in BC_HSS:
        params = ",".join("/".join(codes[name] for name in level.split("/")) for level in levels)
        cert = bc.ask("selfsigned", "hss", params)
        if cert.startswith("error"):
            sys.exit(f"Bouncy Castle refused HSS {levels}: {cert}")
        if bc.ask("verify", cert, cert) != "good":
            sys.exit(f"Bouncy Castle does not verify its own HSS {levels}")
        lines.append(f"bc scheme=hss params={','.join(levels)} cert={cert} witnesses=bc-hbs")
    for scheme, params in BC_XMSS:
        cert = bc.ask("selfsigned", scheme, params)
        if cert.startswith("error"):
            sys.exit(f"Bouncy Castle refused {scheme} {params}: {cert}")
        if bc.ask("verify", cert, cert) != "good":
            sys.exit(f"Bouncy Castle does not verify its own {scheme} {params}")
        lines.append(f"bc scheme={scheme} params={params} cert={cert} witnesses=bc-hbs")

    rng = random.Random(9802)
    specs = []
    for levels, count in OURS_HSS:
        m = 24 if "M24" in levels[0] else 32
        specs.append(f"ours scheme=hss levels={','.join(levels)} seed={rng.randbytes(m).hex()} "
                     f"id={rng.randbytes(16).hex()} count={count}")
    for name, idx in OURS_XMSS:
        n = 64 if name.endswith("_512") else 32
        specs.append(f"ours scheme=xmss set={name} sk_seed={rng.randbytes(n).hex()} "
                     f"sk_prf={rng.randbytes(n).hex()} seed={rng.randbytes(n).hex()} idx={idx}")
    made = subprocess.run([TOOL], input="".join(s + "\n" for s in specs), capture_output=True,
                          text=True, check=True).stdout.split()
    if len(made) != len(specs):
        sys.exit("hbs_certs did not answer every spec")
    for spec, cert in zip(specs, made):
        if bc.ask("verify", cert, cert) != "good":
            sys.exit(f"Bouncy Castle does not verify {spec}")
        bad = bytearray(bytes.fromhex(cert))
        bad[-3] ^= 0x20
        if bc.ask("verify", bad.hex(), cert) != "bad":
            sys.exit(f"Bouncy Castle verifies a changed signature for {spec}")
        if bc.ask("spki", cert) not in cert:
            sys.exit(f"Bouncy Castle writes the key of {spec} differently")
        lines.append(f"{spec} cert={cert} witnesses=bc-hbs")

    header = [
        "# HSS, XMSS and XMSS^MT certificates (RFC 9802). Written by",
        "# scripts/make_hbs_x509_vectors.py; do not edit. bc: Bouncy Castle 1.85's own;",
        "# ours: this library's, verified by Bouncy Castle 1.85.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
