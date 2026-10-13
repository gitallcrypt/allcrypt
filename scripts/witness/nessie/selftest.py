#!/usr/bin/env python3
"""Every NESSIE witness in OUT must reproduce the published vectors that
libtomcrypt's self-tests and the kernel's testmgr.h carry, both ways, a
block at a time. Run by build.sh; exits non-zero on the first failure.

    python3 selftest.py /opt/nessie
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import published  # noqa: E402

# Where each cipher's published tests are: libtomcrypt's file, its test
# function and the macros it is built with; testmgr.h's template; and
# the section of Botan's validate.dat. They are required of every
# program named <cipher>-<source>.
CIPHERS = {
    "khazad": {"block": 8, "libtomcrypt": ("khazad.c", "khazad_test", ("LTC_KHAZAD",)),
               "testmgr": "khazad_tv_template"},
    "anubis": {"block": 16,
               "libtomcrypt": ("anubis.c", "anubis_test", ("LTC_ANUBIS", "LTC_ANUBIS_TWEAK")),
               "testmgr": "anubis_tv_template"},
    "noekeon": {"block": 16, "libtomcrypt": ("noekeon.c", "noekeon_test", ("LTC_NOEKEON",))},
    "noekeon-indirect": {"block": 16, "botan": "Noekeon"},
    "shacal2": {"block": 32, "cryptopp": "shacal2.txt", "botan3": ("shacal2.vec", "SHACAL2")},
}
SOURCES = ("libtomcrypt", "linux", "reference", "botan", "cryptopp", "bc")


def vectors(out, cipher):
    where = CIPHERS[cipher]
    src = os.path.join(out, "src")
    rows = []
    if "libtomcrypt" in where:
        name, function, defined = where["libtomcrypt"]
        rows += published.libtomcrypt(open(os.path.join(src, "libtomcrypt", name)).read(),
                                      function, defined)
    if "testmgr" in where:
        rows += published.testmgr(open(os.path.join(src, "linux", "testmgr.h")).read(),
                                  where["testmgr"])
    if "botan" in where:
        rows += published.botan(open(os.path.join(src, "botan", "validate.dat")).read(),
                                where["botan"])
    if "botan3" in where:
        name, section = where["botan3"]
        rows += published.botan3(open(os.path.join(src, "botan3", name)).read(), section)
    if "cryptopp" in where:
        rows += published.cryptopp(open(os.path.join(src, "cryptopp", where["cryptopp"])).read())
    block = where["block"]
    for row in rows:
        key = row["key"][:row["keylen"]] if "keylen" in row else row["key"]
        for i in range(0, len(row["pt"]), block):
            yield key, row["pt"][i:i + block], row["ct"][i:i + block]


def ask(program, requests):
    out = subprocess.run([program], input="".join(r + "\n" for r in requests),
                         capture_output=True, text=True, check=True).stdout.split()
    return out


def main():
    out = sys.argv[1]
    for cipher in CIPHERS:
        rows = list(vectors(out, cipher))
        requests = [f"enc {k.hex()} {p.hex()}" for k, p, _ in rows]
        requests += [f"dec {k.hex()} {c.hex()}" for k, _, c in rows]
        expected = [c.hex() for _, _, c in rows] + [p.hex() for _, p, _ in rows]
        for source in SOURCES:
            program = os.path.join(out, f"{cipher}-{source}")
            if not os.path.exists(program):
                continue
            if ask(program, requests) != expected:
                sys.exit(f"{cipher}-{source} does not reproduce the published vectors")
            print(f"{cipher}-{source}: {len(rows)} published blocks, both ways")


if __name__ == "__main__":
    main()
