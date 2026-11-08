#!/usr/bin/env python3
"""Write vectors/rc4_hmac.vec: Kerberos's RC4-HMAC (RFC 4757), types 23
and 24, the -138 checksum, the PRF and string-to-key.

    sh scripts/witness/rc4hmac/build.sh /opt/rc4hmacwitness
    python3 scripts/make_rc4_hmac_vectors.py [/opt/rc4hmacwitness]

**A development tool, not a test.** `tests/test_rc4_hmac.rs` and
`pytests/test_rc4_hmac.py` read the file offline.

Rows, hex fields, "-" for empty:

    s2k password= key= witnesses=
    encrypt enctype= key= usage= plain= confounder= cipher= witnesses=
    checksum key= usage= data= checksum= witnesses=
    prf key= input= output= witnesses=

`password` is the password's UTF-8. An `encrypt` row's ciphertext was
made by the first witness named, MIT Kerberos and Kerby by turns, each
under a confounder it drew itself; every other witness that has the
type opened it, and for type 23 impacket, given the confounder read
back out of it, made the same bytes. The usages include 3 and 23, which
RFC 4757 renumbers to 8 and 13, and 9, which the RFC's text renumbers
and the three keep; the lengths cross RC4-HMAC's 8 byte confounder and
a few multiples of 8 and 16. Every `checksum`, `prf` and `s2k` row is
all three's answer, agreed.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "rc4_hmac.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "rc4hmac"))
from selftest import PASSWORDS, confounder_of, hexa, witnesses  # noqa: E402

USAGES = [0, 1, 2, 3, 4, 7, 8, 9, 11, 12, 13, 23, 1024, 2**31 - 1]
LENGTHS = [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 100, 1000]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/rc4hmacwitness"
    mit, kerby, imp = witnesses(out)
    every = (mit, kerby, imp)
    rng = random.Random(4757)
    lines = []

    passwords = PASSWORDS + ["".join(chr(rng.choice([rng.randrange(0x20, 0x7f),
                                                     rng.randrange(0xa0, 0xd800),
                                                     rng.randrange(0x10000, 0x110000)]))
                                     for _ in range(rng.randrange(1, 20)))
                             for _ in range(10)]
    for pw in passwords:
        keys = {w.s2k(pw) for w in every}
        if len(keys) != 1:
            sys.exit(f"string-to-key disagrees on {pw!r}")
        lines.append(f"s2k password={hexa(pw.encode())} key={keys.pop().hex()} "
                     f"witnesses={','.join(w.name for w in every)}")

    turn = 0
    for enctype in (23, 24):
        for usage in USAGES:
            for length in LENGTHS:
                key, plain = rng.randbytes(16), rng.randbytes(length)
                maker = (mit, kerby)[turn % 2]
                turn += 1
                ct = maker.encrypt(enctype, key, usage, plain)
                names = [maker.name]
                for w in every:
                    if w is maker or enctype not in w.enctypes:
                        continue
                    if w.decrypt(enctype, key, usage, ct) != plain:
                        sys.exit(f"{w.name} does not open {maker.name}'s {enctype} {usage}")
                    names.append(w.name)
                conf = confounder_of(enctype, key, usage, ct)
                if enctype == 23 and imp.encrypt_with(key, usage, plain, conf) != ct:
                    sys.exit(f"impacket does not make {maker.name}'s ciphertext")
                lines.append(f"encrypt enctype={enctype} key={key.hex()} usage={usage} "
                             f"plain={hexa(plain)} confounder={conf.hex()} cipher={ct.hex()} "
                             f"witnesses={','.join(names)}")

    for usage in USAGES:
        for length in (0, 1, 16, 65, 1000):
            key, data = rng.randbytes(16), rng.randbytes(length)
            sums = {w.checksum(key, usage, data) for w in every}
            if len(sums) != 1:
                sys.exit(f"the checksums disagree at usage {usage}")
            lines.append(f"checksum key={key.hex()} usage={usage} data={hexa(data)} "
                         f"checksum={sums.pop().hex()} witnesses={','.join(w.name for w in every)}")

    for length in (0, 1, 15, 16, 63, 64, 65, 1000):
        key, data = rng.randbytes(16), rng.randbytes(length)
        outs = {w.prf(key, data) for w in every}
        if len(outs) != 1:
            sys.exit("the PRFs disagree")
        lines.append(f"prf key={key.hex()} input={hexa(data)} output={outs.pop().hex()} "
                     f"witnesses={','.join(w.name for w in every)}")

    header = [
        "# Kerberos RC4-HMAC (RFC 4757). Written by scripts/make_rc4_hmac_vectors.py;",
        "# do not edit. Witnesses: MIT Kerberos 1.21.3, Apache Kerby, impacket 0.13.1",
        "# (type 23 only), all agreeing; an encrypt row's maker is its first witness.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
