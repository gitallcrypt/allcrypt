#!/usr/bin/env python3
"""Write `vectors/pkcs12_kdf_gost.vec`: the PKCS#12 KDF (RFC 7292
appendix B.2) over GOST 34.311-95, as OpenSSL's `PKCS12_key_gen_utf8`
computes it with dstu-engine's hash.

    scripts/witness/dstuengine/build.sh /opt/dstuengine
    python3 scripts/make_pkcs12_kdf_gost_vectors.py

**A development tool, not a test.** GOST 34.311's block is 32 bytes, so
the KDF's `v` is 32 here where every hash in `vectors/pkcs12_kdf.vec`
has 64 or 128; this is the MAC key derivation of the PKCS#12 files
Ukrainian software writes. OpenSSL converts the password to a BMPString
itself - UTF-16 big endian with a two-byte NUL, the NUL alone for the
empty password - and the rows record the BMPString, in the format of
`vectors/pkcs12_kdf.vec`. They cross `v` in the salt and the password,
the output's 32 bytes in the length, and take every ID.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "vectors", "pkcs12_kdf_gost.vec")
WITNESS = os.environ.get("DSTUENGINE_WITNESS", "/opt/dstuengine")


def engine(password, salt, purpose, iterations, length):
    env = dict(os.environ, DSTU_ENGINE=f"{WITNESS}/dstu.so")
    out = subprocess.run([f"{WITNESS}/dstuengine-witness", "p12kdf", password or "-", salt.hex(),
                          str(iterations), str(length), str(purpose)],
                         check=True, capture_output=True, text=True, env=env).stdout.strip()
    if out.startswith("error"):
        sys.exit(out)
    return bytes.fromhex(out)


def main():
    passwords = ["", "a", "smeg", "testplat2021", "пароль", "x" * 15, "y" * 16, "z" * 17,
                 "w" * 31, "v" * 32, "correct horse battery staple"]
    salts = [bytes(range(1, 9)), bytes(range(32)), bytes(range(33)), bytes(range(64)),
             bytes(range(100, 165))]
    rows = []
    for i, password in enumerate(passwords):
        for j, salt in enumerate(salts):
            purpose = 1 + (i + j) % 3
            iterations = (1, 2, 1000)[(i + 2 * j) % 3]
            length = (1, 8, 24, 31, 32, 33, 64, 65, 100)[(i + j) % 9]
            out = engine(password, salt, purpose, iterations, length)
            if len(out) != length:
                sys.exit(f"the engine gave {len(out)} bytes for {length}")
            bmp = password.encode("utf-16-be") + b"\x00\x00"
            rows.append(f"hash=gost34311 password={bmp.hex()} salt={salt.hex()} id={purpose} "
                        f"iterations={iterations} out={out.hex()}")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# The PKCS#12 KDF (RFC 7292 B.2) over GOST 34.311-95, as OpenSSL's\n"
                "# PKCS12_key_gen_utf8 computes it with dstu-engine's hash (v = 32).\n"
                "# Written by scripts/make_pkcs12_kdf_gost_vectors.py. Do not edit.\n"
                "# password is the BMPString the KDF takes.\n"
                f"# rows: {len(rows)}\n")
        for row in rows:
            f.write(row + "\n")
    print(f"{len(rows)} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
