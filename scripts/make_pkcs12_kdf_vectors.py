#!/usr/bin/env python3
"""Write `vectors/pkcs12_kdf.vec`: the PKCS#12 KDF (RFC 7292 appendix B.2)
as OpenSSL's `PKCS12KDF` computes it, through `openssl kdf`.

    python3 scripts/make_pkcs12_kdf_vectors.py

OpenSSL's KDF takes the password as raw bytes, so each row's password is
handed over as the BMPString already - UTF-16 big endian with a two byte
NUL, or nothing at all for the empty password, which is OpenSSL's own
reading of it. The rows cross the hash's block (`v`, 64 or 128 bytes)
in the salt and the password, and its output (`u`) in the length, where
the KDF's two loops turn over; and they take every ID.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "vectors", "pkcs12_kdf.vec")


def bmp(text):
    return text.encode("utf-16-be") + b"\x00\x00" if text else b""


def openssl_kdf(digest, password, salt, purpose, iterations, length):
    args = ["openssl", "kdf", "-keylen", str(length), "-kdfopt", f"digest:{digest}",
            "-kdfopt", f"hexsalt:{salt.hex()}", "-kdfopt", f"iter:{iterations}",
            "-kdfopt", f"id:{purpose}", "-binary"]
    # An empty `hexpass:` is refused as malformed; `pass:` with nothing
    # after it is the empty password.
    args[4:4] = ["-kdfopt", f"hexpass:{password.hex()}" if password else "pass:"]
    return subprocess.run(args + ["PKCS12KDF"], check=True, capture_output=True).stdout


def main():
    version = subprocess.run(["openssl", "version"], check=True, capture_output=True,
                             text=True).stdout.strip()
    rows = []
    passwords = ["", "smeg", "queeg", "correct horse battery staple",
                 "пароль", "x" * 31, "y" * 32, "z" * 63, "w" * 64]
    salts = [bytes.fromhex("0a58cf64530d823f"), bytes(range(1, 21)), bytes(range(64)),
             bytes(range(100, 230))]
    count = 0
    for digest in ("SHA1", "SHA256", "SHA512", "MD5", "SHA384"):
        for i, password in enumerate(passwords):
            salt = salts[i % len(salts)]
            purpose = 1 + i % 3
            iterations = (1, 2, 1000, 2048)[i % 4]
            length = (24, 8, 20, 32, 64, 65, 100, 129, 1)[i % 9]
            out = openssl_kdf(digest, bmp(password), salt, purpose, iterations, length)
            assert len(out) == length
            rows.append(f"hash={digest.lower()} password={bmp(password).hex() or '-'} "
                        f"salt={salt.hex()} id={purpose} iterations={iterations} "
                        f"out={out.hex()}")
            count += 1
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# The PKCS#12 KDF (RFC 7292 B.2), as OpenSSL's PKCS12KDF computes\n"
                f"# it: {version}.\n"
                "# Written by scripts/make_pkcs12_kdf_vectors.py. Do not edit.\n"
                "# password is the BMPString the KDF takes, '-' for none.\n")
        f.write(f"# rows: {count}\n")
        for row in rows:
            f.write(row + "\n")
    print(f"{count} rows to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
