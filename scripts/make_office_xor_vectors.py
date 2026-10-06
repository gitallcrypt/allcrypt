#!/usr/bin/env python3
"""Write `vectors/office_xor.vec` from msoffcrypto-tool's XOR obfuscation
(`msoffcrypto/method/xor_obfuscation.py`): for passwords of every length
from 1 to 15, the 16-bit verifier, the XOR key, the 16-byte array, and
data decrypted from several starting array indices.

    python3 scripts/make_office_xor_vectors.py --msoffcrypto ~/src/msoffcrypto-tool

The module is loaded from its file, so nothing of the package (or
olefile) is imported. msoffcrypto-tool has no function that returns the
verifier, only `verifypw`, which compares; the verifier is found by
asking it about every 16-bit value and requiring exactly one to match.
Its decryption is driven through `DocumentXOR.decrypt` with a record of
`count` encrypted bytes, whose array index starts at `count % 16` - the
rule Excel's records follow - so lengths are chosen to start at several
indices.
"""

import argparse
import importlib.util
import io
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(checkout):
    path = os.path.join(checkout, "msoffcrypto", "method", "xor_obfuscation.py")
    spec = importlib.util.spec_from_file_location("xor_obfuscation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DocumentXOR


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--msoffcrypto", required=True, metavar="CHECKOUT")
    args = parser.parse_args()
    xor = load(args.msoffcrypto)
    choose = random.Random(1995)
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%"
    passwords = ["VelvetSweatshop"]
    for length in range(1, 16):
        passwords.append("".join(choose.choice(letters) for _ in range(length)))
    lines = ["# msoffcrypto-tool's XOR obfuscation (method 1), written by",
             "# scripts/make_office_xor_vectors.py. Password is text; the rest hex.",
             "# Decrypted is In decrypted with the array starting at index",
             "# Length mod 16.", ""]
    for password in passwords:
        matches = [v for v in range(65536) if xor.verifypw(password, v)]
        assert len(matches) == 1, (password, matches)
        key = xor.create_xor_key_method1(password)
        array = bytes(xor.create_xor_array_method1(password))
        lines += [f"Password = {password}", f"Verifier = {matches[0]:04x}",
                  f"Key = {key:04x}", f"Array = {array.hex()}"]
        for length in (1, 7, 16, 21, 40):
            data = bytes(choose.randrange(256) for _ in range(length))
            out = xor.decrypt(password, io.BytesIO(data), [-1] * length, None, 0).read()
            lines += [f"In = {data.hex()}", f"Decrypted = {out.hex()}"]
        lines.append("")
    with open(os.path.join(ROOT, "vectors", "office_xor.vec"), "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
