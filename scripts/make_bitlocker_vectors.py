#!/usr/bin/env python3
"""Write `vectors/bitlocker.vec`: BitLocker sector encryption known
answers for `tests/test_bitlocker_vectors.rs`.

No document publishes BitLocker test vectors this repository can vendor.
These come from the reference in `scripts/diff_check.py`
(`_bl_encrypt`): OpenSSL's AES through python-cryptography for the IV,
Elephant's sector key, CBC and XTS, and the two diffusers written in
Linux dm-crypt's loop shape. `diff_check.py bitlocker` sweeps the same
reference over more offsets; these rows exist so that `cargo test` on its
own, with no Python, still fails if a method changes. The BitLocker
example's tests read volumes Windows wrote.

    python3 scripts/make_bitlocker_vectors.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from diff_check import _bl_encrypt, corpus_data, keypattern  # noqa: E402

KEY_LEN = {"aes-cbc-elephant-128": 32, "aes-cbc-elephant-256": 64, "aes-cbc-128": 16,
           "aes-cbc-256": 32, "aes-xts-128": 32, "aes-xts-256": 64}

# A small offset and one past 2^32, whose high half only the 64-bit
# little-endian encoding of the offset carries; 4096-byte sectors for
# the two Elephant methods, whose diffusers then run over 1024 words.
CASES = [(method, 512, offset) for method in KEY_LEN for offset in (8192, (1 << 32) + 512)]
CASES += [("aes-cbc-elephant-128", 4096, 1 << 33), ("aes-cbc-elephant-256", 4096, 4096)]


def main():
    out = os.path.join(os.path.dirname(HERE), "vectors", "bitlocker.vec")
    with open(out, "w") as f:
        f.write("# BitLocker sector encryption, from scripts/make_bitlocker_vectors.py:\n"
                "# OpenSSL's AES and dm-crypt's diffusers. key = keypattern, plain =\n"
                "# corpus_data, as in scripts/diff_check.py. Do not edit.\n")
        for method, size, offset in CASES:
            sealed = _bl_encrypt(method, keypattern(KEY_LEN[method]), offset, corpus_data(size))
            f.write(f"\nmethod = {method}\nsize = {size}\noffset = {offset}\n"
                    f"ciphertext = {sealed.hex()}\n")
    print(f"wrote {len(CASES)} rows to {out}")


if __name__ == "__main__":
    main()
