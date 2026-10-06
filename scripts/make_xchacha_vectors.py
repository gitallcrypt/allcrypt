#!/usr/bin/env python3
"""Write `vectors/xchacha.vec` from golang.org/x/crypto v0.37.0: HChaCha20
subkeys, XChaCha20 keystreams at block counters 0, 1 and near 2^32, and
XChaCha20-Poly1305 seals with and without associated data, at lengths
around the 64-byte block and the 16-byte Poly1305 block.

    python3 scripts/make_xchacha_vectors.py

The witness is `scripts/witness/xchachawitness`, built against a clone of
`golang/crypto` at v0.37.0 (`docs/building.md`). The draft's own vectors
are read out of `rfcs/draft-irtf-cfrg-xchacha-03.txt` by the unit tests;
these are the second opinion.
"""

import os
import random
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WITNESS = "/opt/wgwitness/xchachawitness"


def main():
    choose = random.Random(2408)
    rand = lambda n: bytes(choose.randrange(256) for _ in range(n))
    requests, records = [], []
    for _ in range(12):
        key, nonce = rand(32), rand(16)
        requests.append(f"hchacha {key.hex()} {nonce.hex()}")
        records.append(("HChaCha20", [("Key", key), ("Nonce", nonce)]))
    for counter, lengths in ((0, (1, 63, 64, 65, 200)), (1, (64, 129)),
                             (0xffffffff, (64,))):
        for length in lengths:
            key, nonce, data = rand(32), rand(24), rand(length)
            requests.append(f"stream {key.hex()} {nonce.hex()} {counter} {data.hex()}")
            records.append(("XChaCha20", [("Key", key), ("Nonce", nonce),
                                          ("Counter", counter), ("In", data)]))
    for length in (0, 1, 15, 16, 17, 63, 64, 65, 300):
        for aad_length in (0, 13):
            key, nonce, aad, data = rand(32), rand(24), rand(aad_length), rand(length)
            requests.append(f"seal {key.hex()} {nonce.hex()} {aad.hex() or '-'} "
                            f"{data.hex() or '-'}")
            records.append(("XChaCha20-Poly1305", [("Key", key), ("Nonce", nonce),
                                                   ("AD", aad), ("In", data)]))
    answers = subprocess.run([WITNESS], input="\n".join(requests) + "\n", capture_output=True,
                             text=True, check=True).stdout.split("\n")
    lines = ["# golang.org/x/crypto v0.37.0's HChaCha20, XChaCha20 and XChaCha20-Poly1305,",
             "# written by scripts/make_xchacha_vectors.py. Hex; Out is the keystream XOR In,",
             "# or the ciphertext then the 16-byte tag.", ""]
    section = None
    for (name, fields), answer in zip(records, answers):
        if name != section:
            lines += [f"[{name}]", ""]
            section = name
        for k, v in fields:
            lines.append(f"{k} = {v if isinstance(v, int) else v.hex()}")
        lines += [f"Out = {answer}", ""]
    with open(os.path.join(ROOT, "vectors", "xchacha.vec"), "w") as f:
        f.write("\n".join(lines))
    print(f"{len(records)} records")


if __name__ == "__main__":
    main()
