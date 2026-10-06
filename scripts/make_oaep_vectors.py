#!/usr/bin/env python3
"""Vendor Wycheproof's RSA-OAEP decryption vectors.

    git clone --depth 1 https://github.com/C2SP/wycheproof ~/src/wycheproof
    python3 scripts/make_oaep_vectors.py --wycheproof ~/src/wycheproof

Writes `vectors/rsa_oaep.vec`. A development tool: the gate never runs it
and needs no network. What ships is the file it writes.

## What is kept

Every group of every two-prime `rsa_oaep_*_test.json` in
`testvectors_v1`: the eleven 2048-bit files, six 3072-bit and four
4096-bit, each one hash and MGF1 hash, and `rsa_oaep_misc_test.json`'s
groups up to 2048 bits, which pair every hash with every MGF1 hash - the
combinations the single-pair files never reach. The misc file's larger
groups repeat those pairings at sizes the 3072 and 4096-bit files
already cover, and would double the file. The three-prime files are
left out: the library's RSA keys have two primes.

Each group keeps the key as `n`, `e`, `p` and `q` - the reader rebuilds
the rest, which is itself a check - and each test its id, verdict,
flags, comment, label, ciphertext and message.

## The encoded message, and where it comes from

Each test whose ciphertext is a reduced integer of the modulus' length
also carries `em = c^d mod n`, computed here with Python's own
integers. The Rust test checks the OAEP decoding against `em` for every
case - fast, and it says *which* layer is wrong when one is - and runs
the whole decryption, private operation included, on a subset whose
cost a debug build can carry. `em` is derived data, not Wycheproof's,
and the reader checks it against the private operation where it runs
that.
"""

from __future__ import annotations

import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "vectors" / "rsa_oaep.vec"

HASHES = {"SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256", "SHA-384": "sha384",
          "SHA-512": "sha512", "SHA-512/224": "sha512_224", "SHA-512/256": "sha512_256"}


def even_hex(value: int) -> str:
    text = f"{value:x}"
    return "0" + text if len(text) % 2 else text


def files(directory: pathlib.Path) -> list[pathlib.Path]:
    found = sorted(directory.glob("rsa_oaep_*_test.json"))
    if not found:
        raise SystemExit(f"no rsa_oaep_*_test.json in {directory}")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--wycheproof", required=True, type=pathlib.Path,
                        help="a checkout of github.com/C2SP/wycheproof")
    args = parser.parse_args()
    directory = args.wycheproof / "testvectors_v1"

    out = ["# RSA-OAEP decryption vectors from Wycheproof (C2SP/wycheproof,",
           "# testvectors_v1), written by scripts/make_oaep_vectors.py. Do not",
           "# edit: every verdict here is Wycheproof's.",
           "#",
           "# `em` is c^d mod n computed by the script with Python's integers,",
           "# for the tests whose ciphertext is a reduced integer of the right",
           "# length; it is derived data, not Wycheproof's. The script's",
           "# docstring says what was kept and why.",
           "#",
           "# A section is `[file group bits hash mgf-hash count]`; `-` is empty."]
    total = 0
    for path in files(directory):
        document = json.loads(path.read_text())
        misc = path.name == "rsa_oaep_misc_test.json"
        for number, group in enumerate(document["testGroups"]):
            if group["type"] != "RsaesOaepDecrypt" or group["mgf"] != "MGF1":
                raise SystemExit(f"{path.name}: group {number} is {group['type']}")
            if misc and group["keySize"] > 2048:
                continue
            key = group["privateKey"]
            n = int(key["modulus"], 16)
            d = int(key["privateExponent"], 16)
            p, q = int(key["prime1"], 16), int(key["prime2"], 16)
            if p * q != n:
                raise SystemExit(f"{path.name}: group {number} is not a two-prime key")
            size = (n.bit_length() + 7) // 8
            tests = group["tests"]
            out += ["", f"[{path.stem} {number} {group['keySize']} {HASHES[group['sha']]} "
                        f"{HASHES[group['mgfSha']]} {len(tests)}]",
                    f"n = {even_hex(n)}",
                    f"e = {even_hex(int(key['publicExponent'], 16))}",
                    f"p = {even_hex(p)}",
                    f"q = {even_hex(q)}"]
            for test in tests:
                ct = bytes.fromhex(test["ct"])
                fields = [("tcId", str(test["tcId"])), ("result", test["result"]),
                          ("flags", ",".join(test["flags"]) or "-"),
                          ("comment", test["comment"] or "-"),
                          ("label", test["label"] or "-"), ("ct", test["ct"] or "-"),
                          ("msg", test["msg"] or "-")]
                c = int.from_bytes(ct, "big")
                if len(ct) == size and c < n:
                    fields.append(("em", pow(c, d, n).to_bytes(size, "big").hex()))
                out.append("")
                out += [f"{name} = {value}" for name, value in fields]
                total += 1
    OUT.write_text("\n".join(out) + "\n")
    print(f"{total} tests -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
