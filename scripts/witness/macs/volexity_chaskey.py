#!/usr/bin/env python3
"""volexity/chaskey-lts as a witness: its Chaskey-LTS block cipher, the
16 round permutation as `pi(x ^ K) ^ K`, and its inverse, through the
package's private `_chaskey_block`. The package's one public mode, CTR,
encrypts the counter with the same function, but raises OverflowError
when the counter is all ones: it increments the counter past 2^128 - 1
after the last block instead of wrapping it. Requests, one per line:

    cipher 16 <key hex> <block hex>
    decipher 16 <key hex> <block hex>

The answer is the 16 byte block in hex, or "error ...". Run as
`volexity_chaskey.py <package src directory>`.
"""

import sys

sys.path.insert(0, sys.argv[1])
from chaskey import Chaskey  # noqa: E402


def main():
    for line in sys.stdin:
        f = line.split()
        if len(f) != 4 or f[0] not in ("cipher", "decipher") or len(f[2]) != 32 \
                or len(f[3]) != 32:
            print("error request", flush=True)
        elif f[1] != "16":
            print("error unsupported", flush=True)
        else:
            c = Chaskey("ctr", bytes.fromhex(f[2]), bytes(16))
            out = c._chaskey_block(f[0] == "cipher", bytes.fromhex(f[3]))
            print(bytes(out).hex(), flush=True)


if __name__ == "__main__":
    main()
