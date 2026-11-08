#!/usr/bin/env python3
"""pyhsslms 2.0.0 (Russ Housley's) as a witness, under the request lines
selftest.py describes. The second argument is the directory it was
installed into.

A tree is its LmsPrivateKey from SEED and I at the leaf asked for. It
draws the randomiser C at random, so for the one signature the module's
`randBytes` is replaced by a function giving the C that RFC 9858's
examples and hash-sigs use, H(I || u32str(q) || u16str(0xfffd) ||
u8str(0xff) || SEED), computed with pyhsslms's own H; everything after
C is pyhsslms's. Its hierarchies draw every tree below the top at random,
so it signs no `hss` request; it verifies any.
"""

import sys

sys.path.insert(0, sys.argv[1])
import pyhsslms.pyhsslms as lms  # noqa: E402


def tree(f):
    if len(f) != 6:
        return "error request"
    lms_type, ots_type = int(f[1]).to_bytes(4, "big"), int(f[2]).to_bytes(4, "big")
    if lms_type not in lms.lms_params or ots_type not in lms.lmots_params:
        return "error unsupported"
    alg, n, _, _, _ = lms.lmots_params[ots_type]
    seed_i = bytes.fromhex(f[3])
    q = int(f[4])
    message = b"" if f[5] == "-" else bytes.fromhex(f[5])
    seed, ident = seed_i[:n], seed_i[n:]
    key = lms.LmsPrivateKey(lms_type=lms_type, lmots_type=ots_type, SEED=seed, I=ident, q=q)
    c = lms.H(alg, ident + q.to_bytes(4, "big") + b"\xff\xfd\xff" + seed, n)
    drawn = lms.randBytes
    lms.randBytes = lambda length: c if length == n else drawn(length)
    try:
        signature = key.sign(message)
    finally:
        lms.randBytes = drawn
    return key.publicKey().serialize().hex() + " " + signature.hex()


def verify(f):
    if len(f) != 4:
        return "error request"
    try:
        public = lms.HssPublicKey.deserialize(bytes.fromhex(f[1]))
        message = b"" if f[2] == "-" else bytes.fromhex(f[2])
        return "ok" if public.verify(message, bytes.fromhex(f[3])) else "bad"
    except Exception:  # noqa: BLE001 - a malformed signature is a refusal
        return "bad"


def main():
    for line in sys.stdin:
        f = line.split()
        if f and f[0] == "lms":
            out = tree(f)
        elif f and f[0] == "verify":
            out = verify(f)
        elif f and f[0] == "hss":
            out = "error unsupported"
        else:
            out = "error request"
        print(out, flush=True)


if __name__ == "__main__":
    main()
