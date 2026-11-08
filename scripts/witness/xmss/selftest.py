#!/usr/bin/env python3
"""Checks /opt/xmsswitness before anything is written from it.

    python3 scripts/witness/xmss/selftest.py [/opt/xmsswitness]

Requests, one per line, hex fields, "-" for empty; <kind> is xmss or
xmssmt, whose OIDs are numbered apart:

    sign <kind> <oid> <SK_SEED||SK_PRF||SEED> <idx> <message>
                                -> <OID || root || SEED> <signature>
    sign-rfc8391 <kind> <oid> <SK_SEED||SK_PRF||SEED> <idx> <message>
                                -> the same, WOTS+ keys derived as RFC 8391
                                   suggests rather than as SP 800-208 requires
    verify <kind> <OID || root || SEED> <message> <signature>  -> ok | bad

A witness answers "error unsupported" for what it does not do.

The answers the XMSS reference implementation gave, as Botan's tests carry
them (vectors/botan_xmss/): every witness that signs with SP 800-208's
derivation must give the seven public keys of xmss_keygen_reference.vec
and the signatures of xmss_sig.vec whose private keys name that
derivation; every verifier must accept xmss_verify.vec's signatures and
refuse each with a byte changed.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
WITNESSES = ["ref-xmss", "botan-xmss", "bc-xmss"]
SIGNERS = {"sign": ["ref-xmss", "botan-xmss"], "sign-rfc8391": ["bc-xmss"]}
# XMSS OIDs by name, RFC 8391's and SP 800-208's: seven families of three
# heights.
FAMILIES = ["SHA2_{}_256", "SHA2_{}_512", "SHAKE_{}_256", "SHAKE_{}_512",
            "SHA2_{}_192", "SHAKE256_{}_256", "SHAKE256_{}_192"]
OIDS = {f.format(h): 3 * i + j + 1 for i, f in enumerate(FAMILIES)
        for j, h in enumerate((10, 16, 20))}


def n_of(oid):
    return [32, 64, 32, 64, 24, 32, 24][(oid - 1) // 3]


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def botan_rows(name):
    """The records of one of Botan's .vec files: dicts of its fields."""
    rows, row = [], {}
    for line in open(os.path.join(ROOT, "vectors", "botan_xmss", name)):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key == "Params" and row:
            rows.append(row)
            row = {}
        row[key] = value.strip()
    rows.append(row)
    return rows


def oid_of(params):
    return OIDS[params.removeprefix("XMSS-")]


def known_answers():
    """(request, expected) for the signers, and verify requests: (request,
    expected)."""
    signing, verifying = [], []
    for r in botan_rows("xmss_keygen_reference.vec"):
        oid = oid_of(r["Params"])
        seeds = r["SecretSeed"] + r["SecretPrf"] + r["PublicSeed"]
        signing.append((f"sign xmss {oid} {seeds} 0 -", r["PublicKey"]))
    for r in botan_rows("xmss_sig.vec"):
        oid = oid_of(r["Params"])
        n = n_of(oid)
        key = bytes.fromhex(r["PrivateKey"])
        public, rest = key[:4 + 2 * n], key[4 + 2 * n:]
        if len(rest) != 4 + 2 * n + 1 or rest[-1] != 2:
            continue  # Botan 2's derivation, or none named
        idx = int.from_bytes(rest[:4], "big")
        prf, sk_seed = rest[4:4 + n], rest[4 + n:4 + 2 * n]
        seeds = (sk_seed + prf + public[4 + n:]).hex()
        signing.append((f"sign xmss {oid} {seeds} {idx} {r['Msg'] or '-'}",
                        f"{public.hex()} {r['Signature']}"))
    for r in botan_rows("xmss_verify.vec"):
        request = f"verify xmss {r['PublicKey']} {r['Msg'] or '-'}"
        verifying.append((f"{request} {r['Signature']}", "ok"))
        bad = bytearray(bytes.fromhex(r["Signature"]))
        bad[len(bad) // 2] ^= 0x40
        verifying.append((f"{request} {bytes(bad).hex()}", "bad"))
    return signing, verifying


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/xmsswitness"
    signing, verifying = known_answers()
    if len(signing) < 20 or len(verifying) != 126:
        sys.exit(f"read {len(signing)} signing and {len(verifying)} verifying answers")
    counts = {}
    for w in WITNESSES:
        signed = 0
        if w in SIGNERS["sign"]:
            for (request, want), got in zip(signing, ask(out, w, [r for r, _ in signing])):
                # A known public key is checked against the first field only.
                if got.split()[0] != want.split()[0] or (" " in want and got != want):
                    sys.exit(f"{w} does not reproduce {request[:60]}: {got[:60]}")
                signed += 1
        verified = 0
        for (request, want), got in zip(verifying, ask(out, w, [r for r, _ in verifying])):
            if got == "error unsupported" and w == "bc-xmss":
                continue
            if got != want:
                sys.exit(f"{w} answers {got} to {request[:70]}, not {want}")
            verified += 1
        counts[w] = (signed, verified)
    print("xmss witnesses: the reference's answers in Botan's tests reproduced: " + ", ".join(
        f"{w} {s} signed, {v} verified" for w, (s, v) in counts.items()))


if __name__ == "__main__":
    main()
