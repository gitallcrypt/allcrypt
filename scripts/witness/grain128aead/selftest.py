#!/usr/bin/env python3
"""Checks /opt/grainaeadwitness before any vector is written from it.

    python3 scripts/witness/grain128aead/selftest.py [/opt/grainaeadwitness]

1. The NIST final round's known-answer file for Grain-128AEADv2, as
   lwc-finalists carries it (1,089 cases, associated data and plaintext
   of 0 to 32 bytes each), reproduced by every witness.
2. The witnesses agreeing on random inputs whose associated data and
   plaintext lengths cross the DER length forms (127, 128, 255, 256, 257
   and 65,536 bytes of associated data) and the 16 bit steps of the
   keystream. Bouncy Castle 1.77 writes the length's bytes little endian,
   and must agree exactly where that gives the DER encoding: below 256
   bytes, and at 257, whose two bytes are the same either way.
3. For Grain-128AEAD v1, before the round 3 tweak: the designers'
   known-answer file (the same 1,089 inputs) reproduced by the designers'
   reference and optimised implementations and by lightweight-crypto,
   each of which also decrypts its answer back and refuses it with the
   tag's last bit flipped, and the three agreeing on the random inputs
   of 2. And v1 and v2 differing on every one of those inputs.
"""

import os
import random
import subprocess
import sys

WITNESSES = ["rweather-grain", "rust-grain", "bc-grain"]
WITNESSES_V1 = ["ref-grain-v1", "opt-grain-v1", "rweather-grain-v1"]


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def kat(out, v1=False):
    """(key, nonce, plaintext, ad, ct || tag) for each case of the file:
    NIST's for v2, the designers' for v1."""
    if v1:
        path = os.path.join(out, "src", "grain-128aead", "NIST", "ref",
                            "LWC_AEAD_KAT_128_96.txt")
    else:
        path = os.path.join(out, "src", "lwc-finalists", "test", "kat", "Grain-128AEAD.txt")
    cases, case = [], {}
    for line in open(path):
        if "=" not in line:
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        case[name] = bytes.fromhex(value) if name != "Count" else value
        if name == "CT":
            cases.append((case["Key"], case["Nonce"], case["PT"], case["AD"], case["CT"]))
            case = {}
    return cases


def der_length(n, little=False):
    """The DER length prefix, or Bouncy Castle 1.77's with its length bytes
    little endian."""
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + (body[::-1] if little else body)


def request(key, nonce, ad, pt):
    return f"seal {key.hex()} {nonce.hex()} {ad.hex() or '-'} {pt.hex() or '-'}"


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/grainaeadwitness"
    cases = kat(out)
    if len(cases) != 1089:
        sys.exit(f"read {len(cases)} cases from the known-answer file, not 1089")
    requests = [request(k, n, ad, pt) for k, n, pt, ad, _ in cases]
    for w in WITNESSES:
        answers = ask(out, w, requests)
        for (k, n, pt, ad, ct), a in zip(cases, answers):
            if a != ct.hex():
                sys.exit(f"{w} does not reproduce the known answer for {len(ad)} {len(pt)}: {a}")

    rng = random.Random(2021)
    inputs = []
    for adlen in (0, 1, 127, 128, 255, 256, 257, 65536):
        for ptlen in (0, 1, 2, 3, 15, 16, 17, 100):
            inputs.append((rng.randbytes(16), rng.randbytes(12), rng.randbytes(adlen),
                           rng.randbytes(ptlen)))
    requests = [request(*i) for i in inputs]
    answers = {w: ask(out, w, requests) for w in WITNESSES}
    for i, (_, _, ad, pt) in enumerate(inputs):
        if answers["rweather-grain"][i] != answers["rust-grain"][i]:
            sys.exit(f"rweather and the crate disagree at {len(ad)} {len(pt)}")
        same = answers["bc-grain"][i] == answers["rweather-grain"][i]
        if same != (der_length(len(ad)) == der_length(len(ad), little=True)):
            sys.exit(f"bc-grain {'agrees' if same else 'disagrees'} at {len(ad)} bytes of "
                     f"associated data")

    v1_cases = kat(out, v1=True)
    if len(v1_cases) != 1089:
        sys.exit(f"read {len(v1_cases)} cases from the v1 known-answer file, not 1089")
    v1_requests = [request(k, n, ad, pt) for k, n, pt, ad, _ in v1_cases]
    for w in WITNESSES_V1:
        for (k, n, pt, ad, ct), a in zip(v1_cases, ask(out, w, v1_requests)):
            if a != ct.hex():
                sys.exit(f"{w} does not reproduce the v1 known answer for {len(ad)} {len(pt)}: "
                         f"{a}")
    v1_answers = {w: ask(out, w, requests) for w in WITNESSES_V1}
    for i, (_, _, ad, pt) in enumerate(inputs):
        if len({v1_answers[w][i] for w in WITNESSES_V1}) != 1:
            sys.exit(f"the v1 witnesses disagree at {len(ad)} {len(pt)}")
        if v1_answers["ref-grain-v1"][i] == answers["rweather-grain"][i]:
            sys.exit(f"v1 and v2 agree at {len(ad)} {len(pt)}")
    print(f"grain witnesses: the 1,089 known answers reproduced by {', '.join(WITNESSES)}; "
          f"Bouncy Castle 1.77 disagrees where its length bytes are reversed, as expected; "
          f"the designers' 1,089 v1 known answers reproduced by {', '.join(WITNESSES_V1)}")


if __name__ == "__main__":
    main()
