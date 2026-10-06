#!/usr/bin/env python3
"""Write vectors/xeddsa.vec: libsignal-protocol-c's own XEdDSA answers.

libsignal-protocol-c is the witness for `src/ec/xeddsa.rs`. Its two
signers are called directly - `curve25519_sign`, which is what Signal
signs prekeys and group messages with, and `xed25519_sign`, the
specification's form - and so are their two verifiers. The tests read
this file and need no libsignal.

    python3 scripts/make_xeddsa_vectors.py --witness /opt/signalwitness/signalwitness

The witness is `scripts/witness/signalwitness`; docs/building.md has the
build line. **A development tool, not a test**: nothing in the build or
the gate runs it. Every input is derived from a fixed seed and the
witness takes its randomness as an argument, so a re-run writes the
same file byte for byte; a diff after regenerating means the witness
changed.

What each section holds:

  * `[sign]` - private key, message and the 64 random bytes `Z`, and the
    witness's signature. Keys are clamped, as libsignal stores them; the
    witness signs with the bytes it is given, and this library clamps
    first, so only for clamped keys are the two the same function.
    Both signs of `kB` occur, so both branches of the specification's
    negation are reached.
  * `[verify]` - public key, message, signature and each verifier's
    verdict. Signatures that should and should not verify, chosen to
    separate the two verifiers from each other and from RFC 8032:
    `S + L`, `S` with a high bit set, a flipped bit in `R`, a changed
    message, a `u` with bit 255 set, a `u` at or above `p`, and each
    form's signature under the other's verifier.
"""

import argparse
import hashlib
import os
import subprocess

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(os.path.dirname(HERE), "vectors", "xeddsa.vec")

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def stream(label, length):
    """Deterministic bytes: SHA-256 of a label and a counter."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{label}/{counter}".encode()).digest()
        counter += 1
    return out[:length]


def clamp(key):
    key = bytearray(key)
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64
    return bytes(key)


def public(private):
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


class Witness:
    def __init__(self, path):
        self.process = subprocess.Popen([path, "00", "1", "self", "peer"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True)

    def ask(self, *words):
        self.process.stdin.write(" ".join(words) + "\n")
        self.process.stdin.flush()
        reply = self.process.stdout.readline().split()
        if not reply or reply[0] == "error":
            raise SystemExit(f"the witness refused {words[0]}: {reply}")
        return reply[1]

    def sign(self, form, private, message, random):
        command = "sign" if form == "signal" else "xsign"
        return bytes.fromhex(self.ask(command, private.hex(), message.hex() or "", random.hex()))

    def verify(self, form, public_key, message, signature):
        command = "verify" if form == "signal" else "xverify"
        return self.ask(command, public_key.hex(), message.hex(), signature.hex()) == "1"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--witness", default="/opt/signalwitness/signalwitness")
    args = parser.parse_args()
    witness = Witness(args.witness)

    # An empty message has to reach the witness as a word, so messages
    # are never empty on the command line: the witness's unhex of ""
    # cannot be sent through a whitespace-split protocol. Lengths start
    # at one here and the empty message is covered by the library's own
    # tests.
    sign_rows = []
    for index in range(40):
        form = "signal" if index % 2 == 0 else "xeddsa"
        private = clamp(stream(f"key/{index}", 32))
        message = stream(f"message/{index}", 1 + index * 3)
        random = stream(f"random/{index}", 64)
        signature = witness.sign(form, private, message, random)
        if not witness.verify(form, public(private), message, signature):
            raise SystemExit(f"the witness refused its own {form} signature, row {index}")
        sign_rows.append((form, private, message, random, signature))

    # The sign of kB, read from where the Signal form stores it.
    signs = {row[1]: witness.sign("signal", row[1], b"x", bytes(64))[63] >> 7
             for row in sign_rows}
    if set(signs.values()) != {0, 1}:
        raise SystemExit("every key had the same sign; the negation is untested")

    verify_rows = []

    def both(label, public_key, message, signature):
        verdicts = {form: witness.verify(form, public_key, message, signature)
                    for form in ("signal", "xeddsa")}
        verify_rows.append((label, public_key, message, signature, verdicts))

    for index, (form, private, message, random, signature) in enumerate(sign_rows[:12]):
        key = public(private)
        negative = signs[private]
        tag = f"{form} signature, key {'negative' if negative else 'positive'}"
        both(tag, key, message, signature)

        s = int.from_bytes(signature[32:], "little") & ((1 << 255) - 1)
        sign_bit = signature[63] & 0x80
        malleated = bytearray(signature[:32] + (s + L).to_bytes(32, "little"))
        malleated[63] |= sign_bit
        both(f"{tag}, S + L", key, message, bytes(malleated))

        high = bytearray(signature)
        high[63] |= 0x20
        both(f"{tag}, bit 253 of S set", key, message, bytes(high))

        flipped = bytearray(signature)
        flipped[index % 32] ^= 1 << (index % 8)
        both(f"{tag}, a bit of R flipped", key, message, bytes(flipped))

        both(f"{tag}, message changed", key, message + b"!", signature)

        flagged = bytearray(key)
        flagged[31] |= 0x80
        both(f"{tag}, bit 255 of u set", bytes(flagged), message, signature)

    # A u at or above p. Only the nineteen values p..p+18 fit below
    # 2^255, so the key is k = 1 *unclamped*, whose u is 9: the witness
    # signs with the bytes it is given, and p + 9 is the same u for a
    # verifier that reduces and a refusal for one that does not.
    one = (1).to_bytes(32, "little")
    for form in ("signal", "xeddsa"):
        signature = witness.sign(form, one, b"unreduced u", stream(f"one/{form}", 64))
        for u in (9, P + 9):
            both(f"{form} signature by k = 1, u = {'9' if u == 9 else 'p + 9'}",
                 u.to_bytes(32, "little"), b"unreduced u", signature)

    # u = p - 1 has no Edwards image; both readings turn it into y = 0.
    both("u = p - 1", (P - 1).to_bytes(32, "little"), b"m", sign_rows[0][4])

    for name in ("signal", "xeddsa"):
        if not any(v[name] for *_, v in verify_rows) or all(v[name] for *_, v in verify_rows):
            raise SystemExit(f"the {name} verifier said the same thing about every row")
    if all(v["signal"] == v["xeddsa"] for *_, v in verify_rows):
        raise SystemExit("the two verifiers agreed on every row; nothing separates them")

    with open(OUTPUT, "w") as out:
        out.write("# XEdDSA vectors from libsignal-protocol-c.\n#\n")
        out.write("# Generated by scripts/make_xeddsa_vectors.py. Do not edit: every\n")
        out.write("# signature and verdict here is libsignal's answer, and a hand edit\n")
        out.write("# makes it ours.\n#\n")
        out.write("# libsignal-protocol-c 2.3.3, curve25519_sign / curve25519_verify\n")
        out.write("# (form = signal) and xed25519_sign / xed25519_verify (form = xeddsa).\n#\n")
        out.write("# Every input is derived from a fixed seed, so regenerating writes\n")
        out.write("# the same file. The tests that read it need no libsignal.\n#\n")
        out.write("# Counts, asserted by the test that reads this:\n")
        out.write(f"#   sign                     {len(sign_rows)}\n")
        out.write(f"#   verify                   {len(verify_rows)}\n\n")
        out.write("[sign]\n\n")
        for form, private, message, random, signature in sign_rows:
            out.write(f"form = {form}\nprivate = {private.hex()}\nmessage = {message.hex()}\n")
            out.write(f"random = {random.hex()}\nsignature = {signature.hex()}\n\n")
        out.write("[verify]\n\n")
        for label, key, message, signature, verdicts in verify_rows:
            out.write(f"case = {label}\npublic = {key.hex()}\nmessage = {message.hex()}\n")
            out.write(f"signature = {signature.hex()}\n")
            out.write(f"signal = {int(verdicts['signal'])}\nxeddsa = {int(verdicts['xeddsa'])}\n\n")
    print(f"{len(sign_rows)} signatures, {len(verify_rows)} verdicts -> {OUTPUT}")


if __name__ == "__main__":
    main()
