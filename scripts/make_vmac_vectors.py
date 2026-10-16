#!/usr/bin/env python3
"""Write vectors/vmac.vec: VMAC (draft-krovetz-vmac-01).

    sh scripts/witness/macs/build.sh /opt/macwitness
    python3 scripts/make_vmac_vectors.py [/opt/macwitness]

**A development tool, not a test.** `tests/test_vmac.rs` reads the file
offline, and reads the draft's own vectors out of
`rfcs/draft-krovetz-vmac-01.txt` itself.

Two implementations that share no code: Crypto++ 8.9.0's VMAC, over any
of AES, Twofish, Serpent, Camellia, ARIA, SEED and SM4 with either tag,
and the Linux kernel 6.6's `vmac64` (`crypto/vmac.c`, its VMAC core run
in user space over OpenSSL's AES), which is AES-128 with the 64 bit tag
and a 16 byte nonce - a shorter nonce is given to it right-aligned in
zeros, which is how the draft's pad derivation reads one. In order:

1. Crypto++'s published VMAC tests, `TestVectors/vmac.txt` in the
   pinned tree - the draft's five and six more each for both tags
   (`source=cryptopp-tests`); every witness that takes a row reproduces
   it, and the rows marked NotVerify are left out.
2. Rows from a seeded generator (`source=generated`): every cipher at
   each of its key lengths, both tags, nonces of 1 to 16 bytes, and
   messages either side of 16 and 128 bytes and of several 128 byte
   segments. Each row is written only when every witness that takes it
   gives the same tag.

Rows, hex fields, "-" for empty; a long message that repeats a short
unit is `r<count>:<unit hex>`:

    vmac cipher= key= nonce= msg= tag= source= witnesses=
"""

import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "vmac.vec")
PROGRAMS = {"cryptopp": "cryptopp-vmac", "kernel": "kernel-vmac"}
#: cipher: key lengths
CIPHERS = {"aes": [16, 24, 32], "twofish": [16, 24, 32], "serpent": [16, 32],
           "camellia": [16, 24, 32], "aria": [16, 32], "seed": [16], "sm4": [16]}


def h(data):
    return data.hex() or "-"


def message_field(msg):
    """A message as the file writes it: hex, or for a long repetition of
    a short unit `r<count>:<unit hex>`, so a million repetitions of "abc"
    is a dozen characters rather than six million."""
    if len(msg) > 4096:
        for size in range(1, 17):
            unit = msg[:size]
            if len(msg) % size == 0 and unit * (len(msg) // size) == msg:
                return f"r{len(msg) // size}:{unit.hex()}"
    return h(msg)


def takes(witness, cipher, key, tag_len):
    if witness == "kernel":
        return cipher == "aes" and len(key) == 16 and tag_len == 8
    return True


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, PROGRAMS[witness])],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    for request, answer in zip(requests, answers):
        if answer.startswith("error"):
            sys.exit(f"{witness} refused {request[:80]}: {answer}")
    return answers


def value(text):
    """Crypto++'s test-file value: quoted strings, `rN` repeating the next
    token, and hex with spaces."""
    out, repeat = b"", 1
    for token in re.findall(r'"[^"]*"|r\d+|[0-9A-Fa-f ]+', text.strip()):
        token = token.strip()
        if not token:
            continue
        if token.startswith('"'):
            out += token[1:-1].encode() * repeat
            repeat = 1
        elif re.fullmatch(r"r\d+", token):
            repeat = int(token[1:])
        else:
            out += bytes.fromhex(token.replace(" ", "")) * repeat
            repeat = 1
    return out


def published(out):
    path = os.path.join(out, "src", "cryptopp", "TestVectors", "vmac.txt")
    rows, fields = [], {}
    for line in open(path):
        if ":" not in line:
            continue
        name, text = line.split(":", 1)
        name = name.strip()
        if name == "Name":
            fields = {"tag_len": int(text.strip().rsplit("-", 1)[1]) // 8}
        elif name in ("Key", "IV", "Message", "MAC"):
            fields[name] = value(text)
        elif name == "Test" and text.strip() == "Verify":
            rows.append(("aes", fields["Key"], fields["IV"], fields["Message"], fields["MAC"],
                         fields["tag_len"]))
    if len(rows) != 20:
        sys.exit(f"{path}: expected twenty Verify rows, read {len(rows)}")
    return rows


def request(cipher, key, nonce, msg, tag_len):
    return f"vmac {cipher} {h(key)} {h(nonce)} {h(msg)} {tag_len}"


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/macwitness"
    lines = []
    for cipher, key, nonce, msg, tag, tag_len in published(out):
        witnesses = [w for w in PROGRAMS if takes(w, cipher, key, tag_len)]
        for witness in witnesses:
            if ask(out, witness, [request(cipher, key, nonce, msg, tag_len)]) != [tag.hex()]:
                sys.exit(f"{witness} does not reproduce a published row ({len(msg)} bytes)")
        lines.append(f"vmac cipher={cipher} key={h(key)} nonce={h(nonce)} msg={message_field(msg)} "
                     f"tag={tag.hex()} source=cryptopp-tests witnesses={','.join(witnesses)}")

    rng = random.Random(20261016)
    rows = []
    lengths = [0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 3 * 128 + 40, 1000]
    for cipher, key_lengths in CIPHERS.items():
        for i, length in enumerate(lengths):
            for tag_len in (8, 16):
                key = rng.randbytes(key_lengths[(i + tag_len) % len(key_lengths)])
                nonce = rng.randbytes(1 + (i * 5 + tag_len) % 16)
                if len(nonce) == 16:
                    nonce = bytes([nonce[0] & 0x7f]) + nonce[1:]
                rows.append((cipher, key, nonce, rng.randbytes(length), tag_len))
    # AES-128 with the 64 bit tag over every nonce length, both last bits.
    for length in range(1, 17):
        for last in (0, 1):
            nonce = bytearray(rng.randbytes(length))
            nonce[0] &= 0x7f if length == 16 else 0xff
            nonce[-1] = (nonce[-1] & 0xfe) | last
            rows.append(("aes", rng.randbytes(16), bytes(nonce), rng.randbytes(length * 9), 8))

    answers = {}
    for witness in PROGRAMS:
        mine = [i for i, r in enumerate(rows) if takes(witness, r[0], r[1], r[4])]
        got = ask(out, witness, [request(*rows[i]) for i in mine])
        answers[witness] = dict(zip(mine, got))
    for i, (cipher, key, nonce, msg, tag_len) in enumerate(rows):
        witnesses = [w for w in PROGRAMS if i in answers[w]]
        given = {answers[w][i] for w in witnesses}
        if len(given) != 1:
            sys.exit(f"the witnesses disagree on {request(cipher, key, nonce, msg, tag_len)[:90]}")
        lines.append(f"vmac cipher={cipher} key={h(key)} nonce={h(nonce)} msg={h(msg)} "
                     f"tag={given.pop()} source=generated witnesses={','.join(witnesses)}")

    header = [
        "# VMAC (draft-krovetz-vmac-01). Written by scripts/make_vmac_vectors.py; do",
        "# not edit. source=cryptopp-tests: Crypto++'s published tests, the draft's",
        "# among them, reproduced by every witness that takes them; generated: seeded",
        "# random inputs. witnesses: who gave the tag, every one that takes the row",
        "# agreeing - cryptopp is Crypto++ 8.9.0, kernel is Linux 6.6's vmac64.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
