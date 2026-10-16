#!/usr/bin/env python3
"""The eSTREAM ciphers' published known answers, and the witnesses.

Imported by `selftest.py` and `scripts/make_estream_vectors.py`.

The published answers are read out of Crypto++'s TestVectors in the
pinned tree, which carry each cipher's own vectors and rows Crypto++
generated:

- rabbit.txt: six "Rabbit test vectors", RFC 4503's appendix A with its
  octet strings reversed, then 254 rows Crypto++ generated with the
  eSTREAM reference's rabbit.c, with and without an IV.
- hc128.txt: the two "HC-128 verified test vectors" and 78 generated
  with the reference's hc-128.c.
- hc256.txt: the three vectors of the designer's testvectors.txt, then
  286 rows Crypto++ attributes to the reference's hc-256.c. Those 286
  are reproduced by Crypto++ alone: its HC-256 reads each key and IV
  word rotated by a byte, which the designer's three cannot show, since
  each has at most the first byte of a word set. Both eSTREAM HC-256
  submissions, Bouncy Castle and RustCrypto give other answers, the
  submissions saying in their own comments that a word's bytes are
  little endian. So those rows are `cryptopp-only`, and no witness for
  anything.
- sosemanuk.txt: the reference's own vector, a 5 byte key (the row with
  a digest instead of a ciphertext is skipped).

Every value is a byte string in the ciphers' own convention - key, IV
and keystream as bytes, words little endian - which is how every
witness and allcrypt take and give them.
"""

import os
import re
import subprocess
import sys

#: witness program: the ciphers it takes
PROGRAMS = {
    "ref-hc128-200606": ["hc128"],
    "ref-hc128-200701a": ["hc128"],
    "ref-hc128-200701b": ["hc128"],
    "ref-hc256-200511": ["hc256"],
    "ref-hc256-200701": ["hc256"],
    "ref-rabbit": ["rabbit", "rabbit-iv"],
    "ref-sosemanuk": ["sosemanuk"],
    "cryptopp-stream": ["rabbit", "rabbit-iv", "hc128", "sosemanuk"],
    "ltc-stream": ["rabbit", "rabbit-iv", "sosemanuk"],
    "bc-stream": ["hc128", "hc256"],
    "rust-stream": ["rabbit", "rabbit-iv", "hc256"],
}
#: The witnesses' names in the vector file.
SHORT = {"cryptopp-stream": "cryptopp", "ltc-stream": "libtomcrypt", "bc-stream": "bc",
         "rust-stream": "rustcrypto"}
FILES = {"rabbit.txt": None, "hc128.txt": "hc128", "hc256.txt": "hc256",
         "sosemanuk.txt": "sosemanuk"}


def short(program):
    return SHORT.get(program, program)


def takes(program, cipher):
    return cipher in PROGRAMS[program]


def request(cipher, key, iv, length):
    """Rabbit with an IV is `rabbit-iv` to the drivers that tell the two
    apart; the ECRYPT reference takes `rabbit` and an IV or none."""
    return f"stream {cipher} {key.hex()} {iv.hex() or '-'} {length}"


def ask(out, program, requests):
    """Each request, with `rabbit-iv` spelled as the reference wants it."""
    if program == "ref-rabbit":
        requests = [r.replace("stream rabbit-iv ", "stream rabbit ") for r in requests]
    done = subprocess.run([os.path.join(out, program)],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{program} answered {len(answers)} of {len(requests)} requests")
    for r, a in zip(requests, answers):
        if a.startswith("error"):
            sys.exit(f"{program} refused {r[:80]}: {a}")
    return answers


def _value(text):
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


def rows(out):
    """(cipher, key, iv, keystream, source) for every Crypto++ test row
    with a plaintext and a ciphertext."""
    found = []
    for name, cipher in FILES.items():
        path = os.path.join(out, "src", "cryptopp", "TestVectors", name)
        text = re.sub(r"\\\s*\n\s*", " ", open(path).read())
        current, fields = cipher, {}
        for line in text.splitlines():
            if line.startswith("#") or ":" not in line:
                continue
            field, value = (part.strip() for part in line.split(":", 1))
            if field == "Name":
                current = {"Rabbit": "rabbit", "RabbitWithIV": "rabbit-iv"}.get(value, cipher)
            elif field in ("Key", "IV", "Plaintext", "Ciphertext", "Source"):
                fields[field] = value
            elif field == "Test":
                if "Plaintext" in fields and "Ciphertext" in fields:
                    plain, cipher_text = _value(fields["Plaintext"]), _value(fields["Ciphertext"])
                    found.append((current, _value(fields["Key"]), _value(fields.get("IV", "")),
                                  bytes(a ^ b for a, b in zip(plain, cipher_text)),
                                  fields["Source"]))
                fields = {}
    return found


def cryptopp_only(row):
    """Crypto++'s generated HC-256 rows, which nothing else reproduces."""
    return row[0] == "hc256" and row[4] == "hc-256.c reference implementation"
