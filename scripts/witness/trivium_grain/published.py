#!/usr/bin/env python3
"""Trivium's and Grain's published known answers, and the witnesses.

Imported by `selftest.py` and `scripts/make_trivium_grain_vectors.py`.

The published answers are the eSTREAM project's test-vector files,
vendored in `vectors/estream/` from avr-crypto-lib's `testvectors/`
(nerilex/avr-crypto-lib, a705bca), which carries them as the project
published them:

- trivium-unverified.test-vectors: Trivium with an 80 bit key and IVs of
  32, 64 and 80 bits, 246 vectors.
- grain-v1-verified.test-vectors: Grain v1, 80 bit key and 64 bit IV,
  83 vectors.
- grain-128-unverified.test-vectors: Grain-128, 128 bit key and 96 bit
  IV, 92 vectors.

Each vector gives a key, an IV, some 64 byte stretches of the keystream
(`stream[a..b]`) and an `xor-digest`, the XOR of every 64 byte block of
the whole keystream - 512 bytes, or 131072 for set 6 - so a witness that
reproduces the digest reproduces every byte. The files' key, IV and
keystream are byte strings in the ECRYPT interface's order, which is how
every witness here, the submissions and allcrypt take and give them.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
VECTORS = os.path.join(ROOT, "vectors", "estream")

#: file: the cipher its vectors are for
FILES = {
    "trivium-unverified.test-vectors": "trivium",
    "grain-v1-verified.test-vectors": "grainv1",
    "grain-128-unverified.test-vectors": "grain128",
}

#: witness program: {cipher: the (key length, IV length) shapes it takes}
PROGRAMS = {
    "ref-trivium": {"trivium": [(10, 4), (10, 6), (10, 8), (10, 10)]},
    "go-trivium": {"trivium": [(10, 10)]},
    "ref-grainv1": {"grainv1": [(10, 8)]},
    "gstream-grainv1": {"grainv1": [(10, 8)]},
    "bc-hw": {"grainv1": [(10, 8)], "grain128": [(16, 12)]},
    "rust-hw": {"trivium": [(10, 10)], "grain128": [(16, 12)]},
}
#: The witnesses' names in the vector file.
SHORT = {"bc-hw": "bc", "rust-hw": "crates", "go-trivium": "pedroalbanese",
         "gstream-grainv1": "gstream"}


def short(program):
    return SHORT.get(program, program)


def takes(program, cipher, key_len=None, iv_len=None):
    shapes = PROGRAMS[program].get(cipher)
    if not shapes:
        return False
    return key_len is None or (key_len, iv_len) in shapes


def request(cipher, key, iv, length):
    return f"stream {cipher} {key.hex()} {iv.hex() or '-'} {length}"


def request_for(program, cipher, key, iv, length):
    """The request to put to a program, or None if it cannot answer it. A
    Trivium IV shorter than ten bytes is the ten byte one with zero bytes
    in front, as the submission reads it, so a program that takes only
    ten byte IVs is asked that - which is also how that reading is
    checked."""
    if takes(program, cipher, len(key), len(iv)):
        return request(cipher, key, iv, length)
    if cipher == "trivium" and len(iv) < 10 and takes(program, cipher, len(key), 10):
        return request(cipher, key, bytes(10 - len(iv)) + iv, length)
    return None


def answering(cipher, key, iv):
    """The programs that can answer for this key and IV."""
    return [p for p in PROGRAMS if request_for(p, cipher, key, iv, 1) is not None]


def ask_all(out, cipher, inputs):
    """Each (key, iv, length) put to every program that can answer it:
    a list, per input, of {program: answer}."""
    answers = [dict() for _ in inputs]
    for program in PROGRAMS:
        mine = [(i, request_for(program, cipher, k, v, n)) for i, (k, v, n) in enumerate(inputs)]
        mine = [(i, r) for i, r in mine if r is not None]
        for (i, _), got in zip(mine, ask(out, program, [r for _, r in mine])):
            answers[i][program] = got
    return answers


def ask(out, program, requests):
    """Every request through one run of the program, an answer per line."""
    if not requests:
        return []
    run = subprocess.run([os.path.join(out, program)], input="\n".join(requests) + "\n",
                         capture_output=True, text=True, check=True)
    answers = run.stdout.split("\n")[:len(requests)]
    if len(answers) != len(requests):
        sys.exit(f"{program} answered {len(answers)} of {len(requests)} requests")
    return answers


def xor_digest(keystream):
    digest = bytearray(64)
    for at in range(0, len(keystream), 64):
        for i, b in enumerate(keystream[at:at + 64]):
            digest[i] ^= b
    return bytes(digest)


def read(path):
    """The vectors in one eSTREAM file: dicts of cipher-independent fields
    - set, vector, key, iv, length, stretches [(start, bytes)], digest."""
    text = open(path).read().replace("\r", "")
    vectors, current, length, field = [], None, None, None
    for line in text.split("\n"):
        # A set without the "(stream is generated ..." line - sets 4 and 6 -
        # covers 131072 bytes, as its last stretch and its digest do.
        if line.startswith("Test vectors -- set"):
            length = None
            continue
        m = re.match(r"\(stream is generated by encrypting (\d+) zero bytes", line)
        if m:
            length = int(m.group(1))
            continue
        m = re.match(r"Set (\d+), vector# *(\d+):", line)
        if m:
            current = {"set": int(m.group(1)), "vector": int(m.group(2)),
                       "length": length, "stretches": [], "digest": b""}
            vectors.append(current)
            field = None
            continue
        if current is None:
            continue
        m = re.match(r"\s+(key|IV|stream\[(\d+)\.\.(\d+)\]|xor-digest) = ([0-9A-F]+)$", line)
        if m:
            name, value = m.group(1), bytes.fromhex(m.group(4))
            if name == "key":
                current["key"], field = value, "key"
            elif name == "IV":
                current["iv"], field = value, "iv"
            elif name == "xor-digest":
                current["digest"], field = value, "digest"
            else:
                current["stretches"].append([int(m.group(2)), value])
                field = "stretch"
            continue
        m = re.match(r"\s+([0-9A-F]+)$", line)
        if m and field:
            value = bytes.fromhex(m.group(1))
            if field == "stretch":
                current["stretches"][-1][1] += value
            else:
                current[field] += value
            continue
        if line.strip() == "":
            field = None
    for v in vectors:
        if v["length"] is None and v["stretches"]:
            v["length"] = max(start for start, _ in v["stretches"]) + 64
        if v["length"] is None or "key" not in v or "iv" not in v or len(v["digest"]) != 64:
            sys.exit(f"{path}: vector {v['set']}/{v['vector']} is incomplete")
        for start, stretch in v["stretches"]:
            if len(stretch) != 64:
                sys.exit(f"{path}: vector {v['set']}/{v['vector']}: a stretch of "
                         f"{len(stretch)} bytes at {start}")
    return vectors


def published():
    """Every published vector: (cipher, vector dict, source label)."""
    rows = []
    expected = {"trivium": 246, "grainv1": 83, "grain128": 92}
    for name, cipher in FILES.items():
        vectors = read(os.path.join(VECTORS, name))
        if len(vectors) != expected[cipher]:
            sys.exit(f"{name}: expected {expected[cipher]} vectors, read {len(vectors)}")
        rows += [(cipher, v, f"eSTREAM_{name}") for v in vectors]
    return rows


def matches(vector, keystream):
    """Whether a keystream reproduces every stretch and the digest."""
    if len(keystream) != vector["length"]:
        return False
    for start, stretch in vector["stretches"]:
        if keystream[start:start + 64] != stretch:
            return False
    return xor_digest(keystream) == vector["digest"]
