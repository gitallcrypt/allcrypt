#!/usr/bin/env python3
"""Strumok's published known answers, read out of the witnesses' sources.

    python3 published.py <witness dir>          list them
    python3 published.py --check <witness dir>  require both witnesses
                                                to reproduce every one

Three sources, each read from a file build.sh fetched and pinned:

- standard: DSTU 8845:2019's Annex D examples (D.1.1 for 256-bit keys,
  D.2.1 for 512-bit keys), as uacrypt's tests/strumok.rs transcribes
  them from the standard's text: words exactly as printed, K3..K0 or
  K7..K0 and IV3..IV0 from the most significant down, keystream words
  Z0..Z7.
- uapki: dstu8845_self_test() in UAPKI's dstu8845.c, the same examples
  as UAPKI's authors carry them (keys and IVs as bytes, keystream as
  64-bit words), and one 200 byte keystream crossing a 128 byte block.
- letter: the two examples of the letter uacrypt's tests/strumok.rs
  cites as accompanying Annex D in conformance testing, printed as
  byte strings: key and IV with byte 0 last, the keystream in 8 byte
  words each with its most significant byte first.

Every source is converted to one convention: key, IV and keystream as
byte strings, each 64-bit word little endian, word 0 first. That is how
UAPKI and uacrypt take and give bytes, and how allcrypt does.
"""

import os
import re
import struct
import subprocess
import sys


def le_words(words):
    """64-bit word values, word 0 first, as bytes."""
    return b"".join(struct.pack("<Q", w) for w in words)


def standard(src):
    text = open(os.path.join(src, "uacrypt/tests/strumok.rs"), encoding="utf-8").read()
    out = []
    pattern = re.compile(r'annex_d_test_(256|512)!\(\s*(\w+),\s*"([^"]*)",\s*'
                         r"\[([^\]]*)\],\s*\[([^\]]*)\],\s*\[([^\]]*)\]")
    for m in pattern.finditer(text):
        bits = int(m.group(1))
        key, iv, z = ([int(w, 16) for w in re.findall(r'"([0-9a-f]{16})"', g)]
                      for g in m.group(4, 5, 6))
        if len(key) != bits // 64 or len(iv) != 4 or len(z) != 8:
            sys.exit(f"an Annex D example of the wrong shape: {m.group(2)}")
        # Printed from the most significant word down; word 0 is last.
        out.append(("standard", m.group(3), le_words(key[::-1]), le_words(iv[::-1]),
                    le_words(z)))
    if len(out) != 8:
        sys.exit(f"expected Annex D's eight examples in uacrypt's tests, found {len(out)}")
    return out


def uapki(src):
    text = open(os.path.join(src, "uapki/src/dstu8845.c"), encoding="utf-8").read()
    body = text[text.index("int dstu8845_self_test(void)"):]
    byte_arrays = {name: bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})\b", vals))
                   for name, vals in re.findall(r"static const uint8_t (\w+)\[\] = \{([^}]*)\}",
                                                body)}
    word_arrays = {name: [int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{16})ULL", vals)]
                   for name, vals in re.findall(r"static const uint64_t (\w+)\[\] = \{([^}]*)\}",
                                                body)}
    out = []
    for name, words in word_arrays.items():
        m = re.fullmatch(r"(k(?:256|512)_\d)_(iv_\d)(?:_(\d+))?", name)
        if not m:
            sys.exit(f"an unexpected array in dstu8845_self_test: {name}")
        length = int(m.group(3) or 64)
        if len(words) * 8 != length:
            sys.exit(f"{name}: {len(words)} words for {length} bytes")
        out.append(("uapki", name, byte_arrays[m.group(1)], byte_arrays[m.group(2)],
                    le_words(words)))
    if len(out) != 9:
        sys.exit(f"expected nine keystreams in dstu8845_self_test, found {len(out)}")
    return out


def letter(src):
    text = open(os.path.join(src, "uacrypt/tests/strumok.rs"), encoding="utf-8").read()
    module = text[text.index("mod official_letter_vectors"):]
    module = module[:module.index("\nmod ", 1)]
    out = []
    for bits, body in re.findall(r"fn strumok_(256|512)\(\) \{(.*?)\n    \}", module, re.S):
        arrays = {name: bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", vals))
                  for name, vals in re.findall(r"let (\w+): \[u8; \d+\] = \[([^\]]*)\]", body)}
        key, iv, block = arrays["key_as_printed"], arrays["iv_as_printed"], arrays["randblock"]
        if len(key) * 8 != int(bits) or len(iv) != 32 or len(block) != 128:
            sys.exit(f"a letter example of the wrong shape: strumok_{bits}")
        z = b"".join(block[i:i + 8][::-1] for i in range(0, 128, 8))
        out.append(("letter", f"strumok-{bits}", key[::-1], iv[::-1], z))
    if len(out) != 2:
        sys.exit(f"expected the letter's two examples in uacrypt's tests, found {len(out)}")
    return out


def all_published(src):
    return standard(src) + uapki(src) + letter(src)


def run(program, requests):
    stdin = "".join(f"{k.hex()} {v.hex()} {','.join(map(str, p))}\n" for k, v, p in requests)
    lines = subprocess.run(program, input=stdin, capture_output=True, text=True,
                           check=True).stdout.split("\n")[:len(requests)]
    for line in lines:
        if line.startswith("error"):
            sys.exit(f"{program[0]} refused a request: {line}")
    return [bytes.fromhex(line) for line in lines]


def witnesses(out_dir):
    return {"uapki": [os.path.join(out_dir, "strumok-uapki")],
            "uacrypt": [os.path.join(out_dir, "strumok-uacrypt")]}


def check(out_dir):
    src = os.path.join(out_dir, "src")
    rows = all_published(src)
    selftest = subprocess.run([os.path.join(out_dir, "strumok-uapki")], input="selftest\n",
                              capture_output=True, text=True, check=True).stdout.strip()
    if selftest != "0":
        sys.exit(f"UAPKI's dstu8845_self_test returned {selftest}")
    for who, program in witnesses(out_dir).items():
        got = run(program, [(k, v, [len(z)]) for _, _, k, v, z in rows])
        for (source, label, _, _, z), g in zip(rows, got):
            if g != z:
                sys.exit(f"{who} misses {source} {label}: {g.hex()} != {z.hex()}")
    print(f"both witnesses reproduce all {len(rows)} published keystreams")


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        check(sys.argv[2])
    else:
        for source, label, k, v, z in all_published(os.path.join(sys.argv[1], "src")):
            print(source, label, k.hex(), v.hex(), z.hex())
