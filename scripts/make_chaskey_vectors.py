#!/usr/bin/env python3
"""Write vectors/chaskey.vec: Chaskey, Chaskey-12 and Chaskey-LTS.

    sh scripts/witness/macs/build.sh /opt/macwitness
    python3 scripts/make_chaskey_vectors.py [/opt/macwitness]

**A development tool, not a test.** `tests/test_chaskey.rs` and
`src/mac/chaskey.rs`'s tests read the file offline.

Three implementations that share no code: dgryski/go-chaskey, built twice
- its amd64 assembly (`go`) and its portable Go (`go-purego`) - for 8 and
12 rounds; sacundim's Rust crate (`sacundim`) for 8, 12 and 16; and
volexity's pure Python Chaskey-LTS block cipher (`volexity`), the 16
round permutation alone. In order:

1. go-chaskey's published tags (`source=go-chaskey-tests`), read out of
   its `chaskey_test.go` in the pinned tree: 64 messages `00 01 ..` of
   length 0 to 63 under one key, for 8 and for 12 rounds, reproduced by
   every witness that takes the round count.
2. Generated MAC rows (`source=generated`): every round count, messages
   either side of every multiple of 16 up to 65 bytes and longer ones,
   and keys chosen so that each of the two doublings does and does not
   carry out of the top. Written only when every witness that takes the
   row gives the same tag.
3. Block cipher rows, `pi(x ^ K) ^ K` over the 16 round permutation:
   the FELIX block from sacundim's tests (`source=felix`), then generated
   ones, the all-zero key among them - which is the permutation itself -
   agreed by sacundim and volexity. Chaskey-LTS has no second MAC here,
   so these are what give its permutation a second reading.

Rows, hex fields, "-" for empty:

    chaskey rounds= key= msg= tag= source= witnesses=
    chaskey-cipher rounds= key= block= out= source= witnesses=
"""

import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "chaskey.vec")
PROGRAMS = {"go": "go-chaskey", "go-purego": "go-chaskey-purego", "sacundim": "rust-chaskey",
            "volexity": "volexity-chaskey"}
#: witness: the MAC round counts it takes
MAC_ROUNDS = {"go": (8, 12), "go-purego": (8, 12), "sacundim": (8, 12, 16)}
CIPHER_WITNESSES = ["sacundim", "volexity"]


def h(data):
    return data.hex() or "-"


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


def published(out):
    """go-chaskey's `vectors8` and `vectors12`: four little-endian words
    per tag, over the messages 00 01 .. of length 0 to 63."""
    path = os.path.join(out, "src", "go-chaskey", "chaskey_test.go")
    text = open(path).read()
    words = re.search(r"k := \[4\]uint32\{([^}]*)\}", text).group(1)
    key = b"".join(int(w, 16).to_bytes(4, "little") for w in words.split(","))
    rows = []
    for rounds in (8, 12):
        table = re.search(rf"var vectors{rounds} = \[64\]\[4\]uint32\{{(.*?)\n\}}", text, re.S)
        tags = re.findall(r"\{([^}]*)\}", table.group(1))
        if len(tags) != 64:
            sys.exit(f"{path}: expected 64 tags for {rounds} rounds, read {len(tags)}")
        for i, tag in enumerate(tags):
            value = b"".join(int(w, 16).to_bytes(4, "little") for w in tag.split(","))
            rows.append((rounds, key, bytes(range(i)), value))
    return rows


def felix(out):
    """The FELIX Chaskey-LTS block in sacundim's `cipher.rs` tests."""
    path = os.path.join(out, "src", "chaskey", "src", "cipher.rs")
    text = open(path).read()
    found = {}
    for name in ("KEY", "PLAINTEXT", "CIPHERTEXT"):
        body = re.search(rf"const {name}: \[u8; 16\] = \[(.*?)\];", text, re.S).group(1)
        found[name] = bytes(int(b, 16) for b in body.split(",") if b.strip())
        if len(found[name]) != 16:
            sys.exit(f"{path}: {name} is {len(found[name])} bytes")
    return found["KEY"], found["PLAINTEXT"], found["CIPHERTEXT"]


def carries(key):
    """Whether K . x and K1 . x carry out of the top: bits 127 and 126 of
    the key read as a little-endian number."""
    return key[15] >> 7, key[15] >> 6 & 1


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/macwitness"
    lines = []

    for rounds, key, msg, tag in published(out):
        witnesses = [w for w, r in MAC_ROUNDS.items() if rounds in r]
        for witness in witnesses:
            if ask(out, witness, [f"chaskey {rounds} {key.hex()} {h(msg)}"]) != [tag.hex()]:
                sys.exit(f"{witness} does not reproduce go-chaskey's {rounds} round tag "
                         f"over {len(msg)} bytes")
        lines.append(f"chaskey rounds={rounds} key={key.hex()} msg={h(msg)} tag={tag.hex()} "
                     f"source=go-chaskey-tests witnesses={','.join(witnesses)}")

    rng = random.Random(20261016)
    lengths = [0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 100, 127,
               128, 129, 1000]
    rows = []
    for rounds in (8, 12, 16):
        for i, length in enumerate(lengths):
            key = bytearray(rng.randbytes(16))
            # The two top bits cycle through all four combinations.
            key[15] = (key[15] & 0x3f) | (i % 4) << 6
            rows.append((rounds, bytes(key), rng.randbytes(length)))
    if {carries(k) for _, k, _ in rows} != {(0, 0), (0, 1), (1, 0), (1, 1)}:
        sys.exit("the generated keys miss a carry combination")
    answers = {}
    for witness, takes in MAC_ROUNDS.items():
        mine = [i for i, r in enumerate(rows) if r[0] in takes]
        got = ask(out, witness, [f"chaskey {rows[i][0]} {rows[i][1].hex()} {h(rows[i][2])}"
                                 for i in mine])
        answers[witness] = dict(zip(mine, got))
    for i, (rounds, key, msg) in enumerate(rows):
        witnesses = [w for w in MAC_ROUNDS if i in answers[w]]
        given = {answers[w][i] for w in witnesses}
        if len(given) != 1:
            sys.exit(f"the witnesses disagree on {rounds} rounds over {len(msg)} bytes")
        lines.append(f"chaskey rounds={rounds} key={key.hex()} msg={h(msg)} tag={given.pop()} "
                     f"source=generated witnesses={','.join(witnesses)}")

    key, block, expected = felix(out)
    blocks = [(key, block, "felix")]
    blocks += [(bytes(16), rng.randbytes(16), "generated") for _ in range(8)]
    blocks += [(rng.randbytes(16), bytes(16), "generated") for _ in range(4)]
    blocks += [(rng.randbytes(16), rng.randbytes(16), "generated") for _ in range(27)]
    requests = [f"cipher 16 {k.hex()} {b.hex()}" for k, b, _ in blocks]
    given = {w: ask(out, w, requests) for w in CIPHER_WITNESSES}
    if given["sacundim"][0] != expected.hex():
        sys.exit("sacundim does not reproduce its own FELIX block")
    for i, (key, block, source) in enumerate(blocks):
        if len({given[w][i] for w in CIPHER_WITNESSES}) != 1:
            sys.exit(f"the block ciphers disagree on {requests[i]}")
        lines.append(f"chaskey-cipher rounds=16 key={key.hex()} block={block.hex()} "
                     f"out={given['sacundim'][i]} source={source} "
                     f"witnesses={','.join(CIPHER_WITNESSES)}")

    header = [
        "# Chaskey, Chaskey-12 and Chaskey-LTS (8, 12 and 16 rounds). Written by",
        "# scripts/make_chaskey_vectors.py; do not edit. source=go-chaskey-tests: the",
        "# tags go-chaskey's test file publishes; felix: the Chaskey-LTS block in",
        "# sacundim's tests; generated: seeded random inputs. witnesses: who gave the",
        "# value, every one that takes the row agreeing - go and go-purego are",
        "# dgryski/go-chaskey's assembly and portable builds, sacundim is sacundim's",
        "# Rust crate, volexity is volexity's Python Chaskey-LTS block cipher.",
        "# chaskey-cipher rows are pi(block ^ key) ^ key over the 16 round permutation.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
