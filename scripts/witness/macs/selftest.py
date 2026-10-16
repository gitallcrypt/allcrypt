#!/usr/bin/env python3
"""Check the MAC witnesses before anything uses them.

    python3 scripts/witness/macs/selftest.py /opt/macwitness

  * Rogaway's published PMAC-AES-128 tests, read out of miscreant.go's
    `vectors/aes_pmac.tjson` in the pinned tree, reproduced by all three
    PMAC witnesses.
  * The three agreeing over every cipher each has, at message lengths
    around one and two blocks.
  * libtomcrypt's default build (`ltc-pmac-fast`) still disagreeing over a
    64 bit cipher past 16 bytes, which is why `ltc-pmac` is the
    LTC_NO_FAST build; if a future libtomcrypt fixes it, this says so.
  * The draft's VMAC-AES tests, as Crypto++'s `TestVectors/vmac.txt`
    carries them, reproduced by Crypto++ (both tags) and the kernel's
    vmac64 (the 64 bit ones), and the two agreeing over AES-128 with the
    64 bit tag at nonce lengths 1 to 16.
  * The 64 Chaskey and 64 Chaskey-12 tags go-chaskey's test file
    publishes, reproduced by both of its builds and by sacundim's crate;
    the three agreeing at every round count each has; the FELIX
    Chaskey-LTS block in sacundim's tests, and volexity's own CTR test,
    reproduced by both block ciphers.
"""

import json
import os
import re
import subprocess
import sys

PMAC = {"ltc-pmac": ["aes", "des", "3des", "blowfish"],
        "rust-pmac": ["aes", "des", "3des", "blowfish"],
        "go-pmac": ["aes"]}
KEYS = {"aes": 16, "des": 8, "3des": 24, "blowfish": 16}


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)], input="\n".join(requests) + "\n",
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def h(data):
    return data.hex() or "-"


def published(out):
    path = os.path.join(out, "src", "miscreant.go", "vectors", "aes_pmac.tjson")
    rows = json.load(open(path))["examples:A<O>"]
    if len(rows) < 7:
        sys.exit(f"{path}: expected at least seven examples, read {len(rows)}")
    return [(f"pmac aes {r['key:d16'] or '-'} {r['message:d16'] or '-'}", r["tag:d16"])
            for r in rows]


def chaskey_published(out):
    """go-chaskey's test file: `vectors8` and `vectors12`, 64 tags of four
    little-endian words each, over the messages 00 01 .. of length 0 to
    63 under the key its testVectors names."""
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
    """The Chaskey-LTS block in sacundim's cipher tests, taken from FELIX:
    key, plaintext and ciphertext as byte arrays."""
    path = os.path.join(out, "src", "chaskey", "src", "cipher.rs")
    text = open(path).read()
    found = {}
    for name in ("PLAINTEXT", "CIPHERTEXT", "KEY"):
        body = re.search(rf"const {name}: \[u8; 16\] = \[(.*?)\];", text, re.S).group(1)
        found[name] = bytes(int(b, 16) for b in body.replace("\n", " ").split(",") if b.strip())
        if len(found[name]) != 16:
            sys.exit(f"{path}: {name} is {len(found[name])} bytes")
    return found["KEY"], found["PLAINTEXT"], found["CIPHERTEXT"]


def check_chaskey(out):
    published = chaskey_published(out)
    for witness in ("go-chaskey", "go-chaskey-purego", "rust-chaskey"):
        requests = [f"chaskey {r} {k.hex()} {h(m)}" for r, k, m, _ in published]
        if ask(out, witness, requests) != [t.hex() for *_, t in published]:
            sys.exit(f"{witness} does not reproduce go-chaskey's published tags")
    requests = [f"chaskey {r} {bytes(range(3, 19)).hex()} {h(bytes(range(n)))}"
                for r in (8, 12, 16) for n in (0, 1, 15, 16, 17, 32, 33, 100)]
    answers = {w: ask(out, w, requests)
               for w in ("go-chaskey", "go-chaskey-purego", "rust-chaskey")}
    for i, request in enumerate(requests):
        given = {a[i] for a in answers.values() if not a[i].startswith("error")}
        if len(given) != 1:
            sys.exit(f"the Chaskey witnesses disagree on {request}: {given}")
    key, plain, cipher = felix(out)
    for witness in ("rust-chaskey", "volexity-chaskey"):
        if ask(out, witness, [f"cipher 16 {key.hex()} {plain.hex()}"]) != [cipher.hex()]:
            sys.exit(f"{witness} does not reproduce the FELIX Chaskey-LTS block")
    # volexity's tests/test_chaskey.py: "foo" under CTR from the counter
    # "0000000000000000" (ASCII) and the key "0123456789012345".
    test = os.path.join(out, "src", "chaskey-lts", "tests", "test_chaskey.py")
    if 'assert ciphertext == b"\\x2b\\xda\\xd6"' not in open(test).read():
        sys.exit(f"{test} no longer carries the CTR test this checks")
    request = f"cipher 16 {b'0123456789012345'.hex()} {b'0000000000000000'.hex()}"
    for witness in ("rust-chaskey", "volexity-chaskey"):
        block = bytes.fromhex(ask(out, witness, [request])[0])
        if bytes(a ^ b for a, b in zip(block, b"foo")) != bytes.fromhex("2bdad6"):
            sys.exit(f"{witness} does not reproduce volexity's CTR test")
    return len(published)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/macwitness"
    tests = published(out)
    for witness in PMAC:
        if ask(out, witness, [q for q, _ in tests]) != [t for _, t in tests]:
            sys.exit(f"{witness} does not reproduce the published PMAC-AES tests")

    requests = []
    for cipher, key_len in KEYS.items():
        key = bytes(range(1, key_len + 1))
        for length in (0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100):
            requests.append(f"pmac {cipher} {h(key)} {h(bytes(range(length)))}")
    answers = {w: ask(out, w, requests) for w in PMAC}
    for i, request in enumerate(requests):
        cipher = request.split()[1]
        given = {answers[w][i] for w in PMAC if cipher in PMAC[w]}
        if len(given) != 1 or any(a.startswith("error") for a in given):
            sys.exit(f"the PMAC witnesses disagree on {request}: {given}")

    fast = ask(out, "ltc-pmac-fast", requests)
    differs = [r for r, a, b in zip(requests, fast, answers["ltc-pmac"]) if a != b]
    if not differs or any(r.split()[1] == "aes" for r in differs):
        sys.exit("libtomcrypt's LTC_FAST PMAC no longer differs only over 64 bit "
                 f"ciphers: {differs[:3]}")
    # VMAC: the draft's five tests for each tag, which head Crypto++'s file.
    key, nonce = b"abcdefghijklmnop".hex(), b"bcdefghi".hex()
    draft = {8: ["2576be1c56d8b81b", "2d376cf5b1813ce5", "e8421f61d573d298",
                 "4492df6c5cac1bbe"],
             16: ["472766c70f74ed23481d6d7de4e80dac", "4ee815a06a1d71edd36fc75d51188a42",
                  "09f2c80c8e1007a0c12fae19fe4504ae", "66438817154850c61d8a412164803bcb"]}
    path = os.path.join(out, "src", "cryptopp", "TestVectors", "vmac.txt")
    printed = [line.split(":", 1)[1].replace(" ", "").strip().lower()
                 for line in open(path) if line.startswith("MAC:")]
    for tag_len, tags in draft.items():
        if not all(t in printed for t in tags):
            sys.exit(f"{path} no longer carries the draft's {tag_len * 8} bit tests")
    messages = ["-", b"abc".hex(), (b"abc" * 16).hex(), (b"abc" * 100).hex()]
    for tag_len, tags in draft.items():
        witnesses = ["cryptopp-vmac"] + (["kernel-vmac"] if tag_len == 8 else [])
        requests = [f"vmac aes {key} {nonce} {m} {tag_len}" for m in messages]
        for witness in witnesses:
            if ask(out, witness, requests) != tags:
                sys.exit(f"{witness} does not reproduce the draft's VMAC-{tag_len * 8} tests")
    requests = []
    for length in range(1, 17):
        n = bytes([0x7f]) + bytes(range(1, length)) if length else b""
        requests.append(f"vmac aes {bytes(range(16)).hex()} {n.hex()} {bytes(range(length * 13)).hex() or '-'} 8")
    if ask(out, "cryptopp-vmac", requests) != ask(out, "kernel-vmac", requests):
        sys.exit("Crypto++ and the kernel disagree on VMAC-64")

    chaskey = check_chaskey(out)

    print(f"mac witnesses: {len(tests)} published PMAC tests reproduced, the three "
          f"agree; LTC_FAST differs on {len(differs)} 64 bit rows; the draft's VMAC "
          f"tests reproduced and the two VMAC witnesses agree; {chaskey} published "
          f"Chaskey tags reproduced, the Chaskey witnesses agree, and both block "
          f"ciphers give the FELIX block")


if __name__ == "__main__":
    main()
