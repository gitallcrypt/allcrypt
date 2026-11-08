#!/usr/bin/env python3
"""Write vectors/uea1_uia1.vec: UEA1 and UIA1, KASUMI's f8 and f9.

    sh scripts/witness/snow3g_zuc/build.sh /opt/gppwitness
    python3 scripts/make_uea1_uia1_vectors.py [/opt/gppwitness]

**A development tool, not a test.** `tests/test_uea1_uia1.rs` reads the
file offline, and reads Intel's tests itself from `vectors/kasumi_3gpp/`.

Two witnesses from scripts/witness/snow3g_zuc: the KASUMI reference
implementation with f8 and f9 from the specifications' annexes, as
CryptoMobile carries it (`ref-kasumi`), and intel-ipsec-mb (`ipsecmb`).
Before anything is written both must reproduce every one of Intel's UEA1
and UIA1 tests. Then random inputs at lengths either side of the byte and
block steps, every bearer and both directions, each written only when
both give the same answer. intel-ipsec-mb refuses a UIA1 of an empty
message, so that one row has the reference alone.

    uea1 key= count= bearer= dir= bits= data= out= witnesses=
    uia1 key= count= fresh= dir= bits= data= out= witnesses=

`data` carries random bits past `bits` in its last byte, which a MAC must
ignore and a ciphertext has cleared; "-" for none. COUNT and FRESH are hex.
"""

import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "uea1_uia1.vec")
WITNESSES = ["ref-kasumi", "ipsecmb"]


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def initialisers(path):
    """The fields of each initialiser in an intel-ipsec-mb test file."""
    text = re.sub(r"/\*.*?\*/", "", open(path).read(), flags=re.S)
    body = text[text.index("[] = {") + 6:]
    out = []
    for entry in body.split("},"):
        entry = entry.strip()
        if not entry.startswith("{") or "NULL" in entry:
            continue
        fields = re.findall(r'((?:"[^"]*"\s*)+|[^,{}"\s]+)', entry[1:])
        out.append([bytes.fromhex("".join(re.findall(r"\\x([0-9a-f]{2})", f)))
                    if f.startswith('"') else int(f) for f in fields])
    return out


def clear_tail(data, bits):
    data = bytearray(data)
    if bits % 8:
        data[-1] &= (0xff << (8 - bits % 8)) & 0xff
    return bytes(data)


def f8_request(key, count, bearer, direction, bits, data):
    return f"f8 uea1 {key.hex()} {count:08x} {bearer} {direction} {bits} {data.hex() or '-'}"


def f9_request(key, count, fresh, direction, bits, data):
    return f"f9 uia1 {key.hex()} {count:08x} {fresh:08x} {direction} {bits} {data.hex() or '-'}"


def published(out):
    """Every Intel test, through both witnesses."""
    vectors = os.path.join(ROOT, "vectors", "kasumi_3gpp")
    requests, expected = [], []
    for e in initialisers(os.path.join(vectors, "kasumi_f8.json.c")):
        key, iv, msg, ct, bits = e[3], e[4], e[5], e[6], e[8]
        n = (bits + 7) // 8
        requests.append(f8_request(key, int.from_bytes(iv[:4], "big"), iv[4] >> 3,
                                   iv[4] >> 2 & 1, bits, msg[:n]))
        expected.append(clear_tail(ct[:n], bits).hex())
    for e in initialisers(os.path.join(vectors, "kasumi_f9.json.c")):
        key, msg, tag, bits, iv = e[3], e[4], e[5], e[7], e[8]
        if iv:
            requests.append(f9_request(key, int.from_bytes(iv[1:5], "big"),
                                       int.from_bytes(iv[5:9], "big"), iv[0], bits,
                                       msg[:(bits + 7) // 8]))
        else:
            bit = lambda i: msg[i // 8] >> (7 - i % 8) & 1  # noqa: E731
            stop = max(i for i in range(bits) if bit(i))
            length = stop - 1 - 64
            requests.append(f9_request(key, int.from_bytes(msg[:4], "big"),
                                       int.from_bytes(msg[4:8], "big"), bit(stop - 1), length,
                                       clear_tail(msg[8:8 + (length + 7) // 8], length)))
        expected.append(tag.hex())
    if len(requests) != 49:
        sys.exit(f"read {len(requests)} of Intel's tests, not 49")
    for w in WITNESSES:
        for request, answer, want in zip(requests, ask(out, w, requests), expected):
            if answer != want:
                sys.exit(f"{w} does not reproduce Intel's test {request[:60]}: {answer}")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/gppwitness"
    published(out)
    rng = random.Random(19990801)
    inputs = []
    lengths = [0, 1, 2, 7, 8, 9, 31, 32, 33, 55, 56, 57, 62, 63, 64, 65, 66, 127, 128, 129,
               191, 192, 193, 255, 256, 257, 511, 512, 513, 798, 1000, 4095, 4096, 4097, 20000]
    for kind in ("uea1", "uia1"):
        for bits in lengths:
            for _ in range(3):
                key = rng.randbytes(16)
                count, value = rng.getrandbits(32), rng.getrandbits(32)
                direction = rng.getrandbits(1)
                data = rng.randbytes((bits + 7) // 8)
                if kind == "uea1":
                    inputs.append((kind, key, count, value % 32, direction, bits, data))
                else:
                    inputs.append((kind, key, count, value, direction, bits, data))
    requests = [(f8_request if k == "uea1" else f9_request)(key, c, v, d, b, data)
                for k, key, c, v, d, b, data in inputs]
    answers = {w: ask(out, w, requests) for w in WITNESSES}
    lines = []
    for i, (kind, key, count, value, direction, bits, data) in enumerate(inputs):
        given = {w: answers[w][i] for w in WITNESSES}
        if kind == "uia1" and bits == 0 and given["ipsecmb"] == "error refused":
            del given["ipsecmb"]
        for w, a in given.items():
            if a.startswith("error"):
                sys.exit(f"{w} refused {requests[i][:70]}: {a}")
        if len(set(given.values())) != 1:
            sys.exit(f"the witnesses disagree on {requests[i][:70]}: {given}")
        field = "bearer" if kind == "uea1" else "fresh"
        shown = str(value) if kind == "uea1" else f"{value:08x}"
        lines.append(f"{kind} key={key.hex()} count={count:08x} {field}={shown} dir={direction} "
                     f"bits={bits} data={data.hex() or '-'} out={next(iter(given.values())) or '-'} "
                     f"witnesses={','.join(given)}")

    header = [
        "# UEA1 and UIA1, KASUMI's f8 and f9. Written by scripts/make_uea1_uia1_vectors.py;",
        "# do not edit. data: the message, random bits past `bits` in its last byte; out: the",
        "# ciphertext with those bits cleared, or the MAC. COUNT and FRESH hex. witnesses: the",
        "# reference implementation as CryptoMobile carries it and intel-ipsec-mb, agreeing;",
        "# intel-ipsec-mb refuses an empty UIA1 message.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
