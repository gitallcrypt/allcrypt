#!/usr/bin/env python3
"""Write vectors/dstu4145.vec: DSTU 4145-2002 signatures, public keys,
compression and Diffie-Hellman over binary curves.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/cryptonite/build.sh /opt/cryptonite
    python3 scripts/make_dstu4145_vectors.py

**A development tool, not a test.** It fetches three files once, each
checked against its SHA-256 - Bouncy Castle's `DSTU4145Test.java` and
cryptonite's two test files for the algorithm - and
`tests/test_dstu4145.rs` reads `vectors/dstu4145.vec` offline.

Two implementations that share no code: Bouncy Castle 1.77
(`DSTU4145Signer`, `DSTU4145PointEncoder`, its EC agreements) and
PrivatBank's cryptonite. Bouncy Castle signs with an `e` handed to it
through its random source, which is how its own tests reproduce the
standard's example; cryptonite draws `e` from its own generator, so it
verifies every signature here rather than making one. Diffie-Hellman
comes from cryptonite, which returns the whole shared point, and Bouncy
Castle must agree on its x coordinate.

In order:

1. The examples. Bouncy Castle's file signs with a fixed `e` on five
   curves given whole; the first is the standard's own worked example
   (`source=standard`), which cryptonite's acceptance test verifies
   under the same numbers. cryptonite's unit tests give a public key,
   its compression, two signatures and a shared point on the named
   curves (`source=cryptonite-tests`). Every witness that takes an
   example must reproduce it.
2. Rows both witnesses agree on (`source=both`), on all ten named
   curves and the four curves of the examples: public keys (including
   d = 1 and d = n - 1), compressions read back by both, signatures
   over 32-byte hashes - longer than some fields and shorter than
   others - each verified by both, changed copies that both refuse,
   and shared points with and without the cofactor.
3. Signatures over hashes of 0, 1, 20, 64 and 77 bytes, and their
   changed copies, from Bouncy Castle alone (`source=bouncycastle`):
   cryptonite takes a 32-byte hash and nothing else.

Rows, integers and field elements as big-endian hex, "-" for empty:

    pub curve= d= qx= qy=
    compress curve= qx= qy= packed=
    sign curve= d= e= hash= r= s=
    verify curve= qx= qy= hash= r= s= ok=
    dh curve= d= qx= qy= cofactor= zx= zy=

`curve` is `dstu4145-m163` to `dstu4145-m431`, or a curve given whole
as `M:K3,K2,K1:A:B:N:GX:GY` (one K for a trinomial). `hash` is the
byte string handed to the signer, which reads it little endian.
"""

import hashlib
import os
import random
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "dstu4145.vec")
PARAMS = os.path.join(ROOT, "src", "ec", "dstu4145_params.rs")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
CRYPTONITE = os.environ.get("CRYPTONITE_WITNESS", "/opt/cryptonite")
CN_BASE = "https://raw.githubusercontent.com/privat-it/cryptonite/master/src/"
ATEST_URL = CN_BASE + "cryptoniteAtest/c/atest_dstu4145.c"
ATEST_SHA256 = "6935b53448f47e5d60a9d374d21cfe4455b4c56ebd60c7829ba6bd768aacb569"
UTEST_URL = CN_BASE + "cryptoniteUtest/c/utest_dstu4145.c"
UTEST_SHA256 = "5d1ac9cff7caedeb543fba84eec95ce136476505741527041fec4b462d36775e"
BC_URL = ("https://raw.githubusercontent.com/bcgit/bc-java/r1rv77/core/src/test/java/"
          "org/bouncycastle/crypto/test/DSTU4145Test.java")
BC_SHA256 = "be878efb6baf14b4dd2d843de152758dbd92e477c0a7ac5f3dfde78c59054cf0"
NAMES = ["dstu4145-m163", "dstu4145-m167", "dstu4145-m173", "dstu4145-m179",
         "dstu4145-m191", "dstu4145-m233", "dstu4145-m257", "dstu4145-m307",
         "dstu4145-m367", "dstu4145-m431"]


def fetch(url, digest):
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data.decode()


def h(b):
    return b.hex() or "-"


def x(v):
    s = f"{v:x}"
    return "0" * (len(s) % 2) + s


class Curve:
    """What the script needs to know of a curve: its name in the file and
    in each witness's spelling, m and n."""

    def __init__(self, name, m, n, spec):
        self.name, self.m, self.n, self.spec = name, m, n, spec

    def fe(self, v):
        return f"{v:0{(self.m + 7) // 8 * 2}x}"

    def __repr__(self):
        return self.name


def named_curves():
    text = open(PARAMS, encoding="utf-8").read()
    # The file also holds the normal-basis curves, as OnbParams, which
    # this script does not use; \b keeps them out of the count.
    found = re.findall(r'\bParams \{ m: (\d+),.*?n: "(\w+)"', text, re.S)
    if len(found) != 10:
        sys.exit(f"read {len(found)} curves from {PARAMS}")
    return [Curve(NAMES[i], int(m), int(n, 16), str(i)) for i, (m, n) in enumerate(found)]


def given_curve(m, terms, a, b, n, gx, gy):
    spec = ":".join([str(m), ",".join(str(t) for t in terms), str(a), x(b), x(n), x(gx), x(gy)])
    return Curve(spec, m, n, spec)


def run(command, op, lines, who):
    out = subprocess.run(command + [op], input="".join(line + "\n" for line in lines),
                         check=True, capture_output=True, text=True).stdout.split("\n")
    out = out[:len(lines)]
    if len(out) != len(lines):
        sys.exit(f"{who} answered {len(out)} of {len(lines)}")
    for line, request in zip(out, lines):
        if line.startswith("error"):
            sys.exit(f"{who} refused {op} {request}: {line}")
    return [line.split() for line in out]


def bc(op, lines):
    return run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness"], op, lines, "Bouncy Castle")


def cn(op, lines):
    return run([f"{CRYPTONITE}/cryptonite-witness", "0"], op, lines, "cryptonite")


def both(op, lines):
    a, b = bc(op, lines), cn(op, lines)
    for request, p, q in zip(lines, a, b):
        if [int(v, 16) for v in p] != [int(v, 16) for v in q]:
            sys.exit(f"the witnesses disagree on {op} {request}: {p} and {q}")
    return a


def bouncy_castle_examples(text):
    """(curve, d, e bytes, hash, r, s) from each test in DSTU4145Test.java."""
    out = []
    for body in re.split(r"private void test", text)[1:]:
        if "generateSignature" not in body:
            continue
        rnd = re.search(r'TestRandomData\(Hex\.decode\("(\w+)"\)\)', body).group(1)
        message = bytes.fromhex(re.search(r'hash = Hex\.decode\("(\w+)"\)', body).group(1))
        if "hash[i] = hash[hash.length - 1 - i]" in body:
            message = message[::-1]
        c = re.search(r'new ECCurve\.F2m\((\d+), (\d+), (\d+), (\d+), (ONE|ZERO), '
                      r'new BigInteger\("(\w+)", 16\)', body)
        g = re.search(r'createPoint\(new BigInteger\("(\w+)", 16\), new BigInteger\("(\w+)", 16\)\)',
                      body)
        n = int(re.search(r'BigInteger n = new BigInteger\("(\w+)", 16\)', body).group(1), 16)
        d = int(re.search(r'BigInteger d = new BigInteger\("(\w+)", 16\)', body).group(1), 16)
        r = int(re.search(r'BigInteger r = new BigInteger\("(\w+)", 16\)', body).group(1), 16)
        s = int(re.search(r'BigInteger s = new BigInteger\("(\w+)", 16\)', body).group(1), 16)
        m, k1, k2, k3 = (int(v) for v in c.groups()[:4])
        curve = given_curve(m, [k3, k2, k1], 1 if c.group(5) == "ONE" else 0, int(c.group(6), 16),
                            n, int(g.group(1), 16), int(g.group(2), 16))
        # The signer takes (bit_len(n) - 1 + 7) / 8 bytes, masks the
        # spare top bits, and reads them big endian.
        bits = n.bit_length() - 1
        e = int.from_bytes(bytes.fromhex(rnd)[:(bits + 7) // 8], "big") & ((1 << bits) - 1)
        out.append((curve, d, e, message, r, s))
    return out


def cryptonite_values(text, function):
    """The named byte arrays in one of cryptonite's test functions: an
    integer for each, and the bytes as cryptonite holds them."""
    body = text[text.index(f"static void {function}(void)"):]
    body = body[:body.index("\n}\n")]
    values = {}
    for name, order, digits in re.findall(
            r'(\w+)\s*=\s*ba_alloc_from_(le|be)_hex_string\(\s*"(\w+)"\s*\)', body, re.S):
        raw = bytes.fromhex("0" * (len(digits) % 2) + digits)
        held = raw if order == "le" else raw[::-1]
        values[name] = (int.from_bytes(held, "little"), held)
    return body, values


def main():
    bc_text = fetch(BC_URL, BC_SHA256)
    atest = fetch(ATEST_URL, ATEST_SHA256)
    utest = fetch(UTEST_URL, UTEST_SHA256)
    named = named_curves()
    rows = []

    def pub_row(c, d, qx, qy, source):
        if any(row.startswith(f"pub curve={c} d={x(d)} ") for row in rows):
            return
        rows.append(f"pub curve={c} d={x(d)} qx={c.fe(qx)} qy={c.fe(qy)} source={source}")

    def verify_row(c, qx, qy, message, r, s, ok, source):
        rows.append(f"verify curve={c} qx={c.fe(qx)} qy={c.fe(qy)} hash={h(message)} r={x(r)} "
                    f"s={x(s)} ok={int(ok)} source={source}")

    def verify_both(c, qx, qy, message, r, s):
        """Both witnesses' verdict, or Bouncy Castle's alone for a hash
        that is not 32 bytes, which cryptonite refuses. r and s go to
        cryptonite at n's width: it takes an odd total length of the two
        as a failed signature."""
        width = (c.n.bit_length() + 7) // 8 * 2
        line = (f"{c.spec} {c.fe(qx)} {c.fe(qy)} {h(message)} {r:0{width}x} {s:0{width}x}")
        witness = both if len(message) == 32 else bc
        return witness("dstu4145-verify", [line])[0] == ["01"]

    def source_for(message, source="both"):
        return source if len(message) == 32 else "bouncycastle"

    # 1. The examples.
    examples = bouncy_castle_examples(bc_text)
    if len(examples) != 5:
        sys.exit(f"read {len(examples)} signing examples from Bouncy Castle's test")
    given = []
    for i, (c, d, e, message, r, s) in enumerate(examples):
        source = "standard" if i == 0 else "bouncycastle-tests"
        got = bc("dstu4145-sign", [f"{c.spec} {x(d)} {x(e)} {h(message)}"])[0]
        if [int(v, 16) for v in got] != [r, s]:
            sys.exit(f"Bouncy Castle misses its own example on {c.m} bits")
        qx, qy = (int(v, 16) for v in both("dstu4145-pub", [f"{c.spec} {x(d)}"])[0])
        if not verify_both(c, qx, qy, message, r, s):
            sys.exit(f"the example on {c.m} bits does not verify")
        pub_row(c, d, qx, qy, source)
        rows.append(f"sign curve={c} d={x(d)} e={x(e)} hash={h(message)} r={x(r)} s={x(s)} "
                    f"source={source}")
        verify_row(c, qx, qy, message, r, s, True, source)
        if c.spec not in [g.spec for g in given]:
            given.append(c)
    standard = examples[0]

    # cryptonite's acceptance test: the standard's example, verified.
    body, v = cryptonite_values(atest, "dstu4145_verify_pn")
    f = [int(t) for t in re.search(r"int f\[5\] = \{([\d, ]+)\}", body).group(1).split(",")]
    a = int(re.search(r"int a = (\d);", body).group(1))
    c = given_curve(f[0], [t for t in f[1:] if t], a, v["b"][0], v["n"][0], v["px_d"][0],
                    v["py_d"][0])
    if c.spec != standard[0].spec or (v["r"][0], v["s"][0]) != standard[4:]:
        sys.exit("cryptonite's acceptance test is not the standard's example")
    if v["hash"][1] != standard[3]:
        sys.exit("cryptonite's acceptance test hashes other bytes")
    if not verify_both(c, v["px_pub"][0], v["py_pub"][0], v["hash"][1], v["r"][0], v["s"][0]):
        sys.exit("cryptonite's acceptance test does not verify")

    # cryptonite's unit tests, on the named curves.
    m257, m367 = named[6], named[8]
    _, v = cryptonite_values(utest, "dstu4145_keys_test")
    d, qx, qy, packed = v["key"][0], v["qx"][0], v["qy"][0], v["q"][0]
    if both("dstu4145-pub", [f"6 {x(d)}"])[0] != [m257.fe(qx), m257.fe(qy)]:
        sys.exit("cryptonite's public key example is not reproduced")
    if [int(t, 16) for t in both("dstu4145-compress", [f"6 {m257.fe(qx)} {m257.fe(qy)}"])[0]] \
            != [packed]:
        sys.exit("cryptonite's compression example is not reproduced")
    pub_row(m257, d, qx, qy, "cryptonite-tests")
    rows.append(f"compress curve={m257} qx={m257.fe(qx)} qy={m257.fe(qy)} "
                f"packed={m257.fe(packed)} source=cryptonite-tests")
    for function, c in (("dstu4145_verify_test", m257), ("dstu4145_verify_367_test", m367)):
        _, v = cryptonite_values(utest, function)
        args = (v["qx"][0], v["qy"][0], v["hash"][1], v["r"][0], v["s"][0])
        if not verify_both(c, *args):
            sys.exit(f"cryptonite's {function} does not verify")
        verify_row(c, *args, True, "cryptonite-tests")
    _, v = cryptonite_values(utest, "dstu4145_dh_test")
    d1, d2, zx, zy = v["key1"][0], v["key2"][0], v["zx_exp"][0], v["zy_exp"][0]
    q2 = cn("dstu4145-pub", [f"6 {x(d2)}"])[0]
    line = f"6 {x(d1)} {q2[0]} {q2[1]} 1"
    if cn("dstu4145-dh", [line])[0] != [m257.fe(zx), m257.fe(zy)] \
            or int(bc("dstu4145-dh", [line])[0][0], 16) != zx:
        sys.exit("cryptonite's shared point example is not reproduced")
    rows.append(f"dh curve={m257} d={x(d1)} qx={q2[0]} qy={q2[1]} cofactor=1 "
                f"zx={m257.fe(zx)} zy={m257.fe(zy)} source=cryptonite-tests")
    examples_count = len(rows)

    # 2. Both.
    rng = random.Random(0x4145)
    others = [0, 1, 20, 64, 77]
    for index, c in enumerate(named + given):
        ds = [1, c.n - 1] + [rng.randrange(1, c.n) for _ in range(3)]
        keys = both("dstu4145-pub", [f"{c.spec} {x(d)}" for d in ds])
        for d, (qx, qy) in zip(ds, keys):
            pub_row(c, d, int(qx, 16), int(qy, 16), "both")
        packed = both("dstu4145-compress", [f"{c.spec} {qx} {qy}" for qx, qy in keys])
        back = both("dstu4145-decompress", [f"{c.spec} {p[0]}" for p in packed])
        for (qx, qy), p, q in zip(keys, packed, back):
            if [int(t, 16) for t in q] != [int(qx, 16), int(qy, 16)]:
                sys.exit(f"a compression on {c} does not read back")
            rows.append(f"compress curve={c} qx={qx} qy={qy} packed={c.fe(int(p[0], 16))} "
                        f"source=both")
        bits = c.n.bit_length() - 1
        signs = []
        for i in range(3):
            d = ds[2 + i]
            e = rng.randrange(1, 1 << bits)
            message = rng.randbytes(32 if i < 2 else others[index % len(others)])
            r, s = (int(t, 16) for t in bc("dstu4145-sign", [f"{c.spec} {x(d)} {x(e)} {h(message)}"])[0])
            signs.append((d, e, message, r, s, keys[2 + i]))
        for i, (d, e, message, r, s, (qx, qy)) in enumerate(signs):
            qx, qy = int(qx, 16), int(qy, 16)
            if not verify_both(c, qx, qy, message, r, s):
                sys.exit(f"a signature on {c} does not verify")
            rows.append(f"sign curve={c} d={x(d)} e={x(e)} hash={h(message)} r={x(r)} s={x(s)} "
                        f"source={source_for(message)}")
            verify_row(c, qx, qy, message, r, s, True, source_for(message))
            # A changed copy: r, s, the hash, or the key.
            other = signs[(i + 1) % len(signs)][5]
            changed = [(qx, qy, message, r ^ 1, s), (qx, qy, message, r, (s + 1) % c.n),
                       (qx, qy, bytes([message[0] ^ 0x80]) + message[1:] if message
                        else b"\x02", r, s),
                       (int(other[0], 16), int(other[1], 16), message, r, s)][(i + index) % 4:(i + index) % 4 + 1]
            changed.append((qx, qy, message, r, s ^ (1 << (bits - 1))))
            for args in changed:
                if args[3] == 0 or args[4] == 0:
                    continue
                if verify_both(c, *args):
                    sys.exit(f"a changed signature on {c} verifies")
                verify_row(c, *args, False, source_for(args[2]))
        for cofactor in (0, 1):
            d, (qx, qy) = ds[2 + cofactor], keys[4 - cofactor]
            line = f"{c.spec} {x(d)} {qx} {qy} {cofactor}"
            zx, zy = cn("dstu4145-dh", [line])[0]
            if int(bc("dstu4145-dh", [line])[0][0], 16) != int(zx, 16):
                sys.exit(f"the witnesses disagree on a shared point on {c}")
            rows.append(f"dh curve={c} d={x(d)} qx={qx} qy={qy} cofactor={cofactor} zx={zx} "
                        f"zy={zy} source=both")

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# DSTU 4145-2002 over binary curves. Written by\n"
                  "# scripts/make_dstu4145_vectors.py; do not edit. source=standard: the\n"
                  "# standard's worked example as Bouncy Castle's and cryptonite's tests carry\n"
                  "# it; bouncycastle-tests and cryptonite-tests: their other examples; both:\n"
                  "# Bouncy Castle 1.77 and cryptonite agree (Bouncy Castle signs, both verify).\n"
                  f"# rows: {len(rows)}, examples: {examples_count}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(rows)} rows, {examples_count} examples", file=sys.stderr)


if __name__ == "__main__":
    main()
