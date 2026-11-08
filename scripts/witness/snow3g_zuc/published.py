#!/usr/bin/env python3
"""SNOW 3G's and ZUC's published test data, and the witnesses.

Imported by `selftest.py` and `scripts/make_snow3g_zuc_vectors.py`.

The published answers are ETSI/SAGE's implementors' test data, vendored
in `rfcs/` as PDF and as `pdftotext -layout` text
(`scripts/make_spec_text.py`), and read here from the text:

- `Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.txt` (v1.1): section 3, four
  SNOW 3G keystreams, the fourth to word 2500; section 4, five UEA2
  messages with the keystream and the result printed beside each other;
  section 5, six UIA2 MACs.
- `eea3eia3testdatav11.txt` (v1.1): section 3, four ZUC keystreams, the
  fourth to word 2000; section 4, five 128-EEA3 messages; section 5, five
  128-EIA3 MACs.

There is no published test data for ZUC-256 among them, so ZUC-256 is
checked by the witnesses agreeing with each other, and selftest.py
requires them to reproduce the ZUC-256 paper's zero-key keystream and MAC
values as Intel's own tests carry them.

One misprint is corrected: UEA2 test set 5's plaintext prints its twentieth
word `060876A0` as `60876A0`. The printed keystream and result settle it,
and the correction replaces that token only, asserting it is there.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
DOC3 = os.path.join(ROOT, "rfcs", "Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.txt")
ZUCDATA = os.path.join(ROOT, "rfcs", "eea3eia3testdatav11.txt")

#: witness program: the requests it takes, as "stream snow3g", "f8 uea2",
#: "f9 eia1", "zucmac 16/32" (key bytes / tag bits) and so on.
PROGRAMS = {
    "ref-snow3g": {"stream snow3g", "f8 uea2", "f9 uia2", "f9 eia1"},
    "ref-zuc": {"stream zuc128", "f8 eea3", "f9 eia3"},
    "ipsecmb": {"stream snow3g", "stream zuc128", "stream zuc256", "f8 uea2", "f8 eea3",
                "f9 uia2", "f9 eia1", "f9 eia3", "zucmac 16/32", "zucmac 32/32",
                "zucmac 32/64", "zucmac 32/128"},
    "gmssl-zuc": {"stream zuc128", "stream zuc256", "f8 eea3", "f9 eia3", "zucmac 16/32",
                  "zucmac 32/32", "zucmac 32/64", "zucmac 32/128"},
    "go-free5gc": {"stream snow3g", "stream zuc128", "f8 uea2", "f8 eea3", "f9 eia1",
                   "f9 eia3"},
    "bc-zuc": {"stream zuc128", "stream zuc256", "zucmac 16/32", "zucmac 32/32",
               "zucmac 32/64", "zucmac 32/128"},
    "rust-zuc": {"stream zuc128", "stream zuc256", "f8 eea3", "f9 eia3", "zucmac 16/32",
                 "zucmac 32/32", "zucmac 32/64", "zucmac 32/128"},
    "rust-oxirush": {"stream snow3g", "stream zuc128", "f8 uea2", "f8 eea3", "f9 eia1",
                     "f9 eia3"},
}
#: The witnesses' names in the vector file.
SHORT = {"ref-snow3g": "ref", "ref-zuc": "ref", "ipsecmb": "ipsec-mb", "gmssl-zuc": "gmssl",
         "go-free5gc": "free5gc", "bc-zuc": "bc", "rust-zuc": "zuc-crate",
         "rust-oxirush": "oxirush"}


def short(program):
    return SHORT.get(program, program)


def kind(request):
    """The capability a request needs: "stream zuc128", "f9 eia3",
    "zucmac 32/64"."""
    f = request.split()
    if f[0] == "zucmac":
        return f"zucmac {len(f[2]) // 2}/{f[1]}"
    return f"{f[0]} {f[1]}"


def can_answer(program, request):
    """Whether the program implements what the request asks, within the
    limits it states: Bouncy Castle's MACs take whole bytes and its
    engines stop after 2047 (ZUC-128) and 625 (ZUC-256) keystream words,
    which bounds its MACs' messages too."""
    if kind(request) not in PROGRAMS[program]:
        return False
    f = request.split()
    if program == "bc-zuc":
        if f[0] == "zucmac":
            words = 2047 if len(f[2]) == 32 else 625
            # The MAC draws a word per 32 bits and up to five more.
            return int(f[4]) % 8 == 0 and int(f[4]) <= 32 * (words - 8)
        if f[0] == "stream" and int(f[4]) > 4 * (2047 if f[1] == "zuc128" else 625):
            return False
    return True


def refusal_expected(program, request):
    """A refusal that is a known limit rather than a fault, all of them of
    an empty message to a MAC: Intel's UIA2, EIA3 and both ZUC MACs refuse
    one, the
    reference f9 cannot take one, so its driver refuses it, and free5gc's
    NIA1 panics on one."""
    f = request.split()
    if f[0] not in ("f9", "zucmac"):
        return False
    bits = int(f[6]) if f[0] == "f9" else int(f[4])
    if bits != 0:
        return False
    if program == "ipsecmb":
        return True
    if program == "go-free5gc":
        return f[0] == "f9" and f[1] == "eia1"
    return program == "ref-snow3g" and f[0] == "f9"


def witnesses_needed(request):
    """Two, except for 128-EIA1 of an empty message: of the three SNOW 3G
    MACs only oxirush-security takes one (refusal_expected), so that one
    answer stands alone and the vector file names it alone."""
    f = request.split()
    if f[0] == "f9" and f[1] == "eia1" and f[6] == "0":
        return 1
    return 2


def ask_all(out, requests):
    """Each request put to every program that can answer it: a list, per
    request, of {program: answer}. An error from a program that claims
    the request is fatal unless refusal_expected says otherwise, and then
    the program is left out of that request."""
    answers = [dict() for _ in requests]
    for program in PROGRAMS:
        mine = [(i, r) for i, r in enumerate(requests) if can_answer(program, r)]
        for (i, r), got in zip(mine, ask(out, program, [r for _, r in mine])):
            if got.startswith("error"):
                if refusal_expected(program, r):
                    continue
                sys.exit(f"{program} answered {got!r} to {r[:200]}")
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


# Requests.

def stream(cipher, key, iv, n):
    return f"stream {cipher} {key.hex()} {iv.hex()} {n}"


def f8(alg, key, count, bearer, direction, bits, data):
    return f"f8 {alg} {key.hex()} {count:08x} {bearer} {direction} {bits} {data.hex() or '-'}"


def f9(alg, key, count, fresh, direction, bits, data):
    value = f"{fresh:08x}" if alg == "uia2" else str(fresh)
    return f"f9 {alg} {key.hex()} {count:08x} {value} {direction} {bits} {data.hex() or '-'}"


def zucmac(tagbits, key, iv, bits, data):
    return f"zucmac {tagbits} {key.hex()} {iv.hex()} {bits} {data.hex() or '-'}"


def clear_tail(data, bits):
    """The data with the bits past `bits` cleared, as the witnesses give
    an f8 result."""
    data = bytearray(data[:(bits + 7) // 8])
    if bits % 8:
        data[-1] &= (0xff << (8 - bits % 8)) & 0xff
    return bytes(data)


# The documents.

def _text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _sections(text, first, last):
    """The test sets between section `first` and the heading after
    `last`: {(section, set number): its text}. The table of contents
    lists the same headings with dot leaders, which are skipped."""
    found = {}
    heads = list(re.finditer(r"^\s*(\d)\.(\d)\.?\s+Test Set (\d+)\s*$", text, re.M))
    for i, m in enumerate(heads):
        section = int(m.group(1))
        if not first <= section <= last:
            continue
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        body = text[m.end():end]
        # A set ends at the next numbered section heading too.
        stop = re.search(r"^\s*\d\.?\s+[A-Z]{4}", body, re.M)
        found[(section, int(m.group(3)))] = body[:stop.start()] if stop else body
    return found


def _field(body, label, pattern=r"(.+)"):
    m = re.search(rf"^\s*{label}\s*[=:]\s*(?:\(hex\)\s*)?{pattern}\s*$", body, re.M | re.I)
    if not m:
        raise ValueError(f"no {label} in {body[:80]!r}")
    return m.group(1).strip()


def _bytes(body, label):
    return bytes.fromhex(_field(body, label, r"((?:[0-9A-Fa-f]{2}\s*)+?)"))


_FURNITURE = re.compile(r"3GPP Confidentiality|Implementor|page \d+ of", re.I)
_HEX = re.compile(r"^[0-9A-Fa-f]+$")


def _block(body, label, bits):
    """The hex block after `label` - "Plaintext:", "MESSAGE:" - up to the
    first line that is not hex, skipping page furniture and a "(hex)"
    prefix and stopping at a "(bin)" one: ceil(bits/8) bytes, the
    document's padding past them dropped. Returns the tokens too."""
    m = re.search(rf"^\s*{label}\s*:\s*$", body, re.M | re.I)
    if not m:
        raise ValueError(f"no {label}")
    tokens = []
    for line in body[m.end():].split("\n"):
        line = line.strip()
        if not line or _FURNITURE.search(line):
            continue
        if line.startswith("(bin)"):
            break
        if line.startswith("(hex)"):
            line = line[5:]
        words = line.split()
        if not all(_HEX.match(w) for w in words):
            break
        tokens += words
    return tokens


def _join(tokens, bits):
    data = bytes.fromhex("".join(tokens))
    need = (bits + 7) // 8
    if len(data) < need or len(data) - need >= 4:
        raise ValueError(f"{len(data)} bytes printed for {bits} bits")
    return data[:need]


def snow3g_keystreams():
    """Doc3 section 3: {key, iv, words: {index: z_index}} per set."""
    out = []
    for (_, number), body in sorted(_sections(_text(DOC3), 3, 3).items()):
        head = body.split("K0")[0]
        words = {int(i): int(w.replace(" ", ""), 16)
                 for i, w in re.findall(r"z(\d+):\s*((?:[0-9A-F]{2} ?){4})", head)}
        out.append({"set": number, "key": _bytes(head, "Key"), "iv": _bytes(head, "IV"),
                    "words": words})
    return out


def uea2_sets():
    """Doc3 section 4: count, bearer, direction, key, bits, plaintext,
    keystream (the printed words, whole) and the printed result."""
    out = []
    for (_, number), body in sorted(_sections(_text(DOC3), 4, 4).items()):
        bits = int(_field(body, "Length", r"(\d+)\s*bits"))
        tokens = _block(body, "Plaintext", bits)
        if number == 5:
            assert tokens.count("60876A0") == 1, "UEA2 set 5's misprint is not where it was"
            tokens[tokens.index("60876A0")] = "060876A0"
        keystream, result = [], []
        table = body.split("Wordnumber", 1)[1].split("\n", 1)[1]
        for line in table.split("\n"):
            f = line.split()
            if not f or not f[0].isdigit() or not all(_HEX.match(w) for w in f[1:]):
                continue
            half = (len(f) - 1) // 2
            keystream += f[1:1 + half]
            result += f[1 + half:]
        out.append({"set": number, "count": int(_field(body, "Count-C"), 16),
                    "bearer": int(_field(body, "Bearer"), 16),
                    "direction": int(_field(body, "Direction")),
                    "key": _bytes(body, "CK"), "bits": bits,
                    "plaintext": _join(tokens, bits),
                    "keystream": bytes.fromhex("".join(keystream)),
                    "result": bytes.fromhex("".join(result))})
    return out


def uia2_sets():
    """Doc3 section 5: count, fresh, direction, key, bits, message, MAC."""
    out = []
    for (_, number), body in sorted(_sections(_text(DOC3), 5, 5).items()):
        bits = int(_field(body, "LENGTH", r"(\d+)\s*bits"))
        out.append({"set": number, "count": int(_field(body, "COUNT-I"), 16),
                    "fresh": int(_field(body, "FRESH"), 16),
                    "direction": int(_field(body, "DIRECTION")),
                    "key": _bytes(body, "IK"), "bits": bits,
                    "message": _join(_block(body, "MESSAGE", bits), bits),
                    "mac": bytes.fromhex(_field(body, "MAC-I", r"([0-9A-F]{8})"))})
    return out


def zuc_keystreams():
    """The EEA3/EIA3 test data, section 3: {key, iv, words} per set."""
    out = []
    for (_, number), body in sorted(_sections(_text(ZUCDATA), 3, 3).items()):
        head = body.split("Initialisation Mode")[0]
        words = {int(i): int(w, 16) for i, w in re.findall(r"[zZ](\d+):\s*([0-9a-f]{8})", head)}
        out.append({"set": number, "key": _bytes(head, "Key"), "iv": _bytes(head, "IV"),
                    "words": words})
    return out


def eea3_sets():
    """Section 4: count, bearer, direction, key, bits, plaintext, ciphertext."""
    out = []
    for (_, number), body in sorted(_sections(_text(ZUCDATA), 4, 4).items()):
        bits = int(_field(body, "Length", r"(\d+)\s*bits"))
        out.append({"set": number, "count": int(_field(body, "Count", r"([0-9a-f]+)"), 16),
                    "bearer": int(_field(body, "Bearer", r"([0-9a-f]+)"), 16),
                    "direction": int(_field(body, "Direction", r"([01])")),
                    "key": _bytes(body, "Key"), "bits": bits,
                    "plaintext": _join(_block(body, "Plaintext", bits), bits),
                    "ciphertext": _join(_block(body, "Ciphertext", bits), bits)})
    return out


def eia3_sets():
    """Section 5: count, bearer, direction, key, bits, message, MAC."""
    out = []
    for (_, number), body in sorted(_sections(_text(ZUCDATA), 5, 5).items()):
        bits = int(_field(body, "Length", r"(\d+)\s*bits"))
        out.append({"set": number, "count": int(_field(body, "Count", r"([0-9a-f]+)"), 16),
                    "bearer": int(_field(body, "Bearer", r"([0-9a-f]+)"), 16),
                    "direction": int(_field(body, "Direction", r"([01])")),
                    "key": _bytes(body, "Key"), "bits": bits,
                    "message": _join(_block(body, "Message", bits), bits),
                    "mac": bytes.fromhex(_field(body, "MAC", r"([0-9a-f]{8})"))})
    return out


#: How many of each the documents hold; a parser that finds fewer has
#: missed a spelling, and that is an error rather than a smaller test.
COUNTS = {"snow3g": 4, "uea2": 5, "uia2": 6, "zuc": 4, "eea3": 5, "eia3": 5}


def published():
    """Every published set, counted, and the UEA2 sets checked against
    themselves: plaintext XOR keystream is the printed result."""
    sets = {"snow3g": snow3g_keystreams(), "uea2": uea2_sets(), "uia2": uia2_sets(),
            "zuc": zuc_keystreams(), "eea3": eea3_sets(), "eia3": eia3_sets()}
    for name, rows in sets.items():
        if len(rows) != COUNTS[name]:
            sys.exit(f"{name}: {len(rows)} test sets found, {COUNTS[name]} expected")
    for v in sets["uea2"]:
        xored = bytes(a ^ b for a, b in zip(v["plaintext"], v["keystream"]))
        if clear_tail(xored, v["bits"]) != clear_tail(v["result"], v["bits"]):
            sys.exit(f"UEA2 set {v['set']}: plaintext XOR keystream is not the printed result")
    if [len(v["words"]) for v in sets["snow3g"]] != [2, 2, 2, 4] or \
            [len(v["words"]) for v in sets["zuc"]] != [2, 2, 2, 3]:
        sys.exit("a keystream test set lost a word")
    return sets


def requests_for_published(sets):
    """Each published set as (request, what the answer must be, label)."""
    out = []
    for v in sets["snow3g"] + sets["zuc"]:
        cipher = "snow3g" if v in sets["snow3g"] else "zuc128"
        n = 4 * max(v["words"])
        want = {i: w for i, w in v["words"].items()}
        out.append((stream(cipher, v["key"], v["iv"], n), ("words", want),
                    f"{cipher} set {v['set']}"))
    for v in sets["uea2"]:
        out.append((f8("uea2", v["key"], v["count"], v["bearer"], v["direction"], v["bits"],
                       v["plaintext"]), ("bytes", clear_tail(v["result"], v["bits"])),
                    f"uea2 set {v['set']}"))
    for v in sets["eea3"]:
        out.append((f8("eea3", v["key"], v["count"], v["bearer"], v["direction"], v["bits"],
                       v["plaintext"]), ("bytes", clear_tail(v["ciphertext"], v["bits"])),
                    f"eea3 set {v['set']}"))
    for v in sets["uia2"]:
        out.append((f9("uia2", v["key"], v["count"], v["fresh"], v["direction"], v["bits"],
                       v["message"]), ("bytes", v["mac"]), f"uia2 set {v['set']}"))
    for v in sets["eia3"]:
        out.append((f9("eia3", v["key"], v["count"], v["bearer"], v["direction"], v["bits"],
                       v["message"]), ("bytes", v["mac"]), f"eia3 set {v['set']}"))
    return out


def answer_matches(want, got):
    shape, value = want
    data = bytes.fromhex(got)
    if shape == "bytes":
        return data == value
    return all(int.from_bytes(data[4 * (i - 1):4 * i], "big") == w for i, w in value.items())


# ZUC-256: Intel's test vectors, as intel-ipsec-mb 2.0.3 carries them
# (test/kat-app/zuc_eea3_256.json.c and zuc_eia3_256.json.c, vendored in
# vectors/zuc256/). Each is a C initialiser: sizes in bits, a test number,
# and string literals of \x escapes.

ZUC256_DIR = os.path.join(ROOT, "vectors", "zuc256")
_LITERALS = r"((?:\s*\"[^\"]*\")+)"


def _c_bytes(literals):
    return bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", literals))


def unpack_iv(iv):
    """A 23 byte ZUC-256 IV as the 25 byte one the specification writes:
    the last six bytes hold eight six bit values, first value highest."""
    if len(iv) == 25:
        return iv
    bits = int.from_bytes(iv[17:], "big")
    return iv[:17] + bytes((bits >> (42 - 6 * i)) & 0x3f for i in range(8))


def zuc256_keystreams():
    """The keystream vectors: {test, key, iv (25 bytes), bits, keystream}.
    Every message in the file is zeros, so the ciphertext is the
    keystream; that is checked."""
    with open(os.path.join(ZUC256_DIR, "zuc_eea3_256.json.c")) as handle:
        text = handle.read()
    entry = re.compile(r"\{\s*(\d+),\s*(\d+),\s*(\d+)," + ",".join([_LITERALS] * 4)
                       + r",\s*(\d+),\s*(\d+)\s*\}")
    out = []
    for m in entry.finditer(text):
        iv_bits, key_bits, test = int(m.group(1)), int(m.group(2)), int(m.group(3))
        key, iv, msg, ct = (_c_bytes(m.group(i)) for i in range(4, 8))
        bits = int(m.group(9))
        assert len(key) * 8 == key_bits and len(iv) * 8 == iv_bits and len(ct) * 8 == bits
        assert m.group(8) == "1" and msg == bytes(len(msg)), f"test {test} is not a keystream"
        out.append({"test": test, "key": key, "iv": unpack_iv(iv), "iv_as_given": iv,
                    "bits": bits, "keystream": ct})
    return out


def zuc256_macs():
    """The MAC vectors: {test, key, iv (25 bytes), tagbits, bits, message,
    tag}."""
    with open(os.path.join(ZUC256_DIR, "zuc_eia3_256.json.c")) as handle:
        text = handle.read()
    entry = re.compile(r"\{\s*(\d+),\s*(\d+),\s*(\d+)," + ",".join([_LITERALS] * 3)
                       + r",\s*(\d+),\s*(\d+)," + _LITERALS + r",\s*(\d+)\s*\}")
    out = []
    for m in entry.finditer(text):
        key_bits, tag_bits, test = int(m.group(1)), int(m.group(2)), int(m.group(3))
        key, msg, tag = (_c_bytes(m.group(i)) for i in range(4, 7))
        bits, iv, iv_bits = int(m.group(8)), _c_bytes(m.group(9)), int(m.group(10))
        assert m.group(7) == "1"
        assert len(key) * 8 == key_bits and len(tag) * 8 == tag_bits and len(iv) * 8 == iv_bits
        assert len(msg) == (bits + 7) // 8, f"test {test}: {len(msg)} bytes for {bits} bits"
        out.append({"test": test, "key": key, "iv": unpack_iv(iv), "iv_as_given": iv,
                    "tagbits": tag_bits, "bits": bits, "message": msg, "tag": tag})
    return out


#: How many vectors the two files hold, the terminating all-NULL entry not
#: counted.
ZUC256_COUNTS = (10, 36)


def zuc256_published():
    ks, macs = zuc256_keystreams(), zuc256_macs()
    if (len(ks), len(macs)) != ZUC256_COUNTS:
        sys.exit(f"ZUC-256: {len(ks)} keystreams and {len(macs)} MACs found, "
                 f"{ZUC256_COUNTS} expected")
    return ks, macs


def requests_for_zuc256(ks, macs):
    out = []
    for v in ks:
        out.append((stream("zuc256", v["key"], v["iv"], v["bits"] // 8),
                    ("bytes", v["keystream"]), f"zuc256 keystream test {v['test']}"))
    for v in macs:
        out.append((zucmac(v["tagbits"], v["key"], v["iv"], v["bits"], v["message"]),
                    ("bytes", v["tag"]), f"zuc256 mac test {v['test']}"))
    return out
