#!/usr/bin/env python3
"""Every witness in OUT must reproduce the published vectors its projects
carry, both ways, a block at a time, at the round count each test names.
Run by build.sh; exits non-zero on the first failure.

    python3 selftest.py /opt/oldciphers

The readers of libtomcrypt's `tests[]` self-tests and Botan's
validate.dat are ../nessie/published.py's; a cipher that is another read
in a different byte order takes that one's tests, transformed. Read here: Crypto++'s
TestData files, one test per line, with the key lengths and round counts
its validat4.cpp runs each group of lines at; libtomcrypt's SAFER tests,
which are separate arrays and a setup call; and libtomcrypt's default
round counts, from its tomcrypt_cipher.h, for the test that leaves its
count out; the test in a libmcrypt module's own self-test function; the
LOKI97 reference's self-test with Crypt::Loki97's Perl tests; Crypto++'s
TestVectors files; go-krypto's test case lists; Project Nayuki's
SHACAL tests; PRESENT.go's test cases; NTT's FEAL-NX test data; and the
Simon and Speck papers' tests as inmcm's tests carry them. A cipher whose witnesses encrypt only is asked only that.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "nessie"))
import published  # noqa: E402

# Where each cipher's published tests are. They are required of every
# program named <cipher>-<source>.
#
#   libtomcrypt   (file, test function, macros) of a `tests[]` self-test
#   ltc_safer     the array prefix of a libtomcrypt SAFER test
#   botan         a section of validate.dat; a round count in brackets
#                 in its name, SAFER-SK(10), is the tests' round count
#   testdata      a Crypto++ TestData file
#   mcrypt        a libmcrypt module whose _mcrypt_self_test is a test
#   validat       (Crypto++ class, key length): which groups of the
#                 TestData file's lines are this cipher's, read from the
#                 calls in validat4.cpp that consume them
#   same_as       (cipher, transform[, key lengths]): another cipher's
#                 published tests, with the key, the block and the result
#                 each passed through the transform - for a cipher that is
#                 another read in a different byte order - and only those
#                 with a key of the given lengths, when they are given
#   loki97        the LOKI97 reference's self-test and Crypt::Loki97's
#                 tests t/01.t to t/06.t
#   testvectors   (file, name suffix): a Crypto++ TestVectors file's
#                 encryption tests under the names ending in the suffix;
#                 a test's Tweak, where it has one, follows its key
#   gokrypto      (package, files): go-krypto's tests, its BlockTestCase
#                 lists, which for LEA and HIGHT are KISA's known-answer
#                 tests, and for HIGHT the standard's examples too
#   project79068  a test file of Project Nayuki's library: its
#                 testCipher calls on SHACAL-1
#   presentgo     a Go test file of Nirusu/PRESENT.go: its test cases,
#                 Key, Plaintext and Ciphertext
#   ntt           NTT's FEAL-NX test data, in Shift JIS: ten keys, each
#                 with 4,096 blocks, at 32 rounds
#   inmcm_tests   (family, block bits): the paper's tests as inmcm's
#                 test_simonspeck.py has them, integers read as the
#                 designers' little-endian byte encoding
#   lengths       {source: key lengths}: a source that takes only these,
#                 asked only the tests with them
#   encrypt_only  the witnesses encrypt only, so only encryption is
#                 asked of them
#   witnesses     how many programs it needs, when not two: a cipher
#                 with one implementation here in each of two byte
#                 orders has one each, and the vectors script puts every
#                 input through both, each in its own order
CIPHERS = {
    "skipjack": {"block": 8, "libtomcrypt": ("skipjack.c", "skipjack_test", ("LTC_SKIPJACK",))},
    "skipjack-reversed": {"block": 8, "botan": "Skipjack", "testdata": "skipjack.dat"},
    "safer-k64": {"block": 8, "ltc_safer": "k64", "testdata": "saferval.dat",
                  "validat": ("SAFER_K", 8)},
    "safer-k128": {"block": 8, "testdata": "saferval.dat", "validat": ("SAFER_K", 16)},
    "safer-sk64": {"block": 8, "ltc_safer": "sk64", "testdata": "saferval.dat",
                   "validat": ("SAFER_SK", 8)},
    "safer-sk128": {"block": 8, "ltc_safer": "sk128", "botan": "SAFER-SK(10)",
                    "testdata": "saferval.dat", "validat": ("SAFER_SK", 16)},
    "square": {"block": 16, "botan": "Square", "testdata": "squareva.dat"},
    "kasumi": {"block": 8, "libtomcrypt": ("kasumi.c", "kasumi_test", ("LTC_KASUMI",)),
               "botan": "KASUMI"},
    "misty1": {"block": 8, "botan": "MISTY1"},
    "saferplus": {"block": 16, "libtomcrypt": ("saferp.c", "saferp_test", ("LTC_SAFERP",)),
                  "witnesses": 1},
    "saferplus-reversed-words": {"block": 16, "same_as": ("saferplus", "reverse_words"),
                                 "mcrypt": "saferplus.c", "witnesses": 1},
    "threeway": {"block": 12, "testdata": "3wayval.dat", "mcrypt": "3-way.c"},
    "loki97": {"block": 16, "loki97": True, "witnesses": 1},
    # libmcrypt pads every key to 32 bytes, so only the 32 byte tests are
    # the same cipher in its order.
    "loki97-mcrypt": {"block": 16, "mcrypt": "loki97.c",
                      "same_as": ("loki97", "swap_word_bytes", (32,)), "witnesses": 1},
    "lea": {"block": 16, "testvectors": ("lea.txt", "/ECB"),
            "gokrypto": ("lea", ("test_128_test.go", "test_196_test.go", "test_256_test.go"))},
    "hight": {"block": 8, "testvectors": ("hight.txt", "/ECB"),
              "gokrypto": ("hight", ("testcases_128_test.go",))},
    "speck32": {"block": 4, "inmcm_tests": ("speck", 32)},
    "speck48": {"block": 6, "inmcm_tests": ("speck", 48), "lengths": {"lwbc": (12,)}},
    "speck64": {"block": 8, "testvectors": ("speck.txt", "SPECK-64/ECB"),
                "lengths": {"lwbc": (16,)}},
    "speck96": {"block": 12, "inmcm_tests": ("speck", 96), "lengths": {"lwbc": (18,)}},
    "speck128": {"block": 16, "testvectors": ("speck.txt", "SPECK-128/ECB")},
    "simon32": {"block": 4, "inmcm_tests": ("simon", 32)},
    "simon48": {"block": 6, "inmcm_tests": ("simon", 48), "lengths": {"lwbc": (12,)}},
    "simon64": {"block": 8, "testvectors": ("simon.txt", "SIMON-64/ECB"),
                "lengths": {"lwbc": (16,)}},
    "simon96": {"block": 12, "inmcm_tests": ("simon", 96), "lengths": {"lwbc": (18,)}},
    "simon128": {"block": 16, "testvectors": ("simon.txt", "SIMON-128/ECB")},
    "present": {"block": 8, "presentgo": "present_test.go"},
    "feal-nx": {"block": 8, "ntt": "test-vectors.txt"},
    "shacal1": {"block": 20, "project79068": "ShacalTest.java", "encrypt_only": True},
    "threefish256": {"block": 32, "testvectors": ("threefish.txt", "Threefish-256(256)/ECB")},
    "threefish512": {"block": 64, "testvectors": ("threefish.txt", "Threefish-512(512)/ECB")},
    "threefish1024": {"block": 128,
                      "testvectors": ("threefish.txt", "Threefish-1024(1024)/ECB")},
}


def reverse_words(data):
    """`data` with its 32-bit words in the opposite order, each word's
    bytes kept as they are."""
    return b"".join(data[i:i + 4] for i in range(len(data) - 4, -1, -4))


def swap_word_bytes(data):
    """`data` with the bytes of each 32-bit word reversed."""
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


TRANSFORMS = {"reverse_words": reverse_words, "swap_word_bytes": swap_word_bytes}
SOURCES = ("libtomcrypt", "botan", "cryptopp", "bc", "reference", "mcrypt", "gokrypto", "kernel",
           "inmcm", "skein3fish", "openssl", "presentgo", "kurtfu", "opentitan", "zilijonas",
           "donaldduck8", "lwbc")


def testdata(text):
    """A Crypto++ TestData file of whitespace-separated key, plaintext
    and ciphertext, one test per line."""
    rows = []
    for line in text.split("\n"):
        fields = line.split()
        if len(fields) == 3:
            key, pt, ct = (bytes.fromhex(f) for f in fields)
            rows.append({"key": key, "pt": pt, "ct": ct})
    return rows


def mcrypt_selftest(text):
    """The test in a libmcrypt module's _mcrypt_self_test: a key of its
    key size with byte j `(j * 2 + 10) % 256`, a block with byte j `j`,
    and CIPHER, the ciphertext in hex. The formulas are required as
    written, so a module that builds its test differently is refused
    rather than misread."""
    sizes = {}
    for what in ("key", "block"):
        match = re.search(rf"_mcrypt_get_{what}_size\(\)\s*\{{\s*return (\d+);", text)
        if not match:
            sys.exit(f"no _mcrypt_get_{what}_size returning a constant")
        sizes[what] = int(match.group(1))
    if ("keyword[j] = ((j * 2 + 10) % 256);" not in text
            or not re.search(r"plaintext\[j\] = j( % 256)?;", text)):
        sys.exit("the self-test does not build its key and block as expected")
    ct = bytes.fromhex(re.search(r'#define CIPHER "([0-9a-f]+)"', text).group(1))
    if len(ct) != sizes["block"]:
        sys.exit("the self-test's CIPHER is not one block")
    return [{"key": bytes((j * 2 + 10) % 256 for j in range(sizes["key"])),
             "pt": bytes(range(sizes["block"])), "ct": ct}]


def loki97_tests(source, perl_tests):
    """The LOKI97 reference's self_test() - its key array, its plain
    block and the expected ciphertext - and each of Crypt::Loki97's
    tests: a key, one block given, and the answer `is` expects, which is
    the ciphertext when the plaintext was given and the plaintext when
    the ciphertext was."""
    body = source[source.index("int self_test()\n"):]
    arrays = {}
    for name, opening in (("key", "unsigned char hexkey[32] = {"), ("pt", "plain[BLOCK_SIZE] =")):
        at = body.index(opening) + len(opening)
        text = body[body.index("{", at - 1) + 1:body.index("}", at)]
        arrays[name] = bytes(int(v, 0) for v in re.findall(r"0[xX][0-9a-fA-F]+|\d+", text))
    ct = bytes.fromhex(re.search(r'hexcipher = "([0-9a-f]{32})"', body).group(1))
    if len(arrays["key"]) != 32 or len(arrays["pt"]) != 16:
        sys.exit("_loki97.c: the self-test's arrays are not 32 and 16 bytes")
    rows = [{"key": arrays["key"], "pt": arrays["pt"], "ct": ct}]
    for text in perl_tests:
        key = re.search(r'my \$key = pack "H32", "([0-9a-f]{32})"', text)
        given = re.search(r'my \$(plaintext|ciphertext) = pack "H32", "([0-9a-f]{32})"', text)
        answer = re.search(r'is\("([0-9a-f]{32})", \$answer\)', text)
        if not (key and given and answer):
            sys.exit("a Crypt::Loki97 test is not a key, a block and an answer")
        block, other = bytes.fromhex(given.group(2)), bytes.fromhex(answer.group(1))
        pt, ct = (block, other) if given.group(1) == "plaintext" else (other, block)
        row = {"key": bytes.fromhex(key.group(1)), "pt": pt, "ct": ct}
        if row not in rows:
            rows.append(row)
    return rows


def testvectors(text, suffix):
    """A Crypto++ TestVectors file: records of `Field: value` lines, a
    line ending in a backslash continued on the next, a Name carrying
    over until the next, each record ending at its Test line; the
    encryption tests whose Name ends in `suffix`. A test with a Tweak
    has it appended to its key, as the drivers take it."""
    rows, name, record = [], None, {}
    for line in re.sub(r"\\\n", " ", text).split("\n"):
        field, _, value = line.partition(":")
        field, value = field.strip(), value.strip()
        if field == "Name":
            name = value
        elif field in ("Key", "Tweak", "Plaintext", "Ciphertext"):
            record[field] = value
        elif field == "Test":
            if value == "Encrypt" and name and name.endswith(suffix):
                if set(record) - {"Tweak"} != {"Key", "Plaintext", "Ciphertext"}:
                    sys.exit(f"a {name} test without a key, plaintext and ciphertext")
                rows.append({"key": datum(record["Key"]) + datum(record.get("Tweak", "")),
                             "pt": datum(record["Plaintext"]),
                             "ct": datum(record["Ciphertext"])})
            record = {}
    return rows


def inmcm_tests(text, family, bits):
    """The paper's tests in inmcm's test_simonspeck.py: each
    `def test_<family><bits>_<key bits>` with `key = 0x...`,
    `plaintxt = 0x...` and `ciphertxt = 0x...`, the paper's integers,
    written here as their little-endian bytes. The file has each test
    twice, once per class; each is taken once."""
    rows = []
    for key_bits, key, pt, ct in re.findall(
            rf"def test_{family}{bits}_(\d+)\(self\):\s*key = 0x([0-9a-f]+)\s*"
            r"plaintxt = 0x([0-9a-f]+)\s*ciphertxt = 0x([0-9a-f]+)", text):
        row = {"key": int(key, 16).to_bytes(int(key_bits) // 8, "little"),
               "pt": int(pt, 16).to_bytes(bits // 8, "little"),
               "ct": int(ct, 16).to_bytes(bits // 8, "little")}
        if row not in rows:
            rows.append(row)
    return rows


def ntt_feal(text):
    """NTT's FEAL-NX test data: `KEY = <hex>`, then `PT: <hex>,  CT: <hex>`
    lines under it, at FEAL-NX's 32 rounds; ten keys of 4,096 blocks. The
    legend's own `KEY = ` line, which is not hex, is not one."""
    rows, key = [], None
    for line in text.split("\n"):
        line = line.strip()
        named = re.fullmatch(r"KEY = ([0-9A-F]{32})", line)
        if named:
            key = bytes.fromhex(named.group(1))
        found = re.fullmatch(r"PT: ([0-9A-F]{16}),\s+CT: ([0-9A-F]{16})", line)
        if found:
            rows.append({"key": key, "pt": bytes.fromhex(found.group(1)),
                         "ct": bytes.fromhex(found.group(2)), "rounds": 32})
    if len(rows) != 40960:
        sys.exit(f"NTT's FEAL-NX data: {len(rows)} blocks, not 40,960")
    return rows


def presentgo(text):
    """PRESENT.go's test cases: `Key: "..."`, `Plaintext: "..."` and
    `Ciphertext: "..."` in turn, in hex in the specification's order."""
    rows = []
    for key, pt, ct in re.findall(r'Key:\s*"([0-9A-Fa-f]+)",\s*Plaintext:\s*"([0-9A-Fa-f]+)",'
                                  r'\s*Ciphertext:\s*"([0-9A-Fa-f]+)"', text):
        rows.append({"key": bytes.fromhex(key), "pt": bytes.fromhex(pt), "ct": bytes.fromhex(ct)})
    return rows


def project79068(text):
    """Project Nayuki's SHACAL tests: `testCipher(new Shacal(true, N),
    key, plaintext, ciphertext)`, the true for SHACAL-1 and N the key's
    length in bytes, which each key must have."""
    rows = []
    for length, key, pt, ct in re.findall(
            r'testCipher\(new Shacal\(true, (\d+)\),\s*"([0-9A-Fa-f]+)",\s*"([0-9A-Fa-f]+)",'
            r'\s*"([0-9A-Fa-f]+)"\)', text):
        if len(key) != 2 * int(length):
            sys.exit(f"a SHACAL-1 test whose key is not {length} bytes")
        rows.append({"key": bytes.fromhex(key), "pt": bytes.fromhex(pt), "ct": bytes.fromhex(ct)})
    return rows


def datum(value):
    """A TestVectors value: hex digits, a list of 0xNN bytes, or `word64`
    and 64-bit words in hex, each stored little-endian, which Crypto++
    reads all three; anything else is refused rather than guessed at.
    Only the records a cipher uses are read, so a typo elsewhere in a
    file does not stop it."""
    if value.startswith("word64 "):
        words = value[len("word64 "):].split()
        if not all(re.fullmatch(r"[0-9A-Fa-f]{16}", w) for w in words):
            sys.exit(f"not a list of 64-bit words: {value}")
        return b"".join(int(w, 16).to_bytes(8, "little") for w in words)
    if re.fullmatch(r"(0[xX][0-9A-Fa-f]{2}\s*,?\s*)+", value):
        return bytes(int(v, 16) for v in re.findall(r"0[xX]([0-9A-Fa-f]{2})", value))
    return bytes.fromhex(value)


def gokrypto(text):
    """go-krypto's BlockTestCase entries: Key, Plain and Secure, each a
    backquoted hex string, spaces allowed, and `Reverse: true` on an
    entry printed as its standard prints it, most significant byte first,
    which go-krypto reverses before use and so does this. The count is
    required to be the number of entries the file opens."""
    found = re.findall(r"\{\s*(Reverse:\s*(?:true|false),\s*)?Key:\s*`([0-9A-Fa-f ]+)`,"
                       r"\s*Plain:\s*`([0-9A-Fa-f ]+)`,\s*Secure:\s*`([0-9A-Fa-f ]+)`,?\s*\}",
                       text)
    if len(found) != text.count("Key:"):
        sys.exit(f"{len(found)} go-krypto test cases read of {text.count('Key:')}")
    rows = []
    for reverse, *fields in found:
        k, p, c = (bytes.fromhex(f) for f in fields)
        if "true" in reverse:
            k, p, c = k[::-1], p[::-1], c[::-1]
        rows.append({"key": k, "pt": p, "ct": c})
    return rows


def validat_groups(text, data):
    """The calls in validat4.cpp that read `data`: in order, each
    (class, key length, rounds, how many lines it takes)."""
    body = text[text.index(f'DataDir("TestData/{data}")'):]
    body = body[:body.index("return pass;")]
    found = re.findall(r"VariableRoundsCipherFactory<(\w+)_Encryption, \w+>\((\d+),\s*(\d+)\),"
                       r"\s*valdata,\s*(\d+)\)", body)
    if not found:
        sys.exit(f"no calls read {data} in validat4.cpp")
    return [(cls, int(keylen), int(rounds), int(count)) for cls, keylen, rounds, count in found]


def ltc_defaults(text):
    """libtomcrypt's default SAFER round counts, by variant."""
    return {m.group(1).lower(): int(m.group(2)) for m in
            re.finditer(r"#define LTC_SAFER_(K64|K128|SK64|SK128)_DEFAULT_NOF_ROUNDS\s+(\d+)",
                        text)}


def ltc_safer(text, prefix, defaults):
    """libtomcrypt's SAFER test named by `prefix`: its three arrays and
    the round count its setup call passes, 0 meaning the default."""
    arrays = {}
    for name in ("pt", "key", "ct"):
        match = re.search(rf"\b{prefix}_{name}\[\]\s*=\s*\{{([^}}]*)\}}", text)
        arrays[name] = bytes(int(v, 0) for v in re.findall(r"0x[0-9a-fA-F]+|\d+", match.group(1)))
    setup = re.search(rf"safer_{prefix}_setup\({prefix}_key,\s*(\d+),\s*(\d+),", text)
    if int(setup.group(1)) != len(arrays["key"]):
        sys.exit(f"the {prefix} test's key length is not its array's")
    rounds = int(setup.group(2)) or defaults[prefix]
    return [{"key": arrays["key"], "pt": arrays["pt"], "ct": arrays["ct"], "rounds": rounds}]


def vectors(out, cipher):
    """(key, plaintext block, ciphertext block, rounds) for each published
    test; rounds is 0 where the cipher has no round count."""
    where = CIPHERS[cipher]
    src = os.path.join(out, "src")
    read = lambda *path: open(os.path.join(src, *path)).read()  # noqa: E731
    rows = []
    if "libtomcrypt" in where:
        name, function, defined = where["libtomcrypt"]
        for row in published.libtomcrypt(read("libtomcrypt", name), function, defined):
            # A test of several key lengths pads every key to the longest.
            if "keylen" in row:
                row["key"] = row["key"][:row["keylen"]]
            rows.append(row)
    if "same_as" in where:
        other, transform, *lengths = where["same_as"]
        f = TRANSFORMS[transform]
        for key, pt, ct, rounds in vectors(out, other):
            if not lengths or len(key) in lengths[0]:
                rows.append({"key": f(key), "pt": f(pt), "ct": f(ct), "rounds": rounds})
    if "testvectors" in where:
        name, suffix = where["testvectors"]
        rows += testvectors(read("cryptopp", name), suffix)
    if "gokrypto" in where:
        package, files = where["gokrypto"]
        for name in files:
            rows += gokrypto(read("go-krypto", package, name))
    if "inmcm_tests" in where:
        rows += inmcm_tests(read("inmcm", "test_simonspeck.py"), *where["inmcm_tests"])
    if "ntt" in where:
        rows += ntt_feal(open(os.path.join(src, "feal", where["ntt"]), encoding="shift_jis").read())
    if "presentgo" in where:
        rows += presentgo(read("presentgo", where["presentgo"]))
    if "project79068" in where:
        rows += project79068(read("project79068", where["project79068"]))
    if "loki97" in where:
        tests = [read("reference", "t", f"{n:02}.t") for n in range(1, 7)]
        rows += loki97_tests(read("reference", "_loki97.c"), tests)
    if "mcrypt" in where:
        rows += mcrypt_selftest(read("mcrypt", where["mcrypt"]))
    if "ltc_safer" in where:
        defaults = ltc_defaults(read("libtomcrypt", "tomcrypt_cipher.h"))
        rows += ltc_safer(read("libtomcrypt", "safer.c"), where["ltc_safer"], defaults)
    if "botan" in where:
        section = where["botan"]
        bracket = re.search(r"\((\d+)\)$", section)
        for row in published.botan(read("botan", "validate.dat"), section):
            row["rounds"] = int(bracket.group(1)) if bracket else 0
            rows.append(row)
    if "testdata" in where:
        lines = testdata(read("cryptopp", where["testdata"]))
        if "validat" not in where:
            rows += lines
        else:
            at = 0
            for cls, keylen, rounds, count in validat_groups(read("cryptopp", "validat4.cpp"),
                                                             where["testdata"]):
                group, at = lines[at:at + count], at + count
                if (cls, keylen) == where["validat"]:
                    for row in group:
                        if len(row["key"]) != keylen:
                            sys.exit(f"{where['testdata']}: a {cls} line is not {keylen} bytes")
                        row["rounds"] = rounds
                        rows.append(row)
            if at != len(lines):
                sys.exit(f"{where['testdata']}: {len(lines)} lines, the calls read {at}")
    block = where["block"]
    for row in rows:
        for i in range(0, len(row["pt"]), block):
            yield row["key"], row["pt"][i:i + block], row["ct"][i:i + block], row.get("rounds", 0)


def ask(program, requests, rounds=0):
    """`requests` to `program`, at `rounds` rounds (0: the program's
    default, or a cipher without a count)."""
    env = dict(os.environ)
    env.pop("ROUNDS", None)
    if rounds:
        env["ROUNDS"] = str(rounds)
    return subprocess.run([program], input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True, env=env).stdout.split()


def main():
    out = sys.argv[1]
    for cipher in CIPHERS:
        rows = list(vectors(out, cipher))
        if not rows:
            sys.exit(f"no published vectors found for {cipher}")
        found = 0
        for source in SOURCES:
            program = os.path.join(out, f"{cipher}-{source}")
            if not os.path.exists(program):
                continue
            lengths = CIPHERS[cipher].get("lengths", {}).get(source)
            asked = 0
            for rounds in sorted({r for *_, r in rows}):
                some = [(k, p, c) for k, p, c, r in rows
                        if r == rounds and (lengths is None or len(k) in lengths)]
                if not some:
                    continue
                asked += len(some)
                requests = [f"enc {k.hex()} {p.hex()}" for k, p, _ in some]
                expected = [c.hex() for _, _, c in some]
                if not CIPHERS[cipher].get("encrypt_only"):
                    requests += [f"dec {k.hex()} {c.hex()}" for k, _, c in some]
                    expected += [p.hex() for _, p, _ in some]
                if ask(program, requests, rounds) != expected:
                    sys.exit(f"{cipher}-{source} does not reproduce the published vectors"
                             + (f" at {rounds} rounds" if rounds else ""))
            if not asked:
                sys.exit(f"{cipher}-{source} takes the key of none of the published vectors")
            print(f"{cipher}-{source}: {asked} published blocks, "
                  + ("encrypted" if CIPHERS[cipher].get("encrypt_only") else "both ways"))
            found += 1
        needed = CIPHERS[cipher].get("witnesses", 2)
        if found < needed:
            sys.exit(f"{cipher} has {found} witnesses built; it needs {needed}")


if __name__ == "__main__":
    main()
