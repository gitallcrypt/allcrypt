#!/usr/bin/env python3
"""The KeePass example (`examples/products/keepass`) against
gokeepasslib, and against databases other KeePass applications wrote.

Both sides print a database in one canonical listing - format, cipher,
key derivation, then every group, string field and attachment as hex -
so every comparison here is two listings that must be identical:

  * **Databases other KeePass applications wrote**: gokeepasslib's
    test databases (KDBX 3.1, 4.0 and 4.1; AES, ChaCha20, Twofish;
    AES-KDF and Argon2d; uncompressed; key files; kdbxweb's protected
    attachments, in both versions) and pykeepass's (key files of
    each kind, a blank password, Argon2id). Ours and gokeepasslib both
    list each one. gokeepasslib has no Argon2id, so those files are
    opened by ours alone - the HMAC over the header and every block
    has to check, which it cannot under a wrong key.
  * **gokeepasslib writes, ours reads**: every format, cipher, key
    derivation and compression it has, with a password, a key file of
    each kind, and both.
  * **Ours writes, gokeepasslib reads**: the same, plus Argon2id, which
    only ours can read back.
  * A wrong password and a wrong key file are refused by both.

    python3 scripts/check_keepass.py [--witness PATH] [--ours PATH]
        [--gokeepasslib-tests DIR] [--pykeepass-tests DIR]
    python3 scripts/check_keepass.py --record

`--record` writes a set of gokeepasslib-made databases and gokeepasslib's
own test databases, each with gokeepasslib's listing, into
`examples/products/fixtures/keepass/` for the offline tests.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example keepass`.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures", "keepass")
WITNESS = "/opt/kdbxwitness/kdbxwitness"
OURS = os.path.join(ROOT, "target", "release", "examples", "keepass")

# gokeepasslib's tests/ and pykeepass's tests/: (file, password, key file).
GOKEEPASSLIB = [
    ("kdbx3/example.kdbx", "abcdefg12345678", None),
    ("kdbx3/example-key.kdbx", "abcdefg12345678", "kdbx3/example-key.key"),
    ("kdbx3/group-first.kdbx", "123", None),
    ("kdbx3/protected-binary.kdbx", "123", None),
    ("kdbx4/protected-binary.kdbx", "123", None),
    ("kdbx4/example.kdbx", "abcdefg12345678", None),
    ("kdbx4/example-key.kdbx", "abcdefg12345678", "kdbx4/example-key.key"),
    ("kdbx4/example-nocompression.kdbx", "abcdefg12345678", None),
    ("kdbx4/example-chacha.kdbx", "abcdefg12345678", None),
    ("kdbx4/example-chacha-argon2.kdbx", "abcdefg12345678", None),
    ("kdbx41/example.kdbx", "abcdefg12345678", None),
]
PYKEEPASS = [
    ("test3.kdbx", "password", "test3.key"),
    ("test4.kdbx", "password", "test4.key"),
    ("test4_aes.kdbx", "password", "test4.key"),
    ("test4_aeskdf.kdbx", "password", "test4.key"),
    ("test4_chacha20.kdbx", "password", "test4.key"),
    ("test4_twofish.kdbx", "password", "test4.key"),
    ("test4_hex.kdbx", "password", "test4_hex.key"),
    ("test4_aes_uncompressed.kdbx", "password", None),
    ("test4_chacha20_uncompressed.kdbx", "password", None),
    ("test4_twofish_uncompressed.kdbx", "password", None),
    ("test4_argon2id.kdbx", "password", None),
    ("test4_blankpass.kdbx", "", "test4.key"),
    ("test4_keyx.kdbx", "password", "test4_keyx.keyx"),
    ("extra_content.kdbx", "password", None),
]
# gokeepasslib has no Argon2id, and fails on test3.kdbx's empty
# attachment (`<Binary ID="0" Compressed="True"/>`, which KeePass writes
# for a zero-length file): ours alone opens these.
GOKEEPASSLIB_CANNOT = {"test4_argon2id.kdbx", "test3.kdbx"}
KEYFILES = ["bin_32_byte.key", "hex_64_byte.key", "non_hex_64_byte.key", "txt_derive.key",
            "xml_v1.0.key", "xml_v2.0.key"]


def witness_dump(witness, path, password, key):
    command = [witness, "dump", "-pass", password]
    if key:
        command += ["-key", key]
    result = subprocess.run(command + [path], capture_output=True, text=True)
    return result.returncode, (result.stdout if result.returncode == 0 else result.stderr)


def ours_dump(ours, path, password, key):
    command = [ours, "dump", path, "--canonical", "--password", password]
    if key:
        command += ["--key-file", key]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, (result.stdout if result.returncode == 0 else result.stderr)


class Tally:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
            print(f"ok   {what}")
        else:
            self.failed += 1
            print(f"FAIL {what}")
            if detail:
                print("     " + detail.strip().replace("\n", "\n     ")[:1500])


def compare(tally, args, what, path, password, key, witness_can=True):
    ours_code, ours_text = ours_dump(args.ours, path, password, key)
    if not witness_can:
        tally.check(ours_code == 0 and "\ngroup " in ours_text,
                    f"{what} (ours only)", ours_text)
        return ours_text
    witness_code, witness_text = witness_dump(args.witness, path, password, key)
    if witness_code != 0:
        tally.check(False, what, "gokeepasslib: " + witness_text)
        return None
    tally.check(ours_code == 0 and ours_text == witness_text, what,
                ours_text if ours_code else diff(witness_text, ours_text))
    return witness_text


def diff(a, b):
    for i, (x, y) in enumerate(zip(a.splitlines(), b.splitlines())):
        if x != y:
            return f"line {i + 1}:\n  gokeepasslib: {x}\n  ours:         {y}"
    return f"lengths differ: {len(a)} and {len(b)}"


def refuses(tally, args, what, path, password, key):
    ours_code, _ = ours_dump(args.ours, path, password, key)
    witness_code, _ = witness_dump(args.witness, path, password, key)
    tally.check(ours_code != 0 and witness_code != 0, what)


def matrix():
    """(name, witness create flags, ours create flags, gokeepasslib can read)."""
    rows = []
    for version, ours_format in (("3", "3"), ("40", "40"), ("41", "41")):
        for cipher in ("aes", "chacha20", "twofish"):
            kdfs = ["aes"] if version == "3" else ["aes", "argon2d", "argon2id"]
            for kdf in kdfs:
                name = f"kdbx{version}-{cipher}-{kdf}"
                witness = ["-version", version, "-cipher", cipher, "-kdf", kdf,
                           "-rounds", "1000", "-iterations", "2", "-memory", "1024"]
                ours = ["--format", ours_format, "--cipher", cipher, "--kdf", kdf,
                        "--rounds", "1000", "--iterations", "2", "--memory", "1024"]
                rows.append((name, witness, ours, kdf != "argon2id"))
    rows.append(("kdbx41-aes-aes-uncompressed",
                 ["-version", "41", "-kdf", "aes", "-rounds", "1000", "-compress=false"],
                 ["--format", "41", "--kdf", "aes", "--rounds", "1000", "--no-compress"], True))
    rows.append(("kdbx3-aes-aes-uncompressed",
                 ["-version", "3", "-rounds", "1000", "-compress=false"],
                 ["--format", "3", "--rounds", "1000", "--no-compress"], True))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--witness", default=WITNESS)
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--gokeepasslib-tests", required=True)
    parser.add_argument("--pykeepass-tests")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    tally = Tally()
    work = tempfile.mkdtemp()
    recorded = []
    go = args.gokeepasslib_tests

    print("== databases other KeePass applications wrote")
    for name, password, key in GOKEEPASSLIB:
        listing = compare(tally, args, f"gokeepasslib tests/{name}", os.path.join(go, name),
                          password, key and os.path.join(go, key))
        if listing:
            recorded.append(("go-" + name.replace("/", "-")[:-len(".kdbx")], os.path.join(go, name),
                             password,
                             key and os.path.join(go, key), listing))
    if args.pykeepass_tests:
        py = args.pykeepass_tests
        for name, password, key in PYKEEPASS:
            compare(tally, args, f"pykeepass tests/{name}", os.path.join(py, name), password,
                    key and os.path.join(py, key), witness_can=name not in GOKEEPASSLIB_CANNOT)

    print("== gokeepasslib writes, ours reads; ours writes, gokeepasslib reads")
    keyfiles = [None] + [os.path.join(go, "keyfiles", k) for k in KEYFILES]
    for index, (name, witness_flags, ours_flags, readable) in enumerate(matrix()):
        key = keyfiles[index % len(keyfiles)]
        password = f"pass {index} é"
        label = name + (f", key file {os.path.basename(key)}" if key else "")
        key_args_w = ["-key", key] if key else []
        key_args_o = ["--key-file", key] if key else []
        if readable:
            path = os.path.join(work, f"w-{name}.kdbx")
            made = subprocess.run([args.witness, "create", "-pass", password] + key_args_w +
                                  witness_flags + [path], capture_output=True, text=True)
            if made.returncode != 0:
                tally.check(False, f"gokeepasslib writes {label}", made.stderr)
            else:
                listing = compare(tally, args, f"gokeepasslib writes {label}", path, password,
                                  key)
                if listing:
                    recorded.append((f"w-{name}", path, password, key, listing))
                    refuses(tally, args, f"  a wrong password for {name}", path, password + "x",
                            key)
        path = os.path.join(work, f"o-{name}.kdbx")
        made = subprocess.run([args.ours, "create", path, "--password", password] + key_args_o +
                              ours_flags, capture_output=True, text=True)
        if made.returncode != 0:
            tally.check(False, f"ours writes {label}", made.stderr)
            continue
        compare(tally, args, f"ours writes {label}", path, password, key, witness_can=readable)

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    if args.record and not tally.failed:
        if os.path.isdir(FIXTURES):
            shutil.rmtree(FIXTURES)
        os.makedirs(FIXTURES)
        lines = ["# Databases and gokeepasslib's listing of each, written by",
                 "# scripts/check_keepass.py --record. Files named go-* are",
                 "# gokeepasslib's own test databases (MIT licence, see keepass/NOTICE);",
                 "# w-* gokeepasslib wrote.",
                 "", "[database]"]
        for name, path, password, key, listing in recorded:
            shutil.copy(path, os.path.join(FIXTURES, name + ".kdbx"))
            lines.append(f"name = {name}")
            lines.append(f"password = {password.encode().hex()}")
            if key:
                key_name = name + "-" + os.path.basename(key)
                shutil.copy(key, os.path.join(FIXTURES, key_name))
                lines.append(f"key_file = {key_name}")
            lines.append(f"listing = {listing.encode().hex()}")
        with open(os.path.join(FIXTURES, "..", "keepass.vec"), "w") as out:
            out.write("\n".join(lines) + "\n")
        license_text = open(os.path.join(go, "..", "LICENSE.md")).read()
        with open(os.path.join(FIXTURES, "NOTICE"), "w") as out:
            out.write("The go-*.kdbx databases and every key file here come from the tests\n"
                      "of gokeepasslib (github.com/tobischo/gokeepasslib, tests/). The\n"
                      "w-*.kdbx databases gokeepasslib wrote. Under this licence:\n\n")
            out.write(license_text)
        print(f"{len(recorded)} databases -> {FIXTURES}")
    shutil.rmtree(work)
    return 1 if tally.failed else 0


if __name__ == "__main__":
    sys.exit(main())
