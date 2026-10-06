#!/usr/bin/env python3
"""The Office example (`examples/products/office`) against
msoffcrypto-tool, LibreOffice and documents Office wrote.

  * **Office and LibreOffice write, ours decrypts**: msoffcrypto-tool's
    test documents, which Office wrote (agile AES-256 with SHA-512, and
    standard AES-128), must decrypt to exactly the package
    msoffcrypto-tool's own tests expect; LibreOffice writes a document,
    spreadsheet and presentation with a password (standard encryption,
    in the version installed), which ours must decrypt to the package
    msoffcrypto-tool decrypts.
  * **msoffcrypto-tool encrypts, ours decrypts** (agile, AES-256 and
    SHA-512, the only parameters it writes), byte for byte.
  * **Ours encrypts, they decrypt**: agile under AES-128, 192 and 256
    with SHA-1, SHA-256, SHA-384 and SHA-512, and standard under
    AES-128, 192 and 256. LibreOffice 24.2 must open each one it reads
    (agile AES-128 with SHA-1 or SHA-384 and AES-256 with SHA-512;
    standard AES-128) with the password, find the content the plain
    package has, and refuse a wrong password. msoffcrypto-tool must
    decrypt the rest of them to the package byte for byte, except
    where it cannot: it reads an agile 192-bit key as 256 bits, does
    not pad a derived key longer than the hash, and checks a SHA-1
    HMAC with the padding left on its key - so agile AES-192, and
    AES-256 with SHA-1, have no witness here, and a SHA-1 package is
    decrypted without its integrity check.
  * **The binary formats, ours decrypts**: Office's `.doc` and `.xls`
    under RC4 CryptoAPI and its `.xls` under XOR obfuscation, and
    LibreOffice's `.doc` (one with a picture, which puts it in the Data
    stream) and `.xls` under Office 97's RC4. Every stream must be what
    msoffcrypto-tool decrypts - but for the Word encryption header,
    which it decrypts into noise and ours zeroes - and LibreOffice must
    read ours, with no password, as it reads the original with one.
  * Ours refuses a wrong password, and refuses an agile package whose
    encrypted bytes were changed.

    python3 scripts/check_office.py --msoffcrypto ~/src/msoffcrypto-tool \\
        --olefile ~/src/olefile
    python3 scripts/check_office.py ... --record

`--record` keeps the Office- and LibreOffice-written documents and some
of ours, with the SHA-256 of each package, in
`examples/products/fixtures/office/` for the offline tests.

**A development tool, not a test.** Build ours first:
`cargo build --release --example office`. LibreOffice is driven through
UNO (`python3-uno`), headless, with its own profile in a temporary
directory.
"""

import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

from libreoffice_uno import CONTENT, LibreOffice, write_png

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "office")
PASSWORD = "Pässword 1234"
OFFICE_PASSWORD = "Password1234_"

# msoffcrypto-tool's test documents: input, expected output.
OFFICE_FILES = [("example_password.docx", "example.docx"),
                ("example_password.xlsx", "example.xlsx"),
                ("ecma376standard_password.docx", "ecma376standard_password_plain.docx")]

# The binary formats: msoffcrypto-tool's test documents, which Office
# wrote, and what LibreOffice writes.
BINARY_OFFICE = [("rc4cryptoapi_password.doc", OFFICE_PASSWORD),
                 ("rc4cryptoapi_password.xls", OFFICE_PASSWORD),
                 ("xor_password_123456789012345.xls", "123456789012345")]
BINARY_LIBREOFFICE = [("swriter", "MS Word 97", "doc"), ("scalc", "MS Excel 97", "xls")]

AGILE = [(bits, h) for bits in (128, 192, 256) for h in ("SHA1", "SHA256", "SHA384", "SHA512")]
STANDARD = [128, 192, 256]
# What LibreOffice 24.2 reads (oox/source/crypto: AgileEngine.cxx and
# Standard2007Engine.cxx at libreoffice-24.2.7.2).
LIBREOFFICE_AGILE = {(128, "SHA1"), (128, "SHA384"), (256, "SHA512")}
LIBREOFFICE_STANDARD = {128}
HASH_BITS = {"SHA1": 160, "SHA256": 256, "SHA384": 384, "SHA512": 512}


PLAIN = [("swriter", "MS Word 2007 XML", "docx"),
         ("scalc", "Calc MS Excel 2007 XML", "xlsx"),
         ("simpress", "Impress MS PowerPoint 2007 XML", "pptx")]


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, **kwargs)


class Tally:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
            print(f"ok   {what}")
        else:
            self.failed += 1
            print(f"FAIL {what}")
            if detail:
                text = detail.decode(errors="replace") if isinstance(detail, bytes) else detail
                print("     " + str(text).strip()[:600].replace("\n", "\n     "))


def ms_decrypt(path, password, integrity=True):
    import msoffcrypto
    with open(path, "rb") as f:
        office = msoffcrypto.OfficeFile(f)
        office.load_key(password=password)
        out = io.BytesIO()
        if integrity:
            office.decrypt(out, verify_integrity=True)
        else:
            office.decrypt(out)
        return out.getvalue()


def ole_streams(path):
    import olefile
    ole = olefile.OleFileIO(path)
    out = {"/".join(entry): ole.openstream(entry).read() for entry in ole.listdir()}
    ole.close()
    return out


def word_header(streams):
    """A Word document's table stream and the length of the encryption
    header at its start, or (None, 0)."""
    document = streams.get("WordDocument")
    if document is None:
        return None, 0
    flags = int.from_bytes(document[10:12], "little")
    return ("1Table" if flags & 0x200 else "0Table"), int.from_bytes(document[14:18], "little")


def check_binary(tally, args, lo, work, label, path, password, recorded, expected_text=None):
    """Ours decrypts a .doc or .xls: every stream as msoffcrypto-tool
    decrypts it (bar the Word encryption header, which it decrypts into
    noise and ours zeroes), and LibreOffice reads ours, with no
    password, as it reads the original with one."""
    theirs_path = os.path.join(work, "theirs" + os.path.splitext(path)[1])
    import msoffcrypto
    with open(path, "rb") as f:
        office = msoffcrypto.OfficeFile(f)
        office.load_key(password=password)
        with open(theirs_path, "wb") as out:
            office.decrypt(out)
    got, error = ours_decrypt(args, path, password, work)
    if got is None:
        tally.check(False, f"{label}: ours decrypts", error)
        return
    ours_path = os.path.join(work, "ours" + os.path.splitext(path)[1])
    with open(ours_path, "wb") as f:
        f.write(got)
    theirs, ours = ole_streams(theirs_path), ole_streams(ours_path)
    table, header = word_header(ole_streams(path))
    problem = None if sorted(theirs) == sorted(ours) else f"{sorted(ours)} vs {sorted(theirs)}"
    for name in sorted(theirs):
        if problem:
            break
        skip = header if name == table else 0
        if ours[name][skip:] != theirs[name][skip:] or len(ours[name]) != len(theirs[name]):
            problem = f"stream {name!r} differs"
        elif any(ours[name][:skip]):
            problem = "the encryption header was left in the table stream"
    tally.check(not problem, f"{label}: every stream as msoffcrypto-tool decrypts it",
                problem or "")
    wanted = lo.read(path, password)
    text = lo.read(ours_path)
    tally.check(text == wanted and bool(text) and (expected_text is None or text == expected_text),
                f"{label}: LibreOffice reads ours as it reads the original",
                f"{text!r} vs {wanted!r}")
    wrong, _ = ours_decrypt(args, path, "not the password", work)
    tally.check(wrong is None, f"  {label}: a wrong password refused")
    if not problem:
        digests = {name: (header if name == table else 0,
                          hashlib.sha256(data[header if name == table else 0:]).hexdigest())
                   for name, data in ours.items()}
        recorded.append((label.replace(" ", "-").replace("/", "-"), path, password, digests))


def ms_encrypt(plain, path, password):
    import msoffcrypto
    with open(plain, "rb") as f:
        office = msoffcrypto.format.ooxml.OOXMLFile(f)
        with open(path, "wb") as out:
            office.encrypt(password, out)


def ours_decrypt(args, path, password, work):
    out = os.path.join(work, "ours-plain.bin")
    result = run([args.ours, "decrypt", path, out, "--password-stdin"],
                 input=(password + "\n").encode())
    if result.returncode:
        return None, result.stderr
    with open(out, "rb") as f:
        return f.read(), b""


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--msoffcrypto", required=True)
    parser.add_argument("--olefile", required=True)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    sys.path[:0] = [args.msoffcrypto, args.olefile]
    tally = Tally()
    work = tempfile.mkdtemp()
    recorded = []
    office_tests = os.path.join(args.msoffcrypto, "tests")

    print("== Office's documents, ours decrypts")
    for name, expected in OFFICE_FILES:
        path = os.path.join(office_tests, "inputs", name)
        with open(os.path.join(office_tests, "outputs", expected), "rb") as f:
            want = f.read()
        got, error = ours_decrypt(args, path, OFFICE_PASSWORD, work)
        tally.check(got == want, f"{name}: the package msoffcrypto-tool's tests expect", error)
        wrong, _ = ours_decrypt(args, path, "not the password", work)
        tally.check(wrong is None, f"  {name}: a wrong password refused")
        if got == want:
            recorded.append((f"office-{os.path.splitext(name)[0]}", path, OFFICE_PASSWORD, want))

    lo = LibreOffice(work)
    try:
        print("== LibreOffice writes, ours decrypts")
        plains = []
        for kind, filter_name, extension in PLAIN:
            plain = os.path.join(work, f"plain.{extension}")
            lo.make(kind, plain, filter_name)
            plains.append((kind, plain))
            path = os.path.join(work, f"libreoffice.{extension}")
            lo.make(kind, path, filter_name, PASSWORD)
            want = ms_decrypt(path, PASSWORD, integrity=False)
            got, error = ours_decrypt(args, path, PASSWORD, work)
            tally.check(got == want and want is not None,
                        f"libreoffice .{extension}: the package msoffcrypto-tool decrypts", error)
            if got == want:
                recorded.append((f"libreoffice-{extension}", path, PASSWORD, want))

        print("== msoffcrypto-tool encrypts, ours decrypts")
        for kind, plain in plains:
            extension = plain.rsplit(".", 1)[1]
            path = os.path.join(work, f"msoffcrypto.{extension}")
            ms_encrypt(plain, path, PASSWORD)
            with open(plain, "rb") as f:
                want = f.read()
            got, error = ours_decrypt(args, path, PASSWORD, work)
            tally.check(got == want, f"msoffcrypto-tool .{extension}: decrypted byte for byte",
                        error)
            if got == want and kind == "swriter":
                recorded.append((f"msoffcrypto-{extension}", path, PASSWORD, want))

        print("== ours encrypts, LibreOffice and msoffcrypto-tool decrypt")
        schemes = ([("agile", bits, h) for bits, h in AGILE]
                   + [("standard", bits, "SHA1") for bits in STANDARD])
        for kind, plain in plains:
            extension = plain.rsplit(".", 1)[1]
            with open(plain, "rb") as f:
                want = f.read()
            expected_text = lo.read(plain)
            # Or every comparison below would pass on two empty strings.
            tally.check(expected_text == CONTENT[kind],
                        f"LibreOffice reads its own plain .{extension} back",
                        f"{expected_text!r}")
            for method, bits, hash_name in schemes:
                label = f"ours {method} AES-{bits}" + (f" {hash_name}" if method == "agile" else "")
                path = os.path.join(work, f"ours-{method}-{bits}-{hash_name}.{extension}")
                made = run([args.ours, "encrypt", plain, path, "--password-stdin", "--method",
                            method, "--key-bits", str(bits), "--hash", hash_name,
                            "--spin-count", "10000"], input=(PASSWORD + "\n").encode())
                if made.returncode:
                    tally.check(False, f"{label} .{extension}", made.stderr)
                    continue
                readable = ((bits, hash_name) in LIBREOFFICE_AGILE if method == "agile"
                            else bits in LIBREOFFICE_STANDARD)
                witnessed = False
                if readable:
                    witnessed = True
                    text = lo.read(path, PASSWORD)
                    tally.check(text == expected_text and text is not None,
                                f"{label} .{extension}: LibreOffice opens it",
                                f"{text!r} vs {expected_text!r}")
                    tally.check(lo.read(path, "not the password") is None,
                                f"  {label} .{extension}: LibreOffice refuses a wrong password")
                # msoffcrypto-tool takes the decrypted key whole, so it
                # reads a 192-bit key as 256 bits; and it does not pad a
                # derived key that is longer than the hash.
                if method == "standard" or (bits != 192 and HASH_BITS[hash_name] >= bits):
                    witnessed = True
                    try:
                        theirs = ms_decrypt(path, PASSWORD,
                                            integrity=(method == "agile" and hash_name != "SHA1"))
                        problem = None if theirs == want else "different bytes"
                    except Exception as error:  # noqa: BLE001 - reported
                        problem = f"{type(error).__name__}: {error}"
                    tally.check(not problem, f"{label} .{extension}: msoffcrypto-tool decrypts",
                                problem or "")
                got, error = ours_decrypt(args, path, PASSWORD, work)
                tally.check(got == want, f"{label} .{extension}: ours decrypts its own", error)
                if kind == "swriter" and got == want and witnessed:
                    tag = f"{method}-{bits}" + (f"-{hash_name}" if method == "agile" else "")
                    recorded.append((f"ours-{tag}", path, PASSWORD, want))

        print("== the binary formats: ours decrypts")
        for name, password in BINARY_OFFICE:
            check_binary(tally, args, lo, work, "office-" + name.replace(".", "-"),
                         os.path.join(office_tests, "inputs", name), password, recorded)
        for kind, filter_name, extension in BINARY_LIBREOFFICE:
            path = os.path.join(work, f"libreoffice.{extension}")
            lo.make(kind, path, filter_name, PASSWORD)
            check_binary(tally, args, lo, work, f"libreoffice-{extension}", path, PASSWORD,
                         recorded, CONTENT[kind])
        # A picture puts a Data stream in a .doc, which is encrypted too.
        picture = os.path.join(work, "picture.png")
        write_png(picture)
        path = os.path.join(work, "libreoffice-picture.doc")
        lo.make("swriter", path, "MS Word 97", PASSWORD, picture=picture)
        tally.check("Data" in ole_streams(path), "LibreOffice's .doc with a picture has a "
                    "Data stream")
        check_binary(tally, args, lo, work, "libreoffice-picture-doc", path, PASSWORD,
                     recorded)

        print("== a changed agile package is refused")
        path = os.path.join(work, "ours-agile-256-SHA512.docx")
        sys.path[:0] = [args.olefile]
        import olefile
        with open(path, "rb") as f:
            data = bytearray(f.read())
        ole = olefile.OleFileIO(bytes(data))
        start = ole.root.kids_dict["encryptedpackage"].isectStart
        # The package is in ordinary 512-byte sectors; flip a bit in its
        # last whole block, far from the size field.
        offset = 512 * (start + 1) + 600
        data[offset] ^= 1
        changed = os.path.join(work, "changed.docx")
        with open(changed, "wb") as f:
            f.write(data)
        got, error = ours_decrypt(args, changed, PASSWORD, work)
        tally.check(got is None and b"integrity" in error,
                    "a flipped bit in an agile package is refused", error)
    finally:
        lo.close()

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    if args.record and not tally.failed:
        record(args, recorded)
    shutil.rmtree(work)
    return 1 if tally.failed else 0


def record(args, recorded):
    directory = os.path.join(FIXTURES, "office")
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)
    lines = ["# Encrypted Office documents and the SHA-256 of the package each",
             "# decrypts to - or, for .doc and .xls, of each stream - written by",
             "# scripts/check_office.py --record. Files",
             "# named office-* are msoffcrypto-tool's test documents, which Office",
             "# wrote (see office/NOTICE); libreoffice-* LibreOffice wrote;",
             "# msoffcrypto-* msoffcrypto-tool encrypted; ours-* the example",
             "# encrypted, each opened by LibreOffice, msoffcrypto-tool or both.", "",
             "[document]"]
    for label, path, password, plain in recorded:
        name = label + os.path.splitext(path)[1]
        shutil.copy(path, os.path.join(directory, name))
        lines += [f"name = {name}", f"password = {password.encode().hex()}"]
        if isinstance(plain, dict):
            # A binary document: each stream's path (hex, it may hold
            # control characters), how many leading bytes are not
            # compared, and the SHA-256 of the rest.
            for stream, (skip, digest) in sorted(plain.items()):
                lines.append(f"stream = {stream.encode().hex()} {skip} {digest}")
        else:
            lines += [f"size = {len(plain)}", f"sha256 = {hashlib.sha256(plain).hexdigest()}"]
    with open(os.path.join(FIXTURES, "office.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    with open(os.path.join(directory, "NOTICE"), "w") as out:
        out.write("The office-* files are test documents from msoffcrypto-tool\n"
                  "(github.com/nolze/msoffcrypto-tool, tests/inputs/), under this "
                  "licence:\n\n")
        out.write(open(os.path.join(args.msoffcrypto, "LICENSE.txt")).read())
    print(f"{len(recorded)} documents -> {directory}")


if __name__ == "__main__":
    sys.exit(main())
