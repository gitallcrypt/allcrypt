#!/usr/bin/env python3
"""The PDF example (`examples/products/pdf`) against qpdf and pdftk.

qpdf is the judge throughout: `qpdf --json=2` lists every object of a
file - decrypting it, given a password - with each stream's data as
stored (filters left on, encryption taken off). Two files hold the same
document when those listings agree object for object, leaving out what
only describes the file's structure (cross-reference and object
streams, the `/Encrypt` dictionary, the trailer) and each stream's
`/Length`, which encryption changes.

  * **Decrypting what others encrypted**: qpdf's own test files - made
    by Acrobat XI and other writers, revisions 2 to 6, 40 to 256 bits,
    cleartext metadata, crypt filters named per stream, encrypted
    attachments, a signature, junk before the header, short `/O` and
    `/U`, user and owner passwords, long passwords - and files qpdf and
    pdftk encrypt here from a document the script writes, with and
    without object streams. Ours decrypts with each password the file
    has and must report the same password qpdf reports (owner when a
    password is both); the result must list as qpdf lists the encrypted
    original and must pass `qpdf --check`.
  * **Encrypting for others**: ours encrypts that document under every
    scheme; qpdf must open the result with the user and with the owner
    password, report the revision and cipher asked for, list it as the
    original, and pass `--check`; pdftk must decrypt it where it can
    (pdftk-java stops at revision 4). Ours also re-encrypts every one of
    qpdf's test files under every scheme, and qpdf must list each as
    the original.
  * A wrong password, and one a character short of what the revision
    reads, is refused.

    python3 scripts/check_pdf.py --qpdf-tests ~/src/qpdf/qpdf/qtest/qpdf
    python3 scripts/check_pdf.py --qpdf-tests DIR --record

`--record` keeps the qpdf test files (Apache-2.0, with the licence) and
the files encrypted here, with what qpdf listed of each, in
`examples/products/fixtures/pdf/` and `pdf.vec` for the offline tests.

**A development tool, not a test.** Build ours first:
`cargo build --release --example pdf`.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "pdf")

# qpdf's test files and the passwords to try, from their names and
# from qpdf's own test scripts (qtest/encryption.test). Which password
# each is - user or owner - is asked of qpdf.
LONG_V5 = "qwertyuiopasdfghjklzxcvbnm" * 5
QPDF_FILES = [
    ("enc-R2,V1.pdf", [""]),
    ("enc-R2,V1,O=master.pdf", ["", "master"]),
    ("enc-R2,V1,U=view,O=master.pdf", ["view", "master"]),
    ("enc-R2,V1,U=view,O=view.pdf", ["view"]),
    ("enc-R3,V2.pdf", [""]),
    ("enc-R3,V2,O=master.pdf", ["", "master"]),
    ("enc-R3,V2,U=view,O=master.pdf", ["view", "master"]),
    ("enc-R3,V2,U=view,O=view.pdf", ["view"]),
    ("enc-XI-R6,V5,O=master.pdf", ["", "master"]),
    ("enc-XI-R6,V5,U=view,O=master.pdf", ["view", "master"]),
    ("enc-XI-R6,V5,U=wwwww,O=wwwww.pdf", ["wwwww"]),
    ("enc-XI-R6,V5,U=view,attachments,cleartext-metadata.pdf", ["view"]),
    ("enc-XI-R6,V5,U=attachment,encrypted-attachments.pdf", ["attachment"]),
    # Passwords longer than each revision reads (32 bytes before
    # revision 5, 127 from it): the excess is ignored, so both of these
    # open - and one character fewer than the limit does not.
    ("enc-XI-long-password.pdf", [LONG_V5, LONG_V5[:127]]),
    ("enc-long-password.pdf", ["asdf asdf asdf asdf asdf asdf qwer",
                               "asdf asdf asdf asdf asdf asdf qw"]),
    ("V4-aes.pdf", [""]),
    ("V4-aes-clearmeta.pdf", [""]),
    ("encrypted-40-bit-R3.pdf", ["623"]),
    ("encrypted-with-images.pdf", [""]),
    ("c-r2.pdf", ["user1"]),
    ("c-r3.pdf", ["user2", "owner2"]),
    ("c-r4.pdf", ["user2"]),
    ("c-r5-in.pdf", ["user3"]),
    ("c-r6-in.pdf", ["user4", "owner4"]),
    ("20-pages.pdf", ["user", "owner"]),
    ("pages-copy-encryption.pdf", ["user", "owner"]),
    ("job-json-encrypt-40.pdf", ["u", "o"]),
    ("job-json-encrypt-128.pdf", ["u", "o"]),
    ("job-json-input-file-password.pdf", ["user", "owner"]),
    ("V4.pdf", [""]),
    ("V4-clearmeta.pdf", [""]),
    ("metadata-crypt-filter.pdf", [""]),
    ("minimal-signed-restricted.pdf", [""]),
    # /Length 129 on revision 3: not a whole number of bytes.
    ("bad-encryption-length.pdf", [""]),
    # /P written as a positive number.
    ("encrypted-positive-P.pdf", [""]),
    ("copied-positive-P.pdf", [""]),
    # The trailer's /ID is not two strings.
    ("invalid-id-xref.pdf", [""]),
    # 12 KB of junk before the header; offsets count from the header.
    ("leading-junk.pdf", [""]),
    # Crypt filters named per stream, including undecodable ones.
    ("nontrivial-crypt-filter.pdf", ["asdfqwer"]),
    ("unfilterable-with-crypt.pdf", ["attachment"]),
    # /O and /U shorter than the 32 bytes revision 4 writes.
    ("short-O-U.pdf", ["19723102477"]),
]
# Checked here and left out of the offline fixtures, for size: 136 KB,
# and the signature it is there for is in the document make_plain writes.
NOT_RECORDED = {"minimal-signed-restricted.pdf"}

# One character short of what the revision reads: must be refused.
TOO_SHORT = [("enc-long-password.pdf", "asdf asdf asdf asdf asdf asdf q"),
             ("enc-XI-long-password.pdf", LONG_V5[:126])]

SCHEMES = ["rc4-40", "rc4-128", "rc4-128-r4", "aes-128", "aes-256-r5", "aes-256"]
QPDF_SCHEMES = [("R2", ["40"]), ("R3", ["128", "--use-aes=n"]),
                ("R4-RC4", ["128", "--use-aes=n", "--force-V4"]),
                ("R4-AES", ["128", "--use-aes=y"]),
                ("R4-AES-clearmeta", ["128", "--use-aes=y", "--cleartext-metadata"]),
                ("R5", ["256", "--force-R5"]), ("R6", ["256"])]
PDFTK_SCHEMES = ["encrypt_40bit", "encrypt_128bit", "encrypt_aes128"]


def make_plain(path):
    """A small unencrypted document holding what encryption has edges on:
    strings of 0, 15, 16 and 17 bytes (AES blocks), UTF-16 and binary
    strings, escapes, an empty stream, a compressed content stream, an
    XMP metadata stream, an annotation, an embedded file and a signature
    dictionary."""
    text = ("These lines are an attachment. " * 160).encode()
    content = zlib.compress(b"BT /F1 24 Tf 72 700 Td (Hello, encrypted world) Tj ET\n")
    xmp = (b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
           b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
           b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description '
           b'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Plain</dc:title>'
           b'</rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end="w"?>')

    def stream(header, data):
        return b"<< " + header + b" /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"

    def utf16(value):
        return b"<feff" + value.encode("utf-16-be").hex().encode() + b">"

    # Everything is reachable from the catalog: qpdf drops unreferenced
    # objects when it rewrites a file.
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R"
        b" /Names << /EmbeddedFiles << /Names [(attachment.txt) 8 0 R] >> >>"
        b" /AcroForm << /Fields [14 0 R] /SigFlags 3 >> /Extra [11 0 R 12 0 R] >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> /Annots [9 0 R] >>",
        stream(b"/Filter /FlateDecode", content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        stream(b"/Type /Metadata /Subtype /XML", xmp),
        b"<< /Title " + utf16("Plain \u03a3 document") + b" /Author (A. Writer)"
        b" /Subject (\\(parens\\), a backslash \\\\ and a tab\\t)"
        b" /Keywords <000102fffe80> /Producer (scripts/check_pdf.py)"
        b" /CreationDate (D:20260101000000Z) /Empty () /Fifteen (fifteen bytes!!)"
        b" /Sixteen (sixteen bytes, ok) /Seventeen (seventeen bytes ok) >>",
        b"<< /Type /Filespec /F (attachment.txt) /UF " + utf16("attachment.txt")
        + b" /EF << /F 10 0 R >> >>",
        b"<< /Type /Annot /Subtype /Text /Rect [100 100 120 120] /Contents (A note)"
        b" /T (Reviewer) >>",
        stream(b"/Type /EmbeddedFile /Subtype /text#2Fplain /Params << /Size %d >>"
               % len(text), text),
        stream(b"", b""),
        stream(b"", b"exactly 16 bytes"),
        # A signature's /Contents stays in the clear; its other strings
        # do not.
        b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached"
        b" /ByteRange [0 10 20 30] /Contents <" + b"30820a5c" * 8 + b">"
        b" /M (D:20260101000000Z) /Name (A. Signer) >>",
        b"<< /FT /Sig /T (Signature1) /V 13 0 R >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    start = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f\r\n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n\r\n" % offset
    out += (b"trailer\n<< /Size %d /Root 1 0 R /Info 7 0 R"
            b" /ID [<00112233445566778899aabbccddeeff> <00112233445566778899aabbccddeeff>] >>\n"
            b"startxref\n%d\n%%%%EOF\n" % (len(objects) + 1, start))
    with open(path, "wb") as f:
        f.write(out)


def without_crypt_filter(dictionary):
    """Drop a stream's /Crypt filter and its parameters, as qpdf's writer
    does: a decrypted file must not keep it, and qpdf's listing of the
    encrypted file still shows it."""
    filters = dictionary.get("/Filter")
    if filters == "/Crypt":
        dictionary.pop("/Filter")
        dictionary.pop("/DecodeParms", None)
    elif isinstance(filters, list) and "/Crypt" in filters:
        index = filters.index("/Crypt")
        dictionary["/Filter"] = filters[:index] + filters[index + 1:]
        parms = dictionary.get("/DecodeParms")
        if isinstance(parms, list) and index < len(parms):
            dictionary["/DecodeParms"] = parms[:index] + parms[index + 1:]


def listing(path, password):
    """qpdf's objects, normalised: structure left out, /Length dropped."""
    result = subprocess.run(["qpdf", "--json=2", "--json-key=qpdf", "--json-stream-data=inline",
                             "--decode-level=none", f"--password={password}", path],
                            capture_output=True, text=True)
    if result.returncode not in (0, 3):
        raise RuntimeError(result.stderr.strip()[:300])
    objects = json.loads(result.stdout)["qpdf"][1]
    encrypt = objects.get("trailer", {}).get("value", {}).get("/Encrypt")
    out = {}
    for key, value in objects.items():
        if key == "trailer" or key == f"obj:{encrypt}":
            continue
        if "stream" in value:
            dictionary = dict(value["stream"]["dict"])
            if dictionary.get("/Type") in ("/XRef", "/ObjStm"):
                continue
            dictionary.pop("/Length", None)
            without_crypt_filter(dictionary)
            value = {"stream": {"dict": dictionary, "data": value["stream"].get("data")}}
        out[key] = value
    return out


def difference(a, b):
    for key in sorted(set(a) | set(b)):
        if a.get(key) != b.get(key):
            return f"{key}: {json.dumps(a.get(key))[:200]} vs {json.dumps(b.get(key))[:200]}"
    return None


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
                print("     " + str(text).strip()[:800].replace("\n", "\n     "))


def check_decrypt(tally, args, work, label, path, password, which, recorded):
    out = os.path.join(work, "decrypted.pdf")
    result = run([args.ours, "decrypt", path, out, "--password", password])
    if result.returncode:
        tally.check(False, f"{label}, {which} password", result.stderr)
        return
    info = run([args.ours, "info", path, "--password", password]).stdout.decode()
    if f"opened with the {which} password" not in info:
        tally.check(False, f"{label}: ours says it opened with the wrong password", info)
        return
    try:
        theirs = listing(path, password)
        ours = listing(out, "")
    except RuntimeError as error:
        tally.check(False, f"{label}, {which} password", str(error))
        return
    check = run(["qpdf", "--check", out])
    problem = difference(theirs, ours) or (check.stdout + check.stderr if check.returncode else None)
    tally.check(not problem, f"{label}, {which} password: decrypted as qpdf reads it",
                problem or "")
    if not problem:
        recorded.append((label, path, password, which, theirs))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--qpdf-tests", required=True)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    tally = Tally()
    work = tempfile.mkdtemp()
    recorded = []

    print("== qpdf's test files")
    for name, passwords in QPDF_FILES:
        path = os.path.join(args.qpdf_tests, name)
        for password in passwords:
            shown = run(["qpdf", "--show-encryption", f"--password={password}", path])
            which = "owner" if b"Supplied password is owner password" in shown.stdout else "user"
            check_decrypt(tally, args, work, f"qpdf tests/{name}", path, password, which, recorded)
        if all(passwords):
            wrong = run([args.ours, "decrypt", path, os.path.join(work, "x.pdf"),
                         "--password", "not the password"])
            tally.check(wrong.returncode != 0, f"  qpdf tests/{name}: a wrong password refused")
    for name, password in TOO_SHORT:
        wrong = run([args.ours, "decrypt", os.path.join(args.qpdf_tests, name),
                     os.path.join(work, "x.pdf"), "--password", password])
        tally.check(wrong.returncode != 0,
                    f"  qpdf tests/{name}: one character short of the limit refused")

    print("== ours re-encrypts qpdf's test files, qpdf decrypts")
    for name, passwords in QPDF_FILES:
        path = os.path.join(args.qpdf_tests, name)
        original = listing(path, passwords[0])
        for scheme in SCHEMES:
            out = os.path.join(work, "re-encrypted.pdf")
            made = run([args.ours, "encrypt", path, out, "--password", passwords[0],
                        "--user", "user pw", "--owner", "owner pw", "--scheme", scheme])
            problem = made.stderr if made.returncode else None
            if not problem:
                try:
                    problem = difference(original, listing(out, "user pw"))
                except RuntimeError as error:
                    problem = str(error)
            tally.check(not problem, f"qpdf tests/{name} re-encrypted {scheme}", problem or "")

    print("== qpdf and pdftk encrypt, ours decrypts")
    plains = []
    plain = os.path.join(work, "plain.pdf")
    make_plain(plain)
    check = run(["qpdf", "--check", plain])
    tally.check(check.returncode == 0, "the plain document passes qpdf --check",
                check.stdout + check.stderr)
    packed = os.path.join(work, "plain-objstm.pdf")
    run(["qpdf", "--object-streams=generate", plain, packed])
    plains += [plain, packed]
    for plain in plains:
        base = os.path.basename(plain)[:-4]
        for label, options in QPDF_SCHEMES:
            out = os.path.join(work, f"qpdf-{base}-{label}.pdf")
            made = run(["qpdf", "--allow-weak-crypto", "--encrypt", "user pw", "owner pw"]
                       + options + ["--", plain, out])
            if made.returncode not in (0, 3):
                tally.check(False, f"qpdf {label} {base}", made.stderr)
                continue
            for password, which in (("user pw", "user"), ("owner pw", "owner")):
                check_decrypt(tally, args, work, f"qpdf {label} {base}", out, password, which,
                              recorded)
        for scheme in PDFTK_SCHEMES:
            out = os.path.join(work, f"pdftk-{base}-{scheme}.pdf")
            made = run(["pdftk", plain, "output", out, "owner_pw", "owner", "user_pw", "user",
                        scheme])
            if made.returncode:
                tally.check(False, f"pdftk {scheme} {base}", made.stderr)
                continue
            for password, which in (("user", "user"), ("owner", "owner")):
                check_decrypt(tally, args, work, f"pdftk {scheme} {base}", out, password, which,
                              recorded)

    print("== ours encrypts, qpdf and pdftk decrypt")
    expected = {"rc4-40": ("R = 2", "RC4"), "rc4-128": ("R = 3", "RC4"),
                "rc4-128-r4": ("R = 4", "RC4"), "aes-128": ("R = 4", "AESv2"),
                "aes-256-r5": ("R = 5", "AESv3"), "aes-256": ("R = 6", "AESv3")}
    for plain in plains:
        base = os.path.basename(plain)[:-4]
        original = listing(plain, "")
        for scheme in SCHEMES:
            out = os.path.join(work, f"ours-{base}-{scheme}.pdf")
            made = run([args.ours, "encrypt", plain, out, "--user", "user pw", "--owner",
                        "owner pw", "--scheme", scheme, "--permissions", "-3904"])
            if made.returncode:
                tally.check(False, f"ours {scheme} {base}", made.stderr)
                continue
            shown = run(["qpdf", "--show-encryption", "--password=user pw", out]).stdout.decode()
            revision, method = expected[scheme]
            tally.check(revision in shown and f"stream encryption method: {method}" in shown
                        or (scheme in ("rc4-40", "rc4-128") and revision in shown),
                        f"ours {scheme} {base}: qpdf reports {revision}, {method}", shown)
            for password in ("user pw", "owner pw"):
                try:
                    problem = difference(original, listing(out, password))
                except RuntimeError as error:
                    problem = str(error)
                check = run(["qpdf", f"--password={password}", "--check", out])
                if not problem and check.returncode not in (0, 3):
                    problem = check.stdout + check.stderr
                tally.check(not problem, f"ours {scheme} {base}, qpdf opens with {password!r}",
                            problem or "")
            # pdftk-java's iText stops at revision 4 ("unknown.encryption.type.r",
            # for qpdf's own revision 6 files as much as for these).
            if not scheme.startswith("aes-256"):
                decrypted = os.path.join(work, "pdftk-out.pdf")
                result = run(["pdftk", out, "input_pw", "owner pw", "output", decrypted])
                problem = result.stderr if result.returncode else None
                if not problem:
                    theirs = run(["qpdf", "--show-npages", decrypted]).stdout
                    mine = run(["qpdf", "--show-npages", plain]).stdout
                    problem = None if theirs == mine else f"pages {theirs} vs {mine}"
                tally.check(not problem, f"ours {scheme} {base}, pdftk decrypts", problem or "")
            wrong = run(["qpdf", "--password=nope", "--check", out])
            tally.check(wrong.returncode == 2, f"  ours {scheme} {base}, qpdf refuses a wrong password")
            recorded.append((f"ours {scheme} {base}", out, "user pw", "user", original))

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    if args.record and not tally.failed:
        record(args, recorded)
    shutil.rmtree(work)
    return 1 if tally.failed else 0


def items(value, number, out):
    """The strings and stream data in one object of a listing, in the
    order the offline test walks ours: dictionary keys sorted, arrays in
    order, a stream's dictionary before its data. qpdf writes a string
    as `b:` and its bytes in hex, or as `u:` and its text where that
    text says it unambiguously; the test accepts the encodings of `u:`
    text that qpdf would read back as it (UTF-16 either way round with
    a byte order mark, UTF-8 with one, and single bytes)."""
    if isinstance(value, dict):
        if "stream" in value:
            items(value["stream"]["dict"], number, out)
            data = base64.b64decode(value["stream"].get("data") or "")
            out.append(("data", f"{number} {hashlib.sha256(data).hexdigest()}"))
        elif set(value) == {"value"}:
            items(value["value"], number, out)
        else:
            for key in sorted(value):
                items(value[key], number, out)
    elif isinstance(value, list):
        for item in value:
            items(item, number, out)
    elif isinstance(value, str) and value.startswith("b:") and len(value) > 130:
        digest = hashlib.sha256(bytes.fromhex(value[2:])).hexdigest()
        out.append(("string", f"{number} sha256 {digest}"))
    elif isinstance(value, str) and value.startswith("b:"):
        out.append(("string", f"{number} b {value[2:]}"))
    elif isinstance(value, str) and value.startswith("u:"):
        out.append(("string", f"{number} u {value[2:].encode().hex()}"))


def record(args, recorded):
    directory = os.path.join(FIXTURES, "pdf")
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)
    lines = ["# Encrypted PDFs and qpdf's listing of each, decrypted, written by",
             "# scripts/check_pdf.py --record. Each document: the number of objects",
             "# qpdf lists (the script's normalisation), then every string - `b` and",
             "# its bytes, `sha256` and theirs for a long one, or `u` and the UTF-8",
             "# of qpdf's text - and the SHA-256 of every stream's data, each after",
             "# its object number; then each password that opens it and which one",
             "# qpdf said it is. Files named qpdf-tests-* are",
             "# qpdf's own test files (see pdf/NOTICE); the rest were encrypted by",
             "# qpdf, pdftk and the example from a document the script writes.", "",
             "[document]"]
    names = {}
    for label, path, password, which, objects in recorded:
        if os.path.basename(path) in NOT_RECORDED:
            continue
        name = names.get(path)
        if name is not None:
            lines.append(f"open = {password.encode().hex()} {which}")
            continue
        stem = label.replace("qpdf tests/", "qpdf-tests-").replace(" ", "-") \
            .replace(",", "_").replace("=", "-").replace("/", "-")
        if stem.endswith(".pdf"):
            stem = stem[:-4]
        name = stem + ".pdf"
        names[path] = name
        shutil.copy(path, os.path.join(directory, name))
        lines.append(f"name = {name}")
        lines.append(f"objects = {len(objects)}")
        for key in sorted(objects, key=lambda k: int(k.split(":")[1].split()[0])):
            found = []
            items(objects[key], key.split(":")[1].split()[0], found)
            lines += [f"{k} = {v}" for k, v in found]
        lines.append(f"open = {password.encode().hex()} {which}")
    lines += ["", "# Passwords that must be refused.", "", "[refused]"]
    for name, password in TOO_SHORT:
        lines.append(f"name = qpdf-tests-{name}")
        lines.append(f"password = {password.encode().hex()}")
        if not os.path.exists(os.path.join(directory, f"qpdf-tests-{name}")):
            raise SystemExit(f"{name} is refused but not recorded")
    with open(os.path.join(FIXTURES, "pdf.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    license_path = os.path.join(args.qpdf_tests, "..", "..", "..", "LICENSE.txt")
    with open(os.path.join(directory, "NOTICE"), "w") as out:
        out.write("The qpdf-tests-* files are test files from qpdf\n"
                  "(github.com/qpdf/qpdf, qpdf/qtest/qpdf/), under this licence:\n\n")
        out.write(open(license_path).read())
    print(f"{len(recorded)} documents -> {directory}")


if __name__ == "__main__":
    sys.exit(main())
