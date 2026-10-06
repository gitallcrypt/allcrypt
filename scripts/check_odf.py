#!/usr/bin/env python3
"""The OpenDocument example (`examples/products/odf`) against
LibreOffice, both directions.

LibreOffice 24.2 writes all three schemes, depending on its
configuration: AES-256-CBC by default (ODF 1.2 and later), Blowfish when
told to write ODF 1.1, and AES-256-GCM under Argon2id over the whole
package in its experimental mode. The script sets each in its own
profile.

  * **LibreOffice encrypts, ours decrypts**: a text document (one with
    a picture in it as well), a spreadsheet and a presentation, under
    each scheme. Ours must give back a plain package whose files are,
    byte for byte, what an independent decryption here - written from
    the manifest with python-cryptography - gives; LibreOffice must read
    ours, with no password, as it reads the original with one; and a
    wrong password must be refused.
  * **Ours encrypts, LibreOffice decrypts**: the same documents, plain,
    encrypted by ours under each scheme. LibreOffice must open each with
    the password and find the content, and refuse a wrong password; the
    independent decryption must give back every file byte for byte.
  * Ours refuses a whole-package encryption with one bit changed.

    python3 scripts/check_odf.py
    python3 scripts/check_odf.py --record

`--record` keeps some of each direction's documents, with the SHA-256 of
every file in them, in `examples/products/fixtures/odf/` for the offline
tests.

**A development tool, not a test.** Build ours first:
`cargo build --release --example odf`.
"""

import argparse
import base64
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib

from libreoffice_uno import CONTENT, LibreOffice, write_png

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "odf")
PASSWORD = "Pässword 1234"

KINDS = [("swriter", "writer8", "odt"), ("scalc", "calc8", "ods"),
         ("simpress", "impress8", "odp")]
SCHEMES = ["aes", "blowfish", "gcm"]


def configure(lo, scheme):
    """LibreOffice's configuration for writing `scheme`: ODF 1.1 for
    Blowfish, the default (1.3 extended) otherwise, and experimental
    mode for the whole-package GCM."""
    lo.configure("/org.openoffice.Office.Common/Save/ODF", "DefaultVersion",
                 2 if scheme == "blowfish" else 3)
    lo.configure("/org.openoffice.Office.Common/Misc", "ExperimentalMode", scheme == "gcm")


def independent_decrypt(path, password):
    """Every file of an encrypted package, decrypted with
    python-cryptography straight from the manifest: a second reading,
    for comparing ours with byte for byte."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
    except ImportError:
        Blowfish = algorithms.Blowfish
    archive = zipfile.ZipFile(path)
    manifest = archive.read("META-INF/manifest.xml").decode()
    out = {}
    entries = re.findall(r"<manifest:file-entry (.*?)(?:/>|>(.*?)</manifest:file-entry>)",
                         manifest, re.S)
    encrypted = {}
    for attributes, body in entries:
        name = re.search(r'manifest:full-path="([^"]*)"', attributes).group(1)
        if "encryption-data" in (body or ""):
            encrypted[name] = (attributes, body)

    def attr(text, name):
        m = re.search(r'(?:manifest|loext):' + name + r'="([^"]*)"', text)
        return m.group(1) if m else None

    for info in archive.infolist():
        data = archive.read(info.filename)
        if info.filename not in encrypted:
            if info.filename != "META-INF/manifest.xml":
                out[info.filename] = data
            continue
        attributes, body = encrypted[info.filename]
        start = attr(body, "start-key-generation-name") or "SHA1"
        start_key = (hashlib.sha256 if "sha256" in start else hashlib.sha1)(
            password.encode()).digest()
        salt = base64.b64decode(attr(body, "salt"))
        iv = base64.b64decode(attr(body, "initialisation-vector"))
        derivation = re.search(r"<manifest:key-derivation (.*?)/>", body, re.S).group(1)
        key_size = int(attr(derivation, "key-size") or 16)
        if attr(derivation, "key-derivation-name") == "PBKDF2":
            key = hashlib.pbkdf2_hmac("sha1", start_key, salt,
                                      int(attr(derivation, "iteration-count")), key_size)
        else:
            key = Argon2id(salt=salt, length=key_size,
                           iterations=int(attr(derivation, "argon2-iterations")),
                           lanes=int(attr(derivation, "argon2-lanes")),
                           memory_cost=int(attr(derivation, "argon2-memory"))).derive(start_key)
        algorithm = attr(body, "algorithm-name")
        if algorithm.endswith("aes256-gcm"):
            deflated = AESGCM(key).decrypt(data[:12], data[12:], None)
        elif algorithm.endswith("aes256-cbc"):
            d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            padded = d.update(data) + d.finalize()
            deflated = padded[:-padded[-1]]
        else:
            d = Cipher(Blowfish(key), modes.CFB(iv)).decryptor()
            deflated = d.update(data) + d.finalize()
        plain = zlib.decompressobj(-15).decompress(deflated)
        if info.filename == "encrypted-package":
            return {name: data for name, data in independent_files(plain).items()}
        out[info.filename] = plain
    return out


def independent_files(package_bytes):
    archive = zipfile.ZipFile(io.BytesIO(package_bytes))
    return {i.filename: archive.read(i.filename) for i in archive.infolist()
            if i.filename != "META-INF/manifest.xml"}


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


def ours(args, command, source, out, password, *extra):
    return run([args.ours, command, source, out, "--password-stdin", *extra],
               input=(password + "\n").encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    tally = Tally()
    work = tempfile.mkdtemp()
    recorded = []
    lo = LibreOffice(work)
    try:
        picture = os.path.join(work, "picture.png")
        write_png(picture)
        documents = [(kind, f, ext, None) for kind, f, ext in KINDS]
        documents.append(("swriter", "writer8", "odt", picture))

        print("== LibreOffice encrypts, ours decrypts")
        for scheme in SCHEMES:
            configure(lo, scheme)
            for kind, filter_name, extension, pic in documents:
                label = f"libreoffice {scheme} {'picture ' if pic else ''}.{extension}"
                path = os.path.join(work, f"lo-{scheme}-{'p' if pic else ''}{kind}.{extension}")
                lo.make(kind, path, filter_name, PASSWORD, picture=pic)
                info = run([args.ours, "info", path]).stdout.decode()
                expected = {"aes": "AesCbc", "blowfish": "Blowfish", "gcm": "AesGcm"}[scheme]
                tally.check(expected in info, f"{label}: LibreOffice wrote {expected}", info)
                plain = os.path.join(work, "ours-plain." + extension)
                made = ours(args, "decrypt", path, plain, PASSWORD)
                if made.returncode:
                    tally.check(False, label, made.stderr)
                    continue
                with open(plain, "rb") as f:
                    files = independent_files(f.read())
                theirs = independent_decrypt(path, PASSWORD)
                tally.check(files == theirs, f"{label}: every file as the manifest decrypts it",
                            f"{sorted(files)} vs {sorted(theirs)}")
                text, wanted = lo.read(plain), lo.read(path, PASSWORD)
                tally.check(text == wanted == CONTENT[kind],
                            f"{label}: LibreOffice reads ours as it reads the original",
                            f"{text!r} vs {wanted!r}")
                wrong = ours(args, "decrypt", path, plain, "not the password")
                tally.check(wrong.returncode != 0, f"  {label}: a wrong password refused")
                # One text document per scheme: LibreOffice derives a key
                # per file with 100,000 iterations, which a debug build of
                # the offline test pays for again.
                if files == theirs and kind == "swriter" and not pic:
                    recorded.append((label, path, PASSWORD, files))

        print("== ours encrypts, LibreOffice decrypts")
        configure(lo, "aes")
        for kind, filter_name, extension, pic in documents:
            plain = os.path.join(work, f"plain-{'p' if pic else ''}{kind}.{extension}")
            lo.make(kind, plain, filter_name, picture=pic)
            with open(plain, "rb") as f:
                original = independent_files(f.read())
            for scheme in SCHEMES:
                label = f"ours {scheme} {'picture ' if pic else ''}.{extension}"
                path = os.path.join(work, f"ours-{scheme}-{'p' if pic else ''}{kind}.{extension}")
                made = ours(args, "encrypt", plain, path, PASSWORD, "--scheme", scheme,
                            "--iterations", "1000", "--argon2", "1,1024,2")
                if made.returncode:
                    tally.check(False, label, made.stderr)
                    continue
                text = lo.read(path, PASSWORD)
                tally.check(text == CONTENT[kind], f"{label}: LibreOffice opens it", f"{text!r}")
                tally.check(lo.read(path, "not the password") is None,
                            f"  {label}: LibreOffice refuses a wrong password")
                theirs = independent_decrypt(path, PASSWORD)
                tally.check(theirs == original,
                            f"{label}: every file decrypts to the plain package's",
                            f"{sorted(theirs)} vs {sorted(original)}")
                if theirs == original and kind == "swriter" and not pic:
                    recorded.append((label, path, PASSWORD, original))

        print("== a changed whole-package encryption is refused")
        path = os.path.join(work, "ours-gcm-swriter.odt")
        archive = zipfile.ZipFile(path)
        changed = io.BytesIO()
        with zipfile.ZipFile(changed, "w") as out:
            for info in archive.infolist():
                data = bytearray(archive.read(info.filename))
                if info.filename == "encrypted-package":
                    data[len(data) // 2] ^= 1
                out.writestr(info, bytes(data))
        changed_path = os.path.join(work, "changed.odt")
        with open(changed_path, "wb") as f:
            f.write(changed.getvalue())
        result = ours(args, "decrypt", changed_path, os.path.join(work, "x.odt"), PASSWORD)
        tally.check(result.returncode != 0, "a flipped bit in a GCM package is refused",
                    result.stderr)
    finally:
        lo.close()

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    if args.record and not tally.failed:
        record(recorded)
    shutil.rmtree(work)
    return 1 if tally.failed else 0


def record(recorded):
    directory = os.path.join(FIXTURES, "odf")
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)
    lines = ["# Encrypted OpenDocument packages and the SHA-256 of every file in",
             "# each, decrypted, written by scripts/check_odf.py --record. Files",
             "# named libreoffice-* LibreOffice encrypted; ours-* the example",
             "# encrypted and LibreOffice opened. Each file's path is in hex.", "",
             "[document]"]
    for label, path, password, files in recorded:
        name = re.sub(r"[^a-z0-9.]+", "-", label.lower()).replace("-.", ".")
        shutil.copy(path, os.path.join(directory, name))
        lines += [f"name = {name}", f"password = {password.encode().hex()}"]
        for file, data in sorted(files.items()):
            lines.append(f"file = {file.encode().hex()} {hashlib.sha256(data).hexdigest()}")
    with open(os.path.join(FIXTURES, "odf.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    print(f"{len(recorded)} documents -> {directory}")


if __name__ == "__main__":
    sys.exit(main())
