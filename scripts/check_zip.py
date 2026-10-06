#!/usr/bin/env python3
"""The ZIP example (`examples/products/zip`) against Info-ZIP, libarchive,
7-Zip and Python's zipfile, both directions.

  * **They write, ours extracts**: Info-ZIP's `zip` (ZipCrypto, stored
    and deflated, to a file and to a pipe - a pipe makes it write data
    descriptors, which changes ZipCrypto's check byte), libarchive's
    `bsdtar` (ZipCrypto, AES-128 and AES-256, stored and deflated) and
    7-Zip's `7zz` (ZipCrypto and AES-128, -192 and -256; stored,
    deflated and bzip2). Every file must come out byte for byte, and a
    wrong password must be refused.
  * **Ours writes, they extract**: every encryption ours writes - none,
    ZipCrypto, AES-128/192/256 as AE-1 and AE-2 - given to each reader
    that has it: `7zz` and `bsdtar` all of them (libarchive reads
    AES-192 though it does not write it), `unzip` and Python's `zipfile`
    ZipCrypto. Each must extract the
    files byte for byte, and refuse a wrong password.

    python3 scripts/check_zip.py [--ours PATH] [--sevenzip PATH] [--bsdtar PATH]
    python3 scripts/check_zip.py --record

`--record` keeps a set of the witnesses' archives (small files only) in
`examples/products/fixtures/zip/`, with each entry's SHA-256, for the
offline tests.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example zip`.
"""

import argparse
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "zip")
SEVENZIP = "/opt/7zip/7zz"
BSDTAR = "/opt/libarchive/bin/bsdtar"
# ASCII: a ZIP password is bytes with no stated encoding, and 7-Zip
# refuses a non-ASCII one for ZIP rather than guess.
PASSWORD = "correct horse battery staple"


def payload(directory, large):
    """Files at the boundaries that matter: empty, one byte, either side
    of an AES block, a few hundred blocks of text, and a large random
    file that crosses many CTR blocks and deflate's window."""
    choose = random.Random(1)
    files = {
        "empty.bin": b"",
        "one.bin": b"\x01",
        "fifteen.bin": bytes(range(15)),
        "sixteen.bin": bytes(range(16)),
        "seventeen.bin": bytes(range(17)),
        "text.txt": b"".join(b"line %d of some compressible text\n" % i for i in range(300)),
        "dir/nested.txt": b"in a directory\n",
    }
    if large:
        files["random.bin"] = bytes(choose.randrange(256) for _ in range(70000))
    for name, data in files.items():
        path = os.path.join(directory, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as out:
            out.write(data)
    return files


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, **kwargs)


class Tally:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what, detail=b""):
        if ok:
            self.passed += 1
            print(f"ok   {what}")
        else:
            self.failed += 1
            print(f"FAIL {what}")
            if detail:
                text = detail.decode(errors="replace") if isinstance(detail, bytes) else detail
                print("     " + text.strip()[:600].replace("\n", "\n     "))


def same_tree(directory, files):
    for name, data in files.items():
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            return f"{name} is missing"
        with open(path, "rb") as f:
            if f.read() != data:
                return f"{name} differs"
    return None


def witness_archives(args, work, source, files):
    """(label, path) for every archive the witnesses write."""
    names = sorted(files)
    out = []
    env = dict(os.environ, LD_LIBRARY_PATH=os.path.dirname(os.path.dirname(args.bsdtar)) + "/lib")

    def made(label, path, result):
        if result.returncode == 0 and os.path.exists(path):
            out.append((label, path))
        else:
            print(f"     (witness could not write {label}: {result.stderr[:200]!r})")

    for level in ("-0", "-6"):
        path = os.path.join(work, f"infozip{level}.zip")
        made(f"Info-ZIP zip {level} ZipCrypto", path,
             run(["zip", "-q", level, "-X", "-P", PASSWORD, path] + names, cwd=source))
        path = os.path.join(work, f"infozip{level}-pipe.zip")
        with open(path, "wb") as sink:
            result = subprocess.run(["zip", "-q", level, "-X", "-P", PASSWORD, "-"] + names,
                                    cwd=source, stdout=sink, stderr=subprocess.PIPE)
        made(f"Info-ZIP zip {level} ZipCrypto to a pipe", path, result)
    # -fz forces ZIP64 extra fields, with the 32-bit sizes saturated in
    # the central directory: the only way to reach that path without a
    # file of 4 GiB.
    path = os.path.join(work, "infozip-zip64.zip")
    made("Info-ZIP zip -fz (ZIP64) ZipCrypto", path,
         run(["zip", "-q", "-fz", "-X", "-P", PASSWORD, path] + names, cwd=source))
    for encryption in ("zipcrypt", "aes128", "aes256"):
        for compression in ("store", "deflate"):
            path = os.path.join(work, f"bsdtar-{encryption}-{compression}.zip")
            made(f"bsdtar {encryption} {compression}", path,
                 run([args.bsdtar, "--format", "zip", "--options",
                      f"zip:encryption={encryption},zip:compression={compression}",
                      "--passphrase", PASSWORD, "-cf", path] + names, cwd=source, env=env))
    for encryption in ("ZipCrypto", "AES128", "AES192", "AES256"):
        for method in ("Copy", "Deflate", "BZip2"):
            path = os.path.join(work, f"7zz-{encryption}-{method}.zip")
            made(f"7-Zip {encryption} {method}", path,
                 run([args.sevenzip, "a", "-tzip", f"-p{PASSWORD}", f"-mem={encryption}",
                      f"-mm={method}", path] + names, cwd=source))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--sevenzip", default=SEVENZIP)
    parser.add_argument("--bsdtar", default=BSDTAR)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    tally = Tally()
    work = tempfile.mkdtemp()
    env = dict(os.environ, LD_LIBRARY_PATH=os.path.dirname(os.path.dirname(args.bsdtar)) + "/lib")

    for large in (True, False):
        source = os.path.join(work, f"source-{large}")
        files = payload(source, large)
        print(f"== they write, ours extracts ({'with' if large else 'without'} the large file)")
        # A fresh directory per set: 7-Zip and Info-ZIP *add to* an
        # archive that exists, so reusing a name keeps the last set's
        # files in it.
        archive_dir = os.path.join(work, f"archives-{large}")
        os.makedirs(archive_dir)
        archives = witness_archives(args, archive_dir, source, files)
        for label, path in archives:
            target = tempfile.mkdtemp(dir=work)
            result = run([args.ours, "extract", path, target, "--password", PASSWORD])
            problem = result.stderr if result.returncode else same_tree(target, files)
            tally.check(not problem, label, problem or b"")
            wrong = run([args.ours, "extract", path, tempfile.mkdtemp(dir=work),
                         "--password", PASSWORD + "x"])
            tally.check(wrong.returncode != 0, f"  {label}, a wrong password refused")
        if not large:
            # The small set is run again only to be recorded: everything
            # in it is in the large set too.
            if args.record and not tally.failed:
                record(archives, files)
            break

        print("== ours writes, they extract")
        names = sorted(files)
        for sealing in ("none", "zipcrypto", "aes128", "aes192", "aes256"):
            for ae in (("1", "2") if sealing.startswith("aes") else ("2",)):
                label = sealing + (f" AE-{ae}" if sealing.startswith("aes") else "")
                path = os.path.join(work, f"ours-{sealing}-{ae}.zip")
                made = run([args.ours, "create", path] + names +
                           ["--encryption", sealing, "--ae", ae, "--password", PASSWORD],
                           cwd=source)
                if made.returncode:
                    tally.check(False, f"ours writes {label}", made.stderr)
                    continue
                readers = [("7-Zip", lambda t: [args.sevenzip, "x", f"-p{PASSWORD}", f"-o{t}",
                                                path, "-y"], None)]
                readers.append(("bsdtar", lambda t: [args.bsdtar, "-xf", path, "-C", t,
                                                     "--passphrase", PASSWORD], env))
                if sealing in ("none", "zipcrypto"):
                    readers.append(("unzip", lambda t: ["unzip", "-q", "-P", PASSWORD, path,
                                                        "-d", t], None))
                for reader, command, reader_env in readers:
                    target = tempfile.mkdtemp(dir=work)
                    result = run(command(target), env=reader_env)
                    problem = result.stderr + result.stdout if result.returncode \
                        else same_tree(target, files)
                    tally.check(not problem, f"ours writes {label}, {reader} extracts",
                                problem or b"")
                if sealing in ("none", "zipcrypto"):
                    try:
                        with zipfile.ZipFile(path) as z:
                            z.setpassword(PASSWORD.encode())
                            ok = all(z.read(n) == d for n, d in files.items())
                        tally.check(ok, f"ours writes {label}, Python's zipfile extracts")
                    except Exception as error:
                        tally.check(False, f"ours writes {label}, Python's zipfile extracts",
                                    str(error))
                if sealing != "none":
                    wrong = run([args.sevenzip, "x", f"-p{PASSWORD}x",
                                 f"-o{tempfile.mkdtemp(dir=work)}", path, "-y"])
                    tally.check(wrong.returncode != 0,
                                f"  ours writes {label}, 7-Zip refuses a wrong password")

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    shutil.rmtree(work)
    return 1 if tally.failed else 0


def record(archives, files):
    directory = os.path.join(FIXTURES, "zip")
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)
    lines = ["# Archives the witnesses wrote, kept by scripts/check_zip.py --record,",
             "# with the SHA-256 of every file in each. The password is",
             f"# {PASSWORD.encode().hex()} (hex of its UTF-8).", "", "[archive]"]
    for label, path in archives:
        name = os.path.basename(path)
        shutil.copy(path, os.path.join(directory, name))
        lines.append(f"name = {name}")
        lines.append(f"made_by = {label}")
    lines += ["", "[file]"]
    for name, data in sorted(files.items()):
        lines.append(f"name = {name}")
        lines.append(f"sha256 = {hashlib.sha256(data).hexdigest()}")
    with open(os.path.join(FIXTURES, "zip.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    print(f"{len(archives)} archives -> {directory}")


if __name__ == "__main__":
    sys.exit(main())
