#!/usr/bin/env python3
"""The 7z example (`examples/products/sevenzip`) against 7-Zip and
libarchive, both directions.

  * **7-Zip writes, ours extracts**: every method ours reads - Copy,
    LZMA at assorted lc/lp/pb and dictionary sizes and with an end
    marker, LZMA2 (single- and multi-threaded, over data that makes it
    switch between stored and LZMA chunks), Deflate, BZip2 - every
    branch filter but IA64 and Delta at several distances, solid and not,
    the header compressed or not, and 7zAES with and without the header
    encrypted. Every file and directory must come out byte for byte, and
    a wrong password must be refused. PPMd and BCJ2 must be refused with
    a message rather than a panic. And liblzma's LZMA2 (`xz --format=raw`)
    in a container written here, because liblzma resets the LZMA state
    after a stored chunk and 7-Zip never does.
  * **Ours writes, they extract**: stored, under 7zAES at several cycle
    counts (including 0x3F, the raw key), and with the header encrypted;
    `7zz x` and `7zz t` read all of them and `bsdtar` the unencrypted
    one, byte for byte, and 7-Zip must refuse a wrong password.

    python3 scripts/check_sevenzip.py [--ours PATH] [--sevenzip PATH] [--bsdtar PATH]
    python3 scripts/check_sevenzip.py --record

`--record` keeps the small set of 7-Zip's archives in
`examples/products/fixtures/sevenzip/`, with each file's SHA-256, for the
offline tests.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example sevenzip`.
"""

import argparse
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "sevenzip")
SEVENZIP = "/opt/7zip/7zz"
BSDTAR = "/opt/libarchive/bin/bsdtar"
XZ = "xz"
# Not ASCII, so the password's UTF-16LE encoding is exercised.
PASSWORD = "correct horse battery stäple"


def text(choose, n):
    words = [b"the ", b"quick ", b"brown ", b"fox\n", b"jumps ", b"over ", b"lazy ", b"dog. "]
    out = bytearray()
    while len(out) < n:
        out += choose.choice(words)
    return bytes(out[:n])


def branchy(choose, n, word):
    """`n` bytes in which about half of the aligned positions hold what
    `word` makes - an instruction some branch filter converts - and the
    rest random. `n` is deliberately not a multiple of four."""
    out = bytearray()
    while len(out) < n:
        out += word(choose) if choose.random() < 0.5 else bytes(choose.randrange(256)
                                                                 for _ in range(4))
    return bytes(out[:n])


def x86(choose):
    # CALL/JMP with an operand whose top byte is 00 or FF, sometimes
    # preceded by stray E8 bytes, which is what the filter's mask is for.
    # Mostly near offsets, as in real code - 00 00 or FF FF on top, which
    # is what sends the decoder round its loop when the mask is set - and
    # some just either side of 0x01000000 and 0xFF000000, where adding the
    # position carries into the top byte; and some right after a stray E8
    # whose operand's third byte is a carry away from 00 or FF, which is
    # the case the decoder's inner loop exists for.
    lead = bytes([0xe8]) * choose.randrange(3)
    kind = choose.random()
    if kind < 0.5:
        operand = choose.getrandbits(16) | choose.choice([0, 0xffff0000])
    elif kind < 0.7:
        operand = choose.choice([0x00ffffff - choose.getrandbits(12),
                                 0xff000000 + choose.getrandbits(12)])
    elif kind < 0.85:
        lead = b"\xe8"
        operand = choose.getrandbits(8) \
            | choose.choice([0xff, 0xfe, 0x00, 0x01, choose.getrandbits(8)]) << 8 \
            | choose.choice([0xfe, 0x01, 0xfd, 0x02]) << 16 | choose.choice([0, 0xff]) << 24
    else:
        operand = choose.getrandbits(24) | choose.choice([0, 0xff000000])
    return lead + bytes([choose.choice([0xe8, 0xe9])]) + struct.pack("<I", operand)


def arm(choose):
    return bytes(choose.randrange(256) for _ in range(3)) + b"\xeb"


def armt(choose):
    return bytes([choose.randrange(256), 0xf0 | choose.randrange(8),
                  choose.randrange(256), 0xf8 | choose.randrange(8)])


def ppc(choose):
    return struct.pack(">I", 0x48000001 | (choose.getrandbits(24) << 2))


def sparc(choose):
    near = choose.choice([0x40000000 | choose.getrandbits(22),
                          0x7fc00000 | choose.getrandbits(22)])
    return struct.pack(">I", near if choose.random() < 0.8 else 0x40000000 |
                       choose.getrandbits(30))


def arm64(choose):
    if choose.random() < 0.5:
        return struct.pack("<I", 0x94000000 | choose.getrandbits(26))
    # ADRP: immlo in 29..30, immhi in 5..23; both in range and out.
    immhi = choose.getrandbits(19) if choose.random() < 0.3 else \
        (choose.getrandbits(17) | (0x7e000 if choose.random() < 0.5 else 0))
    return struct.pack("<I", 0x90000000 | (choose.getrandbits(2) << 29) | (immhi << 5)
                       | choose.getrandbits(5))


def payload(directory, large):
    """Files at the boundaries that matter - empty, one byte, either side
    of an AES block - text, something for every branch filter, a nested
    file and an empty directory; and in the large set, random data and a
    file that makes LZMA2 alternate stored and LZMA chunks. The small
    set's branch files are a quarter the size, since it is recorded."""
    choose = random.Random(7)
    files = {
        "empty.bin": b"",
        "one.bin": b"\x01",
        "fifteen.bin": bytes(range(15)),
        "sixteen.bin": bytes(range(16)),
        "seventeen.bin": bytes(range(17)),
        "text.txt": text(choose, 20000),
        "dir/nested.txt": b"in a directory\n",
        "code/x86.bin": branchy(choose, 6001 if large else 1501, x86),
        "code/arm.bin": branchy(choose, 4002 if large else 1001, arm),
        "code/armt.bin": branchy(choose, 4003 if large else 1001, armt),
        "code/ppc.bin": branchy(choose, 4001 if large else 1001, ppc),
        "code/sparc.bin": branchy(choose, 4002 if large else 1001, sparc),
        "code/arm64.bin": branchy(choose, 4003 if large else 1001, arm64),
    }
    if large:
        files["random.bin"] = bytes(choose.randrange(256) for _ in range(70000))
        # Incompressible stretches longer than a chunk's 64 KiB packed
        # limit, between compressible ones longer than its 2 MiB
        # unpacked limit.
        mixed = bytearray()
        for _ in range(3):
            mixed += bytes(choose.randrange(256) for _ in range(150000))
            mixed += text(choose, 2500000)
        files["mixed.bin"] = bytes(mixed)
    for name, data in files.items():
        path = os.path.join(directory, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as out:
            out.write(data)
    os.makedirs(os.path.join(directory, "hollow"), exist_ok=True)
    return files


def chunks_payload(directory):
    """One file that makes 7-Zip's LZMA2 write an LZMA chunk, a stored
    one, and an LZMA chunk that carries the state on across it (control
    0x80). 7-Zip never resets the state alone (`Lzma2Enc.c` has that
    line commented out); `xz_archive` is the case that does."""
    choose = random.Random(11)
    data = text(choose, 10000) + bytes(choose.randrange(256) for _ in range(140000)) \
        + text(choose, 10000)
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "chunks.bin"), "wb") as out:
        out.write(data)
    return {"chunks.bin": data}


def number(value):
    """7z's UINT64: leading ones in the first byte count the bytes that
    follow, little endian, and the first byte's remaining bits are the
    value's top."""
    for extra in range(8):
        if value < 1 << (7 * (extra + 1)):
            high = value >> (8 * extra)
            return bytes([(0xff00 >> extra) & 0xff | high]) + value.to_bytes(8, "little")[:extra]
    return b"\xff" + value.to_bytes(8, "little")


def lzma2_archive(path, name, data, stream, dict_byte):
    """A 7z archive of one file whose packed stream is `stream`, raw
    LZMA2 from some other encoder - written here by hand from
    7zFormat.txt, so that 7-Zip's acceptance of it is the check that it
    is a well-formed container."""
    crc = zlib.crc32(data)
    folder = b"\x01" + b"\x21\x21\x01" + bytes([dict_byte])
    header = (b"\x01\x04"
              + b"\x06" + number(0) + number(1) + b"\x09" + number(len(stream)) + b"\x00"
              + b"\x07\x0b" + number(1) + b"\x00" + folder
              + b"\x0c" + number(len(data)) + b"\x0a\x01" + struct.pack("<I", crc) + b"\x00"
              + b"\x00")
    names = b"\x00" + name.encode("utf-16-le") + b"\x00\x00"
    header += b"\x05" + number(1) + b"\x11" + number(len(names)) + names + b"\x00\x00"
    start = struct.pack("<QQI", len(stream), len(header), zlib.crc32(header))
    with open(path, "wb") as out:
        out.write(b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start
                  + stream + header)


def blocks_archive(args, directory):
    """7-Zip's LZMA2 in 4 KiB blocks, each starting with a dictionary
    reset: an LZMA chunk (control 0xE0) for text and a stored chunk
    (control 1) for random bytes."""
    choose = random.Random(17)
    data = text(choose, 6000) + bytes(choose.randrange(256) for _ in range(9000)) \
        + text(choose, 6000)
    source = os.path.join(directory, "blocks")
    os.makedirs(source, exist_ok=True)
    with open(os.path.join(source, "blocks.bin"), "wb") as out:
        out.write(data)
    path = os.path.join(directory, "LZMA2-blocks.7z")
    made = seven(args, path, ["-m0=LZMA2:c=4k:d=64k", "-mmt=2"], None, source, ["blocks.bin"])
    if made.returncode:
        return None, made.stderr
    return (path, {"blocks.bin": data}), None


def stored_then_repeated(choose):
    """Random bytes, 2000 from near their start again, then text:
    liblzma stores most of the random bytes in a chunk that resets the
    dictionary, and the next chunk has a match reaching back to the
    start of that one, 64,600 bytes away."""
    noise = bytes(choose.randrange(256) for _ in range(65600))
    return noise + noise[1000:3000] + text(choose, 3000)


def xz_archives(args, directory):
    """liblzma's LZMA2, in two archives. The first starts with text and
    goes on into random bytes, so liblzma writes an LZMA chunk, a stored
    one, and then an LZMA chunk that resets the state but not the
    dictionary (control 0xA0) - which 7-Zip's encoder never does. The
    second starts with random bytes: a stored chunk that resets the
    dictionary (control 1), then an LZMA chunk bringing properties
    without a reset (0xC0) whose first match reaches into the stored
    one. `xz --format=raw` writes the bare chunks."""
    choose = random.Random(13)
    layouts = {
        "xz-state": text(choose, 4000) + bytes(choose.randrange(256) for _ in range(130000))
        + text(choose, 1000),
        "xz-stored": stored_then_repeated(choose),
    }
    out = []
    for name, data in layouts.items():
        raw = run([args.xz, "--format=raw", "--lzma2=dict=64KiB", "-c"], input=data)
        if raw.returncode:
            return None, raw.stderr
        path = os.path.join(directory, f"{name}.7z")
        lzma2_archive(path, f"{name}.bin", data, raw.stdout, 8)
        out.append((path, {f"{name}.bin": data}))
    return out, None


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


def same_tree(directory, files, dirs=("hollow",)):
    for name, data in files.items():
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            return f"{name} is missing"
        with open(path, "rb") as f:
            if f.read() != data:
                return f"{name} differs"
    for name in dirs:
        if not os.path.isdir(os.path.join(directory, name)):
            return f"the directory {name} is missing"
    return None


# (label, 7zz switches). A password is added to every case whose label
# says AES.
CASES = [
    ("Copy", ["-m0=Copy"]),
    ("LZMA", ["-m0=LZMA"]),
    ("LZMA lc0 lp0 pb0", ["-m0=LZMA:lc=0:lp=0:pb=0"]),
    ("LZMA lc8 lp0 pb4", ["-m0=LZMA:lc=8:lp=0:pb=4"]),
    ("LZMA lc0 lp4 pb4", ["-m0=LZMA:lc=0:lp=4:pb=4"]),
    ("LZMA lc1 lp3 pb1", ["-m0=LZMA:lc=1:lp=3:pb=1"]),
    ("LZMA d=4k", ["-m0=LZMA:d=4k"]),
    ("LZMA eos", ["-m0=LZMA:eos"]),
    ("LZMA2", ["-m0=LZMA2"]),
    ("LZMA2 lc0 lp4", ["-m0=LZMA2:lc=0:lp=4:pb=0"]),
    ("LZMA2 lc4 lp0", ["-m0=LZMA2:lc=4:lp=0:pb=4"]),
    ("LZMA2 d=4k", ["-m0=LZMA2:d=4k"]),
    ("LZMA2 mt4", ["-m0=LZMA2:c=256k", "-mmt=4"]),
    ("LZMA2 mx9", ["-mx=9"]),
    ("Deflate", ["-m0=Deflate"]),
    ("BZip2", ["-m0=BZip2"]),
    ("BCJ LZMA2", ["-m0=BCJ", "-m1=LZMA2"]),
    ("ARM LZMA2", ["-m0=ARM", "-m1=LZMA2"]),
    ("ARMT LZMA2", ["-m0=ARMT", "-m1=LZMA2"]),
    ("PPC LZMA2", ["-m0=PPC", "-m1=LZMA2"]),
    ("SPARC LZMA2", ["-m0=SPARC", "-m1=LZMA2"]),
    ("ARM64 LZMA2", ["-m0=ARM64", "-m1=LZMA2"]),
    ("BCJ Copy", ["-m0=BCJ", "-m1=Copy"]),
    ("Delta1 LZMA", ["-m0=Delta:1", "-m1=LZMA"]),
    ("Delta4 LZMA", ["-m0=Delta:4", "-m1=LZMA"]),
    ("Delta7 Copy", ["-m0=Delta:7", "-m1=Copy"]),
    ("not solid", ["-ms=off"]),
    ("solid by extension", ["-ms=e"]),
    ("header not compressed", ["-mhc=off"]),
    ("all times", ["-mtc=on", "-mta=on"]),
    ("AES Copy", ["-m0=Copy"]),
    ("AES LZMA2", []),
    ("AES header", ["-mhe=on"]),
    ("AES header Copy", ["-mhe=on", "-m0=Copy", "-mhc=off"]),
    ("AES BCJ Deflate", ["-m0=BCJ", "-m1=Deflate"]),
]

REFUSED = [
    ("PPMd", ["-m0=PPMd"], "PPMD"),
    ("BCJ2", ["-m0=BCJ2", "-m1=LZMA", "-m2=LZMA", "-m3=LZMA", "-mb0:1", "-mb0s1:2",
              "-mb0s2:3"], "BCJ2"),
]


def seven(args, path, switches, password, source, names):
    command = [args.sevenzip, "a", "-bd", "-y", path] + switches
    if password:
        command.append(f"-p{password}")
    return run(command + names, cwd=source)


def witness_archives(args, work, source, files):
    names = sorted({n.split("/")[0] for n in files} | {"hollow"})
    out = []
    for label, switches in CASES:
        path = os.path.join(work, label.replace(" ", "-").replace("=", "") + ".7z")
        result = seven(args, path, switches, PASSWORD if "AES" in label else None, source,
                       names)
        if result.returncode == 0:
            out.append((label, path))
        else:
            print(f"     (7-Zip could not write {label}: {result.stderr[:300]!r})")
    return out


def extract_check(args, tally, work, label, path, files, dirs=("hollow",)):
    encrypted = "AES" in label
    target = tempfile.mkdtemp(dir=work)
    command = [args.ours, "extract", path, target]
    result = run(command + (["--password", PASSWORD] if encrypted else []))
    problem = (result.stderr or b"failed") if result.returncode else \
        same_tree(target, files, dirs)
    tally.check(not problem, label, problem or b"")
    listed = run([args.ours, "list", path] + (["--password", PASSWORD] if encrypted else []))
    tally.check(listed.returncode == 0, f"  {label}, listed", listed.stderr)
    if encrypted:
        wrong = run(command + ["--password", PASSWORD + "x"])
        tally.check(wrong.returncode != 0 and b"panicked" not in wrong.stderr,
                    f"  {label}, a wrong password refused", wrong.stderr)
        none = run([args.ours, "extract", path, tempfile.mkdtemp(dir=work)])
        tally.check(none.returncode != 0 and b"panicked" not in none.stderr,
                    f"  {label}, no password refused", none.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--sevenzip", default=SEVENZIP)
    parser.add_argument("--bsdtar", default=BSDTAR)
    parser.add_argument("--xz", default=XZ)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    tally = Tally()
    work = tempfile.mkdtemp()
    env = dict(os.environ, LD_LIBRARY_PATH=os.path.dirname(os.path.dirname(args.bsdtar)) + "/lib")

    for large in (True, False):
        source = os.path.join(work, f"source-{large}")
        files = payload(source, large)
        print(f"== 7-Zip writes, ours extracts ({'large' if large else 'small'} set)")
        # A fresh directory per set: 7-Zip adds to an archive that exists.
        archive_dir = os.path.join(work, f"archives-{large}")
        os.makedirs(archive_dir)
        archives = witness_archives(args, archive_dir, source, files)
        for label, path in archives:
            extract_check(args, tally, work, label, path, files)
        for label, switches, method in REFUSED:
            path = os.path.join(archive_dir, f"{label}.7z")
            made = seven(args, path, switches, None, source, sorted(files))
            if made.returncode:
                tally.check(False, f"7-Zip writes {label}", made.stderr)
                continue
            result = run([args.ours, "extract", path, tempfile.mkdtemp(dir=work)])
            tally.check(result.returncode == 1 and method.encode() in result.stderr
                        and b"panicked" not in result.stderr,
                        f"{label} refused by name", result.stderr)
        if large:
            # A filter that converted nothing would round-trip whatever
            # the decoder did, so each must have changed its own file.
            for name, filter_name in [("x86", "BCJ"), ("arm", "ARM"), ("armt", "ARMT"),
                                      ("ppc", "PPC"), ("sparc", "SPARC"), ("arm64", "ARM64")]:
                path = os.path.join(archive_dir, f"only-{filter_name}.7z")
                made = seven(args, path, [f"-m0={filter_name}", "-m1=Copy", "-mhc=off"], None,
                             source, [f"code/{name}.bin"])
                with open(path, "rb") as f:
                    stored = f.read()[32:32 + len(files[f"code/{name}.bin"])]
                changed = sum(a != b for a, b in zip(stored, files[f"code/{name}.bin"]))
                tally.check(made.returncode == 0 and changed > 100,
                            f"{filter_name} changed {changed} bytes of {name}.bin")
        if not large:
            chunks_source = os.path.join(work, "chunks")
            chunks = chunks_payload(chunks_source)
            path = os.path.join(archive_dir, "LZMA2-chunks.7z")
            made = seven(args, path, ["-m0=LZMA2"], None, chunks_source, ["chunks.bin"])
            tally.check(made.returncode == 0, "7-Zip writes LZMA2 chunks", made.stderr)
            extract_check(args, tally, work, "LZMA2 stored then LZMA chunks", path, chunks,
                          dirs=())
            made, problem = blocks_archive(args, archive_dir)
            tally.check(made is not None, "7-Zip writes LZMA2 in 4 KiB blocks", problem or b"")
            blocks_files = {}
            if made:
                path, blocks_files = made
                extract_check(args, tally, work, "LZMA2 in blocks, each resetting the "
                              "dictionary", path, blocks_files, dirs=())
                archives.append(("LZMA2 in 4 KiB blocks", path))
            made, problem = xz_archives(args, archive_dir)
            tally.check(made is not None, "xz writes raw LZMA2", problem or b"")
            xz_files = {}
            for path, these in made or []:
                tested = run([args.sevenzip, "t", path])
                tally.check(b"Everything is Ok" in tested.stdout,
                            f"7-Zip reads {os.path.basename(path)}, xz's LZMA2 in the "
                            "hand-made container", tested.stdout + tested.stderr)
                extract_check(args, tally, work, f"liblzma LZMA2, {os.path.basename(path)}",
                              path, these, dirs=())
                archives.append(("xz (liblzma) LZMA2, put in a 7z container by hand", path))
                xz_files.update(these)
            if args.record and not tally.failed:
                record(archives, {**files, **blocks_files, **xz_files})
            break

        print("== ours writes, 7-Zip and libarchive extract")
        names = sorted({n.split("/")[0] for n in files} | {"hollow"})
        sealings = [("stored", []), ("AES 2^19", ["--password", PASSWORD]),
                    ("AES 2^0", ["--password", PASSWORD, "--cycles", "0"]),
                    ("AES 2^1", ["--password", PASSWORD, "--cycles", "1"]),
                    ("AES raw key", ["--password", PASSWORD, "--cycles", "63"]),
                    ("AES header", ["--password", PASSWORD, "--encrypt-header"])]
        for label, options in sealings:
            path = os.path.join(work, f"ours-{label.replace(' ', '-')}.7z")
            made = run([args.ours, "create", path] + names + options, cwd=source)
            if made.returncode:
                tally.check(False, f"ours writes {label}", made.stderr)
                continue
            encrypted = "AES" in label
            password = [f"-p{PASSWORD}"] if encrypted else []
            readers = [("7-Zip", lambda t: [args.sevenzip, "x", "-y", f"-o{t}", path]
                        + password, None)]
            if not encrypted:
                readers.append(("bsdtar", lambda t: [args.bsdtar, "-xf", path, "-C", t], env))
            for reader, command, reader_env in readers:
                target = tempfile.mkdtemp(dir=work)
                result = run(command(target), env=reader_env)
                problem = result.stderr + result.stdout if result.returncode \
                    else same_tree(target, files)
                tally.check(not problem, f"ours writes {label}, {reader} extracts",
                            problem or b"")
            tested = run([args.sevenzip, "t", path] + password)
            tally.check(tested.returncode == 0 and b"Everything is Ok" in tested.stdout,
                        f"ours writes {label}, 7-Zip tests it", tested.stdout + tested.stderr)
            if encrypted:
                wrong = run([args.sevenzip, "t", path, f"-px{PASSWORD}"])
                tally.check(wrong.returncode != 0,
                            f"  ours writes {label}, 7-Zip refuses a wrong password")
                # A raw key is the salt and the UTF-16LE password cut to
                # 32 bytes: past the sixteenth character nothing counts.
                longer = run([args.sevenzip, "t", path, f"-p{PASSWORD}x"])
                tally.check((longer.returncode == 0) == ("raw" in label),
                            f"  ours writes {label}, 7-Zip "
                            f"{'accepts' if 'raw' in label else 'refuses'} the password "
                            "with a character added")
                listing = run([args.sevenzip, "l", path, f"-p{PASSWORD}x"])
                hidden = "header" in label
                tally.check((listing.returncode != 0) == hidden,
                            f"  ours writes {label}, the names are "
                            f"{'hidden' if hidden else 'listed'} without the password")

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    shutil.rmtree(work)
    return 1 if tally.failed else 0


def record(archives, files):
    directory = os.path.join(FIXTURES, "sevenzip")
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)
    lines = ["# Archives 7-Zip wrote, kept by scripts/check_sevenzip.py --record, with",
             "# the SHA-256 of every file in them. Each holds every [file] below except",
             "# blocks.bin and the two xz-*.bin, and an empty directory named hollow. Those",
             "# are alone in LZMA2-blocks.7z and xz-*.7z, the last xz's raw LZMA2 in a",
             "# container the script writes. The password is",
             f"# {PASSWORD.encode().hex()} (hex of its UTF-8).", "", "[archive]"]
    for label, path in archives:
        name = os.path.basename(path)
        shutil.copy(path, os.path.join(directory, name))
        lines.append(f"name = {name}")
        lines.append(f"made_by = 7-Zip {label}")
    lines += ["", "[file]"]
    for name, data in sorted(files.items()):
        lines.append(f"name = {name}")
        lines.append(f"sha256 = {hashlib.sha256(data).hexdigest()}")
    with open(os.path.join(FIXTURES, "sevenzip.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    print(f"{len(archives)} archives -> {directory}")


if __name__ == "__main__":
    sys.exit(main())
