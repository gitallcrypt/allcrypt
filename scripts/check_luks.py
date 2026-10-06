#!/usr/bin/env python3
"""The LUKS example (`examples/products/luks`) against cryptsetup.

Both directions, on image files, without root:

  * **cryptsetup's images, opened by ours.** `cryptsetup luksFormat`
    makes LUKS1 and LUKS2 headers across ciphers, IV modes, hashes and
    key derivations; our `open` must recover the volume key that
    `cryptsetup luksDump --dump-volume-key` prints. For the data area,
    `cryptsetup reencrypt --encrypt` encrypts a known plaintext in
    userspace (no device-mapper needed), and LUKS1 gets data the same
    way through `cryptsetup convert`; our `open --decrypt` must give the
    plaintext back.
  * **Our images, opened by cryptsetup.** Our `format` writes LUKS1 and
    LUKS2 images; cryptsetup must accept the header, unlock the keyslot
    with the passphrase and dump the same volume key.
  * **cryptsetup's own test images** (`--cryptsetup-tests DIR`, a
    cryptsetup source tree's `tests/`): its compatibility images, whose
    volume key ours must match; and LUKS1 volumes made with the
    kernel's dm-crypt holding a FAT filesystem whose serial is
    DEAD-BABE - serpent and twofish, Whirlpool, LRW, ESSIV with a
    truncated Whirlpool under XTS. Our decryption of the first data
    sector must show that serial.

    python3 scripts/check_luks.py --cryptsetup /opt/cryptsetup/run.sh
    python3 scripts/check_luks.py --cryptsetup-tests ~/src/cryptsetup/tests
    python3 scripts/check_luks.py --record

`--record` writes a few of the cryptsetup-made images, with their data,
into `examples/products/fixtures/` (sparse: only the non-zero runs) for
the example's offline tests.

**A development tool, not a test.** It needs a cryptsetup build; the
gate runs none of it. Nothing touches a real disk: every image is a
file in a temporary directory.
"""

import argparse
import hashlib
import lzma
import os
import re
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")

# cryptsetup's side: (name, luksFormat or reencrypt arguments, data?).
# Only AES here: without the kernel's crypto API, cryptsetup checks a
# cipher it cannot run in userspace by activating it, which needs root.
FAST = ["--pbkdf-force-iterations", "1000"]
ARGON = ["--pbkdf-force-iterations", "4", "--pbkdf-memory", "64", "--pbkdf-parallel", "1"]
THEIRS = [
    ("luks1-xts-sha256", ["--type", "luks1", "--cipher", "aes-xts-plain64", "--key-size", "256",
                          "--hash", "sha256"] + FAST, False),
    ("luks1-xts512-sha512", ["--type", "luks1", "--cipher", "aes-xts-plain64",
                             "--key-size", "512", "--hash", "sha512"] + FAST, False),
    ("luks1-cbc-essiv-sha1", ["--type", "luks1", "--cipher", "aes-cbc-essiv:sha256",
                              "--key-size", "256", "--hash", "sha1"] + FAST, False),
    ("luks1-xts-plain-ripemd160", ["--type", "luks1", "--cipher", "aes-xts-plain",
                                   "--key-size", "256", "--hash", "ripemd160"] + FAST, False),
    ("luks2-argon2id", ["--type", "luks2", "--cipher", "aes-xts-plain64", "--key-size", "512",
                        "--pbkdf", "argon2id"] + ARGON, False),
    ("luks2-argon2i-2lanes", ["--type", "luks2", "--cipher", "aes-xts-plain64",
                              "--key-size", "256", "--pbkdf", "argon2i",
                              "--pbkdf-force-iterations", "4", "--pbkdf-memory", "128",
                              "--pbkdf-parallel", "2"], False),
    ("luks2-pbkdf2-sha512", ["--type", "luks2", "--cipher", "aes-xts-plain64",
                             "--key-size", "256", "--pbkdf", "pbkdf2", "--hash", "sha512"]
     + FAST, False),
    ("luks2-cbc-essiv", ["--type", "luks2", "--cipher", "aes-cbc-essiv:sha256",
                         "--key-size", "256", "--pbkdf", "pbkdf2"] + FAST, False),
    # With data, which cryptsetup writes in userspace.
    ("luks2-data-512", ["--type", "luks2", "--cipher", "aes-xts-plain64", "--key-size", "256",
                        "--sector-size", "512", "--pbkdf", "argon2id"] + ARGON, True),
    ("luks2-data-4096", ["--type", "luks2", "--cipher", "aes-xts-plain64", "--key-size", "256",
                         "--sector-size", "4096", "--pbkdf", "pbkdf2"] + FAST, True),
    ("luks2-data-cbc-essiv-4096", ["--type", "luks2", "--cipher", "aes-cbc-essiv:sha256",
                                   "--key-size", "256", "--sector-size", "4096",
                                   "--pbkdf", "pbkdf2"] + FAST, True),
    ("luks1-data-xts", ["--type", "luks1", "--cipher", "aes-xts-plain64", "--key-size", "256",
                        "--hash", "sha256"] + FAST, True),
    ("luks1-data-cbc-essiv", ["--type", "luks1", "--cipher", "aes-cbc-essiv:sha256",
                              "--key-size", "256", "--hash", "sha1"] + FAST, True),
]
RECORDED = ["luks1-data-xts", "luks1-data-cbc-essiv", "luks2-data-512", "luks2-data-4096",
            "luks2-argon2i-2lanes"]

# Ours: (name, format arguments).
OURS = [
    ("luks1-xts", ["--type", "luks1", "--cipher", "aes-xts-plain64", "--key-size", "512"]),
    ("luks1-cbc-essiv-sha1", ["--type", "luks1", "--cipher", "aes-cbc-essiv:sha256",
                              "--key-size", "256", "--hash", "sha1"]),
    ("luks1-xts-sha512", ["--type", "luks1", "--cipher", "aes-xts-plain64", "--key-size", "256",
                          "--hash", "sha512"]),
    ("luks2-argon2id", ["--type", "luks2", "--pbkdf", "argon2id", "--iterations", "3",
                        "--memory", "1024", "--parallel", "2"]),
    ("luks2-argon2i", ["--type", "luks2", "--pbkdf", "argon2i", "--iterations", "3",
                       "--memory", "256", "--parallel", "1", "--key-size", "256"]),
    ("luks2-pbkdf2-4096", ["--type", "luks2", "--pbkdf", "pbkdf2", "--sector-size", "4096"]),
    ("luks2-cbc-essiv", ["--type", "luks2", "--pbkdf", "pbkdf2",
                         "--cipher", "aes-cbc-essiv:sha256", "--key-size", "256"]),
]

PASSPHRASE = "correct horse battery staple"


def plaintext(sectors):
    return b"".join((b"luks plaintext sector %08d " % i).ljust(512, b".")
                    for i in range(sectors))


class Rig:
    def __init__(self, cryptsetup, luks, directory):
        self.cryptsetup = cryptsetup
        self.luks = luks
        self.d = directory

    def cs(self, *args, passphrase=PASSPHRASE, check=True):
        run = subprocess.run([self.cryptsetup, "--batch-mode", *args, "--key-file", "-"],
                             input=passphrase.encode(), capture_output=True, timeout=300)
        if check and run.returncode != 0:
            raise RuntimeError(f"cryptsetup {args[0]}: {run.stderr.decode()[-400:]}")
        return run

    def dumped_key(self, image, passphrase=PASSPHRASE):
        out = self.cs("luksDump", "--dump-volume-key", image,
                      passphrase=passphrase).stdout.decode()
        match = re.search(r"MK dump:(.*?)(?:\n\S|\Z)", out, re.S)
        return "".join(match.group(1).split())

    def ours(self, *args):
        run = subprocess.run([self.luks, *args], capture_output=True, text=True, timeout=600)
        if run.returncode != 0:
            raise RuntimeError(run.stderr.strip())
        return run.stdout

    def our_key(self, image, passphrase=PASSPHRASE, decrypt=None):
        out = self.ours("open", image, passphrase, "--volume-key",
                        *(["--decrypt", decrypt] if decrypt else []))
        return re.search(r"volume key: ([0-9a-f]+)", out).group(1)

    def theirs(self, name, arguments, with_data):
        image = os.path.join(self.d, f"{name}.img")
        data = None
        if with_data:
            data = plaintext(128)
            luks1 = arguments[1] == "luks1"
            args = list(arguments)
            if luks1:
                # cryptsetup encrypts LUKS1 data only by way of LUKS2:
                # a LUKS2 volume with a PBKDF2 keyslot, then converted.
                args[1] = "luks2"
                at = args.index("--hash")
                args[at:at] = ["--pbkdf", "pbkdf2"]
            with open(image, "wb") as out:
                out.write(data + bytes(4 * 1024 * 1024))
            # --reduce-device-size makes room for the header in front of
            # the data, which cryptsetup moves along.
            self.cs("reencrypt", "--encrypt", *args, "--reduce-device-size", "4M", image)
            if luks1:
                self.cs("convert", "--type", "luks1", image)
        else:
            with open(image, "wb") as out:
                out.truncate(4 * 1024 * 1024)
            extra = ["--luks2-metadata-size", "16k", "--luks2-keyslots-size", "512k"] \
                if "luks2" in arguments else []
            self.cs("luksFormat", *arguments, *extra, image)
        return image, data


def used_ranges(data, data_length):
    """The parts of a LUKS image anything reads: the headers, each
    active keyslot's key material, and `data_length` bytes of data.
    cryptsetup fills unused keyslot space with random bytes, which would
    otherwise make every fixture megabytes of noise."""
    import json
    if data[6:8] == b"\x00\x01":
        key_bytes = int.from_bytes(data[108:112], "big")
        ranges = [(0, 592)]
        for slot in range(8):
            at = 208 + 48 * slot
            if int.from_bytes(data[at:at + 4], "big") == 0x00AC71F3:
                offset = int.from_bytes(data[at + 40:at + 44], "big") * 512
                stripes = int.from_bytes(data[at + 44:at + 48], "big")
                ranges.append((offset, key_bytes * stripes))
        payload = int.from_bytes(data[104:108], "big") * 512
        ranges.append((payload, data_length))
        return ranges
    hdr_size = int.from_bytes(data[8:16], "big")
    header = json.loads(data[4096:hdr_size].split(b"\0")[0])
    ranges = [(0, 2 * hdr_size)]
    for slot in header["keyslots"].values():
        if slot["type"] == "luks2":
            ranges.append((int(slot["area"]["offset"]),
                           slot["key_size"] * slot["af"]["stripes"]))
    segment = header["segments"]["0"]
    ranges.append((int(segment["offset"]), data_length))
    return ranges


def write_sparse(image_path, out_path, data_length):
    """The image, keeping only what is read (`used_ranges`), as runs of
    non-zero 512 byte blocks. Its length is cut after the data kept."""
    data = open(image_path, "rb").read()
    ranges = used_ranges(data, data_length)
    kept = bytearray(max(start + length for start, length in ranges))
    for start, length in ranges:
        kept[start:start + length] = data[start:start + length]
    runs = []
    at = 0
    block = 512
    while at < len(kept):
        if any(kept[at:at + block]):
            start = at
            while at < len(kept) and any(kept[at:at + block]):
                at += block
            runs.append((start, bytes(kept[start:at])))
        else:
            at += block
    with open(out_path, "wb") as out:
        out.write(b"SPARSE01" + len(kept).to_bytes(8, "big"))
        for start, run in runs:
            out.write(start.to_bytes(8, "big") + len(run).to_bytes(4, "big") + run)


def fat_serial_is_deadbabe(sector):
    """A FAT boot sector's volume serial: at 0x27 (FAT12/16) or 0x43
    (FAT32), little endian."""
    return sector[0x27:0x2b] == bytes.fromhex("bebaadde") or \
        sector[0x43:0x47] == bytes.fromhex("bebaadde")


def cryptsetup_test_images(rig, tests_dir, report):
    # The compatibility images, LUKS1 from an early cryptsetup among
    # them: our volume key against cryptsetup's.
    for name in ("compatimage.img.xz", "compatv10image.img.xz", "compatimage2.img.xz"):
        path = os.path.join(rig.d, name[:-3])
        with lzma.open(os.path.join(tests_dir, name)) as source, open(path, "wb") as out:
            out.write(source.read())
        try:
            expected = rig.dumped_key(path, passphrase="compatkey")
            got = rig.our_key(path, passphrase="compatkey")
            report(got == expected, f"cryptsetup test image {name[:-3]}",
                   f"ours {got[:16]} cryptsetup {expected[:16]}")
        except Exception as error:  # noqa: BLE001
            report(False, f"cryptsetup test image {name[:-3]}", str(error)[-200:])
    # LUKS1 volumes the kernel's dm-crypt wrote, with a FAT filesystem.
    archive = os.path.join(tests_dir, "luks1-images.tar.xz")
    with tarfile.open(archive) as tar:
        tar.extractall(rig.d, filter="data")
    images = os.path.join(rig.d, "luks1-images")
    keyfile = os.path.join(images, "keyfile1")
    for name in sorted(os.listdir(images)):
        if not name.startswith("luks1_"):
            continue
        path = os.path.join(images, name)
        out = os.path.join(rig.d, "plain")
        run = subprocess.run([rig.luks, "open", path, "--key-file", keyfile, "--decrypt", out],
                             capture_output=True, text=True)
        ok = run.returncode == 0 and fat_serial_is_deadbabe(open(out, "rb").read(512))
        report(ok, f"cryptsetup test image {name}", run.stderr.strip()[-200:])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cryptsetup", default="/opt/cryptsetup/run.sh")
    parser.add_argument("--cryptsetup-tests", metavar="DIR",
                        help="a cryptsetup source tree's tests/ directory")
    parser.add_argument("--record", action="store_true",
                        help="write the RECORDED images to examples/products/fixtures/")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "--quiet", "--release", "--example", "luks"],
                   cwd=ROOT, check=True)
    luks = os.path.join(ROOT, "target", "release", "examples", "luks")
    version = subprocess.run([args.cryptsetup, "--version"], capture_output=True,
                             text=True).stdout.strip()
    print(f"witness: {version}")
    failures = rows = 0
    records = []

    def report(ok, label, detail=""):
        nonlocal failures, rows
        rows += 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label:58} {'' if ok else detail}")

    with tempfile.TemporaryDirectory() as d:
        rig = Rig(args.cryptsetup, luks, d)
        for name, arguments, with_data in THEIRS:
            try:
                image, data = rig.theirs(name, arguments, with_data)
                expected = rig.dumped_key(image)
                out = os.path.join(d, "decrypted")
                got = rig.our_key(image, decrypt=out if data else None)
                ok = got == expected
                detail = f"ours {got[:16]}... cryptsetup {expected[:16]}..."
                if data and ok:
                    decrypted = open(out, "rb").read()
                    ok = decrypted[:len(data)] == data
                    detail = "the data differs"
                report(ok, f"cryptsetup's {name}, opened by ours", detail)
                if ok and args.record and name in RECORDED:
                    os.makedirs(os.path.join(FIXTURES, "luks"), exist_ok=True)
                    sparse = f"luks/{name}.sparse"
                    write_sparse(image, os.path.join(FIXTURES, sparse),
                                 len(data) if data else 0)
                    cipher = re.search(r"opened: (\S+)", rig.ours("open", image, PASSPHRASE)
                                       ).group(1)
                    records.append(dict(name=name, image=sparse, passphrase=PASSPHRASE,
                                        cipher=cipher, volume_key=expected,
                                        data_length=len(data or b""),
                                        data_sha256=hashlib.sha256(data or b"").hexdigest(),
                                        arguments=" ".join(arguments)))
            except Exception as error:  # noqa: BLE001 - reported, not hidden
                report(False, f"cryptsetup's {name}, opened by ours", str(error)[-300:])

        for name, arguments in OURS:
            image = os.path.join(d, f"ours-{name}.img")
            try:
                out = rig.ours("format", image, PASSPHRASE, *arguments)
                ours = re.search(r"volume key: ([0-9a-f]+)", out).group(1)
                theirs = rig.dumped_key(image)
                wrong = rig.cs("open", "--test-passphrase", image, passphrase="wrong",
                               check=False).returncode
                report(ours == theirs and wrong != 0, f"our {name}, opened by cryptsetup",
                       f"ours {ours[:16]}... cryptsetup {theirs[:16]}... wrong={wrong}")
            except Exception as error:  # noqa: BLE001
                report(False, f"our {name}, opened by cryptsetup", str(error)[-300:])

        # The passphrase from standard input, as a pipe gives it, and a
        # key file read whole from it.
        image = os.path.join(d, "ours-stdin.img")
        try:
            out = rig.ours("format", image, PASSPHRASE, *OURS[0][1])
            key = re.search(r"volume key: ([0-9a-f]+)", out).group(1)

            def piped(*args, data):
                return subprocess.run([luks, "open", image, *args, "--volume-key"],
                                      input=data, capture_output=True, timeout=600)
            line = piped("--passphrase-stdin", data=(PASSPHRASE + "\n").encode())
            whole = piped("--key-file", "-", data=PASSPHRASE.encode())
            wrong = piped("--passphrase-stdin", data=b"wrong\n")
            report(f"volume key: {key}".encode() in line.stdout
                   and f"volume key: {key}".encode() in whole.stdout
                   and wrong.returncode != 0,
                   "ours opened with --passphrase-stdin and --key-file -",
                   (line.stderr + whole.stderr).decode()[-200:])
        except Exception as error:  # noqa: BLE001
            report(False, "ours opened with --passphrase-stdin and --key-file -", str(error))

        if args.cryptsetup_tests:
            cryptsetup_test_images(rig, args.cryptsetup_tests, report)

    print(f"{rows - failures} of {rows} passed.")
    if args.record and not failures:
        with open(os.path.join(FIXTURES, "luks.vec"), "w") as out:
            out.write(
                "# LUKS images cryptsetup made, for examples/products/luks's tests.\n"
                "# Written by scripts/check_luks.py --record. Each image is\n"
                "# fixtures/luks/NAME.sparse; the data was encrypted by\n"
                "# `cryptsetup reencrypt --encrypt` (LUKS1 by way of `cryptsetup\n"
                "# convert`), and volume_key is what `cryptsetup luksDump\n"
                "# --dump-volume-key` printed. Only what is read is kept: the\n"
                "# headers, the active keyslots' material and the data recorded;\n"
                "# the rest (cryptsetup's random fill of unused keyslot space,\n"
                "# data beyond data_length) is zeros. Do not edit.\n"
                f"#\n# {version}\n\n[cryptsetup]\n")
            for record in records:
                out.write("\n")
                for key in ("name", "arguments", "image", "passphrase", "cipher", "volume_key",
                            "data_length", "data_sha256"):
                    out.write(f"{key} = {record[key]}\n")
        print(f"wrote {len(records)} images to {FIXTURES}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
