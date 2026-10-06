#!/usr/bin/env python3
"""The VeraCrypt example (`examples/products/veracrypt`) against real
TrueCrypt and VeraCrypt volumes, and against cryptsetup.

  * **Volumes TrueCrypt and VeraCrypt made** - cryptsetup's test suite
    (`--cryptsetup-tests DIR`, a cryptsetup source tree's `tests/`,
    whose `tcrypt-images.tar.xz` holds volumes from TrueCrypt 1.0 to
    7.1 and VeraCrypt to 1.26): every hash, every cipher and cascade,
    XTS, LRW and CBC, hidden volumes, keyfiles, PIMs. Each must open
    with the algorithm its name says, and its first data sector must
    decrypt to the FAT boot sector whose serial is DEAD-BABE (CAFE-BABE
    in a hidden volume). Where
    cryptsetup can judge in userspace (AES), the master key must also be
    the one `cryptsetup tcryptDump --dump-master-key` prints.
  * **Our volumes, opened by cryptsetup.** Our `format` writes VeraCrypt
    and TrueCrypt volumes under every hash; `cryptsetup tcryptDump`
    must open each and print our master key, and python-cryptography's
    AES-XTS under that key must decrypt our data.

    python3 scripts/check_veracrypt.py --cryptsetup-tests ~/src/cryptsetup/tests
    python3 scripts/check_veracrypt.py --record

`--record` writes a few of our volumes that cryptsetup opened, with its
master key, into `examples/products/fixtures/` for the example's
offline tests.

**A development tool, not a test.** It needs a cryptsetup build; the
gate runs none of it.
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tarfile
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")

PASSWORD = "aaaaaaaaaaaa"
PASSWORD_HIDDEN = "bbbbbbbbbbbb"
PASSWORD_72 = "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeeeffffffffffff"
PASSWORD_PIM = "cccccccccccccccccccc"
HASHES = {"stribog512": "streebog"}
DISPLAY = {"aes": "AES", "serpent": "Serpent", "twofish": "Twofish", "camellia": "Camellia",
           "kuznyechik": "Kuznyechik", "cast5": "CAST5", "des3_ede": "Triple DES",
           "blowfish": "Blowfish"}

# Ours: (name, format arguments, the PIM cryptsetup is given).
OURS = [
    ("vc-sha512", ["--hash", "sha512", "--pim", "1"], "1"),
    ("vc-sha256", ["--hash", "sha256", "--pim", "1"], "1"),
    ("vc-whirlpool", ["--hash", "whirlpool", "--pim", "1"], "1"),
    ("vc-blake2s", ["--hash", "blake2s", "--pim", "1"], "1"),
    ("vc-ripemd160", ["--hash", "ripemd160", "--pim", "1"], "1"),
    # Not Streebog or Argon2id: cryptsetup 2.8.8 with OpenSSL 3.0 opens
    # neither. Those KDFs are judged by the VeraCrypt-made test volumes.
    ("vc-sha512-default", ["--hash", "sha512"], None),
    ("tc-sha512", ["--truecrypt", "--hash", "sha512"], None),
    ("tc-ripemd160", ["--truecrypt", "--hash", "ripemd160"], None),
    ("tc-whirlpool", ["--truecrypt", "--hash", "whirlpool"], None),
]
# TrueCrypt's derivations are cheap enough for a debug build's tests;
# VeraCrypt's are recorded too and checked in an optimised one.
RECORDED = ["tc-sha512", "tc-ripemd160", "tc-whirlpool", "vc-sha512", "vc-blake2s"]
SIZE = 2 * 131072 + 65536


def fat_serial(sector, serial="bebaadde"):
    """A FAT boot sector's volume serial, at 0x27 (FAT12/16) or 0x43
    (FAT32), little endian: DEAD-BABE in the test volumes, CAFE-BABE in
    their hidden volumes."""
    return sector[0x27:0x2b] == bytes.fromhex(serial) or \
        sector[0x43:0x47] == bytes.fromhex(serial)


def cryptsetup_master_key(cryptsetup, volume, password, *, pim=None, hidden=False,
                          keyfiles=(), veracrypt=True, system=False):
    args = [cryptsetup, "tcryptDump", "--dump-master-key", "--batch-mode", volume]
    if veracrypt:
        args.append("--veracrypt")
    if pim:
        args += ["--veracrypt-pim", str(pim)]
    if hidden:
        args.append("--tcrypt-hidden")
    if system:
        args.append("--tcrypt-system")
    for keyfile in keyfiles:
        args += ["--key-file", keyfile]
    run = subprocess.run(args, input=(password + "\n").encode(), capture_output=True,
                         timeout=600)
    if run.returncode != 0:
        return None, run.stderr.decode()[-200:]
    text = run.stdout.decode()
    match = re.search(r"MK dump:(.*?)(?:\n\S|\Z)", text, re.S)
    return "".join(match.group(1).split()), text


def ours(binary, *args):
    run = subprocess.run([binary, *args], capture_output=True, text=True, timeout=1800)
    if run.returncode != 0:
        raise RuntimeError(run.stderr.strip()[-300:])
    return run.stdout


def their_images(binary, cryptsetup, tests_dir, d, report):
    counts = {"volumes": 0, "filesystem": 0, "header only": 0, "master key": 0}
    with tarfile.open(os.path.join(tests_dir, "tcrypt-images.tar.xz")) as tar:
        tar.extractall(d, filter="data")
    images = os.path.join(d, "tcrypt-images")
    keyfiles = [os.path.join(images, "keyfile1"), os.path.join(images, "keyfile2")]
    for name in sorted(os.listdir(images)):
        if not re.match(r"^(tc|vc|tck|vck|vcpim|sys_vc)_", name):
            continue
        path = os.path.join(images, name)
        parts = name.split("-")
        hash_name = HASHES.get(parts[1], parts[1])
        mode = parts[2]
        ciphers = [p for p in parts[3:] if p != "hidden"]
        password, pim, files = PASSWORD, None, []
        if name.startswith("vcpim_"):
            pim = re.match(r"vcpim_1_(\d+)", name).group(1)
            password = PASSWORD_PIM
        if name.startswith(("tck_", "vck_")):
            files = keyfiles
            if "_nopw" in name:
                password = ""
            elif "_pw72" in name:
                password = PASSWORD_72
        # The names give VeraCrypt's display name (the last cipher
        # applied first), except the Camellia and Kuznyechik cascades,
        # which are named in the order the ciphers are applied.
        names = ["-".join(DISPLAY[c] for c in ciphers),
                 "-".join(DISPLAY[c] for c in reversed(ciphers))]
        system = name.startswith("sys_")
        rows = [(False, password)]
        if parts[-1] == "hidden":
            rows.append((True, PASSWORD_HIDDEN))
        for hidden, word in rows:
            counts["volumes"] += 1
            label = f"{name}{' (hidden)' if hidden else ''}"
            args = ["open", path, word, "--hash", hash_name, "--master-key"]
            if pim:
                args += ["--pim", pim]
            if hidden:
                args.append("--hidden")
            if system:
                args.append("--system")
            for f in files:
                args += ["--keyfile", f]
            # A system volume's data area is the drive from its first
            # encrypted partition on; the filesystem is where that starts.
            decrypt = ["--decrypt", os.path.join(d, "plain"), "--limit",
                       "1048576" if system else "4096"]
            try:
                out = ours(binary, *args, *decrypt)
            except RuntimeError as error:
                if "is not decrypted" not in str(error):
                    report(False, label, str(error))
                    continue
                # Legacy cascades and Blowfish: the header and master keys
                # are read, the data is not.
                out = ours(binary, *args)
                ok = any(f"{n} ({mode.upper()})" in out for n in names)
                counts["header only"] += ok
                report(ok, f"{label}: header and master keys (data not read)", out[:160])
                continue
            plain = open(os.path.join(d, "plain"), "rb").read()
            if system:
                # MBR full-drive encryption starts at sector 63; the
                # partition, and its boot sector, at 1 MiB.
                start = 1048576 - int(re.search(r"data at (\d+)", out).group(1))
                plain = plain[max(start, 0):] if start < len(plain) else plain
            ok = any(f"{n} ({mode.upper()})" in out for n in names) and \
                fat_serial(plain[:512], "bebafeca" if hidden else "bebaadde")
            counts["filesystem"] += ok
            detail = out[:200]
            key = re.search(r"master key: ([0-9a-f]+)", out).group(1)
            # cryptsetup 2.8.8 does not open VeraCrypt's Argon2id volumes
            # here, so those are judged by their filesystem alone.
            if ok and ciphers == ["aes"] and mode == "xts" and hash_name != "argon2id":
                theirs, text = cryptsetup_master_key(
                    cryptsetup, path, word, pim=pim, hidden=hidden, keyfiles=files,
                    veracrypt=name.startswith(("v", "sys_v")), system=system)
                ok = theirs == key
                counts["master key"] += ok
                detail = f"cryptsetup: {theirs and theirs[:16]} {text[-120:]}"
                label += ", master key = cryptsetup's"
            report(ok, label, detail)
    print(f"  TrueCrypt and VeraCrypt volumes: {counts['volumes']} opened; "
          f"{counts['filesystem']} decrypted to their filesystem, "
          f"{counts['header only']} header and keys only; "
          f"{counts['master key']} master keys compared with cryptsetup's")


def our_volumes(binary, cryptsetup, d, report, record, records):
    plaintext = b"".join((b"veracrypt plaintext sector %06d " % i).ljust(512, b".")
                         for i in range(32))
    data = os.path.join(d, "data.bin")
    with open(data, "wb") as out:
        out.write(plaintext)
    for seed, (name, arguments, pim) in enumerate(OURS, start=1):
        volume = os.path.join(d, f"{name}.hc")
        try:
            out = ours(binary, "format", volume, PASSWORD, "--size", str(SIZE), "--data", data,
                       "--seed", str(seed), *arguments)
            key = re.search(r"master key: ([0-9a-f]+)", out).group(1)
            theirs, text = cryptsetup_master_key(cryptsetup, volume, PASSWORD, pim=pim,
                                                 veracrypt="--truecrypt" not in arguments)
            ok = theirs == key
            detail = f"ours {key[:16]} cryptsetup {theirs and theirs[:16]} {text[-150:]}"
            if ok:
                raw = open(volume, "rb").read()[131072:131072 + len(plaintext)]
                k = bytes.fromhex(key)
                decrypted = b""
                for i in range(len(raw) // 512):
                    decryptor = Cipher(algorithms.AES(k), modes.XTS(
                        (256 + i).to_bytes(16, "little"))).decryptor()
                    decrypted += decryptor.update(raw[i * 512:(i + 1) * 512]) + \
                        decryptor.finalize()
                ok = decrypted == plaintext
                detail = "python-cryptography's XTS gives other data"
            report(ok, f"our {name}, opened by cryptsetup", detail)
            if seed == 1:
                # The password from standard input, as a pipe gives it.
                pim_args = ["--pim", pim] if pim else []
                piped = subprocess.run([binary, "open", volume, "--password-stdin",
                                        "--master-key", *pim_args],
                                       input=(PASSWORD + "\n").encode(), capture_output=True,
                                       timeout=600)
                wrong = subprocess.run([binary, "open", volume, "--password-stdin", *pim_args],
                                       input=b"wrong\n", capture_output=True, timeout=600)
                report(f"master key: {key}" in piped.stdout.decode() and wrong.returncode != 0,
                       f"our {name}, opened with --password-stdin",
                       piped.stderr.decode()[-200:])
            if ok and record and name in RECORDED:
                write_fixture(volume, name, plaintext)
                records.append(dict(name=name, arguments=" ".join(arguments),
                                    volume=f"veracrypt/{name}.sparse", password=PASSWORD,
                                    pim=pim or "0",
                                    hash=arguments[arguments.index("--hash") + 1],
                                    master_key=key, data_length=len(plaintext),
                                    data_sha256=hashlib.sha256(plaintext).hexdigest()))
        except Exception as error:  # noqa: BLE001 - reported, not hidden
            report(False, f"our {name}, opened by cryptsetup", str(error)[-300:])


def write_fixture(volume, name, plaintext):
    """The volume with only what is read kept: the header, the data
    recorded and the backup header. VeraCrypt fills the rest with random
    bytes, which would be most of the file."""
    data = open(volume, "rb").read()
    kept = bytearray(len(data))
    for start, length in ((0, 512), (131072, len(plaintext)), (len(data) - 131072, 512)):
        kept[start:start + length] = data[start:start + length]
    os.makedirs(os.path.join(FIXTURES, "veracrypt"), exist_ok=True)
    with open(os.path.join(FIXTURES, "veracrypt", f"{name}.sparse"), "wb") as out:
        out.write(b"SPARSE01" + len(kept).to_bytes(8, "big"))
        at = 0
        while at < len(kept):
            if any(kept[at:at + 512]):
                start = at
                while at < len(kept) and any(kept[at:at + 512]):
                    at += 512
                out.write(start.to_bytes(8, "big") + (at - start).to_bytes(4, "big")
                          + bytes(kept[start:at]))
            else:
                at += 512


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cryptsetup", default="/opt/cryptsetup/run.sh")
    parser.add_argument("--cryptsetup-tests", metavar="DIR")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "--quiet", "--release", "--example", "veracrypt"],
                   cwd=ROOT, check=True)
    binary = os.path.join(ROOT, "target", "release", "examples", "veracrypt")
    version = subprocess.run([args.cryptsetup, "--version"], capture_output=True,
                             text=True).stdout.strip()
    print(f"witness: {version}")
    failures = rows = 0
    records = []

    def report(ok, label, detail=""):
        nonlocal failures, rows
        rows += 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label:70} {'' if ok else detail}")

    with tempfile.TemporaryDirectory() as d:
        our_volumes(binary, args.cryptsetup, d, report, args.record, records)
        if args.cryptsetup_tests:
            their_images(binary, args.cryptsetup, args.cryptsetup_tests, d, report)
    print(f"{rows - failures} of {rows} passed.")
    if args.record and not failures:
        with open(os.path.join(FIXTURES, "veracrypt.vec"), "w") as out:
            out.write(
                "# VeraCrypt and TrueCrypt volumes examples/products/veracrypt wrote\n"
                "# that cryptsetup opened, for the example's tests. Written by\n"
                "# scripts/check_veracrypt.py --record; master_key is what\n"
                "# `cryptsetup tcryptDump --dump-master-key` printed, and\n"
                "# python-cryptography's AES-XTS under it decrypted the data.\n"
                "# Only the headers and the data recorded are kept; the random\n"
                "# fill of the rest is zeros. Do not edit.\n"
                f"#\n# {version}\n\n[cryptsetup]\n")
            for record in records:
                out.write("\n")
                for key in ("name", "arguments", "volume", "password", "pim", "hash",
                            "master_key", "data_length", "data_sha256"):
                    out.write(f"{key} = {record[key]}\n")
        print(f"wrote {len(records)} volumes to {FIXTURES}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
