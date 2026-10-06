#!/usr/bin/env python3
"""The BitLocker example (`examples/products/bitlocker`) against cryptsetup.

cryptsetup's test suite carries BitLocker volumes that Windows made
(`tests/bitlk-images.tar.xz`): every method - AES-CBC with and without
the Elephant diffuser and AES-XTS, at 128 and 256 bits - 4096-byte
sectors, BitLocker To Go, startup keys, a clear key, two recovery
passwords, a non-ASCII password, a volume still being encrypted. Its
`images.conf` gives each one's password, recovery password and the
SHA-256 of the volume as dm-crypt decrypts it.

For each image:

  * our `dump` against `cryptsetup bitlkDump`: the GUID, the sector and
    volume sizes, the description, the cipher, every protector's GUID,
    kind and salt, the metadata offsets and the relocated volume
    header;
  * our `open` with every secret the image has against `cryptsetup
    bitlkDump --dump-volume-key` with the same secret, and a wrong
    password refused;
  * our `open --decrypt` against `images.conf`'s SHA-256 of the whole
    decrypted volume, or a refusal where cryptsetup refuses too (a
    volume still being encrypted).

And the other way: our `format` writes a volume with every method at
both sector sizes, with a password and a recovery password protector
(and one with a clear key alone);
`cryptsetup bitlkDump` must read the same metadata and dump our volume
key with either secret, and refuse a wrong one. cryptsetup cannot
decrypt the data without device-mapper; our own reading, which is what
matched Windows's volumes above, gets the data back.

    python3 scripts/check_bitlocker.py --cryptsetup-tests ~/src/cryptsetup/tests
    python3 scripts/check_bitlocker.py --cryptsetup-tests DIR --record

`--record` writes the images (sparse: only their non-zero 512-byte
blocks) and what was checked into `examples/products/fixtures/` for the
example's offline tests, with the SHA-256 of some stretches of each
decrypted volume taken from the output whose whole hash matched.

**A development tool, not a test.** It needs a cryptsetup build and
cryptsetup's test images; the gate runs none of it.
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")


def images_conf(path):
    """`[name]` sections of `KEY=value` lines."""
    sections, current = {}, None
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
        elif "=" in line and current is not None:
            key, value = line.split("=", 1)
            current[key] = value
    return sections


def field(text, label):
    m = re.search(rf"^\s*{re.escape(label)}:\s*(.*)$", text, re.M)
    return m.group(1).strip() if m else None


def cryptsetup_dump(cryptsetup, image):
    text = subprocess.run([cryptsetup, "bitlkDump", image], capture_output=True, text=True,
                          check=True).stdout
    slots = re.findall(r"^\s*\d+: VMK\n(?:\s*Name:\s*(.*)\n)?\s*GUID:\s*(\S+)\n"
                       r"\s*Protection:\s*VMK protected with (.+?)\n\s*Salt:\s*(\S+)", text, re.M)
    segments = re.findall(r"^\s*\d+: FVE metadata area\n\s*Offset:\s*(\d+)", text, re.M)
    header = re.search(r"Volume header\n\s*Offset:\s*(\d+) \[bytes\]\n\s*Size:\s*(\d+)", text)
    return dict(
        guid=field(text, "GUID"),
        sector=field(text, "Sector size").split()[0],
        size=field(text, "Volume size").split()[0],
        description=field(text, "Description"),
        mode=field(text, "Cipher mode"),
        bits=field(text, "Cipher key").split()[0],
        slots=[(g, p, s, n.strip()) for n, g, p, s in slots],
        offsets=segments,
        header=(header.group(1), header.group(2)) if header else None,
    )


PROTECTIONS = {"password": "passphrase", "recovery password": "recovery passphrase",
               "startup key": "startup key", "clear key": "clear key", "TPM": "TPM",
               "TPM and PIN": "TPM and PIN", "smart card": "smart card"}


def our_dump(ours, image):
    text = subprocess.run([ours, "dump", image], capture_output=True, text=True,
                          check=True).stdout
    slots = []
    for m in re.finditer(r"^Protector \d+:\s+(\S+) (.+?)(?: \((.*)\))?\n  salt\s+(\S+)",
                         text, re.M):
        salt = "0" * 32 if m.group(4) == "-" else m.group(4)
        slots.append((m.group(1), PROTECTIONS.get(m.group(2), m.group(2)), salt,
                      m.group(3) or ""))
    dm = re.search(r"dm-crypt:\s+aes-(\S+), (\d+) bit key", text)
    header = re.search(r"Volume header:\s+(\d+) bytes at (\d+)", text)
    return dict(
        guid=field(text, "GUID"),
        sector=field(text, "Sector size"),
        size=field(text, "Volume size"),
        description=field(text, "Description"),
        mode=dm.group(1) if dm else None,
        bits=dm.group(2) if dm else None,
        slots=slots,
        offsets=re.findall(r"^Metadata \d+:\s+(\d+)", text, re.M),
        header=(header.group(2), header.group(1)) if header else None,
    )


def cryptsetup_key(cryptsetup, image, secret, keyfile=None):
    """The volume key `bitlkDump --dump-volume-key` prints, or None."""
    args = [cryptsetup, "bitlkDump", image, "--dump-volume-key"]
    if keyfile:
        args += ["--key-file", keyfile]
    run = subprocess.run(args, input=None if keyfile else (secret or "") + "\n",
                         capture_output=True, text=True)
    m = re.search(r"MK dump:\s*((?:[0-9a-f]{2}\s+)+)", run.stdout)
    return "".join(m.group(1).split()) if m else None


def our_open(ours, image, kind, secret, decrypt=None):
    args = [ours, "open", image]
    stdin = None
    if kind == "password":
        args.append("--password-stdin")
        stdin = (secret + "\n").encode()
    elif kind == "recovery":
        args += ["--recovery-password", secret]
    elif kind == "startup":
        args += ["--startup-key", secret]
    elif kind == "clear":
        args.append("--clear-key")
    elif kind == "volume-key":
        args += ["--volume-key", secret]
    if decrypt:
        args += ["--decrypt", decrypt]
    run = subprocess.run(args, input=stdin, capture_output=True, timeout=600)
    m = re.search(rb"Volume key:\s+([0-9a-f]+)", run.stdout)
    return (m.group(1).decode() if m else None), run.stderr.decode().strip()


def write_sparse(image_path, out_path):
    """Every non-zero 512-byte block of the image, as runs."""
    data = open(image_path, "rb").read()
    runs, at = [], 0
    while at < len(data):
        if any(data[at:at + 512]):
            start = at
            while at < len(data) and any(data[at:at + 512]):
                at += 512
            runs.append((start, data[start:at]))
        else:
            at += 512
    with open(out_path, "wb") as out:
        out.write(b"SPARSE01" + len(data).to_bytes(8, "big"))
        for start, run in runs:
            out.write(start.to_bytes(8, "big") + len(run).to_bytes(4, "big") + run)


def samples(dump, length):
    """Stretches of the decrypted volume worth checking offline: the
    start, both sides of every zeroed area, and the end."""
    ranges = [(0, 65536)]
    for offset in [int(o) for o in dump["offsets"]] + [int(dump["header"][0])]:
        for edge in (offset, offset + (65536 if offset != int(dump["header"][0])
                                       else int(dump["header"][1]))):
            start = max(0, edge - 8192)
            ranges.append((start, min(16384, length - start)))
    ranges.append((length - 65536, 65536))
    return ranges


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cryptsetup", default="/opt/cryptsetup/run.sh")
    parser.add_argument("--cryptsetup-tests", metavar="DIR", required=True,
                        help="a cryptsetup source tree's tests/ directory")
    parser.add_argument("--record", action="store_true",
                        help="write the images to examples/products/fixtures/")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "--quiet", "--release", "--example", "bitlocker"],
                   cwd=ROOT, check=True)
    ours = os.path.join(ROOT, "target", "release", "examples", "bitlocker")
    version = subprocess.run([args.cryptsetup, "--version"], capture_output=True,
                             text=True).stdout.strip()
    print(f"witness: {version}")
    failures = rows = 0
    records = []

    def report(ok, label, detail=""):
        nonlocal failures, rows
        rows += 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label:66} {'' if ok else detail}")

    with tempfile.TemporaryDirectory() as d:
        with tarfile.open(os.path.join(args.cryptsetup_tests, "bitlk-images.tar.xz")) as tar:
            tar.extractall(d, filter="data")
        directory = os.path.join(d, "bitlk-images")
        conf = images_conf(os.path.join(directory, "images.conf"))
        beks = sorted(f for f in os.listdir(directory) if f.endswith(".BEK"))
        for name in sorted(conf):
            image = os.path.join(directory, name + ".img")
            if not os.path.exists(image):
                continue
            settings = conf[name]
            theirs = cryptsetup_dump(args.cryptsetup, image)
            mine = our_dump(ours, image)
            differing = [k for k in theirs if theirs[k] != mine[k]]
            report(not differing, f"{name}: dump",
                   "; ".join(f"{k}: ours {mine[k]} cryptsetup {theirs[k]}" for k in differing))

            secrets = []
            if settings.get("PW"):
                secrets.append(("password", settings["PW"], None))
            for key in ("RP", "RP2"):
                if settings.get(key):
                    secrets.append(("recovery", settings[key], None))
            if "startup-key" in name:
                for bek in beks:
                    secrets.append(("startup", os.path.join(directory, bek), bek))
            if "clearkey" in name:
                secrets.append(("clear", None, None))
            opened = None
            for kind, secret, bek in secrets:
                label = f"{name}: {kind}" + (f" {bek}" if bek else "")
                expected = cryptsetup_key(args.cryptsetup, image, secret,
                                          keyfile=secret if kind == "startup" else None)
                got, error = our_open(ours, image, kind, secret)
                if expected is None and kind == "startup":
                    # The other volume's startup key: both must refuse it.
                    report(got is None, f"{label} refused", f"ours gave {got}")
                    continue
                report(got is not None and got == expected, label,
                       f"ours {got} ({error[-80:]}), cryptsetup {expected}")
                if got == expected and opened is None:
                    opened = (kind, secret, bek, got)
            if settings.get("PW"):
                got, _ = our_open(ours, image, "password", settings["PW"] + "x")
                report(got is None, f"{name}: a wrong password refused", f"ours gave {got}")

            if opened is None:
                continue
            out = os.path.join(d, "plain")
            got, error = our_open(ours, image, "volume-key", opened[3], decrypt=out)
            want = settings.get("SHA256SUM", "")
            if not want:
                # cryptsetup refuses to activate these (encrypt-on-write,
                # or not fully encrypted); so must we.
                report(got is not None and error != "", f"{name}: decrypt refused",
                       error[-120:])
                plain_sha256 = ""
            else:
                plain_sha256 = hashlib.sha256(open(out, "rb").read()).hexdigest() \
                    if os.path.exists(out) else error[-200:]
                report(plain_sha256 == want, f"{name}: decrypted volume's SHA-256",
                       f"ours {plain_sha256[:16]}... images.conf {want[:16]}...")
            if args.record and (not want or plain_sha256 == want):
                os.makedirs(os.path.join(FIXTURES, "bitlocker"), exist_ok=True)
                sparse = f"bitlocker/{name}.sparse"
                write_sparse(image, os.path.join(FIXTURES, sparse))
                record = dict(name=name, image=sparse, cipher=settings["CIPHER"],
                              password=settings.get("PW", ""),
                              recovery=settings.get("RP", ""),
                              volume_key=opened[3], opened_by=opened[0],
                              startup_key=opened[2] or "", sha256=want)
                if want:
                    plain = open(out, "rb").read()
                    record["samples"] = " ".join(
                        f"{start}:{length}:{hashlib.sha256(plain[start:start + length]).hexdigest()}"
                        for start, length in samples(mine, len(plain)))
                else:
                    record["samples"] = ""
                records.append(record)

        # Ours, read by cryptsetup: every method at both sector sizes,
        # with a password and a recovery password protector.
        plain = bytes((i * 7 + i // 509) & 0xff for i in range(1 << 20))
        data = os.path.join(d, "data")
        open(data, "wb").write(plain)
        for method in ("aes-cbc-elephant-128", "aes-cbc-elephant-256", "aes-cbc-128",
                       "aes-cbc-256", "aes-xts-128", "aes-xts-256"):
            for sector in ("512", "4096"):
                label = f"ours {method}, {sector}-byte sectors, read by cryptsetup"
                image = os.path.join(d, "ours.img")
                try:
                    run = subprocess.run([ours, "format", image, "--size", str(4 << 20),
                                          "--data", data, "--method", method, "--sector-size",
                                          sector, "--password-stdin", "--new-recovery-password"],
                                         input="pässword\n".encode(), capture_output=True,
                                         check=True)
                    key = re.search(rb"Volume key:\s+([0-9a-f]+)", run.stdout).group(1).decode()
                    recovery = re.search(rb"Recovery:\s+(\S+)", run.stdout).group(1).decode()
                    theirs = cryptsetup_dump(args.cryptsetup, image)
                    mine = our_dump(ours, image)
                    differing = [k for k in theirs if theirs[k] != mine[k]]
                    by_password = cryptsetup_key(args.cryptsetup, image, "pässword")
                    by_recovery = cryptsetup_key(args.cryptsetup, image, recovery)
                    wrong = cryptsetup_key(args.cryptsetup, image, "password")
                    out = os.path.join(d, "back")
                    got, _ = our_open(ours, image, "recovery", recovery, decrypt=out)
                    back = open(out, "rb").read(len(plain)) if os.path.exists(out) else b""
                    ok = (not differing and by_password == key and by_recovery == key
                          and wrong is None and got == key and back == plain)
                    report(ok, label, f"differing {differing}, cryptsetup {by_password} "
                           f"{by_recovery} wrong {wrong}, ours {key} {got}, "
                           f"data {back == plain}")
                except Exception as error:  # noqa: BLE001 - reported, not hidden
                    report(False, label, str(error)[-200:])

        # A clear key alone: protection suspended, opened with no secret.
        image = os.path.join(d, "ours-clear.img")
        try:
            run = subprocess.run([ours, "format", image, "--size", str(4 << 20), "--data", data,
                                  "--clear-key"], capture_output=True, check=True)
            key = re.search(rb"Volume key:\s+([0-9a-f]+)", run.stdout).group(1).decode()
            theirs = cryptsetup_key(args.cryptsetup, image, "")
            got, _ = our_open(ours, image, "clear", None)
            report(theirs == key and got == key, "ours with a clear key, read by cryptsetup",
                   f"ours {key} cryptsetup {theirs}")
        except Exception as error:  # noqa: BLE001
            report(False, "ours with a clear key, read by cryptsetup", str(error)[-200:])

        print(f"{rows - failures} of {rows} passed.")
        if args.record and not failures:
            for bek in beks:
                with open(os.path.join(directory, bek), "rb") as source, \
                        open(os.path.join(FIXTURES, "bitlocker", bek), "wb") as out:
                    out.write(source.read())
            with open(os.path.join(FIXTURES, "bitlocker.vec"), "w") as out:
                out.write(
                    "# BitLocker volumes Windows made, from cryptsetup's tests/bitlk-images,\n"
                    "# for examples/products/bitlocker's tests. Written by\n"
                    "# scripts/check_bitlocker.py --record. Each image is\n"
                    "# fixtures/bitlocker/NAME.sparse (its non-zero 512-byte blocks);\n"
                    "# password, recovery and sha256 are images.conf's, volume_key is what\n"
                    "# `cryptsetup bitlkDump --dump-volume-key` printed, opened_by the first\n"
                    "# secret that opened it, and each sample START:LENGTH:SHA256 a stretch\n"
                    "# of the decrypted volume whose whole SHA-256 matched sha256. Do not\n"
                    f"# edit.\n#\n# {version}\n\n[windows]\n")
                for record in records:
                    out.write("\n")
                    for key in ("name", "image", "cipher", "password", "recovery",
                                "startup_key", "opened_by", "volume_key", "sha256", "samples"):
                        out.write(f"{key} = {record[key] or '-'}\n")
            print(f"wrote {len(records)} images to {FIXTURES}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
