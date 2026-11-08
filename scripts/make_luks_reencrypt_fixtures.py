#!/usr/bin/env python3
"""Write examples/products/fixtures/luks/reencrypt/: LUKS2 volumes that
cryptsetup left in the middle of changing their volume key
(`cryptsetup reencrypt`), for the LUKS example's offline tests.

    python3 scripts/make_luks_reencrypt_fixtures.py [--cryptsetup /opt/cryptsetup/run.sh]

One volume is made first: a known plaintext, encrypted by `cryptsetup
reencrypt --encrypt` under AES-CBC-ESSIV, 512 byte sectors, with a fixed
old volume key. Each fixture is a copy of it that `cryptsetup reencrypt`
was moving to AES-XTS, 4096 byte sectors, a fixed new volume key, in
hotzones of 16 KiB - and was stopped at a chosen write into the data area
by `scripts/kill_at_write.c`, a preload library this compiles with `cc`:

  * before the write (the hotzone still all old), part of the way through
    it (a torn write: some blocks new, the rest old) or after it (all
    new), each with the process gone before the header records the step;
  * by SIGTERM, which cryptsetup catches: it finishes the step and records
    it, so the header has no hotzone.

Each with a resilience mode: `checksum` (a hash of every old block in the
reencrypt keyslot's area, so recovery can tell old blocks from new),
`journal` (a copy of the hotzone's old ciphertext there) or `none`.

The witness is cryptsetup itself: for every fixture it must repair the
volume (which checks the reencryption digest and recovers the hotzone),
finish the reencryption, then decrypt it to plaintext (`reencrypt
--decrypt --header`) - and the result must be the plaintext that was
encrypted. The example must read the same plaintext from the stopped
volume without writing to it.

The fixtures are sparse (`SPARSE01`, as `check_luks.py` writes them),
keeping only what a reader reads: both header copies, the part of the
reencrypt area the hotzone uses, the data, and - in one fixture - the
keyslots' key material. The others carry no keyslot material and are
opened with the two volume keys, which `luks-reencrypt.vec` lists.

**A development tool, not a test.**
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from check_luks import write_sparse  # noqa: E402

FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OUT = os.path.join(FIXTURES, "luks", "reencrypt")
SHIM_SOURCE = os.path.join(HERE, "kill_at_write.c")
PASSPHRASE = "reencrypt passphrase"
DATA = 64 * 1024
HOTZONE = 16 * 1024
OLD_KEY = hashlib.sha256(b"allcrypt luks reencrypt old").digest()[:16]
NEW_KEY = hashlib.sha256(b"allcrypt luks reencrypt new").digest()
FAST = ["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha256"]

# (name, resilience, resilience hash, which data write, how it stops,
#  keyslot material kept). The data area is 4 hotzones; the writes into
# it are numbered from 1.
CASES = [
    ("interrupted-checksum", "checksum", "sha256", 2, "sigterm", True),
    ("checksum-before-write", "checksum", "sha256", 1, 0, False),
    ("checksum-torn", "checksum", "sha512", 3, 3 * 4096, False),
    ("checksum-after-write", "checksum", "sha256", 2, HOTZONE, False),
    ("journal-before-write", "journal", None, 4, 0, False),
    ("journal-torn", "journal", None, 2, 4096, False),
    ("interrupted-none", "none", None, 3, "sigterm", False),
]


def plaintext():
    return bytes((i * 29 + i // 509) & 0xFF for i in range(DATA))


class Rig:
    def __init__(self, cryptsetup, tmp):
        self.cryptsetup = cryptsetup
        self.tmp = tmp
        self.key_file = os.path.join(tmp, "pass")
        with open(self.key_file, "w") as handle:
            handle.write(PASSPHRASE)

    def cs(self, *args, env=None, check=True):
        result = subprocess.run([self.cryptsetup, *args, "--key-file", self.key_file, "-q"],
                                capture_output=True, text=True, timeout=600,
                                env={**os.environ, **(env or {})})
        if check and result.returncode != 0:
            sys.exit(f"cryptsetup {args[0]}: {result.stderr.strip()[-300:]}")
        return result

    def header(self, image):
        return json.loads(self.cs("luksDump", "--dump-json-metadata", image).stdout)

    def base(self):
        image = os.path.join(self.tmp, "base.img")
        old_key = os.path.join(self.tmp, "old.key")
        with open(old_key, "wb") as handle:
            handle.write(OLD_KEY)
        with open(image, "wb") as handle:
            handle.write(plaintext() + bytes(1024 * 1024))
        self.cs("reencrypt", "--encrypt", "--type", "luks2", "--cipher", "aes-cbc-essiv:sha256",
                "--key-size", "128", "--volume-key-file", old_key, "--sector-size", "512",
                *FAST, "--luks2-metadata-size", "16k", "--luks2-keyslots-size", "480k",
                "--reduce-device-size", "1M", image)
        offset = int(self.header(image)["segments"]["0"]["offset"])
        # The data area is the plaintext's length and no more: the
        # segment is "dynamic", to the end of the device.
        os.truncate(image, offset + DATA)
        return image, offset

    def witness(self, image):
        """cryptsetup's own reading: repair, finish, decrypt."""
        work = os.path.join(self.tmp, "witness.img")
        header = os.path.join(self.tmp, "witness.hdr")
        shutil.copyfile(image, work)
        if os.path.exists(header):
            os.remove(header)
        self.cs("repair", work)
        # Recovering the last hotzone finishes the reencryption.
        if self.header(work)["config"].get("requirements", {}).get("mandatory"):
            self.cs("reencrypt", "--resume-only", "--force-offline-reencrypt", work)
        self.cs("reencrypt", "--decrypt", "--header", header, "--force-offline-reencrypt", work)
        return open(work, "rb").read()[:DATA]


def kept_ranges(image, header, keep_keyslots):
    """What a reader reads: the headers, the reencrypt area's used part,
    the data, and with `keep_keyslots` the key material."""
    data = open(image, "rb").read()
    hdr_size = int.from_bytes(data[8:16], "big")
    ranges = [(0, 2 * hdr_size)]
    segments = header["segments"]
    hotzone = [s for s in segments.values() if "in-reencryption" in s.get("flags", [])]
    for slot in header["keyslots"].values():
        area = slot["area"]
        if slot["type"] == "luks2" and keep_keyslots:
            ranges.append((int(area["offset"]), slot["key_size"] * slot["af"]["stripes"]))
        elif slot["type"] == "reencrypt" and hotzone:
            length = int(hotzone[0]["size"])
            if area["type"] == "checksum":
                digest = hashlib.new(area["hash"]).digest_size
                length = length // area["sector_size"] * digest
            ranges.append((int(area["offset"]), length))
    first = min(int(s["offset"]) for s in segments.values())
    ranges.append((first, DATA))
    return ranges


def describe(header):
    segments = header["segments"]
    hotzone = [s for s in segments.values() if "in-reencryption" in s.get("flags", [])]
    if not hotzone:
        return "no hotzone"
    return f"hotzone {hotzone[0]['size']} bytes at {hotzone[0]['offset']}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cryptsetup", default="/opt/cryptsetup/run.sh")
    args = parser.parse_args()
    version = subprocess.run([args.cryptsetup, "--version"], capture_output=True,
                             text=True).stdout.split()[1]
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    records = []
    with tempfile.TemporaryDirectory() as tmp:
        rig = Rig(args.cryptsetup, tmp)
        shim = os.path.join(tmp, "kill_at_write.so")
        subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-o", shim, SHIM_SOURCE, "-ldl"],
                       check=True)
        base, data_offset = rig.base()
        new_key = os.path.join(tmp, "new.key")
        with open(new_key, "wb") as handle:
            handle.write(NEW_KEY)
        for name, resilience, csum_hash, at, stop, keep in CASES:
            image = os.path.join(tmp, f"{name}.img")
            shutil.copyfile(base, image)
            env = {"LD_PRELOAD": shim, "KILL_DATA_OFFSET": str(data_offset), "KILL_AT": str(at)}
            if stop == "sigterm":
                env["KILL_SIGNAL"] = "15"
            else:
                env["KILL_KEEP"] = str(stop)
            extra = ["--resilience-hash", csum_hash] if csum_hash else []
            result = rig.cs("reencrypt", "--cipher", "aes-xts-plain64", "--new-key-size", "256",
                            "--new-volume-key-file", new_key, "--sector-size", "4096", *FAST,
                            "--resilience", resilience, *extra, "--hotzone-size", str(HOTZONE),
                            "--force-offline-reencrypt", image, env=env, check=False)
            if result.returncode == 0:
                sys.exit(f"{name}: cryptsetup finished; it was to be stopped")
            header = rig.header(image)
            if "online-reencrypt-v2" not in header["config"]["requirements"]["mandatory"]:
                sys.exit(f"{name}: the header is not mid-reencryption")
            hotzone = describe(header)
            if (stop == "sigterm") != (hotzone == "no hotzone"):
                sys.exit(f"{name}: {hotzone}, not what stopping it this way leaves")
            if rig.witness(image) != plaintext():
                sys.exit(f"{name}: cryptsetup does not recover the plaintext")
            write_sparse(image, os.path.join(OUT, f"{name}.sparse"), DATA,
                         ranges=kept_ranges(image, header, keep))
            stopped = (f"SIGTERM at data write {at}" if stop == "sigterm" else
                       f"exit at data write {at} after {stop} of its {HOTZONE} bytes")
            records.append({"name": name, "image": f"luks/reencrypt/{name}.sparse",
                            "passphrase": PASSPHRASE if keep else "-",
                            "old_key": OLD_KEY.hex(), "new_key": NEW_KEY.hex(),
                            "resilience": resilience, "stopped": stopped, "state": hotzone,
                            "data_length": DATA,
                            "data_sha256": hashlib.sha256(plaintext()).hexdigest()})
    with open(os.path.join(FIXTURES, "luks-reencrypt.vec"), "w") as handle:
        handle.write(
            "# LUKS2 volumes stopped in the middle of `cryptsetup reencrypt`, written by\n"
            "# scripts/make_luks_reencrypt_fixtures.py; do not edit. Each was repaired,\n"
            "# finished and decrypted by cryptsetup to the plaintext whose SHA-256 is\n"
            "# data_sha256. passphrase `-`: the keyslot material is not kept; open with\n"
            f"# old_key and new_key. cryptsetup {version}.\n")
        handle.write("\n[cryptsetup]\n")
        for record in records:
            for key, value in record.items():
                handle.write(f"{key} = {value}\n")
            handle.write("\n")
    print(f"wrote {OUT}: {len(records)} volumes")


if __name__ == "__main__":
    main()
