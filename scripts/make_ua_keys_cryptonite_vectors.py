#!/usr/bin/env python3
"""Write vectors/ua_keys_cryptonite.vec: the Ukrainian key containers as
PrivatBank's cryptonite reads them - a second witness beside dstu-engine's
keylib, which scripts/check_ua_keys.py records in vectors/ua_keys.vec.

    sh scripts/witness/cryptonite/build.sh /opt/cryptonite
    python3 scripts/make_ua_keys_cryptonite_vectors.py [--cryptonite-tests DIR]

cryptonite's storage library reads PKCS#8, IIT's PBES2 (GOST 28147 CFB
under PBKDF2-HMAC-GOST 34.311) and PKCS#12; not `Key-6.dat` or JKS, so
those rows of the keylib file have no row here. It is asked about:

  * every plain and encrypted PKCS#8 in `tests/keys/ua/` - jkurwa's and
    this library's;
  * the PKCS#12 stores in `examples/products/fixtures/keystore-ua/` -
    dstu-engine's and this library's;
  * `cryptonite-iit.pfx` there, a PKCS#12 the IIT software wrote, from
    cryptonite's own tests (`src/storageUtest/resources/`, BSD licence).
    With `--cryptonite-tests DIR` it is copied from that directory, after
    its git blob ID is checked; without, the copy already there is
    checked.

**A development tool, not a test.** `tests/test_ua_keys.rs` reads the
PKCS#8 rows and the key store example's tests the PKCS#12 ones, offline.

Rows, hex fields, `-` for empty:

    pkcs8 file= password=- keys=M:D:QX:QY kep=D|- witnesses=cryptonite
    pbes2 file= password= keys= kep= witnesses=cryptonite
    p12 file= password= key-password= keys=K,K... kep=D|-,... witnesses=cryptonite
    refused file= format= password= code= why=

`keys` are as `vectors/ua_keys.vec` writes them - the field's degree, `d`
reduced modulo the order, and the public point cryptonite computes from
it, big-endian and as wide as the field. `kep` is the IIT key-agreement
key in the attributes, as cryptonite's `pkcs8_get_kep_privatekey` reads
it; cryptonite reads no curve for it, so only `d`. A `refused` row is a
file this library and keylib read and cryptonite does not, with
cryptonite's error code.
"""

import argparse
import base64
import hashlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WITNESS = "/opt/cryptonite/cryptonite-storage"
OUTPUT = os.path.join(ROOT, "vectors", "ua_keys_cryptonite.vec")
KEYS = os.path.join(ROOT, "tests", "keys", "ua")
STORES = os.path.join(ROOT, "examples", "products", "fixtures", "keystore-ua")
IIT = ("pkcs12_by_iit(123456).pfx", "cryptonite-iit.pfx",
       "c79f067f473332f812cbd76f319f5cb7843f409c", "123456")

# The files cryptonite refuses, and why - checked, so that a new refusal
# is a failure rather than a quiet row.
EXPECTED_REFUSALS = {
    # d is above the group order; this library and keylib reduce it.
    "tests/keys/ua/KeyE54B.cer": (6, "RET_INVALID_PRIVATE_KEY: d is above the order"),
    # A 48 byte password: cryptonite's hmac_init hashes a key only above
    # 64 bytes rather than above the hash's 32 byte block, so it uses the
    # password's first 32 bytes.
    "tests/keys/ua/ours-m431-pbes2-long.der": (
        102, "RET_ASN1_DECODE_ERROR: the HMAC key is cut to 32 bytes"),
}


def git_blob(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def der(path):
    data = open(path, "rb").read()
    if data.startswith(b"-----"):
        return base64.b64decode(b"".join(
            line for line in data.splitlines() if line and not line.startswith(b"-----")))
    return data


class Cryptonite:
    def __init__(self):
        self.p = subprocess.Popen([WITNESS], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True)

    def ask(self, *words):
        self.p.stdin.write(" ".join(words) + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()


def key_text(answer):
    """`M:D:QX:QY:N[ kep:D]` from the witness, as (keys entry, kep)."""
    main, _, kep = answer.partition(" kep:")
    m, d, qx, qy, n = main.split(":")
    m = int(m)
    width = (m + 7) // 8 * 2
    d = int(d, 16) % int(n, 16)
    return (f"{m}:{d:0{width}x}:{int(qx, 16):0{width}x}:{int(qy, 16):0{width}x}",
            kep or "-")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cryptonite-tests")
    args = parser.parse_args()
    target = os.path.join(STORES, IIT[1])
    if args.cryptonite_tests:
        source = os.path.join(args.cryptonite_tests, IIT[0])
        if git_blob(open(source, "rb").read()) != IIT[2]:
            sys.exit(f"{source} is not the file whose blob is {IIT[2]}")
        shutil.copyfile(source, target)
    if git_blob(open(target, "rb").read()) != IIT[2]:
        sys.exit(f"{target} is not cryptonite's {IIT[0]}")

    witness = Cryptonite()
    lines, refused = [], {}
    for row in open(os.path.join(ROOT, "vectors", "ua_keys.vec")):
        if row.startswith("#"):
            continue
        f = dict(w.split("=", 1) for w in row.split())
        if f["format"] not in ("pkcs8", "pbes2"):
            continue
        rel = f"tests/keys/ua/{f['file']}"
        data = der(os.path.join(KEYS, f["file"])).hex()
        answer = (witness.ask("pkcs8", data) if f["format"] == "pkcs8"
                  else witness.ask("pbes2", f["password"], data))
        if answer.startswith("error"):
            refused[rel] = (f["format"], f["password"], int(answer.split()[-1]))
            continue
        keys, kep = key_text(answer)
        lines.append(f"{f['format']} file={rel} password={f['password']} keys={keys} kep={kep} "
                     "witnesses=cryptonite")

    stores = [(name, password, key_password) for name, password, key_password in
              [(r["name"], r["password"], r["key-password"]) for r in store_records()]
              if name.endswith((".p12", ".pfx"))]
    stores.append((IIT[1], IIT[3].encode().hex(), IIT[3].encode().hex()))
    for name, password, key_password in stores:
        rel = f"examples/products/fixtures/keystore-ua/{name}"
        answer = witness.ask("p12", password, key_password,
                             open(os.path.join(STORES, name), "rb").read().hex())
        if answer.startswith("error"):
            refused[rel] = ("p12", password, int(answer.split()[-1]))
            continue
        found = [key_text(part.split(" ", 2)[2]) for part in answer.split(" | ")
                 if part.startswith("key ")]
        if not found:
            sys.exit(f"cryptonite found no key in {rel}")
        lines.append(f"p12 file={rel} password={password} key-password={key_password} "
                     f"keys={','.join(k for k, _ in found)} kep={','.join(e for _, e in found)} "
                     "witnesses=cryptonite")

    if set(refused) != set(EXPECTED_REFUSALS):
        sys.exit(f"cryptonite refused {sorted(refused)}, not {sorted(EXPECTED_REFUSALS)}")
    for rel, (fmt, password, code) in sorted(refused.items()):
        expected, why = EXPECTED_REFUSALS[rel]
        if code != expected:
            sys.exit(f"cryptonite refused {rel} with {code}, not {expected}")
        lines.append(f"refused file={rel} format={fmt} password={password} code={code} "
                     f"why={why.replace(' ', '_')}")

    header = [
        "# DSTU 4145 keys in Ukrainian containers as PrivatBank's cryptonite (commit",
        "# 3618d340) read them. Written by scripts/make_ua_keys_cryptonite_vectors.py;",
        "# do not edit. keys as in vectors/ua_keys.vec; kep is the key-agreement",
        "# key's d; a refused row is a file cryptonite does not read.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows, {len(refused)} refused")


def store_records():
    """The `[store]` records of keystore-ua.vec, as dicts."""
    records, current = [], None
    for line in open(os.path.join(ROOT, "examples", "products", "fixtures",
                                  "keystore-ua.vec"), encoding="utf-8"):
        line = line.strip()
        if line.startswith("name = "):
            current = {"name": line[len("name = "):]}
            records.append(current)
        elif current is not None and " = " in line:
            key, value = line.split(" = ", 1)
            current.setdefault(key, value)
    return records


if __name__ == "__main__":
    main()
