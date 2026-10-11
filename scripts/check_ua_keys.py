#!/usr/bin/env python3
"""Ukrainian key containers against dstu-engine's keylib, both directions.

keylib is the container library that ships with dstu-engine, an OpenSSL
engine for the Ukrainian standards; `scripts/witness/dstuengine` builds
it with a driver that prints every key it finds as numbers (the curve,
`d`, the public point) and the SHA-256 of every certificate.

  * **They write, ours reads**: the containers in dstu-engine's tests
    (IIT's `Key-6.dat`, a PKCS#12 and a PrivatBank JKS) and in jkurwa's
    (an encrypted PKCS#8 and plain keys, DER and PEM, one with `d` above
    the order). The library (`dstu4145_keys_open`) or the key store
    example must find the keys keylib finds, in its order, and the
    certificates; a wrong password must be refused.
  * **Ours writes, keylib reads**: a key on each of the ten named curves,
    some with a second key in the attributes, as a plain PKCS#8, as
    PBES2 with GOST 28147 CFB and HMAC-GOST 34.311, and as a
    `Key-6.dat`; and the key store example's GOST PKCS#12 and JKS.
  * jkurwa's self-signed certificates carry, as their subject key
    identifier, the key identifier of the key beside them; ours must
    compute the same.

keylib's JKS reader handles a trusted-certificate entry without skipping
its alias and date, so it refuses any JKS that has one; ours is checked
with a store of key entries only.

    python3 scripts/check_ua_keys.py --dstu-engine DIR --jkurwa DIR
    python3 scripts/check_ua_keys.py --dstu-engine DIR --jkurwa DIR --record

DIR are dstu-engine's `tests/` and jkurwa's `test/data/`; each file used
is checked against the git blob ID below. `--record` keeps the files and
what keylib found in them for the offline tests: the library's in
`tests/keys/ua/` with `vectors/ua_keys.vec`, the key stores in
`examples/products/fixtures/keystore-ua/` with `keystore-ua.vec`.

**A development tool, not a test.** Build the witness
(`scripts/witness/dstuengine/build.sh`), the Python module and
`cargo build --release --example keystore` first.
"""

import argparse
import base64
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "python"))

import allcrypt  # noqa: E402

WITNESS = "/opt/dstuengine/dstuengine-witness"
ENGINE = "/opt/dstuengine/dstu.so"
KEYSTORE = os.path.join(ROOT, "target", "release", "examples", "keystore")
LIB_FIXTURES = os.path.join(ROOT, "tests", "keys", "ua")
LIB_VEC = os.path.join(ROOT, "vectors", "ua_keys.vec")
STORE_FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures", "keystore-ua")
STORE_VEC = os.path.join(ROOT, "examples", "products", "fixtures", "keystore-ua.vec")

# Git blob IDs of the files taken from each project.
BLOBS = {
    ("dstu-engine", "Key-6.dat"): "2ce7b66d7dbad576e363742184dbfeffbac09d65",
    ("dstu-engine", "Key-6.pfx"): "3ce1432bb313de436672df6ad6af752b152433e5",
    ("dstu-engine", "key.jks"): "9e2935682d7439d2237175ff0bbd7b9719204299",
    ("jkurwa", "STORE_A040.dat"): "411c30d9f1f5336cf0d305fb743307803fd15f92",
    ("jkurwa", "STORE_A040.pem"): "849801b9d37aee87ef17fec5542998cb6c16bcd2",
    ("jkurwa", "Key40A0.cer"): "691a0318f52a1264f09da46164ce0f62419b8662",
    ("jkurwa", "Key40A0.pem"): "ba1bec5f6c2bbf357e416069157bdfd58e068cee",
    ("jkurwa", "PRIV1.cer"): "609bf615a4fdede81da44d917f04f27e770bbeda",
    ("jkurwa", "Key6929.cer"): "4a6662d6ec7ffcb66c84b73c2e5d492b464bb673",
    ("jkurwa", "KeyE54B.cer"): "f145351a3bb361c6019ba4d5e55d472eaeba677a",
    ("jkurwa", "SELF_SIGNED1.cer"): "e2359afbe39d2f37399da1347ef0265f7bebd41d",
    ("jkurwa", "SELF_SIGNED_ENC_40A0.cer"): "a1ed0be13ea189daf0a72527f31b5f2cb9884b9a",
    ("jkurwa", "SELF_SIGNED_ENC_6929.cer"): "2cb088c654236307f197ff4793f568c6ff8c9600",
    ("jkurwa", "SELF_SIGNED_ENC_E54B.cer"): "b07459551dbef9b6c13bf50b5bda3ef0bfd4cdd7",
}

# The library's containers: project, file, format (key6, pbes2 for an
# encrypted PKCS#8, pkcs8 for a plain one), password.
THEIRS = [
    ("dstu-engine", "Key-6.dat", "key6", "tect4"),
    ("jkurwa", "STORE_A040.dat", "pbes2", "password"),
    ("jkurwa", "STORE_A040.pem", "pbes2", "password"),
    ("jkurwa", "Key40A0.cer", "pkcs8", ""),
    ("jkurwa", "Key40A0.pem", "pkcs8", ""),
    ("jkurwa", "PRIV1.cer", "pkcs8", ""),
    ("jkurwa", "Key6929.cer", "pkcs8", ""),
    ("jkurwa", "KeyE54B.cer", "pkcs8", ""),
]

# Each certificate and the container holding its key.
CERTIFICATES = [("SELF_SIGNED1.cer", "PRIV1.cer"),
                ("SELF_SIGNED_ENC_40A0.cer", "Key40A0.cer"),
                ("SELF_SIGNED_ENC_6929.cer", "Key6929.cer"),
                ("SELF_SIGNED_ENC_E54B.cer", "KeyE54B.cer")]

# The key stores: project, file, format, store password, key password.
STORES = [("dstu-engine", "Key-6.pfx", "pkcs12", "testplat2021", "testplat2021"),
          ("dstu-engine", "key.jks", "jks", "123456", "qwerty")]

PASSWORD = "пароль"


def git_blob(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def der_of(data):
    """A PEM file's first block, or the bytes as they are."""
    if data.startswith(b"-----BEGIN"):
        body = data.split(b"-----")[2]
        return base64.b64decode(b"".join(body.split()))
    return data


def witness(fmt, data, password, key_password=None):
    """What keylib finds: [(m, d mod n, qx, qy)], [certificate SHA-256]."""
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(der_of(data) if fmt in ("pkcs8", "pbes2") else data)
        f.flush()
        if fmt in ("pkcs8", "pbes2"):
            command = [WITNESS, "pkcs8", f.name, "-" if fmt == "pkcs8" else password]
        else:
            command = [WITNESS, fmt, f.name, password]
        if key_password is not None:
            command.append(key_password)
        result = subprocess.run(command, capture_output=True, text=True,
                                env=dict(os.environ, DSTU_ENGINE=ENGINE))
    if result.returncode or result.stdout.startswith("error"):
        raise RuntimeError(f"keylib: {(result.stdout + result.stderr).strip()}")
    keys, certs = [], []
    for line in result.stdout.splitlines():
        words = line.split()
        if words[0] == "key":
            v = dict(w.split("=") for w in words[1:])
            n = int(v["n"], 16)
            keys.append((int(v["m"]), int(v["d"], 16) % n, int(v["qx"], 16),
                         int(v["qy"], 16)))
        elif words[0] == "cert":
            certs.append(words[1])
    return keys, certs


def numbers(key):
    """A key of ours as the witness prints one."""
    m = int(key.curve.rsplit("m", 1)[1])
    q = key.public_key().public_bytes()
    half = len(q) // 2
    return (m, int.from_bytes(key.private_bytes(), "big"),
            int.from_bytes(q[:half], "big"), int.from_bytes(q[half:], "big"))


def ours(data, password):
    return [numbers(k) for k in allcrypt.dstu4145_keys_open(data, password.encode())]


def keystore(*args):
    result = subprocess.run([KEYSTORE, *args], capture_output=True)
    if result.returncode:
        raise RuntimeError(f"keystore {args[0]}: {result.stderr.decode().strip()}")
    return result.stdout.decode()


def store_contents(path, password, key_password):
    """The key store example's entries: [(kind, DER)] in its order."""
    out = []
    for line in keystore("list", path, "--password", password,
                         "--key-password", key_password, "--canonical").splitlines():
        words = line.split()
        out.append((words[0], bytes.fromhex(words[-1])))
    return out


def store_keys(entries, first_only):
    """The keys in the store's key entries; keylib's PKCS#12 reader takes
    only the first key of each, its JKS reader both."""
    keys = []
    for kind, der in entries:
        if kind == "key":
            found = ours(der, "")
            keys.extend(found[:1] if first_only else found)
    return keys


def key_text(key):
    m, d, qx, qy = key
    width = (m + 7) // 8
    return f"{m}:{d:0{width * 2}x}:{qx:0{width * 2}x}:{qy:0{width * 2}x}"


def ski(der):
    """The subject key identifier, found by its OID: these certificates'
    authority key identifiers are malformed, so no strict parser takes
    them whole."""
    at = der.index(bytes.fromhex("0603551d0e"))
    inner = der.index(b"\x04\x20", at + 5)
    return der[inner + 2:inner + 34]


def refuses_another_password(tally, name, data, password):
    try:
        allcrypt.dstu4145_keys_open(data, (password + "x").encode())
        tally.check(False, name, "a wrong password was accepted")
    except Exception:
        tally.check(True, name)


class Tally:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
        else:
            self.failed += 1
            print(f"FAIL {what} {detail}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dstu-engine", required=True, help="dstu-engine's tests/")
    parser.add_argument("--jkurwa", required=True, help="jkurwa's test/data/")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    sources = {"dstu-engine": args.dstu_engine, "jkurwa": args.jkurwa}
    files = {}
    for (project, name), blob in BLOBS.items():
        with open(os.path.join(sources[project], name), "rb") as f:
            files[name] = f.read()
        if git_blob(files[name]) != blob:
            sys.exit(f"{project} {name}: not the file this script was written against")

    tally = Tally()
    lib_rows = []      # (file name, format, password, keys)
    lib_files = {}     # file name -> bytes, to record

    # They write, ours reads.
    for _, name, fmt, password in THEIRS:
        data = files[name]
        expected, _ = witness(fmt, data, password)
        got = ours(data, password)
        tally.check(got == expected, name, f"ours {got} keylib {expected}")
        if fmt != "pkcs8":
            refuses_another_password(tally, name, data, password)
        lib_rows.append((name, fmt, password, expected))
        lib_files[name] = data

    by_file = {name: allcrypt.dstu4145_keys_open(files[name], b"")
               for _, name in CERTIFICATES}
    for cert, key_file in CERTIFICATES:
        tally.check(by_file[key_file][0].key_id() == ski(files[cert]), cert)
        lib_files[cert] = files[cert]

    # Ours writes, keylib reads.
    curves = allcrypt.dstu4145_curves_available
    for i, curve in enumerate(curves):
        key = allcrypt.Dstu4145Key.generate(curve)
        second = allcrypt.Dstu4145Key.generate(curves[(i + 5) % 10]) if i % 2 == 0 else None
        expected = [numbers(key)] + ([numbers(second)] if second else [])
        bits = curve.rsplit("-", 1)[1]
        plain = key.private_key_info(second)
        made = [(f"ours-{bits}.der", "pkcs8", "", plain)]
        # Under a password; under one longer than HMAC-GOST 34.311's
        # 32-byte block, which HMAC hashes first; and under the empty one,
        # whose GOST 34.311 is of the empty message.
        sealed = {"dstu4145-m257": ("", PASSWORD), "dstu4145-m431": ("-long", PASSWORD * 4),
                  "dstu4145-m163": ("-empty", "")}
        if curve in sealed:
            suffix, password = sealed[curve]
            made.append((f"ours-{bits}-pbes2{suffix}.der", "pbes2", password,
                         allcrypt.encrypt_private_key(plain, password.encode(),
                                                      "gost28147-cfb")))
            made.append((f"ours-{bits}-key6{suffix}.dat", "key6", password,
                         allcrypt.dstu4145_key6(key, password.encode(), second)))
        for name, fmt, password, data in made:
            read, _ = witness(fmt, data, password)
            tally.check(read == expected, name, f"keylib {read} ours {expected}")
            tally.check(ours(data, password) == expected, name, "ours does not read it back")
            if fmt != "pkcs8":
                refuses_another_password(tally, name, data, password)
            lib_rows.append((name, fmt, password, expected))
            lib_files[name] = data

    # The key stores.
    store_rows = []    # (file name, password, key password, entries, keys)
    store_files = {}
    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for _, name, fmt, password, key_password in STORES:
            paths[name] = os.path.join(tmp, name)
            with open(paths[name], "wb") as f:
                f.write(files[name])
        made = [("ours-gost.p12", "key.jks", "pkcs12",
                 ["--key-scheme", "gost", "--cert-scheme", "gost", "--mac", "gost34311"]),
                ("ours-gost-from-pfx.p12", "Key-6.pfx", "pkcs12",
                 ["--key-scheme", "gost", "--cert-scheme", "gost", "--mac", "gost34311"]),
                ("ours.jks", "key.jks", "jks", []),
                ("ours-from-pfx.jks", "Key-6.pfx", "jks", [])]
        stores = [(name, fmt, password, key_password, files[name])
                  for _, name, fmt, password, key_password in STORES]
        for name, source, fmt, options in made:
            _, _, _, password, key_password = next(s for s in STORES if s[1] == source)
            paths[name] = os.path.join(tmp, name)
            keystore("convert", paths[source], paths[name], "--password", password,
                     "--key-password", key_password, "--out-password", PASSWORD,
                     "--format", fmt, *options)
            with open(paths[name], "rb") as f:
                stores.append((name, fmt, PASSWORD, PASSWORD, f.read()))
        for name, fmt, password, key_password, data in stores:
            keys, certs = witness(fmt, data, password,
                                  key_password if fmt == "jks" else None)
            entries = store_contents(paths[name], password, key_password)
            tally.check(store_keys(entries, fmt == "pkcs12") == keys, name,
                        f"keylib {keys}")
            ours_certs = sorted(hashlib.sha256(der).hexdigest()
                                for kind, der in entries if kind != "key")
            tally.check(ours_certs == sorted(certs), name, "certificates")
            try:
                keystore("list", paths[name], "--password", password + "x",
                         "--key-password", key_password + "x")
                tally.check(False, name, "a wrong password was accepted")
            except RuntimeError:
                tally.check(True, name)
            store_rows.append((name, password, key_password,
                               [f"{kind} {hashlib.sha256(der).hexdigest()}"
                                for kind, der in entries],
                               store_keys(entries, False)))
            store_files[name] = data

    print(f"{tally.passed} passed, {tally.failed} failed")
    if tally.failed:
        sys.exit(1)
    if args.record:
        record(lib_rows, lib_files, store_rows, store_files)


def password_hex(password):
    return password.encode().hex() if password else "-"


def record(lib_rows, lib_files, store_rows, store_files):
    for directory in (LIB_FIXTURES, STORE_FIXTURES):
        os.makedirs(directory, exist_ok=True)
        for name in os.listdir(directory):
            if name != "README.md":
                os.remove(os.path.join(directory, name))
    for name, data in lib_files.items():
        with open(os.path.join(LIB_FIXTURES, name), "wb") as f:
            f.write(data)
    with open(LIB_VEC, "w") as out:
        out.write("# DSTU 4145 keys in Ukrainian containers, as dstu-engine's keylib\n"
                  "# read them: the files in tests/keys/ua/, dstu-engine's, jkurwa's\n"
                  "# and ours. Written by scripts/check_ua_keys.py --record. Do not edit.\n"
                  "# format is key6, pbes2 (an encrypted PKCS#8) or pkcs8 (a plain\n"
                  "# one); password is hex, - for the empty one; each key is\n"
                  "# m:d:qx:qy, big-endian hex, d reduced mod n, the signing key\n"
                  "# first.\n"
                  f"# rows: {len(lib_rows)}\n")
        for name, fmt, password, keys in lib_rows:
            out.write(f"file={name} format={fmt} password={password_hex(password)} "
                      f"keys={','.join(key_text(k) for k in keys)}\n")
    for name, data in store_files.items():
        with open(os.path.join(STORE_FIXTURES, name), "wb") as f:
            f.write(data)
    with open(STORE_VEC, "w") as out:
        out.write("# Ukrainian key stores - dstu-engine's PKCS#12 and PrivatBank JKS,\n"
                  "# and ours converted from them - written by\n"
                  "# scripts/check_ua_keys.py --record: each entry's kind and the\n"
                  "# SHA-256 of its contents as ours read them, and each DSTU 4145 key\n"
                  "# in the key entries as m:d:qx:qy, after dstu-engine's keylib\n"
                  "# agreed on the keys and the certificates.\n"
                  "[store]\n")
        for name, password, key_password, entries, keys in store_rows:
            out.write(f"name = {name}\npassword = {password_hex(password)}\n"
                      f"key-password = {password_hex(key_password)}\n")
            for entry in entries:
                out.write(f"entry = {entry}\n")
            for key in keys:
                out.write(f"dstu = {key_text(key)}\n")
    print(f"recorded {len(lib_rows)} containers and {len(store_rows)} stores")


if __name__ == "__main__":
    main()
