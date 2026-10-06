#!/usr/bin/env python3
"""The CMS example (`examples/products/cms`) against OpenSSL 3.0 and 3.5,
python-cryptography and NSS's `cmsutil`, both directions.

  * **The OIDs**: every identifier `cms oids` prints is named by OpenSSL
    the way the example names it, except id-shake256-len, which OpenSSL
    does not know and which is checked against RFC 8419's module.
  * **They write, ours reads**: OpenSSL signs with RSA (PKCS#1 v1.5 and
    PSS), ECDSA on P-256 and P-384, DSA and - 3.5 only - Ed25519 and
    Ed448, attached and detached, with and without attributes, by key
    identifier, and as S/MIME, clear and opaque; it encrypts under every
    content cipher to RSA and EC recipients, with RSA-OAEP, every ECDH
    KDF and the cofactor variant, to a password, to a shared key, as
    EncryptedData and as AES-GCM AuthEnvelopedData. python-cryptography
    signs and encrypts what it can, NSS signs with RSA and ECDSA and
    encrypts to RSA. Ours verifies or decrypts each, byte for byte, and
    refuses the wrong key.
  * **Ours writes, they read**: every signature ours makes is verified by
    both OpenSSLs where they have the algorithm, and by NSS; everything
    ours encrypts is decrypted by OpenSSL, the RSA PKCS#1 v1.5 ones by
    python-cryptography and NSS too.

    python3 scripts/check_cms.py [--ours PATH] [--openssl35 DIR]
    python3 scripts/check_cms.py --record

`--record` keeps the keys and certificates it made and a set of the
witnesses' messages in `examples/products/fixtures/cms/`, listed in
`cms.vec`, for the offline tests.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example cms`.
"""

import argparse
import hashlib
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "cms")
OPENSSL35 = "/opt/openssl35"
LEGACY = ["-provider", "legacy", "-provider", "default"]

TEXT = b"".join(b"Line %d of a message, some of it signed and some sealed.\n" % i
                for i in range(12))
BINARY = bytes(random.Random(3).randrange(256) for _ in range(700))
PASSWORD = "correct horse battery staple"
KEK = "000102030405060708090a0b0c0d0e0f"
KEK_ID = "6b656b2d31"


def canonical(data):
    return re.sub(rb"(?<!\r)\n", b"\r\n", data)


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


class Env:
    def __init__(self, args, work):
        self.args = args
        self.work = work
        self.ssl30 = ["openssl"]
        lib = ":".join(os.path.join(args.openssl35, d) for d in ("lib64", "lib"))
        self.ssl35 = ["env", f"LD_LIBRARY_PATH={lib}", os.path.join(args.openssl35, "bin",
                                                                     "openssl")]
        self.keys = {}
        self.counter = 0

    def path(self, name):
        return os.path.join(self.work, name)

    def fresh(self, suffix):
        self.counter += 1
        return self.path(f"m{self.counter:03d}{suffix}")


def make_keys(env):
    """A CA and a leaf certificate for each key type, with subject key
    identifiers, made by OpenSSL 3.0."""
    ssl = env.ssl30
    ca_key, ca_crt = env.path("ca.key"), env.path("ca.crt")
    run(ssl + ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key,
               "-out", ca_crt, "-subj", "/CN=Example CA", "-days", "3650"], check=True)
    ext = env.path("ext.cnf")
    with open(ext, "w") as f:
        f.write("subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
                "keyUsage=digitalSignature,keyEncipherment,keyAgreement\n")
    specs = {
        "rsa": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "ec": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "ec384": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
        "ed25519": ["-algorithm", "ED25519"],
        "ed448": ["-algorithm", "ED448"],
    }
    params = env.path("dsa.params")
    run(ssl + ["genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", "dsa_paramgen_bits:2048",
               "-out", params], check=True)
    specs["dsa"] = ["-paramfile", params]
    for name, spec in specs.items():
        key, crt, csr = env.path(f"{name}.key"), env.path(f"{name}.crt"), env.path(f"{name}.csr")
        run(ssl + ["genpkey"] + spec + ["-out", key], check=True)
        run(ssl + ["req", "-new", "-key", key, "-subj", f"/CN={name} signer", "-out", csr],
            check=True)
        run(ssl + ["x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-days", "3650",
                   "-extfile", ext, "-out", crt], check=True)
        env.keys[name] = (key, crt)
    env.keys["ca"] = (ca_key, ca_crt)


def nss_db(env):
    db = env.path("nssdb")
    os.makedirs(db)
    run(["certutil", "-N", "-d", f"sql:{db}", "--empty-password"], check=True)
    for name in ("rsa", "ec"):
        key, crt = env.keys[name]
        p12 = env.path(f"{name}.p12")
        run(env.ssl30 + ["pkcs12", "-export", "-in", crt, "-inkey", key, "-out", p12,
                         "-passout", "pass:pw", "-name", name], check=True)
        run(["pk12util", "-i", p12, "-d", f"sql:{db}", "-W", "pw"], check=True)
    run(["certutil", "-A", "-d", f"sql:{db}", "-n", "ca", "-t", "CT,C,C", "-i",
         env.keys["ca"][1]], check=True)
    return f"sql:{db}"


def check_oids(env, tally):
    print("== object identifiers")
    listing = run([env.args.ours, "oids"])
    rows = [line.split(" ", 1) for line in listing.stdout.decode().splitlines()]
    tally.check(len(rows) > 70, f"ours lists {len(rows)} identifiers")
    for dotted, name in rows:
        named = run(env.ssl35 + ["asn1parse", "-genstr", f"OID:{dotted}"]).stdout.decode()
        theirs = named.rsplit(":", 1)[-1].strip()
        tally.check(theirs == name, f"{dotted} is {name}", f"OpenSSL calls it {theirs}")
    # id-shake256-len: RFC 8419's module, hashAlgs 18.
    text = open(os.path.join(ROOT, "rfcs", "rfc8419.txt")).read()
    arcs = re.search(r"hashalgs\s+OBJECT IDENTIFIER\s+::=\s+\{([^}]*)\}", text).group(1)
    base = ".".join(re.findall(r"\((\d+)\)", arcs) + [arcs.split()[-1]])
    last = re.search(r"id-shake256-len\s+OBJECT IDENTIFIER\s+::=\s+\{\s*hashAlgs\s+(\d+)",
                     text).group(1)
    source = open(os.path.join(ROOT, "examples", "products", "cms", "asn.rs")).read()
    ours = re.search(r'SHAKE256_LEN: &str = "([0-9.]+)"', source).group(1)
    tally.check(ours == f"{base}.{last}", f"id-shake256-len is {base}.{last} (RFC 8419)",
                f"ours is {ours}")


# --------------------------------------------------------- they write, ours reads --

def openssl_signed(env):
    """(label, path, form, detached-content, expected, extra) for OpenSSL's
    signatures."""
    out = []
    text, binary = env.path("text.txt"), env.path("binary.bin")
    for ssl, which in ((env.ssl30, "3.0"), (env.ssl35, "3.5")):
        names = ["rsa", "ec", "ec384", "dsa"] + (["ed25519", "ed448"] if which == "3.5" else [])
        for name in names:
            key, crt = env.keys[name]
            md = {"ed25519": "sha512", "ed448": "shake256"}.get(name)
            mdargs = ["-md", md] if md else []
            cases = [("attached", ["-nodetach", "-binary", "-outform", "DER"], binary, None),
                     ("detached", ["-binary", "-outform", "DER"], binary, binary),
                     ("S/MIME clear", [], text, None),
                     ("S/MIME opaque", ["-nodetach"], text, None)]
            if name != "ed448":
                cases.append(("no attributes", ["-nodetach", "-binary", "-outform", "DER",
                                                "-noattr"], binary, None))
            if name in ("rsa", "ec"):
                cases.append(("key id", ["-nodetach", "-binary", "-outform", "DER", "-keyid"],
                              binary, None))
                for md2 in ("sha1", "sha384", "sha512"):
                    cases.append((md2, ["-nodetach", "-binary", "-outform", "DER", "-md", md2],
                                  binary, None))
            if name == "rsa":
                cases.append(("PSS", ["-nodetach", "-binary", "-outform", "DER", "-keyopt",
                                      "rsa_padding_mode:pss"], binary, None))
            for label, options, source, detached in cases:
                path = env.fresh(".p7")
                made = run(ssl + ["cms", "-sign", "-in", source, "-signer", crt, "-inkey", key,
                                  "-out", path] + options + mdargs)
                if made.returncode:
                    print(f"     (OpenSSL {which} could not sign {name} {label}: "
                          f"{made.stderr[:200]!r})")
                    continue
                expected = open(source, "rb").read()
                if source == text and "-binary" not in options:
                    expected = canonical(expected)
                out.append((f"OpenSSL {which} {name} {label}", path, detached, expected,
                            ["--allow-weak"] if "sha1" in label else []))
    return out


def python_signed(env):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7
    out = []
    data = open(env.path("binary.bin"), "rb").read()
    for name in ("rsa", "ec", "ec384"):
        key_path, crt_path = env.keys[name]
        key = serialization.load_pem_private_key(open(key_path, "rb").read(), None)
        cert = x509.load_pem_x509_certificate(open(crt_path, "rb").read())
        for hash_name, hash_ in (("sha256", hashes.SHA256()), ("sha512", hashes.SHA512())):
            for label, options, encoding in (
                    ("attached", [pkcs7.PKCS7Options.Binary], serialization.Encoding.DER),
                    ("detached", [pkcs7.PKCS7Options.Binary,
                                  pkcs7.PKCS7Options.DetachedSignature],
                     serialization.Encoding.DER),
                    ("no attributes", [pkcs7.PKCS7Options.Binary,
                                       pkcs7.PKCS7Options.NoAttributes],
                     serialization.Encoding.DER),
                    ("PEM", [pkcs7.PKCS7Options.Binary], serialization.Encoding.PEM),
                    ("S/MIME", [pkcs7.PKCS7Options.Binary,
                                pkcs7.PKCS7Options.DetachedSignature],
                     serialization.Encoding.SMIME)):
                signed = pkcs7.PKCS7SignatureBuilder().set_data(data) \
                    .add_signer(cert, key, hash_).sign(encoding, options)
                path = env.fresh(".p7")
                open(path, "wb").write(signed)
                detached = env.path("binary.bin") if label == "detached" else None
                out.append((f"python-cryptography {name} {hash_name} {label}", path, detached,
                            data, []))
    return out


def nss_signed(env, db):
    out = []
    for name in ("rsa", "ec"):
        for label, options in (("with time and capabilities", ["-G", "-P"]),
                               ("plain", []), ("detached", ["-T"])):
            path = env.fresh(".p7")
            made = run(["cmsutil", "-S", "-N", name, "-i", env.path("binary.bin"), "-o", path,
                        "-d", db, "-u", "0"] + options)
            if made.returncode:
                print(f"     (NSS could not sign {name} {label}: {made.stderr[:200]!r})")
                continue
            detached = env.path("binary.bin") if label == "detached" else None
            out.append((f"NSS {name} {label}", path, detached,
                        open(env.path("binary.bin"), "rb").read(), []))
    return out


def ours_verifies(env, tally, messages):
    ca = env.keys["ca"][1]
    for label, path, detached, expected, extra in messages:
        out = env.fresh(".out")
        command = [env.args.ours, "verify", path, out, "--roots", ca] + extra
        if detached:
            command += ["--content", detached]
        result = run(command)
        got = open(out, "rb").read() if os.path.exists(out) else b""
        tally.check(result.returncode == 0 and got == expected, f"ours verifies {label}",
                    result.stderr + result.stdout)


def openssl_enveloped(env):
    """(label, path, credentials) for OpenSSL's encryptions."""
    out = []
    binary = env.path("binary.bin")
    ciphers = ["aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "des-ede3-cbc", "aes-128-gcm",
               "aes-256-gcm"]
    for ssl, which in ((env.ssl30, "3.0"), (env.ssl35, "3.5")):
        legacy = LEGACY if which == "3.0" else []
        def add(label, options, creds, tail=()):
            path = env.fresh(".p7")
            made = run(ssl + ["cms", "-encrypt", "-in", binary, "-out", path, "-outform", "DER",
                              "-binary"] + legacy + options + list(tail))
            if made.returncode:
                print(f"     (OpenSSL {which} could not encrypt {label}: {made.stderr[:200]!r})")
                return
            out.append((f"OpenSSL {which} {label}", path, creds))
        for name in ("rsa", "ec", "ec384"):
            key, crt = env.keys[name]
            for cipher in ciphers:
                add(f"{cipher} to {name}", [f"-{cipher}"], {"key": name}, [crt])
        for cipher in ("des-cbc", "rc2-40-cbc", "rc2-64-cbc", "rc2-cbc"):
            if which == "3.0":
                add(f"{cipher} to rsa", [f"-{cipher}"], {"key": "rsa"}, [env.keys["rsa"][1]])
        rsa = env.keys["rsa"][1]
        for md in ("sha1", "sha256", "sha512"):
            add(f"RSA-OAEP {md}", ["-aes-256-cbc", "-recip", rsa, "-keyopt",
                                   "rsa_padding_mode:oaep", "-keyopt", f"rsa_oaep_md:{md}"],
                {"key": "rsa"})
        for md in ("sha1", "sha224", "sha256", "sha384", "sha512"):
            add(f"ECDH KDF {md}", ["-aes-256-cbc", "-recip", env.keys["ec"][1], "-keyopt",
                                   f"ecdh_kdf_md:{md}"], {"key": "ec"})
        add("ECDH cofactor", ["-aes-128-cbc", "-recip", env.keys["ec"][1], "-keyopt",
                              "ecdh_cofactor_mode:1"], {"key": "ec"})
        add("two recipients by key id", ["-aes-256-cbc", "-keyid"], {"key": "ec"},
            [rsa, env.keys["ec"][1]])
        add("password", ["-aes-256-cbc", "-pwri_password", PASSWORD], {"password": PASSWORD})
        add("password 3DES", ["-des-ede3-cbc", "-pwri_password", PASSWORD],
            {"password": PASSWORD})
        if which == "3.0":
            # An RC2 KEK, whose key length OpenSSL takes from the effective
            # bits rather than writing it into PBKDF2's parameters.
            for cipher in ("rc2-40-cbc", "rc2-64-cbc"):
                add(f"password {cipher}", [f"-{cipher}", "-pwri_password", PASSWORD],
                    {"password": PASSWORD})
        for bits, kek in ((128, KEK), (192, KEK + "1011121314151617"),
                          (256, KEK + "101112131415161718191a1b1c1d1e1f")):
            add(f"shared key AES-{bits}", ["-aes-128-cbc", "-secretkey", kek, "-secretkeyid",
                                           KEK_ID], {"kek": kek})
        path = env.fresh(".p7")
        made = run(ssl + ["cms", "-EncryptedData_encrypt", "-in", binary, "-out", path,
                          "-outform", "DER", "-binary", "-aes-128-cbc", "-secretkey", KEK])
        if made.returncode == 0:
            out.append((f"OpenSSL {which} EncryptedData", path, {"secret": KEK}))
        path = env.fresh(".p7")
        made = run(ssl + ["cms", "-encrypt", "-in", env.path("text.txt"), "-out", path,
                          "-aes-256-cbc", env.keys["ec"][1]])
        if made.returncode == 0:
            out.append((f"OpenSSL {which} S/MIME to ec", path, {"key": "ec", "text": True}))
    return out


def python_enveloped(env):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.serialization import pkcs7
    out = []
    data = open(env.path("binary.bin"), "rb").read()
    cert = x509.load_pem_x509_certificate(open(env.keys["rsa"][1], "rb").read())
    for name, algorithm in (("AES-128", algorithms.AES128), ("AES-256", algorithms.AES256)):
        for encoding in (serialization.Encoding.DER, serialization.Encoding.PEM,
                         serialization.Encoding.SMIME):
            sealed = pkcs7.PKCS7EnvelopeBuilder().set_data(data).add_recipient(cert) \
                .set_content_encryption_algorithm(algorithm) \
                .encrypt(encoding, [pkcs7.PKCS7Options.Binary])
            path = env.fresh(".p7")
            open(path, "wb").write(sealed)
            out.append((f"python-cryptography {name} {encoding.name}", path, {"key": "rsa"}))
    return out


def nss_enveloped(env, db):
    path = env.fresh(".p7")
    made = run(["cmsutil", "-E", "-r", "rsa", "-i", env.path("binary.bin"), "-o", path,
                "-d", db])
    return [("NSS to rsa", path, {"key": "rsa"})] if made.returncode == 0 else []


def credential_args(env, creds):
    if "key" in creds:
        key, crt = env.keys[creds["key"]]
        return ["--key", key, "--cert", crt]
    if "password" in creds:
        return ["--password", creds["password"]]
    if "kek" in creds:
        return ["--kek-id", KEK_ID, "--kek", creds["kek"]]
    return ["--secret-key", creds["secret"]]


def wrong_args(env, creds):
    if "key" in creds:
        other = "ec384" if creds["key"] == "ec" else "rsa" if creds["key"] != "rsa" else "ec"
        key, crt = env.keys[other]
        return ["--key", key]
    if "password" in creds:
        return ["--password", creds["password"] + "!"]
    if "kek" in creds:
        return ["--kek-id", KEK_ID, "--kek", "ff" + creds["kek"][2:]]
    return ["--secret-key", "ff" + creds["secret"][2:]]


def ours_decrypts(env, tally, messages):
    for label, path, creds in messages:
        out = env.fresh(".out")
        result = run([env.args.ours, "decrypt", path, out] + credential_args(env, creds))
        source = env.path("text.txt") if creds.get("text") else env.path("binary.bin")
        expected = open(source, "rb").read()
        got = open(out, "rb").read() if os.path.exists(out) else b""
        if creds.get("text"):
            got, expected = canonical(got), canonical(expected)
        tally.check(result.returncode == 0 and got == expected, f"ours decrypts {label}",
                    result.stderr)
        wrong = run([env.args.ours, "decrypt", path, env.fresh(".out")] +
                    wrong_args(env, creds))
        tally.check(wrong.returncode != 0 and b"panicked" not in wrong.stderr,
                    f"  ours refuses {label} under the wrong key", wrong.stderr)


# --------------------------------------------------------- ours writes, they read --

def ours_signs(env, tally, db):
    print("== ours signs, they verify")
    binary, text = env.path("binary.bin"), env.path("text.txt")
    ca = env.keys["ca"][1]
    for name in ("rsa", "ec", "ec384", "dsa", "ed25519", "ed448"):
        key, crt = env.keys[name]
        cases = [("attached", [], binary), ("detached", ["--detached"], binary),
                 ("no attributes", ["--no-attributes"], binary), ("key id", ["--keyid"], binary),
                 ("S/MIME clear", ["--smime", "--detached"], text),
                 ("S/MIME opaque", ["--smime"], text), ("PEM", ["--pem"], binary)]
        if name in ("rsa", "ec", "ec384"):
            cases += [("sha384", ["--hash", "sha384"], binary),
                      ("sha512", ["--hash", "sha512"], binary)]
        if name == "rsa":
            cases += [("PSS", ["--pss"], binary), ("PSS sha512", ["--pss", "--hash", "sha512"],
                                                   binary)]
        for label, options, source in cases:
            path = env.fresh(".p7")
            made = run([env.args.ours, "sign", source, path, "--signer", crt, key] + options)
            if made.returncode:
                tally.check(False, f"ours signs {name} {label}", made.stderr)
                continue
            expected = open(source, "rb").read()
            smime = "--smime" in options
            if smime and "--detached" in options:
                expected = canonical(expected)
            form = [] if smime else ["-inform", "PEM" if "--pem" in options else "DER"]
            detached = ["-content", source] if "--detached" in options and not smime else []
            # OpenSSL 3.0 has no EdDSA in CMS; neither knows RFC 8419's
            # id-shake256-len, which Ed448 with attributes uses; 3.5
            # cannot verify Ed448 without them either.
            witnesses = [("OpenSSL 3.0", env.ssl30), ("OpenSSL 3.5", env.ssl35)]
            if name.startswith("ed"):
                no_attrs = "--no-attributes" in options
                witnesses = [] if name == "ed448" or no_attrs else [("OpenSSL 3.5", env.ssl35)]
            for witness, ssl in witnesses:
                out = env.fresh(".out")
                # A clear-signed message is verified the way it was meant:
                # canonicalised. OpenSSL's -binary reading of one keeps the
                # CR of the CRLF that RFC 2046 gives to the delimiter.
                binary_flag = [] if smime and "--detached" in options else ["-binary"]
                result = run(ssl + ["cms", "-verify", "-in", path, "-CAfile", ca, "-out", out]
                             + binary_flag + form + detached)
                got = open(out, "rb").read() if os.path.exists(out) else b""
                if smime:
                    got, expected_here = canonical(got), canonical(expected)
                else:
                    expected_here = expected
                tally.check(result.returncode == 0 and got == expected_here,
                            f"ours signs {name} {label}, {witness} verifies", result.stderr)
            if name in ("rsa", "ec") and not smime and "--pem" not in options:
                nss = ["cmsutil", "-D", "-i", path, "-d", db, "-u", "0", "-h", "1"]
                if "--detached" in options:
                    nss += ["-c", source]
                result = run(nss)
                tally.check(b"GoodSignature" in result.stdout and expected in result.stdout,
                            f"ours signs {name} {label}, NSS verifies",
                            result.stdout[:300] + result.stderr)
            if name == "ed448" or (name == "ed25519" and "--no-attributes" in options):
                content = ["--content", source] if "--detached" in options and not smime \
                    else []
                result = run([env.args.ours, "verify", path, env.fresh(".out"), "--roots", ca]
                             + content)
                tally.check(result.returncode == 0, f"ours signs {name} {label}, ours verifies",
                            result.stderr)


def ours_encrypts(env, tally, db):
    print("== ours encrypts, they decrypt")
    binary = env.path("binary.bin")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs7
    rsa_cert = x509.load_pem_x509_certificate(open(env.keys["rsa"][1], "rb").read())
    rsa_key = serialization.load_pem_private_key(open(env.keys["rsa"][0], "rb").read(), None)
    expected = open(binary, "rb").read()
    ciphers = ["aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "des-ede3-cbc", "des-cbc",
               "rc2-40-cbc", "rc2-64-cbc", "rc2-128-cbc", "aes-128-gcm", "aes-192-gcm",
               "aes-256-gcm"]
    cases = []
    for cipher in ciphers:
        cases.append((f"{cipher} to rsa", ["--recipient", env.keys["rsa"][1], "--cipher", cipher],
                      {"key": "rsa"}))
        if not cipher.startswith(("des-cbc", "rc2-40", "rc2-64")):
            for name in ("ec", "ec384"):
                cases.append((f"{cipher} to {name}", ["--recipient", env.keys[name][1],
                                                      "--cipher", cipher], {"key": name}))
        cases.append((f"{cipher} to a password", ["--password", PASSWORD, "--iterations",
                                                  "2000", "--cipher", cipher],
                      {"password": PASSWORD}))
    for md in ("sha1", "sha256", "sha512"):
        cases.append((f"RSA-OAEP {md}", ["--recipient", env.keys["rsa"][1], "--oaep", md],
                      {"key": "rsa"}))
    for md in ("sha1", "sha224", "sha384", "sha512"):
        cases.append((f"ECDH KDF {md}", ["--recipient", env.keys["ec"][1], "--kdf-hash", md],
                      {"key": "ec"}))
    cases.append(("key id", ["--recipient", env.keys["rsa"][1], "--recipient",
                             env.keys["ec"][1], "--keyid"], {"key": "ec"}))
    for kek in (KEK, KEK + "1011121314151617", KEK + "101112131415161718191a1b1c1d1e1f"):
        cases.append((f"shared key AES-{len(kek) * 4}", ["--kek-id", KEK_ID, "--kek", kek],
                      {"kek": kek}))
    cases.append(("EncryptedData", ["--secret-key", KEK, "--cipher", "aes-128-cbc"],
                  {"secret": KEK}))
    cases.append(("S/MIME to rsa", ["--recipient", env.keys["rsa"][1], "--smime"],
                  {"key": "rsa", "smime": True}))
    for label, options, creds in cases:
        path = env.fresh(".p7")
        made = run([env.args.ours, "encrypt", binary, path] + options)
        if made.returncode:
            tally.check(False, f"ours encrypts {label}", made.stderr)
            continue
        form = [] if creds.get("smime") else ["-inform", "DER"]
        if "key" in creds:
            key, crt = env.keys[creds["key"]]
            how = ["-decrypt", "-inkey", key, "-recip", crt]
        elif "password" in creds:
            how = ["-decrypt", "-pwri_password", creds["password"]]
        elif "kek" in creds:
            how = ["-decrypt", "-secretkey", creds["kek"], "-secretkeyid", KEK_ID]
        else:
            how = ["-EncryptedData_decrypt", "-secretkey", creds["secret"]]
        for witness, ssl, legacy in (("OpenSSL 3.0", env.ssl30, LEGACY),
                                     ("OpenSSL 3.5", env.ssl35, [])):
            if witness == "OpenSSL 3.5" and any(c in label for c in ("des-cbc", "rc2")):
                continue
            out = env.fresh(".out")
            result = run(ssl + ["cms", "-in", path, "-out", out, "-binary"] + form + how +
                         legacy)
            got = open(out, "rb").read() if os.path.exists(out) else b""
            tally.check(result.returncode == 0 and got == expected,
                        f"ours encrypts {label}, {witness} decrypts", result.stderr)
        plain_rsa = creds.get("key") == "rsa" and "OAEP" not in label and \
            label.endswith("to rsa") and label.split()[0] in ("aes-128-cbc", "aes-256-cbc")
        if plain_rsa:
            try:
                got = pkcs7.pkcs7_decrypt_der(open(path, "rb").read(), rsa_cert, rsa_key, [])
                tally.check(got == expected, f"ours encrypts {label}, python-cryptography "
                                             "decrypts")
            except Exception as error:
                tally.check(False, f"ours encrypts {label}, python-cryptography decrypts",
                            str(error))
        if creds.get("key") == "rsa" and "OAEP" not in label and "gcm" not in label \
                and not creds.get("smime"):
            result = run(["cmsutil", "-D", "-i", path, "-d", db])
            tally.check(result.returncode == 0 and result.stdout == expected,
                        f"ours encrypts {label}, NSS decrypts", result.stderr)


# ---------------------------------------------------------------------- driver --

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--openssl35", default=OPENSSL35)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    tally = Tally()
    work = tempfile.mkdtemp()
    env = Env(args, work)
    open(env.path("text.txt"), "wb").write(TEXT)
    open(env.path("binary.bin"), "wb").write(BINARY)
    make_keys(env)
    db = nss_db(env)
    check_oids(env, tally)

    print("== they sign, ours verifies")
    signed = openssl_signed(env) + python_signed(env) + nss_signed(env, db)
    ours_verifies(env, tally, signed)
    print("== they encrypt, ours decrypts")
    sealed = openssl_enveloped(env) + python_enveloped(env) + nss_enveloped(env, db)
    ours_decrypts(env, tally, sealed)
    ours_signs(env, tally, db)
    ours_encrypts(env, tally, db)

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    if args.record and not tally.failed:
        record(env, signed, sealed)
    shutil.rmtree(work)
    return 1 if tally.failed else 0


def record(env, signed, sealed):
    # OpenSSL 3.5 is recorded only for what 3.0 cannot do: the rest is
    # the same code, and checked live.
    def kept(label):
        return not label.startswith("OpenSSL 3.5") or "ed25519" in label or "ed448" in label
    signed = [m for m in signed if kept(m[0])]
    sealed = [m for m in sealed if kept(m[0])]
    directory = os.path.join(FIXTURES, "cms")
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)
    for name, (key, crt) in env.keys.items():
        if name != "ca":
            shutil.copy(key, os.path.join(directory, f"{name}.key"))
        shutil.copy(crt, os.path.join(directory, f"{name}.crt"))
    shutil.copy(env.path("text.txt"), os.path.join(directory, "text.txt"))
    shutil.copy(env.path("binary.bin"), os.path.join(directory, "binary.bin"))
    lines = ["# Messages the witnesses wrote, kept by scripts/check_cms.py --record.",
             "# The keys and certificates are the ones they were made for; ca.crt",
             "# issued every certificate. `expect` is the file the content must equal,",
             "# compared in canonical form (CRLF) when `canonical` is yes.",
             f"# The password is {PASSWORD.encode().hex()} (hex of its UTF-8), the",
             f"# shared key's id is {KEK_ID}.", "", "[signed]"]
    for i, (label, path, detached, expected, extra) in enumerate(signed):
        name = f"signed-{i:03d}.p7"
        shutil.copy(path, os.path.join(directory, name))
        lines += [f"name = {name}", f"made_by = {label}",
                  f"detached = {'binary.bin' if detached else 'no'}",
                  f"expect = {'text.txt' if expected != BINARY else 'binary.bin'}",
                  f"canonical = {'yes' if expected not in (BINARY, TEXT) else 'no'}",
                  f"weak = {'yes' if extra else 'no'}"]
    lines += ["", "[sealed]"]
    for i, (label, path, creds) in enumerate(sealed):
        name = f"sealed-{i:03d}.p7"
        shutil.copy(path, os.path.join(directory, name))
        how = next(f"{k} = {v}" for k, v in creds.items() if k in ("key", "kek", "secret")) \
            if "password" not in creds else "password = yes"
        lines += [f"name = {name}", f"made_by = {label}", how,
                  f"expect = {'text.txt' if creds.get('text') else 'binary.bin'}"]
    with open(os.path.join(FIXTURES, "cms.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    print(f"{len(signed) + len(sealed)} messages -> {directory}")


if __name__ == "__main__":
    sys.exit(main())
