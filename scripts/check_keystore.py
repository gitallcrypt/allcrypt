#!/usr/bin/env python3
"""The key store example (`examples/products/keystore`) against OpenSSL,
Java's keytool, NSS's pk12util and python-cryptography, both directions.

Keys - RSA, EC on P-256 and P-384, Ed25519, DSA - and self-signed
certificates come from `openssl`. A key is compared by its private
numbers, through python-cryptography, because every tool re-encodes the
PKCS#8 it hands out; a certificate byte for byte.

  * **They write, ours reads**: OpenSSL 3.0 and 3.5 under every
    `-keypbe`/`-certpbe` it has - AES-256, 3DES, 40-bit RC2, none - with
    HMAC-SHA-1, HMAC-SHA-256 and no MAC, and 3.5's PBMAC1;
    python-cryptography under both its schemes; NSS's `pk12util`; and
    keytool's JKS, JCEKS and PKCS#12, with private keys, trusted
    certificates and secret keys. Ours must list every key and
    certificate the writer was given, and refuse a wrong password.
  * **Ours writes, they read**: PKCS#12 under each key scheme, each
    certificate scheme and each MAC, read by OpenSSL 3.0 (and 3.5 for
    PBMAC1), python-cryptography and keytool; JKS and JCEKS read by
    keytool, which then converts them to PKCS#12 for OpenSSL to show
    the keys.
  * Secret keys: keytool converts its JCEKS to PKCS#12 and back, and
    ours must find the same key in every form.

    python3 scripts/check_keystore.py
    python3 scripts/check_keystore.py --record

`--record` keeps a set of the witnesses' stores, with what each holds,
in `examples/products/fixtures/keystore/` for the offline tests.

**A development tool, not a test.** Build ours first:
`cargo build --release --example keystore`.
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "keystore")
OPENSSL35 = "/opt/openssl35/bin/openssl"
PASSWORD = "store pässword"
# keytool and JCEKS take ASCII; a separate password for those.
JAVA_PASSWORD = "store password"
# JCEKS seals keys with 200,000 iterations by default, which the
# offline tests then pay for in a debug build; 10,000 is the JDK's floor.
KEYTOOL = ["keytool", "-J-Djdk.jceks.iterationCount=10000"]

KEYS = [("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
        ("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
        ("p384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]),
        ("ed25519", ["-algorithm", "ED25519"]),
        ("dsa", ["-paramfile", "{dsaparam}"])]


def run(command, check=True, **kwargs):
    env = dict(os.environ)
    env["JAVA_TOOL_OPTIONS"] = ""
    if command[0] == OPENSSL35:
        env["LD_LIBRARY_PATH"] = "/opt/openssl35/lib"
    result = subprocess.run(command, capture_output=True, env=env, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(command[:3])}: "
                           + (result.stderr or result.stdout).decode(errors="replace")[:500])
    return result


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
                print("     " + str(detail).strip()[:800].replace("\n", "\n     "))


def key_identity(der_or_pem):
    """A private key's identity: its numbers, whatever the encoding."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
    if der_or_pem.startswith(b"-----"):
        key = serialization.load_pem_private_key(der_or_pem, None)
    else:
        key = serialization.load_der_private_key(der_or_pem, None)
    if isinstance(key, rsa.RSAPrivateKey):
        return ("rsa", key.private_numbers().d)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return ("ec", key.curve.name, key.private_numbers().private_value)
    if isinstance(key, dsa.DSAPrivateKey):
        return ("dsa", key.private_numbers().x)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return ("ed25519", key.private_bytes_raw())
    return (type(key).__name__,)


def pem_der(pem):
    import base64
    body = b"".join(line for line in pem.splitlines() if line and not line.startswith(b"-----"))
    return base64.b64decode(body)


def ours_list(args, path, password, key_password=None):
    command = [args.ours, "list", path, "--password-stdin", "--canonical"]
    if key_password:
        command += ["--key-password", key_password]
    result = run(command, check=False, input=(password + "\n").encode())
    if result.returncode:
        return None, result.stderr.decode(errors="replace")
    entries = []
    for line in result.stdout.decode().splitlines():
        parts = line.split(" ")
        kind = parts[0]
        if kind in ("key", "cert", "chain"):
            data = bytes.fromhex(parts[-1])
            ident = key_identity(data) if kind == "key" else hashlib.sha256(data).hexdigest()
            entries.append((kind if kind != "chain" else "cert", parts[1], ident))
        elif kind == "secret":
            entries.append(("secret", parts[1], parts[-1]))
    return entries, ""


def openssl_contents(openssl, path, password, legacy=False):
    """What OpenSSL finds in a PKCS#12: keys and certificates, with
    their friendly names. `legacy` loads the provider OpenSSL 3 keeps
    RC2 in."""
    result = run([openssl, "pkcs12", "-in", path, "-passin", f"pass:{password}", "-nodes",
                  *(["-legacy"] if legacy else [])], check=False)
    if result.returncode:
        return None, result.stderr.decode(errors="replace")
    out = []
    name = "-"
    for block in re.split(rb"(?=Bag Attributes)", result.stdout):
        m = re.search(rb"friendlyName: (.*)", block)
        name = m.group(1).decode().strip() if m else "-"
        for pem in re.findall(rb"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", block, re.S):
            if b"PRIVATE KEY" in pem:
                out.append(("key", name, key_identity(pem)))
            elif b"CERTIFICATE" in pem:
                out.append(("cert", name, hashlib.sha256(pem_der(pem)).hexdigest()))
    return out, ""


def openssl_null_password(key_pem, cert_pem, out, nid_key, nid_cert):
    """A PKCS#12 from OpenSSL's API with a NULL password, through
    ctypes: the `openssl` command passes an empty string instead, which
    hashes differently. Nids 0 are OpenSSL 3's defaults; 146 and 149 are
    PBE-SHA1-3DES and PBE-SHA1-RC2-40, which need the legacy provider."""
    import ctypes
    lib = ctypes.CDLL("libcrypto.so.3")
    p = ctypes.c_void_p
    for name, restype, argtypes in [
            ("OSSL_PROVIDER_load", p, [p, ctypes.c_char_p]),
            ("BIO_new_file", p, [ctypes.c_char_p, ctypes.c_char_p]),
            ("BIO_free", ctypes.c_int, [p]),
            ("PEM_read_bio_PrivateKey", p, [p] * 4),
            ("PEM_read_bio_X509", p, [p] * 4),
            ("PKCS12_create", p, [ctypes.c_char_p, ctypes.c_char_p, p, p, p] + [ctypes.c_int] * 5),
            ("i2d_PKCS12_bio", ctypes.c_int, [p, p])]:
        getattr(lib, name).restype = restype
        getattr(lib, name).argtypes = argtypes
    if not (lib.OSSL_PROVIDER_load(None, b"legacy") and lib.OSSL_PROVIDER_load(None, b"default")):
        raise RuntimeError("OpenSSL's legacy provider")

    def read(path, reader):
        bio = lib.BIO_new_file(path.encode(), b"r")
        try:
            return reader(bio, None, None, None)
        finally:
            lib.BIO_free(bio)
    pkey = read(key_pem, lib.PEM_read_bio_PrivateKey)
    cert = read(cert_pem, lib.PEM_read_bio_X509)
    p12 = lib.PKCS12_create(None, b"rsa", pkey, cert, None, nid_key, nid_cert, 0, 0, 0)
    if not (pkey and cert and p12):
        raise RuntimeError("PKCS12_create with a NULL password")
    bio = lib.BIO_new_file(out.encode(), b"wb")
    try:
        if lib.i2d_PKCS12_bio(bio, p12) != 1:
            raise RuntimeError("i2d_PKCS12_bio")
    finally:
        lib.BIO_free(bio)


def same(found, expected):
    """The same entries, whatever their order and names."""
    def strip(entries):
        return sorted((kind, str(ident)) for kind, _, ident in entries)
    return found is not None and strip(found) == strip(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    tally = Tally()
    work = tempfile.mkdtemp()
    recorded = []

    def path(name):
        return os.path.join(work, name)

    # The material: a key and a self-signed certificate of each kind.
    material = {}
    # OpenSSL 3.0's genpkey cannot take DSA parameter options and a key
    # in one step; the parameters come first.
    run(["openssl", "genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt",
         "dsa_paramgen_bits:2048", "-out", path("dsa.param")])
    for name, options in KEYS:
        options = [o.replace("{dsaparam}", path("dsa.param")) for o in options]
        run(["openssl", "genpkey", *options, "-out", path(f"{name}.key")])
        run(["openssl", "req", "-x509", "-new", "-key", path(f"{name}.key"), "-subj",
             f"/CN={name}", "-days", "30", "-out", path(f"{name}.crt")])
        with open(path(f"{name}.key"), "rb") as f:
            key = key_identity(f.read())
        with open(path(f"{name}.crt"), "rb") as f:
            cert = hashlib.sha256(pem_der(f.read())).hexdigest()
        material[name] = (key, cert)

    def expect(names):
        return ([("key", n, material[n][0]) for n in names]
                + [("cert", n, material[n][1]) for n in names])

    print("== OpenSSL writes PKCS#12, ours reads")
    openssl_cases = [("aes", ["-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC"]),
                     ("3des-sha1", ["-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES",
                                    "-macalg", "sha1"]),
                     ("legacy", ["-legacy"]),
                     ("none", ["-keypbe", "NONE", "-certpbe", "NONE"]),
                     ("nomac", ["-nomac"]),
                     ("iter1", ["-iter", "1", "-maciter"])]
    for label, options in openssl_cases:
        for name in ("rsa", "p256", "ed25519"):
            out = path(f"openssl-{label}-{name}.p12")
            run(["openssl", "pkcs12", "-export", "-inkey", path(f"{name}.key"), "-in",
                 path(f"{name}.crt"), "-name", name, "-passout", f"pass:{PASSWORD}", *options,
                 "-out", out])
            found, error = ours_list(args, out, PASSWORD)
            tally.check(same(found, expect([name])), f"openssl {label} {name}", error or found)
            wrong, _ = ours_list(args, out, "not the password")
            if label not in ("none", "nomac"):
                tally.check(wrong is None, f"  openssl {label} {name}: a wrong password refused")
            if found is not None and name == "rsa":
                recorded.append((f"openssl-{label}", out, PASSWORD, None, found))
    # The empty password: RFC 7292's BMPString of it is the two-byte NUL
    # terminator, which is what the command line hashes.
    for label, options in [("empty-aes", ["-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC"]),
                           ("empty-legacy", ["-legacy"])]:
        out = path(f"openssl-{label}.p12")
        run(["openssl", "pkcs12", "-export", "-inkey", path("rsa.key"), "-in", path("rsa.crt"),
             "-name", "rsa", "-passout", "pass:", *options, "-out", out])
        found, error = ours_list(args, out, "")
        tally.check(same(found, expect(["rsa"])), f"openssl {label}", error or found)
        wrong, _ = ours_list(args, out, "not the password")
        tally.check(wrong is None, f"  openssl {label}: a wrong password refused")
        if found is not None:
            recorded.append((f"openssl-{label}", out, "", None, found))
    # OpenSSL's API with a NULL password hashes no bytes at all for the
    # MAC, where the command line's empty string is the NUL terminator.
    for label, nids in [("null", (0, 0)), ("null-legacy", (146, 149))]:
        out = path(f"openssl-{label}.p12")
        openssl_null_password(path("rsa.key"), path("rsa.crt"), out, *nids)
        found, error = ours_list(args, out, "")
        tally.check(same(found, expect(["rsa"])), f"openssl API {label}", error or found)
        wrong, _ = ours_list(args, out, "not the password")
        tally.check(wrong is None, f"  openssl API {label}: a wrong password refused")
        if found is not None:
            recorded.append((f"openssl-{label}", out, "", None, found))
    for label, options in [("pbmac1", ["-pbmac1_pbkdf2"]),
                           ("pbmac1-sha512", ["-pbmac1_pbkdf2", "-pbmac1_pbkdf2_md", "sha512"])]:
        out = path(f"openssl35-{label}.p12")
        run([OPENSSL35, "pkcs12", "-export", "-inkey", path("p384.key"), "-in", path("p384.crt"),
             "-name", "p384", "-passout", f"pass:{PASSWORD}", *options, "-out", out])
        found, error = ours_list(args, out, PASSWORD)
        tally.check(same(found, expect(["p384"])), f"openssl 3.5 {label}", error or found)
        wrong, _ = ours_list(args, out, "not the password")
        tally.check(wrong is None, f"  openssl 3.5 {label}: a wrong password refused")
        if found is not None:
            recorded.append((f"openssl35-{label}", out, PASSWORD, None, found))

    print("== python-cryptography writes PKCS#12, ours reads")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography import x509
    for label, algorithm, mac in [("aes", pkcs12.PBES.PBESv2SHA256AndAES256CBC, hashes.SHA256()),
                                  ("3des", pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC,
                                   hashes.SHA1())]:
        for name in ("rsa", "p384", "dsa"):
            with open(path(f"{name}.key"), "rb") as f:
                key = serialization.load_pem_private_key(f.read(), None)
            with open(path(f"{name}.crt"), "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            encryption = (serialization.PrivateFormat.PKCS12.encryption_builder()
                          .kdf_rounds(5000).key_cert_algorithm(algorithm).hmac_hash(mac)
                          .build(PASSWORD.encode()))
            data = pkcs12.serialize_key_and_certificates(name.encode(), key, cert, None,
                                                         encryption)
            out = path(f"python-{label}-{name}.p12")
            with open(out, "wb") as f:
                f.write(data)
            found, error = ours_list(args, out, PASSWORD)
            tally.check(same(found, expect([name])), f"python-cryptography {label} {name}",
                        error or found)
            if found is not None and name == "dsa":
                recorded.append((f"python-{label}", out, PASSWORD, None, found))

    print("== NSS's pk12util writes PKCS#12, ours reads")
    nss = path("nssdb")
    os.makedirs(nss)
    run(["certutil", "-N", "-d", f"sql:{nss}", "--empty-password"])
    source = path("rsa-openssl.p12")
    run(["openssl", "pkcs12", "-export", "-inkey", path("rsa.key"), "-in", path("rsa.crt"),
         "-name", "rsa", "-passout", f"pass:{JAVA_PASSWORD}", "-out", source])
    run(["pk12util", "-i", source, "-d", f"sql:{nss}", "-W", JAVA_PASSWORD])
    for label, options in [("default", []), ("aes", ["-c", "AES-256-CBC", "-C", "AES-256-CBC"]),
                           ("legacy", ["-c", "PKCS #12 V2 PBE With SHA-1 And 3KEY Triple DES-CBC",
                                       "-C", "PKCS #12 V2 PBE With SHA-1 And 40 Bit RC2 CBC"])]:
        out = path(f"nss-{label}.p12")
        result = run(["pk12util", "-o", out, "-n", "rsa", "-d", f"sql:{nss}", "-W",
                      JAVA_PASSWORD, *options], check=False)
        if result.returncode:
            tally.check(False, f"pk12util {label}", result.stderr.decode(errors="replace"))
            continue
        found, error = ours_list(args, out, JAVA_PASSWORD)
        tally.check(same(found, expect(["rsa"])), f"pk12util {label}", error or found)
        # NSS's MAC takes 600,000 iterations and has no option to take
        # fewer, so one of its stores is kept, for the BER it writes.
        if found is not None and label == "default":
            recorded.append((f"nss-{label}", out, JAVA_PASSWORD, None, found))

    print("== keytool writes JKS, JCEKS and PKCS#12, ours reads")
    stores = {}
    for store_type in ("JKS", "JCEKS", "PKCS12"):
        store = path(f"keytool.{store_type.lower()}")
        for name in ("rsa", "p256"):
            p12 = path(f"{name}-for-keytool.p12")
            run(["openssl", "pkcs12", "-export", "-inkey", path(f"{name}.key"), "-in",
                 path(f"{name}.crt"), "-name", name, "-passout", f"pass:{JAVA_PASSWORD}",
                 "-out", p12])
            run([*KEYTOOL, "-importkeystore", "-srckeystore", p12, "-srcstoretype", "PKCS12",
                 "-srcstorepass", JAVA_PASSWORD, "-destkeystore", store, "-deststoretype",
                 store_type, "-deststorepass", JAVA_PASSWORD, "-destkeypass", JAVA_PASSWORD,
                 "-noprompt"])
        run([*KEYTOOL, "-importcert", "-keystore", store, "-storetype", store_type,
             "-storepass", JAVA_PASSWORD, "-alias", "trusted", "-file", path("p384.crt"),
             "-noprompt"])
        if store_type != "JKS":
            run([*KEYTOOL, "-genseckey", "-keystore", store, "-storetype", store_type,
                 "-storepass", JAVA_PASSWORD, "-keypass", JAVA_PASSWORD, "-alias", "secret",
                 "-keyalg", "AES", "-keysize", "256"])
        stores[store_type] = store
        expected = expect(["rsa", "p256"]) + [("cert", "trusted", material["p384"][1])]
        found, error = ours_list(args, store, JAVA_PASSWORD)
        secrets = [e for e in (found or []) if e[0] == "secret"]
        tally.check(same([e for e in (found or []) if e[0] != "secret"], expected)
                    and len(secrets) == (store_type != "JKS"),
                    f"keytool {store_type}", error or found)
        wrong, _ = ours_list(args, store, "not the password")
        tally.check(wrong is None, f"  keytool {store_type}: a wrong password refused")
        if found is not None:
            recorded.append((f"keytool-{store_type.lower()}", store, JAVA_PASSWORD, None, found))

    # The same secret key, as keytool moves it between its formats.
    found_jceks, _ = ours_list(args, stores["JCEKS"], JAVA_PASSWORD)
    moved = path("keytool-moved.p12")
    run([*KEYTOOL, "-importkeystore", "-srckeystore", stores["JCEKS"], "-srcstoretype", "JCEKS",
         "-srcstorepass", JAVA_PASSWORD, "-destkeystore", moved, "-deststoretype", "PKCS12",
         "-deststorepass", JAVA_PASSWORD, "-noprompt"])
    found_moved, error = ours_list(args, moved, JAVA_PASSWORD)
    secret_jceks = [e[2] for e in (found_jceks or []) if e[0] == "secret"]
    secret_moved = [e[2] for e in (found_moved or []) if e[0] == "secret"]
    # A PKCS#12 secret bag holds the key inside a PrivateKeyInfo-shaped
    # structure; the key is its last 32 bytes.
    tally.check(bool(secret_jceks) and secret_moved
                and secret_moved[0].endswith(secret_jceks[0]),
                "keytool's JCEKS secret key, moved to PKCS#12, is the same key",
                f"{secret_jceks} vs {secret_moved} {error}")

    # Java's KeyStore API writes what keytool will not: a store under the
    # empty password, here with its legacy algorithms.
    java_empty = path("java-empty-legacy.p12")
    run(["java", "-Dkeystore.pkcs12.keyProtectionAlgorithm=PBEWithSHA1AndDESede",
         "-Dkeystore.pkcs12.certProtectionAlgorithm=PBEWithSHA1AndRC2_40",
         "-Dkeystore.pkcs12.macAlgorithm=HmacPBESHA1",
         os.path.join(ROOT, "scripts", "witness", "javakeystore", "Rewrite.java"),
         stores["PKCS12"], "PKCS12", JAVA_PASSWORD, java_empty, "PKCS12", ""])
    found_empty, error = ours_list(args, java_empty, "")
    found_keytool, _ = ours_list(args, stores["PKCS12"], JAVA_PASSWORD)
    tally.check(found_empty is not None and sorted(found_empty) == sorted(found_keytool or []),
                "Java's PKCS#12 under the empty password, legacy algorithms", error or found_empty)
    if found_empty is not None:
        recorded.append(("java-empty-legacy", java_empty, "", None, found_empty))

    print("== ours writes PKCS#12, they read")
    two = path("two.p12")
    run(["openssl", "pkcs12", "-export", "-inkey", path("rsa.key"), "-in", path("rsa.crt"),
         "-name", "rsa", "-passout", f"pass:{PASSWORD}", "-out", two])
    for key_scheme in ("aes-256", "3des", "rc2-40", "none"):
        for cert_scheme in ("aes-256", "3des", "rc2-40", "none"):
            for mac in ("sha256", "sha1", "pbmac1", "none"):
                if mac != "sha256" and (key_scheme, cert_scheme) not in (
                        ("aes-256", "aes-256"), ("3des", "rc2-40")):
                    continue
                label = f"ours keys {key_scheme}, certificates {cert_scheme}, MAC {mac}"
                out = path(f"ours-{key_scheme}-{cert_scheme}-{mac}.p12")
                made = run([args.ours, "convert", two, out, "--password-stdin", "--format",
                            "pkcs12", "--key-scheme", key_scheme, "--cert-scheme", cert_scheme,
                            "--mac", mac, "--iterations", "2048"],
                           check=False, input=(PASSWORD + "\n").encode())
                if made.returncode:
                    tally.check(False, label, made.stderr.decode(errors="replace"))
                    continue
                openssl = OPENSSL35 if mac == "pbmac1" else "openssl"
                found, error = openssl_contents(openssl, out, PASSWORD,
                                                legacy="rc2-40" in (key_scheme, cert_scheme))
                tally.check(same(found, expect(["rsa"])), f"{label}: OpenSSL reads it",
                            error or found)
                if mac != "pbmac1" and not (key_scheme == "rc2-40" or cert_scheme == "rc2-40"):
                    with open(out, "rb") as f:
                        try:
                            loaded = pkcs12.load_pkcs12(f.read(), PASSWORD.encode())
                            ok = (key_identity(loaded.key.private_bytes(
                                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())) == material["rsa"][0])
                            detail = ""
                        except Exception as e:  # noqa: BLE001 - reported
                            ok, detail = False, str(e)
                    tally.check(ok, f"{label}: python-cryptography reads it", detail)
                # Java's PBE keys refuse a password outside printable
                # ASCII, so keytool gets the same store under another.
                java = path(f"ours-{key_scheme}-{cert_scheme}-{mac}-java.p12")
                run([args.ours, "convert", two, java, "--password-stdin", "--format",
                     "pkcs12", "--key-scheme", key_scheme, "--cert-scheme", cert_scheme,
                     "--mac", mac, "--iterations", "2048", "--out-password", JAVA_PASSWORD],
                    input=(PASSWORD + "\n").encode())
                # JDK 21 has no PBMAC1 (its PKCS12KeyStore asks for an
                # "HmacPBE" + OID algorithm that does not exist), and
                # loads only shrouded key bags - a plain keyBag is
                # skipped as "Unsupported PKCS12 bag type" - so a store
                # with plain keys lists as empty.
                if mac != "pbmac1":
                    listed = run([*KEYTOOL, "-list", "-keystore", java, "-storetype",
                                  "PKCS12", "-storepass", JAVA_PASSWORD], check=False)
                    wanted = (b"PrivateKeyEntry" if key_scheme != "none"
                              else b"contains 0 entries")
                    tally.check(listed.returncode == 0 and wanted in listed.stdout,
                                f"{label}: keytool reads it",
                                (listed.stdout + listed.stderr).decode(errors="replace"))
                if found is not None and mac in ("sha256", "pbmac1") and \
                        (key_scheme, cert_scheme) in (("aes-256", "aes-256"), ("3des", "rc2-40")):
                    recorded.append((f"ours-{key_scheme}-{cert_scheme}-{mac}", out, PASSWORD,
                                     None, found))

    print("== ours writes JKS and JCEKS, keytool reads")
    for fmt in ("jks", "jceks"):
        source = stores["PKCS12"]
        out = path(f"ours.{fmt}")
        made = run([args.ours, "convert", source, out, "--password-stdin", "--format", fmt,
                    "--iterations", "2048"], check=False,
                   input=(JAVA_PASSWORD + "\n").encode())
        if made.returncode:
            # The PKCS#12 holds keytool's secret key, which does not go
            # to JKS; drop to the JKS store for that.
            source = stores["JKS"]
            made = run([args.ours, "convert", source, out, "--password-stdin", "--format", fmt,
                        "--iterations", "2048"], check=False,
                       input=(JAVA_PASSWORD + "\n").encode())
        if made.returncode:
            tally.check(False, f"ours {fmt}", made.stderr.decode(errors="replace"))
            continue
        listed = run([*KEYTOOL, "-list", "-v", "-keystore", out, "-storetype", fmt.upper(),
                      "-storepass", JAVA_PASSWORD], check=False)
        text = listed.stdout.decode(errors="replace")
        tally.check(listed.returncode == 0 and text.count("PrivateKeyEntry") == 2
                    and text.count("trustedCertEntry") == 1, f"ours {fmt}: keytool lists it",
                    text + listed.stderr.decode(errors="replace"))
        converted = path(f"ours-{fmt}-by-keytool.p12")
        run([*KEYTOOL, "-importkeystore", "-srckeystore", out, "-srcstoretype", fmt.upper(),
             "-srcstorepass", JAVA_PASSWORD, "-destkeystore",
             converted, "-deststoretype", "PKCS12", "-deststorepass", JAVA_PASSWORD,
             "-noprompt"], check=False)
        found, error = openssl_contents("openssl", converted, JAVA_PASSWORD)
        keys = [e for e in (found or []) if e[0] == "key"]
        wanted = [e for e in expect(["rsa", "p256"]) if e[0] == "key"]
        tally.check(same(keys, wanted), f"ours {fmt}: keytool decrypts the keys", error or found)
        if found is not None:
            found_ours, _ = ours_list(args, out, JAVA_PASSWORD)
            recorded.append((f"ours-{fmt}", out, JAVA_PASSWORD, None, found_ours))

    print("== ours writes a secret key, keytool reads it")
    # JCEKS seals the key as a serialised SecretKeySpec, which Java has to
    # deserialise; PKCS#12 puts it in a secret bag. keytool moves each to
    # the other format and ours reads the key back.
    for fmt, there in (("jceks", "PKCS12"), ("pkcs12", "JCEKS")):
        out = path(f"ours-secret.{fmt}")
        made = run([args.ours, "convert", stores["JCEKS"], out, "--password-stdin", "--format",
                    fmt, "--iterations", "2048"], check=False,
                   input=(JAVA_PASSWORD + "\n").encode())
        if made.returncode:
            tally.check(False, f"ours {fmt} with a secret key", made.stderr.decode(errors="replace"))
            continue
        listed = run([*KEYTOOL, "-list", "-keystore", out, "-storetype", fmt.upper(),
                      "-storepass", JAVA_PASSWORD], check=False)
        tally.check(listed.returncode == 0 and b"SecretKeyEntry" in listed.stdout,
                    f"ours {fmt} with a secret key: keytool lists it",
                    (listed.stdout + listed.stderr).decode(errors="replace"))
        back = path(f"ours-secret-{fmt}-by-keytool.{there.lower()}")
        moved_back = run([*KEYTOOL, "-importkeystore", "-srckeystore", out, "-srcstoretype",
                          fmt.upper(), "-srcstorepass", JAVA_PASSWORD, "-destkeystore", back,
                          "-deststoretype", there, "-deststorepass", JAVA_PASSWORD,
                          "-destkeypass", JAVA_PASSWORD, "-noprompt"], check=False)
        found_back, error = ours_list(args, back, JAVA_PASSWORD)
        secret_back = [e[2] for e in (found_back or []) if e[0] == "secret"]
        tally.check(bool(secret_back) and (secret_back[0].endswith(secret_jceks[0])),
                    f"ours {fmt} with a secret key: keytool unseals the same key",
                    f"{secret_back} {error} "
                    f"{(moved_back.stdout + moved_back.stderr).decode(errors='replace')}")
        if fmt == "pkcs12":
            # Java's secret bag, before shrouding, is a structure of its
            # own; ours must be byte for byte the one keytool wrote.
            found_ours, error = ours_list(args, out, JAVA_PASSWORD)
            secret_ours = [e[2] for e in (found_ours or []) if e[0] == "secret"]
            tally.check(secret_ours == secret_moved,
                        "ours pkcs12 with a secret key: the bag is keytool's",
                        f"{secret_ours} vs {secret_moved} {error}")
        if found_back is not None:
            recorded.append((f"ours-secret-{fmt}", out, JAVA_PASSWORD, None, found_back))

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    if args.record and not tally.failed:
        record(recorded)
    shutil.rmtree(work)
    return 1 if tally.failed else 0


def record(recorded):
    directory = os.path.join(FIXTURES, "keystore")
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)
    lines = ["# Key stores the witnesses wrote, and ours, with what each holds,",
             "# written by scripts/check_keystore.py --record: for each entry its",
             "# kind and the SHA-256 of its plain contents - the PKCS#8 for a key,",
             "# the DER for a certificate, the key for a secret - as ours read",
             "# them after the witness agreed.", "", "[store]"]
    import subprocess as sp
    for label, path, password, _, _ in recorded:
        name = label + os.path.splitext(path)[1]
        shutil.copy(path, os.path.join(directory, name))
        listing = sp.run([OURS, "list", path, "--password-stdin", "--canonical"],
                         input=(password + "\n").encode(), capture_output=True, check=True)
        # "-" for the empty password, which as hex would be nothing.
        lines += [f"name = {name}", f"password = {password.encode().hex() or '-'}"]
        for line in listing.stdout.decode().splitlines():
            parts = line.split(" ")
            data = bytes.fromhex(parts[-1])
            lines.append(f"entry = {parts[0]} {hashlib.sha256(data).hexdigest()}")
    with open(os.path.join(FIXTURES, "keystore.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    print(f"{len(recorded)} stores -> {directory}")


if __name__ == "__main__":
    sys.exit(main())
