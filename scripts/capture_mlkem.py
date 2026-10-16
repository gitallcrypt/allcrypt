#!/usr/bin/env python3
"""OpenSSL 3.5's ML-KEM keys, encapsulations and certificates, recorded for
offline tests, and this library's checked by OpenSSL while it runs.

    python3 scripts/build_python.py
    python3 scripts/capture_mlkem.py --openssl /opt/openssl35/bin/openssl

**A development tool, not a test.** It writes **`vectors/ml_kem_openssl.vec`**,
per parameter set:

  * `[key]`: one key in all three of RFC 9935's private key forms as
    OpenSSL writes them (`seed-only`, `priv-only`, `seed-priv`), and its
    public key;
  * `[encapsulation]`: `pkeyutl -encap` to that public key, three times -
    the ciphertext and the shared secret OpenSSL kept, which the matching
    private key read here must decapsulate to;
  * `[certificate]`: an ML-KEM certificate OpenSSL issued for the key,
    keyUsage keyEncipherment, under an ML-DSA CA of the matching level,
    with the CA's certificate.

And it checks the other direction live, through the Python bindings,
failing if OpenSSL disagrees: OpenSSL's `pkeyutl -decap` must recover
what this library encapsulated to OpenSSL's public key, read out of its
PEM; and `openssl verify -x509_strict` must accept, and `openssl x509`
must read the key out of, a certificate `CertificateAuthority.issue_ml_kem`
issued for it. Those results are not recorded - the run fails instead.

Keys, ciphertexts and certificates are fresh on every run, so every row
changes; the counts do not.
"""

import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

VECTORS = os.path.join(ROOT, "vectors", "ml_kem_openssl.vec")

SETS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
SIGNERS = {"ML-KEM-512": "ML-DSA-44", "ML-KEM-768": "ML-DSA-65", "ML-KEM-1024": "ML-DSA-87"}
FORMATS = ["seed-only", "priv-only", "seed-priv"]
ENCAPSULATIONS = 3


def run(openssl, *arguments, data=None):
    return subprocess.run([openssl, *arguments], check=True, capture_output=True,
                          input=data).stdout


def pem_body(path):
    """The base64 of a PEM file on one line - what the reader decodes."""
    with open(path) as handle:
        return "".join(line.strip() for line in handle if not line.startswith("-----"))


def read(path):
    with open(path, "rb") as handle:
        return handle.read()


def keys_and_encapsulations(openssl, work):
    keys, encapsulations = [], []
    for parameter_set in SETS:
        base = os.path.join(work, parameter_set)
        run(openssl, "genpkey", "-algorithm", parameter_set, "-out", base + ".key")
        record = [("name", parameter_set)]
        for form in FORMATS:
            path = f"{base}.{form}.key"
            run(openssl, "pkey", "-in", base + ".key", "-out", path,
                "-provparam", f"ml-kem.output_formats={form}")
            record.append((form, pem_body(path)))
        run(openssl, "pkey", "-in", base + ".key", "-pubout", "-out", base + ".pub")
        record.append(("public", pem_body(base + ".pub")))
        keys.append(record)

        for _ in range(ENCAPSULATIONS):
            ciphertext, secret = base + ".ct", base + ".ss"
            run(openssl, "pkeyutl", "-encap", "-pubin", "-inkey", base + ".pub",
                "-out", ciphertext, "-secret", secret)
            # OpenSSL decapsulates its own ciphertext before it is believed
            # about ours.
            again = base + ".ss2"
            run(openssl, "pkeyutl", "-decap", "-inkey", base + ".key", "-in", ciphertext,
                "-secret", again)
            if read(again) != read(secret):
                raise RuntimeError(f"{parameter_set}: OpenSSL disagrees with itself")
            encapsulations.append([("name", parameter_set),
                                   ("ciphertext", read(ciphertext).hex()),
                                   ("secret", read(secret).hex())])
    return keys, encapsulations


def certificates(openssl, work):
    extensions = os.path.join(work, "extensions.cnf")
    with open(extensions, "w") as out:
        out.write("[kem]\nkeyUsage=critical,keyEncipherment\n"
                  "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    found = []
    for parameter_set in SETS:
        base = os.path.join(work, parameter_set)
        signer = SIGNERS[parameter_set]
        run(openssl, "req", "-x509", "-newkey", signer, "-nodes",
            "-keyout", base + "-ca.key", "-out", base + "-ca.crt",
            "-subj", f"/CN={signer} CA", "-days", "3650",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run(openssl, "x509", "-new", "-subj", f"/CN={parameter_set} key",
            "-force_pubkey", base + ".pub", "-CA", base + "-ca.crt",
            "-CAkey", base + "-ca.key", "-days", "3650",
            "-extfile", extensions, "-extensions", "kem", "-out", base + ".crt")
        run(openssl, "verify", "-x509_strict", "-CAfile", base + "-ca.crt", base + ".crt")
        found.append([("name", parameter_set),
                      ("certificate", pem_body(base + ".crt")),
                      ("ca", pem_body(base + "-ca.crt"))])
    return found


def ours_against_openssl(openssl, work):
    """This library's encapsulation and certificates, judged by OpenSSL."""
    sys.path.insert(0, os.path.join(ROOT, "python"))
    import allcrypt

    ca = allcrypt.CertificateAuthority("allcrypt ML-DSA CA", "20260101000000Z",
                                       "20360101000000Z", key_type="ML-DSA-65")
    ca_path = os.path.join(work, "ours-ca.crt")
    with open(ca_path, "w") as out:
        out.write(ca.certificate_pem)
    for parameter_set in SETS:
        base = os.path.join(work, parameter_set)
        with open(base + ".pub", "rb") as handle:
            public = allcrypt.MlKemPublicKey.from_spki(handle.read())
        secret, ciphertext = public.encapsulate()
        with open(base + ".ours.ct", "wb") as out:
            out.write(ciphertext)
        run(openssl, "pkeyutl", "-decap", "-inkey", base + ".key", "-in", base + ".ours.ct",
            "-secret", base + ".ours.ss")
        if read(base + ".ours.ss") != secret:
            raise RuntimeError(f"{parameter_set}: OpenSSL decapsulated our ciphertext to "
                               f"another secret")

        der = ca.issue_ml_kem(f"{parameter_set} key", public, "20260101000000Z",
                              "20360101000000Z")
        with open(base + ".ours.crt", "w") as out:
            out.write(allcrypt.pem_wrap(der, "CERTIFICATE"))
        run(openssl, "verify", "-x509_strict", "-CAfile", ca_path, base + ".ours.crt")
        theirs = run(openssl, "x509", "-in", base + ".ours.crt", "-noout", "-pubkey")
        if run(openssl, "pkey", "-pubin", "-outform", "DER", data=theirs) != \
                run(openssl, "pkey", "-pubin", "-in", base + ".pub", "-outform", "DER"):
            raise RuntimeError(f"{parameter_set}: OpenSSL read another key out of our "
                               f"certificate")
        print(f"{parameter_set}: OpenSSL decapsulated ours and verified our certificate")


def write_vectors(version, sections):
    with open(VECTORS, "w") as out:
        out.write(
            "# ML-KEM keys, encapsulations and certificates from OpenSSL.\n"
            "#\n"
            "# Generated by scripts/capture_mlkem.py. Do not edit: every value\n"
            "# here is OpenSSL's, and the tests that read it need no OpenSSL.\n"
            "#\n"
            f"# {version}\n"
            "#\n"
            "# PEM bodies are written as one line of base64. `[key]` holds one\n"
            "# key per parameter set in the three forms of RFC 9935 section 6;\n"
            "# `[encapsulation]` is `pkeyutl -encap` to that key's public half;\n"
            "# `[certificate]` is an ML-KEM certificate and the ML-DSA CA that\n"
            "# issued it.\n"
            "#\n"
            "# Counts, asserted by the test that reads this:\n")
        for name, records in sections:
            out.write(f"#   {name:24} {len(records)}\n")
        for name, records in sections:
            out.write(f"\n[{name}]\n")
            for record in records:
                out.write("\n")
                for key, value in record:
                    out.write(f"{key} = {value}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", default="/opt/openssl35/bin/openssl")
    args = parser.parse_args()
    prefix = os.path.dirname(os.path.dirname(os.path.abspath(args.openssl)))
    libraries = [os.path.join(prefix, d) for d in ("lib64", "lib")
                 if os.path.isdir(os.path.join(prefix, d))]
    os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(
        libraries + [os.environ.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    version = run(args.openssl, "version").decode().strip()
    with tempfile.TemporaryDirectory() as work:
        config = os.path.join(work, "openssl.cnf")
        with open(config, "w") as out:
            out.write("[req]\ndistinguished_name = dn\n[dn]\n")
        os.environ["OPENSSL_CONF"] = config
        keys, encapsulations = keys_and_encapsulations(args.openssl, work)
        certs = certificates(args.openssl, work)
        ours_against_openssl(args.openssl, work)
    sections = [("key", keys), ("encapsulation", encapsulations), ("certificate", certs)]
    write_vectors(version, sections)
    print(f"wrote {VECTORS}: " + ", ".join(f"{len(r)} {n}" for n, r in sections))
    return 0


if __name__ == "__main__":
    sys.exit(main())
