#!/usr/bin/env python3
"""Post-quantum keys written by this library, read by OpenSSL 3.5.

    python3 scripts/build_python.py
    python3 scripts/check_pq_key_writing.py --openssl /opt/openssl35/bin/openssl

**A development tool, not a test**, and it records nothing: it fails if
OpenSSL disagrees. `tests/test_pq_key_writing.rs` is the offline half,
which writes OpenSSL's own keys again and compares the bytes.

For keys generated here, through the Python bindings:

  * ML-DSA, each set, each of the three private key forms: `openssl
    pkey` reads the PEM and derives the public key this library wrote,
    and `pkeyutl -sign -rawin` with it makes a signature this library
    verifies;
  * ML-KEM, each set, each form: the same public key, and `pkeyutl
    -decap` with it recovers the secret this library encapsulated;
  * SLH-DSA, each of the twelve sets: the same public key, and a
    signature by OpenSSL with the key that this library verifies;
  * every public key: `openssl pkey -pubin` reads the `PUBLIC KEY` file
    and writes it back unchanged;
  * one key of each kind encrypted with `encrypt_private_key`
    (PBES2, AES-256-CBC), which OpenSSL decrypts with the password.

OpenSSL 3.5 has no HashSLH-DSA, so keys bound to a pre-hash are not
asked about.
"""

import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

FORMS = ["seed", "expanded", "both"]
MESSAGE = b"written by allcrypt, read by OpenSSL"


def run(openssl, *arguments, data=None):
    result = subprocess.run([openssl, *arguments], capture_output=True, input=data)
    if result.returncode:
        raise RuntimeError(f"openssl {' '.join(arguments)}: {result.stderr.decode()}")
    return result.stdout


def write(path, data):
    with open(path, "wb" if isinstance(data, bytes) else "w") as out:
        out.write(data)
    return path


def openssl_public(openssl, key_path, *extra):
    return run(openssl, "pkey", "-in", key_path, "-pubout", "-outform", "DER", *extra)


def check_public(openssl, allcrypt, work, name, public):
    spki = public.to_spki()
    path = write(os.path.join(work, f"{name}.pub.pem"), allcrypt.pem_wrap(spki, "PUBLIC KEY"))
    if run(openssl, "pkey", "-pubin", "-in", path, "-outform", "DER") != spki:
        raise RuntimeError(f"{name}: OpenSSL wrote our public key back differently")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", default="/opt/openssl35/bin/openssl")
    args = parser.parse_args()
    openssl = args.openssl
    prefix = os.path.dirname(os.path.dirname(os.path.abspath(openssl)))
    libraries = [os.path.join(prefix, d) for d in ("lib64", "lib")
                 if os.path.isdir(os.path.join(prefix, d))]
    os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(
        libraries + [os.environ.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    sys.path.insert(0, os.path.join(ROOT, "python"))
    import allcrypt

    checked = 0
    with tempfile.TemporaryDirectory() as work:
        message = write(os.path.join(work, "message"), MESSAGE)

        for parameter_set in allcrypt.ml_dsa_parameter_sets():
            key = allcrypt.MlDsaKey.generate(parameter_set)
            spki = key.public_key().to_spki()
            for form in FORMS:
                path = write(os.path.join(work, f"{parameter_set}-{form}.pem"),
                             allcrypt.pem_wrap(key.to_pkcs8(form), "PRIVATE KEY"))
                if openssl_public(openssl, path) != spki:
                    raise RuntimeError(f"{parameter_set} {form}: another public key")
                signature = os.path.join(work, "signature")
                run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", path, "-in", message,
                    "-out", signature)
                with open(signature, "rb") as handle:
                    if not key.public_key().verify(MESSAGE, handle.read()):
                        raise RuntimeError(f"{parameter_set} {form}: OpenSSL's signature "
                                           f"does not verify")
                checked += 1
            check_public(openssl, allcrypt, work, parameter_set, key.public_key())
            print(f"{parameter_set}: OpenSSL read all three forms and signed with them")

        for parameter_set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
            key = allcrypt.MlKemKey.generate(parameter_set)
            spki = key.public_key().to_spki()
            for form in FORMS:
                path = write(os.path.join(work, f"{parameter_set}-{form}.pem"),
                             allcrypt.pem_wrap(key.to_pkcs8(form), "PRIVATE KEY"))
                if openssl_public(openssl, path) != spki:
                    raise RuntimeError(f"{parameter_set} {form}: another public key")
                secret, ciphertext = key.public_key().encapsulate()
                ct = write(os.path.join(work, "ciphertext"), ciphertext)
                out = os.path.join(work, "secret")
                run(openssl, "pkeyutl", "-decap", "-inkey", path, "-in", ct, "-secret", out)
                with open(out, "rb") as handle:
                    if handle.read() != secret:
                        raise RuntimeError(f"{parameter_set} {form}: OpenSSL decapsulated "
                                           f"another secret")
                checked += 1
            check_public(openssl, allcrypt, work, parameter_set, key.public_key())
            print(f"{parameter_set}: OpenSSL read all three forms and decapsulated with them")

        for parameter_set in allcrypt.slh_dsa_parameter_sets():
            key = allcrypt.SlhDsaKey.generate(parameter_set)
            path = write(os.path.join(work, f"{parameter_set}.pem"),
                         allcrypt.pem_wrap(key.to_pkcs8(), "PRIVATE KEY"))
            if openssl_public(openssl, path) != key.public_key().to_spki():
                raise RuntimeError(f"{parameter_set}: another public key")
            signature = os.path.join(work, "signature")
            run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", path, "-in", message,
                "-out", signature)
            with open(signature, "rb") as handle:
                if not key.public_key().verify(MESSAGE, handle.read()):
                    raise RuntimeError(f"{parameter_set}: OpenSSL's signature does not verify")
            check_public(openssl, allcrypt, work, parameter_set, key.public_key())
            checked += 1
            print(f"{parameter_set}: OpenSSL read the key and signed with it")

        for key in [allcrypt.MlDsaKey.generate("ML-DSA-65"),
                    allcrypt.MlKemKey.generate("ML-KEM-768"),
                    allcrypt.SlhDsaKey.generate("SLH-DSA-SHAKE-128f")]:
            der = key.to_pkcs8()
            encrypted = allcrypt.encrypt_private_key(der, b"correct horse", "aes-256-cbc",
                                                     pem=True)
            path = write(os.path.join(work, "encrypted.pem"), encrypted)
            got = openssl_public(openssl, path, "-passin", "pass:correct horse")
            if got != key.public_key().to_spki():
                raise RuntimeError(f"{key!r}: OpenSSL decrypted another key")
            checked += 1
        print("one key of each kind, encrypted: OpenSSL decrypted all three")
    print(f"{checked} keys written here read by OpenSSL")
    return 0


if __name__ == "__main__":
    sys.exit(main())
