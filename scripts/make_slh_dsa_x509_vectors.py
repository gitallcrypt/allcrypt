#!/usr/bin/env python3
"""SLH-DSA certificates and private keys from four other implementations,
recorded for offline tests, and this library's certificates checked by
OpenSSL while it runs.

    python3 scripts/build_python.py
    python3 scripts/make_slh_dsa_x509_vectors.py --openssl /opt/openssl35/bin/openssl

**A development tool, not a test.** It needs the network once, and
writes **`vectors/slh_dsa_x509.vec`**.

The IETF hackathon's PQC certificate interoperability repository has each
participant publish, per algorithm, a self-signed certificate (`_ta.der`)
and the PKCS#8 private key that signed it (`_priv.der`), in a zip per
participant. Four of those zips are fetched at a pinned commit and
SHA-256 checked, and from them this keeps:

  * pure SLH-DSA, all twelve parameter sets, from OpenSSL 3.5 (`ossl35`)
    and Bouncy Castle (`bc`);
  * HashSLH-DSA, all twelve, from Bouncy Castle and Carl Wallace's
    Redhound (`carl-redhound`), the two that publish it;
  * pure SLH-DSA at the two 128-bit sets of each family from Botan and
    Redhound, so that every implementation that signed is represented
    without carrying every one of its signatures - the `f` sets at 256
    bits are 49 KB each.

Redhound's HashSLH-DSA certificates are signed under the HashSLH-DSA OID
by a key whose SubjectPublicKeyInfo carries the pure one, which RFC 9909
section 8 forbids; they are kept as they are, and the test checks both
that they are refused and that their signatures are right as HashSLH-DSA.

The file names carry the participant's own name for the algorithm and
the dotted OID, and both are kept: the test that reads this checks this
library's OID table against them as well as verifying each certificate.

And it checks the other direction live, through the Python bindings,
failing if OpenSSL disagrees: for each of the twelve pure sets, a
`CertificateAuthority` with an SLH-DSA key, its self-signed certificate
and a leaf it issued must pass `openssl verify -x509_strict`, and OpenSSL
must name the set this library meant. OpenSSL 3.5 has no HashSLH-DSA, so
that half rests on the recorded artifacts. The live results are not
recorded - the run fails instead.
"""

import argparse
import base64
import hashlib
import io
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VECTORS = os.path.join(ROOT, "vectors", "slh_dsa_x509.vec")

COMMIT = "09f55bb1aeff8140a60df492061fae9fca48bf5d"
BASE = ("https://raw.githubusercontent.com/IETF-Hackathon/pqc-certificates/"
        f"{COMMIT}/providers/")
ZIPS = {
    "ossl35": "5836cbc8c8fa581067016fc89600b91947f8a77215211cc0c15bf2c96239cb54",
    "bc": "bbf01bd8aec1d4bb3d8fa9110d64a18f75acbe65bbc6a501c4b44b6238baa2ec",
    "carl-redhound": "609b681ec900b99043aaa3db642ac54e6a2830f7e084a22845a07f04e1ba0774",
    "botan": "be562af86b0d9db4b6f9ea4f3bcd2277563744ee64e290909a41d046f2dd202c",
}

SETS = [f"SLH-DSA-{family}-{bits}{speed}"
        for family in ("SHA2", "SHAKE") for bits in (128, 192, 256) for speed in "sf"]
# FIPS 205's twelve, numbered as RFC 9909 numbers them: pure from .20,
# pre-hashed from .35, in this order.
PURE_ARC = 20
HASHED_ARC = 35
NIST_SIG_ALGS = "2.16.840.1.101.3.4.3."

#: provider -> which of its artifacts to keep: "pure", "hashed", and
#: "pure-128" for the 128-bit pure sets only.
KEEP = {
    "ossl35": ["pure"],
    "bc": ["pure", "hashed"],
    "carl-redhound": ["hashed", "pure-128"],
    "botan": ["pure-128"],
}

ARTIFACT = re.compile(r"(?:.*/)?((?:hash-)?slh-dsa-[a-z0-9-]+?)-(2\.16\.840\.1\.101\.3\.4\.3\.\d+)"
                      r"_(ta|priv)\.der$")


def fetch(provider):
    url = f"{BASE}{provider}/artifacts_certs_r5.zip"
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != ZIPS[provider]:
        sys.exit(f"{provider}'s zip changed upstream; read it before trusting it")
    return zipfile.ZipFile(io.BytesIO(data))


def wanted(provider, oid):
    arc = int(oid.rsplit(".", 1)[1])
    for kind in KEEP[provider]:
        if kind == "hashed" and HASHED_ARC <= arc < HASHED_ARC + 12:
            return True
        if kind == "pure" and PURE_ARC <= arc < PURE_ARC + 12:
            return True
        if kind == "pure-128" and PURE_ARC <= arc < PURE_ARC + 12 \
                and "128" in SETS[arc - PURE_ARC]:
            return True
    return False


def artifacts(provider):
    """`(name, oid, certificate, private)` for each kept pair, by OID."""
    archive = fetch(provider)
    pairs = {}
    for entry in archive.namelist():
        match = ARTIFACT.match(entry)
        if not match:
            continue
        name, oid, kind = match.groups()
        if not wanted(provider, oid):
            continue
        pairs.setdefault((oid, name), {})[kind] = archive.read(entry)
    found = []
    for (oid, name), pair in sorted(pairs.items(),
                                    key=lambda item: int(item[0][0].rsplit(".", 1)[1])):
        if set(pair) != {"ta", "priv"}:
            sys.exit(f"{provider}: {name} has {sorted(pair)} and not both halves")
        found.append((name, oid, pair["ta"], pair["priv"]))
    expected = sum({"pure": 12, "hashed": 12, "pure-128": 4}[k] for k in KEEP[provider])
    if len(found) != expected:
        sys.exit(f"{provider}: kept {len(found)} pairs, expected {expected}")
    return found


def run(openssl, *arguments):
    return subprocess.run([openssl, *arguments], check=True, capture_output=True).stdout


def ours_against_openssl(openssl, work):
    """This library's SLH-DSA certificates, judged by OpenSSL."""
    sys.path.insert(0, os.path.join(ROOT, "python"))
    import allcrypt

    for parameter_set in SETS:
        ca = allcrypt.CertificateAuthority(f"allcrypt {parameter_set} CA", "20260101000000Z",
                                           "20360101000000Z", key_type=parameter_set)
        base = os.path.join(work, parameter_set)
        with open(base + "-ca.crt", "w") as out:
            out.write(ca.certificate_pem)
        leaf, _ = ca.issue("slh-dsa.example", "20260101000000Z", "20360101000000Z")
        with open(base + ".crt", "w") as out:
            out.write(allcrypt.pem_wrap(leaf, "CERTIFICATE"))
        run(openssl, "verify", "-x509_strict", "-CAfile", base + "-ca.crt", base + "-ca.crt")
        run(openssl, "verify", "-x509_strict", "-CAfile", base + "-ca.crt", base + ".crt")
        text = run(openssl, "x509", "-in", base + ".crt", "-noout", "-text").decode()
        if f"Signature Algorithm: {parameter_set}" not in text:
            raise RuntimeError(f"{parameter_set}: OpenSSL names our signature otherwise:\n"
                               + "\n".join(line for line in text.splitlines()
                                           if "Algorithm" in line))
        print(f"{parameter_set}: OpenSSL verified our CA and its leaf")


def write_vectors(records):
    with open(VECTORS, "w") as out:
        out.write(
            "# SLH-DSA certificates and private keys from the IETF hackathon's\n"
            "# PQC certificate interoperability artifacts.\n"
            "#\n"
            "# Generated by scripts/make_slh_dsa_x509_vectors.py. Do not edit:\n"
            "# every value here is the participant's, fetched from\n"
            f"# github.com/IETF-Hackathon/pqc-certificates at {COMMIT}.\n"
            "#\n"
            "# `name` and `oid` are the participant's file name: its own name\n"
            "# for the algorithm and the dotted OID. `certificate` is the\n"
            "# self-signed `_ta.der` and `private` the `_priv.der` that signed\n"
            "# it, each as one line of base64.\n"
            "#\n"
            "# Counts, asserted by the test that reads this:\n"
            f"#   certificate              {len(records)}\n"
            "\n[certificate]\n")
        for provider, name, oid, certificate, private in records:
            out.write(f"\nprovider = {provider}\nname = {name}\noid = {oid}\n"
                      f"certificate = {base64.b64encode(certificate).decode()}\n"
                      f"private = {base64.b64encode(private).decode()}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", default="/opt/openssl35/bin/openssl")
    args = parser.parse_args()

    records = []
    for provider in ZIPS:
        for name, oid, certificate, private in artifacts(provider):
            records.append((provider, name, oid, certificate, private))

    prefix = os.path.dirname(os.path.dirname(os.path.abspath(args.openssl)))
    libraries = [os.path.join(prefix, d) for d in ("lib64", "lib")
                 if os.path.isdir(os.path.join(prefix, d))]
    os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(
        libraries + [os.environ.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    with tempfile.TemporaryDirectory() as work:
        config = os.path.join(work, "openssl.cnf")
        with open(config, "w") as out:
            out.write("[req]\ndistinguished_name = dn\n[dn]\n")
        os.environ["OPENSSL_CONF"] = config
        ours_against_openssl(args.openssl, work)

    write_vectors(records)
    print(f"wrote {VECTORS}: {len(records)} certificates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
