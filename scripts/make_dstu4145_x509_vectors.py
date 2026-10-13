#!/usr/bin/env python3
"""Write vectors/dstu4145_x509.vec: DSTU 4145-2002 certificates, real and
ours, and what two other implementations make of them.

    scripts/witness/dstuengine/build.sh /opt/dstuengine
    scripts/witness/li0ard/build.sh /opt/li0ard
    python3 scripts/make_dstu4145_x509_vectors.py

**A development tool, not a test.** It needs the network once, both
witnesses built (the second runs under bun) and `cargo`;
`tests/test_dstu4145_x509.rs` and `pytests/test_dstu4145_x509.py` read
the certificates in `tests/keys/ua-x509/` and `vectors/dstu4145_x509.vec`
offline.

The certificates:

* Three real ones, the root certificates of Ukraine's central certifying
  authority that li0ard's `src/dstu4145/x509.spec.ts` tests against
  (fetched at a pinned commit and SHA-256 checked, each certificate
  checked again): `czo-root-2017.cer` over GOST 34.311-95,
  `cao-2026.cer` over Kupyna-256, and `czo-1.cer` over GOST 34.311-95
  under a DKE of its own; all on m431, given whole. Each is self-signed.
* Ours, from `tools/src/bin/dstu4145_certs.rs`: one on each of the ten
  named curves in both byte orders and over each hash, and three chains
  of two, written into `tests/keys/ua-x509/` as `ours-x509-*.cer`.

The witnesses:

* dstu-engine's OpenSSL engine (`scripts/witness/dstuengine`, its x509
  op): `X509_verify` under the issuer's key, over GOST 34.311-95 with the
  key's DKE, in either byte order - and the subject key's numbers, read
  through OpenSSL's certificate parser, for every certificate.
* li0ard's TypeScript (`scripts/witness/li0ard`, its x509 op), which
  builds the signer and the hash from the issuer's parameters as its own
  x509.spec.ts does: little-endian keys, over GOST 34.311-95 or Kupyna.

Every signature is checked by each witness that can check it - both for
a little-endian key over GOST 34.311-95, dstu-engine alone for a
big-endian one, li0ard alone over Kupyna - and so are two changed copies
of each certificate, one byte of the signature and one of the
TBSCertificate, which each must refuse. A disagreement, or a witness
that accepts a changed copy, stops the script. One row per certificate,
numbers big endian, as dstu-engine prints them:

    cert file= issuer= hash= order=<le|be> m= poly= a= b= n= gx= gy= qx= qy=
        source=<both|dstu-engine|li0ard>
"""

import base64
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "dstu4145_x509.vec")
FIXTURES = os.path.join(ROOT, "tests", "keys", "ua-x509")
ENGINE = os.environ.get("DSTU_ENGINE_WITNESS", "/opt/dstuengine")
LI0ARD = os.environ.get("LI0ARD_WITNESS", "/opt/li0ard")
BUN = os.environ.get("BUN") or "bun"

SPEC_URL = ("https://raw.githubusercontent.com/li0ard/dstu/"
            "6c277c8906588a11f0d21a844347e83574ca325a/src/dstu4145/x509.spec.ts")
SPEC_SHA256 = "73f73f8e70ffff2e5a5409457bb53631727bfb3d902f6d8d7b665155c9d9a386"
# The three certificates in the order the spec has them.
REAL = [("czo-root-2017.cer", "ec3524a1229cb318961fd394dbe3b024946f979c9f5f4390497fad7fe4f73de9"),
        ("cao-2026.cer", "9db1740aa0cbe1da0b26fd7243653f85220ec2e7f6aff0927d190efd62f51878"),
        ("czo-1.cer", "b72d195d8bdd7a1695e5e502182004c2e0f0943390db772e1de18519a8fe622f")]

DSTU4145_LE = "1.2.804.2.1.1.1.1.3.1.1"
DSTU4145_BE = "1.2.804.2.1.1.1.1.3.1.1.1.1"
HASHES = {DSTU4145_LE: "gost34311", DSTU4145_BE: "gost34311",
          "1.2.804.2.1.1.1.1.3.6.1.1": "kupyna256",
          "1.2.804.2.1.1.1.1.3.6.2.1": "kupyna384",
          "1.2.804.2.1.1.1.1.3.6.3.1": "kupyna512"}


# --------------------------------------------------------------- DER ---
# Enough DER to take a certificate apart, written here rather than
# borrowed from the library under test.

def tlv(data, at=0):
    """(tag, contents, end) of the element at `at`."""
    tag, length, i = data[at], data[at + 1], at + 2
    if length & 0x80:
        count = length & 0x7f
        length, i = int.from_bytes(data[i:i + count], "big"), i + count
    return tag, data[i:i + length], i + length


def children(data):
    out, at = [], 0
    while at < len(data):
        tag, body, end = tlv(data, at)
        out.append((tag, body, data[at:end]))
        at = end
    return out


def oid(body):
    arcs, value = [], 0
    for byte in body:
        value = value << 7 | byte & 0x7f
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(map(str, [first, arcs[0] - 40 * first] + arcs[1:]))


def certificate_parts(der):
    """The TBSCertificate's bytes, the signature OID, the signature's
    OCTET STRING contents, and the subject public key info's parts:
    the key OID, the ECBinary fields, the DKE and the key's OCTET STRING
    contents."""
    _, body, _ = tlv(der)
    tbs, algorithm, signature = children(body)
    signature_oid = oid(children(algorithm[1])[0][1])
    _, signature_value, _ = tlv(signature[1][1:])
    fields = children(tbs[1])
    if fields[0][0] == 0xa0:
        fields = fields[1:]
    spki = children(fields[5][1])
    key_algorithm = children(spki[0][1])
    key_oid = oid(key_algorithm[0][1])
    params = children(key_algorithm[1][1])
    if params[0][0] != 0x30:
        sys.exit("a certificate's curve is named rather than given whole")
    ecbinary = children(params[0][1])
    if ecbinary[0][0] == 0xa0:
        ecbinary = ecbinary[1:]
    field, a, b, n, bp = ecbinary
    field = children(field[1])
    m = int.from_bytes(field[0][1], "big")
    if field[1][0] == 0x02:
        exponents = [int.from_bytes(field[1][1], "big")]
    else:
        exponents = [int.from_bytes(t[1], "big") for t in children(field[1][1])]
    dke = params[1][1] if len(params) > 1 else None
    _, key, _ = tlv(spki[1][1][1:])
    return dict(tbs=tbs[2], signature_oid=signature_oid, signature=signature_value,
                key_oid=key_oid, m=m, exponents=exponents, a=int.from_bytes(a[1], "big"),
                b=b[1], n=int.from_bytes(n[1], "big"), bp=bp[1], dke=dke, key=key)


# --------------------------------------------------------- witnesses ---

def engine(cert, issuer):
    """dstu-engine's reading of `cert`'s key, and its verdict."""
    env = dict(os.environ, DSTU_ENGINE=f"{ENGINE}/dstu.so")
    out = subprocess.run([f"{ENGINE}/dstuengine-witness", "x509", cert, issuer], env=env,
                         capture_output=True, text=True, check=True).stdout.split("\n")
    if not out[0].startswith("pub ") or not out[1].startswith("verify "):
        sys.exit(f"dstu-engine refused {cert}: {out}")
    key = dict(field.split("=") for field in out[0].split()[1:])
    return key, out[1] == "verify 1"


def li0ard(der, issuer_der):
    signed, signer = certificate_parts(der), certificate_parts(issuer_der)
    hex_ = lambda b: b.hex() or "-"  # noqa: E731
    n = f"{signer['n']:x}"
    line = " ".join([
        "x509", str(signer["m"]), ",".join(map(str, signer["exponents"])), str(signer["a"]),
        hex_(signer["b"]), n.zfill(len(n) + len(n) % 2), hex_(signer["bp"]),
        hex_(signer["dke"]) if signer["dke"] else "-", HASHES[signed["signature_oid"]],
        hex_(signed["tbs"]), hex_(signed["signature"]), hex_(signer["key"])])
    out = subprocess.run([BUN, f"{LI0ARD}/run/driver.ts"], input=line + "\n",
                         capture_output=True, text=True, check=True).stdout.split("\n")[0]
    if out not in ("00", "01"):
        sys.exit(f"li0ard refused: {out}")
    return out == "01"


def changed(der, offset):
    out = bytearray(der)
    out[offset] ^= 0x01
    return bytes(out)


def verdicts(cert_path, issuer_path, witnesses):
    """Each witness's verdict on the certificate, and on its two changed
    copies: the signature's last byte, and the TBSCertificate's serial
    number's last byte."""
    der, issuer = open(cert_path, "rb").read(), open(issuer_path, "rb").read()
    _, body, _ = tlv(der)
    _, tbs, tbs_end = tlv(body)
    # The serial number's last byte, as an offset into the certificate:
    # past the outer header, the TBS's header and the version, if any.
    fields = children(tbs)
    serial = 1 if fields[0][0] == 0xa0 else 0
    tbs_start = (len(der) - len(body)) + (tbs_end - len(tbs))
    serial_last = tbs_start + sum(len(f[2]) for f in fields[:serial + 1]) - 1
    copies = [der, changed(der, len(der) - 1), changed(der, serial_last)]
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name in witnesses:
            got = []
            for i, copy in enumerate(copies):
                path = os.path.join(tmp, f"{i}.cer")
                with open(path, "wb") as f:
                    f.write(copy)
                if name == "dstu-engine":
                    key, ok = engine(path, issuer_path if issuer_path != cert_path else path)
                    if i == 0:
                        results["key"] = key
                else:
                    ok = li0ard(copy, issuer if issuer_path != cert_path else copy)
                got.append(ok)
            if got != [True, False, False]:
                sys.exit(f"{name} on {os.path.basename(cert_path)} and its two changed "
                         f"copies: {got}, not [True, False, False]")
            results[name] = True
    return results


# ------------------------------------------------------------------ main ---

def fetch_real():
    with urllib.request.urlopen(SPEC_URL) as response:
        spec = response.read()
    if hashlib.sha256(spec).hexdigest() != SPEC_SHA256:
        sys.exit(f"{SPEC_URL} changed upstream; read it before trusting it")
    blocks = re.findall(r"const certificate = `([^`]*)`", spec.decode())
    if len(blocks) != len(REAL):
        sys.exit(f"found {len(blocks)} certificates in li0ard's spec, not {len(REAL)}")
    for (name, digest), block in zip(REAL, blocks):
        der = base64.b64decode("".join(block.split()))
        if hashlib.sha256(der).hexdigest() != digest:
            sys.exit(f"{name} is not the certificate expected")
        with open(os.path.join(FIXTURES, name), "wb") as f:
            f.write(der)
    return [(name, name) for name, _ in REAL]


def issue_ours():
    out = subprocess.run(["cargo", "run", "-q", "-p", "allcrypt-tools", "--bin",
                          "dstu4145_certs", FIXTURES], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.split("\n")
    pairs = [tuple(line.split()[1:]) for line in out if line.startswith("cert ")]
    if len(pairs) != 16:
        sys.exit(f"the issuer wrote {len(pairs)} certificates, not 16")
    return pairs


def main():
    rows = []
    for file, issuer in fetch_real() + issue_ours():
        cert_path, issuer_path = (os.path.join(FIXTURES, f) for f in (file, issuer))
        parts = certificate_parts(open(cert_path, "rb").read())
        signer = certificate_parts(open(issuer_path, "rb").read())
        hash_name = HASHES[parts["signature_oid"]]
        little_endian = signer["key_oid"] == DSTU4145_LE
        witnesses = []
        if hash_name == "gost34311":
            witnesses.append("dstu-engine")
        if little_endian:
            witnesses.append("li0ard")
        if not witnesses:
            sys.exit(f"nothing can check {file}")
        results = verdicts(cert_path, issuer_path, witnesses)
        key = results.get("key") or engine(cert_path, issuer_path)[0]
        source = "both" if len(witnesses) == 2 else witnesses[0]
        numbers = " ".join(f"{k}={key[k].lower()}" for k in
                           ("m", "poly", "a", "b", "n", "gx", "gy", "qx", "qy"))
        rows.append(f"cert file={file} issuer={issuer} hash={hash_name} "
                    f"order={'le' if little_endian else 'be'} {numbers} source={source}")

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# DSTU 4145-2002 certificates in tests/keys/ua-x509/: three real ones\n"
                  "# and ours. Written by scripts/make_dstu4145_x509_vectors.py; do not\n"
                  "# edit. Each signature verifies under its issuer's key for the\n"
                  "# witnesses in source (both: dstu-engine and li0ard), which refuse two\n"
                  "# changed copies; the subject key is dstu-engine's reading, big endian.\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
