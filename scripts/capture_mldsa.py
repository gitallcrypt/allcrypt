#!/usr/bin/env python3
"""OpenSSL 3.5's ML-DSA files and handshakes, recorded for offline tests.

`scripts/check_mldsa_witness.py` checks this library against OpenSSL
3.5 live. This records the half of that evidence that can be replayed
without OpenSSL, into two files:

  * **`vectors/ml_dsa_openssl.vec`**, per parameter set:
    - `[key]`: one key in all three of RFC 9881's private key forms as
      OpenSSL writes them (`seed-only`, `priv-only`, `seed-priv`), and
      its public key;
    - `[certificate]`: a self-signed certificate OpenSSL issued for
      that key, and one chain across all three sets - an ML-DSA-87
      root, an ML-DSA-65 intermediate, an ML-DSA-44 leaf - so a
      certificate is checked under a key of a *different* set;
    - `[signature]`: `pkeyutl -sign` over messages of several lengths,
      with and without a FIPS 204 context string.
  * **`tests/transcripts/mldsa_handshakes.txt`**: a TLS 1.3 handshake
    per parameter set between `s_client` and `s_server`, recorded by a
    relay between them, with `s_server -keylogfile`'s secrets. The test
    that reads it decrypts the server's flight and checks OpenSSL's
    CertificateVerify with this library's code.

    python3 scripts/capture_mldsa.py --openssl /opt/openssl35/bin/openssl

**A development tool, not a test.** Keys, signatures and handshakes are
fresh on every run, so every row changes; the counts do not.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from capture_gost_transcripts import Relay, free_port, wait_for_accept  # noqa: E402

VECTORS = os.path.join(ROOT, "vectors", "ml_dsa_openssl.vec")
TRANSCRIPTS = os.path.join(ROOT, "tests", "transcripts", "mldsa_handshakes.txt")

SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
FORMATS = ["seed-only", "priv-only", "seed-priv"]
# No empty message: `pkeyutl -rawin` on an empty file fails with "Could
# not allocate 0 bytes for oneshot sign/verify buffer" in 3.5.4.
MESSAGE_LENGTHS = [1, 64, 1000, 5000]
CONTEXT = b"allcrypt"


def run(openssl, *arguments, data=None):
    return subprocess.run([openssl, *arguments], check=True, capture_output=True,
                          input=data).stdout


def pem_body(path):
    """The base64 of a PEM file on one line - what the reader decodes."""
    with open(path) as handle:
        return "".join(line.strip() for line in handle if not line.startswith("-----"))


def message(length):
    return bytes((7 * i + 3) & 0xFF for i in range(length))


def keys_and_signatures(openssl, work):
    keys, signatures = [], []
    for parameter_set in SETS:
        base = os.path.join(work, parameter_set)
        run(openssl, "genpkey", "-algorithm", parameter_set, "-out", base + ".key")
        record = [("name", parameter_set)]
        for form in FORMATS:
            path = f"{base}.{form}.key"
            run(openssl, "pkey", "-in", base + ".key", "-out", path,
                "-provparam", f"ml-dsa.output_formats={form}")
            record.append((form, pem_body(path)))
        run(openssl, "pkey", "-in", base + ".key", "-pubout", "-out", base + ".pub")
        record.append(("public", pem_body(base + ".pub")))
        keys.append(record)

        for length in MESSAGE_LENGTHS:
            for context in (b"", CONTEXT):
                data_path = os.path.join(work, "message")
                with open(data_path, "wb") as out:
                    out.write(message(length))
                options = ["-pkeyopt", f"hexcontext-string:{context.hex()}"] if context else []
                signature_path = os.path.join(work, "signature")
                run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", base + ".key",
                    "-in", data_path, "-out", signature_path, *options)
                with open(signature_path, "rb") as handle:
                    signature = handle.read()
                # OpenSSL checks its own signature before it is believed
                # about ours.
                run(openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
                    base + ".pub", "-in", data_path, "-sigfile", signature_path,
                    *options)
                signatures.append([("name", parameter_set), ("length", str(length)),
                                   ("context", context.hex()),
                                   ("signature", signature.hex())])
    return keys, signatures


def certificates(openssl, work):
    found = []
    for parameter_set in SETS:
        base = os.path.join(work, parameter_set)
        run(openssl, "req", "-x509", "-key", base + ".key", "-out", base + ".crt",
            "-subj", f"/CN={parameter_set} self-signed", "-days", "3650")
        found.append([("name", f"{parameter_set}-self-signed"),
                      ("certificate", pem_body(base + ".crt"))])

    # A chain across all three sets: each certificate is signed under a
    # key of a different parameter set from its own.
    chain = os.path.join(work, "chain")
    run(openssl, "req", "-x509", "-newkey", "ML-DSA-87", "-nodes",
        "-keyout", chain + "-root.key", "-out", chain + "-root.crt",
        "-subj", "/CN=ML-DSA-87 root", "-days", "3650",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    extensions = os.path.join(work, "extensions.cnf")
    with open(extensions, "w") as out:
        out.write("[ca]\nbasicConstraints=critical,CA:TRUE\n"
                  "keyUsage=critical,keyCertSign,cRLSign\n"
                  "[leaf]\nbasicConstraints=critical,CA:FALSE\n"
                  "keyUsage=critical,digitalSignature\n"
                  "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    for name, set_, issuer, section in [("intermediate", "ML-DSA-65", "root", "ca"),
                                        ("leaf", "ML-DSA-44", "intermediate", "leaf")]:
        cn = "localhost" if name == "leaf" else f"{set_} intermediate"
        run(openssl, "req", "-new", "-newkey", set_, "-nodes",
            "-keyout", f"{chain}-{name}.key", "-out", f"{chain}-{name}.csr",
            "-subj", f"/CN={cn}")
        run(openssl, "x509", "-req", "-in", f"{chain}-{name}.csr",
            "-CA", f"{chain}-{issuer}.crt", "-CAkey", f"{chain}-{issuer}.key",
            "-out", f"{chain}-{name}.crt", "-days", "3650",
            "-extfile", extensions, "-extensions", section)
    run(openssl, "verify", "-x509_strict", "-CAfile", chain + "-root.crt",
        "-untrusted", chain + "-intermediate.crt", chain + "-leaf.crt")
    found.append([("name", "chain"),
                  ("leaf", pem_body(chain + "-leaf.crt")),
                  ("intermediate", pem_body(chain + "-intermediate.crt")),
                  ("root", pem_body(chain + "-root.crt"))])
    return found


def handshake(openssl, work, parameter_set):
    """One TLS 1.3 handshake with an ML-DSA certificate, both ends
    OpenSSL, recorded by a relay."""
    base = os.path.join(work, parameter_set)
    keylog = f"{base}.keylog"
    port = free_port()
    # X25519 and AES-128-GCM-SHA256 pinned: the test is about the
    # signature, and the loader the transcript tests share knows these.
    server = subprocess.Popen(
        [openssl, "s_server", "-accept", str(port), "-tls1_3", "-cert", base + ".crt",
         "-key", base + ".key", "-groups", "X25519",
         "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-keylogfile", keylog,
         "-naccept", "1", "-www"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not wait_for_accept(server):
            raise RuntimeError("s_server never announced ACCEPT")
        relay = Relay(port)
        client = subprocess.run(
            [openssl, "s_client", "-connect", f"127.0.0.1:{relay.port}", "-tls1_3",
             "-groups", "X25519", "-CAfile", base + ".crt", "-quiet", "-ign_eof"],
            input=b"GET / HTTP/1.0\r\n\r\n", capture_output=True, timeout=40)
        relay.thread.join(30)
        if relay.error is not None:
            raise RuntimeError(f"the relay failed: {relay.error}")
        if b"HTTP" not in client.stdout:
            raise RuntimeError(client.stderr.decode(errors="replace")[:300])
        time.sleep(0.2)
        secrets = []
        with open(keylog) as handle:
            for line in handle:
                pieces = line.split()
                if len(pieces) == 3 and not line.startswith("#"):
                    secrets.append(pieces)
        name = parameter_set.lower().replace("-", "")
        fields = [("version", "TLSv1.3"), ("cipher", "TLS_AES_128_GCM_SHA256"),
                  ("to_server", bytes(relay.to_server).hex()),
                  ("to_client", bytes(relay.to_client).hex())]
        fields += [("secret", " ".join(pieces)) for pieces in secrets]
        return name, fields
    finally:
        server.kill()
        server.wait(timeout=10)


def write_vectors(version, sections):
    with open(VECTORS, "w") as out:
        out.write(
            "# ML-DSA keys, certificates and signatures from OpenSSL.\n"
            "#\n"
            "# Generated by scripts/capture_mldsa.py. Do not edit: every value\n"
            "# here is OpenSSL's, and the tests that read it need no OpenSSL.\n"
            "#\n"
            f"# {version}\n"
            "#\n"
            "# PEM bodies are written as one line of base64. `[key]` holds one\n"
            "# key per parameter set in the three forms of RFC 9881 section 6;\n"
            "# `[signature]` messages are byte i = (7 i + 3) mod 256.\n"
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


def write_transcripts(version, captured):
    with open(TRANSCRIPTS, "w") as out:
        out.write(
            "# TLS 1.3 handshakes with ML-DSA certificates, both ends OpenSSL,\n"
            "# recorded by a relay between them by scripts/capture_mldsa.py.\n"
            "#\n"
            f"# {version}\n"
            "#\n"
            "# Same format as handshakes.txt: \"<field> <transcript> <value>\".\n"
            "# Fresh keys and randoms on every capture.\n")
        for name, fields in captured:
            out.write("\n")
            for field, value in fields:
                out.write(f"{field} {name} {value}\n")


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
        keys, signatures = keys_and_signatures(args.openssl, work)
        certs = certificates(args.openssl, work)
        captured = [handshake(args.openssl, work, s) for s in SETS]
    sections = [("key", keys), ("certificate", certs), ("signature", signatures)]
    write_vectors(version, sections)
    write_transcripts(version, captured)
    print(f"wrote {VECTORS}: " + ", ".join(f"{len(r)} {n}" for n, r in sections))
    print(f"wrote {TRANSCRIPTS}: {len(captured)} handshakes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
