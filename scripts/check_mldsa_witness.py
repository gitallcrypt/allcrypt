#!/usr/bin/env python3
"""ML-DSA certificates and TLS 1.3 signatures, against OpenSSL 3.5.

Nothing in the test suite has a second implementation of ML-DSA in
X.509 or TLS: the OpenSSL the pytests run against is 3.0, and
python-cryptography has no ML-DSA. OpenSSL 3.5 has both, so this
script drives, for each of ML-DSA-44, -65 and -87:

  * **our client against `openssl s_server`** holding an ML-DSA
    certificate OpenSSL made - so our verifier checks OpenSSL's
    certificate signature and its CertificateVerify;
  * **`openssl s_client` against our server**, holding a certificate
    *our* CA issued, with `-verify_return_error` and that CA as its
    only root - so OpenSSL checks our certificate signature, our
    SubjectPublicKeyInfo, and our CertificateVerify;
  * **`openssl verify`** on the chain our CA issued, which judges the
    certificates without a handshake in the way.

Each connection carries application data both ways after the
handshake, because only records that decrypt say the peer accepted
the Finished.

    python3 scripts/check_mldsa_witness.py --openssl /opt/openssl35/bin/openssl

**A development tool, not a test.** It needs an OpenSSL 3.5 binary and
loopback sockets; nothing in the test suite runs it. The offline half
of the same evidence is `vectors/ml_dsa_openssl.vec` and
`tests/transcripts/mldsa_handshakes.txt`, written by
`scripts/capture_mldsa.py`. The result is recorded in
`docs/post-quantum.md` with the OpenSSL version it ran against.
"""

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "python"))
sys.path.insert(0, HERE)

import allcrypt  # noqa: E402

from check_pq_witness import free_port, pump  # noqa: E402

SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SCHEMES = {"ML-DSA-44": "mldsa44", "ML-DSA-65": "mldsa65", "ML-DSA-87": "mldsa87"}
MESSAGE = b"signed by a lattice\n"
VALID = ("20250101000000Z", "20350101000000Z")


def run(*command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, **kwargs)


def openssl_identity(openssl, parameter_set, directory):
    """A self-signed certificate and key, both made by OpenSSL."""
    key = os.path.join(directory, f"{parameter_set}.key")
    cert = os.path.join(directory, f"{parameter_set}.crt")
    run(openssl, "req", "-x509", "-newkey", parameter_set, "-keyout", key,
        "-out", cert, "-nodes", "-subj", "/CN=localhost", "-days", "30",
        "-addext", "subjectAltName=DNS:localhost")
    return cert, key


def our_client(openssl, parameter_set, directory):
    """Our client, OpenSSL's server and certificate."""
    cert, key = openssl_identity(openssl, parameter_set, directory)
    port = free_port()
    server = subprocess.Popen(
        [openssl, "s_server", "-accept", f"127.0.0.1:{port}", "-tls1_3",
         "-cert", cert, "-key", key, "-rev", "-quiet"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=2)
                break
            except OSError:
                time.sleep(0.1)
        else:
            return False, "s_server did not start"
        roots = allcrypt.TrustStore()
        with open(cert) as handle:
            roots.add_pem(handle.read())
        client = allcrypt.TlsClient("localhost", roots, now=int(time.time()),
                                    min_version="TLSv1.3", max_version="TLSv1.3")
        deadline = time.time() + 20
        with sock:
            pump(sock, client, lambda: client.established, deadline)
            client.write(MESSAGE)
            received = bytearray()

            def got_reply():
                received.extend(client.take_incoming())
                return b"\n" in received
            pump(sock, client, got_reply, deadline)
        expected = MESSAGE.rstrip(b"\n")[::-1]
        ok = client.certificate_verified and expected in bytes(received)
        return ok, (f"verified={client.certificate_verified} group={client.named_group} "
                    f"reply={'ok' if expected in bytes(received) else bytes(received)!r}")
    except Exception as error:  # noqa: BLE001 - reported, not hidden
        return False, f"{type(error).__name__}: {error}"
    finally:
        server.kill()
        server.wait()


def our_issued_chain(parameter_set, directory):
    """A CA and a leaf for localhost, both ours, as files and objects."""
    ca = allcrypt.CertificateAuthority("allcrypt ML-DSA test CA", *VALID,
                                       key_type=parameter_set)
    leaf, seed = ca.issue("localhost", *VALID)
    ca_path = os.path.join(directory, f"our-{parameter_set}-ca.pem")
    leaf_path = os.path.join(directory, f"our-{parameter_set}-leaf.pem")
    with open(ca_path, "w") as out:
        out.write(ca.certificate_pem)
    with open(leaf_path, "w") as out:
        out.write(allcrypt.pem_wrap(leaf))
    key = allcrypt.MlDsaKey.from_seed(parameter_set, seed)
    return ca, leaf, key, ca_path, leaf_path


def openssl_verifies_our_chain(openssl, chain):
    _, _, _, ca_path, leaf_path = chain
    result = subprocess.run([openssl, "verify", "-x509_strict", "-CAfile", ca_path,
                             leaf_path], capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def our_server(openssl, parameter_set, chain):
    """OpenSSL's client, verifying against our CA; our server, our leaf."""
    _, leaf, key, ca_path, _ = chain
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    client = subprocess.Popen(
        [openssl, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3",
         "-servername", "localhost", "-verify_return_error", "-verify_hostname",
         "localhost", "-CAfile", ca_path, "-sigalgs", SCHEMES[parameter_set],
         "-brief", "-ign_eof"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        listener.settimeout(10)
        sock, _ = listener.accept()
        server = allcrypt.TlsServer([leaf], key, now=int(time.time()),
                                    min_version="TLSv1.3")
        deadline = time.time() + 20
        with sock:
            pump(sock, server, lambda: server.established, deadline)
            client.stdin.write(MESSAGE)
            client.stdin.flush()
            received = bytearray()

            def got_line():
                received.extend(server.take_incoming())
                return b"\n" in received
            pump(sock, server, got_line, deadline)
            server.write(bytes(received)[::-1].lstrip(b"\n") + b"\n")
            sock.sendall(server.take_outgoing())
            time.sleep(0.5)
        client.stdin.close()
        output = client.stdout.read().decode(errors="replace")
        signature = next((line.strip() for line in output.splitlines()
                          if "Signature type" in line), "")
        verification = next((line.strip() for line in output.splitlines()
                             if "Verification" in line), "")
        echoed = MESSAGE.rstrip(b"\n")[::-1].decode() in output
        ok = (bytes(received) == MESSAGE and echoed
              and parameter_set.replace("-", "").lower() in signature.replace("-", "").lower()
              and "OK" in verification)
        return ok, f"{signature!r} {verification!r} data={'ok' if echoed else 'missing'}"
    except Exception as error:  # noqa: BLE001
        return False, f"{type(error).__name__}: {error}"
    finally:
        listener.close()
        try:
            client.kill()
        except OSError:
            pass
        client.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", default="/opt/openssl35/bin/openssl")
    args = parser.parse_args()
    # A prefix build's libraries are next to it, not on the loader's path.
    prefix = os.path.dirname(os.path.dirname(os.path.abspath(args.openssl)))
    libraries = [os.path.join(prefix, d) for d in ("lib64", "lib")
                 if os.path.isdir(os.path.join(prefix, d))]
    os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(
        libraries + [os.environ.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    version = run(args.openssl, "version").stdout.decode().strip()
    print(f"witness: {version}")
    failures = 0
    rows = 0
    with tempfile.TemporaryDirectory() as directory:
        # A prefix build has no openssl.cnf, and `req` will not run
        # without one; this is the least it accepts.
        config = os.path.join(directory, "openssl.cnf")
        with open(config, "w") as out:
            out.write("[req]\ndistinguished_name = dn\n[dn]\n")
        os.environ["OPENSSL_CONF"] = config
        for parameter_set in SETS:
            chain = our_issued_chain(parameter_set, directory)
            for label, check in [
                    ("our client, OpenSSL's server and certificate",
                     lambda: our_client(args.openssl, parameter_set, directory)),
                    ("openssl verify, our CA and leaf",
                     lambda: openssl_verifies_our_chain(args.openssl, chain)),
                    ("OpenSSL's client, our server and certificate",
                     lambda: our_server(args.openssl, parameter_set, chain))]:
                ok, detail = check()
                rows += 1
                failures += not ok
                print(f"  {'ok  ' if ok else 'FAIL'} {parameter_set:10} {label}: {detail}")
    print(f"{rows - failures} of {rows} passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
