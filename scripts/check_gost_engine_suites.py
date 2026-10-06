#!/usr/bin/env python3
"""Run this library's TLS client against gost-engine's own server, one
GOST suite at a time. A development tool, not a test.

    OPENSSL_ENGINES=/path/to/gost-engine/build/bin \
        python3 scripts/check_gost_engine_suites.py

    python3 scripts/check_gost_engine_suites.py --suite magma_ctr_omac
    python3 scripts/check_gost_engine_suites.py --keep   # keep the work dir

## Why this exists, given everything else that already does

Three things test the GOST suites and none of them does what this does.

  * `pytests/` and `cargo test` hand our client to **our own server**.
    Both ends are one reading of RFC 9189, so they agree on every
    mistake that reading contains. That is not interoperability, it is
    self-consistency.
  * `tests/test_gost_transcript.rs` replays **recorded** handshakes
    between two OpenSSL processes. Those bytes are somebody else's, which
    makes them worth a great deal - but our client is not in them. It
    decrypts records it never negotiated and answers nothing.
  * `scripts/check_live.py --gost` puts our client in front of real
    CryptoPro servers, which is the strongest check there is, and it
    reaches **one** suite: all three endpoints choose
    `KUZNYECHIK_CTR_OMAC`. Magma, IMIT, the LEGACY spelling and the 2001
    suite have never been spoken to anything but ourselves, and they are
    a different block cipher, a different MAC, a different key
    derivation and a different signature algorithm respectively.

This closes that: our client, driving a full handshake, against a server
that is not ours, on every GOST suite gost-engine implements - offline,
over loopback, repeatable, with nothing recorded in between.

**And it verifies the chain.** `check_live.py --gost` deliberately turns
verification off, because no trust store here carries a Russian test CA,
so our verifier has never been asked to check a GOST signature on a
certificate it did not issue. Here the CA is one gost-engine made, we
trust it explicitly, and the row fails if our verifier cannot follow it.
That is the only check of GOST certificate verification against a foreign
issuer in this repository.

## What it needs

A built gost-engine, which this does not build and will not download:

    git clone --branch v3.0.3 https://github.com/gost-engine/engine gost-engine
    cd gost-engine && git submodule update --init --recursive --depth 1
    cmake -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr
    cmake --build build -j
    export OPENSSL_ENGINES=$PWD/build/bin

Everything here is loopback and nothing fetches anything, but it is still
a script rather than a test: it needs a C library built from a tag, and a
gate that depends on that is a gate that fails on a machine which is
perfectly fine. `pytests/conftest.py` blocks non-loopback connections and
this file is not run by it.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))

try:
    import allcrypt_ssl
except ImportError as reason:                    # pragma: no cover
    sys.exit(f"build the module first "
             f"(python3 scripts/build_python.py): {reason}")


#: `(our name, gost-engine's name, which certificate, extra cipher terms)`
#:
#: The certificate tag matters as much as the suite. `2012xa` is a
#: GOST R 34.10-2012 256 bit key on **CryptoPro-XchA**, chosen rather than
#: the canonical `A`: two of CryptoPro's three public endpoints spell
#: their key that way, and a client that rebuilds the ephemeral key's
#: parameter-set OID from the curve instead of echoing the peer's is
#: refused by all of them with `decode_error`. Generating the server key
#: on the canonical spelling would make every row here pass on a client
#: with that bug - which is what the first five transcript captures did.
#:
#: **The four MGM suites are absent on purpose.** RFC 9367 defines them
#: for TLS 1.3, and neither OpenSSL 3.0 nor gost-engine 3.0.3 has a TLS
#: 1.3 GOST suite at all: there is no name to pass to `-cipher`. So those
#: four have no differential partner here, and saying so is better than a
#: row that fails for a reason that is not about us. They are covered
#: against the engine at the primitive level instead, by
#: `vectors/gost_engine.vec` and `tests/test_gost_engine_vectors.rs`,
#: which reach MGM through `scripts/gost_engine_probe.c`.
SUITES = [
    ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
     "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC", "2012xa", ""),
    ("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
     "GOST2012-MAGMA-MAGMAOMAC", "2012xa", ""),
    ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
     "GOST2012-GOST8912-GOST8912", "2012xa", ""),
    ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT_LEGACY",
     "LEGACY-GOST2012-GOST8912-GOST8912", "2012xa", ""),
    # **`@SECLEVEL=0`, and only here.** This chain is signed with
    # GOST R 34.11-94, and OpenSSL's default security level refuses to
    # *load* such a certificate: `ca md too weak`. That is a policy about
    # the CA's digest, not about the suite, and this library exists for
    # the algorithms other people's policies have switched off.
    ("TLS_GOSTR341001_WITH_28147_CNT_IMIT",
     "GOST2001-GOST89-GOST89", "2001a", "@SECLEVEL=0"),
    # The 512 bit key, which is a different signature algorithm on the
    # certificate and the same suite on the wire. Worth its own row
    # because `tlsgost-512.cryptopro.ru` is a real deployment of it.
    ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
     "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC", "2012-512", ""),
]

#: The GOST suites this library has that no row above can reach.
#:
#: Listed rather than left out, so that "6 of 6 worked" cannot be read as
#: complete coverage of a library that has ten GOST rows' worth of suites.
UNREACHABLE = [
    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
]

#: `(tag, genpkey algorithm, paramset, digest)`
#:
#: The digest is the CA's signing digest and is **not** a free choice: a
#: 2001 key cannot sign with Streebog, so `md_gost94` is the only option
#: there, and it is what makes `@SECLEVEL=0` necessary above.
CERTIFICATES = [
    ("2012xa", "gost2012_256", "XA", "md_gost12_256"),
    ("2012-512", "gost2012_512", "A", "md_gost12_512"),
    ("2001a", "gost2001", "A", "md_gost94"),
]

#: What the client sends once the handshake is done.
#:
#: **Long enough to cross a re-keying boundary.** CryptoPro key meshing
#: fires after 1024 octets under the 28147 suites and TLSTREE re-keys the
#: CTR-OMAC ones, so a request that fits in one short record never
#: exercises the part of the record layer where the key changes. This is
#: a real HTTP request because `s_server -www` answers those.
REQUEST = (b"GET /" + b"a" * 1400 + b" HTTP/1.0\r\n"
           b"Host: localhost\r\nConnection: close\r\n\r\n")


def engine_environment():
    """The environment for every `openssl` call, and the check that the
    engine is actually there.

    Checked once, loudly, rather than letting five servers each fail to
    start with a different message.
    """
    env = dict(os.environ)
    engines = env.get("OPENSSL_ENGINES")
    if not engines:
        sys.exit("set OPENSSL_ENGINES to a built gost-engine's bin "
                 "directory - see this file's header")
    if not os.path.isdir(engines):
        sys.exit(f"OPENSSL_ENGINES={engines} is not a directory")
    probe = subprocess.run(["openssl", "engine", "-t", "gost"], env=env,
                           capture_output=True, text=True)
    if "available" not in probe.stdout:
        sys.exit(f"openssl cannot load the gost engine from {engines}:\n"
                 f"{probe.stdout}{probe.stderr}")
    return env


def openssl(arguments, env, quiet=True):
    """One `openssl` call, with its output kept for the failure message."""
    done = subprocess.run(["openssl"] + arguments, env=env,
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(arguments)} failed:\n"
                           f"{done.stdout}{done.stderr}")
    if not quiet:
        print(done.stdout)
    return done.stdout


def make_chain(work, env, tag, algorithm, paramset, digest):
    """A CA and a `localhost` server certificate under it.

    **A real two-certificate chain, not a self-signed leaf.** A
    self-signed certificate is verified by checking a signature against
    the key inside it, which a verifier that ignored the signature
    entirely would also pass. Here the leaf is signed by a separate CA
    key, so following the chain is the only way through - and the CA's
    signature is a GOST signature produced by somebody else's code, which
    is the whole point of doing this against the engine.
    """
    paths = {name: os.path.join(work, f"{name}-{tag}.pem")
             for name in ("cakey", "cacrt", "key", "crt", "csr")}
    extensions = os.path.join(work, f"ext-{tag}.cnf")

    openssl(["genpkey", "-engine", "gost", "-algorithm", algorithm,
             "-pkeyopt", f"paramset:{paramset}", "-out", paths["cakey"]], env)
    openssl(["req", "-engine", "gost", "-new", "-x509", "-key", paths["cakey"],
             "-" + digest, "-subj", f"/CN=allcrypt {tag} CA",
             "-days", "3650", "-out", paths["cacrt"]], env)

    openssl(["genpkey", "-engine", "gost", "-algorithm", algorithm,
             "-pkeyopt", f"paramset:{paramset}", "-out", paths["key"]], env)
    openssl(["req", "-engine", "gost", "-new", "-key", paths["key"],
             "-" + digest, "-subj", "/CN=localhost", "-out", paths["csr"]], env)
    with open(extensions, "w") as handle:
        handle.write("subjectAltName=DNS:localhost\n"
                     "basicConstraints=critical,CA:FALSE\n"
                     "keyUsage=critical,digitalSignature,keyEncipherment,"
                     "keyAgreement\n"
                     "extendedKeyUsage=serverAuth\n")
    openssl(["x509", "-engine", "gost", "-req", "-in", paths["csr"],
             "-CA", paths["cacrt"], "-CAkey", paths["cakey"], "-" + digest,
             "-extfile", extensions, "-days", "3650",
             "-set_serial", "4919", "-out", paths["crt"]], env)
    return paths


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Server:
    """One `s_server`, offering exactly one suite.

    **One server per suite rather than one server offering all of them.**
    A server with several suites enabled and a client restricted to one
    conflates "the engine does not implement this" with "the engine chose
    something else", and the first run of this idea did exactly that: the
    log said `no shared cipher` for five rows and said nothing at all
    about three others that closed without an alert.

    `-www` rather than a pipe on stdin: `s_server` exits when its stdin
    closes, and a server that has exited while the client is still
    connecting produces a confusing read error rather than a refusal.
    """

    def __init__(self, port, suite, paths, extra, env, log):
        self.port = port
        self.log = open(log, "w")
        self.process = subprocess.Popen(
            ["openssl", "s_server", "-engine", "gost",
             "-accept", f"127.0.0.1:{port}",
             "-cert", paths["crt"], "-key", paths["key"],
             "-CAfile", paths["cacrt"],
             "-cipher", suite + extra, "-www", "-tls1_2"],
            env=env, stdout=self.log, stderr=subprocess.STDOUT)
        self.log_path = log

    def wait_until_listening(self, seconds=10):
        """Wait for `s_server` to say ACCEPT, not for the port to open.

        The port is open before the engine has finished loading the key,
        so connecting on a port check races the server and fails in a way
        that looks like a handshake problem.
        """
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.process.poll() is not None:
                return False
            with open(self.log_path) as handle:
                if "ACCEPT" in handle.read():
                    return True
            time.sleep(0.1)
        return False

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.log.close()

    def output(self):
        with open(self.log_path) as handle:
            return handle.read()


def speak(port, suite, ca_file, verify):
    """Our client, restricted to `suite`, against the server on `port`.

    Returns `(ok, detail)`. The checks in here are what make a row mean
    something beyond "no exception was raised":

      * the suite negotiated is the one asked for, because a restriction
        that silently failed would make every row measure the same suite;
      * a **reply** arrives, because a handshake that completes and a
        record layer that works are different claims - the Finished
        message is one short record in each direction and says nothing
        about the re-keying boundary a 1.4 kB request crosses;
      * and the certificate's parameter set is reported, since that is
        the field that decides whether the ClientKeyExchange is
        acceptable and the curve name cannot express it.
    """
    context = allcrypt_ssl.create_legacy_context()
    context.set_ciphers(suite)
    if verify:
        context.load_verify_locations(cafile=ca_file)
    else:
        context.check_hostname = False
        context.verify_mode = allcrypt_ssl.CERT_NONE

    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    try:
        with context.wrap_socket(raw, server_hostname="localhost") as sock:
            negotiated = sock.cipher()[0]
            if negotiated != suite:
                return False, f"asked for {suite}, negotiated {negotiated}"
            certificate = sock.getpeercert()
            sock.sendall(REQUEST)
            body = b""
            while True:
                chunk = sock.recv(16384)
                if not chunk:
                    break
                body += chunk
            if not body.startswith(b"HTTP/"):
                return False, (f"handshake fine, but the reply was "
                               f"{body[:60]!r}")
            if len(body) < 200:
                return False, f"reply was only {len(body)} bytes"
            return True, (f"{sock.version()}  {len(body)} bytes back  "
                          f"key={certificate['publicKeyType']} "
                          f"paramset="
                          f"{certificate.get('publicKeyParameterSet')}")
    finally:
        raw.close()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--suite", action="append",
                        help="only suites whose name contains this "
                             "(case-insensitive). Repeatable.")
    parser.add_argument("--keep", action="store_true",
                        help="keep the working directory and say where")
    parser.add_argument("--no-verify", action="store_true",
                        help="do not verify the chain, to separate a "
                             "verification failure from a handshake one")
    arguments = parser.parse_args()

    env = engine_environment()
    work = tempfile.mkdtemp(prefix="allcrypt-gost-suites-")
    failures = []
    skipped = []
    worked = []

    try:
        print("building keys and certificates with the engine")
        chains = {}
        for tag, algorithm, paramset, digest in CERTIFICATES:
            chains[tag] = make_chain(work, env, tag, algorithm, paramset,
                                     digest)
            print(f"  {tag:<10} {algorithm} paramset {paramset} "
                  f"signed with {digest}")

        print("\nour client against gost-engine's s_server, one suite each")
        for our_name, their_name, tag, extra in SUITES:
            if arguments.suite and not any(
                    want.lower() in our_name.lower() or
                    want.lower() in their_name.lower()
                    for want in arguments.suite):
                continue
            label = our_name.replace("TLS_GOSTR341112_256_WITH_", "") \
                            .replace("TLS_GOSTR341001_WITH_", "2001/")
            label = f"{label} [{tag}]"
            port = free_port()
            server = Server(port, their_name, chains[tag], extra, env,
                            os.path.join(work, f"s_server-{port}.log"))
            try:
                if not server.wait_until_listening():
                    skipped.append((label, "s_server did not start"))
                    print(f"  [ skip ] {label:<44} s_server did not start")
                    print(f"           {server.output().strip()[:300]}")
                    continue
                try:
                    ok, detail = speak(port, our_name, chains[tag]["cacrt"],
                                       not arguments.no_verify)
                except Exception as reason:      # noqa: BLE001
                    ok = False
                    detail = f"{type(reason).__name__}: {reason}"
            finally:
                server.close()

            if ok:
                worked.append(label)
                print(f"  [  ok  ] {label:<44} {detail}")
            else:
                failures.append((label, detail, server.output()))
                print(f"  [ FAIL ] {label:<44} {detail}")

        print(f"\n{len(worked)} of {len(worked) + len(failures) + len(skipped)}"
              f" rows worked")
        for label, detail, log in failures:
            print(f"\n  FAIL {label}\n    {detail}")
            tail = [line for line in log.splitlines()
                    if "error" in line.lower() or "ACCEPT" not in line][-6:]
            for line in tail:
                print(f"    s_server: {line}")
        for label, why in skipped:
            print(f"\n  skip {label}: {why}")

        # **The MGM suites, said out loud.** Four of this library's nine
        # GOST suites cannot appear above, because there is no TLS 1.3
        # GOST suite in OpenSSL or gost-engine to negotiate against. A
        # summary that counted "6 of 6" without saying so would report
        # complete coverage of two thirds of them.
        print("\n  not reachable this way at all, and why:")
        for name in UNREACHABLE:
            print(f"    {name}")
        print("    RFC 9367 defines these for TLS 1.3, and neither OpenSSL 3.0")
        print("    nor gost-engine 3.0.3 has any TLS 1.3 GOST suite to offer -")
        print("    so there is no name to put after -cipher and no handshake to")
        print("    have. Their ciphers and MACs are checked against the engine")
        print("    as primitives instead: vectors/gost_engine.vec, written by")
        print("    scripts/make_gost_vectors.py via scripts/gost_engine_probe.c.")
    finally:
        if arguments.keep:
            print(f"\nworking directory kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
