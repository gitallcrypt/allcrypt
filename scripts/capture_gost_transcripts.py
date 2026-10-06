#!/usr/bin/env python3
"""Capture real GOST TLS handshakes into tests/transcripts/gost_handshakes.txt.

`scripts/capture_transcripts.py` does this for the suites Python's `ssl`
can speak. It cannot speak any of the GOST ones, and until OpenSSL's
gost-engine was built here nothing on this machine could - so
`tests/test_gost_handshake.rs` drives a whole handshake against a server
written in the same file, and `docs/pitfalls.md` says what that settles
and what it cannot:

> It settles the *wiring* - directions, ordering, which key comes from
> where - and cannot settle byte orders, since both ends are ours.

This closes that. **Both ends here are OpenSSL with gost-engine**, and
every byte that crossed is recorded through a relay that sits between
them. With `s_server -keylogfile` giving up the master secret, the
fixture is not only a framing sample: `tests/test_gost_transcript.rs`
derives the key block from that secret and **decrypts records the
engine encrypted**. Nothing of ours is anywhere in the capture.

That is the only thing that can settle the byte orders. Our key
expansion, our CTR-ACPKM keystream, our OMAC, our TLSTREE and our
CryptoPro meshing are each self-consistent when wrong, and a handshake
between two copies of this library agrees with itself whichever way
round any of them is.

    python3 scripts/capture_gost_transcripts.py --engines ~/gost-engine/build/bin

**This is a development tool and not a test.** It needs the engine, the
`openssl` binary and loopback sockets; the test that reads its output
needs none of those. No test in this repository uses the network, and
`pytests/conftest.py` raises on any connection to anything but loopback.

## What is captured

Four suites, which is every one this OpenSSL and this engine will
negotiate:

  * `GOST2012-KUZNYECHIK-KUZNYECHIKOMAC` (0xC100)
  * `GOST2012-MAGMA-MAGMAOMAC` (0xC101)
  * `GOST2012-GOST8912-GOST8912` (0xC102, CNT_IMIT)
  * `LEGACY-GOST2012-GOST8912-GOST8912` (0xFF85, the CryptoPro code point)

and `GOST2001-GOST89-GOST89` (0x0081), which needs a GOST R
34.10-**2001** certificate. That one also needs `@SECLEVEL=0`: its chain
is signed with GOST R 34.11-94 and OpenSSL's default security level
refuses to load such a certificate at all - `ca md too weak`, a policy
about the CA's digest rather than about the suite. Lowering it is the
right answer here, because this library exists for the algorithms other
people's policies have turned off.

Each capture also sends application data in both directions **after** the
handshake, because the second record is where every re-keying mistake
lives: CTR-ACPKM starts a fresh keystream per record, CryptoPro meshing
fires after 1024 octets, and TLSTREE changes the record key at sequence
boundaries. A capture of a handshake alone would see none of them.

## Determinism

None. Every capture has fresh keys, fresh randoms and a fresh
certificate, so re-running this rewrites the whole file. That is the
same arrangement `capture_transcripts.py` has and for the same reason -
what matters is that the suites listed are the ones we want, not that
the bytes are stable.
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_OUTPUT = os.path.join(ROOT, "tests", "transcripts",
                              "gost_handshakes.txt")

# `(name, suite, which certificate, extra cipher-string terms)`.
#
# The name is what the fixture and the Rust test call it; the suite is
# OpenSSL's own name for it, and is what goes into the fixture so that
# `suites::by_name` resolves it - the extra terms are for the command
# line only and are not recorded.
#
# **`@SECLEVEL=0` for the 2001 suite.** Its chain is signed with GOST R
# 34.11-94, and OpenSSL's default security level refuses to *load* such
# a certificate at all: `SSL_CTX_use_certificate: ca md too weak`. That
# is a policy about the CA's digest rather than anything about the
# suite, and this library exists for exactly the algorithms other
# people's policies have turned off - so it is lowered here rather than
# the suite being dropped.
SUITES = [
    ("kuznyechik_ctr_omac", "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC", "2012", ""),
    ("magma_ctr_omac", "GOST2012-MAGMA-MAGMAOMAC", "2012", ""),
    ("gost28147_cnt_imit", "GOST2012-GOST8912-GOST8912", "2012", ""),
    ("gost28147_cnt_imit_legacy", "LEGACY-GOST2012-GOST8912-GOST8912",
     "2012", ""),
    ("gost2001_cnt_imit", "GOST2001-GOST89-GOST89", "2001", "@SECLEVEL=0"),
    # **The same suite on two other spellings of the same curve**, which
    # is here because of a bug a real server found.
    #
    # `paramset:A` is `id-GostR3410-2001-CryptoPro-A-ParamSet`, and the
    # identical curve is also named `id-GostR3410-2001-CryptoPro-XchA-
    # ParamSet` (RFC 4357's exchange set) and `id-tc26-gost-3410-12-256-
    # paramSetB` (TC 26's renumbering, shifted by one). A client that
    # rebuilt the ephemeral key's OID from the curve answered a server on
    # any of these with the CryptoPro spelling, and CryptoPro refuses that
    # with `decode_error`.
    #
    # The five rows above cannot see it: gost-engine's own `genpkey`
    # writes the canonical OID, so its certificates and ours agree by
    # accident. These two make the engine demonstrate the echo on a
    # spelling it did not choose - which is the difference between a test
    # of the rule and a hand-built illustration of it.
    ("kuznyechik_ctr_omac_xcha", "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC",
     "2012-xcha", ""),
    ("kuznyechik_ctr_omac_tc26_b", "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC",
     "2012-tc26-b", ""),
]

# Sent by the client after the handshake, then echoed by `s_server`.
#
# **Long enough to cross a re-keying boundary.** CryptoPro key meshing
# fires after 1024 octets of data, and a capture whose records are all
# short is a capture that never re-keys - which is exactly the half of
# `meshing.rs` that is right for the first 1024 octets and wrong
# afterwards. Sent as several writes so it lands in several records.
REQUEST_PIECES = [b"first\n", bytes(700) + b"\n", bytes(700) + b"\n",
                  b"last\n"]


def openssl(args, env, **kwargs):
    done = subprocess.run(["openssl"] + args, env=env, capture_output=True,
                          **kwargs)
    if done.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args[:2])}: "
                           f"{done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def make_chain(env, work, algorithm, paramset, tag):
    """A GOST CA and a leaf for `localhost`, both signed by the engine.

    Generated rather than committed: a certificate is an input here, and
    the thing being tested is the record layer, not the parser. The
    certificates in `vectors/live/` are the ones kept for their own
    sake.
    """
    ca_key = os.path.join(work, f"ca-{tag}.key")
    ca_crt = os.path.join(work, f"ca-{tag}.crt")
    key = os.path.join(work, f"srv-{tag}.key")
    crt = os.path.join(work, f"srv-{tag}.crt")
    csr = os.path.join(work, f"srv-{tag}.csr")
    ext = os.path.join(work, f"ext-{tag}.cnf")
    digest = "md_gost12_256" if algorithm != "gost2001" else "md_gost94"

    openssl(["genpkey", "-engine", "gost", "-algorithm", algorithm,
             "-pkeyopt", f"paramset:{paramset}", "-out", ca_key], env)
    openssl(["req", "-engine", "gost", "-new", "-x509", "-key", ca_key,
             "-" + digest, "-subj", "/CN=allcrypt gost transcript CA",
             "-days", "3650", "-out", ca_crt], env)

    openssl(["genpkey", "-engine", "gost", "-algorithm", algorithm,
             "-pkeyopt", f"paramset:{paramset}", "-out", key], env)
    openssl(["req", "-engine", "gost", "-new", "-key", key, "-" + digest,
             "-subj", "/CN=localhost", "-out", csr], env)
    with open(ext, "w") as handle:
        handle.write("subjectAltName=DNS:localhost\n"
                     "basicConstraints=critical,CA:FALSE\n"
                     "keyUsage=critical,digitalSignature,keyEncipherment,"
                     "keyAgreement\n"
                     "extendedKeyUsage=serverAuth\n")
    openssl(["x509", "-engine", "gost", "-req", "-in", csr, "-CA", ca_crt,
             "-CAkey", ca_key, "-" + digest, "-extfile", ext,
             "-days", "3650", "-set_serial", "4919", "-out", crt], env)
    return ca_crt, crt, key


class Relay:
    """A one-connection TCP relay that keeps every byte.

    The recording has to sit **between** the two OpenSSL processes
    rather than inside either: an `s_client -msg` dump is OpenSSL's
    rendering of its own bytes, and what this fixture is for is the
    bytes themselves. A relay also gets the two directions separated
    without having to reassemble them from a merged log.
    """

    def __init__(self, upstream_port):
        self.upstream_port = upstream_port
        self.to_server = bytearray()
        self.to_client = bytearray()
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _pump(self, source, sink, record):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                record += data
                sink.sendall(data)
        except OSError:
            pass
        finally:
            # Half-close so the other side sees the end rather than
            # waiting. A relay that only closes both at the end turns a
            # clean shutdown into a timeout.
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _run(self):
        try:
            self.listener.settimeout(20)
            client, _ = self.listener.accept()
            upstream = socket.create_connection(
                ("127.0.0.1", self.upstream_port), timeout=20)
            with client, upstream:
                up = threading.Thread(target=self._pump,
                                      args=(client, upstream, self.to_server))
                down = threading.Thread(target=self._pump,
                                        args=(upstream, client,
                                              self.to_client))
                up.start()
                down.start()
                up.join(30)
                down.join(30)
        except Exception as reason:                  # noqa: BLE001
            self.error = reason
        finally:
            self.listener.close()


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_accept(server, seconds=20):
    """Wait until `s_server` prints ACCEPT, rather than probing the port.

    **`-naccept 1` counts connections**, so a connect-and-close to see
    whether it is listening spends the one accept and the real client
    then gets nothing. `pytests/test_tls13_early_data.py` documents the
    same trap. Reading its own announcement is the only way that costs
    nothing.
    """
    deadline = time.time() + seconds
    while time.time() < deadline:
        line = server.stdout.readline()
        if not line:
            break
        if b"ACCEPT" in line:
            return True
    return False


def capture(env, work, name, suite, extra, ca_crt, crt, key):
    """`(fields, note)` for one suite; `fields` is None if it did not
    negotiate, with the note saying so rather than raising - the 2001
    suite is expected to be unavailable on some builds."""
    port = free_port()
    keylog = os.path.join(work, f"{name}.keylog")
    if os.path.exists(keylog):
        os.remove(keylog)

    # `-www` rather than a stdin pipe: `s_server` exits when its stdin
    # reaches EOF, which can be before the client has connected, and
    # `-www` needs no stdin at all. It also answers with a status page
    # of a couple of kilobytes across several records, which is what
    # makes the server's direction worth decrypting - a single short
    # record exercises none of the re-keying.
    server = subprocess.Popen(
        ["openssl", "s_server", "-engine", "gost", "-accept", str(port),
         "-cert", crt, "-key", key, "-CAfile", ca_crt,
         "-cipher", suite + extra,
         "-tls1_2", "-keylogfile", keylog, "-naccept", "1", "-www"],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    try:
        if not wait_for_accept(server):
            return None, "s_server never announced ACCEPT"

        relay = Relay(port)
        request = b"GET / HTTP/1.0\r\n" + b"".join(
            b"X-Padding-%d: %s\r\n" % (n, b"p" * 700) for n in range(3)
        ) + b"\r\n"
        client = subprocess.run(
            ["openssl", "s_client", "-engine", "gost",
             "-connect", f"127.0.0.1:{relay.port}", "-CAfile", ca_crt,
             "-cipher", suite + extra, "-tls1_2", "-quiet", "-ign_eof"],
            env=env, input=request, capture_output=True, timeout=40)
        relay.thread.join(30)
        if relay.error is not None:
            return None, f"the relay failed: {relay.error}"

        message = client.stderr.decode(errors="replace")
        if b"HTTP" not in client.stdout and "Verify return code: 0" not in message:
            return None, f"the handshake did not complete: {message.strip()[:200]}"
        if not os.path.exists(keylog):
            return None, "no key log was written"

        secrets = []
        with open(keylog) as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pieces = line.split()
                if len(pieces) == 3:
                    secrets.append(tuple(pieces))
        if not secrets:
            return None, "the key log has no secrets in it"

        if not relay.to_server or not relay.to_client:
            return None, "a direction recorded nothing"

        fields = [("version", "TLSv1.2"), ("cipher", suite),
                  ("to_server", bytes(relay.to_server).hex()),
                  ("to_client", bytes(relay.to_client).hex())]
        for label, random, secret in secrets:
            fields.append(("secret", f"{label} {random} {secret}"))
        return fields, (f"{len(relay.to_server)} bytes up, "
                        f"{len(relay.to_client)} down")
    finally:
        server.kill()
        server.wait(timeout=10)


HEADER = """\
# Real GOST TLS handshakes, captured by scripts/capture_gost_transcripts.py.
#
# **Both ends are OpenSSL with gost-engine**, recorded by a relay that sat
# between them, so every byte here was produced by an implementation that
# is not ours. `s_server -keylogfile` gives up the master secret, which
# turns this from a framing sample into the one thing that can settle the
# byte orders: tests/test_gost_transcript.rs derives the key block from
# that secret and decrypts records the engine encrypted.
#
# tests/test_gost_handshake.rs is the other half of this. It drives a whole
# handshake against a server written in the same file, which settles the
# wiring - directions, ordering, which key comes from where - and cannot
# settle a byte order, because both ends of it are ours.
#
# The client sends a padded request and the server answers with `-www`'s
# status page, so both directions carry several application records. That
# matters: CTR-ACPKM starts a fresh keystream per record, CryptoPro key
# meshing fires after 1024 octets, and TLSTREE changes the record key at a
# sequence boundary. A capture of the handshake alone would exercise none
# of them.
#
# One record per line: "<field> <transcript> <value>", read by
# tests/transcripts/loader.rs. Nothing here is deterministic - fresh keys,
# fresh randoms, a fresh certificate every time - so a diff against the
# previous capture is noise. What matters is which suites are listed.
#
# The last two rows repeat one suite on two other spellings of the same
# curve - RFC 4357's XchA and TC 26's paramSetB are both CryptoPro-A's
# parameters - so that the ephemeral key's parameter set OID is checked
# against a peer that chose a non-canonical one. See
# tests/test_gost_client_key_exchange.rs.
"""


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engines", metavar="DIR",
                        default=os.environ.get("OPENSSL_ENGINES"),
                        help="the directory holding gost.so")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.engines:
        parser.error("pass --engines DIR or set OPENSSL_ENGINES; this needs "
                     "OpenSSL's gost-engine, which is not a dependency of "
                     "the library and is not built here")
    if not os.path.exists(os.path.join(args.engines, "gost.so")):
        parser.error(f"no gost.so in {args.engines}")
    if shutil.which("openssl") is None:
        parser.error("no openssl binary")

    env = dict(os.environ, OPENSSL_ENGINES=os.path.abspath(args.engines))

    captured, skipped = [], []
    with tempfile.TemporaryDirectory() as work:
        # `XA` and `TCB` are the engine's names for the exchange set and
        # TC 26's `paramSetB`. Both are the *same curve* as `A`, which is
        # the entire point: only the OID differs.
        chains = {
            "2012": make_chain(env, work, "gost2012_256", "A", "2012"),
            "2001": make_chain(env, work, "gost2001", "A", "2001"),
            "2012-xcha": make_chain(env, work, "gost2012_256", "XA", "xcha"),
            "2012-tc26-b": make_chain(env, work, "gost2012_256", "TCB",
                                      "tc26b"),
        }
        for name, suite, which, extra in SUITES:
            ca_crt, crt, key = chains[which]
            fields, note = capture(env, work, name, suite, extra,
                                   ca_crt, crt, key)
            if fields is None:
                skipped.append((name, note))
                print(f"  {name}: skipped - {note}")
                continue
            captured.append((name, fields))
            print(f"  {name}: {note}")

    if not captured:
        raise RuntimeError("nothing was captured; the engine is loaded but no "
                           "GOST suite negotiated")

    with open(args.output, "w") as handle:
        handle.write(HEADER)
        for name, fields in captured:
            handle.write("\n")
            for field, value in fields:
                handle.write(f"{field} {name} {value}\n")

    print(f"{args.output}: {len(captured)} transcripts"
          + (f", {len(skipped)} skipped" if skipped else ""))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:                                # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
