#!/usr/bin/env python3
"""Save a server's certificate chain, **including when we refuse it**.

The tool that was missing. `check_live.py` reports a rejection and
throws the evidence away with the exception, so a row like

    tlsgost-256.cryptopro.ru  reject  certificate: Name attribute
                                      contains an embedded NUL.

says something is wrong and gives nothing to work on. A certificate we
cannot parse, or parse and then refuse, is exactly the certificate worth
keeping: it is somebody else's bytes, and the whole reason the offline
suite cannot find these bugs is that every certificate it judges is one
we generated.

So this drives the handshake by hand rather than through the `ssl`
shim, and reads `peer_certificates` off the connection **before**
deciding anything. The chain is saved whether the handshake succeeded,
failed at verification, or failed at parsing.

    python3 scripts/fetch_chain.py tlsgost-256.cryptopro.ru
    python3 scripts/fetch_chain.py www.cryptopro.ru --dir vectors/live

It writes `<host>-0.der`, `<host>-1.der`, ... and prints what it could
make of each one. **Nothing here is a test.** No test in this
repository uses the network, and `pytests/conftest.py` raises on any
connection to anything but loopback; this is a development tool for the
one thing that cannot be done offline - getting bytes somebody else
produced onto the machine, where a test can then use them.
"""

import argparse
import os
import socket
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import allcrypt                                  # noqa: E402


def fetch(host, port, suites, timeout):
    """`(chain, note)` - the DER chain and what happened.

    The chain comes back even on failure, which is the point. A
    handshake that dies *after* the Certificate message has already
    given us what we came for.
    """
    # `verify=False` and a low floor on purpose: the question here is
    # what the server *sent*, and a verification failure would throw the
    # answer away, which is the whole reason this script exists.
    client = allcrypt.TlsClient(host, allcrypt.TrustStore(), int(time.time()),
                                ciphers=suites, verify=False,
                                verify_hostname=False,
                                min_version="TLSv1.0", max_version="TLSv1.3")
    note = "handshake completed"
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        with sock:
            while True:
                out = client.take_outgoing()
                if out:
                    sock.sendall(out)
                if client.established:
                    break
                data = sock.recv(65536)
                if not data:
                    note = "the server closed the connection"
                    break
                client.push_incoming(data)
                try:
                    client.process()
                except Exception as reason:      # noqa: BLE001
                    note = f"{type(reason).__name__}: {reason}"
                    # Anything queued is the alert we are about to send,
                    # and sending it is the polite end of a refusal.
                    try:
                        sock.sendall(client.take_outgoing())
                    except OSError:
                        pass
                    break
    except OSError as reason:
        note = f"socket: {reason}"

    # **Which suite was negotiated is half the answer.** A server may
    # send a different certificate for a different suite - that is what
    # these endpoints do - so a chain saved without the suite beside it
    # cannot be compared with a report that named one. This was learned
    # by saving a certificate that turned out not to be the one a
    # failing run had seen.
    try:
        negotiated = client.cipher()
        if negotiated:
            note = f"{note} [{client.version()} {negotiated[0]}]"
    except Exception:                            # noqa: BLE001
        pass

    try:
        chain = client.peer_certificates
    except Exception as reason:                  # noqa: BLE001
        return [], f"{note}; and no chain: {reason}"
    return list(chain or []), note


def describe(der):
    """What this library makes of one certificate, failing softly.

    Each line is a separate `try`, because the interesting case is a
    certificate where one field is refused and the rest is readable -
    and a single try would hide everything after the first problem.
    """
    lines = []
    try:
        leaf = allcrypt.Certificate(der)
    except Exception as reason:                  # noqa: BLE001
        return [f"    does not parse: {reason}"]
    details = {}
    try:
        details = leaf.to_dict()
    except Exception as reason:                  # noqa: BLE001
        lines.append(f"    to_dict:     !! {reason}")
    for label, get in [("subject", lambda: leaf.subject),
                       ("issuer", lambda: leaf.issuer),
                       ("not before", lambda: leaf.not_before),
                       ("not after", lambda: leaf.not_after),
                       ("key", lambda: "{} {} bits".format(
                           details.get("publicKeyType"),
                           details.get("publicKeyBits"))),
                       ("signature", lambda: details.get("signatureAlgorithm")),
                       ("SANs", lambda: details.get("subjectAltName"))]:
        try:
            lines.append(f"    {label + ':':<12} {get()}")
        except Exception as reason:              # noqa: BLE001
            lines.append(f"    {label + ':':<12} !! {reason}")
    return lines


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--dir", default="vectors/live",
                        help="where to write the DER files")
    parser.add_argument("--suites", default="all",
                        help="which selection to offer: \"modern\", "
                             "\"legacy\", \"all\", or one suite by name - "
                             "which is how to reproduce a report that "
                             "named the suite it failed on")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()

    chain, note = fetch(args.host, args.port, args.suites, args.timeout)
    print(f"{args.host}:{args.port} - {note}")
    if not chain:
        print("  no certificate arrived, so there is nothing to save.")
        return 1

    os.makedirs(args.dir, exist_ok=True)
    for index, der in enumerate(chain):
        path = os.path.join(args.dir, f"{args.host}-{index}.der")
        with open(path, "wb") as out:
            out.write(der)
        print(f"  [{index}] {len(der)} bytes -> {path}")
        for line in describe(der):
            print(line)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:                            # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
