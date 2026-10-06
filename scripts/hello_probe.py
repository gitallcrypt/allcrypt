#!/usr/bin/env python3
"""Which ClientHello does this server answer?

For the failure that has no error message: the peer resets the
connection, or closes it, without sending an alert. There is nothing to
read and nothing to parse, so the only way to learn anything is to vary
what goes out and see which variant gets a ServerHello back.

Each row narrows the hello by one thing, and the first row that works
says what the previous one contained that the server could not take.
The hello's size is printed with each, because **a record length
between 256 and 511 bytes is a known trigger** in more than one old
stack, and it changes as the suite list does - so it has to be visible
rather than inferred.

    python3 scripts/hello_probe.py tlsgost-256.cryptopro.ru

This is a development tool and not a test. No test in this repository
uses the network, and `pytests/conftest.py` raises on any connection to
anything but loopback.
"""

import argparse
import os
import socket
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import allcrypt                                  # noqa: E402


# Each row: a label, and the keyword arguments that build the hello.
#
# **Ordered widest first**, so the first one that works brackets the
# problem between itself and the row above. The pairs that differ in one
# thing only are the ones that carry the information:
#
#   * "legacy, to 1.3" against "legacy, to 1.2" separates *offering TLS
#     1.3 at all* - which brings the four RFC 9367 suites, their seven
#     signature schemes, `key_share` and `supported_versions` - from
#     everything else.
#   * "1.2, GOST only" against "legacy, to 1.2" separates the size and
#     the long suite list from the GOST suites themselves.
#   * the single-suite rows say which one the server actually wants.
VARIANTS = [
    ("all, to 1.3", dict(ciphers="all", min_version="TLSv1.0",
                         max_version="TLSv1.3")),
    ("legacy, to 1.3", dict(ciphers="legacy", min_version="TLSv1.0",
                            max_version="TLSv1.3")),
    ("legacy, to 1.2", dict(ciphers="legacy", min_version="TLSv1.0",
                            max_version="TLSv1.2")),
    ("modern, to 1.2", dict(ciphers="modern", min_version="TLSv1.2",
                            max_version="TLSv1.2")),
    ("1.2, the three RFC 9189 suites",
     dict(ciphers="TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC,"
                  "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC,"
                  "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
          min_version="TLSv1.2", max_version="TLSv1.2")),
    ("1.2, KUZNYECHIK_CTR_OMAC alone",
     dict(ciphers="TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
          min_version="TLSv1.2", max_version="TLSv1.2")),
    ("1.2, CNT_IMIT at 0xC102 alone",
     dict(ciphers="TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
          min_version="TLSv1.2", max_version="TLSv1.2")),
    ("1.2, CNT_IMIT at 0xFF85 alone",
     dict(ciphers="TLS_GOSTR341112_256_WITH_28147_CNT_IMIT_LEGACY",
          min_version="TLSv1.2", max_version="TLSv1.2")),
    ("1.0, the 2001 suite 0x0081 alone",
     dict(ciphers="TLS_GOSTR341001_WITH_28147_CNT_IMIT",
          min_version="TLSv1.0", max_version="TLSv1.0")),
    ("1.3 only, the four RFC 9367 suites",
     dict(ciphers="TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,"
                  "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,"
                  "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,"
                  "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
          min_version="TLSv1.3", max_version="TLSv1.3")),
]


def probe(host, port, options, timeout, dump=None):
    """`(hello_size, outcome)` for one variant.

    The outcome distinguishes four things that look alike from a
    distance and mean different things: the server never answered, it
    reset, it sent an alert, or it sent a ServerHello and the failure is
    later. Only the last two are about the protocol; the first two are
    about the hello.
    """
    try:
        client = allcrypt.TlsClient(host, allcrypt.TrustStore(),
                                    int(time.time()), verify=False,
                                    verify_hostname=False, **options)
    except Exception as reason:                  # noqa: BLE001
        return 0, f"cannot build: {reason}"

    hello = client.take_outgoing()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as reason:
        return len(hello), f"no connection: {reason}"

    with sock:
        try:
            sock.sendall(hello)
            first = sock.recv(65536)
        except OSError as reason:
            return len(hello), f"** {reason} **"
        if not first:
            return len(hello), "** closed with no answer **"

        # **Keep the bytes.** A ServerHello that says something
        # surprising is worth decoding afterwards, and the only chance
        # to keep it is here - `process()` consumes it and an exception
        # takes the rest with it.
        if dump:
            with open(dump, "wb") as out:
                out.write(first)

        # A ServerHello is a handshake record (0x16) whose first body
        # byte is 2. An alert record is 0x15, and its two bytes say
        # which - that is the server telling us something, which is a
        # better outcome than silence.
        if first[0] == 0x15 and len(first) >= 7:
            return len(hello), f"alert level {first[5]} description {first[6]}"
        if first[0] != 0x16:
            return len(hello), f"record type {first[0]:#04x}, not a handshake"

        client.push_incoming(first)
        try:
            client.process()
            # **One record is not the flight.** A server may split the
            # ServerHello from what follows, and asking for the suite
            # after only the first record read back `None` - which
            # looks like a failure and is a short read. Drained until
            # the suite is known or the peer stops.
            for _ in range(8):
                if client.cipher():
                    break
                sock.settimeout(timeout)
                more = sock.recv(65536)
                if not more:
                    break
                if dump:
                    with open(dump, "ab") as out:
                        out.write(more)
                client.push_incoming(more)
                client.process()
        except Exception as reason:              # noqa: BLE001
            # The ServerHello arrived; whatever went wrong is past the
            # hello, which is what this script is asking about.
            suite = client.cipher()
            if suite:
                return len(hello), f"{suite[0]}, then {reason}"
            return len(hello), f"ServerHello, then {reason}"
        except OSError as reason:
            return len(hello), f"ServerHello, then socket: {reason}"
        suite = client.cipher()
        chosen = suite[0] if suite else "no suite reported"
        return len(hello), f"ServerHello: {client.version()} {chosen}"


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--dump", metavar="DIR",
                        help="save each variant's first response bytes "
                             "here, for decoding afterwards")
    args = parser.parse_args()
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)

    print(f"\n{args.host}:{args.port}\n" + "-" * 78)
    print(f"  {'variant':<36} {'hello':>6}  outcome")
    for index, (label, options) in enumerate(VARIANTS):
        dump = None
        if args.dump:
            dump = os.path.join(args.dump, f"{args.host}-{index}.bin")
        size, outcome = probe(args.host, args.port, options, args.timeout, dump)
        note = ""
        # Flagged because it is a real trigger and it is invisible
        # otherwise: several old stacks mishandle a ClientHello record
        # whose length lands in this range.
        if 256 <= size <= 511:
            note = "  <- 256..511"
        print(f"  {label:<36} {size:>6}{note}")
        print(f"  {'':<36} {'':>6}  {outcome}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:                            # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
