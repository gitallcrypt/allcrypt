#!/usr/bin/env python3
"""Checks /opt/hbswitness before any vector is written from it.

    python3 scripts/witness/hbsx509/selftest.py [/opt/hbswitness]

Bouncy Castle 1.85 must verify the three self-signed certificates in RFC
9802's appendices - HSS, XMSS and XMSS^MT - and write each one's subject
key back exactly as the certificate carries it: the raw key under the
scheme's OID with absent parameters. Then a certificate with one byte of
its signature changed must fail. Last, a detached HSS SignedData it signs
must verify over its content and not over another.
"""

import base64
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RFC = os.path.join(HERE, "..", "..", "..", "rfcs", "rfc9802.txt")


class Bc:
    def __init__(self, out):
        self.p = subprocess.Popen([os.path.join(out, "bc-hbs")], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def ask(self, *words):
        self.p.stdin.write(" ".join(words) + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()


def appendix_certificates():
    certs, body = [], None
    started = False
    for line in open(RFC, encoding="utf-8"):
        line = line.strip()
        if line.startswith("Appendix A.  HSS X.509"):
            started = True
        if not started:
            continue
        if line == "-----BEGIN CERTIFICATE-----":
            body = []
        elif line == "-----END CERTIFICATE-----":
            certs.append(base64.b64decode("".join(body)))
            body = None
        elif body is not None and line and len(line) <= 64 and all(
                c.isalnum() or c in "+/=" for c in line):
            body.append(line)
    return certs


def spki_of(cert):
    """The SubjectPublicKeyInfo's bytes, found by the key's OID prefix
    (good enough for these three certificates, which the reader in the
    library parses properly)."""
    for oid in (bytes.fromhex("060b2a864886f70d0109100311"), bytes.fromhex("06082b06010505070622"),
                bytes.fromhex("06082b06010505070623")):
        at = cert.find(oid)
        while at >= 0:
            # The SPKI is SEQUENCE { SEQUENCE { OID }, BIT STRING }; the
            # signature algorithm's identifiers have the same inner shape
            # and no BIT STRING after them.
            end = at + len(oid)
            if cert[at - 4] == 0x30 and cert[at - 2] == 0x30 and cert[end] == 0x03:
                start = at - 4
                if cert[start + 1] & 0x80:
                    raise SystemExit("long-form SPKI length not expected here")
                return cert[start:start + 2 + cert[start + 1]]
            at = cert.find(oid, at + 1)
    raise SystemExit("no hash-based key in the certificate")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/hbswitness"
    bc = Bc(out)
    certs = appendix_certificates()
    if len(certs) != 3:
        sys.exit(f"found {len(certs)} appendix certificates, not 3")
    for cert in certs:
        if bc.ask("verify", cert.hex(), cert.hex()) != "good":
            sys.exit("Bouncy Castle does not verify an RFC 9802 appendix certificate")
        if bc.ask("spki", cert.hex()) != spki_of(cert).hex():
            sys.exit("Bouncy Castle writes an appendix key differently")
        bad = bytearray(cert)
        bad[-5] ^= 1
        if bc.ask("verify", bytes(bad).hex(), cert.hex()) != "bad":
            sys.exit("Bouncy Castle verifies a changed signature")
    message = bc.ask("cmssign", "hss", "5/4", b"selftest".hex(), "attrs", "detached")
    if bc.ask("cmsverify", message, b"selftest".hex()) != "good":
        sys.exit("Bouncy Castle does not verify its own CMS message")
    if not bc.ask("cmsverify", message, b"selftesT".hex()).startswith("bad"):
        sys.exit("Bouncy Castle verifies a CMS message over other content")
    print("hbs witness: Bouncy Castle 1.85 verifies RFC 9802's three appendix certificates "
          "and writes their keys back unchanged, and checks a CMS message of its own")


if __name__ == "__main__":
    main()
