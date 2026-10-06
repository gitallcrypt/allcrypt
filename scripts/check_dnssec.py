#!/usr/bin/env python3
"""The DNSSEC example (`examples/products/dnssec`) against dnspython
2.7.0, both directions, for the eleven algorithms dnspython has: RSAMD5,
DSA, RSASHA1, DSA-NSEC3-SHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512,
ECDSAP256SHA256, ECDSAP384SHA384, ED25519 and ED448.

  * **Keys**: ours made by `keygen`, read by dnspython from the `.key`
    file; its key tag and its DS under SHA-1, SHA-256 and SHA-384
    against ours.
  * **Ours signing**: a zone with a secure and an insecure delegation,
    glue, a wildcard and an empty non-terminal, signed by ours under NSEC
    and under NSEC3; dnspython reads the signed zone and validates every
    RRset, and recomputes every NSEC3 owner and the NSEC chain's order.
  * **Their keys, our signing**: a key made with python-cryptography and
    written here as BIND's `Private-key-format` file, from the format's
    own description, signed with by ours and validated by dnspython.
  * **Theirs signing**: the same zone without delegations, signed by
    dnspython's `sign_zone` (NSEC), checked by ours.
  * **NSEC3 hashes**: random names, salts and iteration counts.

GOST (12, 23) and SM2 (17) are not in dnspython; their RFCs' examples
are the offline tests' business.

    python3 scripts/check_dnssec.py [--ours PATH]
    python3 scripts/check_dnssec.py --record

`--record` writes `examples/products/fixtures/dnssec/` for the offline
tests: dnspython's signed zones, dnspython's answers for key tags, DS
records and NSEC3 hashes, and two RSA and two DSA keys
python-cryptography made, in BIND's private key format.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example dnssec`. dnspython is a git
checkout of its v2.7.0 tag (`docs/building.md`).
"""

import argparse
import base64
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures", "dnssec")
OURS = os.path.join(ROOT, "target", "release", "examples", "dnssec")
WITNESS = "/opt/dnswitness/dnspython"

sys.path.insert(0, WITNESS)

import dns.dnssec  # noqa: E402
import dns.name  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402
import dns.rrset  # noqa: E402
import dns.zone  # noqa: E402
from dns.dnssectypes import Algorithm  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

ALGORITHMS = [1, 3, 5, 6, 7, 8, 10, 13, 14, 15, 16]
NAMES = {1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1",
         8: "RSASHA256", 10: "RSASHA512", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384",
         15: "ED25519", 16: "ED448"}
POLICY = dns.dnssec.allow_all_policy
ORIGIN = dns.name.from_text("example.")
INCEPTION = 1767225600          # 2026-01-01
EXPIRATION = INCEPTION + 90 * 86400
NOW = INCEPTION + 3600

# Names in capitals inside RDATA, which the signed form lowercases for
# the types RFC 4034 section 6.2 lists: a disagreement about which types
# those are is invisible between two copies of one implementation.
ZONE = """$TTL 3600
@ SOA NS1.Example. HostMaster 1 7200 3600 1209600 300
@ NS NS1
@ MX 10 Mail
ns1 A 192.0.2.1
mail AAAA 2001:db8::25
alias CNAME Mail.EXAMPLE.
_sip._tcp SRV 0 5 5060 Mail.Example.
ptr PTR Host.EXAMPLE.
*.wild TXT "any"
deep.below.empty A 192.0.2.7
Mixed.Case A 192.0.2.8
"""
DELEGATIONS = """sub NS ns.sub
ns.sub A 192.0.2.53
secure NS ns.secure
secure DS 12345 13 2 0102030405060708091011121314151617181920212223242526272829303132
"""

COUNTS = {}
FAILURES = []


def check(kind, condition, detail):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    if not condition:
        FAILURES.append(f"{kind}: {detail}")
        print(f"FAIL {kind}: {detail}")


def ours(*args, stdin=None):
    result = subprocess.run([OURS, *args], capture_output=True, text=True, input=stdin)
    if result.returncode == 2:
        raise RuntimeError(f"ours {' '.join(args)}: {result.stderr.strip()}")
    return result


def read_key_file(path):
    zone = dns.zone.from_text(open(path).read(), origin=dns.name.root, relativize=False,
                              check_origin=False)
    for name, node in zone.nodes.items():
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        if rds:
            return name, rds[0]
    raise ValueError(path)


def keygen(tmp, algorithm, ksk):
    args = ["keygen", "example.", "--algorithm", str(algorithm), "--directory", tmp]
    if algorithm in (1, 5, 7, 8, 10):
        args += ["--bits", "1024"]
    if ksk:
        args.append("--ksk")
    base = ours(*args).stdout.strip()
    return os.path.join(tmp, base)


# --------------------------------------------------------------------- keys --

def check_keys(tmp, record):
    for algorithm in ALGORITHMS:
        for ksk in (False, True):
            base = keygen(tmp, algorithm, ksk)
            name, dnskey = read_key_file(base + ".key")
            tag = int(ours("key-tag", base + ".key").stdout)
            check("key tag", tag == dns.dnssec.key_id(dnskey), f"{NAMES[algorithm]} {base}")
            for digest in (1, 2, 4):
                theirs = dns.dnssec.make_ds(name, dnskey, digest, policy=POLICY)
                line = ours("ds", base + ".key", "--digest", str(digest)).stdout.split()
                check("DS", line[-1].lower() == theirs.digest.hex(),
                      f"{NAMES[algorithm]} digest {digest}")
                record.setdefault("ds", []).append([
                    ("name", f"{NAMES[algorithm]}-{digest}"),
                    ("owner", name.to_text()),
                    ("dnskey", base64.b64encode(dnskey.to_wire()).decode()),
                    ("tag", str(dns.dnssec.key_id(dnskey))),
                    ("digest-type", str(digest)),
                    ("digest", theirs.digest.hex())])


# ------------------------------------------------------------- ours signing --

def validate_zone(text, label, nsec3=None):
    """dnspython reads the zone and validates every RRset ours signed."""
    zone = dns.zone.from_text(text, origin=ORIGIN, relativize=False)
    dnskeys = zone.get_rdataset(ORIGIN, dns.rdatatype.DNSKEY)
    keys = {ORIGIN: dnskeys}
    cuts = [n for n, node in zone.nodes.items()
            if n != ORIGIN and node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS)]
    signed = 0
    for name, node in zone.nodes.items():
        below_cut = any(name != c and name.is_subdomain(c) for c in cuts)
        for rds in node.rdatasets:
            if rds.rdtype == dns.rdatatype.RRSIG:
                continue
            sigs = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, rds.rdtype)
            at_cut = name in cuts and rds.rdtype not in (dns.rdatatype.DS,
                                                         dns.rdatatype.NSEC,
                                                         dns.rdatatype.NSEC3)
            if below_cut or at_cut:
                check("unsigned where it should be", not sigs,
                      f"{label} {name} {dns.rdatatype.to_text(rds.rdtype)}")
                continue
            rrset = dns.rrset.RRset(name, rds.rdclass, rds.rdtype)
            rrset.update(rds)
            try:
                dns.dnssec.validate(rrset, (name, sigs), keys, now=NOW, policy=POLICY)
                ok = True
            except Exception as e:  # noqa: BLE001
                ok = False
                print(e)
            check("RRset validated", ok and sigs is not None,
                  f"{label} {name} {dns.rdatatype.to_text(rds.rdtype)}")
            signed += 1
    names = sorted(n for n, node in zone.nodes.items()
                   if not node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
                   and not any(n != c and n.is_subdomain(c) for c in cuts))
    if nsec3 is None:
        for i, name in enumerate(names):
            nsec = zone.get_rdataset(name, dns.rdatatype.NSEC)
            want = names[(i + 1) % len(names)]
            check("NSEC chain", nsec is not None and nsec[0].next == want,
                  f"{label} {name}")
    else:
        salt, iterations = nsec3
        owners = {n.labels[0].decode().upper() for n, node in zone.nodes.items()
                  if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)}
        wanted = set()
        for name in names:
            # The name and every empty non-terminal above it.
            n = name
            while n != ORIGIN and len(n) > len(ORIGIN):
                wanted.add(dns.dnssec.nsec3_hash(n, salt, iterations, 1).upper())
                n = n.parent()
            wanted.add(dns.dnssec.nsec3_hash(ORIGIN, salt, iterations, 1).upper())
        check("NSEC3 owners", owners == wanted, f"{label} {owners ^ wanted}")
    return signed


def check_our_signing(tmp):
    with open(os.path.join(tmp, "zone"), "w") as f:
        f.write(ZONE + DELEGATIONS)
    for algorithm in ALGORITHMS:
        ksk, zsk = keygen(tmp, algorithm, True), keygen(tmp, algorithm, False)
        for nsec3 in (None, ("aabbccdd", 5), ("", 0)):
            extra = [] if nsec3 is None else ["--nsec3", nsec3[0] or "-", str(nsec3[1])]
            text = ours("sign", os.path.join(tmp, "zone"), "--origin", "example.",
                        "--key", ksk + ".private", "--key", zsk + ".private",
                        "--inception", str(INCEPTION), "--expiration", str(EXPIRATION),
                        *extra).stdout
            validate_zone(text, f"{NAMES[algorithm]} {'NSEC3' if nsec3 else 'NSEC'}",
                          None if nsec3 is None else (nsec3[0], nsec3[1]))
            with open(os.path.join(tmp, "signed"), "w") as f:
                f.write(text)
            result = ours("verify", os.path.join(tmp, "signed"), "--origin", "example.",
                          "--now", str(NOW))
            check("ours verifying ours", result.returncode == 0,
                  f"{NAMES[algorithm]} {result.stdout[-300:]}")


# --------------------------------------------------- their keys, our signing --

def b64(n):
    return base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode()


def private_file(algorithm):
    """A python-cryptography key and BIND's file for it, written here."""
    head = f"Private-key-format: v1.3\nAlgorithm: {algorithm} ({NAMES[algorithm]})\n"
    if algorithm in (1, 5, 7, 8, 10):
        key = rsa.generate_private_key(65537, 1024)
        n = key.private_numbers()
        fields = [("Modulus", n.public_numbers.n), ("PublicExponent", n.public_numbers.e),
                  ("PrivateExponent", n.d), ("Prime1", n.p), ("Prime2", n.q),
                  ("Exponent1", n.dmp1), ("Exponent2", n.dmq1), ("Coefficient", n.iqmp)]
        return key, head + "".join(f"{k}: {b64(v)}\n" for k, v in fields)
    if algorithm in (3, 6):
        key = dsa.generate_private_key(1024)
        n = key.private_numbers()
        p = n.public_numbers.parameter_numbers
        fields = [("Prime(p)", p.p), ("Subprime(q)", p.q), ("Base(g)", p.g),
                  ("Private_value(x)", n.x), ("Public_value(y)", n.public_numbers.y)]
        return key, head + "".join(f"{k}: {b64(v)}\n" for k, v in fields)
    if algorithm in (13, 14):
        key = ec.generate_private_key(ec.SECP256R1() if algorithm == 13 else ec.SECP384R1())
        width = 32 if algorithm == 13 else 48
        d = key.private_numbers().private_value.to_bytes(width, "big")
        return key, head + f"PrivateKey: {base64.b64encode(d).decode()}\n"
    key = (ed25519.Ed25519PrivateKey if algorithm == 15 else ed448.Ed448PrivateKey).generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    return key, head + f"PrivateKey: {base64.b64encode(raw).decode()}\n"


def check_their_keys(tmp):
    with open(os.path.join(tmp, "zone"), "w") as f:
        f.write(ZONE)
    for algorithm in ALGORITHMS:
        key, text = private_file(algorithm)
        path = os.path.join(tmp, f"theirs-{algorithm}.private")
        with open(path, "w") as f:
            f.write(text)
        signed = ours("sign", os.path.join(tmp, "zone"), "--origin", "example.", "--key", path,
                      "--inception", str(INCEPTION), "--expiration", str(EXPIRATION)).stdout
        zone = dns.zone.from_text(signed, origin=ORIGIN, relativize=False)
        dnskey = zone.get_rdataset(ORIGIN, dns.rdatatype.DNSKEY)[0]
        expected = dns.dnssec.make_dnskey(key.public_key(), algorithm, flags=256)
        check("their key read", dnskey.key == expected.key, NAMES[algorithm])
        validate_zone(signed, f"their {NAMES[algorithm]} key")


# ------------------------------------------------------------ theirs signing --

def their_signed_zone(algorithm):
    zone = dns.zone.from_text(ZONE, origin=ORIGIN, relativize=False)
    keys = []
    for flags in (257, 256):
        key, _ = private_file(algorithm)
        keys.append((key, dns.dnssec.make_dnskey(key.public_key(), algorithm, flags=flags)))
    with zone.writer() as txn:
        dns.dnssec.sign_zone(zone, txn, keys=keys, inception=INCEPTION, expiration=EXPIRATION,
                             policy=POLICY)
    return zone.to_text(relativize=False)


def check_their_signing(tmp, record):
    for algorithm in ALGORITHMS:
        text = their_signed_zone(algorithm)
        path = os.path.join(tmp, "theirs.zone")
        with open(path, "w") as f:
            f.write(text)
        result = ours("verify", path, "--origin", "example.", "--now", str(NOW))
        check("ours verifying theirs", result.returncode == 0,
              f"{NAMES[algorithm]} {result.stdout[-500:]}")
        record.setdefault("zones", []).append((NAMES[algorithm], text))


# -------------------------------------------------------------------- NSEC3 --

def check_nsec3(choose, record):
    for _ in range(40):
        labels = [choose.choice(["a", "B", "xn--x", "*", "deep", "q1"]) + str(choose.randrange(99))
                  for _ in range(choose.randrange(0, 4))]
        name = ".".join(labels + ["example", ""]) if labels else "example."
        salt = bytes(choose.randrange(256) for _ in range(choose.randrange(0, 9)))
        iterations = choose.choice([0, 1, 5, 12, 150])
        theirs = dns.dnssec.nsec3_hash(name, salt.hex(), iterations, 1)
        line = ours("nsec3-hash", name, salt.hex() or "-", str(iterations)).stdout.strip()
        check("NSEC3 hash", line == theirs, f"{name} {salt.hex()} {iterations}")
        record.setdefault("nsec3", []).append([
            ("name", name), ("salt", salt.hex() or "-"), ("iterations", str(iterations)),
            ("hash", theirs)])


def write_record(record):
    os.makedirs(FIXTURES, exist_ok=True)
    lines = ["# dnspython 2.7.0's answers, kept by scripts/check_dnssec.py --record for",
             "# the offline tests in examples/products/dnssec. DNSKEY RDATA is base64;",
             "# digests are hex; a salt of - is empty.", ""]
    for section in ["ds", "nsec3"]:
        lines.append(f"[{section}]")
        for rec in record[section]:
            lines += [f"{k} = {v}" for k, v in rec]
        lines.append("")
    with open(os.path.join(FIXTURES, "dnssec.vec"), "w") as f:
        f.write("\n".join(lines))
    # Keys python-cryptography made, in BIND's format as written here:
    # the offline tests sign with them rather than generating RSA and DSA
    # keys, which a debug build takes most of a minute over.
    for algorithm, label in ((8, "rsa"), (3, "dsa")):
        for n in (1, 2):
            _, text = private_file(algorithm)
            with open(os.path.join(FIXTURES, f"{label}-{n}.private"), "w") as f:
                f.write(text)
    for name, text in record["zones"]:
        with open(os.path.join(FIXTURES, f"{name.lower()}.zone"), "w") as f:
            f.write(f"; Signed by dnspython 2.7.0's sign_zone, valid from {INCEPTION}\n"
                    f"; to {EXPIRATION}; scripts/check_dnssec.py --record.\n" + text)


def main():
    global OURS
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--seed", type=int, default=53)
    args = parser.parse_args()
    OURS = args.ours
    choose = random.Random(args.seed)
    record = {}
    with tempfile.TemporaryDirectory() as tmp:
        check_keys(tmp, record)
        check_our_signing(tmp)
        check_their_keys(tmp)
        check_their_signing(tmp, record)
        check_nsec3(choose, record)
    if args.record:
        write_record(record)
    total = sum(COUNTS.values())
    print(", ".join(f"{k} {v}" for k, v in COUNTS.items()))
    print(f"{total - len(FAILURES)} of {total} passed")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
