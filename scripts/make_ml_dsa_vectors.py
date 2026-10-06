#!/usr/bin/env python3
"""Vendor NIST's ML-DSA test vectors from the ACVP files.

    python3 scripts/make_ml_dsa_vectors.py
    python3 scripts/make_ml_dsa_vectors.py --keep   # keep the downloads

Writes `vectors/ml_dsa.vec` (key generation and signing) and
`vectors/ml_dsa_sigver.vec` (verification, including signatures that
must be refused). A development tool: the gate never runs it and needs
no network. What ships is the files it writes.

## Why these carry the verdict

Nothing on this machine implements ML-DSA: python-cryptography 46 has
no ML-DSA, OpenSSL here is 3.0 and grew it in 3.5, and PyPI is
unreachable from the development container. As for SLH-DSA and ML-KEM,
NIST's numbers are the independent opinion, every section header carries
its count, and the readers assert it.

## What is kept, and how

**`keyGen` whole**: 75 cases. Inputs are a 32 byte seed; outputs are
stored as length, first 64 bytes and SHA-256, for the reason
`make_ml_kem_vectors.py` gives - key generation from a stated seed is
deterministic, so a matching digest is byte equality.

**`sigGen`, three cases per group** - the three with the smallest
inputs, because the private key is an *input* and must be stored whole,
and at ML-DSA-87 it is 4,896 bytes. All 24 groups are kept: three
parameter sets, deterministic and hedged, and four interfaces -
internal, internal with an external `mu`, external pure and external
pre-hash. The signature is an output, stored like a key.

**Except in the pre-hash groups, where the choice is by hash function.**
ACVP varies `hashAlg` per test rather than per group, so "the three
smallest" would cover whichever functions those happen to use. Instead
each pre-hash group takes, smallest first, cases whose function no
earlier pre-hash group has covered, and fills up with the smallest. Six
groups of three cover all twelve functions; the script stops if they
do not.

**`sigVer`, one case per reason per group**: twelve groups, five
reasons - valid, modified message, modified commitment (`c-tilde`),
modified `z`, modified hint - so 48 of the 60 must be refused. The
signature is an input here and is stored whole. The reasons come from
`internalProjection.json`; `expectedResults.json` gives only the
verdict, and the two are required to agree.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import make_slh_dsa_vectors as base  # noqa: E402  (fetch and joined)

ROOT = base.ROOT
OUT = ROOT / "vectors" / "ml_dsa.vec"
OUT_SIGVER = ROOT / "vectors" / "ml_dsa_sigver.vec"

PREFIX_BYTES = 64
SIGGEN_CAP = 3

REASONS = [
    "valid signature and message - signature should verify successfully",
    "modified message",
    "modified signature - commitment",
    "modified signature - z",
    "modified signature - hint",
]

HASH_ALGORITHMS = {
    "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224",
    "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
    "SHAKE-128", "SHAKE-256",
}


def derived(name: str, value: str) -> list:
    raw = bytes.fromhex(value)
    return [(f"{name}Length", len(raw)),
            (f"{name}Prefix", value[:2 * PREFIX_BYTES].upper()),
            (f"{name}Digest", hashlib.sha256(raw).hexdigest().upper())]


def interface(group) -> str:
    """The section's interface token, which must identify the group."""
    if group["signatureInterface"] == "internal":
        return "internal-externalMu" if group.get("externalMu") else "internal"
    return f"external-{group['preHash']}"


def inputs(group, test) -> list:
    """The input fields of a signing or verification case, in order."""
    out = []
    if group.get("externalMu"):
        out.append("mu")
    else:
        out.append("message")
    if group["signatureInterface"] == "external":
        out.append("context")
    if group.get("preHash") == "preHash":
        out.append("hashAlg")
    if "rnd" in test:
        out.append("rnd")
    for field in out:
        if field not in test:
            raise SystemExit(f"tcId {test['tcId']}: no {field!r}; the ACVP "
                             f"shape has changed.")
    return out


def size(test) -> int:
    return sum(len(test.get(field, "")) for field in ("message", "mu",
                                                      "context"))


def write_keygen(handle, groups) -> int:
    kept = 0
    for group, tests in groups:
        handle.write(f"\n[keyGen {group['parameterSet']} {len(tests)}]\n")
        for test in sorted(tests, key=lambda t: t["tcId"]):
            handle.write(f"\ntcId = {test['tcId']}\nseed = {test['seed']}\n")
            for field in ("pk", "sk"):
                for name, value in derived(field, test[field]):
                    handle.write(f"{name} = {value}\n")
            kept += 1
    return kept


def write_siggen(handle, groups) -> int:
    covered = set()
    kept = 0
    for group, tests in groups:
        by_size = sorted(tests, key=lambda t: (size(t), t["tcId"]))
        if group.get("preHash") == "preHash":
            chosen = []
            for test in by_size:
                if test["hashAlg"] not in covered and len(chosen) < SIGGEN_CAP:
                    chosen.append(test)
                    covered.add(test["hashAlg"])
            for test in by_size:
                if len(chosen) < SIGGEN_CAP and test not in chosen:
                    chosen.append(test)
        else:
            chosen = by_size[:SIGGEN_CAP]
        kind = "deterministic" if group["deterministic"] else "hedged"
        handle.write(f"\n[sigGen-{interface(group)}-{kind} "
                     f"{group['parameterSet']} {len(chosen)}]\n")
        for test in sorted(chosen, key=lambda t: t["tcId"]):
            handle.write(f"\ntcId = {test['tcId']}\nsk = {test['sk']}\n")
            for field in inputs(group, test):
                handle.write(f"{field} = {test[field]}\n")
            for name, value in derived("signature", test["signature"]):
                handle.write(f"{name} = {value}\n")
            kept += 1
    if covered != HASH_ALGORITHMS:
        raise SystemExit(f"the pre-hash groups cover {sorted(covered)}, not "
                         f"all twelve; raise SIGGEN_CAP.")
    return kept


def write_sigver(handle, groups, reasons) -> int:
    kept = 0
    for group, tests in groups:
        chosen = {}
        for test in sorted(tests, key=lambda t: (size(t), t["tcId"])):
            reason, passed = reasons[(group["tgId"], test["tcId"])]
            if reason not in REASONS:
                raise SystemExit(f"tcId {test['tcId']}: unknown reason "
                                 f"{reason!r}. Add it to REASONS.")
            if passed != test["testPassed"]:
                raise SystemExit(f"tcId {test['tcId']}: the two ACVP files "
                                 f"disagree on the verdict.")
            chosen.setdefault(reason, test)
        missing = [r for r in REASONS if r not in chosen]
        if missing:
            raise SystemExit(f"{group['parameterSet']} {interface(group)}: "
                             f"no case for {missing}")
        handle.write(f"\n[sigVer-{interface(group)} {group['parameterSet']} "
                     f"{len(REASONS)}]\n")
        for reason in REASONS:
            test = chosen[reason]
            handle.write(f"\ntcId = {test['tcId']}\nreason = {reason}\n"
                         f"testPassed = "
                         f"{'true' if test['testPassed'] else 'false'}\n"
                         f"pk = {test['pk']}\n")
            for field in inputs(group, test):
                handle.write(f"{field} = {test[field]}\n")
            handle.write(f"signature = {test['signature']}\n")
            kept += 1
    return kept


def preamble(handle, what: str, headers) -> None:
    handle.write(f"# ML-DSA (FIPS 204) {what} from NIST's ACVP files.\n#\n"
                 "# Generated by scripts/make_ml_dsa_vectors.py. Do not edit: "
                 "every number\n# here is NIST's answer, and a hand edit makes "
                 "it ours again.\n#\n"
                 "# Source: usnistgov/ACVP-Server, gen-val/json-files.\n")
    for header in headers:
        handle.write(f"#   {header['algorithm']} {header['mode']} "
                     f"{header['revision']} (vsId {header['vsId']})\n")
    handle.write("#\n# A section is `[mode parameterSet count]`; the script's "
                 "docstring says\n# what was kept and why.\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true",
                        help="cache the downloaded JSON beside the output")
    keep = parser.parse_args().keep

    keygen_header, keygen = base.joined("ML-DSA-keyGen-FIPS204", keep)
    siggen_header, siggen = base.joined("ML-DSA-sigGen-FIPS204", keep)
    sigver_header, sigver = base.joined("ML-DSA-sigVer-FIPS204", keep)
    projection = base.fetch("ML-DSA-sigVer-FIPS204",
                            "internalProjection.json", keep)
    reasons = {(group["tgId"], test["tcId"]): (test["reason"],
                                               test["testPassed"])
               for group in projection["testGroups"]
               for test in group["tests"]}

    with open(OUT, "w", encoding="utf-8") as handle:
        preamble(handle, "key generation and signing vectors",
                 [keygen_header, siggen_header])
        handle.write("#\n# Derived values - keys and signatures - are "
                     "stored as length, first 64\n# bytes and SHA-256. "
                     "Inputs are stored whole.\n")
        total = write_keygen(handle, keygen) + write_siggen(handle, siggen)
    print(f"wrote {OUT.relative_to(ROOT)}: {total} cases, "
          f"{OUT.stat().st_size:,} bytes")

    with open(OUT_SIGVER, "w", encoding="utf-8") as handle:
        preamble(handle, "verification vectors", [sigver_header])
        total = write_sigver(handle, sigver, reasons)
    print(f"wrote {OUT_SIGVER.relative_to(ROOT)}: {total} cases, "
          f"{OUT_SIGVER.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
