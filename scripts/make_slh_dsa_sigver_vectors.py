#!/usr/bin/env python3
"""Vendor NIST's SLH-DSA *verification* vectors - the negative cases.

    python3 scripts/make_slh_dsa_sigver_vectors.py
    python3 scripts/make_slh_dsa_sigver_vectors.py --keep   # keep downloads

Writes `vectors/slh_dsa_sigver.vec`. A development tool: the gate never
runs it and needs no network. What ships is the file it writes.

## Why these exist

`vectors/slh_dsa.vec` is NIST's key generation and signing cases. Once a
deterministic signature's digest matches, our signature *is* NIST's and
handing it to our verifier checks verification against NIST's bytes -
but only ever with signatures that must be **accepted**. A verifier that
returned `true` for everything would pass all of them. ACVP's `sigVer`
file is the other half: signatures somebody else decided must be
refused, and why.

## The seven reasons, and why the reason is vendored too

ACVP's `internalProjection.json` says why each case should fail:

    valid signature and message - signature should verify successfully
    modified message
    modified signature - R            (the randomiser)
    modified signature - SIGFORS      (the FORS signature)
    modified signature - SIGHT        (the hypertree signature)
    invalid signature - too small     (one byte short)
    invalid signature - too large     (one byte long)

**Every reason is kept for every group kept**, because each one reaches a
different part of verification - a verifier that never looked at the
hypertree would refuse "modified R" and "modified SIGFORS" and accept
"modified SIGHT". The reason goes into the file so the test can say which
part of verification failed to notice, not just that something did.

## What is trimmed

The full file is 30 MB: signatures are inputs here, so they cannot be
stored as a digest the way `make_slh_dsa_vectors.py` stores signing
answers, and an SLH-DSA-SHA2-256f signature is 49,856 bytes.

So two parameter sets are kept, **`SLH-DSA-SHA2-128s` and
`SLH-DSA-SHAKE-128s`** - the smallest signatures, 7,856 bytes, and one set
from each hash family, since the two families share nothing below the
tweakable-hash layer. Both keep all three of their groups - internal,
external pure, external pre-hash - and one case per reason per group, the
case with the smallest message (lowest `tcId` on a tie). That is 42
cases.

What that does not cover is the other ten parameter sets' *negative*
behaviour. Their positive behaviour is covered by `slh_dsa.vec`, and
verification is the same code at every parameter set with different
numbers in it; the risk left is a parameter-specific length or offset in
verification that only a wrong signature reaches, which is why the two
kept here are the two families rather than two sizes of one.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import make_slh_dsa_vectors as base  # noqa: E402  (fetch and joined)

ROOT = base.ROOT
OUT = ROOT / "vectors" / "slh_dsa_sigver.vec"
DIRECTORY = "SLH-DSA-sigVer-FIPS205"

KEPT_SETS = ("SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s")

#: Every reason ACVP gives, in the order the reader expects them. A
#: reason not in this list stops the script rather than being copied in
#: unread, and one missing from a group stops it too.
REASONS = [
    "valid signature and message - signature should verify successfully",
    "modified message",
    "modified signature - R",
    "modified signature - SIGFORS",
    "modified signature - SIGHT",
    "invalid signature - too small",
    "invalid signature - too large",
]


def label(group) -> str:
    interface = group["signatureInterface"]
    if interface == "external":
        interface = f"external-{group['preHash']}"
    return f"sigVer-{interface}"


def reasons_by_test() -> dict:
    """`(tgId, tcId) -> (reason, testPassed)` from the internal projection.

    `testPassed` is taken from here as well as from `expectedResults.json`
    and the two are required to agree, so a reason cannot end up attached
    to the wrong verdict.
    """
    projection = base.fetch(DIRECTORY, "internalProjection.json", KEEP)
    out = {}
    for group in projection["testGroups"]:
        for test in group["tests"]:
            out[(group["tgId"], test["tcId"])] = (test["reason"],
                                                  test["testPassed"])
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true",
                        help="cache the downloaded JSON beside the output")
    global KEEP
    KEEP = parser.parse_args().keep

    print(f"{DIRECTORY}:")
    header, groups = base.joined(DIRECTORY, KEEP)
    reasons = reasons_by_test()

    total = 0
    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write(
            "# SLH-DSA (FIPS 205) signature verification vectors from NIST's "
            "ACVP\n# files: signatures that must be accepted, and signatures "
            "that must be\n# refused, each with ACVP's reason.\n#\n"
            "# Generated by scripts/make_slh_dsa_sigver_vectors.py. Do not "
            "edit.\n#\n# Source: usnistgov/ACVP-Server, gen-val/json-files.\n"
            f"#   {header['algorithm']} {header['mode']} {header['revision']} "
            f"(vsId {header['vsId']})\n#\n"
            "# Two parameter sets of twelve - the smallest signature in each "
            "hash\n# family - every group of each, and one case per reason "
            "per group. The\n# script's docstring argues the choice.\n#\n"
            "# A section is `[sigVer-interface parameterSet count]`.\n")

        for group, tests in groups:
            if group["parameterSet"] not in KEPT_SETS:
                continue
            chosen = {}
            for test in tests:
                reason, passed = reasons[(group["tgId"], test["tcId"])]
                if reason not in REASONS:
                    raise SystemExit(f"tcId {test['tcId']}: unknown reason "
                                     f"{reason!r}. Add it to REASONS.")
                if passed != test["testPassed"]:
                    raise SystemExit(f"tcId {test['tcId']}: the two ACVP "
                                     f"files disagree on the verdict.")
                size = len(test["message"]) + len(test["signature"])
                best = chosen.get(reason)
                if best is None or (size, test["tcId"]) < best[0]:
                    chosen[reason] = ((size, test["tcId"]), test)
            missing = [r for r in REASONS if r not in chosen]
            if missing:
                raise SystemExit(f"{group['parameterSet']} {label(group)}: "
                                 f"no case for {missing}")

            handle.write(f"\n[{label(group)} {group['parameterSet']} "
                         f"{len(REASONS)}]\n")
            for reason in REASONS:
                test = chosen[reason][1]
                handle.write(f"\ntcId = {test['tcId']}\n")
                handle.write(f"reason = {reason}\n")
                handle.write(f"testPassed = "
                             f"{'true' if test['testPassed'] else 'false'}\n")
                handle.write(f"pk = {test['pk']}\n")
                handle.write(f"message = {test['message']}\n")
                if group["signatureInterface"] == "external":
                    handle.write(f"context = {test['context']}\n")
                if group.get("preHash") == "preHash":
                    handle.write(f"hashAlg = {test['hashAlg']}\n")
                handle.write(f"signature = {test['signature']}\n")
                total += 1

    print(f"\nwrote {OUT.relative_to(ROOT)}: {total} cases, "
          f"{OUT.stat().st_size:,} bytes")
    return 0


KEEP = False

if __name__ == "__main__":
    sys.exit(main())
