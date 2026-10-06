#!/usr/bin/env python3
"""Vendor NIST's SLH-DSA test vectors from the ACVP files.

    python3 scripts/make_slh_dsa_vectors.py
    python3 scripts/make_slh_dsa_vectors.py --keep   # keep the downloads

Writes `vectors/slh_dsa.vec`. A development tool: the gate never runs it
and needs no network. What ships is the file it writes.

## Why the vectors carry the whole verdict here

Every other algorithm in this library has a second opinion on the machine
- `hashlib`, `python-cryptography`, OpenSSL, and for GOST a built engine.
**SLH-DSA has none.** python-cryptography 46 does not implement it,
OpenSSL added it in 3.5 and this container has 3.0, and there is no
published worked example in a document the way RFC 9367 gives one for
GOST at TLS 1.3.

So these numbers are not a supplement to a differential test, they *are*
the test, and that raises the bar on the parser rather than lowering it. A
vector file that silently parses to nothing turns every loop in
`tests/test_slh_dsa.rs` into a pass, so the section header records the
count and the reader asserts it. That assertion has already earned its
place three times in this repository, in three different documents.

## Where they come from

`usnistgov/ACVP-Server`, which is NIST's own validation system: the same
files a vendor's implementation is tested against for FIPS certification.
Two files per mode - `prompt.json` has the inputs and
`expectedResults.json` the answers, joined on `tcId`.

## What is trimmed, and why trimming is a script rather than an edit

`keyGen` is kept whole: twelve parameter sets, ten cases each, and a case
is two 16-to-32 byte seeds in and two keys out, so the lot is a few tens
of kilobytes.

`sigGen` cannot be. Its answers are 32 MB, because an SLH-DSA-SHA2-256s
signature is 29,792 bytes and there are hundreds of them, and vendoring
all 72 groups with their signatures intact would put 4.4 MB in the
repository - ten times the largest vector file already here. Two things
cut it down, and both are choices worth stating rather than burying:

1. **Three cases per internal group, two per pre-hash group and one per
   pure group** - see `siggen_cap`, which argues each of the three. The
   short version: the internal groups are the arithmetic, the external
   ones are a wrapper, and the pre-hash cap is 2 rather than 1 because
   that is the smallest number at which the *fast* parameter sets cover
   all twelve approved hash functions, and the slow ones are too slow to
   run on every build.
2. **A signature is stored as its length, its first 256 bytes, and the
   SHA-256 of the whole**, rather than in full. That is a transformation
   of NIST's data rather than a copy of it, so it needs justifying: for
   a *deterministic* signature there is exactly one right answer, so
   comparing `SHA-256(ours)` against `SHA-256(theirs)` establishes byte
   for byte equality as surely as comparing the bytes would. What it
   loses is the ability to see *where* a wrong signature diverges, which
   is why the first 256 bytes are kept whole - a signature begins with
   `R` and then the FORS signature, so an error in `PRF_msg`, `H_msg` or
   the start of FORS shows up in the prefix, and the digest catches
   everything after it.

   The transformation is done here, by committed code, so "these are
   NIST's numbers" stays checkable: re-run this and the file should not
   move. Doing the same by hand would not be.

Note the consequence for testing verification, which is worth having in
mind before anyone adds full signatures back: once a deterministic
signature's digest matches, **our signature is NIST's signature**, so
handing it to our own verifier tests verification against NIST's bytes
at no storage cost. What that does not cover is NIST's *negative* cases -
signatures that must be rejected - which is what `sigVer` is for and is
the reason to vendor some of it later.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "vectors" / "slh_dsa.vec"

BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/master"
        "/gen-val/json-files")

#: `(directory, how many tests to keep per group or None for all)`.
#:
#: `None` for keyGen because the whole thing is small. The signing modes
#: are capped: enough to cover every parameter set and every combination
#: of the flags that change the construction, and not enough to put
#: megabytes of hex in the repository.
MODES = [
    ("SLH-DSA-keyGen-FIPS205", None),
    ("SLH-DSA-sigGen-FIPS205", None),
]

def siggen_cap(group) -> int:
    """How many cases to keep from one `sigGen` group.

    Three for the internal groups: they are the scheme's arithmetic, and
    the cases differ in key and message.

    The external groups are a wrapper around that - a domain separator
    byte, a context string, optionally a pre-hash - so what they need to
    cover is the *combinations*, and there are 48 of them against 24
    internal. One case covers a `pure` group completely, because nothing
    varies between its tests that the wrapper cares about.

    **Two for a `preHash` group**, and the number is measured rather than
    chosen: ACVP varies `hashAlg` per *test* rather than per group, so how
    many hash functions a cap covers depends on the cap. At one case per
    group the twelve fast-set groups reach 9 of the 12 approved functions;
    at two they reach all twelve. Since the small-set cases are too slow to
    run on every build, one case per group would have left three hash
    functions checked only by a test behind `--ignored`.
    """
    if group["signatureInterface"] == "internal":
        return 3
    return 2 if group.get("preHash") == "preHash" else 1

#: How much of a signature is kept verbatim, in bytes.
#:
#: 256 covers `R` and the beginning of the FORS signature at every
#: parameter set, which is where an error in `PRF_msg`, `H_msg` or the
#: first FORS tree first becomes visible. The rest is covered by the
#: digest, which catches any difference but says nothing about where.
PREFIX_BYTES = 256


def fetch(directory: str, name: str, keep: bool) -> dict:
    """One ACVP file, cached beside the output while `--keep` is set."""
    cache = ROOT / "vectors" / f".acvp-{directory}-{name}"
    if keep and cache.exists():
        print(f"  {directory}/{name}: cached")
        return json.loads(cache.read_text())

    url = f"{BASE}/{directory}/{name}"
    print(f"  {directory}/{name}: fetching")
    with urllib.request.urlopen(url, timeout=300) as response:
        raw = response.read()
    print(f"    {len(raw):,} bytes")
    if keep:
        cache.write_bytes(raw)
    return json.loads(raw)


def joined(directory: str, keep: bool):
    """`(header, groups)` with each test's inputs and answers merged.

    ACVP keeps them apart - `prompt.json` has what to do and
    `expectedResults.json` what should come out - joined on `tcId` within
    a group. **Joined by dictionary rather than by position**, because two
    lists in the same order is an assumption, and a silent
    mis-registration here would produce a file full of right-looking
    numbers attached to the wrong inputs.
    """
    prompt = fetch(directory, "prompt.json", keep)
    expected = fetch(directory, "expectedResults.json", keep)

    answers = {}
    for group in expected["testGroups"]:
        for test in group["tests"]:
            answers[(group["tgId"], test["tcId"])] = test

    header = {
        "algorithm": prompt.get("algorithm"),
        "mode": prompt.get("mode"),
        "revision": prompt.get("revision"),
        "vsId": prompt.get("vsId"),
    }
    groups = []
    for group in prompt["testGroups"]:
        merged = []
        for test in group["tests"]:
            answer = answers.get((group["tgId"], test["tcId"]))
            if answer is None:
                raise SystemExit(
                    f"{directory}: test {group['tgId']}/{test['tcId']} has no "
                    f"expected result. The two files do not describe the same "
                    f"vector set.")
            row = dict(test)
            row.update({k: v for k, v in answer.items() if k != "tcId"})
            merged.append(row)
        groups.append((group, merged))
    return header, groups


#: The fields written out, in order, per mode. Anything else in the ACVP
#: test object is dropped - deliberately listed rather than "everything
#: that is a string", so a new field in a future ACVP release shows up as
#: a missing one here rather than being copied in unnoticed.
FIELDS = {
    "keyGen": ["skSeed", "skPrf", "pkSeed", "sk", "pk"],
    "sigGen": ["sk", "message"],
}

#: Fields that exist only for some `sigGen` groups.
#:
#: Appended rather than listed in `FIELDS` so that their absence from a
#: group that should not have them is not mistaken for the ACVP shape
#: having changed - `write` raises on a missing `FIELDS` entry, and these
#: are genuinely conditional. `hashAlg` is a field of the *test* rather
#: than of the group, which is why the pre-hash groups cover twelve hash
#: functions in seven tests.
CONDITIONAL = [
    ("additionalRandomness", lambda g: not g["deterministic"]),
    ("context", lambda g: g["signatureInterface"] == "external"),
    ("hashAlg", lambda g: g.get("preHash") == "preHash"),
]


def label(mode: str, group) -> str:
    """The section name, which has to identify a group uniquely.

    For `keyGen` the parameter set is enough. For `sigGen` it is not:
    there are two groups per parameter set kept here, deterministic and
    hedged, and they produce different signatures from the same key and
    message. Two sections with the same header would make "the count in
    the header" ambiguous, which is the one thing the header is for - so
    the variant goes in the mode token.
    """
    if mode != "sigGen":
        return mode
    kind = "deterministic" if group["deterministic"] else "hedged"
    interface = group["signatureInterface"]
    if interface == "external":
        # `pure` or `preHash`, which change the message that gets signed
        # and so are as much part of the section's identity as the rest.
        interface = f"{interface}-{group['preHash']}"
    return f"{mode}-{interface}-{kind}"


def derived(test) -> list:
    """`(name, value)` pairs computed from a test rather than copied.

    Only the signature, and only because keeping 4.4 MB of signatures
    would be worse. The module docstring argues why a digest is as good a
    check as the bytes for a deterministic signature, and why the prefix
    is kept as well.
    """
    signature = test["signature"]
    if len(signature) % 2:
        raise SystemExit(f"tcId {test['tcId']}: signature is not whole bytes")
    raw = bytes.fromhex(signature)
    return [("signatureLength", len(raw)),
            ("signaturePrefix", signature[:2 * PREFIX_BYTES].upper()),
            ("signatureDigest", hashlib.sha256(raw).hexdigest().upper())]


def write(handle, header, groups, mode: str, cap):
    kept = 0
    for group, tests in groups:
        if mode == "sigGen":
            cap = siggen_cap(group)
        chosen = tests if cap is None else sorted(
            tests, key=lambda t: t["tcId"])[:cap]
        # **The count goes in the section header.** The reader asserts it
        # before using anything, which is what stops a parse that finds
        # nothing from turning the test into an empty loop that passes.
        handle.write(f"\n[{label(mode, group)} {group['parameterSet']} "
                     f"{len(chosen)}]\n")
        for key in ("deterministic", "signatureInterface", "preHash"):
            if key in group:
                handle.write(f"# {key} = {group[key]}\n")

        fields = list(FIELDS[mode])
        if mode == "sigGen":
            fields += [name for name, applies in CONDITIONAL if applies(group)]

        for test in chosen:
            handle.write("\n")
            handle.write(f"tcId = {test['tcId']}\n")
            for field in fields:
                if field not in test:
                    raise SystemExit(
                        f"{mode} {group['parameterSet']} tcId {test['tcId']}: "
                        f"no {field!r}. The ACVP shape has changed; update "
                        f"FIELDS in this script rather than dropping it.")
                handle.write(f"{field} = {test[field]}\n")
            if mode == "sigGen":
                for name, value in derived(test):
                    handle.write(f"{name} = {value}\n")
            kept += 1
    return kept


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true",
                        help="cache the downloaded JSON beside the output")
    arguments = parser.parse_args()

    sections = []
    for directory, cap in MODES:
        mode = directory.split("-")[2]          # keyGen, sigGen, sigVer
        print(f"{directory}:")
        header, groups = joined(directory, arguments.keep)
        sections.append((mode, cap, header, groups))

    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write("# SLH-DSA (FIPS 205) test vectors from NIST's ACVP "
                     "files.\n#\n")
        handle.write("# Generated by scripts/make_slh_dsa_vectors.py. Do not "
                     "edit: every\n# number here is NIST's answer, and a hand "
                     "edit makes it ours again,\n# which is the one thing this "
                     "file exists not to be.\n#\n")
        handle.write("# Source: usnistgov/ACVP-Server, gen-val/json-files.\n")
        for mode, _cap, header, _groups in sections:
            handle.write(f"#   {header['algorithm']} {header['mode']} "
                         f"{header['revision']} (vsId {header['vsId']})\n")
        handle.write("#\n# **Nothing on this machine implements SLH-DSA.** "
                     "python-cryptography 46\n# does not have it and OpenSSL "
                     "added it in 3.5, where this container has\n# 3.0. These "
                     "numbers are therefore the whole of the independent\n"
                     "# opinion rather than a supplement to one, which is why "
                     "each section\n# header carries its count and the reader "
                     "asserts it.\n#\n"
                     "# A section is `[mode parameterSet count]`, where the "
                     "mode carries the\n# signing variant: sigGen-internal-"
                     "deterministic and -hedged produce\n# different "
                     "signatures from the same key and message, so they are\n"
                     "# different sections.\n#\n"
                     "# **A sigGen signature is not stored whole.** Each case "
                     "carries its\n# length, its first 256 bytes, and the "
                     "SHA-256 of all of it. For a\n# deterministic signature "
                     "there is one right answer, so a matching\n# digest "
                     "proves byte-for-byte equality; the prefix is kept so "
                     "that a\n# mismatch says roughly where. Storing all 72 "
                     "groups in full would be\n# 4.4 MB, ten times the "
                     "largest vector file in this repository.\n")

        total = 0
        for mode, cap, header, groups in sections:
            total += write(handle, header, groups, mode, cap)

    print(f"\nwrote {OUT.relative_to(ROOT)}: {total} cases, "
          f"{OUT.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
