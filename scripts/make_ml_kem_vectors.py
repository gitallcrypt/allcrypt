#!/usr/bin/env python3
"""Vendor NIST's ML-KEM test vectors from the ACVP files.

    python3 scripts/make_ml_kem_vectors.py
    python3 scripts/make_ml_kem_vectors.py --keep   # keep the downloads

Writes `vectors/ml_kem.vec`. A development tool: the gate never runs it
and needs no network. What ships is the file it writes.

## Why these carry the whole verdict, and what is different from SLH-DSA

Nothing on this machine implements ML-KEM. python-cryptography 46 has no
KEM module at all, OpenSSL here is 3.0 and grew ML-KEM in 3.5, and **PyPI
is unreachable from the development container** - `pip download six` fails
the same way `pip install kyber-py` does - so a Python reference cannot be
installed either. Checked rather than assumed.

So, as with SLH-DSA, the vectors are the independent opinion rather than a
supplement to one, and every section header carries its count for the
reader to assert.

**One thing is much better here than for SLH-DSA**, and it is worth
saying: ACVP's `encapDecap` file has `encapsulationKeyCheck` and
`decapsulationKeyCheck` groups, each half valid and half not. Those are
*negative* cases - keys somebody else decided are malformed - which is
exactly what SLH-DSA's vendored set lacks. A scheme can produce every
right answer and still accept everything, and nothing in a
"produce the right answer" vector set can see that.

## What is trimmed, and why trimming is a script rather than an edit

`keyGen` is kept whole, and so are the three `encapDecap` functions that
matter most - see `CAPS`. Only encapsulation is capped.

The `keyGen` answers are 544 KB because `dk` is up to 3,168 bytes. They are stored
as a **length and a SHA-256** rather than in full, for the same reason and
with the same justification as `make_slh_dsa_vectors.py`: key generation
from a stated `(d, z)` is deterministic, so there is one right answer and a
matching digest establishes byte equality as surely as the bytes would.
That turns 544 KB into about 20 KB.

What it loses is the ability to see *where* a wrong key diverges. For a
signature that mattered enough to keep a 256 byte prefix; here it matters
less, because `ek` is `ByteEncode_12(t_hat) ‖ rho` and `dk` ends with
`ek ‖ H(ek) ‖ z`, so a wrong key is almost never wrong in a localised way -
it is a different `t_hat` throughout. The prefix is kept anyway, at 64
bytes, because it covers the first few coefficients of `t_hat` and costs
nothing.
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
OUT = ROOT / "vectors" / "ml_kem.vec"

BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/master"
        "/gen-val/json-files")

#: `(directory, how many tests to keep per group or None for all)`.
#:
#: For `encapDecap` the cap is applied per *function*, by `CAPS` below,
#: because the four functions in that file are four different tests.
MODES = [
    ("ML-KEM-keyGen-FIPS203", None),
    ("ML-KEM-encapDecap-FIPS203", None),
]

#: How many cases to keep per group, by section name.
#:
#: **Every negative case is kept.** The two key-check functions are half
#: valid and half not, and they are the only cases anywhere in the
#: vendored post-quantum vectors where somebody other than this library
#: decided what must be *refused*. Decapsulation is kept whole as well:
#: it is where the Fujisaki-Okamoto transform is exercised, including
#: ciphertexts that must take the implicit-rejection path.
#:
#: Encapsulation is capped, because each case carries a whole `ek` as an
#: input and 25 per parameter set adds breadth of key, not of path.
CAPS = {
    "keyGen": None,
    "encapsulation": 10,
    "decapsulation": None,
    "encapsulationKeyCheck": None,
    "decapsulationKeyCheck": None,
}

#: How much of a derived key is kept verbatim, in bytes. See the module
#: docstring for why this is smaller than SLH-DSA's 256.
PREFIX_BYTES = 64


def fetch(directory: str, name: str, keep: bool) -> dict:
    """One ACVP file, cached beside the output while `--keep` is set."""
    cache = ROOT / "vectors" / f".acvp-{directory}-{name}"
    if keep and cache.exists():
        print(f"  {directory}/{name}: cached")
        return json.loads(cache.read_text())

    url = f"{BASE}/{directory}/{name}"
    print(f"  {directory}/{name}: fetching")
    with urllib.request.urlopen(url, timeout=600) as response:
        raw = response.read()
    print(f"    {len(raw):,} bytes")
    if keep:
        cache.write_bytes(raw)
    return json.loads(raw)


def joined(directory: str, keep: bool):
    """`(header, groups)` with each test's inputs and answers merged.

    Joined by `(tgId, tcId)` dictionary rather than by position, because
    two lists in the same order is an assumption and a silent
    mis-registration would produce right-looking numbers attached to the
    wrong inputs.
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


#: The fields copied straight through, per mode. Listed rather than
#: "everything that is a string", so a new field in a future ACVP release
#: shows up as a missing one here rather than being copied in unnoticed.
FIELDS = {
    "keyGen": ["d", "z"],
    # `k` is the shared secret: 32 bytes, so kept whole.
    "encapsulation": ["ek", "m", "k"],
    "decapsulation": ["dk", "c", "k"],
    "encapsulationKeyCheck": ["ek", "testPassed"],
    "decapsulationKeyCheck": ["dk", "testPassed"],
}

#: The fields stored as a length, a prefix and a digest instead of whole.
#:
#: Only *outputs* can be stored this way. An input has to be handed to
#: the code under test in full, so `ek`, `dk` and the decapsulation `c`
#: are in `FIELDS`, and only the encapsulation `c` - which this library
#: produces and NIST states - is here.
DERIVED = {
    "keyGen": ["ek", "dk"],
    "encapsulation": ["c"],
    "decapsulation": [],
    "encapsulationKeyCheck": [],
    "decapsulationKeyCheck": [],
}


def write(handle, header, groups, mode: str, cap):
    kept = 0
    for group, tests in groups:
        # The encapDecap file holds four tests under one mode; each group
        # names which one, and that name is what the section is.
        if "function" in group:
            mode = group["function"]
        if mode not in FIELDS:
            raise SystemExit(f"{mode}: not a function this script knows. "
                             f"Add it to FIELDS, DERIVED and CAPS rather "
                             f"than letting it through unread.")
        cap = CAPS[mode]
        chosen = tests if cap is None else sorted(
            tests, key=lambda t: t["tcId"])[:cap]
        # **The count goes in the section header.** The reader asserts it
        # before using anything, which is what stops a parse that finds
        # nothing from turning the test into an empty loop that passes.
        handle.write(f"\n[{mode} {group['parameterSet']} {len(chosen)}]\n")
        for test in chosen:
            handle.write("\n")
            handle.write(f"tcId = {test['tcId']}\n")
            for field in FIELDS[mode]:
                if field not in test:
                    raise SystemExit(
                        f"{mode} {group['parameterSet']} tcId {test['tcId']}: "
                        f"no {field!r}. The ACVP shape has changed; update "
                        f"FIELDS in this script rather than dropping it.")
                value = test[field]
                # JSON booleans, written the way the reader expects.
                if isinstance(value, bool):
                    value = "true" if value else "false"
                handle.write(f"{field} = {value}\n")
            for field in DERIVED[mode]:
                if field not in test:
                    raise SystemExit(
                        f"{mode} tcId {test['tcId']}: no {field!r}.")
                raw = bytes.fromhex(test[field])
                handle.write(f"{field}Length = {len(raw)}\n")
                handle.write(f"{field}Prefix = "
                             f"{raw[:PREFIX_BYTES].hex().upper()}\n")
                handle.write(f"{field}Digest = "
                             f"{hashlib.sha256(raw).hexdigest().upper()}\n")
            kept += 1
    return kept


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true",
                        help="cache the downloaded JSON beside the output")
    arguments = parser.parse_args()

    sections = []
    for directory, cap in MODES:
        mode = directory.split("-")[2]          # keyGen, encapDecap
        print(f"{directory}:")
        header, groups = joined(directory, arguments.keep)
        sections.append((mode, cap, header, groups))

    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write("# ML-KEM (FIPS 203) test vectors from NIST's ACVP "
                     "files.\n#\n")
        handle.write("# Generated by scripts/make_ml_kem_vectors.py. Do not "
                     "edit: every\n# number here is NIST's answer, and a hand "
                     "edit makes it ours again,\n# which is the one thing this "
                     "file exists not to be.\n#\n")
        handle.write("# Source: usnistgov/ACVP-Server, gen-val/json-files.\n")
        for mode, _cap, header, _groups in sections:
            handle.write(f"#   {header['algorithm']} {header['mode']} "
                         f"{header['revision']} (vsId {header['vsId']})\n")
        handle.write("#\n# **Nothing on this machine implements ML-KEM.** "
                     "python-cryptography 46\n# has no KEM module, OpenSSL "
                     "here is 3.0 and grew it in 3.5, and PyPI\n# is "
                     "unreachable from the development container so none can "
                     "be\n# installed. These numbers are therefore the whole "
                     "of the independent\n# opinion, which is why each "
                     "section header carries its count and the\n# reader "
                     "asserts it.\n#\n"
                     "# A section is `[mode parameterSet count]`.\n#\n"
                     "# **A derived key is not stored whole.** Each case "
                     "carries its length,\n# its first 64 bytes, and the "
                     "SHA-256 of all of it. Key generation\n# from a stated "
                     "(d, z) is deterministic, so a matching digest proves\n"
                     "# byte-for-byte equality; storing the keys in full "
                     "would be 544 KB.\n")

        total = 0
        for mode, cap, header, groups in sections:
            total += write(handle, header, groups, mode, cap)

    print(f"\nwrote {OUT.relative_to(ROOT)}: {total} cases, "
          f"{OUT.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
