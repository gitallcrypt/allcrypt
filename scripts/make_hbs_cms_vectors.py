#!/usr/bin/env python3
"""Write vectors/hbs_cms.vec: HSS (RFC 9708), XMSS and XMSS^MT SignedData,
both ways between the CMS example and Bouncy Castle 1.85.

    sh scripts/witness/hbsx509/build.sh /opt/hbswitness
    cargo build --release -p allcrypt-tools --bin hbs_certs
    cargo build --release --example cms
    python3 scripts/make_hbs_cms_vectors.py [/opt/hbswitness]

**A development tool, not a test.** The CMS example's tests read the file
offline.

Rows, hex fields, `-` for empty:

    bc scheme= params= digest= attrs= detached= content= message= witnesses=bc-hbs
    ours scheme=hss levels= state= attrs= detached= content= message= witnesses=bc-hbs
    ours scheme=xmss set= state= attrs= detached= content= message= witnesses=bc-hbs

A `bc` row is a message Bouncy Castle signed with a key it generated,
carrying that key's self-signed certificate; `params` is its witness's
form and `digest` the digest it was told to use, or `default` for its own
choice. Bouncy Castle verified it, and refused it over other content.

An `ours` row is a message the CMS example's `sign` made from a
certificate `hbs_certs` issued and the key's state after issuing it
(`state`), run as a user would run it: certificate and key in files, the
key file written back. Bouncy Castle verified it, and refused it with a
byte of the signature changed and over other content. HSS and XMSS
signing are deterministic, so the test makes it again byte for byte from
`state` and the signing time the message carries.

The certificate is in every message, so it is not repeated in the row.
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "hbs_cms.vec")
TOOL = os.path.join(ROOT, "target", "release", "hbs_certs")
CMS = os.path.join(ROOT, "target", "release", "examples", "cms")
sys.path.insert(0, os.path.join(HERE, "witness", "hbsx509"))
from selftest import Bc  # noqa: E402

# Bouncy Castle's messages: (scheme, params, digest, attrs, detached).
# Its own digest for HSS is the tree's hash, which for a SHAKE tree it
# writes as id-shake256-len without the length and then cannot use (a
# NullPointerException), so the SHAKE rows name SHAKE256. For XMSS it has
# no rule and the digest is always named; one row names a digest other
# than the tree's hash.
BC = [("hss", ["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8"], "default", True, False),
      ("hss", ["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W4"], "default", False, True),
      ("hss", ["LMS_SHA256_M24_H5/LMOTS_SHA256_N24_W8"], "default", True, True),
      ("hss", ["LMS_SHAKE_M32_H5/LMOTS_SHAKE_N32_W8"], "SHAKE256", True, False),
      ("hss", ["LMS_SHAKE_M24_H5/LMOTS_SHAKE_N24_W4"], "SHAKE256", False, False),
      ("hss", ["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8", "LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W2"],
       "default", True, True),
      ("xmss", "10/SHA256", "SHA256", True, False),
      ("xmss", "10/SHA256", "SHA256", False, True),
      ("xmss", "10/SHA256", "SHA512", True, False),
      ("xmss", "10/SHAKE256/256", "SHAKE256", True, True),
      ("xmssmt", "20/2/SHA256", "SHA256", True, False),
      ("xmssmt", "20/4/SHA256", "SHA256", False, True)]

# This library's, through the example's `sign`: (levels or set, index,
# attrs, detached). Not SP 800-208's 192 bit XMSS sets, which Bouncy
# Castle 1.85 gets wrong (scripts/make_hbs_x509_vectors.py).
OURS_HSS = [(["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8"], 0, True, False),
            (["LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8"], 3, False, True),
            (["LMS_SHA256_M24_H5/LMOTS_SHA256_N24_W4"], 7, True, False),
            (["LMS_SHAKE_M32_H5/LMOTS_SHAKE_N32_W8", "LMS_SHAKE_M32_H5/LMOTS_SHAKE_N32_W4"], 100,
             True, True),
            (["LMS_SHAKE_M24_H5/LMOTS_SHAKE_N24_W8"], 1, False, False)]
OURS_XMSS = [("XMSS-SHA2_10_256", 0, True, False), ("XMSS-SHA2_10_256", 513, False, True),
             ("XMSS-SHAKE_10_256", 5, True, False), ("XMSS-SHAKE256_10_256", 3, True, True),
             ("XMSS-SHA2_10_512", 2, True, False), ("XMSSMT-SHA2_20/4_256", 33, True, False),
             ("XMSSMT-SHA2_20/4_256", 70000, False, True), ("XMSSMT-SHAKE_20/4_256", 0, True, True)]


def hexs(b):
    return b.hex() or "-"


def flag(b):
    return "yes" if b else "no"


def changed(data):
    return bytes([data[0] ^ 1]) + data[1:] if data else b"x"


def over_other_content(bc, message, data, detached):
    """Bouncy Castle's verdict on the message over content with its first
    byte changed - given beside it when detached, changed inside it when
    not. Empty attached content has no byte to change, and no row has it."""
    if detached:
        return bc.ask("cmsverify", message, hexs(changed(data)))
    # The eContent as DER writes it: id-data, [0] { OCTET STRING }.
    def length(n):
        body = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        return bytes([n]) if n < 0x80 else bytes([0x80 | len(body)]) + body
    octets = b"\x04" + length(len(data)) + data
    found = bytes.fromhex("06092a864886f70d010701") + b"\xa0" + length(len(octets)) + octets
    if not data or message.count(found.hex()) != 1:
        sys.exit("attached content to change must be non-empty and found once")
    other = found[:len(found) - len(data)] + changed(data)
    return bc.ask("cmsverify", message.replace(found.hex(), other.hex()), "attached")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/hbswitness"
    bc = Bc(out)
    codes = dict(line.split() for line in subprocess.run(
        [TOOL, "--types"], capture_output=True, text=True, check=True).stdout.splitlines())
    rng = random.Random(9708)
    lengths = iter([1, 31, 64, 200, 1000, 5000] * 10)

    # Empty content once each way, detached - attached, there would be no
    # byte of it to change.
    def content(empty=False):
        return b"" if empty else rng.randbytes(next(lengths))

    lines = []
    for i, (scheme, params, digest, attrs, detached) in enumerate(BC):
        given = (",".join("/".join(codes[n] for n in level.split("/")) for level in params)
                 if scheme == "hss" else params)
        data = content(empty=i == 1)
        words = ["cmssign", scheme, given, hexs(data), "attrs" if attrs else "noattrs",
                 "detached" if detached else "attached"] + ([] if digest == "default" else [digest])
        message = bc.ask(*words)
        if message.startswith("error"):
            sys.exit(f"Bouncy Castle refused {words[1:3]}: {message}")
        where = hexs(data) if detached else "attached"
        if bc.ask("cmsverify", message, where) != "good":
            sys.exit(f"Bouncy Castle does not verify its own {scheme} {params}")
        if not over_other_content(bc, message, data, detached).startswith("bad"):
            sys.exit(f"Bouncy Castle verifies {scheme} {params} over other content")
        shown = ",".join(params) if scheme == "hss" else params
        lines.append(f"bc scheme={scheme} params={shown} digest={digest} attrs={flag(attrs)} "
                     f"detached={flag(detached)} content={hexs(data)} message={message} "
                     "witnesses=bc-hbs")

    specs, extra = [], []
    for levels, count, attrs, detached in OURS_HSS:
        m = 24 if "M24" in levels[0] else 32
        specs.append(f"ours scheme=hss levels={','.join(levels)} seed={rng.randbytes(m).hex()} "
                     f"id={rng.randbytes(16).hex()} count={count}")
        extra.append(("hss", f"levels={','.join(levels)}", attrs, detached))
    for name, idx, attrs, detached in OURS_XMSS:
        n = 64 if name.endswith("_512") else 32
        specs.append(f"ours scheme=xmss set={name} sk_seed={rng.randbytes(n).hex()} "
                     f"sk_prf={rng.randbytes(n).hex()} seed={rng.randbytes(n).hex()} idx={idx}")
        extra.append(("xmss", f"set={name}", attrs, detached))
    made = subprocess.run([TOOL, "--state"], input="".join(s + "\n" for s in specs),
                          capture_output=True, text=True, check=True).stdout.splitlines()
    if len(made) != len(specs):
        sys.exit("hbs_certs did not answer every spec")
    with tempfile.TemporaryDirectory() as tmp:
        for i, ((cert_hex, state_hex), (scheme, named, attrs, detached)) in enumerate(zip(
                (m.split() for m in made), extra)):
            paths = {k: os.path.join(tmp, k) for k in ("cert", "key", "content", "out")}
            data = content(empty=i == 1)
            open(paths["cert"], "wb").write(bytes.fromhex(cert_hex))
            open(paths["key"], "wb").write(bytes.fromhex(state_hex))
            open(paths["content"], "wb").write(data)
            command = [CMS, "sign", paths["content"], paths["out"], "--signer", paths["cert"],
                       paths["key"]] + ([] if attrs else ["--no-attributes"]) + (
                       ["--detached"] if detached else [])
            subprocess.run(command, check=True)
            message = open(paths["out"], "rb").read().hex()
            if open(paths["key"], "rb").read().hex() == state_hex:
                sys.exit(f"sign did not move the key on: {named}")
            where = hexs(data) if detached else "attached"
            if bc.ask("cmsverify", message, where) != "good":
                sys.exit(f"Bouncy Castle does not verify {named}")
            if not over_other_content(bc, message, data, detached).startswith("bad"):
                sys.exit(f"Bouncy Castle verifies {named} over other content")
            # A byte near the end is the signature's: SignerInfos come last
            # and the signature is the SignerInfo's last field.
            bad = bytearray(bytes.fromhex(message))
            bad[-3] ^= 0x20
            if not bc.ask("cmsverify", bad.hex(), where).startswith("bad"):
                sys.exit(f"Bouncy Castle verifies a changed signature for {named}")
            lines.append(f"ours scheme={scheme} {named} state={state_hex} attrs={flag(attrs)} "
                         f"detached={flag(detached)} content={hexs(data)} message={message} "
                         "witnesses=bc-hbs")

    header = [
        "# HSS (RFC 9708), XMSS and XMSS^MT SignedData. Written by",
        "# scripts/make_hbs_cms_vectors.py; do not edit. bc: Bouncy Castle 1.85's own;",
        "# ours: the CMS example's, verified by Bouncy Castle 1.85.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
