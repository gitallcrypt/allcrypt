#!/usr/bin/env python3
"""Write vectors/lms.vec: LMS and HSS (RFC 8554, RFC 9858).

    sh scripts/witness/lms/build.sh /opt/lmswitness
    python3 scripts/make_lms_vectors.py [/opt/lmswitness]

**A development tool, not a test.** `tests/test_lms_vectors.rs` and
`pytests/test_lms.py` read the file offline.

Rows, hex fields, "-" for empty; types are names:

    lms lms= ots= seed= i= q= msg= public= sig= witnesses=
    hss levels=LMS/OTS,LMS/OTS.. seed= i= count= msg= public= sig= witnesses=
    bad what= public= msg= sig= witnesses=

`lms` is one tree from SEED and I signing at leaf q: every LM-OTS
parameter set under the height-5 LMS set of its hash, at the first,
second, a random and the last leaf, and the w = 1 and 2 sets at height
10. `hss` is a hierarchy whose top tree is SEED and I, after `count`
signatures, the trees below derived as hash-sigs derives them: two
levels of each hash, at the counts either side of a lower tree running
out and at the last; a top and a lower tree of different hashes and
heights, of one length; three levels; and one. `bad` is an HSS public
key, message and signature that must not verify: one part of a good
signature changed at a time, in w = 4 and 8 trees of every hash and
two-level hierarchies. `lms` signatures are bare LMS signatures; `bad`
ones are in the HSS form, a one-level hierarchy for a tree.

Witnesses, from scripts/witness/lms: hash-sigs and Bouncy Castle 1.77
sign every `lms` and `hss` row, and pyhsslms every `lms` row, all
agreeing; then every verifier that takes the row - those three and the
hbs-lms crate, which takes the SHA-256/256 sets - must accept it, and
refuse every `bad` row - but for a signature with a byte added at the
end, which only hash-sigs refuses: Bouncy Castle, pyhsslms and hbs-lms
ignore what follows the signature, so that row leaves them out.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "lms.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "lms"))
from selftest import SIGNERS, WITNESSES, ask, lms_sig_len  # noqa: E402

# Bouncy Castle 1.77, pyhsslms and hbs-lms read an HSS signature from the
# front and ignore bytes past its end; RFC 8554 section 9 makes a signature
# over an object of the wrong length invalid, and hash-sigs refuses it.
# They are left out of that row and held to accepting it.
ACCEPTS = {("bc-lms", "long"), ("pyhsslms", "long"), ("hbs-lms", "long")}

HASHES = [("SHA256", 32, "SHA256", 32), ("SHA256", 24, "SHA256", 24),
          ("SHAKE", 32, "SHAKE", 32), ("SHAKE", 24, "SHAKE", 24)]


def lms_set(family, m, h):
    base = {("SHA256", 32): 5, ("SHA256", 24): 10, ("SHAKE", 32): 15, ("SHAKE", 24): 20}
    return base[family, m] + [5, 10, 15, 20, 25].index(h), f"LMS_{family}_M{m}_H{h}"


def ots_set(family, n, w):
    base = {("SHA256", 32): 1, ("SHA256", 24): 5, ("SHAKE", 32): 9, ("SHAKE", 24): 13}
    return base[family, n] + [1, 2, 4, 8].index(w), f"LMOTS_{family}_N{n}_W{w}"


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/lmswitness"
    rng = random.Random(20190416)
    lengths = iter([0, 1, 2, 31, 32, 33, 64, 100, 255, 1000] * 100)

    def message():
        return rng.randbytes(next(lengths))

    signing = []  # (kind, fields, request)
    for family, m, _, _ in HASHES:
        for w in (1, 2, 4, 8):
            lms, ots = lms_set(family, m, 5), ots_set(family, m, w)
            seed_i = rng.randbytes(m + 16)
            for q in (0, 1, rng.randrange(2, 31), 31):
                signing.append(("lms", (lms, ots, seed_i, q)))
        for w in (1, 2):
            lms, ots = lms_set(family, m, 10), ots_set(family, m, w)
            seed_i = rng.randbytes(m + 16)
            for q in (0, 513, 1023):
                signing.append(("lms", (lms, ots, seed_i, q)))
    hierarchies = []
    for family, m, _, _ in HASHES:
        w = {32: 4, 24: 2}[m] if family == "SHA256" else {32: 2, 24: 4}[m]
        level = (lms_set(family, m, 5), ots_set(family, m, w))
        hierarchies.append(([level, level], [0, 1, 31, 32, 33, 1023]))
    # Hashes that differ between levels but not in length: where the lengths
    # differ, hash-sigs and Bouncy Castle size the lower tree's SEED
    # differently, and no standard says which is meant.
    hierarchies.append(([(lms_set("SHA256", 32, 10), ots_set("SHA256", 32, 1)),
                         (lms_set("SHAKE", 32, 5), ots_set("SHAKE", 32, 2))],
                        [0, 31, 32, 32767]))
    hierarchies.append(([(lms_set("SHAKE", 24, 5), ots_set("SHAKE", 24, 1)),
                         (lms_set("SHA256", 24, 5), ots_set("SHA256", 24, 2))],
                        [0, 32, 1023]))
    three = (lms_set("SHA256", 24, 5), ots_set("SHA256", 24, 2))
    hierarchies.append(([three] * 3, [0, 1023, 1024, 32767]))
    hierarchies.append(([(lms_set("SHA256", 32, 5), ots_set("SHA256", 32, 4))], [0, 31]))
    for levels, counts in hierarchies:
        top = levels[0][0][0]
        seed_i = rng.randbytes((32 if top < 10 or 15 <= top < 20 else 24) + 16)
        for count in counts:
            signing.append(("hss", (levels, seed_i, count)))

    requests, messages = [], []
    for kind, f in signing:
        msg = message()
        messages.append(msg)
        if kind == "lms":
            (lms, _), (ots, _), seed_i, q = f
            requests.append(f"lms {lms} {ots} {seed_i.hex()} {q} {msg.hex() or '-'}")
        else:
            levels, seed_i, count = f
            types = " ".join(f"{a[0]} {b[0]}" for a, b in levels)
            requests.append(f"hss {len(levels)} {types} {seed_i.hex()} {count} "
                            f"{msg.hex() or '-'}")
    answers = {w: ask(out, w, requests) for w in WITNESSES}
    signed = []
    for i, (kind, f) in enumerate(signing):
        given = {w: answers[w][i] for w in SIGNERS[kind]}
        for w, a in given.items():
            if a.startswith("error"):
                sys.exit(f"{w} refused {requests[i][:80]}: {a}")
        if len(set(given.values())) != 1:
            sys.exit(f"the signers disagree on {requests[i][:80]}")
        public, sig = bytes.fromhex(given["hashsigs"].split()[0]), bytes.fromhex(
            given["hashsigs"].split()[1])
        if kind == "lms":
            public, sig = (1).to_bytes(4, "big") + public, bytes(4) + sig
        signed.append((kind, f, messages[i], public, sig, list(given)))

    # Every signature through every verifier.
    checks = [f"verify {p.hex()} {m.hex() or '-'} {s.hex()}" for _, _, m, p, s, _ in signed]
    verdicts = {w: ask(out, w, checks) for w in WITNESSES}
    lines = []
    for i, (kind, f, msg, public, sig, signers) in enumerate(signed):
        verifiers = []
        for w in WITNESSES:
            v = verdicts[w][i]
            if v == "error unsupported" and w == "hbs-lms":
                continue
            if v != "ok":
                sys.exit(f"{w} does not verify {checks[i][:80]}: {v}")
            verifiers.append(w)
        names = ",".join(dict.fromkeys(signers + verifiers))
        if kind == "lms":
            (_, lms), (_, ots), seed_i, q = f
            m = len(seed_i) - 16
            lines.append(f"lms lms={lms} ots={ots} seed={seed_i[:m].hex()} i={seed_i[m:].hex()} "
                         f"q={q} msg={msg.hex() or '-'} public={public[4:].hex()} "
                         f"sig={sig[4:].hex()} witnesses={names}")
        else:
            levels, seed_i, count = f
            m = len(seed_i) - 16
            spec = ",".join(f"{a[1]}/{b[1]}" for a, b in levels)
            lines.append(f"hss levels={spec} seed={seed_i[:m].hex()} i={seed_i[m:].hex()} "
                         f"count={count} msg={msg.hex() or '-'} public={public.hex()} "
                         f"sig={sig.hex()} witnesses={names}")

    # Bad signatures: one part of a good one changed at a time.
    bad = []
    # From the shorter signatures: w = 4 and 8 trees of each hash, and the
    # two-level w = 4 hierarchies.
    picks = [s for s in signed if s[0] == "lms" and s[1][3] == 1
             and s[1][1][1].endswith(("_W4", "_W8"))] + \
        [s for s in signed if s[0] == "hss" and len(s[1][0]) == 2 and s[1][2] == 33
         and s[1][0][1][1][1].endswith("_W4")]
    for kind, f, msg, public, sig, _ in picks:
        body = sig[4:]
        first = lms_sig_len(body)
        ots = int.from_bytes(body[4:8], "big")
        n = 32 if ots in (1, 2, 3, 4, 9, 10, 11, 12) else 24
        p = {32: [265, 133, 67, 34], 24: [200, 101, 51, 26]}[n][(ots - 1) % 4]
        lms_at = 8 + n * (p + 1)   # the LMS type, after the one-time signature

        def flip(at, data=sig):
            b = bytearray(data)
            b[at] ^= 0x01
            return bytes(b)
        q = int.from_bytes(body[:4], "big")
        cases = [
            ("message", public, msg + b"\x00", sig),
            ("q", public, msg, sig[:4] + (q ^ 1).to_bytes(4, "big") + sig[8:]),
            ("ots-type", public, msg, sig[:8] + (int.from_bytes(body[4:8], "big") ^ 1)
             .to_bytes(4, "big") + sig[12:]),
            ("C", public, msg, flip(12)),
            ("y-first", public, msg, flip(12 + n)),
            ("y-last", public, msg, flip(4 + lms_at - 1)),
            ("lms-type", public, msg, flip(4 + lms_at + 3)),
            ("path-first", public, msg, flip(4 + lms_at + 4)),
            ("path-last", public, msg, flip(4 + first - 1)),
            ("short", public, msg, sig[:-1]),
            ("long", public, msg, sig + b"\x00"),
            ("nspk", public, msg, flip(3)),
            ("levels", flip(3, public), msg, sig),
            ("root", flip(len(public) - 1, public), msg, sig),
            ("empty", public, msg, b""),
        ]
        if kind == "hss":
            cases.append(("chain-public", public, msg, flip(4 + first + 8)))
            cases.append(("last-signature", public, msg, flip(len(sig) - 1)))
        else:
            leaves = 1 << ((first - lms_at - 4) // n)
            cases.append(("q-past-the-tree", public, msg,
                          sig[:4] + leaves.to_bytes(4, "big") + sig[8:]))
        for what, p, m, s in cases:
            bad.append((what, p, m, s))
    checks = [f"verify {p.hex()} {m.hex() or '-'} {s.hex() or '-'}" for _, p, m, s in bad]
    verdicts = {w: ask(out, w, checks) for w in WITNESSES}
    for i, (what, p, m, s) in enumerate(bad):
        names = []
        for w in WITNESSES:
            v = verdicts[w][i]
            if v == "error unsupported" and w == "hbs-lms":
                continue
            if (w, what) in ACCEPTS:
                if v != "ok":
                    sys.exit(f"{w} has stopped accepting the changed {what}; look again")
                continue
            if v != "bad":
                sys.exit(f"{w} answers {v} to the changed {what}: {checks[i][:80]}")
            names.append(w)
        lines.append(f"bad what={what} public={p.hex()} msg={m.hex() or '-'} "
                     f"sig={s.hex() or '-'} witnesses={','.join(names)}")

    header = [
        "# LMS and HSS (RFC 8554, RFC 9858). Written by scripts/make_lms_vectors.py; do not",
        "# edit. lms: one tree from SEED and I signing at leaf q; hss: a hierarchy from its top",
        "# tree's SEED and I after count signatures, the lower trees derived as hash-sigs",
        "# derives them; bad: an HSS public key, message and signature that must not verify.",
        "# witnesses: hash-sigs, Bouncy Castle 1.77 and pyhsslms signing, agreeing, and every",
        "# verifier that takes the row - those and hbs-lms - accepting it or refusing it.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
