#!/usr/bin/env python3
"""Write vectors/xmss.vec: XMSS and XMSS^MT (RFC 8391, SP 800-208).

    sh scripts/witness/xmss/build.sh /opt/xmsswitness
    python3 scripts/make_xmss_vectors.py [/opt/xmsswitness]

**A development tool, not a test.** `tests/test_xmss.rs` and
`pytests/test_xmss.py` read the file offline.

Rows, hex fields, "-" for empty; <kind> is xmss or xmssmt:

    sign kind= set= sk_seed= sk_prf= seed= idx= msg= public= sig= witnesses=
    rfc8391 kind= set= public= msg= sig= witnesses=
    bad kind= what= public= msg= sig= witnesses=

`sign` rows are signatures from the three seeds at index idx, WOTS+ keys
derived as SP 800-208 requires: every XMSS set at height 10, at a random
index, and SHA2_10_256 at the first and last - under the seeds of the
reference implementation's keys in Botan's tests (vectors/botan_xmss/),
so building one tree checks that key and the signature together; every
XMSS^MT family of RFC 8391's at 20/4 (trees of height 5) across the ends
of the lowest and second trees and at the index before the last; 20/2
across its lowest tree's end; and 40/8 and 60/12 at indices that need
every byte of theirs. The reference
implementation signs them all and Botan 3.6.1 the XMSS ones, agreeing;
every verifier that takes a row accepts it - those and Bouncy Castle
1.77, which takes RFC 8391's sets. The reference's signature with the
last leaf is wrong - it wipes the key first and signs with what is left
- so SHA2_10_256's last index is Botan's alone, and verified by the
others, and no XMSS^MT row is at the last index. SP 800-208's XMSS^MT
sets have no second implementation here - Botan has no XMSS^MT and
Bouncy Castle 1.77 knows only RFC 8391's sets - so they have no rows:
they are SP 800-208's XMSS trees, which Botan checks, under RFC 8391's
layering, which Bouncy Castle checks.

`rfc8391` rows are signatures Bouncy Castle made with its own key
derivation, RFC 8391's suggestion, which nothing here signs with: they
are for verifying, and every verifier that takes one accepts it.

`bad` rows are a public key, message and signature that must not
verify: one part of a good signature changed at a time, and every
verifier that takes one refuses it - but Bouncy Castle's XMSS, which
accepts an XMSS signature with a byte appended, so those rows leave it
out.
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "xmss.vec")
sys.path.insert(0, os.path.join(HERE, "witness", "xmss"))
from selftest import FAMILIES, SIGNERS, WITNESSES, ask, botan_rows  # noqa: E402

# Bouncy Castle 1.77's XMSSSigner reads a signature from the front and
# ignores a byte past its end; its XMSSMTSigner refuses one. It is left out
# of those rows and held to accepting them.
ACCEPTS = {("bc-xmss", ("long", "xmss"))}

MT_SHAPES = [(20, 2), (20, 4), (40, 2), (40, 4), (40, 8), (60, 3), (60, 6), (60, 12)]
N = [32, 64, 32, 64, 24, 32, 24]


def xmss_set(family, h):
    i = FAMILIES.index(family)
    return 3 * i + [10, 16, 20].index(h) + 1, "XMSS-" + FAMILIES[i].format(h), N[i], h, 1


def mt_set(family, h, d):
    i = FAMILIES.index(family)
    name = "XMSSMT-" + FAMILIES[i].format(f"{h}/{d}")
    return 8 * i + MT_SHAPES.index((h, d)) + 1, name, N[i], h, d


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/xmsswitness"
    rng = random.Random(20180508)
    lengths = iter([0, 1, 31, 32, 33, 100, 1000, 3] * 100)
    jobs = []  # (request kind, xmss kind, set, seeds, idx)
    # The XMSS rows sign with the seeds of the reference implementation's
    # keys in Botan's tests, one per family, so that one tree checks both.
    reference = {r["Params"]: bytes.fromhex(r["SecretSeed"] + r["SecretPrf"] + r["PublicSeed"])
                 for r in botan_rows("xmss_keygen_reference.vec")}
    for family in FAMILIES:
        s = xmss_set(family, 10)
        jobs.append(("sign", "xmss", s, reference[s[1]], rng.randrange(1, 1023)))
    s = xmss_set(FAMILIES[0], 10)
    jobs += [("sign", "xmss", s, reference[s[1]], 0), ("sign", "xmss", s, reference[s[1]], 1023)]
    for family in FAMILIES[:4]:
        s = mt_set(family, 20, 4)
        seeds = rng.randbytes(3 * s[2])
        for idx in (0, 31, 32, 1023, 1024, (1 << 20) - 2):
            jobs.append(("sign", "xmssmt", s, seeds, idx))
    s = mt_set(FAMILIES[0], 20, 2)
    seeds = rng.randbytes(96)
    jobs += [("sign", "xmssmt", s, seeds, 1023), ("sign", "xmssmt", s, seeds, 1024)]
    for family, h, d in ((FAMILIES[0], 40, 8), (FAMILIES[3], 40, 8), (FAMILIES[0], 60, 12)):
        s = mt_set(family, h, d)
        jobs.append(("sign", "xmssmt", s, rng.randbytes(3 * s[2]),
                     (1 << (h - 1)) | rng.getrandbits(h - 1)))
    for kind, s, idx in (("xmss", xmss_set(FAMILIES[0], 10), 0),
                         ("xmss", xmss_set(FAMILIES[0], 10), 1),
                         ("xmss", xmss_set(FAMILIES[3], 10), 2),
                         ("xmssmt", mt_set(FAMILIES[0], 20, 4), 0),
                         ("xmssmt", mt_set(FAMILIES[2], 20, 4), 3)):
        jobs.append(("sign-rfc8391", kind, s, rng.randbytes(3 * s[2]), idx))

    messages = [rng.randbytes(next(lengths)) for _ in jobs]
    requests = [f"{r} {k} {s[0]} {seeds.hex()} {idx} {m.hex() or '-'}"
                for (r, k, s, seeds, idx), m in zip(jobs, messages)]
    answers = {w: ask(out, w, requests) for w in WITNESSES}
    signed = []
    for i, (r, kind, s, seeds, idx) in enumerate(jobs):
        given = {}
        last = idx == (1 << s[3]) - 1
        for w in SIGNERS[r]:
            a = answers[w][i]
            if w == "ref-xmss" and last:
                # The reference wipes the key before it signs with the last
                # leaf, and signs with what is left: index all ones, seeds
                # zero. Held to it, and left out.
                if bytes.fromhex(a.split()[1])[:4] != b"\xff" * 4:
                    sys.exit("the reference signs its last leaf now; look again")
                continue
            if a == "error unsupported" and w == "botan-xmss" and kind == "xmssmt":
                continue
            if a.startswith("error"):
                sys.exit(f"{w} refused {requests[i][:80]}: {a}")
            given[w] = a
        if len(set(given.values())) != 1:
            sys.exit(f"the signers disagree on {requests[i][:80]}")
        public, sig = next(iter(given.values())).split()
        signed.append((r, kind, s, seeds, idx, messages[i], bytes.fromhex(public),
                       bytes.fromhex(sig), list(given)))

    def verify_all(rows, want, labels=None):
        labels = labels or [None] * len(rows)
        checks = [f"verify {kind} {p.hex()} {m.hex() or '-'} {sig.hex() or '-'}"
                  for kind, p, m, sig in rows]
        verdicts = {w: ask(out, w, checks) for w in WITNESSES}
        names = []
        for i in range(len(rows)):
            took = []
            for w in WITNESSES:
                v = verdicts[w][i]
                if v == "error unsupported":
                    continue
                if (w, labels[i]) in ACCEPTS:
                    if v != "ok":
                        sys.exit(f"{w} has stopped accepting {labels[i]}; look again")
                    continue
                if v != want:
                    sys.exit(f"{w} answers {v} to {checks[i][:80]}, not {want}")
                took.append(w)
            names.append(took)
        return names

    verifiers = verify_all([(k, p, m, sig) for _, k, _, _, _, m, p, sig, _ in signed], "ok")
    lines = []
    for (r, kind, s, seeds, idx, msg, public, sig, signers), took in zip(signed, verifiers):
        names = ",".join(dict.fromkeys(signers + took))
        if len(names.split(",")) < 2:
            sys.exit(f"fewer than two witnesses for {s[1]} at {idx}")
        if r == "sign":
            n = s[2]
            lines.append(f"sign kind={kind} set={s[1]} sk_seed={seeds[:n].hex()} "
                         f"sk_prf={seeds[n:2 * n].hex()} seed={seeds[2 * n:].hex()} idx={idx} "
                         f"msg={msg.hex() or '-'} public={public.hex()} sig={sig.hex()} "
                         f"witnesses={names}")
        else:
            lines.append(f"rfc8391 kind={kind} set={s[1]} public={public.hex()} "
                         f"msg={msg.hex() or '-'} sig={sig.hex()} witnesses={names}")

    # Bad signatures, from a few of the good ones.
    bad = []
    picks = [x for x in signed if x[0] == "sign" and (
        (x[2][1] in ("XMSS-SHA2_10_192", "XMSS-SHAKE_10_256") and x[1] == "xmss")
        or (x[2][1] in ("XMSSMT-SHA2_20/4_256", "XMSSMT-SHAKE_20/4_256") and x[4] == 1024))]
    for r, kind, s, seeds, idx, msg, public, sig, _ in picks:
        _, name, n, h, d = s
        ilen = 4 if kind == "xmss" else (h + 7) // 8
        wots = (2 * n + 3) * n
        layer = wots + (h // d) * n

        def flip(at, data=sig):
            b = bytearray(data)
            b[at] ^= 0x01
            return bytes(b)
        first = ilen + n  # the first WOTS+ signature
        cases = [
            ("message", public, msg + b"\x00", sig),
            ("index", public, msg, (idx ^ 1).to_bytes(ilen, "big") + sig[ilen:]),
            ("index-past-the-end", public, msg,
             ((1 << h) if h < 8 * ilen else (1 << (8 * ilen)) - 1).to_bytes(ilen, "big")
             + sig[ilen:]),
            ("r", public, msg, flip(ilen)),
            ("wots-first", public, msg, flip(first)),
            ("wots-last", public, msg, flip(first + wots - 1)),
            ("auth-first", public, msg, flip(first + wots)),
            ("auth-last", public, msg, flip(first + layer - 1)),
            ("short", public, msg, sig[:-1]),
            ("long", public, msg, sig + b"\x00"),
            ("root", flip(4, public), msg, sig),
            ("seed", flip(len(public) - 1, public), msg, sig),
            ("empty", public, msg, b""),
        ]
        if d > 1:
            cases.append(("upper-layer", public, msg, flip(first + layer + 5)))
        bad += [(what, kind, p, m, sg) for what, p, m, sg in cases]
    # The index past the end only exists where the index has spare bits.
    bad = [b for b in bad if b[0] != "index-past-the-end" or b[1] == "xmss"
           or int.from_bytes(b[4][:(20 + 7) // 8], "big") >= 1 << 20]
    took = verify_all([(k, p, m, sg) for _, k, p, m, sg in bad], "bad",
                      [(what, kind) for what, kind, _, _, _ in bad])
    for (what, kind, p, m, sg), names in zip(bad, took):
        lines.append(f"bad kind={kind} what={what} public={p.hex()} msg={m.hex() or '-'} "
                     f"sig={sg.hex() or '-'} witnesses={','.join(names)}")

    header = [
        "# XMSS and XMSS^MT (RFC 8391, SP 800-208). Written by scripts/make_xmss_vectors.py;",
        "# do not edit. sign: from SK_SEED, SK_PRF and SEED at index idx, WOTS+ keys derived",
        "# as SP 800-208 requires; rfc8391: signed by Bouncy Castle 1.77 with RFC 8391's",
        "# derivation, for verifying; bad: must not verify. witnesses: the XMSS reference",
        "# implementation and Botan 3.6.1 signing, agreeing, and every verifier that takes",
        "# the row - those and Bouncy Castle - accepting or refusing it.",
        f"# rows: {len(lines)}",
    ]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(header + lines) + "\n")
    print(f"wrote {OUTPUT}: {len(lines)} rows")


if __name__ == "__main__":
    main()
