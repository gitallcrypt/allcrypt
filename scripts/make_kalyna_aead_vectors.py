#!/usr/bin/env python3
"""Write vectors/kalyna_aead.vec: DSTU 7624:2014's GCM, GMAC, CCM and XTS
over Kalyna.

    scripts/witness/bcwitness/build.sh /opt/bcwitness
    scripts/witness/cryptonite/build.sh /opt/cryptonite
    python3 scripts/make_kalyna_aead_vectors.py

**A development tool, not a test.** It needs both witnesses built, and
fetches two files once, each checked against its SHA-256: cryptonite's
acceptance tests (`src/cryptoniteAtest/c/atest_dstu7624.c`), which carry
the examples in C arrays, and Bouncy Castle's `DSTU7624Test.java`.
`tests/test_kalyna_aead.rs` reads `vectors/kalyna_aead.vec` offline.

Two implementations that share no code, Bouncy Castle 1.77 (KGCM, KGMac,
KCCM, KXTS) and PrivatBank's cryptonite, driven through
`scripts/witness/cryptonite/driver.c`. In order:

1. Every example in cryptonite's acceptance tests must be reproduced by
   cryptonite, and by Bouncy Castle too where it takes the input - whole
   blocks, and for CCM at least one block of associated data. An example
   whose expected output also appears in Bouncy Castle's test file is
   `source=standard`; the others, all with a short last block, are
   `source=cryptonite-tests`.
2. Rows where both agree, `source=both`: whole blocks throughout, and
   for CCM associated data of at least one block and a counter that
   stays clear of a carry out of its first byte (Bouncy Castle's KCCM
   adds one to that byte alone, where Kalyna's counter mode and
   cryptonite carry).
3. Each alone where the other stops or the two part. Bouncy Castle:
   GCM and GMAC with a short last block, which it pads with zeros -
   the script requires cryptonite to give a different answer for the
   message's short block, and Bouncy Castle to fail to open its own
   output there, so both stay on record - and CCM
   messages longer than 255 bytes, which cryptonite's one-byte length
   cannot hold. cryptonite: CCM with a short block, with no associated
   data or no message, and XTS with a short last block.

Rows, hex fields, "-" for empty:

    gcm block= key= iv= q= aad= pt= ct= tag= source=
    gmac block= key= q= msg= tag= source=
    ccm block= key= iv= q= nb= aad= pt= sealed= source=
    xts block= key= iv= pt= ct= source=
"""

import hashlib
import os
import random
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "kalyna_aead.vec")
BC = os.environ.get("BC_WITNESS", "/opt/bcwitness")
CRYPTONITE = os.environ.get("CRYPTONITE_WITNESS", "/opt/cryptonite")
ATEST_URL = ("https://raw.githubusercontent.com/privat-it/cryptonite/master/src/"
             "cryptoniteAtest/c/atest_dstu7624.c")
ATEST_SHA256 = "c2ddf48cd87b8769a8d7f4bc667e2d8b10b821e1d0b1665f7f81c6acf870ca8b"
BC_URL = ("https://raw.githubusercontent.com/bcgit/bc-java/r1rv77/core/src/test/java/"
          "org/bouncycastle/crypto/test/DSTU7624Test.java")
BC_SHA256 = "e1131a41401617ab4e1fe40c196aa103f2bbd41c686758dae973f6ad04db5924"
VARIANTS = [(16, 16), (16, 32), (32, 32), (32, 64), (64, 64)]


def h(b):
    return b.hex() or "-"


def field(x):
    return x if isinstance(x, str) else h(x)


def run(command, rows, who):
    stdin = "".join(" ".join(field(x) for x in r) + "\n" for r in rows)
    out = subprocess.run(command, input=stdin, check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(rows)]
    if len(out) != len(rows):
        sys.exit(f"{who} answered {len(out)} of {len(rows)}")
    return out


def bc(op, block, rows):
    """Bouncy Castle's `op` for a block of `block` bytes; ECB when `op`
    is empty."""
    name = f"kalyna-{op}-{8 * block}" if op else f"kalyna-{8 * block}"
    return run(["java", "-cp", f"{BC}/bcprov.jar:{BC}", "UaWitness", name],
               rows, "Bouncy Castle " + (op or "ecb"))


def cn(op, block, rows):
    return run([f"{CRYPTONITE}/cryptonite-witness", str(8 * block), op], rows, "cryptonite " + op)


def ok(lines, who):
    for line in lines:
        if line.startswith("error"):
            sys.exit(f"{who} refused a row: {line}")
    return [bytes.fromhex(line) for line in lines]


def fetch(url, digest):
    with urllib.request.urlopen(url) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        sys.exit(f"{url} changed upstream; read it before trusting it")
    return data.decode()


def c_array(text, name):
    """The entries of a C array of structs of strings and integers, each
    as a list of fields; adjacent string literals are one field."""
    start = text.index(f"{name}[] = {{")
    body = text[text.index("{", start) + 1:text.index("\n};", start)]
    entries = []
    for entry in re.findall(r"\{(.*?)\}", body, re.S):
        fields = []
        for part in re.split(r",\s*(?=[\"\d])", entry.strip().rstrip(",")):
            strings = re.findall(r'"([0-9A-Fa-f]*)"', part)
            fields.append("".join(strings).lower() if strings else int(part.strip()))
        entries.append(fields)
    return entries


def main():
    atest = fetch(ATEST_URL, ATEST_SHA256)
    bc_text = fetch(BC_URL, BC_SHA256).lower()
    published = set(re.findall(r'"([0-9a-f]+)"', bc_text))
    rows = []

    def source_of(*outputs):
        return "standard" if all(o in published for o in outputs) else "cryptonite-tests"

    # 1. The examples.
    gcm = c_array(atest, "gcm_data")
    gmac = c_array(atest, "gmac_data")
    ccm = c_array(atest, "ccm_data")
    xts = c_array(atest, "xts_data")
    if (len(gcm), len(gmac), len(ccm), len(xts)) != (6, 5, 5, 10):
        sys.exit(f"read {len(gcm)} GCM, {len(gmac)} GMAC, {len(ccm)} CCM, {len(xts)} XTS")
    for key, iv, aad, pt, tag, ct, q, _ in gcm:
        block = len(iv) // 2
        req = [(key, iv, str(q), aad, pt)]
        for who, got in (("cryptonite", cn("gcm", block, req)), ("Bouncy Castle", bc("gcm", block, req))):
            if got[0] != ct + tag:
                sys.exit(f"{who} misses the GCM example under {key}")
        rows.append(f"gcm block={block} key={key} iv={iv} q={q} aad={aad} pt={pt} ct={ct} "
                    f"tag={tag} source={source_of(ct, tag)}")
    for key, msg, tag, q, block in gmac:
        req = [(key, str(q), msg)]
        for who, got in (("cryptonite", cn("gmac", block, req)), ("Bouncy Castle", bc("gmac", block, req))):
            if got[0] != tag:
                sys.exit(f"{who} misses the GMAC example under {key}")
        rows.append(f"gmac block={block} key={key} q={q} msg={msg} tag={tag} "
                    f"source={source_of(tag)}")
    for key, iv, aad, pt, mac, sealed, q, nmax in ccm:
        block, nb = len(iv) // 2, ((nmax - 3) >> 3) + 1
        req = [(key, iv, str(q), str(nmax), aad, pt)]
        if cn("ccm", block, req)[0] != sealed:
            sys.exit(f"cryptonite misses the CCM example under {key}")
        whole = len(pt) % (2 * block) == 0 and len(aad) % (2 * block) == 0 and aad
        if whole and bc("ccm", block, [(key, iv, str(q), str(nb), aad, pt)])[0] != sealed:
            sys.exit(f"Bouncy Castle misses the CCM example under {key}")
        rows.append(f"ccm block={block} key={key} iv={iv} q={q} nb={nb} aad={aad} pt={pt} "
                    f"sealed={sealed} source={source_of(mac, sealed) if whole else 'cryptonite-tests'}")
    for key, iv, pt, ct in xts:
        block = len(iv) // 2
        if cn("xts", block, [(key, iv, pt)])[0] != ct or cn("unxts", block, [(key, iv, ct)])[0] != pt:
            sys.exit(f"cryptonite misses the XTS example under {key}")
        whole = len(pt) % (2 * block) == 0
        if whole and bc("xts", block, [(key, iv, pt)])[0] != ct:
            sys.exit(f"Bouncy Castle misses the XTS example under {key}")
        rows.append(f"xts block={block} key={key} iv={iv} pt={pt} ct={ct} "
                    f"source={source_of(ct) if whole else 'cryptonite-tests'}")
    examples = len(rows)

    rng = random.Random(0x7624AEAD)
    for block, klen in VARIANTS:
        # 2 and 3: GCM.
        reqs = [(rng.randbytes(klen), rng.randbytes(block), str(q), rng.randbytes(a * block),
                 rng.randbytes(m * block))
                for a in (0, 1, 2) for m in (0, 1, 3) for q in sorted({block, 8, block // 2})]
        x, y = ok(cn("gcm", block, reqs), "cryptonite"), ok(bc("gcm", block, reqs), "Bouncy Castle")
        for r, a, b in zip(reqs, x, y):
            if a != b:
                sys.exit(f"the witnesses disagree on GCM under {r[0].hex()}")
            n = len(r[4])
            rows.append(f"gcm block={block} key={r[0].hex()} iv={r[1].hex()} q={r[2]} "
                        f"aad={h(r[3])} pt={h(r[4])} ct={h(a[:n])} tag={a[n:].hex()} source=both")
        opened = ok(cn("ungcm", block, [(k, i, q, a, c[:len(p)], c[len(p):])
                                        for (k, i, q, a, p), c in zip(reqs, x)]), "cryptonite")
        if opened != [r[4] for r in reqs]:
            sys.exit("cryptonite does not open its own GCM")
        short = [(rng.randbytes(klen), rng.randbytes(block), str(block), rng.randbytes(a),
                  rng.randbytes(m))
                 for a, m in ((0, 1), (0, block - 1), (block, block + 1), (block + 3, 2 * block + 5),
                              (1, 0), (block - 1, block), (2 * block + 7, 0))]
        # Bouncy Castle reads a short block's padding from past the end
        # of its buffer, so a length that fills the buffer exactly is an
        # ArrayIndexOutOfBoundsException there: no answer, and no row.
        # Short associated data is where that happens: at a 512-bit
        # block every length does. A short message always has room.
        answered = []
        for r, line in zip(short, bc("gcm", block, short)):
            if not line.startswith("error"):
                answered.append((r, line))
            elif len(r[3]) % block == 0:
                sys.exit(f"Bouncy Castle refused a GCM row with whole associated data: {line}")
        short = [r for r, _ in answered]
        y = [bytes.fromhex(line) for _, line in answered]
        # Bouncy Castle cannot open its own output when the message ends
        # short: decrypting, it pads from the tag that follows rather
        # than with zeros. Required here so the claim stays on record.
        back = bc("ungcm", block, [(k, i, q, a, c) for (k, i, q, a, _), c in zip(short, y)])
        for r, line in zip(short, back):
            if len(r[4]) % block and not line.startswith("error"):
                sys.exit("Bouncy Castle opened its own GCM with a short message block")
            if not len(r[4]) % block and line != r[4].hex():
                sys.exit("Bouncy Castle did not open its own GCM with whole message blocks")
        x = cn("gcm", block, short)
        for r, a, b in zip(short, x, y):
            if len(r[4]) % block and len(r[3]) % block == 0 and a == b.hex():
                sys.exit("cryptonite agrees with Bouncy Castle on a short message block; "
                         "the readings were expected to part")
            n = len(r[4])
            rows.append(f"gcm block={block} key={r[0].hex()} iv={r[1].hex()} q={r[2]} "
                        f"aad={h(r[3])} pt={h(r[4])} ct={h(b[:n])} tag={b[n:].hex()} "
                        f"source=bouncycastle")

        # GMAC.
        reqs = [(rng.randbytes(klen), str(q), rng.randbytes(m * block))
                for m in (0, 1, 2, 5) for q in sorted({block, 8})]
        x, y = ok(cn("gmac", block, reqs), "cryptonite"), ok(bc("gmac", block, reqs), "Bouncy Castle")
        for r, a, b in zip(reqs, x, y):
            if a != b:
                sys.exit(f"the witnesses disagree on GMAC under {r[0].hex()}")
            rows.append(f"gmac block={block} key={r[0].hex()} q={r[1]} msg={h(r[2])} tag={a.hex()} "
                        f"source=both")
        short = [(rng.randbytes(klen), str(block), rng.randbytes(m))
                 for m in (1, block - 1, block + 1, 3 * block + 2)]
        for r, line in zip(short, bc("gmac", block, short)):
            if line.startswith("error"):
                continue
            b = bytes.fromhex(line)
            rows.append(f"gmac block={block} key={r[0].hex()} q={r[1]} msg={h(r[2])} tag={b.hex()} "
                        f"source=bouncycastle")

        # CCM. Bouncy Castle's counter adds one to its first byte alone,
        # so a nonce is taken only when that byte has room for every
        # block the message and MAC need.
        def ccm_nonce(key, blocks):
            while True:
                nonce = rng.randbytes(block)
                first = ok(bc("", block, [(key, nonce)]), "Bouncy Castle")[0][0]
                if first + blocks + 1 < 256:
                    return nonce

        qs = [q for q in (8, 16, 32, 48, 64) if q <= block]
        reqs = []
        for nb in (4, 6, 8):
            if nb + 1 > block:
                continue
            for a in (1, 2):
                # Under 256 bytes: cryptonite writes the length in one.
                for m in (1, 2, 3):
                    for q in (qs[0], qs[-1]):
                        key = rng.randbytes(klen)
                        reqs.append((key, ccm_nonce(key, m + 4), str(q), str(nb),
                                     rng.randbytes(a * block), rng.randbytes(m * block)))
        x = ok(cn("ccm", block, [(k, i, q, str(8 * int(nb)), a, p) for k, i, q, nb, a, p in reqs]),
               "cryptonite")
        y = ok(bc("ccm", block, reqs), "Bouncy Castle")
        for r, a, b in zip(reqs, x, y):
            if a != b:
                sys.exit(f"the witnesses disagree on CCM: block {block}, q {r[2]}, nb {r[3]}, "
                         f"{len(r[4])} bytes of associated data, {len(r[5])} of message")
            rows.append(f"ccm block={block} key={r[0].hex()} iv={r[1].hex()} q={r[2]} nb={r[3]} "
                        f"aad={h(r[4])} pt={h(r[5])} sealed={a.hex()} source=both")
        opened = ok(bc("unccm", block, [(k, i, q, nb, a, s) for (k, i, q, nb, a, _), s
                                        in zip(reqs, y)]), "Bouncy Castle")
        if opened != [r[5] for r in reqs]:
            sys.exit("Bouncy Castle does not open its own CCM")
        alone = [(rng.randbytes(klen), rng.randbytes(block), str(qs[-1]), "32",
                  rng.randbytes(a), rng.randbytes(m))
                 for a, m in ((0, block), (block, 0), (0, 0), (3, 5), (block + 1, block - 1),
                              (2 * block - 1, 2 * block + 1), (block, 3), (5, 3 * block))]
        for r, c in zip(alone, ok(cn("ccm", block, alone), "cryptonite")):
            rows.append(f"ccm block={block} key={r[0].hex()} iv={r[1].hex()} q={r[2]} nb=4 "
                        f"aad={h(r[4])} pt={h(r[5])} sealed={c.hex()} source=cryptonite")
        long = []
        for m in (17 * 16 // block + 1, 300 // block + 1):
            key = rng.randbytes(klen)
            long.append((key, ccm_nonce(key, m + 4), str(block), "4", rng.randbytes(block),
                         rng.randbytes(m * block)))
        for r, c in zip(long, ok(bc("ccm", block, long), "Bouncy Castle")):
            if len(r[5]) < 256:
                sys.exit("a long CCM row is not past cryptonite's one-byte length")
            rows.append(f"ccm block={block} key={r[0].hex()} iv={r[1].hex()} q={r[2]} nb=4 "
                        f"aad={h(r[4])} pt={h(r[5])} sealed={c.hex()} source=bouncycastle")

        # XTS.
        reqs = [(rng.randbytes(klen), rng.randbytes(block), rng.randbytes(m * block))
                for m in (1, 2, 3, 7)]
        x, y = ok(cn("xts", block, reqs), "cryptonite"), ok(bc("xts", block, reqs), "Bouncy Castle")
        for r, a, b in zip(reqs, x, y):
            if a != b:
                sys.exit(f"the witnesses disagree on XTS under {r[0].hex()}")
            rows.append(f"xts block={block} key={r[0].hex()} iv={r[1].hex()} pt={r[2].hex()} "
                        f"ct={a.hex()} source=both")
        back = ok(bc("unxts", block, [(k, i, c) for (k, i, _), c in zip(reqs, y)]), "Bouncy Castle")
        if back != [r[2] for r in reqs]:
            sys.exit("Bouncy Castle does not undo its own XTS")
        short = [(rng.randbytes(klen), rng.randbytes(block), rng.randbytes(n))
                 for n in (block + 1, 2 * block - 1, 3 * block + 5)]
        x = ok(cn("xts", block, short), "cryptonite")
        if ok(cn("unxts", block, [(k, i, c) for (k, i, _), c in zip(short, x)]),
              "cryptonite") != [r[2] for r in short]:
            sys.exit("cryptonite does not undo its own XTS stealing")
        for r, a in zip(short, x):
            rows.append(f"xts block={block} key={r[0].hex()} iv={r[1].hex()} pt={r[2].hex()} "
                        f"ct={a.hex()} source=cryptonite")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# DSTU 7624:2014's GCM, GMAC, CCM and XTS over Kalyna. Written by\n"
                "# scripts/make_kalyna_aead_vectors.py; do not edit. source=standard: an\n"
                "# example both cryptonite's acceptance tests and Bouncy Castle's test file\n"
                "# carry, both witnesses reproducing it; source=cryptonite-tests: one only\n"
                "# cryptonite's tests carry; source=both: Bouncy Castle 1.77 and cryptonite\n"
                "# in agreement; source=cryptonite or bouncycastle: that one alone.\n"
                f"# rows: {len(rows)}, examples: {examples}\n")
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows, {examples} examples", file=sys.stderr)


if __name__ == "__main__":
    main()
