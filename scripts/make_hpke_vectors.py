#!/usr/bin/env python3
"""Write vectors/hpke.vec: HPKE vectors from the two drafts' own test
vector files, one line per vector.

    python3 scripts/make_hpke_vectors.py --cfrg CFRG_JSON --pq PQ_JSON

  * CFRG_JSON is `test-vectors.json` from github.com/cfrg/draft-irtf-cfrg-hpke
    (commit b1f7cb0c), the file RFC 9180's appendix A was printed from:
    128 vectors, all four modes, DHKEM over P-256, P-521, X25519 and X448
    (the RFC prints 28 of them; `rfcs/rfc9180.txt` is read for those as
    well).
  * PQ_JSON is `test-vectors.json` from github.com/hpkewg/hpke-pq (commit
    6433c8fc), draft-ietf-hpke-pq-05's vectors: ML-KEM, the hybrid KEMs
    and the one-stage SHAKE and TurboSHAKE KDFs, made by the draft's
    reference implementation; Cloudflare's CIRCL checks the HKDF ones
    there, and nothing outside the draft checks the TurboSHAKE ones.

Both files are checked against their SHA-256 before anything is read.
Of the CFRG file's 257 encryptions per vector, those at sequence numbers
0, 1, 2, 255 and 256 are kept - the last two straddle the byte where
the nonce's counter carries; the PQ file's are kept whole.

Fields are `name=hex`, `-` for empty. `encryptions` is
`seq:aad:pt:ct` joined by `,`; `exports` is `context:L:value` the same
way.
"""

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "vectors", "hpke.vec")
SOURCES = {
    "cfrg": "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6",
    "pq": "35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c",
}
KEEP = {0, 1, 2, 255, 256}
FIELDS = ["mode", "kem_id", "kdf_id", "aead_id", "info", "ikmR", "ikmE", "ikmS", "skRm",
          "pkRm", "skSm", "pkSm", "psk", "psk_id", "enc", "shared_secret", "key",
          "base_nonce", "exporter_secret"]


def h(value):
    return value if value else "-"


def line(source, vector):
    parts = [f"source={source}"]
    for field in FIELDS:
        if field not in vector:
            continue
        value = vector[field]
        parts.append(f"{field}={value if isinstance(value, int) else h(value)}")
    encryptions = []
    for seq, item in enumerate(vector["encryptions"]):
        if source == "cfrg" and seq not in KEEP:
            continue
        encryptions.append(f"{seq}:{h(item['aad'])}:{h(item['pt'])}:{h(item['ct'])}")
    parts.append(f"encryptions={','.join(encryptions) or '-'}")
    exports = [f"{h(e['exporter_context'])}:{e['L']}:{e['exported_value']}"
               for e in vector["exports"]]
    parts.append(f"exports={','.join(exports)}")
    return " ".join(parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cfrg", required=True)
    parser.add_argument("--pq", required=True)
    args = parser.parse_args()
    lines = []
    for source, path in (("cfrg", args.cfrg), ("pq", args.pq)):
        data = open(path, "rb").read()
        digest = hashlib.sha256(data).hexdigest()
        if digest != SOURCES[source]:
            sys.exit(f"{path}: SHA-256 {digest}, not the {source} file's {SOURCES[source]}")
        vectors = json.loads(data)
        for vector in vectors:
            lines.append(line(source, vector))
    with open(OUT, "w") as handle:
        handle.write("# HPKE vectors from the CFRG's RFC 9180 test vector file (commit\n"
                     "# b1f7cb0c) and draft-ietf-hpke-pq-05's (hpkewg/hpke-pq, commit\n"
                     "# 6433c8fc). Written by\n"
                     "# scripts/make_hpke_vectors.py; do not edit.\n")
        handle.write(f"# vectors: {len(lines)}\n")
        handle.write("\n".join(lines) + "\n")
    print(f"wrote {OUT}: {len(lines)} vectors")


if __name__ == "__main__":
    main()
