#!/usr/bin/env python3
"""Write vectors/blake3.vec: BLAKE3 in its three modes, at several output
lengths and offsets, from three implementations.

    scripts/witness/blake3/build.sh /opt/blake3witness
    python3 scripts/make_blake3_vectors.py

**A development tool, not a test.** `tests/test_blake3.rs` and
`pytests/test_blake3.py` read the file offline. The team's own test
vectors are `rfcs/blake3-test-vectors.json`, which the same tests read.

The witnesses (`scripts/witness/blake3`) are the BLAKE3 team's C
implementation without SIMD, their reference implementation in Rust, and
Bouncy Castle's Blake3Digest, each fed its message in pieces of 1, 2,
3 ... bytes; all three must agree on every `out` row, or the script
stops. The messages sit around the chunk and tree boundaries - a chunk
is 1024 bytes, and the tree's shape changes at every power of two
chunks - up to 129 KB, and are described rather than stored: message
`n` of `len` bytes is SHA-256 of the ASCII text "SEED:j" for j = 0, 1,
2 ... concatenated and cut, which the readers recompute.

    msg n= len= seed=
    out mode= msg= length= seek= digest=

`mode` is `hash`, `keyed` with KEY below, or `derive` with CONTEXT. The
output offsets in `out` rows are small, because Bouncy Castle has no
seek and the reference computes from the start; `seek` rows are the C
implementation's alone, from offsets past 2^32 output blocks, where the
output counter's high word is set:

    seek mode= msg= length= seek= digest=
"""

import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "blake3.vec")
WITNESS = os.environ.get("BLAKE3_WITNESS", "/opt/blake3witness")

KEY = hashlib.sha256(b"allcrypt BLAKE3 key").digest()
CONTEXT = b"allcrypt 2026-10-13 BLAKE3 witness rows"
MODES = {"hash": "hash", "keyed": f"keyed={KEY.hex()}", "derive": f"derive={CONTEXT.hex()}"}
LENGTHS = [0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 3071, 3072, 3073,
           4095, 4096, 4097, 5121, 8191, 8192, 8193, 16385, 31744, 32768, 33793,
           65536, 65537, 132097]
OUTPUTS = [(32, 0), (131, 0), (64, 1), (200, 63), (100, 1000), (1, 4095)]
SEEKS = [(65, 2**32 * 64 - 10), (64, 2**40 + 64), (7, 2**64 - 7)]


def message(seed, length):
    out = b""
    j = 0
    while len(out) < length:
        out += hashlib.sha256(f"{seed}:{j}".encode()).digest()
        j += 1
    return out[:length]


def ask(witness, requests):
    lines = "".join(f"{name} {path}\n" for name, path in requests)
    out = subprocess.run([os.path.join(WITNESS, f"{witness}-witness")], input=lines,
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != len(requests) or "error" in out:
        sys.exit(f"{witness} refused: {out[:5]}")
    return out


def main():
    messages = [(f"m{n}", length) for n, length in enumerate(LENGTHS)]
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for seed, length in messages:
            paths.append(os.path.join(tmp, seed))
            with open(paths[-1], "wb") as f:
                f.write(message(seed, length))
        cases = [(mode, n, length, seek) for mode in MODES for n in range(len(messages))
                 for length, seek in OUTPUTS]
        requests = [(f"{MODES[mode]}/{length}/{seek}", paths[n]) for mode, n, length, seek in cases]
        answers = [ask(w, requests) for w in ("c", "ref", "bc")]
        rows = []
        for case, *given in zip(cases, *answers):
            if len(set(given)) != 1:
                sys.exit(f"the witnesses disagree on {case}")
            mode, n, length, seek = case
            rows.append(f"out mode={mode} msg={n} length={length} seek={seek} digest={given[0]}")
        seek_cases = [(mode, n, length, seek) for mode in MODES for n in (0, 7, 27)
                      for length, seek in SEEKS]
        requests = [(f"{MODES[mode]}/{length}/{seek}", paths[n])
                    for mode, n, length, seek in seek_cases]
        for (mode, n, length, seek), digest in zip(seek_cases, ask("c", requests)):
            rows.append(f"seek mode={mode} msg={n} length={length} seek={seek} digest={digest}")
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("# BLAKE3. Written by scripts/make_blake3_vectors.py; do not edit. The\n"
                  "# BLAKE3 team's C and reference implementations and Bouncy Castle 1.77\n"
                  "# agree on every out row; seek rows are the C implementation's alone.\n"
                  f"# KEY={KEY.hex()}\n"
                  f"# CONTEXT={CONTEXT.decode()}\n")
        for n, (seed, length) in enumerate(messages):
            out.write(f"msg n={n} len={length} seed={seed}\n")
        for row in rows:
            out.write(row + "\n")
    print(f"{len(messages)} messages, {len(rows)} rows")


if __name__ == "__main__":
    main()
