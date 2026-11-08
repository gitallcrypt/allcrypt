#!/usr/bin/env python3
"""Write examples/products/fixtures/age/tag/: age files to the tagged
recipient types, `p256tag` (`age1tag1...`) and `mlkem768p256tag`
(`age1tagpq1...`), both ways between the age example and age 1.3.2.

    sh scripts/witness/agetag/build.sh /opt/age132
    cargo build --release --example age
    python3 scripts/make_age_tag_fixtures.py

The tagged types are the public side of keys held in hardware; age 1.3
encrypts to them natively and leaves decryption to plugins. The keys
here are age's own test identities (`tag/internal/tagtest`): HPKE's
`DeriveKeyPair` of a seed, over P-256 or MLKEM768-P256.
`age-tag-witness`, built inside age's tree, gives their recipients and
decrypts with them. Then:

  * **theirs**: age encrypts to one or two recipients of a type (age
    refuses to mix the hybrid type with any other), plaintexts either
    side of the 64 KiB chunk (past it once per type), binary and
    armored. The tests open each with the identity made from the same
    seed.
  * **ours**: the example encrypts with a seeded generator (`--seed`), so
    the test makes each file again byte for byte; age-tag-witness must
    decrypt it to the plaintext with each identity. Past a chunk only
    for the hybrid type.

`tag.vec` lists every file. **A development tool, not a test.**
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "examples", "products", "fixtures", "age", "tag")
OURS = os.path.join(ROOT, "target", "release", "examples", "age")
AGE = "/opt/age132/bin/age"
WITNESS = "/opt/age132/bin/age-tag-witness"
SIZES = [0, 1000, 70000]
SEEDS = {"classic": ["allcrypt tag one", "allcrypt tag two"],
         "pq": ["allcrypt tagpq one", "allcrypt tagpq two"]}


def run(*args):
    result = subprocess.run(list(args), capture_output=True, timeout=600)
    if result.returncode != 0:
        sys.exit(f"{os.path.basename(args[0])} {' '.join(args[1:3])}: "
                 f"{result.stderr.decode()[-300:]}")
    return result.stdout


def plaintext(size):
    return bytes((i * 41 + i // 251) & 0xFF for i in range(size))


def main():
    version = run(AGE, "--version").decode().strip()
    if version != "v1.3.2":
        sys.exit(f"{AGE} is {version}, not v1.3.2")
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    recipients = {(kind, seed): run(WITNESS, "recipient", kind, seed).decode().strip()
                  for kind, seeds in SEEDS.items() for seed in seeds}
    for size in SIZES:
        with open(os.path.join(OUT, f"plain-{size}"), "wb") as handle:
            handle.write(plaintext(size))
    records = []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, seeds in SEEDS.items():
            for size in SIZES:
                # Past a chunk only once per type: the stanzas are what this
                # tests, and the payload is every recipient's.
                for targets in [seeds] if size > 65536 else ([seeds[0]], seeds):
                    armored = size == 1000
                    name = (f"age-{kind}-{len(targets)}-{size}"
                            f"{'.armored' if armored else ''}.age")
                    args = []
                    for seed in targets:
                        args += ["-r", recipients[(kind, seed)]]
                    run(AGE, *args, *(["-a"] if armored else []), "-o",
                        os.path.join(OUT, name), os.path.join(OUT, f"plain-{size}"))
                    for seed in targets:
                        records.append(("theirs", name, version, kind, seed, size))

            for i, size in enumerate(SIZES):
                if size > 65536 and kind == "classic":
                    continue
                name = f"ours-{kind}-{size}.age"
                seed_number = str(300 + 10 * i + (5 if kind == "pq" else 0))
                args = []
                for seed in seeds:
                    args += ["-r", recipients[(kind, seed)]]
                run(OURS, "encrypt", os.path.join(OUT, f"plain-{size}"), os.path.join(OUT, name),
                    *args, "--seed", seed_number)
                for seed in seeds:
                    out = os.path.join(tmp, "out")
                    run(WITNESS, "decrypt", kind, seed, os.path.join(OUT, name), out)
                    if open(out, "rb").read() != plaintext(size):
                        sys.exit(f"age-tag-witness decrypts {name} with {seed!r} wrongly")
                records.append(("ours", name, seed_number, kind, " + ".join(seeds), size))

    with open(os.path.join(OUT, "tag.vec"), "w") as handle:
        handle.write("# age files to the tagged recipients, written by\n"
                     "# scripts/make_age_tag_fixtures.py; do not edit. theirs: made by age\n"
                     f"# {version}, opened here with the identity from `seed`; ours: made here\n"
                     "# with `seed_number` to every seed's recipient, opened by age's test\n"
                     "# identities (age-tag-witness) with each. A seed's identity is HPKE's\n"
                     "# DeriveKeyPair of its bytes, over P-256 (classic) or MLKEM768-P256 (pq).\n")
        for kind in ("theirs", "ours"):
            handle.write(f"\n[{kind}]\n")
            for record in records:
                if record[0] != kind:
                    continue
                _, name, by, tag_type, seed, size = record
                field = "made_by" if kind == "theirs" else "seed_number"
                handle.write(f"name = {name}\n{field} = {by}\ntype = {tag_type}\n"
                             f"seed = {seed}\nplain = plain-{size}\n")
        handle.write("\n[recipients]\n")
        for (kind, seed), recipient in recipients.items():
            handle.write(f"name = {seed}\ntype = {kind}\nrecipient = {recipient}\n")
    print(f"wrote {OUT}: {len(records)} records")


if __name__ == "__main__":
    main()
