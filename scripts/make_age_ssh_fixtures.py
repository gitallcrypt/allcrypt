#!/usr/bin/env python3
"""Write examples/products/fixtures/age/ssh/: age files to SSH keys, both
ways between the age example and two implementations of age's `agessh`
recipients - age 1.1.1 (Go, `/usr/bin/age`) and rage 0.11.1 (Rust,
`/opt/rage`, `cargo install --locked --root /opt/rage --version 0.11.1 rage`).

    cargo build --release --example age
    python3 scripts/make_age_ssh_fixtures.py

The keys are made by `ssh-keygen` (the system's OpenSSH): Ed25519 and
RSA, and an Ed25519 key encrypted under a passphrase. Then:

  * **theirs**: age and rage each encrypt, to one key and to all three
    at once, plaintexts either side of the 64 KiB chunk, binary and
    armored. Each file is kept with the identity that must open it.
  * **ours**: the example encrypts with a seeded generator (`--seed`), so
    the test makes each file again byte for byte; age and rage must both
    decrypt it to the plaintext.

`ssh.vec` lists every file. **A development tool, not a test**; the age
example's tests read the directory offline.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "examples", "products", "fixtures", "age", "ssh")
OURS = os.path.join(ROOT, "target", "release", "examples", "age")
AGE = "/usr/bin/age"
RAGE = "/opt/rage/bin/rage"
KEY_PASSPHRASE = "key passphrase"
SIZES = [0, 1000, 70000]


def run(*args, stdin=None):
    result = subprocess.run(list(args), capture_output=True, input=stdin, timeout=600)
    if result.returncode != 0:
        sys.exit(f"{os.path.basename(args[0])} {' '.join(args[1:3])}: "
                 f"{result.stderr.decode()[-300:]}")
    return result.stdout


def plaintext(size):
    return bytes((i * 37 + i // 253) & 0xFF for i in range(size))


def version(tool):
    return run(tool, "--version").decode().strip()


def main():
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    records = []
    keys = {"ed25519": ("ed25519", None), "rsa": ("rsa", None),
            "ed25519-encrypted": ("ed25519", KEY_PASSPHRASE)}
    for name, (kind, passphrase) in keys.items():
        args = ["ssh-keygen", "-q", "-t", kind, "-N", passphrase or "", "-C", f"age {name}",
                "-f", os.path.join(OUT, name)]
        if kind == "rsa":
            args[4:4] = ["-b", "2048"]
        run(*args)
    for size in SIZES:
        with open(os.path.join(OUT, f"plain-{size}"), "wb") as handle:
            handle.write(plaintext(size))

    with tempfile.TemporaryDirectory() as tmp:
        # The encrypted key is used through its public half by age and
        # rage (they encrypt to the .pub); decrypting with it needs a
        # passphrase at a terminal, so theirs decrypt with the plain keys.
        plain_keys = ["ed25519", "rsa"]
        for tool, label in ((AGE, f"age {version(AGE)}"), (RAGE, version(RAGE))):
            short = "age" if tool == AGE else "rage"
            for size in SIZES:
                # The one size past a chunk only once per tool: the
                # stanzas are what this tests, and the payload is the same
                # code as every other recipient's.
                for target in (["all"] if size > 65536 else
                               ["ed25519", "rsa", "ed25519-encrypted", "all"]):
                    armored = size == 1000
                    name = f"{short}-{target}-{size}{'.armored' if armored else ''}.age"
                    recipients = []
                    for key in (keys if target == "all" else [target]):
                        recipients += ["-R", os.path.join(OUT, f"{key}.pub")]
                    run(tool, *recipients, *(["-a"] if armored else []),
                        "-o", os.path.join(OUT, name), os.path.join(OUT, f"plain-{size}"))
                    for identity in (plain_keys if target == "all" else [target]):
                        records.append(("theirs", name, label, identity, size))

        for i, size in enumerate(SIZES):
            for target in ["all"] if size > 65536 else ["ed25519", "rsa", "all"]:
                name = f"ours-{target}-{size}.age"
                seed = str(100 + i * 10 + len(target))
                recipients = []
                for key in (keys if target == "all" else [target]):
                    recipients += ["-R", os.path.join(OUT, f"{key}.pub")]
                run(OURS, "encrypt", os.path.join(OUT, f"plain-{size}"),
                    os.path.join(OUT, name), *recipients, "--seed", seed)
                for tool in (AGE, RAGE):
                    for identity in (plain_keys if target == "all" else [target]):
                        out = os.path.join(tmp, "out")
                        if os.path.exists(out):
                            os.remove(out)
                        run(tool, "-d", "-i", os.path.join(OUT, identity), "-o", out,
                            os.path.join(OUT, name))
                        got = open(out, "rb").read() if os.path.exists(out) else b""
                        if got != plaintext(size):
                            sys.exit(f"{tool} decrypts {name} with {identity} wrongly")
                records.append(("ours", name, f"seed {seed}", target, size))

    with open(os.path.join(OUT, "ssh.vec"), "w") as handle:
        handle.write("# age files to SSH keys, written by scripts/make_age_ssh_fixtures.py; do\n"
                     "# not edit. theirs: made by age or rage, opened here with `identity`;\n"
                     "# ours: made here with `seed`, opened by age 1.1.1 and rage 0.11.1 with\n"
                     f"# every key it names. The encrypted key's passphrase is {KEY_PASSPHRASE!r}.\n")
        for kind in ("theirs", "ours"):
            handle.write(f"\n[{kind}]\n")
            for record in records:
                if record[0] != kind:
                    continue
                _, name, by, key, size = record
                field = "made_by" if kind == "theirs" else "seed"
                value = by if kind == "theirs" else by.split()[1]
                handle.write(f"name = {name}\n{field} = {value}\n"
                             f"{'identity' if kind == 'theirs' else 'to'} = {key}\n"
                             f"plain = plain-{size}\n")
    print(f"wrote {OUT}: {len(records)} records")


if __name__ == "__main__":
    main()
