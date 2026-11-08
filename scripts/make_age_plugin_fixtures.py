#!/usr/bin/env python3
"""Write examples/products/fixtures/age/plugin/: the age example talking
to age 1.3.2's own plugins over age's plugin protocol, every
conversation recorded so the tests can play the plugin's side back.

    sh scripts/witness/agetag/build.sh /opt/age132
    cargo build --release --example age
    python3 scripts/make_age_plugin_fixtures.py

Each plugin is run through a wrapper on the `PATH` that copies what the
example writes to it (`.to`) and what it answers (`.from`). The
conversations:

  * **recipient-v1**, the example encrypting through a plugin:
    `age-plugin-tag` and `age-plugin-tagpq` (the tagged types, opened
    afterwards by age's test identities in `age-tag-witness`),
    `age-plugin-pq` (an `age1pq` recipient, opened by age 1.3.2 with the
    native identity) and `age-plugin-batchpass` (`-j batchpass`, a
    passphrase from the environment, opened by age 1.3.2 through the same
    plugin). `--plugin-recipients` sends the types the example knows to
    their plugins.
  * **identity-v1**, the example decrypting through a plugin: files age
    1.3.2 encrypted natively to an `age1pq` recipient, opened with the
    plugin identity `age-plugin-pq -identity` makes of the native one;
    and a file age encrypted with `-j batchpass`, opened with `-j
    batchpass`.

The example encrypts with a seeded generator, so the file key it sends
and every byte it writes come out the same each time; the tests check
that they do, against the plugin's recorded answers.

`plugin.vec` lists every conversation. **A development tool, not a
test.**
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "examples", "products", "fixtures", "age", "plugin")
OURS = os.path.join(ROOT, "target", "release", "examples", "age")
BIN = "/opt/age132/bin"
AGE = os.path.join(BIN, "age")
WITNESS = os.path.join(BIN, "age-tag-witness")
PASSPHRASE = "plugin passphrase"
PLUGINS = ["tag", "tagpq", "pq", "batchpass"]


def plaintext(size):
    return bytes((i * 43 + i // 241) & 0xFF for i in range(size))


class Rig:
    def __init__(self, tmp):
        self.tmp = tmp
        self.bin = os.path.join(tmp, "bin")
        self.capture = os.path.join(tmp, "capture")
        os.makedirs(self.bin)
        os.makedirs(self.capture)
        for name in PLUGINS:
            path = os.path.join(self.bin, f"age-plugin-{name}")
            with open(path, "w") as handle:
                handle.write("#!/bin/sh\n"
                             'n=$(ls "$CAPTURE" | wc -l)\n'
                             f'echo "{name} $*" > "$CAPTURE/$n.args"\n'
                             f'tee "$CAPTURE/$n.to" | {BIN}/age-plugin-{name} "$@" '
                             '| tee "$CAPTURE/$n.from"\n')
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        self.env = {**os.environ, "PATH": f"{self.bin}:{BIN}:{os.environ['PATH']}",
                    "CAPTURE": self.capture, "AGE_PASSPHRASE": PASSPHRASE,
                    "AGE_PASSPHRASE_WORK_FACTOR": "10"}

    def run(self, *args, capture=True):
        for name in os.listdir(self.capture):
            os.remove(os.path.join(self.capture, name))
        result = subprocess.run(list(args), capture_output=True, env=self.env, timeout=600)
        if result.returncode != 0:
            sys.exit(f"{os.path.basename(args[0])} {' '.join(args[1:3])}: "
                     f"{result.stderr.decode()[-300:]}")
        sessions = []
        if capture:
            for index in range(len(os.listdir(self.capture)) // 3):
                read = lambda ext: open(os.path.join(self.capture, f"{index}.{ext}"), "rb").read()
                name, protocol = read("args").decode().split()
                sessions.append((name, protocol.removeprefix("--age-plugin="), read("to"),
                                 read("from")))
        return result.stdout, sessions


def main():
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    records = []
    with tempfile.TemporaryDirectory() as tmp:
        rig = Rig(tmp)
        plain = os.path.join(OUT, "plain")
        with open(plain, "wb") as handle:
            handle.write(plaintext(1000))

        def keep(name, sessions, extra):
            for i, (plugin, protocol, to, frm) in enumerate(sessions):
                stem = f"{name}.{i}"
                open(os.path.join(OUT, f"{stem}.to"), "wb").write(to)
                open(os.path.join(OUT, f"{stem}.from"), "wb").write(frm)
                records.append(dict(name=name, session=stem, plugin=plugin, protocol=protocol,
                                    **extra))

        def check(path, *identity_args, env_plugin=False):
            out = os.path.join(tmp, "out")
            if os.path.exists(out):
                os.remove(out)
            rig.run(AGE, "-d", *identity_args, "-o", out, path, capture=False)
            if open(out, "rb").read() != plaintext(1000):
                sys.exit(f"{path} does not decrypt to the plaintext")

        # recipient-v1: the tagged types, through their plugins.
        for i, (kind, plugin) in enumerate([("classic", "tag"), ("pq", "tagpq")]):
            seed = f"allcrypt plugin {plugin}"
            recipient = rig.run(WITNESS, "recipient", kind, seed, capture=False)[0].decode().strip()
            name = f"ours-{plugin}.age"
            seed_number = str(400 + i)
            _, sessions = rig.run(OURS, "encrypt", plain, os.path.join(OUT, name), "-r", recipient,
                                  "--plugin-recipients", "--seed", seed_number)
            out = os.path.join(tmp, "out")
            rig.run(WITNESS, "decrypt", kind, seed, os.path.join(OUT, name), out, capture=False)
            if open(out, "rb").read() != plaintext(1000):
                sys.exit(f"{name} does not decrypt to the plaintext")
            keep(name, sessions, {"args": f"-r {recipient} --plugin-recipients",
                                  "seed_number": seed_number, "opened_by": "age-tag-witness"})

        # recipient-v1: age1pq through age-plugin-pq; age opens it natively.
        keygen, _ = rig.run(OURS, "keygen", "--pq", "--seed", "402", capture=False)
        pq_recipient = keygen.decode().split("# public key: ")[1].split()[0]
        pq_identity = keygen.decode().strip().splitlines()[-1]
        identity_file = os.path.join(tmp, "pq.key")
        open(identity_file, "w").write(pq_identity + "\n")
        name = "ours-pq.age"
        _, sessions = rig.run(OURS, "encrypt", plain, os.path.join(OUT, name), "-r", pq_recipient,
                              "--plugin-recipients", "--seed", "403")
        check(os.path.join(OUT, name), "-i", identity_file)
        keep(name, sessions, {"args": "-r PQ_RECIPIENT --plugin-recipients", "seed_number": "403",
                              "opened_by": "age 1.3.2, the native identity"})

        # recipient-v1: -j batchpass, a passphrase from the environment.
        name = "ours-batchpass.age"
        _, sessions = rig.run(OURS, "encrypt", plain, os.path.join(OUT, name), "-j", "batchpass",
                              "--seed", "404")
        check(os.path.join(OUT, name), "-j", "batchpass")
        keep(name, sessions, {"args": "-j batchpass", "seed_number": "404",
                              "opened_by": "age 1.3.2 -j batchpass"})

        # identity-v1: age's files opened through age-plugin-pq and batchpass.
        converted = subprocess.run([os.path.join(BIN, "age-plugin-pq"), "-identity"],
                                   input=(pq_identity + "\n").encode(), capture_output=True,
                                   check=True).stdout.decode()
        plugin_identity = [l for l in converted.splitlines() if l.startswith("AGE-PLUGIN-PQ-")][0]
        name = "age-pq.age"
        rig.run(AGE, "-r", pq_recipient, "-o", os.path.join(OUT, name), plain, capture=False)
        out = os.path.join(tmp, "ours-out")
        _, sessions = rig.run(OURS, "decrypt", os.path.join(OUT, name), out, "-i", plugin_identity)
        if open(out, "rb").read() != plaintext(1000):
            sys.exit(f"{name}: the plugin identity does not open it")
        keep(name, sessions, {"args": "-i PQ_PLUGIN_IDENTITY", "made_by": "age 1.3.2"})

        name = "age-batchpass.age"
        rig.run(AGE, "-e", "-j", "batchpass", "-o", os.path.join(OUT, name), plain, capture=False)
        _, sessions = rig.run(OURS, "decrypt", os.path.join(OUT, name), out, "-j", "batchpass")
        if open(out, "rb").read() != plaintext(1000):
            sys.exit(f"{name}: -j batchpass does not open it")
        keep(name, sessions, {"args": "-j batchpass", "made_by": "age 1.3.2 -j batchpass"})

        with open(os.path.join(OUT, "plugin.vec"), "w") as handle:
            handle.write(
                "# The age example and age 1.3.2's plugins, written by\n"
                "# scripts/make_age_plugin_fixtures.py; do not edit. Each record is one\n"
                "# conversation: SESSION.to is what the example wrote to the plugin,\n"
                "# SESSION.from what the plugin answered. ours-*: the example encrypting\n"
                "# plain with seed_number, the file opened as opened_by says; age-*: age's\n"
                "# file, the example decrypting through the plugin.\n"
                f"# passphrase (batchpass): {PASSPHRASE}\n\n[keys]\n"
                f"name = pq\nrecipient = {pq_recipient}\nidentity = {pq_identity}\n"
                f"plugin_identity = {plugin_identity}\n\n[sessions]\n")
            handle.write("\n".join("".join(f"{key} = {value}\n" for key, value in record.items())
                                   for record in records))
    print(f"wrote {OUT}: {len(records)} conversations")


if __name__ == "__main__":
    main()
