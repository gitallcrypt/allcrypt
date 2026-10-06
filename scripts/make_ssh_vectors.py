#!/usr/bin/env python3
"""Write vectors/ssh_keys.vec: OpenSSH's own answers about SSH keys.

`ssh-keygen` from OpenSSH is the witness for everything in `src/ssh/`
that is a file format rather than a protocol: public key lines and
blobs, fingerprints, `openssh-key-v1` private keys (plain and encrypted
under bcrypt_pbkdf with each cipher OpenSSH will write one with), and
SSHSIG signatures. The tests read this file and need no OpenSSH.

    python3 scripts/make_ssh_vectors.py --openssh /opt/openssh/bin \
        --legacy-openssh /opt/openssh74/bin

`--legacy-openssh` is an OpenSSH 7.x, for what 10.0 no longer makes: a
DSA (`ssh-dss`) key, and private key files encrypted with the ciphers
7.6 removed - `blowfish-cbc`, `cast128-cbc`, `arcfour*` and
`rijndael-cbc@lysator.liu.se`.

**A development tool, not a test**, in the same arrangement as
`make_gost_vectors.py`: nothing in the build or the gate runs it, and
re-running it rewrites every row, because keys are generated fresh and
encrypted files carry fresh salts. Diff the counts, not the bytes.

What each section holds:

  * `[key]` - one key per type and size: the `.pub` line, `bits`, the
    SHA-256 and MD5 fingerprints as `ssh-keygen -l` prints them, and the
    unencrypted private key file (base64 of the whole file, armour and
    all).
  * `[encrypted]` - the same keys re-encrypted with `ssh-keygen -p`
    under a passphrase, one row per cipher, with the round count.
  * `[sshsig]` - `ssh-keygen -Y sign` over a fixed message, for each key
    and both hashes SSHSIG allows, with `-Y verify` having accepted it.
"""

import argparse
import base64
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(os.path.dirname(HERE), "vectors", "ssh_keys.vec")

KEYS = [("ed25519", None), ("ecdsa", 256), ("ecdsa", 384), ("ecdsa", 521),
        ("rsa", 1024), ("rsa", 2048), ("rsa", 3072)]

# Every cipher `ssh-keygen -Z` will encrypt a private key with. The
# default is aes256-ctr; the rest are what an older or differently
# configured OpenSSH may have written.
LEGACY_CIPHERS = ["blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
                  "arcfour256", "rijndael-cbc@lysator.liu.se"]

CIPHERS = ["aes256-ctr", "aes128-ctr", "aes192-ctr", "aes128-cbc",
           "aes192-cbc", "aes256-cbc", "3des-cbc", "aes128-gcm@openssh.com",
           "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]

PASSPHRASE = "correct horse battery staple"
ROUNDS = 4          # bcrypt_pbkdf rounds: low, so the tests stay quick.
MESSAGE = b"allcrypt ssh vectors\n"
NAMESPACE = "file"


def run(*command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True,
                          **kwargs)


def b64(data):
    return base64.b64encode(data).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssh", default="/opt/openssh/bin",
                        help="directory holding ssh-keygen and ssh")
    parser.add_argument("--legacy-openssh", metavar="DIR",
                        help="an OpenSSH 7.x bin directory, for DSA and the old ciphers")
    args = parser.parse_args()
    keygen = os.path.join(args.openssh, "ssh-keygen")
    version = run(os.path.join(args.openssh, "ssh"), "-V").stderr.decode().strip()
    if args.legacy_openssh:
        version += "\n# " + run(os.path.join(args.legacy_openssh, "ssh"),
                                "-V").stderr.decode().strip() + " (dsa1024, ed25519-legacy)"

    keys, encrypted, signatures = [], [], []
    with tempfile.TemporaryDirectory() as directory:
        message_path = os.path.join(directory, "message")
        with open(message_path, "wb") as out:
            out.write(MESSAGE)
        plan = [(keygen, kind, bits, kind if bits is None else f"{kind}{bits}",
                 CIPHERS, True) for kind, bits in KEYS]
        if args.legacy_openssh:
            old_keygen = os.path.join(args.legacy_openssh, "ssh-keygen")
            plan += [(old_keygen, "dsa", 1024, "dsa1024", ["aes256-ctr"] + LEGACY_CIPHERS,
                      False),
                     (old_keygen, "ed25519", None, "ed25519-legacy", LEGACY_CIPHERS, False)]
        for tool, kind, bits, label, ciphers, with_sshsig in plan:
            path = os.path.join(directory, label)
            # -o: openssh-key-v1, which 7.x writes for these types only
            # when asked; 10.0 ignores it.
            command = [tool, "-q", "-o", "-t", kind, "-N", "", "-C",
                       f"{label}@allcrypt", "-f", path]
            if bits is not None:
                command[5:5] = ["-b", str(bits)]
            run(*command)
            line = open(path + ".pub").read().strip()
            fingerprints = {}
            for hash_name in ("sha256", "md5"):
                printed = run(tool, "-l", "-E", hash_name, "-f",
                              path + ".pub").stdout.decode().split()
                # "256 SHA256:... comment (ED25519)"
                fingerprints[hash_name] = printed[1]
                fingerprints["bits"] = printed[0]
            private = open(path, "rb").read()
            keys.append([("name", label), ("bits", fingerprints["bits"]),
                         ("line", line),
                         ("sha256", fingerprints["sha256"]),
                         ("md5", fingerprints["md5"]),
                         ("private", b64(private))])

            for cipher in ciphers:
                copy = os.path.join(directory, f"{label}-{cipher}")
                with open(copy, "wb") as out:
                    out.write(private)
                os.chmod(copy, 0o600)
                run(tool, "-q", "-o", "-p", "-f", copy, "-P", "", "-N",
                    PASSPHRASE, "-Z", cipher, "-a", str(ROUNDS))
                # And OpenSSH can read back what it wrote.
                again = run(tool, "-y", "-P", PASSPHRASE, "-f",
                            copy).stdout.decode().split()[:2]
                assert again == line.split()[:2], (label, cipher)
                encrypted.append([("name", label), ("cipher", cipher),
                                  ("rounds", str(ROUNDS)),
                                  ("passphrase", PASSPHRASE),
                                  ("private", b64(open(copy, "rb").read()))])

            for hash_name in ("sha512", "sha256") if with_sshsig else ():
                run(tool, "-Y", "sign", "-f", path, "-n", NAMESPACE,
                    "-O", f"hashalg={hash_name}", message_path)
                signature_path = message_path + ".sig"
                signature = open(signature_path, "rb").read()
                os.unlink(signature_path)
                signers = os.path.join(directory, "allowed_signers")
                with open(signers, "w") as out:
                    out.write(f"signer {line}\n")
                saved = os.path.join(directory, "signature")
                with open(saved, "wb") as out:
                    out.write(signature)
                verify = subprocess.run(
                    [tool, "-Y", "verify", "-f", signers, "-I", "signer",
                     "-n", NAMESPACE, "-s", saved],
                    input=MESSAGE, capture_output=True)
                assert verify.returncode == 0, verify.stderr
                signatures.append([("name", label), ("hash", hash_name),
                                   ("namespace", NAMESPACE),
                                   ("message", MESSAGE.hex()),
                                   ("signature", b64(signature))])

    sections = [("key", keys), ("encrypted", encrypted),
                ("sshsig", signatures)]
    with open(OUTPUT, "w") as out:
        out.write(
            "# SSH key vectors from OpenSSH's ssh-keygen.\n"
            "#\n"
            "# Generated by scripts/make_ssh_vectors.py. Do not edit: every\n"
            "# value here is OpenSSH's answer, and a hand edit makes it\n"
            "# ours.\n"
            "#\n"
            f"# {version}\n"
            "#\n"
            "# The witness is not a dependency: nothing in the build, the\n"
            "# gate or the library links it, and the tests that read this\n"
            "# file need neither OpenSSH nor the network. Keys are fresh on\n"
            "# every run, so every row changes when this is regenerated.\n"
            "#\n"
            "# `private` fields are base64 of the whole private key file,\n"
            "# armour included. These keys exist only to be test vectors.\n"
            "#\n"
            "# Counts, asserted by the test that reads this:\n")
        for name, records in sections:
            out.write(f"#   {name:24} {len(records)}\n")
        for name, records in sections:
            out.write(f"\n[{name}]\n")
            for record in records:
                out.write("\n")
                for key, value in record:
                    out.write(f"{key} = {value}\n")
    print(f"wrote {OUTPUT}: " + ", ".join(f"{len(r)} {n}" for n, r in sections))
    return 0


if __name__ == "__main__":
    sys.exit(main())
