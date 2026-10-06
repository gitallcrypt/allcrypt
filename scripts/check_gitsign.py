#!/usr/bin/env python3
"""The git signing example (`examples/products/gitsign`) against git
2.43, OpenSSH 10.0's `ssh-keygen` and GnuPG 2.4, both directions.

  * **SSH**, every key type OpenSSH makes: commits and tags git signs
    through ours as `gpg.ssh.program`, verified by git through OpenSSH's
    `ssh-keygen`; the same signed through OpenSSH and verified through
    ours. Ed25519 and RSA signatures compared byte for byte. The allowed
    signers file's namespaces, validity dates (git passes the commit's
    time as `verify-time`), principals and a revocation file each
    refusing what they should, in both programs.
  * **OpenPGP**, GnuPG's keys of several algorithms: commits and tags
    git signs through ours as `gpg.program`, verified by git through
    GnuPG, and the reverse; git's `%G?` reading `G` for each.
  * **Objects**: `gitsign sign` on a `git cat-file` object, stored with
    `git hash-object -w` and verified by git and the real tools.

    python3 scripts/check_gitsign.py [--ours PATH]
    python3 scripts/check_gitsign.py --record

`--record` writes `examples/products/fixtures/gitsign/` for the offline
tests: objects OpenSSH and GnuPG signed through git, with the public keys
and allowed signers that check them.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example gitsign`.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures", "gitsign")
OURS = os.path.join(ROOT, "target", "release", "examples", "gitsign")
SSH_KEYGEN = "/opt/openssh/bin/ssh-keygen"

COUNTS = {}
FAILURES = []


def check(kind, condition, detail=""):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    if not condition:
        FAILURES.append(f"{kind}: {detail}")
        print(f"FAIL {kind}: {detail}")


def run(*args, cwd=None, env=None, stdin=None, ok=True):
    result = subprocess.run(args, cwd=cwd, env=env, input=stdin, capture_output=True)
    if ok and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr.decode()}")
    return result


class Repo:
    def __init__(self, tmp, name, env):
        self.path = os.path.join(tmp, name)
        self.env = env
        run("git", "init", "-q", self.path)
        for k, v in [("user.name", "Alice"), ("user.email", "alice@example.com"),
                     ("commit.gpgsign", "false"), ("tag.gpgsign", "false")]:
            self.git("config", k, v)
        self.counter = 0

    def git(self, *args, ok=True, config=()):
        flags = []
        for k, v in config:
            flags += ["-c", f"{k}={v}"]
        return run("git", *flags, *args, cwd=self.path, env=self.env, ok=ok)

    def commit(self, config, message):
        self.counter += 1
        with open(os.path.join(self.path, "f"), "w") as f:
            f.write(f"{self.counter}\n")
        self.git("add", "f")
        self.git("commit", "-q", "-S", "-m", message, config=config)
        return self.git("rev-parse", "HEAD").stdout.decode().strip()

    def tag(self, config, name):
        self.git("tag", "-s", "-m", f"tag {name}", name, config=config)
        return name

    def status(self, config, rev):
        out = self.git("log", "-1", "--format=%G?", rev, config=config).stdout.decode().strip()
        return out


def wrapper(tmp, mode):
    path = os.path.join(tmp, f"ours-{mode}")
    with open(path, "w") as f:
        f.write(f"#!/bin/sh\nexec {OURS} {mode} \"$@\"\n")
    os.chmod(path, 0o755)
    return path


# ---------------------------------------------------------------------- SSH --

SSH_TYPES = [("ed25519", None), ("ecdsa", "256"), ("ecdsa", "384"), ("ecdsa", "521"),
             ("rsa", "2048"), ("rsa", "3072")]


def ssh_key(tmp, kind, bits, name):
    path = os.path.join(tmp, f"{name}-{kind}{bits or ''}")
    args = [SSH_KEYGEN, "-q", "-t", kind, "-N", "", "-C", f"{name}@example.com", "-f", path]
    if bits:
        args[2:2] = ["-b", bits]
    run(*args)
    return path


def check_ssh(tmp, record):
    ours_ssh = wrapper(tmp, "ssh-keygen")
    env = dict(os.environ)
    for kind, bits in SSH_TYPES:
        label = f"{kind}{bits or ''}"
        key = ssh_key(tmp, kind, bits, "alice")
        allowed = os.path.join(tmp, f"allowed-{label}")
        with open(allowed, "w") as f:
            f.write(f"alice@example.com namespaces=\"git\" {open(key + '.pub').read()}")
        repo = Repo(tmp, f"ssh-{label}", env)
        base = [("gpg.format", "ssh"), ("user.signingkey", key),
                ("gpg.ssh.allowedSignersFile", allowed)]
        theirs_cfg = base + [("gpg.ssh.program", SSH_KEYGEN)]
        ours_cfg = base + [("gpg.ssh.program", ours_ssh)]

        for signer, verifier, who in ((ours_cfg, theirs_cfg, "ours signing"),
                                      (theirs_cfg, ours_cfg, "theirs signing")):
            rev = repo.commit(signer, f"{who} {label}")
            v = repo.git("verify-commit", rev, config=verifier, ok=False)
            check("SSH commit verified", v.returncode == 0, f"{label} {who} {v.stderr[-200:]}")
            check("SSH %G?", repo.status(verifier, rev) == "G", f"{label} {who}")
            tag = repo.tag(signer, f"v-{who.split()[0]}")
            v = repo.git("verify-tag", tag, config=verifier, ok=False)
            check("SSH tag verified", v.returncode == 0, f"{label} {who} {v.stderr[-200:]}")
            if who == "theirs signing":
                obj = repo.git("cat-file", "commit", rev).stdout
                record.setdefault("ssh", []).append((label, obj, open(allowed).read(),
                                                     repo.git("cat-file", "tag", tag).stdout))

        # Deterministic signatures, byte for byte, on the same payload.
        if kind in ("ed25519", "rsa"):
            payload = os.path.join(tmp, "payload")
            with open(payload, "wb") as f:
                f.write(os.urandom(300))
            run(SSH_KEYGEN, "-Y", "sign", "-n", "git", "-f", key, payload)
            theirs = open(payload + ".sig").read()
            os.remove(payload + ".sig")
            run(ours_ssh, "-Y", "sign", "-n", "git", "-f", key, payload)
            check("SSH signature identical", open(payload + ".sig").read() == theirs, label)
            os.remove(payload + ".sig")
            if kind == "ed25519":
                record["ssh-signature"] = (open(key).read(), open(payload, "rb").read(), theirs)

        # What the allowed signers file refuses, in both programs.
        rev = repo.commit(ours_cfg, f"policy {label}")
        refusals = {
            "another namespace": f"alice@example.com namespaces=\"file\" {open(key + '.pub').read()}",
            "not yet valid": f"alice@example.com valid-after=\"29990101\" {open(key + '.pub').read()}",
            "expired": f"alice@example.com valid-before=\"20000101\" {open(key + '.pub').read()}",
            "another key": f"alice@example.com {open(ssh_key(tmp, 'ed25519', None, 'eve-' + label) + '.pub').read()}",
        }
        for reason, line in refusals.items():
            policy = os.path.join(tmp, "policy")
            with open(policy, "w") as f:
                f.write(line)
            for program in (SSH_KEYGEN, ours_ssh):
                cfg = base + [("gpg.ssh.program", program),
                              ("gpg.ssh.allowedSignersFile", policy)]
                status = repo.status(cfg, rev)
                check("SSH policy refusal", status != "G",
                      f"{label} {reason} {os.path.basename(program)} gave {status}")
        revoked = os.path.join(tmp, "revoked")
        shutil.copy(key + ".pub", revoked)
        for program in (SSH_KEYGEN, ours_ssh):
            cfg = base + [("gpg.ssh.program", program), ("gpg.ssh.revocationFile", revoked)]
            v = repo.git("verify-commit", rev, config=cfg, ok=False)
            check("SSH revoked key refused", v.returncode != 0,
                  f"{label} {os.path.basename(program)}")


# ------------------------------------------------------------------ OpenPGP --

PGP_ALGOS = ["ed25519", "rsa3072", "nistp256", "nistp384", "brainpoolP256r1", "rsa2048"]


def check_openpgp(tmp, record):
    ours_gpg = wrapper(tmp, "gpg")
    home = os.path.join(tmp, "gnupg")
    os.makedirs(home, mode=0o700)
    env = dict(os.environ, GNUPGHOME=home)
    for algo in PGP_ALGOS:
        uid = f"Bob {algo} <bob-{algo}@example.com>"
        run("gpg", "--batch", "--quiet", "--passphrase", "", "--quick-gen-key", uid, algo, "sign",
            "never", env=env)
        fpr = [l.split(":")[9] for l in run("gpg", "--with-colons", "--list-keys", uid,
                                             env=env).stdout.decode().splitlines()
               if l.startswith("fpr")][0]
        secret = os.path.join(tmp, f"{algo}.sec")
        public = os.path.join(tmp, f"{algo}.pub")
        with open(secret, "wb") as f:
            f.write(run("gpg", "--batch", "--armor", "--export-secret-keys", fpr, env=env).stdout)
        with open(public, "wb") as f:
            f.write(run("gpg", "--armor", "--export", fpr, env=env).stdout)
        repo = Repo(tmp, f"pgp-{algo}", dict(env, GITSIGN_KEYRING=secret))
        base = [("gpg.format", "openpgp"), ("user.signingkey", fpr)]
        theirs_cfg = base + [("gpg.program", "gpg")]
        ours_cfg = base + [("gpg.program", ours_gpg)]
        for signer, verifier, who in ((ours_cfg, theirs_cfg, "ours signing"),
                                      (theirs_cfg, ours_cfg, "theirs signing")):
            rev = repo.commit(signer, f"{who} {algo}")
            v = repo.git("verify-commit", rev, config=verifier, ok=False)
            check("OpenPGP commit verified", v.returncode == 0,
                  f"{algo} {who} {v.stderr[-300:]}")
            check("OpenPGP %G?", repo.status(verifier, rev) == "G", f"{algo} {who}")
            tag = repo.tag(signer, f"v-{who.split()[0]}")
            v = repo.git("verify-tag", tag, config=verifier, ok=False)
            check("OpenPGP tag verified", v.returncode == 0, f"{algo} {who} {v.stderr[-300:]}")
            if who == "theirs signing":
                record.setdefault("openpgp", []).append(
                    (algo, repo.git("cat-file", "commit", rev).stdout, open(public).read(),
                     repo.git("cat-file", "tag", tag).stdout))
        # Our verification with another key in the keyring only.
        other = os.path.join(tmp, "ed25519.pub") if algo != "ed25519" else None
        if other and os.path.exists(other):
            rev = repo.git("rev-parse", "HEAD").stdout.decode().strip()
            obj = repo.git("cat-file", "commit", rev).stdout
            r = run(OURS, "verify", "-", "--keyring", other, stdin=obj, ok=False)
            check("OpenPGP unknown key refused", r.returncode != 0, algo)


def check_protected(tmp):
    """A secret key under a passphrase, which git cannot pass on standard
    input: ours reads it from GITSIGN_PASSPHRASE_FILE."""
    ours_gpg = wrapper(tmp, "gpg")
    home = os.path.join(tmp, "gnupg-protected")
    os.makedirs(home, mode=0o700)
    env = dict(os.environ, GNUPGHOME=home)
    uid = "Dan <dan@example.com>"
    run("gpg", "--batch", "--quiet", "--passphrase", "pw one", "--quick-gen-key", uid,
        "ed25519", "sign", "never", env=env)
    fpr = [l.split(":")[9] for l in run("gpg", "--with-colons", "--list-keys", uid,
                                         env=env).stdout.decode().splitlines()
           if l.startswith("fpr")][0]
    secret = os.path.join(tmp, "dan.sec")
    with open(secret, "wb") as f:
        f.write(run("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "pw one",
                    "--armor", "--export-secret-keys", fpr, env=env).stdout)
    pw = os.path.join(tmp, "pw")
    for passphrase, works in (("pw one", True), ("pw two", False)):
        with open(pw, "w") as f:
            f.write(passphrase + "\n")
        repo = Repo(tmp, f"protected-{works}", dict(env, GITSIGN_KEYRING=secret,
                                                     GITSIGN_PASSPHRASE_FILE=pw))
        cfg = [("gpg.format", "openpgp"), ("user.signingkey", fpr), ("gpg.program", ours_gpg)]
        signed = repo.git("commit", "-q", "--allow-empty", "-S", "-m", "protected", config=cfg,
                          ok=False)
        check("protected key", (signed.returncode == 0) == works, passphrase)
        if works:
            v = repo.git("verify-commit", "HEAD", config=[("gpg.program", "gpg")], ok=False)
            check("protected key's signature verified by GnuPG", v.returncode == 0)


# ------------------------------------------------------------------ objects --

def check_objects(tmp):
    key = ssh_key(tmp, "ed25519", None, "carol")
    allowed = os.path.join(tmp, "allowed-carol")
    with open(allowed, "w") as f:
        f.write(f"carol@example.com {open(key + '.pub').read()}")
    repo = Repo(tmp, "objects", dict(os.environ))
    repo.git("commit", "-q", "--allow-empty", "-m", "unsigned")
    unsigned = repo.git("cat-file", "commit", "HEAD").stdout
    signed = run(OURS, "sign", "-", "--ssh-key", key, stdin=unsigned).stdout
    oid = run("git", "hash-object", "-t", "commit", "-w", "--stdin", cwd=repo.path,
              stdin=signed).stdout.decode().strip()
    cfg = [("gpg.ssh.allowedSignersFile", allowed), ("gpg.ssh.program", SSH_KEYGEN)]
    v = repo.git("verify-commit", oid, config=cfg, ok=False)
    check("object signed by ours, verified by git", v.returncode == 0, v.stderr[-200:])
    back = run(OURS, "verify", "-", "--allowed-signers", allowed, stdin=signed, ok=False)
    check("object verified by ours", back.returncode == 0, back.stdout[-200:])
    payload = run(OURS, "payload", "-", stdin=signed).stdout
    check("payload is the unsigned object", payload == unsigned)
    tampered = signed.replace(b"unsigned", b"unsignee")
    bad = run(OURS, "verify", "-", "--allowed-signers", allowed, stdin=tampered, ok=False)
    check("changed object refused", bad.returncode != 0)


def write_record(record):
    shutil.rmtree(FIXTURES, ignore_errors=True)
    os.makedirs(FIXTURES)
    lines = ["# Objects OpenSSH 10.0's ssh-keygen and GnuPG 2.4.4 signed through git 2.43,",
             "# with what checks them, kept by scripts/check_gitsign.py --record for the",
             "# offline tests in examples/products/gitsign. Each record names its files.", ""]
    for section in ("ssh", "openpgp"):
        lines.append(f"[{section}]")
        for label, commit, keys, tag in record[section]:
            stem = f"{section}-{label}"
            for suffix, data in (("commit", commit), ("tag", tag)):
                with open(os.path.join(FIXTURES, f"{stem}.{suffix}"), "wb") as f:
                    f.write(data)
            with open(os.path.join(FIXTURES, f"{stem}.keys"), "w") as f:
                f.write(keys)
            lines += [f"name = {stem}", f"commit = {stem}.commit", f"tag = {stem}.tag",
                      f"keys = {stem}.keys"]
        lines.append("")
    # A key made for this file alone, the payload and OpenSSH's signature
    # over it: Ed25519 is deterministic, so ours must give the same bytes.
    key, payload, signature = record["ssh-signature"]
    for name, data in (("ssh-signing.key", key.encode()), ("ssh-signing.payload", payload),
                       ("ssh-signing.sig", signature.encode())):
        with open(os.path.join(FIXTURES, name), "wb") as f:
            f.write(data)
    with open(os.path.join(FIXTURES, "gitsign.vec"), "w") as f:
        f.write("\n".join(lines))


def main():
    global OURS
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    OURS = args.ours
    record = {}
    with tempfile.TemporaryDirectory() as tmp:
        check_ssh(tmp, record)
        check_openpgp(tmp, record)
        check_protected(tmp)
        check_objects(tmp)
    if args.record:
        write_record(record)
    total = sum(COUNTS.values())
    print(", ".join(f"{k} {v}" for k, v in COUNTS.items()))
    print(f"{total - len(FAILURES)} of {total} passed")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
