#!/usr/bin/env python3
"""Hand OpenSSH files this library wrote, and see whether it agrees.

`vectors/ssh_keys.vec` checks the reading direction: OpenSSH's keys and
signatures, read here. This checks the writing direction, which no
vector file can, because what this library writes is fresh every time:

  * every key type, written as an `openssh-key-v1` file unencrypted and
    under each cipher, must be read by `ssh-keygen -y` (with the
    passphrase) and give back the `.pub` line we wrote;
  * every SSHSIG we made must pass `ssh-keygen -Y check-novalidate`.

    python3 scripts/check_ssh_witness.py --openssh /opt/openssh/bin \
        --legacy-openssh /opt/openssh74/bin

What OpenSSH 10.0 can no longer read - DSA keys, and key files under
the ciphers 7.6 removed - goes to `--legacy-openssh` (a 7.x); without
one, those rows are skipped and counted as such.

**A development tool, not a test**: it needs OpenSSH and cargo, and the
gate runs neither.
"""

import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssh", default="/opt/openssh/bin")
    parser.add_argument("--legacy-openssh", metavar="DIR")
    args = parser.parse_args()
    current = os.path.join(args.openssh, "ssh-keygen")
    legacy = os.path.join(args.legacy_openssh, "ssh-keygen") if args.legacy_openssh else None
    old_ciphers = {"blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256",
                   "rijndael-cbc@lysator.liu.se"}
    failures = checked = skipped = 0
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(["cargo", "run", "--quiet", "--example", "ssh_write_keys",
                        "--", directory], cwd=ROOT, check=True)
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            old = name.startswith("dsa") or any(c in name for c in old_ciphers)
            keygen = legacy if old else current
            if keygen is None:
                skipped += 1
                continue
            if "--" in name:
                key, cipher = name.split("--", 1)
                expected = open(os.path.join(directory, key + ".pub")).read().split()[:2]
                run = subprocess.run([keygen, "-y", "-P", "pw", "-f", path],
                                     capture_output=True, text=True)
                ok = run.returncode == 0 and run.stdout.split()[:2] == expected
                label = f"key  {key:10} {cipher}"
            elif name.endswith(".sig") and not name.startswith("dsa"):
                key = name.split(".")[0]
                run = subprocess.run(
                    [keygen, "-Y", "check-novalidate", "-n", "file", "-s", path],
                    input="allcrypt\n", capture_output=True, text=True)
                ok = run.returncode == 0
                label = f"sig  {name}"
            else:
                continue
            checked += 1
            failures += not ok
            detail = "" if ok else (run.stderr or run.stdout).strip()
            print(f"  {'ok  ' if ok else 'FAIL'} {label} {detail}")
    print(f"\n{checked - failures} of {checked} accepted by OpenSSH"
          + (f"; {skipped} skipped for want of --legacy-openssh." if skipped else "."))
    return 1 if failures or not checked else 0


if __name__ == "__main__":
    sys.exit(main())
