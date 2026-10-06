#!/usr/bin/env python3
"""The age example (`examples/products/age`) against the age tool.

Both directions, with each age given (`--age`, repeatable; default the
system's 1.1 and a current build at /opt/age-main):

  * **age encrypts, ours decrypts**: X25519 recipients (and the
    post-quantum `age1pq` ones, where that age has them), several sizes
    either side of the 64 KiB chunk, binary and armored; and passphrases.
  * **ours encrypts, age decrypts**: to recipients age generated, to
    recipients and identities ours generated (so age reads our Bech32),
    to both at once, and with passphrases.

age reads passphrases from a terminal only, so those rows run it under a
pseudo-terminal.

    python3 scripts/check_age.py
    python3 scripts/check_age.py --age /usr/bin/age --age /opt/age-main/bin/age

The format's own test vectors (C2SP CCTV, 147 files) are in
`examples/products/fixtures/age/testkit/` and run in `cargo test`; this
script is the live half. **A development tool, not a test.**
"""

import argparse
import os
import pty
import re
import select
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SIZES = [0, 1, 65535, 65536, 65537, 200_000]
PASSPHRASE = "correct horse battery staple"


def run(*args, check=True):
    result = subprocess.run(list(args), capture_output=True, timeout=600)
    if check and result.returncode != 0:
        raise RuntimeError(f"{os.path.basename(args[0])}: {result.stderr.decode()[-300:]}")
    return result


def with_terminal(args, passphrase):
    """Run `args` with `passphrase` typed at whatever it asks."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(args[0], args)
    output = b""
    deadline = time.time() + 600
    typed = 0
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            if re.search(rb"passphrase[^\n]*:\s*$", output.split(b"\n")[-1], re.I) and typed < 2:
                os.write(fd, passphrase.encode() + b"\n")
                typed += 1
        else:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                return os.waitstatus_to_exitcode(status), output
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), output


def contents(path):
    """A file's bytes; age creates no output file for an empty
    plaintext."""
    return open(path, "rb").read() if os.path.exists(path) else b""


def plaintext(size):
    return bytes((i * 31 + i // 251) & 0xFF for i in range(size))


def check_one(age, ours, d, report):
    version = run(age, "--version").stdout.decode().strip()
    keygen = os.path.join(os.path.dirname(age), "age-keygen")
    print(f"\nwitness: {age} {version}")
    pq = "pq" in run(keygen, "--help", check=False).stderr.decode().lower() or \
        version.startswith("v1.3")
    kinds = ["x25519"] + (["pq"] if pq else [])
    for kind in kinds:
        theirs_key = os.path.join(d, f"theirs-{kind}.txt")
        if os.path.exists(theirs_key):
            os.remove(theirs_key)
        run(keygen, *(["-pq"] if kind == "pq" else []), "-o", theirs_key)
        theirs_recipient = re.search(rb"public key: (\S+)", open(theirs_key, "rb").read(),
                                     re.I).group(1).decode()
        our_out = run(ours, "keygen", *(["--pq"] if kind == "pq" else [])).stdout.decode()
        our_recipient = re.search(r"public key: (\S+)", our_out).group(1)
        our_key = os.path.join(d, f"ours-{kind}.txt")
        with open(our_key, "w") as out:
            out.write(our_out)
        for size in SIZES:
            data = os.path.join(d, "plain")
            with open(data, "wb") as out:
                out.write(plaintext(size))
            for armor in (False, True):
                label = f"{kind} {size} bytes{' armored' if armor else ''}"
                enc, dec = os.path.join(d, "enc"), os.path.join(d, "dec")
                try:
                    run(age, "-r", theirs_recipient, *(["-a"] if armor else []), "-o", enc, data)
                    run(ours, "decrypt", enc, dec, "--identity-file", theirs_key)
                    report(contents(dec) == plaintext(size),
                           f"age encrypts, ours decrypts: {label}")
                except RuntimeError as error:
                    report(False, f"age encrypts, ours decrypts: {label}", str(error))
                try:
                    run(ours, "encrypt", data, enc, "-r", our_recipient, "-r", theirs_recipient,
                        *(["--armor"] if armor else []))
                    for key in (our_key, theirs_key):
                        os.path.exists(dec) and os.remove(dec)
                        run(age, "-d", "-i", key, "-o", dec, enc)
                        report(contents(dec) == plaintext(size),
                               f"ours encrypts, age decrypts with "
                               f"{'our' if key == our_key else 'its'} identity: {label}")
                except RuntimeError as error:
                    report(False, f"ours encrypts, age decrypts: {label}", str(error))

    data = os.path.join(d, "plain")
    with open(data, "wb") as out:
        out.write(plaintext(70_000))
    enc, dec = os.path.join(d, "enc-pw"), os.path.join(d, "dec-pw")
    for path in (enc, dec):
        os.path.exists(path) and os.remove(path)
    code, output = with_terminal([age, "-p", "-o", enc, data], PASSPHRASE)
    try:
        run(ours, "decrypt", enc, dec, "--passphrase", PASSPHRASE)
        report(code == 0 and open(dec, "rb").read() == plaintext(70_000),
               "age encrypts with a passphrase, ours decrypts", output[-200:])
    except RuntimeError as error:
        report(False, "age encrypts with a passphrase, ours decrypts", f"{error} {output[-200:]}")
    os.remove(dec)
    # The passphrase from standard input, as a pipe gives it.
    piped = subprocess.run([ours, "decrypt", enc, dec, "--passphrase-stdin"],
                           input=(PASSPHRASE + "\n").encode(), capture_output=True, timeout=600)
    report(piped.returncode == 0 and contents(dec) == plaintext(70_000),
           "age encrypts with a passphrase, ours decrypts it from stdin",
           piped.stderr.decode()[-200:])
    os.remove(dec)
    subprocess.run([ours, "encrypt", data, enc, "--passphrase-stdin"],
                   input=(PASSPHRASE + "\n").encode(), check=True, timeout=600)
    code, output = with_terminal([age, "-d", "-o", dec, enc], PASSPHRASE)
    report(code == 0 and contents(dec) == plaintext(70_000),
           "ours encrypts with a passphrase from stdin, age decrypts", output[-200:])
    os.remove(dec)
    run(ours, "encrypt", data, enc, "--passphrase", PASSPHRASE)
    code, output = with_terminal([age, "-d", "-o", dec, enc], PASSPHRASE)
    report(code == 0 and contents(dec) == plaintext(70_000),
           "ours encrypts with a passphrase, age decrypts", output[-200:])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--age", action="append",
                        help="an age binary, with age-keygen beside it (repeatable)")
    args = parser.parse_args()
    ages = args.age or [a for a in ("/usr/bin/age", "/opt/age-main/bin/age")
                        if os.path.exists(a)]
    subprocess.run(["cargo", "build", "--quiet", "--release", "--example", "age"],
                   cwd=ROOT, check=True)
    ours = os.path.join(ROOT, "target", "release", "examples", "age")
    failures = rows = 0

    def report(ok, label, detail=""):
        nonlocal failures, rows
        rows += 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label:66} {'' if ok else detail}")

    with tempfile.TemporaryDirectory() as d:
        for age in ages:
            check_one(age, ours, d, report)
    print(f"{rows - failures} of {rows} passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
