#!/usr/bin/env python3
"""OpenSSH's `ssh` against our SSH server, every algorithm, on loopback.

Runs `examples/ssh_serve.rs` on 127.0.0.1 offering every algorithm the
library has - the legacy ones included - and connects with OpenSSH's own
client once per key exchange, cipher, MAC, host key algorithm and user
key type, with `-o` options that leave the client one choice. `ssh`
checks the host key against a `known_hosts` file holding ours
(`StrictHostKeyChecking=yes`), so every row is a host key signature over
the exchange hash that OpenSSH verified, then authentication, a channel,
a command, its output and its exit status, and the close.

    python3 scripts/check_ssh_server.py --openssh /opt/openssh
    python3 scripts/check_ssh_server.py --legacy-openssh /opt/openssh74
    python3 scripts/check_ssh_server.py --legacy-openssh /opt/openssh74 \\
        --record tests/transcripts/ssh_server_sessions.txt

Beyond the algorithm rows: password authentication through
`SSH_ASKPASS`; five megabytes through `cat` and `sha256sum` with
`RekeyLimit` low enough that the client re-keys several times
mid-stream; `ssh -tt`, whose terminal request the server records for the
caller; and a key the server does not accept, which `ssh` must report
as refused.

`--legacy-openssh` adds OpenSSH 7.4 (built against OpenSSL 1.0.2) as the
client, for what 10.0 removed: `ssh-dss`, `arcfour`, `blowfish-cbc`,
`cast128-cbc`, `hmac-ripemd160` - what an old management station or
script host would send. 7.4 has no strict key exchange, so those rows
run without it.

With `--record`, a chosen set of sessions is run with the server's
randomness drawn from a counter (`seed=`), and both directions are
written down with the host key, the user key and the output.
`tests/test_ssh_server_sessions.rs` feeds the client's side to a server
seeded the same way and requires it to send exactly what it sent to
`ssh` - which it can only do if every key it derived, and every
signature it made, matched what OpenSSH accepted.

**A development tool, not a test.** It needs the OpenSSH builds and
cargo; the gate runs none of it. Nothing leaves loopback.
"""

import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = 2243

KEX = ["mlkem768x25519-sha256", "sntrup761x25519-sha512",
       "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org",
       "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
       "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
       "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
       "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
       "diffie-hellman-group1-sha1"]
CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com",
           "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
           "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"]
MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
        "hmac-sha1-96", "hmac-sha1-96-etm@openssh.com", "hmac-md5", "hmac-md5-96",
        "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
        "umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "umac-64@openssh.com",
        "umac-128@openssh.com"]
HOST_KEYS = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
# (name, ssh-keygen type, bits, the signature algorithm the client
# should then use, and any option it needs).
USER_KEYS = [("ed25519", "ed25519", None, "ssh-ed25519", []),
             ("ecdsa256", "ecdsa", 256, "ecdsa-sha2-nistp256", []),
             ("ecdsa384", "ecdsa", 384, "ecdsa-sha2-nistp384", []),
             ("ecdsa521", "ecdsa", 521, "ecdsa-sha2-nistp521", []),
             # server-sig-algs is what lets the client use SHA-512 here.
             ("rsa2048", "rsa", 2048, "rsa-sha2-512", []),
             ("rsa2048", "rsa", 2048, "ssh-rsa", ["PubkeyAcceptedAlgorithms=ssh-rsa"])]

LEGACY_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
              "diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256",
              "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"]
LEGACY_CIPHERS = ["arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc",
                  "rijndael-cbc@lysator.liu.se", "3des-cbc", "aes128-ctr",
                  "chacha20-poly1305@openssh.com"]
LEGACY_MACS = ["hmac-ripemd160", "hmac-ripemd160@openssh.com",
               "hmac-ripemd160-etm@openssh.com", "hmac-md5", "hmac-sha1",
               "hmac-sha2-256", "umac-64@openssh.com", "umac-128-etm@openssh.com"]
LEGACY_HOST_KEYS = ["ssh-dss", "ssh-rsa", "rsa-sha2-512", "ssh-ed25519"]
LEGACY_USER_KEYS = [("dsa", "dsa", None, "ssh-dss", ["PubkeyAcceptedKeyTypes=ssh-dss"]),
                    ("rsa2048", "rsa", 2048, "rsa-sha2-512", []),
                    ("ed25519", "ed25519", None, "ssh-ed25519", [])]

# The sessions recorded for offline replay: (name, host key, user key or
# "password", client options, command). Every key exchange family,
# cipher family, MAC mode, host key type and authentication path
# appears in at least one. The group exchanges use AES-128, whose key
# size makes OpenSSH ask for a 3072 bit group: an 8192 bit one would
# take the replay a minute in a debug build.
RECORDED = [
    ("pq-chacha-ed25519", "ed25519", "ed25519", [], None),
    ("sntrup-gcm-nistp256", "ecdsa256", "ecdsa256",
     ["KexAlgorithms=sntrup761x25519-sha512", "Ciphers=aes256-gcm@openssh.com",
      "HostKeyAlgorithms=ecdsa-sha2-nistp256"], None),
    ("x25519-ctr-etm-rsa", "rsa", "rsa2048",
     ["KexAlgorithms=curve25519-sha256", "Ciphers=aes128-ctr",
      "MACs=hmac-sha2-256-etm@openssh.com", "HostKeyAlgorithms=rsa-sha2-512"], None),
    ("nistp384-cbc-hmac", "ecdsa384", "ecdsa384",
     ["KexAlgorithms=ecdh-sha2-nistp384", "Ciphers=aes256-cbc", "MACs=hmac-sha2-512",
      "HostKeyAlgorithms=ecdsa-sha2-nistp384"], None),
    ("nistp521-umac", "ecdsa521", "ed25519",
     ["KexAlgorithms=ecdh-sha2-nistp521", "Ciphers=aes192-ctr",
      "MACs=umac-128-etm@openssh.com", "HostKeyAlgorithms=ecdsa-sha2-nistp521"], None),
    ("gex-sha256-gcm", "rsa", "ed25519",
     ["KexAlgorithms=diffie-hellman-group-exchange-sha256", "Ciphers=aes128-gcm@openssh.com",
      "HostKeyAlgorithms=rsa-sha2-256"], None),
    ("group14-password", "ed25519", "password",
     ["KexAlgorithms=diffie-hellman-group14-sha256", "Ciphers=aes128-gcm@openssh.com"], None),
    ("old-group14-sha1-ssh-rsa", "rsa", "rsa2048",
     ["KexAlgorithms=diffie-hellman-group14-sha1", "Ciphers=aes128-cbc", "MACs=hmac-sha1",
      "HostKeyAlgorithms=ssh-rsa", "PubkeyAcceptedAlgorithms=ssh-rsa"], None),
    ("old-group1-3des-md5", "rsa", "ecdsa256",
     ["KexAlgorithms=diffie-hellman-group1-sha1", "Ciphers=3des-cbc", "MACs=hmac-md5",
      "HostKeyAlgorithms=ssh-rsa"], None),
    # The client re-keys every 4 KiB; 12 KiB through `cat` makes several
    # re-exchanges with channel data on both sides of each.
    ("client-rekeys", "ed25519", "ed25519",
     ["KexAlgorithms=curve25519-sha256", "RekeyLimit=4K"], "cat"),
    ("terminal-request", "ecdsa256", "ed25519",
     ["KexAlgorithms=curve25519-sha256", "RequestTTY=force"], None),
]

LEGACY_RECORDED = [
    ("legacy-dss-group1-arcfour", "dsa", "dsa",
     ["KexAlgorithms=diffie-hellman-group1-sha1", "Ciphers=arcfour", "MACs=hmac-ripemd160",
      "HostKeyAlgorithms=ssh-dss", "PubkeyAcceptedKeyTypes=ssh-dss"], None),
    ("legacy-gex-sha1-blowfish", "rsa", "rsa2048",
     ["KexAlgorithms=diffie-hellman-group-exchange-sha1", "Ciphers=blowfish-cbc",
      "MACs=hmac-md5", "HostKeyAlgorithms=ssh-rsa"], None),
    ("legacy-cast128-ripemd-etm", "ed25519", "ed25519",
     ["KexAlgorithms=curve25519-sha256@libssh.org", "Ciphers=cast128-cbc",
      "MACs=hmac-ripemd160-etm@openssh.com", "HostKeyAlgorithms=ssh-ed25519"], None),
    ("legacy-arcfour256-umac", "dsa", "ed25519",
     ["KexAlgorithms=ecdh-sha2-nistp256", "Ciphers=arcfour256", "MACs=umac-64@openssh.com",
      "HostKeyAlgorithms=ssh-dss"], None),
]

PROFILES = {
    "current": dict(kex=KEX, ciphers=CIPHERS, macs=MACS, host_keys=HOST_KEYS,
                    user_keys=USER_KEYS, recorded=RECORDED,
                    host_key_types=[("ed25519", "ed25519", None), ("ecdsa256", "ecdsa", 256),
                                    ("ecdsa384", "ecdsa", 384), ("ecdsa521", "ecdsa", 521),
                                    ("rsa", "rsa", 2048)]),
    "legacy": dict(kex=LEGACY_KEX, ciphers=LEGACY_CIPHERS, macs=LEGACY_MACS,
                   host_keys=LEGACY_HOST_KEYS, user_keys=LEGACY_USER_KEYS,
                   recorded=LEGACY_RECORDED,
                   host_key_types=[("dsa", "dsa", None), ("rsa", "rsa", 2048),
                                   ("ed25519", "ed25519", None)]),
}

PASSWORD = "correct horse battery staple"


def field(log, name):
    match = re.search(rf"\b{name}=(\S+)", log)
    return match.group(1) if match else ""


class Rig:
    """Keys, a known_hosts file and the server binary, for one client."""

    def __init__(self, profile, openssh, server, directory):
        self.profile = profile
        self.ssh = os.path.join(openssh, "bin", "ssh")
        self.server = server
        self.d = directory
        self.version = subprocess.run([self.ssh, "-V"], capture_output=True,
                                      text=True).stderr.strip()
        keygen = os.path.join(openssh, "bin", "ssh-keygen")

        def make(prefix, name, kind, bits):
            path = os.path.join(directory, f"{prefix}_{name}")
            if not os.path.exists(path):
                # -o: openssh-key-v1, which 7.4 writes only when asked.
                subprocess.run([keygen, "-q", "-o", "-t", kind, "-N", "", "-f", path]
                               + (["-b", str(bits)] if bits else []), check=True)
            return path
        self.host_keys = {name: make("host", name, kind, bits)
                          for name, kind, bits in profile["host_key_types"]}
        self.users = {name: make("user", name, kind, bits)
                      for name, kind, bits, _, _ in profile["user_keys"]}
        self.authorized = os.path.join(directory, "authorized_keys")
        with open(self.authorized, "w") as out:
            for path in self.users.values():
                out.write(open(path + ".pub").read())
        # Made after the file is written, so it is not in it.
        self.users["stranger"] = make("user", "stranger", "ed25519", None)
        self.known = os.path.join(directory, "known_hosts")
        with open(self.known, "w") as out:
            for path in self.host_keys.values():
                kind, blob = open(path + ".pub").read().split()[:2]
                out.write(f"[127.0.0.1]:{PORT} {kind} {blob}\n")
        self.askpass = os.path.join(directory, "askpass")
        with open(self.askpass, "w") as out:
            out.write(f"#!/bin/sh\necho '{PASSWORD}'\n")
        os.chmod(self.askpass, 0o700)

    def session(self, command, user_key="ed25519", options=(), host_keys=None, stdin=b"",
                server_args=(), password=False):
        """One connection: start the server for it, run ssh, return
        (ssh's result, the server's log line)."""
        host_keys = host_keys or list(self.host_keys.values())
        log_path = os.path.join(self.d, "server.log")
        server = subprocess.Popen(
            [self.server, str(PORT), ",".join(host_keys), f"authorized={self.authorized}",
             f"password={PASSWORD}", "kex=all", "cipher=all", "mac=all", "hostkey=all",
             "once"] + list(server_args),
            stderr=open(log_path, "w"))
        time.sleep(0.2)
        argv = [self.ssh, "-F", "/dev/null", "-p", str(PORT),
                "-o", f"UserKnownHostsFile={self.known}", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=20"]
        env = dict(os.environ)
        if password:
            argv += ["-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                     "-o", "NumberOfPasswordPrompts=1"]
            # 10.0 takes SSH_ASKPASS_REQUIRE; 7.4 needs DISPLAY and no
            # terminal, which setsid gives it.
            env.update(SSH_ASKPASS=self.askpass, SSH_ASKPASS_REQUIRE="force", DISPLAY=":0")
        else:
            argv += ["-o", "BatchMode=yes", "-i", self.users[user_key],
                     "-o", "IdentitiesOnly=yes"]
        for option in options:
            argv += ["-o", option]
        argv += ["allcrypt@127.0.0.1", command]
        try:
            run = subprocess.run(argv, input=stdin, capture_output=True, timeout=180, env=env,
                                 start_new_session=password)
        finally:
            try:
                server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        log = open(log_path).read()
        return run, log


def run_profile(name, openssh, server, record, first_seed):
    profile = PROFILES[name]
    failures, rows, recorded = 0, 0, []

    def report(ok, label, detail=""):
        nonlocal failures, rows
        rows += 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label:56} {'' if ok else detail}")

    with tempfile.TemporaryDirectory() as d:
        rig = Rig(profile, openssh, server, d)
        print(f"\n{name}: {rig.version}")
        command = "echo ran; stderr err; exit 7"

        def plain(label, user_key="ed25519", options=(), expect=None):
            run, log = rig.session(command, user_key=user_key, options=options)
            ok = (run.returncode == 7 and run.stdout == b"ran\n" and run.stderr == b"err\n"
                  and "closed=true" in log)
            for key, value in (expect or {}).items():
                ok = ok and field(log, key) == value
            report(ok, label, f"exit={run.returncode} {run.stderr[-200:]!r} "
                              f"{log.strip().splitlines()[-1][:300] if log.strip() else ''}")

        for kex in profile["kex"]:
            plain(f"kex {kex}", options=[f"KexAlgorithms={kex}"], expect={"kex": kex})
        for cipher in profile["ciphers"]:
            plain(f"cipher {cipher}", options=[f"Ciphers={cipher}"],
                  expect={"cipher": f"{cipher}/{cipher}"})
        for mac in profile["macs"]:
            plain(f"mac {mac}", options=[f"MACs={mac}", "Ciphers=aes128-ctr"],
                  expect={"mac": f'Some("{mac}")/Some("{mac}")'})
        for host_key in profile["host_keys"]:
            plain(f"host key {host_key}", options=[f"HostKeyAlgorithms={host_key}"],
                  expect={"hostkey": host_key})
        for user, _, _, algorithm, options in profile["user_keys"]:
            run, log = rig.session(command, user_key=user, options=options)
            ok = run.returncode == 7 and f'auth=Some("publickey {algorithm}")' in log
            report(ok, f"user key {user} as {algorithm}",
                   f"exit={run.returncode} {run.stderr[-200:]!r} {log[-300:]}")

        run, log = rig.session(command, user_key=None, password=True)
        report(run.returncode == 7 and 'auth=Some("password")' in log, "password",
               f"exit={run.returncode} {run.stderr[-200:]!r}")

        run, log = rig.session(command, user_key="stranger")
        report(run.returncode == 255 and b"Permission denied (publickey,password)" in run.stderr,
               "a key not in authorized_keys is refused",
               f"exit={run.returncode} {run.stderr[-200:]!r}")

        big = os.urandom(5_000_000)
        digest = hashlib.sha256(big).hexdigest()
        run, log = rig.session("cat", stdin=big, options=["RekeyLimit=1M"])
        exchanges = int(field(log, "exchanges") or 0)
        report(run.returncode == 0 and run.stdout == big and exchanges > 2,
               "5 MB through cat, client re-keying every 1 MB",
               f"exit={run.returncode} out={len(run.stdout)} exchanges={exchanges}")
        run, log = rig.session("sha256sum", stdin=big, options=["RekeyLimit=512K"])
        report(run.returncode == 0 and run.stdout == f"{digest}  -\n".encode(),
               "5 MB to sha256sum", f"exit={run.returncode} {run.stdout[:80]!r}")

        run, log = rig.session("echo with a terminal; exit 4", options=["RequestTTY=force"])
        report(run.returncode == 4 and b"with a terminal" in run.stdout
               and 'terminal=Some("' in log,
               "ssh -tt: the terminal request recorded, the command run",
               f"exit={run.returncode} {run.stdout!r} {run.stderr[-200:]!r}")

        for seed, (session, host, user, options, cmd) in enumerate(
                profile["recorded"] if record else [], start=first_seed):
            transcript = os.path.join(d, f"{session}.txt")
            cmd = cmd or f"echo {session}; stderr too; exit {seed}"
            stdin = bytes((i * 7 + i // 251) & 0xFF for i in range(12 * 1024)) \
                if cmd == "cat" else b""
            run, log = rig.session(cmd, user_key=None if user == "password" else user,
                                   options=options, host_keys=[rig.host_keys[host]],
                                   stdin=stdin, password=user == "password",
                                   server_args=[f"seed={seed}", f"record={transcript}"])
            expected = stdin if cmd == "cat" else f"{session}\n".encode()
            status = 0 if cmd == "cat" else seed
            ok = run.returncode == status and run.stdout == expected and "closed=true" in log
            report(ok, f"recorded {session}",
                   f"exit={run.returncode} {run.stderr[-200:]!r} {log[-300:]}")
            # The server had every user key and the password; the replay
            # needs the key that was used (any, for the password session,
            # so that `publickey` is among the methods a failure lists).
            used = rig.users["ed25519" if user == "password" else user]
            recorded.append(dict(
                name=session, client=rig.version, seed=seed,
                host_key=base64.b64encode(open(rig.host_keys[host], "rb").read()).decode(),
                authorized=" ".join(open(used + ".pub").read().split()[:2]),
                command=cmd, stdout=run.stdout.hex(), exit=status,
                exchanges=field(log, "exchanges"), auth=re.search(
                    r'auth=Some\("([^"]*)"\)', log).group(1) if ok else "",
                transcript=open(transcript).read() if os.path.exists(transcript) else ""))
    print(f"  {rows - failures} of {rows} passed.")
    return failures, recorded


def write_record(path, recorded):
    with open(path, "w") as out:
        out.write(
            "# SSH sessions between OpenSSH's ssh and this library's server,\n"
            "# recorded on loopback by scripts/check_ssh_server.py --record.\n"
            "#\n"
            "# Each session ran with the server's randomness drawn from a\n"
            "# counter seeded with `seed`, so tests/test_ssh_server_sessions.rs\n"
            "# can feed the `C` lines (what ssh sent) to a server seeded the same\n"
            "# way and require it to produce the `S` lines exactly. The server\n"
            "# offered every algorithm it has; the client's options chose.\n"
            "# The keys exist only for this file. Do not edit: a changed byte\n"
            "# is a session ssh never had.\n"
            f"#\n# sessions: {len(recorded)}\n")
        for entry in recorded:
            out.write(f"\n[{entry['name']}]\nclient = {entry['client']}\n"
                      f"seed = {entry['seed']}\nhost_key = {entry['host_key']}\n")
            out.write(f"authorized = {entry['authorized']}\npassword = {PASSWORD}\n")
            out.write(f"command = {entry['command']}\nauth = {entry['auth']}\n"
                      f"exchanges = {entry['exchanges']}\nstdout = {entry['stdout']}\n"
                      f"exit = {entry['exit']}\n{entry['transcript']}")
    print(f"wrote {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssh", default="/opt/openssh")
    parser.add_argument("--legacy-openssh", metavar="DIR",
                        help="an OpenSSH 7.x build, for the algorithms 10.0 removed")
    parser.add_argument("--record", metavar="FILE",
                        help="record the RECORDED sessions for offline replay")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "--quiet", "--release", "--example", "ssh_serve"],
                   cwd=ROOT, check=True)
    server = os.path.join(ROOT, "target", "release", "examples", "ssh_serve")
    failures, recorded = run_profile("current", args.openssh, server, args.record, 1)
    if args.legacy_openssh:
        more, extra = run_profile("legacy", args.legacy_openssh, server, args.record,
                                  len(recorded) + 1)
        failures += more
        recorded += extra
    if args.record and not failures:
        write_record(args.record, recorded)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
