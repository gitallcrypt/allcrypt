#!/usr/bin/env python3
"""Our SSH client against OpenSSH's sshd, every algorithm, on loopback.

Starts an `sshd` from the OpenSSH witness build on 127.0.0.1 with every
algorithm it still has turned on - the legacy ones included - and runs
`examples/ssh_exec.rs` against it once per key exchange, cipher, MAC,
host key algorithm and user key type, checking that the command's output
and exit status come back. Each row is a whole session: version
exchange, key exchange, host key signature, NEWKEYS, authentication,
a channel, a command, and close.

    python3 scripts/check_ssh_client.py --openssh /opt/openssh
    python3 scripts/check_ssh_client.py --legacy-openssh /opt/openssh74
    python3 scripts/check_ssh_client.py --legacy-openssh /opt/openssh74 \
        --record tests/transcripts/ssh_sessions.txt

`--legacy-openssh` adds a second sshd, an OpenSSH 7.4 built against
OpenSSL 1.0.2, for what current OpenSSH has removed: `ssh-dss`,
`arcfour`, `blowfish-cbc`, `cast128-cbc`, `hmac-ripemd160` - the set an
appliance from the 2000s speaks. It runs on its own port.

With `--record`, a chosen set of sessions is run with the client's
randomness drawn from a counter (`seed=`), and both directions are
written down with the user key, the host key's fingerprint and the
output. `tests/test_ssh_sessions.rs` replays the server's side at a
client seeded the same way and requires it to send exactly what it sent
to sshd - which it can only do if every key it derived matched
OpenSSH's. That is how the gate checks the client without OpenSSH.

**A development tool, not a test.** It needs the OpenSSH build, cargo,
and to run as root (sshd's privilege separation), and the gate runs
none of it. Nothing leaves loopback.
"""

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = 2233

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
USER_KEYS = [("ed25519", None), ("ecdsa", 256), ("ecdsa", 384), ("ecdsa", 521),
             ("rsa", 2048)]

# OpenSSH 7.4: everything it has that 10.0 does not, and enough of the
# rest to know it is the same protocol.
LEGACY_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
              "diffie-hellman-group-exchange-sha1", "curve25519-sha256@libssh.org",
              "ecdh-sha2-nistp256"]
LEGACY_CIPHERS = ["arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc",
                  "rijndael-cbc@lysator.liu.se", "3des-cbc", "aes128-ctr",
                  "chacha20-poly1305@openssh.com"]
LEGACY_MACS = ["hmac-ripemd160", "hmac-ripemd160@openssh.com",
               "hmac-ripemd160-etm@openssh.com", "hmac-md5", "hmac-sha1",
               "hmac-sha2-256", "umac-64@openssh.com", "umac-128-etm@openssh.com"]
LEGACY_HOST_KEYS = ["ssh-dss", "ssh-rsa", "ssh-ed25519"]
LEGACY_USER_KEYS = [("dsa", None), ("rsa", 2048), ("ed25519", None)]
LEGACY_RECORDED = [
    ("legacy-dss-arcfour-ripemd", "dsa",
     ["kex=diffie-hellman-group1-sha1", "cipher=arcfour", "mac=hmac-ripemd160",
      "hostkey=ssh-dss"]),
    ("legacy-blowfish-md5", "rsa2048",
     ["kex=diffie-hellman-group14-sha1", "cipher=blowfish-cbc", "mac=hmac-md5",
      "hostkey=ssh-rsa"]),
    ("legacy-cast128-arcfour256", "dsa",
     ["kex=diffie-hellman-group-exchange-sha1", "cipher=cast128-cbc",
      "mac=hmac-ripemd160-etm@openssh.com", "hostkey=ssh-dss"]),
    ("legacy-arcfour128-rijndael", "ed25519",
     ["kex=curve25519-sha256@libssh.org", "cipher=arcfour128", "mac=hmac-sha1",
      "hostkey=ssh-dss"]),
    ("legacy-umac-64", "rsa2048",
     ["kex=diffie-hellman-group14-sha1", "cipher=aes128-ctr", "mac=umac-64@openssh.com",
      "hostkey=ssh-rsa"]),
]


# The sessions recorded for offline replay: (name, user key, options).
# Every key exchange, cipher family, MAC mode and key type appears in at
# least one, and the old algorithms an appliance would offer have their
# own rows.
RECORDED = [
    ("pq-chacha-ed25519", "ed25519",
     ["kex=mlkem768x25519-sha256", "cipher=chacha20-poly1305@openssh.com",
      "hostkey=ssh-ed25519"]),
    ("x25519-gcm-rsa-user", "rsa2048",
     ["kex=curve25519-sha256", "cipher=aes256-gcm@openssh.com",
      "hostkey=rsa-sha2-512"]),
    ("nistp521-ctr-etm", "ecdsa521",
     ["kex=ecdh-sha2-nistp521", "cipher=aes128-ctr",
      "mac=hmac-sha2-512-etm@openssh.com", "hostkey=ecdsa-sha2-nistp521"]),
    ("nistp256-cbc-encrypt-and-mac", "ecdsa256",
     ["kex=ecdh-sha2-nistp256", "cipher=aes256-cbc", "mac=hmac-sha2-256",
      "hostkey=ecdsa-sha2-nistp256"]),
    ("gex-sha256-ctr", "ecdsa384",
     ["kex=diffie-hellman-group-exchange-sha256", "cipher=aes256-ctr",
      "mac=hmac-sha2-256-etm@openssh.com", "hostkey=rsa-sha2-256"]),
    ("group14-sha256-gcm", "ed25519",
     ["kex=diffie-hellman-group14-sha256", "cipher=aes128-gcm@openssh.com",
      "hostkey=ecdsa-sha2-nistp384"]),
    ("old-appliance-group1-3des-md5", "rsa2048",
     ["kex=diffie-hellman-group1-sha1", "cipher=3des-cbc", "mac=hmac-md5",
      "hostkey=ssh-rsa"]),
    ("old-group14-sha1-cbc-sha1-96", "ed25519",
     ["kex=diffie-hellman-group14-sha1", "cipher=aes128-cbc", "mac=hmac-sha1-96",
      "hostkey=ssh-rsa"]),
    # More of the two methods whose K is 32 bytes: an mpint and a string
    # of 32 bytes are the same bytes unless the top bit is set, so one
    # session tells the two encodings apart only half the time. Four of
    # each make it fifteen times in sixteen, and the replay test checks
    # that it did.
    ("x25519-b", "ed25519", ["kex=curve25519-sha256", "cipher=aes128-ctr",
                             "mac=hmac-sha1", "hostkey=ssh-ed25519"]),
    ("x25519-c", "ecdsa256", ["kex=curve25519-sha256@libssh.org",
                              "cipher=chacha20-poly1305@openssh.com",
                              "hostkey=ecdsa-sha2-nistp256"]),
    ("x25519-d", "ed25519", ["kex=curve25519-sha256", "cipher=aes256-gcm@openssh.com",
                             "hostkey=ssh-ed25519"]),
    ("pq-b", "rsa2048", ["kex=mlkem768x25519-sha256", "cipher=aes256-gcm@openssh.com",
                         "hostkey=rsa-sha2-512"]),
    ("pq-c", "ecdsa384", ["kex=mlkem768x25519-sha256", "cipher=aes128-ctr",
                          "mac=hmac-sha2-256-etm@openssh.com", "hostkey=ssh-ed25519"]),
    ("pq-d", "ed25519", ["kex=mlkem768x25519-sha256", "cipher=aes256-cbc",
                         "mac=hmac-sha2-512", "hostkey=ecdsa-sha2-nistp521"]),
    # Streamlined NTRU Prime, OpenSSH 9.0 to 9.8's default. Its K is a
    # 64 byte string, so the same top-bit argument as above applies.
    ("sntrup-a", "ed25519", ["kex=sntrup761x25519-sha512",
                             "cipher=chacha20-poly1305@openssh.com", "hostkey=ssh-ed25519"]),
    ("sntrup-b", "rsa2048", ["kex=sntrup761x25519-sha512@openssh.com",
                             "cipher=aes256-gcm@openssh.com", "hostkey=rsa-sha2-512"]),
    ("sntrup-c", "ecdsa256", ["kex=sntrup761x25519-sha512", "cipher=aes128-ctr",
                              "mac=hmac-sha2-256-etm@openssh.com",
                              "hostkey=ecdsa-sha2-nistp256"]),
    # UMAC, both tag sizes and both MAC modes; its nonce is the sequence
    # number, so every packet of the session checks a different one.
    ("umac-64-etm", "ed25519", ["kex=curve25519-sha256", "cipher=aes256-ctr",
                                "mac=umac-64-etm@openssh.com", "hostkey=ssh-ed25519"]),
    ("umac-128-encrypt-and-mac", "ecdsa256", ["kex=ecdh-sha2-nistp384", "cipher=aes128-cbc",
                                              "mac=umac-128@openssh.com",
                                              "hostkey=ecdsa-sha2-nistp256"]),
]


PROFILES = {
    "current": dict(port=PORT, kex=KEX, ciphers=CIPHERS, macs=MACS, host_keys=HOST_KEYS,
                    user_keys=USER_KEYS, recorded=RECORDED,
                    host_key_types=[("ed25519", None), ("ecdsa", 256), ("ecdsa", 384),
                                    ("ecdsa", 521), ("rsa", 2048)],
                    accept="PubkeyAcceptedAlgorithms +ssh-rsa"),
    "legacy": dict(port=PORT + 1, kex=LEGACY_KEX, ciphers=LEGACY_CIPHERS, macs=LEGACY_MACS,
                   host_keys=LEGACY_HOST_KEYS, user_keys=LEGACY_USER_KEYS,
                   recorded=LEGACY_RECORDED,
                   host_key_types=[("dsa", None), ("rsa", 2048), ("ed25519", None)],
                   accept="PubkeyAcceptedKeyTypes +ssh-dss,ssh-rsa"),
}


def write_record(path, recorded):
    with open(path, "w") as out:
        out.write(
            "# SSH sessions between this library's client and OpenSSH's sshd,\n"
            "# recorded on loopback by scripts/check_ssh_client.py --record.\n"
            "#\n"
            "# Each session ran with the client's randomness drawn from a\n"
            "# counter seeded with `seed`, so tests/test_ssh_sessions.rs can\n"
            "# replay the `S` lines (what sshd sent) at a client seeded the same\n"
            "# way and require it to produce the `C` lines exactly. The user keys\n"
            "# exist only for this file. Do not edit: a changed byte is a\n"
            "# session sshd never had.\n"
            f"#\n# sessions: {len(recorded)}\n")
        for entry in recorded:
            out.write(f"\n[{entry['name']}]\nserver = {entry['server']}\n"
                      f"seed = {entry['seed']}\noptions = {' '.join(entry['options'])}\n"
                      f"command = {entry['command']}\nhost_key = {entry['host_key']}\n"
                      f"key = {entry['key']}\nstdout = {entry['stdout'].encode().hex()}\n"
                      f"exit = {entry['seed']}\n{entry['transcript']}")
    print(f"wrote {path}")


def run_profile(name, openssh, client, record, first_seed):
    """One sshd, every row of the profile against it, and its recordings."""
    import base64
    profile = PROFILES[name]
    keygen = os.path.join(openssh, "bin", "ssh-keygen")
    sshd = os.path.join(openssh, "sbin", "sshd")
    version = subprocess.run([os.path.join(openssh, "bin", "ssh"), "-V"],
                             capture_output=True, text=True).stderr.strip()
    print(f"\n{name}: {version}")
    failures, recorded = 0, []
    with tempfile.TemporaryDirectory() as d:
        def make_key(prefix, kind, bits):
            path = os.path.join(d, f"{prefix}_{kind}{bits or ''}")
            # -o: the openssh-key-v1 format, which 7.4 writes only when asked.
            subprocess.run([keygen, "-q", "-o", "-t", kind, "-N", "", "-f", path]
                           + (["-b", str(bits)] if bits else []), check=True)
            return path
        host_keys = [make_key("host", kind, bits) for kind, bits in profile["host_key_types"]]
        users = {f"{kind}{bits or ''}": make_key("user", kind, bits)
                 for kind, bits in profile["user_keys"]}
        with open(os.path.join(d, "authorized_keys"), "w") as out:
            for path in users.values():
                out.write(open(path + ".pub").read())
        config = os.path.join(d, "sshd_config")
        with open(config, "w") as out:
            out.write(f"Port {profile['port']}\nListenAddress 127.0.0.1\n")
            for path in host_keys:
                out.write(f"HostKey {path}\n")
            out.write(f"AuthorizedKeysFile {d}/authorized_keys\nPermitRootLogin yes\n"
                      f"StrictModes no\nUsePAM no\nPidFile {d}/sshd.pid\n"
                      f"KexAlgorithms {','.join(profile['kex'])}\n"
                      f"Ciphers {','.join(profile['ciphers'])}\n"
                      f"MACs {','.join(profile['macs'])}\n"
                      f"HostKeyAlgorithms {','.join(profile['host_keys'])}\n"
                      f"{profile['accept']}\n")
        server = subprocess.Popen([sshd, "-D", "-e", "-f", config],
                                  stdout=subprocess.DEVNULL, stderr=open(f"{d}/log", "w"))
        time.sleep(1)
        first_user = users[next(iter(users))]
        ed25519 = users.get("ed25519", first_user)
        rows = ([("kex", k, ed25519) for k in profile["kex"]]
                + [("cipher", c, ed25519) for c in profile["ciphers"]]
                + [("mac", m, ed25519) for m in profile["macs"]]
                + [("hostkey", h, ed25519) for h in profile["host_keys"]]
                + [("user", n, path) for n, path in users.items()])
        if name == "current":
            # Encrypt-and-MAC under CBC, where the receiver decrypts the
            # first block to find the length.
            rows += [("cbc+mac", f"{c} {m}", ed25519)
                     for c in ["aes128-cbc", "3des-cbc"] for m in ["hmac-sha1", "hmac-sha2-256"]]
        port = str(profile["port"])
        try:
            for option, value, key in rows:
                if option == "user":
                    extra = []
                elif option == "cbc+mac":
                    cipher, mac = value.split()
                    extra = [f"cipher={cipher}", f"mac={mac}"]
                else:
                    extra = [f"{option}={value}"]
                if option == "mac":
                    extra.append("cipher=aes128-ctr")
                if option == "user" and value == "dsa":
                    pass
                run = subprocess.run([client, "127.0.0.1", port, "root", key,
                                      "echo ran; exit 7"] + extra,
                                     capture_output=True, text=True, timeout=120)
                ok = run.returncode == 7 and run.stdout == "ran\n"
                failures += not ok
                summary = run.stderr.strip().splitlines()[-1] if run.stderr.strip() else ""
                print(f"  {'ok  ' if ok else 'FAIL'} {option:8} {value:38} "
                      f"{'' if ok else summary}")
            for seed, (session, user, options) in enumerate(
                    profile["recorded"] if record else [], start=first_seed):
                transcript = os.path.join(d, f"{session}.txt")
                command = f"echo {session}; printf 'stderr too\\n' >&2; exit {seed}"
                run = subprocess.run([client, "127.0.0.1", port, "root", users[user],
                                      command] + options
                                     + [f"seed={seed}", f"record={transcript}"],
                                     capture_output=True, text=True, timeout=120)
                ok = run.returncode == seed and run.stdout == f"{session}\n"
                failures += not ok
                host = [w for w in run.stderr.split() if w.startswith("hostkey-fp=")]
                print(f"  {'ok  ' if ok else 'FAIL'} recorded {session}")
                recorded.append(dict(
                    name=session, server=version, seed=seed, options=options,
                    command=command, host_key=host[0].split("=", 1)[1] if host else "",
                    key=base64.b64encode(open(users[user], "rb").read()).decode(),
                    stdout=run.stdout, transcript=open(transcript).read()))
        finally:
            server.send_signal(signal.SIGTERM)
            server.wait()
    print(f"  {len(rows) - failures} of {len(rows)} sessions completed.")
    return failures, recorded


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssh", default="/opt/openssh")
    parser.add_argument("--legacy-openssh", metavar="DIR",
                        help="an OpenSSH 7.x build, for the algorithms 10.0 removed")
    parser.add_argument("--record", metavar="FILE",
                        help="record the RECORDED sessions for offline replay")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "--quiet", "--example", "ssh_exec"],
                   cwd=ROOT, check=True)
    client = os.path.join(ROOT, "target", "debug", "examples", "ssh_exec")
    failures, recorded = run_profile("current", args.openssh, client, args.record, 1)
    if args.legacy_openssh:
        more, extra = run_profile("legacy", args.legacy_openssh, client, args.record,
                                  len(recorded) + 1)
        failures += more
        recorded += extra
    if args.record and not failures:
        write_record(args.record, recorded)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
