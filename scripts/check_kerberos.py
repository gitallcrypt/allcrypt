#!/usr/bin/env python3
"""The Kerberos example (`examples/products/kerberos`) against MIT
Kerberos 1.21.3 and 1.17.2, both directions.

  * **The cryptography**, through `scripts/witness/krb5witness` - a line
    protocol over libk5crypto: string-to-key for every type, at several
    iteration counts, over ASCII, UTF-8, long and short passwords and
    salts; every type encrypting at every length from 0 to 40 and some
    longer ones, under eleven key usages, with MIT decrypting ours and us
    decrypting MIT's; every type's mandatory checksum (byte for byte
    where it is deterministic, verified across where it is confounded),
    the other DES checksums MIT has, and the unkeyed ones; and the PRF
    at lengths 0 to 40. The DES checksums MIT lacks or builds otherwise
    are made from RFC 3961's formulas with OpenSSL's DES, MD4 and MD5. Single DES is gone from 1.21, so 1.17 witnesses
    those three types; everything else is witnessed by both.
  * **Keytabs**: MIT's `ktutil` writes keys from a password and ours
    lists the same keys; ours writes a keytab and MIT's `klist -k`
    lists it, and `kinit -k` authenticates with it.
  * **Tickets**, from a KDC on loopback, once per encryption type: the
    user's key comes from our keytab through `kinit -k`, a service
    ticket is fetched with `kvno`, the TGS and service keys are
    exported with `ktadd -norandkey`, and ours decrypts both tickets
    from MIT's credential cache - version 4 and version 3 - and checks
    their session keys against the cache's.

    python3 scripts/check_kerberos.py [--ours PATH]
    python3 scripts/check_kerberos.py --record

`--record` writes `examples/products/fixtures/kerberos.vec` (MIT's keys,
ciphertexts, checksums and PRF outputs) and keeps a keytab and a
credential cache from each KDC run in `fixtures/kerberos/`, for the
offline tests.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example kerberos`.
"""

import argparse
import hashlib
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "kerberos")
MIT = {"1.21": "/opt/krb5", "1.17": "/opt/krb5-117"}
WITNESS = {"1.21": "/opt/krb5witness/krb5witness-121", "1.17": "/opt/krb5witness/krb5witness-117"}

ENCTYPES = {1: "des-cbc-crc", 2: "des-cbc-md4", 3: "des-cbc-md5", 16: "des3-cbc-sha1",
            17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96",
            19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192",
            23: "arcfour-hmac", 24: "arcfour-hmac-exp", 25: "camellia128-cts-cmac",
            26: "camellia256-cts-cmac"}
KEY_LEN = {1: 8, 2: 8, 3: 8, 16: 24, 17: 16, 18: 32, 19: 16, 20: 32, 23: 16, 24: 16,
           25: 16, 26: 32}
SINGLE_DES = {1, 2, 3}
ITERATED = {17, 18, 19, 20, 25, 26}
USAGES = [1, 2, 3, 4, 7, 8, 9, 11, 12, 23, 1024]
WEAK_CONF = """[libdefaults]
    allow_weak_crypto = true
    allow_des3 = true
    allow_rc4 = true
"""

FAILURES = []
COUNTS = {}


def check(ok, what):
    COUNTS[what.split(":")[0]] = COUNTS.get(what.split(":")[0], 0) + 1
    if not ok:
        FAILURES.append(what)
        print("FAIL", what)


def versions_for(enctype):
    return ["1.17"] if enctype in SINGLE_DES else ["1.21", "1.17"]


def env_for(version, conf):
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = os.path.join(MIT[version], "lib")
    env["KRB5_CONFIG"] = conf
    return env


class Witness:
    """One libk5crypto process per version, spoken to a line at a time."""

    def __init__(self, version, conf):
        self.process = subprocess.Popen([WITNESS[version]], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, text=True,
                                        env=env_for(version, conf))

    def ask(self, *words):
        line = " ".join(w if isinstance(w, str) else (w.hex() or "-") if isinstance(w, bytes)
                        else str(w) for w in words)
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()
        answer = self.process.stdout.readline().strip()
        if answer.startswith("ERR"):
            raise RuntimeError(f"{line}: {answer}")
        return answer

    def close(self):
        self.process.stdin.close()
        self.process.wait()


def ours(*args, data=None, check_ok=True):
    result = subprocess.run([OURS, *map(str, args)], input=data, capture_output=True)
    if check_ok and result.returncode != 0:
        raise RuntimeError(f"ours {' '.join(map(str, args))}: {result.stderr.decode()}")
    return result


def unhex(text):
    return b"" if text == "-" else bytes.fromhex(text)


def padded_equal(enctype, got, plain):
    """Single DES and 3DES pad to a block with zeros and return them."""
    if enctype in SINGLE_DES or enctype == 16:
        return got[:len(plain)] == plain and set(got[len(plain):]) <= {0} \
            and len(got) - len(plain) < 8
    return got == plain


# ----------------------------------------------------------------- crypto --

PASSWORDS = ["password", "potatoe", "", "X" * 64, "X" * 65, "pässwörd", "\U0001d11e",
             "correct horse battery staple"]
SALTS = ["ATHENA.MIT.EDUraeburn", "EXAMPLE.COMuser", "", "EXAMPLE.COMJurišić",
         "pass phrase exceeds block size"]


def check_string_to_key(witnesses, record):
    for enctype, name in ENCTYPES.items():
        counts = [None] if enctype not in ITERATED else [None, 1, 2, 1200]
        for version in versions_for(enctype):
            w = witnesses[version]
            for password in PASSWORDS:
                for salt in SALTS:
                    for count in counts:
                        params = b"" if count is None else count.to_bytes(4, "big")
                        try:
                            theirs = w.ask("s2k", enctype, password.encode(), salt.encode(),
                                           params)
                        except RuntimeError as e:
                            # MIT refuses an empty password for some
                            # types; ours must then still produce a key.
                            check(password == "", f"s2k: {name} {version} {e}")
                            continue
                        args = ["string2key", "--enctype", name, "--principal", "x@Y",
                                "--salt", salt, "--password", password]
                        if count is not None:
                            args += ["--iterations", count]
                        mine = ours(*args).stdout.decode().strip()
                        check(mine == theirs, f"s2k: {name} {version} {password!r} "
                                              f"{salt!r} {count}: {mine} {theirs}")
                        empty_des = enctype in SINGLE_DES and password == salt == ""
                        if version == versions_for(enctype)[0] and (password in ("password",
                                "\U0001d11e") and salt and count in (None, 2) or empty_des):
                            record.setdefault("s2k", []).append(
                                [("name", f"{name} {password!r} {salt!r} {count}"),
                                 ("enctype", name), ("password", password.encode().hex() or "-"),
                                 ("salt", salt.encode().hex() or "-"),
                                 ("params", params.hex() or "-"), ("key", theirs)])


def random_key(choose, enctype):
    return bytes(choose.randrange(256) for _ in range(KEY_LEN[enctype]))


def check_encryption(witnesses, record, choose):
    lengths = list(range(41)) + [63, 64, 65, 100, 1000, 4096]
    for enctype, name in ENCTYPES.items():
        for version in versions_for(enctype):
            w = witnesses[version]
            key = random_key(choose, enctype)
            if enctype in SINGLE_DES or enctype == 16:
                key = bytes.fromhex(w.ask("s2k", enctype, b"pw" + bytes([choose.randrange(97, 122)]),
                                          b"SALT", b""))
            for length in lengths:
                for usage in USAGES if length < 41 else [2, 1024]:
                    plain = bytes(choose.randrange(256) for _ in range(length))
                    # MIT encrypts, ours decrypts.
                    cipher = unhex(w.ask("encrypt", enctype, key, usage, plain))
                    got = ours("decrypt", "-", "-", "--enctype", name, "--key", key.hex(),
                               "--usage", usage, data=cipher).stdout
                    check(padded_equal(enctype, got, plain),
                          f"decrypt: {name} {version} {length} {usage}")
                    if version == versions_for(enctype)[0] and usage in (2, 1024) \
                            and length in (0, 1, 16, 17, 33):
                        record.setdefault("decrypt", []).append(
                            [("name", f"{name} {length} {usage}"), ("enctype", name),
                             ("key", key.hex()), ("usage", str(usage)),
                             ("plain", plain.hex() or "-"), ("cipher", cipher.hex())])
                    # Ours encrypts, MIT decrypts.
                    mine = ours("encrypt", "-", "-", "--enctype", name, "--key", key.hex(),
                                "--usage", usage, data=plain).stdout
                    check(len(mine) == len(cipher), f"length: {name} {length}")
                    theirs = unhex(w.ask("decrypt", enctype, key, usage, mine))
                    check(padded_equal(enctype, theirs, plain),
                          f"encrypt: {name} {version} {length} {usage}")
                    # And a wrong usage is refused by ours (single DES has
                    # no usages).
                    if enctype not in SINGLE_DES and length == 5:
                        wrong = 1025 if usage != 1025 else 1026
                        r = ours("decrypt", "-", "-", "--enctype", name, "--key", key.hex(),
                                 "--usage", wrong, data=cipher, check_ok=False)
                        check(r.returncode != 0, f"wrong usage: {name} {usage}")


def check_checksums(witnesses, record, choose):
    for enctype, name in ENCTYPES.items():
        for version in versions_for(enctype):
            w = witnesses[version]
            key = random_key(choose, enctype)
            if enctype in SINGLE_DES or enctype == 16:
                key = bytes.fromhex(w.ask("s2k", enctype, b"pw", b"SALT", b""))
            # The DES keys can also make the other DES checksums MIT has.
            kinds = [None] + ([3, 8] if enctype in SINGLE_DES else [])
            for kind in kinds:
                for length in list(range(0, 41, 3)) + [64, 1000]:
                    usage = choose.choice(USAGES)
                    data = bytes(choose.randrange(256) for _ in range(length))
                    if kind is None:
                        mtype, theirs = w.ask("checksum", enctype, key, usage, data).split()
                    else:
                        mtype, theirs = str(kind), w.ask("mkcksum", kind, enctype, key, usage,
                                                         data)
                    args = ["checksum", "-", "--enctype", name, "--key", key.hex(), "--usage",
                            usage] + (["--cksumtype", kind] if kind else [])
                    out = ours(*args, data=data).stdout.decode().split()
                    check(out[0] == mtype, f"cksumtype: {name} {out[0]} {mtype}")
                    if int(mtype) in (3, 8):
                        # Confounded: each verifies the other's.
                        good = ours(*args, "--verify", theirs, data=data, check_ok=False)
                        check(good.returncode == 0, f"verify theirs: {name} {mtype} {length}")
                        verdict = w.ask("verify", mtype, enctype, key, usage, data,
                                        unhex(out[1]))
                        check(verdict == "good", f"verify ours: {name} {mtype} {length}")
                        bad = bytearray(unhex(theirs))
                        bad[choose.randrange(len(bad))] ^= 1 << choose.randrange(8)
                        r = ours(*args, "--verify", bytes(bad).hex(), data=data, check_ok=False)
                        check(r.returncode != 0, f"verify altered: {name} {mtype}")
                    else:
                        check(out[1] == theirs, f"checksum: {name} {version} {length}")
                        verdict = w.ask("verify", mtype, enctype, key, usage, data,
                                        unhex(out[1]))
                        check(verdict == "good", f"verify ours: {name} {mtype}")
                    if version == versions_for(enctype)[0] and length in (0, 9):
                        record.setdefault("checksum", []).append(
                            [("name", f"{name} {mtype} {length}"), ("enctype", name),
                             ("cksumtype", mtype), ("mandatory", "no" if kind else "yes"),
                             ("key", key.hex()), ("usage", str(usage)),
                             ("data", data.hex() or "-"), ("checksum", theirs)])
    # The unkeyed ones, against 1.17 (1.21 kept them too).
    for kind, hashname in [(1, None), (2, "md4"), (7, "md5")]:
        for length in range(0, 70, 7):
            data = bytes(choose.randrange(256) for _ in range(length))
            theirs = witnesses["1.17"].ask("mkcksum", kind, 1, bytes(8), 0, data)
            out = ours("checksum", "-", "--cksumtype", kind, data=data).stdout.decode().split()
            check(out[1] == theirs, f"unkeyed: {kind} {length}")
            if hashname == "md5":
                check(theirs == hashlib.md5(data).hexdigest(), f"unkeyed md5: {length}")


def check_prf(witnesses, record, choose):
    for enctype, name in ENCTYPES.items():
        for version in versions_for(enctype):
            w = witnesses[version]
            key = random_key(choose, enctype)
            if enctype in SINGLE_DES or enctype == 16:
                key = bytes.fromhex(w.ask("s2k", enctype, b"pw", b"SALT", b""))
            for length in range(41):
                data = bytes(choose.randrange(256) for _ in range(length))
                theirs = w.ask("prf", enctype, key, data)
                mine = ours("prf", data.hex(), "--enctype", name, "--key",
                            key.hex()).stdout.decode().strip()
                check(mine == theirs, f"prf: {name} {version} {length}")
                if version == versions_for(enctype)[0] and length in (0, 4):
                    record.setdefault("prf", []).append(
                        [("name", f"{name} {length}"), ("enctype", name), ("key", key.hex()),
                         ("input", data.hex() or "-"), ("output", theirs)])


def openssl_des_cbc(key, iv, data):
    out = subprocess.run(["openssl", "enc", "-provider", "legacy", "-provider", "default",
                          "-des-cbc", "-K", key.hex(), "-iv", iv.hex(), "-nopad"],
                         input=data, capture_output=True, check=True).stdout
    assert len(out) == len(data)
    return out


def openssl_md4(data):
    return subprocess.run(["openssl", "dgst", "-provider", "legacy", "-provider", "default",
                           "-md4", "-binary"], input=data, capture_output=True,
                          check=True).stdout


def check_des_checksums(record, choose):
    """The DES checksums MIT does not have, or has under another
    construction - DES-MAC (4), DES-MAC-K (5), RSA-MD4-DES-K (6) - and
    the two it has (3, 8), built from RFC 3961 6.2.4 to 6.2.8's formulas
    with OpenSSL's DES and digests and given to ours to verify."""
    for _ in range(40):
        key = bytes(choose.randrange(256) | 1 for _ in range(8))
        variant = bytes(b ^ 0xf0 for b in key)
        data = bytes(choose.randrange(256) for _ in range(choose.randrange(0, 50)))
        conf = bytes(choose.randrange(256) for _ in range(8))
        pad = lambda m: m + bytes(-len(m) % 8 if m else 8)
        sums = {
            3: openssl_des_cbc(variant, bytes(8), conf + openssl_md4(conf + data)),
            8: openssl_des_cbc(variant, bytes(8), conf + hashlib.md5(conf + data).digest()),
            4: openssl_des_cbc(variant, bytes(8),
                               conf + openssl_des_cbc(key, bytes(8), pad(conf + data))[-8:]),
            5: openssl_des_cbc(key, key, pad(data))[-8:],
            6: openssl_des_cbc(key, key, openssl_md4(data)),
        }
        for kind, value in sums.items():
            r = ours("checksum", "-", "--cksumtype", kind, "--key", key.hex(), "--usage", 0,
                     "--verify", value.hex(), data=data, check_ok=False)
            check(r.returncode == 0, f"des checksum: {kind} {len(data)} {r.stderr}")
            if kind in (5, 6):
                made = ours("checksum", "-", "--cksumtype", kind, "--key", key.hex(),
                            "--usage", 0, data=data).stdout.decode().split()[1]
                check(made == value.hex(), f"des checksum made: {kind} {len(data)}")
            if len(record.get("des-checksum", [])) < 15:
                record.setdefault("des-checksum", []).append(
                    [("name", f"{kind} {len(data)}"), ("cksumtype", str(kind)),
                     ("key", key.hex()), ("data", data.hex() or "-"),
                     ("checksum", value.hex())])


# ---------------------------------------------------------------- keytabs --

def ktutil(version, conf, commands):
    env = env_for(version, conf)
    subprocess.run([os.path.join(MIT[version], "bin", "ktutil")], input="\n".join(commands)
                   + "\nq\n", text=True, env=env, capture_output=True, check=True)


def klist_keys(version, conf, path):
    out = subprocess.run([os.path.join(MIT[version], "bin", "klist"), "-k", "-K", "-e", path],
                         env=env_for(version, conf), capture_output=True, text=True,
                         check=True).stdout
    keys = []
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit() and "(0x" in line:
            enctype = line.split("(")[1].split(")")[0].replace("DEPRECATED:", "")
            keys.append((int(parts[0]), parts[1], enctype, line.split("(0x")[1].rstrip(")")))
    return keys


def ours_keytab(path):
    out = ours("keytab", "list", path, "--keys").stdout.decode()
    return [(int(p[0]), p[3], p[4], p[5]) for p in (line.split() for line in out.splitlines())]


def check_keytabs(tmp, conf, record):
    for version in ["1.21", "1.17"]:
        types = [e for e in ENCTYPES if version in versions_for(e)]
        path = os.path.join(tmp, f"mit-{version}.kt")
        commands = []
        for i, e in enumerate(types):
            commands += [f"addent -password -p host/a\\/b.example.com@EXAMPLE.COM -k {i + 2} "
                         f"-e {ENCTYPES[e]}", "pässwörd"]
        commands.append(f"wkt {path}")
        ktutil(version, conf, commands)
        theirs = klist_keys(version, conf, path)
        mine = ours_keytab(path)
        check(len(theirs) == len(types), f"ktutil: {version} wrote {len(theirs)}")
        check([(k, p, key) for k, p, _, key in mine] == [(k, p, key) for k, p, _, key in theirs],
              f"keytab read: {version}")
        # And each key is the password's: our string-to-key agrees.
        for (kvno, principal, name, key) in mine:
            derived = ours("string2key", "--enctype", name, "--principal", principal,
                           "--password", "pässwörd").stdout.decode().strip()
            check(derived == key, f"keytab key: {version} {name}")
        if record is not None:
            shutil.copy(path, os.path.join(FIXTURES, "kerberos", f"ktutil-{version}.keytab"))
        # Ours writes, MIT lists.
        path = os.path.join(tmp, f"ours-{version}.kt")
        for e in types:
            ours("keytab", "add", path, "--principal", "HTTP/www.example.com@EXAMPLE.COM",
                 "--kvno", 300, "--enctype", ENCTYPES[e], "--password", "pässwörd")
        theirs = klist_keys(version, conf, path)
        mine = ours_keytab(path)
        check([(k, key) for k, _, _, key in theirs] == [(k, key) for k, _, _, key in mine]
              and len(theirs) == len(types), f"keytab written: {version}")


# --------------------------------------------------------------------- KDC --

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_kdc(tmp, version, enctype, ccache_version, record):
    """A realm whose every key is of one type; tickets fetched through
    our keytab; ours opens them."""
    name = ENCTYPES[enctype]
    d = tempfile.mkdtemp(dir=tmp)
    port = free_port()
    # MIT's KDC issues no des-cbc-md5 session key; the tickets are still
    # encrypted in the des-cbc-md5 service keys.
    session = name if enctype != 3 else f"{name} des-cbc-crc"
    conf = os.path.join(d, "krb5.conf")
    with open(conf, "w") as f:
        f.write(f"""[libdefaults]
    default_realm = EXAMPLE.COM
    allow_weak_crypto = true
    allow_des3 = true
    allow_rc4 = true
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    ccache_type = {ccache_version}
    permitted_enctypes = {session}
    default_tkt_enctypes = {session}
    default_tgs_enctypes = {session}
[realms]
    EXAMPLE.COM = {{
        kdc = 127.0.0.1:{port}
    }}
""")
    kdc_conf = os.path.join(d, "kdc.conf")
    with open(kdc_conf, "w") as f:
        f.write(f"""[kdcdefaults]
    kdc_listen = 127.0.0.1:{port}
    kdc_tcp_listen = 127.0.0.1:{port}
    kdc_ports = {port}
    kdc_tcp_ports = {port}
[realms]
    EXAMPLE.COM = {{
        database_name = {d}/principal
        key_stash_file = {d}/stash
        acl_file = {d}/kadm5.acl
        master_key_type = {"des3-cbc-sha1" if enctype in SINGLE_DES else "aes256-cts"}
        supported_enctypes = {name}:normal
    }}
[logging]
    kdc = FILE:{d}/kdc.log
""")
    env = env_for(version, conf)
    env["KRB5_KDC_PROFILE"] = kdc_conf
    env["KRB5CCNAME"] = f"FILE:{d}/cc"
    bin_ = lambda tool: os.path.join(MIT[version], "sbin" if tool in ("kdb5_util", "kadmin.local", "krb5kdc") else "bin", tool)
    run = lambda *a, **k: subprocess.run(list(a), env=env, capture_output=True, text=True,
                                         check=True, **k)
    run(bin_("kdb5_util"), "-r", "EXAMPLE.COM", "create", "-s", "-P", "master password")
    run(bin_("kadmin.local"), "-q", f"cpw -randkey -e {name}:normal krbtgt/EXAMPLE.COM")
    run(bin_("kadmin.local"), "-q", f"addprinc -pw pässwörd -e {name}:normal user")
    run(bin_("kadmin.local"), "-q", f"addprinc -randkey -e {name}:normal HTTP/www.example.com")
    kdc = subprocess.Popen([bin_("krb5kdc"), "-n"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        # The user's key: ours derives it into a keytab, kinit uses it.
        user_kt = os.path.join(d, "user.keytab")
        ours("keytab", "add", user_kt, "--principal", "user@EXAMPLE.COM", "--kvno", 1,
             "--enctype", name, "--password", "pässwörd")
        run(bin_("kinit"), "-k", "-t", user_kt, "user@EXAMPLE.COM")
        run(bin_("kvno"), "HTTP/www.example.com@EXAMPLE.COM")
        service_kt = os.path.join(d, "services.keytab")
        run(bin_("kadmin.local"), "-q",
            f"ktadd -norandkey -k {service_kt} krbtgt/EXAMPLE.COM HTTP/www.example.com")
        with open(f"{d}/cc", "rb") as f:
            cc = f.read()
        check(cc[1] == ccache_version, f"ccache version: {cc[1]}")
        listed = ours("ccache", "list", f"{d}/cc").stdout.decode()
        check("default principal: user@EXAMPLE.COM" in listed
              and "HTTP/www.example.com@EXAMPLE.COM" in listed
              and "krbtgt/EXAMPLE.COM@EXAMPLE.COM" in listed, f"ccache list: {name}")
        opened = ours("ticket", f"{d}/cc", "--keytab", service_kt, check_ok=False)
        out = opened.stdout.decode()
        check(opened.returncode == 0 and out.count("as in the cache") == 2
              and out.count(f", {name})\n") == 2 and "client: user@EXAMPLE.COM" in out,
              f"ticket: {name} v{ccache_version} {opened.stderr.decode()}")
        # The wrong keys are refused: the user's keytab holds no service key.
        wrong = ours("ticket", f"{d}/cc", "--keytab", user_kt, check_ok=False)
        check(wrong.returncode != 0, f"ticket wrong keytab: {name}")
        if record is not None:
            base = os.path.join(FIXTURES, "kerberos", f"{name}-v{ccache_version}")
            shutil.copy(f"{d}/cc", base + ".ccache")
            shutil.copy(service_kt, base + ".keytab")
    finally:
        kdc.terminate()
        kdc.wait()


def write_record(record):
    lines = ["# MIT Kerberos's answers, and DES checksums built with OpenSSL, kept by",
             "# scripts/check_kerberos.py --record for the offline tests in",
             "# examples/products/kerberos. Hex throughout; - is empty.", ""]
    for section in ["s2k", "decrypt", "checksum", "prf", "des-checksum"]:
        lines.append(f"[{section}]")
        for rec in record[section]:
            lines += [f"{k} = {v}" for k, v in rec]
        lines.append("")
    with open(os.path.join(FIXTURES, "kerberos.vec"), "w") as f:
        f.write("\n".join(lines))


def main():
    global OURS
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--seed", type=int, default=3961)
    args = parser.parse_args()
    OURS = args.ours
    choose = random.Random(args.seed)
    record = {}
    tmp = tempfile.mkdtemp(prefix="check_kerberos.")
    conf = os.path.join(tmp, "krb5.conf")
    with open(conf, "w") as f:
        f.write(WEAK_CONF)
    if args.record:
        os.makedirs(os.path.join(FIXTURES, "kerberos"), exist_ok=True)
    witnesses = {v: Witness(v, conf) for v in WITNESS}
    try:
        check_string_to_key(witnesses, record)
        check_encryption(witnesses, record, choose)
        check_checksums(witnesses, record, choose)
        check_prf(witnesses, record, choose)
        check_des_checksums(record, choose)
        check_keytabs(tmp, conf, record if args.record else None)
        for enctype in ENCTYPES:
            if enctype == 2:
                continue  # MIT's KDC has no des-cbc-md4 keys
            version = "1.17" if enctype in SINGLE_DES else "1.21"
            for ccache_version in (4, 3):
                keep = args.record and (ccache_version == 4 and enctype in (18, 20, 23, 26)
                                        or ccache_version == 3 and enctype in (3, 16))
                run_kdc(tmp, version, enctype, ccache_version, record if keep else None)
    finally:
        for w in witnesses.values():
            w.close()
        shutil.rmtree(tmp, ignore_errors=True)
    if args.record:
        write_record(record)
    total = sum(COUNTS.values())
    print(", ".join(f"{k} {v}" for k, v in COUNTS.items()))
    print(f"{total - len(FAILURES)} of {total} passed")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
