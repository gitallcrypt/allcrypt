#!/usr/bin/env python3
"""The OpenPGP example (`examples/products/openpgp`) against GnuPG and
go-crypto.

Both directions with each:

  * **GnuPG 2.4** (`gpg`): it encrypts with a passphrase under every
    cipher it has, every compression, every S2K mode and hash, into the
    three containers it writes - SEIPD v1 (`--rfc4880`), the LibrePGP
    OCB packet (`--force-ocb`, with small chunks so that there are many)
    and the unprotected Symmetrically Encrypted Data packet
    (`--rfc2440`) - binary and armored, from a file and from a pipe (a
    pipe makes it write partial body lengths); ours decrypts, and also
    opens each message with the session key `gpg --show-session-key`
    printed. Ours encrypts in its `v4`, `no-mdc` and `librepgp` formats
    under every cipher; gpg decrypts.
  * **go-crypto** (ProtonMail's, built from source - see
    docs/building.md), which has what GnuPG 2.4 does not: RFC 9580's
    SKESK v6 and SEIPD v2 under OCB, EAX and GCM, and Argon2. It
    encrypts, ours decrypts, and the other way.

Then keys, both ways with each: GnuPG's RSA, DSA with ElGamal, ECDSA
and ECDH on the NIST, Brainpool and secp256k1 curves, Ed25519 with
Curve25519, and its version 5 Ed448 with X448 - fingerprints compared
with GnuPG's, GnuPG encrypting to each and ours decrypting with the
exported secret key, ours encrypting to each and GnuPG decrypting; and
go-crypto's version 4 and 6 keys (RSA, X25519, X448, the NIST and
Brainpool curves) the same way, its v6 PKESK and SEIPD v2 included.

And keys made by ours (`gen-key`): imported by GnuPG and read by
go-crypto, encrypted to and used to sign, both ways.

And signatures, with every one of those keys: GnuPG's and go-crypto's
inline, detached, text-mode and cleartext signatures checked by ours,
ours checked by them, and signed-and-encrypted messages both ways.

    python3 scripts/check_openpgp.py [--gpg gpg] [--go-witness PATH]
    python3 scripts/check_openpgp.py --record

`--record` writes a set of GnuPG-made messages (with a small S2K count,
so that the offline tests stay fast) into
`examples/products/fixtures/openpgp/` for the example's tests.

**A development tool, not a test.** The gate runs none of it.
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
PASSPHRASE = "correct horse battery staple"
GO_WITNESS = "/opt/pgpwitness/pgpwitness"

GPG_CIPHERS = ["IDEA", "3DES", "CAST5", "BLOWFISH", "AES", "AES192", "AES256", "TWOFISH",
               "CAMELLIA128", "CAMELLIA192", "CAMELLIA256"]
OUR_CIPHERS = ["idea", "tripledes", "cast5", "blowfish", "aes128", "aes192", "aes256",
               "twofish", "camellia128", "camellia192", "camellia256"]
SIZES = [0, 1, 15, 16, 17, 1000, 70_000]
# Text for the text-mode and cleartext signatures: trailing spaces, a
# line starting with a dash, and no final newline on purpose.
SIGN_TEXT = b"What a signature covers:  \n\n- the text\n-- and dashes\nlast line"


def plaintext(size, seed=0):
    return bytes((i * 31 + i // 251 + seed) & 0xFF for i in range(size))


class Rig:
    def __init__(self, gpg, ours, go, d):
        self.gpg_binary, self.ours_binary, self.go, self.d = gpg, ours, go, d
        self.home = os.path.join(d, "gnupg")
        os.mkdir(self.home, 0o700)
        # The agent protects exported secret keys with its own S2K count,
        # by default the largest; a small one keeps the recorded keys
        # quick to unlock in the offline tests.
        with open(os.path.join(self.home, "gpg-agent.conf"), "w") as out:
            out.write("s2k-count 65536\n")
        self.n = 0

    def path(self, name):
        self.n += 1
        return os.path.join(self.d, f"{self.n}-{name}")

    def gpg(self, *args, stdin=None, passphrase=PASSPHRASE, check=True):
        run = subprocess.run([self.gpg_binary, "--homedir", self.home, "--batch", "--yes",
                              "--pinentry-mode", "loopback", "--passphrase", passphrase,
                              "--allow-old-cipher-algos", *args],
                             input=stdin, capture_output=True, timeout=600)
        if check and run.returncode != 0:
            raise RuntimeError(f"gpg: {run.stderr.decode()[-300:]}")
        return run

    def ours(self, *args, check=True):
        run = subprocess.run([self.ours_binary, *args], capture_output=True, timeout=600)
        if check and run.returncode != 0:
            raise RuntimeError(f"ours: {run.stderr.decode()[-300:]}")
        return run

    def write(self, name, data):
        path = self.path(name)
        with open(path, "wb") as out:
            out.write(data)
        return path

    def read(self, path):
        return open(path, "rb").read() if os.path.exists(path) else None


def gpg_encrypts(rig, report, records):
    cases = []
    for cipher in GPG_CIPHERS:
        cases.append((f"{cipher}", ["--rfc4880", "--cipher-algo", cipher], 1000, False))
    for compress in ["none", "zip", "zlib", "bzip2"]:
        cases.append((f"compress {compress}", ["--rfc4880", "--compress-algo", compress],
                      70_000, False))
    for mode, digest in [("0", "SHA1"), ("1", "SHA256"), ("3", "MD5"), ("3", "SHA1"),
                         ("3", "RIPEMD160"), ("3", "SHA224"), ("3", "SHA384"),
                         ("3", "SHA512")]:
        cases.append((f"S2K mode {mode} {digest}", ["--rfc4880", "--s2k-mode", mode,
                                                    "--s2k-digest-algo", digest], 100, False))
    for cipher in ["AES", "AES256", "TWOFISH", "CAMELLIA192"]:
        cases.append((f"OCB packet {cipher}", ["--force-ocb", "--chunk-size", "6",
                                               "--cipher-algo", cipher], 1000, False))
    for cipher in ["CAST5", "IDEA", "AES"]:
        cases.append((f"no MDC {cipher}", ["--rfc2440", "--cipher-algo", cipher], 1000, False))
    for size in SIZES:
        cases.append((f"{size} bytes from a pipe", ["--rfc4880"], size, True))
        cases.append((f"{size} bytes OCB from a pipe", ["--force-ocb", "--chunk-size", "8"],
                      size, True))
    cases.append(("armored", ["--rfc4880", "--armor"], 1000, False))
    cases.append(("armored OCB", ["--force-ocb", "--armor"], 1000, False))

    for label, args, size, piped in cases:
        data = plaintext(size, len(label))
        source = rig.write("plain", data)
        encrypted = rig.path("gpg")
        try:
            # gpg reads a count of 1024 or less as "calibrate" and then
            # uses the agent's, which is the maximum; 2048 is honoured.
            fast = ["--s2k-count", "2048"]
            if piped:
                rig.gpg("-c", *fast, *args, "-o", encrypted, stdin=data)
            else:
                rig.gpg("-c", *fast, *args, "-o", encrypted, source)
            out = rig.path("out")
            run = rig.ours("decrypt", encrypted, out, "--passphrase", PASSPHRASE, check=False)
            ok = run.returncode == 0 and rig.read(out) == data
            shown = rig.gpg(*(["--ignore-mdc-error"] if "--rfc2440" in args else []),
                            "--show-session-key", "-d", "-o", rig.path("gpgout"), encrypted)
            key = [l.split("'")[1] for l in shown.stderr.decode().splitlines()
                   if "session key:" in l][0]
            out2 = rig.path("out")
            by_key = rig.ours("decrypt", encrypted, out2, "--session-key", key, check=False)
            ok = ok and by_key.returncode == 0 and rig.read(out2) == data
            wrong = rig.ours("decrypt", encrypted, rig.path("out"), "--passphrase", "wrong",
                             check=False)
            ok = ok and wrong.returncode != 0
            report(ok, f"gpg encrypts, ours decrypts: {label}",
                   (run.stderr + by_key.stderr).decode()[-200:])
            if ok:
                records.append((label, encrypted, data, key))
        except (RuntimeError, IndexError) as error:
            report(False, f"gpg encrypts, ours decrypts: {label}", str(error))


def ours_encrypts_for_gpg(rig, report):
    cases = []
    for cipher in OUR_CIPHERS:
        cases.append((f"v4 {cipher}", ["--format", "v4", "--cipher", cipher], 1000))
        cases.append((f"no-mdc {cipher}", ["--format", "no-mdc", "--cipher", cipher], 1000))
    for cipher in ["aes128", "aes192", "aes256", "twofish", "camellia128", "camellia256"]:
        for aead in ["ocb", "eax"]:
            cases.append((f"librepgp {aead} {cipher}",
                          ["--format", "librepgp", "--aead", aead, "--cipher", cipher,
                           "--chunk-size", "4"], 5000))
    for compress in ["zip", "zlib"]:
        for fmt in ["v4", "librepgp"]:
            cases.append((f"{fmt} {compress}", ["--format", fmt, "--compress", compress],
                          70_000))
    for size in SIZES:
        cases.append((f"v4 {size} bytes", ["--format", "v4"], size))
        cases.append((f"librepgp {size} bytes", ["--format", "librepgp", "--chunk-size", "0"],
                      size))
    cases.append(("v4 encrypted session key", ["--format", "v4", "--esk"], 1000))
    cases.append(("v4 armored", ["--format", "v4", "--armor"], 1000))
    cases.append(("librepgp armored", ["--format", "librepgp", "--armor"], 1000))
    for hash_name in ["md5", "sha1", "ripemd160", "sha224", "sha384", "sha512"]:
        cases.append((f"v4 S2K {hash_name}", ["--format", "v4", "--s2k-hash", hash_name], 100))

    for label, args, size in cases:
        data = plaintext(size, len(label))
        source = rig.write("plain", data)
        encrypted = rig.path("ours")
        try:
            rig.ours("encrypt", source, encrypted, "--passphrase", PASSPHRASE, *args)
            out = rig.path("out")
            # gpg refuses unprotected data unless told otherwise.
            extra = ["--ignore-mdc-error"] if "no-mdc" in label else []
            run = rig.gpg(*extra, "-d", "-o", out, encrypted, check=False)
            report(rig.read(out) == data, f"ours encrypts, gpg decrypts: {label}",
                   run.stderr.decode()[-200:])
        except RuntimeError as error:
            report(False, f"ours encrypts, gpg decrypts: {label}", str(error))


def go_both_ways(rig, report):
    if not os.path.exists(rig.go):
        print(f"  (no go-crypto witness at {rig.go}; skipping its rows)")
        return
    cases = []
    for aead in ["ocb", "eax", "gcm"]:
        for cipher in ["aes128", "aes192", "aes256"]:
            cases.append((f"v6 {aead} {cipher}", ["-aead", aead, "-cipher", cipher],
                          ["--format", "rfc9580", "--aead", aead, "--cipher", cipher], 70_000))
    cases.append(("v6 Argon2", ["-aead", "ocb", "-argon2"],
                  ["--format", "rfc9580", "--s2k", "argon2"], 1000))
    cases.append(("v4 Argon2", ["-aead", "none", "-argon2"],
                  ["--format", "v4", "--s2k", "argon2"], 1000))
    cases.append(("v6 zlib", ["-aead", "ocb", "-compress", "zlib"],
                  ["--format", "rfc9580", "--compress", "zlib"], 70_000))
    cases.append(("v4", ["-aead", "none"], ["--format", "v4"], 1000))
    for size in SIZES:
        cases.append((f"v6 {size} bytes", ["-aead", "ocb"],
                      ["--format", "rfc9580", "--chunk-size", "0"], size))
    for label, theirs, ours, size in cases:
        data = plaintext(size, len(label))
        source = rig.write("plain", data)
        try:
            encrypted = rig.path("go")
            run = subprocess.run([rig.go, "sym-encrypt", "-pass", PASSPHRASE, *theirs, source,
                                  encrypted], capture_output=True, timeout=600)
            if run.returncode != 0:
                raise RuntimeError(run.stderr.decode())
            out = rig.path("out")
            mine = rig.ours("decrypt", encrypted, out, "--passphrase", PASSPHRASE, check=False)
            report(rig.read(out) == data, f"go-crypto encrypts, ours decrypts: {label}",
                   mine.stderr.decode()[-200:])
            encrypted = rig.path("ours")
            rig.ours("encrypt", source, encrypted, "--passphrase", PASSPHRASE, *ours)
            out = rig.path("out")
            run = subprocess.run([rig.go, "decrypt", "-pass", PASSPHRASE, encrypted, out],
                                 capture_output=True, timeout=600)
            report(rig.read(out) == data, f"ours encrypts, go-crypto decrypts: {label}",
                   run.stderr.decode()[-200:])
        except RuntimeError as error:
            report(False, f"go-crypto: {label}", str(error)[-300:])


GPG_KEYS = [("rsa1024", "rsa1024"), ("rsa2048", "rsa2048"), ("rsa3072", "rsa3072"),
            ("dsa1024", "elg1024"), ("dsa2048", "elg2048"), ("nistp256", "nistp256"),
            ("nistp384", "nistp384"), ("nistp521", "nistp521"),
            ("brainpoolP256r1", "brainpoolP256r1"), ("brainpoolP384r1", "brainpoolP384r1"),
            ("brainpoolP512r1", "brainpoolP512r1"), ("secp256k1", "secp256k1"),
            ("ed25519", "cv25519"), ("ed448", "cv448")]


def gpg_keys(rig, report, key_records):
    data = plaintext(5000, 3)
    source = rig.write("plain", data)
    for primary, sub in GPG_KEYS:
        label = f"{primary}/{sub}"
        email = f"{primary}@example.org"
        try:
            rig.gpg("--quick-gen-key", f"{primary} <{email}>", primary, "default", "never")
            listing = rig.gpg("--with-colons", "--list-keys", email).stdout.decode()
            primary_fpr = [l.split(":")[9] for l in listing.splitlines()
                           if l.startswith("fpr")][0]
            rig.gpg("--quick-add-key", primary_fpr, sub, "encr", "never")
            listing = rig.gpg("--with-colons", "--list-keys", email).stdout.decode()
            theirs = [l.split(":")[9] for l in listing.splitlines() if l.startswith("fpr")]
            secret = rig.path("sec.asc")
            public = rig.path("pub.asc")
            with open(secret, "wb") as out:
                out.write(rig.gpg("--armor", "--export-secret-keys", email).stdout)
            with open(public, "wb") as out:
                out.write(rig.gpg("--armor", "--export", email).stdout)
            listed = rig.ours("list-keys", secret).stdout.decode()
            ours = [line.split("fingerprint ")[1].split()[0] for line in listed.splitlines()
                    if "fingerprint" in line]
            report(ours == theirs, f"gpg's {label} key: our fingerprints are gpg's",
                   f"ours {ours} gpg {theirs}")
            for mode in [[], ["--rfc4880"]]:
                encrypted = rig.path("gpg")
                rig.gpg(*mode, "--trust-model", "always", "-e", "-r", email, "-o", encrypted,
                        source)
                out = rig.path("out")
                run = rig.ours("decrypt", encrypted, out, "--secret-key", secret,
                               "--passphrase", PASSPHRASE, check=False)
                report(rig.read(out) == data,
                       f"gpg encrypts to {label}{' (rfc4880)' if mode else ''}, ours decrypts",
                       run.stderr.decode()[-200:])
                if not mode:
                    key_records.append((label, secret, encrypted, data, theirs))
            for fmt in ["v4", "librepgp"]:
                encrypted = rig.path("ours")
                rig.ours("encrypt", source, encrypted, "--recipient", public, "--format", fmt)
                out = rig.path("out")
                run = rig.gpg("-d", "-o", out, encrypted, check=False)
                report(rig.read(out) == data, f"ours encrypts ({fmt}) to {label}, gpg decrypts",
                       run.stderr.decode()[-200:])
            gpg_signatures(rig, report, label, email, secret, public, source, data, key_records)
        except (RuntimeError, IndexError) as error:
            report(False, f"gpg's {label} key", str(error)[-300:])


def gpg_signatures(rig, report, label, email, secret, public, source, data, key_records):
    text = rig.write("text", SIGN_TEXT)
    signed = {}
    for mode, args, signed_file in [("inline", ["-s"], source), ("detached", ["--detach-sign"], source),
                                    ("text-mode", ["-s", "--textmode"], text),
                                    ("cleartext", ["--clearsign"], text)]:
        out = rig.path("gpgsig")
        rig.gpg(*args, "-u", email, "-o", out, signed_file)
        signed[mode] = out
        check = (["verify", signed_file, "--signature", out] if mode == "detached"
                 else ["verify", out])
        run = rig.ours(*check, "--key", public, check=False)
        report(run.returncode == 0 and b"good" in run.stdout,
               f"gpg signs ({mode}) with {label}, ours verifies", run.stdout.decode()[-200:])
        # Altered, it must fail.
        if mode == "cleartext":
            altered = rig.write("altered", open(out, "rb").read().replace(b"the text", b"the test"))
            bad = rig.ours("verify", altered, "--key", public, check=False)
            report(bad.returncode != 0, f"an altered cleartext from {label} is refused")
    for mode, args, signed_file in [("inline", [], source), ("detached", ["--detached"], source),
                                    ("text", ["--text"], text),
                                    ("cleartext", ["--clearsign"], text)]:
        out = rig.path("oursig")
        rig.ours("sign", signed_file, out, "--secret-key", secret, "--passphrase", PASSPHRASE,
                 *args)
        run = rig.gpg("--verify", out, *([signed_file] if mode == "detached" else []),
                      check=False)
        report(run.returncode == 0 and b"Good signature" in run.stderr,
               f"ours signs ({mode}) with {label}, gpg verifies", run.stderr.decode()[-200:])
    both = rig.path("gpgse")
    rig.gpg("--trust-model", "always", "-se", "-u", email, "-r", email, "-o", both, source)
    out = rig.path("out")
    run = rig.ours("decrypt", both, out, "--secret-key", secret, "--passphrase", PASSPHRASE,
                   check=False)
    report(run.returncode == 0 and rig.read(out) == data and b"good" in run.stdout,
           f"gpg signs and encrypts with {label}, ours decrypts and verifies",
           run.stdout.decode()[-200:])
    both = rig.path("ourse")
    rig.ours("encrypt", source, both, "--recipient", public, "--sign-with", secret,
             "--key-passphrase", PASSPHRASE)
    out = rig.path("out")
    run = rig.gpg("-d", "-o", out, both, check=False)
    report(rig.read(out) == data and b"Good signature" in run.stderr,
           f"ours signs and encrypts with {label}, gpg decrypts and verifies",
           run.stderr.decode()[-200:])
    if key_records and key_records[-1][0] == label:
        key_records[-1] = key_records[-1] + (signed,)


GO_KEYS = [("ed25519", True), ("ed448", True), ("rsa", True), ("ed25519", False),
           ("ed448", False), ("rsa", False), ("eddsa", False), ("p256", False),
           ("p384", False), ("p521", False), ("brainpool256", False)]


def go_keys(rig, report):
    if not os.path.exists(rig.go):
        return
    data = plaintext(5000, 4)
    source = rig.write("plain", data)
    for algo, v6 in GO_KEYS:
        label = f"{algo} v{6 if v6 else 4}"
        secret, public = rig.path("gosec"), rig.path("gopub")
        try:
            run = subprocess.run([rig.go, "gen-key", "-algo", algo, *(["-v6"] if v6 else []),
                                  "-aead", "ocb", "-keypass", PASSPHRASE, secret, public],
                                 capture_output=True, timeout=600)
            if run.returncode != 0:
                raise RuntimeError(run.stderr.decode())
            fingerprint = run.stdout.decode().strip()
            listed = rig.ours("list-keys", public).stdout.decode()
            report(f"fingerprint {fingerprint}" in listed.splitlines()[0],
                   f"go-crypto's {label} key: our fingerprint is go-crypto's", listed[:200])
            encrypted, out = rig.path("go"), rig.path("out")
            run = subprocess.run([rig.go, "encrypt", "-to", public, "-aead", "ocb", source,
                                  encrypted], capture_output=True, timeout=600)
            if run.returncode != 0:
                raise RuntimeError(run.stderr.decode())
            mine = rig.ours("decrypt", encrypted, out, "--secret-key", secret,
                            "--passphrase", PASSPHRASE, check=False)
            report(rig.read(out) == data, f"go-crypto encrypts to {label}, ours decrypts",
                   mine.stderr.decode()[-200:])
            for fmt in ["v4", "rfc9580"]:
                encrypted, out = rig.path("ours"), rig.path("out")
                rig.ours("encrypt", source, encrypted, "--recipient", public, "--format", fmt)
                run = subprocess.run([rig.go, "decrypt", "-key", secret, "-keypass", PASSPHRASE,
                                      encrypted, out], capture_output=True, timeout=600)
                report(rig.read(out) == data,
                       f"ours encrypts ({fmt}) to {label}, go-crypto decrypts",
                       run.stderr.decode()[-200:])
            text = rig.write("text", SIGN_TEXT)
            for mode, signed_file in [("inline", source), ("detached", source),
                                      ("clear", text)]:
                out = rig.path("gosig")
                run = subprocess.run([rig.go, "sign", "-key", secret, "-keypass", PASSPHRASE,
                                      "-mode", mode, signed_file, out], capture_output=True)
                if run.returncode != 0:
                    raise RuntimeError(run.stderr.decode())
                check = (["verify", signed_file, "--signature", out] if mode == "detached"
                         else ["verify", out])
                mine = rig.ours(*check, "--key", public, check=False)
                report(mine.returncode == 0, f"go-crypto signs ({mode}) with {label}, ours "
                       "verifies", mine.stdout.decode()[-200:])
            for mode, args, signed_file in [("inline", [], source),
                                            ("detached", ["--detached"], source),
                                            ("clear", ["--clearsign"], text)]:
                out = rig.path("oursig")
                rig.ours("sign", signed_file, out, "--secret-key", secret, "--passphrase",
                         PASSPHRASE, *args)
                go_args = ["-mode", mode] + (["-sig", out, signed_file] if mode == "detached"
                                             else [out])
                run = subprocess.run([rig.go, "verify", "-key", public, *go_args],
                                     capture_output=True)
                report(run.returncode == 0, f"ours signs ({mode}) with {label}, go-crypto "
                       "verifies", run.stderr.decode()[-200:])
            encrypted, out = rig.path("gose"), rig.path("out")
            run = subprocess.run([rig.go, "encrypt", "-to", public, "-signkey", secret,
                                  "-keypass", PASSPHRASE, "-aead", "ocb", source, encrypted],
                                 capture_output=True)
            mine = rig.ours("decrypt", encrypted, out, "--secret-key", secret,
                            "--passphrase", PASSPHRASE, check=False)
            report(mine.returncode == 0 and rig.read(out) == data and b"good" in mine.stdout,
                   f"go-crypto signs and encrypts with {label}, ours decrypts and verifies",
                   mine.stdout.decode()[-200:])
            encrypted, out = rig.path("ourse"), rig.path("out")
            rig.ours("encrypt", source, encrypted, "--recipient", public, "--sign-with", secret,
                     "--key-passphrase", PASSPHRASE, "--format", "rfc9580" if v6 else "v4")
            run = subprocess.run([rig.go, "decrypt", "-key", secret, "-keypass", PASSPHRASE,
                                  "-to", public, encrypted, out], capture_output=True)
            report(run.returncode == 0 and rig.read(out) == data,
                   f"ours signs and encrypts with {label}, go-crypto decrypts and verifies",
                   run.stderr.decode()[-200:])
        except RuntimeError as error:
            report(False, f"go-crypto's {label} key", str(error)[-300:])


OUR_KEYS_FOR_GPG = ["rsa2048", "rsa3072", "dsa2048", "nistp256", "nistp384", "nistp521",
                    "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "secp256k1",
                    "ed25519-legacy"]
OUR_KEYS_FOR_GO = [("ed25519", False), ("ed448", False), ("ed25519", True), ("ed448", True),
                   ("rsa3072", True), ("nistp256", True), ("brainpoolP256r1", True),
                   ("nistp384", False), ("ed25519-legacy", False), ("rsa2048", False)]


def our_keys(rig, report):
    data = plaintext(3000, 5)
    source = rig.write("plain", data)
    for algo in OUR_KEYS_FOR_GPG:
        label = f"our {algo} key"
        email = f"ours-{algo}@example.org"
        secret, public = rig.path("oursec.asc"), rig.path("ourpub.asc")
        try:
            fingerprint = rig.ours("gen-key", secret, public, "--algo", algo, "--uid",
                                   f"ours {algo} <{email}>", "--passphrase", PASSPHRASE,
                                   "--s2k-octets", "65536").stdout.decode().strip()
            rig.gpg("--import", secret)
            listing = rig.gpg("--with-colons", "--list-secret-keys", email).stdout.decode()
            fprs = [l.split(":")[9] for l in listing.splitlines() if l.startswith("fpr")]
            report(fprs[:1] == [fingerprint] and len(fprs) == 2,
                   f"{label}: gpg imports it, both parts", listing[-300:])
            encrypted, out = rig.path("gpg"), rig.path("out")
            rig.gpg("--trust-model", "always", "-e", "-r", email, "-o", encrypted, source)
            run = rig.ours("decrypt", encrypted, out, "--secret-key", secret, "--passphrase",
                           PASSPHRASE, check=False)
            report(rig.read(out) == data, f"gpg encrypts to {label}, ours decrypts",
                   run.stderr.decode()[-200:])
            signed = rig.path("oursig")
            rig.ours("sign", source, signed, "--secret-key", secret, "--passphrase", PASSPHRASE)
            run = rig.gpg("--verify", signed, check=False)
            report(b"Good signature" in run.stderr, f"ours signs with {label}, gpg verifies",
                   run.stderr.decode()[-200:])
            encrypted, out = rig.path("ours"), rig.path("out")
            rig.ours("encrypt", source, encrypted, "--recipient", public)
            run = rig.gpg("-d", "-o", out, encrypted, check=False)
            report(rig.read(out) == data, f"ours encrypts to {label}, gpg decrypts with it",
                   run.stderr.decode()[-200:])
        except (RuntimeError, IndexError) as error:
            report(False, label, str(error)[-300:])
    if not os.path.exists(rig.go):
        return
    for algo, v6 in OUR_KEYS_FOR_GO:
        label = f"our {algo} v{6 if v6 else 4} key"
        secret, public = rig.path("oursec.asc"), rig.path("ourpub.asc")
        try:
            rig.ours("gen-key", secret, public, "--algo", algo, *(["--v6"] if v6 else []),
                     "--uid", "ours <ours@example.org>", "--passphrase", PASSPHRASE,
                     "--s2k-octets", "65536")
            encrypted, out = rig.path("go"), rig.path("out")
            run = subprocess.run([rig.go, "encrypt", "-to", public, "-aead", "ocb", source,
                                  encrypted], capture_output=True)
            if run.returncode != 0:
                raise RuntimeError(run.stderr.decode())
            mine = rig.ours("decrypt", encrypted, out, "--secret-key", secret, "--passphrase",
                            PASSPHRASE, check=False)
            report(rig.read(out) == data, f"go-crypto encrypts to {label}, ours decrypts",
                   mine.stderr.decode()[-200:])
            signed = rig.path("oursig")
            rig.ours("sign", source, signed, "--secret-key", secret, "--passphrase", PASSPHRASE)
            run = subprocess.run([rig.go, "verify", "-key", public, signed], capture_output=True)
            report(run.returncode == 0, f"ours signs with {label}, go-crypto verifies",
                   run.stderr.decode()[-200:])
            encrypted, out = rig.path("ours"), rig.path("out")
            rig.ours("encrypt", source, encrypted, "--recipient", public,
                     *(["--format", "rfc9580"] if v6 else []))
            run = subprocess.run([rig.go, "decrypt", "-key", secret, "-keypass", PASSPHRASE,
                                  encrypted, out], capture_output=True)
            report(rig.read(out) == data,
                   f"ours encrypts to {label}, go-crypto decrypts with our secret key",
                   run.stderr.decode()[-200:])
        except RuntimeError as error:
            report(False, label, str(error)[-300:])


# The GnuPG messages kept for the offline tests: small, and between them
# every container, an old cipher, bzip2 and partial lengths.
RECORDED = ["CAST5", "IDEA", "TWOFISH", "CAMELLIA256", "compress bzip2", "compress zlib",
            "S2K mode 0 SHA1", "S2K mode 3 RIPEMD160", "OCB packet AES",
            "OCB packet CAMELLIA192", "no MDC CAST5", "70000 bytes from a pipe",
            "70000 bytes OCB from a pipe", "0 bytes OCB from a pipe", "armored OCB"]


def record_keys(key_records):
    directory = os.path.join(FIXTURES, "openpgp", "keys")
    os.makedirs(directory, exist_ok=True)
    lines = ["# Keys GnuPG 2.4.4 made and exported, each protected with the",
             "# passphrase below, a message GnuPG encrypted to each, and GnuPG's",
             "# inline and detached signatures over the same data and text-mode and",
             "# cleartext signatures over the SIGN_TEXT of check_openpgp.py. Written by",
             "# scripts/check_openpgp.py --record; fingerprints as `gpg --with-colons`",
             "# lists them, primary first.", "", "[gnupg-keys]", ""]
    for label, secret, message, data, fingerprints, signed in key_records:
        name = label.split("/")[0].lower()
        for mode, path in signed.items():
            with open(path, "rb") as src, \
                    open(os.path.join(directory, f"{name}.{mode}.sig"), "wb") as out:
                out.write(src.read())
        with open(secret, "rb") as src, open(os.path.join(directory, name + ".asc"), "wb") as out:
            out.write(src.read())
        with open(message, "rb") as src, open(os.path.join(directory, name + ".gpg"), "wb") as out:
            out.write(src.read())
        lines += [f"name = {label}", f"key = openpgp/keys/{name}.asc",
                  f"message = openpgp/keys/{name}.gpg", f"passphrase = {PASSPHRASE}",
                  f"fingerprints = {' '.join(fingerprints)}",
                  *[f"{mode} = openpgp/keys/{name}.{mode}.sig" for mode in signed],
                  f"data_length = {len(data)}",
                  "data_seed = 3", f"data_sha256 = {hashlib.sha256(data).hexdigest()}",
                  f"text = {SIGN_TEXT.hex()}", ""]
    with open(os.path.join(FIXTURES, "openpgp-keys.vec"), "w") as out:
        out.write("\n".join(lines))
    print(f"recorded {len(key_records)} keys")


def record(records):
    directory = os.path.join(FIXTURES, "openpgp")
    os.makedirs(directory, exist_ok=True)
    lines = ["# Messages GnuPG 2.4.4 encrypted with a passphrase, that",
             "# examples/products/openpgp decrypts. Written by",
             "# scripts/check_openpgp.py --record; session_key is what",
             "# `gpg --show-session-key` printed; the data is plaintext(length,",
             "# seed) of that script.", "", "[gnupg]", ""]
    for label, path, data, key in records:
        if label not in RECORDED:
            continue
        name = label.lower().replace(" ", "-") + ".gpg"
        with open(path, "rb") as src, open(os.path.join(directory, name), "wb") as out:
            out.write(src.read())
        lines += [f"name = {label}", f"file = openpgp/{name}", f"passphrase = {PASSPHRASE}",
                  f"session_key = {key}", f"data_length = {len(data)}",
                  f"data_seed = {len(label)}",
                  f"data_sha256 = {hashlib.sha256(data).hexdigest()}", ""]
    with open(os.path.join(FIXTURES, "openpgp.vec"), "w") as out:
        out.write("\n".join(lines))
    print(f"recorded {sum(1 for r in records if r[0] in RECORDED)} messages")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gpg", default="gpg")
    parser.add_argument("--go-witness", default=GO_WITNESS)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "--quiet", "--release", "--example", "openpgp"],
                   cwd=ROOT, check=True)
    ours = os.path.join(ROOT, "target", "release", "examples", "openpgp")
    version = subprocess.run([args.gpg, "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    print(f"witnesses: {version}; go-crypto at {args.go_witness}")
    failures = rows = 0
    records = []

    def report(ok, label, detail=""):
        nonlocal failures, rows
        rows += 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label:62} {'' if ok else detail}")

    key_records = []
    with tempfile.TemporaryDirectory() as d:
        rig = Rig(args.gpg, ours, args.go_witness, d)
        try:
            gpg_encrypts(rig, report, records)
            ours_encrypts_for_gpg(rig, report)
            go_both_ways(rig, report)
            gpg_keys(rig, report, key_records)
            go_keys(rig, report)
            our_keys(rig, report)
            if args.record and not failures:
                record(records)
                record_keys(key_records)
        finally:
            subprocess.run(["gpgconf", "--homedir", rig.home, "--kill", "gpg-agent"],
                           capture_output=True)
    print(f"{rows - failures} of {rows} passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
