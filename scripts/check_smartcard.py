#!/usr/bin/env python3
"""The smart card example (`examples/products/smartcard`) against a
virtual card and against other programs' readings of the same card.

The card is `scripts/witness/cardsim.py`: CanoKey's PIV, OpenPGP card and
OATH applications, plus an emulated YubiKey OTP application. Every
command the example has is run against it, and what comes back is judged
by something other than the example:

  * **PIV**: certificates the card's keys sign are verified by OpenSSL;
    signatures by OpenSSL and python-cryptography; RSA decryption of what
    OpenSSL encrypted; ECDH and X25519 against python-cryptography; keys
    imported from files OpenSSL wrote sign as those files' keys. yubikit
    reads back the certificates, PIN and management key the example
    wrote.
  * **OpenPGP card**: the exported public key is imported by GnuPG, which
    checks every self-signature; GnuPG verifies the detached signatures;
    yubikit reads the fingerprints and creation times the example
    registered on the card.
  * **OATH**: every code against HMAC computed here (RFC 4226/6238);
    yubikit lists what the example stored and unlocks the password the
    example set.
  * **YubiKey OTP**: the example's configuration and challenge commands
    are compared byte for byte with yubikit's, both sent to the same
    card; responses against HMAC-SHA1 computed here.
  * **PC/SC** (with `--pcsc`): the same card behind pcsc-lite's `pcscd`
    and `scripts/witness/ifd-tcpcard`, reached through the example's
    own PC/SC binding - and GnuPG's scdaemon, through the same reader,
    decrypts with the key the example generated.

    python3 scripts/check_smartcard.py [--ours PATH] [--card PATH]
            [--yubikit DIR] [--pcsc PREFIX]
    python3 scripts/check_smartcard.py --record

`--record` writes `examples/products/fixtures/smartcard.vec`: each
command's conversation with the card, which the example's offline tests
replay byte for byte.

**A development tool, not a test.** The gate runs none of it. Build ours
first (`cargo build --release --example smartcard`); the witnesses are
built as `docs/building.md` says.
"""

import argparse
import base64
import hashlib
import hmac
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "smartcard")

# A fixed clock, so that what is recorded replays: key creation times,
# certificate validity and TOTP steps all come from here.
T = 1760000000

COUNTS = {}
FAILURES = []


def check(kind, condition, detail=""):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    if not condition:
        FAILURES.append(f"{kind}: {detail}")
        print(f"FAIL {kind}: {detail}")
    return condition


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Card:
    """A fresh virtual card: cardsim.py around a new CanoKey process."""

    def __init__(self, binary, work):
        self.port = free_port()
        self.log = os.path.join(work, f"card-{self.port}.log")
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "witness", "cardsim.py"), "--card", binary,
             "--port", str(self.port), "--log", self.log],
            stdout=subprocess.PIPE, text=True, cwd=work)
        line = self.proc.stdout.readline()
        if "listening" not in line:
            raise RuntimeError(f"cardsim did not start: {line!r}")

    def exchanges(self):
        """Every (command, answer) the card has seen, in hex."""
        out = []
        with open(self.log) as f:
            lines = f.read().splitlines()
        for sent, answer in zip(lines[::2], lines[1::2]):
            out.append((sent[2:], answer[2:]))
        return out

    def close(self):
        self.proc.terminate()
        self.proc.wait()


class Runner:
    """Runs the example against the card, recording when asked."""

    def __init__(self, ours, card, work, record):
        self.ours, self.card, self.work, self.record = ours, card, work, record
        self.recorded = []
        self.seed = 0

    def path(self, name):
        return os.path.join(self.work, name)

    def run(self, name, words, ok=True, files=(), outputs=(), transport=None):
        """The example's standard output; standard error when `ok` is
        False, in which case it must fail. `files` and `outputs` name the
        work-directory files the command reads and writes, which a
        recording carries."""
        self.seed += 1
        print(f"  {name}", flush=True)
        card = transport or ["--card", f"tcp:127.0.0.1:{self.card.port}"]
        recording = self.path(f"rec-{self.seed}.txt")
        extra = ["--record", recording, "--random-seed", str(self.seed)] if self.record else []
        full = [self.path(w) if w in files or w in outputs else w for w in words]
        try:
            result = subprocess.run([self.ours] + card + full + extra, capture_output=True,
                                    env=self.env, timeout=120)
        except subprocess.TimeoutExpired:
            raise SystemExit(f"{name}: no answer in two minutes - is the card held by "
                             f"another client?")
        succeeded = result.returncode == 0
        check(f"runs {name}", succeeded == ok,
              f"{' '.join(words)}: exit {result.returncode}: {result.stderr.decode().strip()}")
        if self.record and transport is None:
            with open(recording) as f:
                exchanges = f.read().strip()
            self.recorded.append({
                "name": name, "words": list(words) + ["--random-seed", str(self.seed)],
                "files": {n: open(self.path(n), "rb").read() for n in files},
                "outputs": {n: open(self.path(n), "rb").read() for n in outputs
                            if succeeded},
                "exchanges": exchanges, "ok": succeeded,
                "output": result.stdout if succeeded else result.stderr.strip(),
            })
        return (result.stdout if ok else result.stderr).decode()

    env = dict(os.environ)


def openssl(*args, data=None):
    result = subprocess.run(["openssl"] + list(args), input=data, capture_output=True)
    return result.returncode == 0, result.stdout + result.stderr


def pem_block(text, kind="CERTIFICATE"):
    start = text.index(f"-----BEGIN {kind}-----")
    end = text.index(f"-----END {kind}-----") + len(f"-----END {kind}-----")
    return text[start:end] + "\n"


def totp(secret, counter, digits=6, hash_name="sha1"):
    mac = hmac.new(secret, struct.pack(">Q", counter), getattr(hashlib, hash_name)).digest()
    offset = mac[-1] & 15
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


# ------------------------------------------------------------------ PIV --

def check_piv(r, yubikit):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, x25519

    with open(r.path("message.txt"), "wb") as f:
        f.write(b"A message for the card to sign.\n")

    out = r.run("info", ["info"])
    check("info names every application",
          all(name in out for name in ("PIV", "OpenPGP", "OATH", "YubiKey OTP")), out)
    r.run("piv info, factory", ["piv", "info"])

    # Generated keys, self-signed certificates; OpenSSL verifies them.
    certificates = {}
    for slot, key_type in [("9a", "p256"), ("9c", "rsa2048"), ("9d", "p384"),
                           ("82", "ed25519")]:
        out = r.run(f"piv generate {slot} {key_type}",
                    ["piv", "generate", slot, key_type, "--self-sign", f"allcrypt {slot}",
                     "--pin", "123456", "--time", str(T), "--days", "30"])
        certificates[slot] = pem_block(out)
        with open(r.path(f"cert-{slot}.pem"), "w") as f:
            f.write(certificates[slot])
        good, why = openssl("verify", "-attime", str(T + 60), "-CAfile",
                            r.path(f"cert-{slot}.pem"), r.path(f"cert-{slot}.pem"))
        check("OpenSSL verifies the self-signed certificate", good, f"{slot}: {why}")
        cert = x509.load_pem_x509_certificate(certificates[slot].encode())
        check("the certificate's validity is the one asked for",
              cert.not_valid_before_utc.timestamp() == T
              and cert.not_valid_after_utc.timestamp() == T + 30 * 86400, slot)
    r.run("piv generate 9e x25519", ["piv", "generate", "9e", "x25519"])

    # Signatures, verified by OpenSSL against the certificate.
    for slot, hash_name in [("9a", "sha256"), ("9a", "sha384"), ("9c", "sha256"),
                            ("9c", "sha512"), ("82", "sha512")]:
        sig = f"sig-{slot}-{hash_name}.bin"
        r.run(f"piv sign {slot} {hash_name}",
              ["piv", "sign", slot, "message.txt", "--pin", "123456", "--hash", hash_name,
               "--out", sig], files=["message.txt"], outputs=[sig])
        public = x509.load_pem_x509_certificate(certificates[slot].encode()).public_key()
        with open(r.path(sig), "rb") as f:
            signature = f.read()
        with open(r.path("message.txt"), "rb") as f:
            message = f.read()
        try:
            if isinstance(public, ed25519.Ed25519PublicKey):
                public.verify(signature, message)
            elif isinstance(public, ec.EllipticCurvePublicKey):
                public.verify(signature, message, ec.ECDSA(getattr(hashes, hash_name.upper())()))
            else:
                public.verify(signature, message, padding.PKCS1v15(),
                              getattr(hashes, hash_name.upper())())
            check("python-cryptography verifies the card's signature", True)
        except Exception as e:  # noqa: BLE001
            check("python-cryptography verifies the card's signature", False,
                  f"{slot} {hash_name}: {e!r}")

    # RSA decryption of what python-cryptography encrypted.
    public = x509.load_pem_x509_certificate(certificates["9c"].encode()).public_key()
    with open(r.path("encrypted.bin"), "wb") as f:
        f.write(public.encrypt(b"a session key, 32 bytes long ...", padding.PKCS1v15()))
    r.run("piv decrypt 9c", ["piv", "decrypt", "9c", "encrypted.bin", "--pin", "123456",
                             "--out", "decrypted.bin"],
          files=["encrypted.bin"], outputs=["decrypted.bin"])
    with open(r.path("decrypted.bin"), "rb") as f:
        check("RSA decryption gives what was encrypted",
              f.read() == b"a session key, 32 bytes long ...")

    # Key agreement against python-cryptography.
    info = r.run("piv info, keys", ["piv", "info"])
    point_9d = bytes.fromhex(info.split("slot 9d: P-384 ")[1].split(";")[0])
    key_9e = bytes.fromhex(info.split("slot 9e: X25519 ")[1].split(";")[0])
    peer = ec.derive_private_key(0x1234567890ABCDEF << 200, ec.SECP384R1())
    peer_point = peer.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
    out = r.run("piv ecdh 9d", ["piv", "ecdh", "9d", peer_point.hex(), "--pin", "123456"])
    expected = peer.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(), point_9d))
    check("P-384 ECDH agrees with python-cryptography", out.strip() == expected.hex())
    peer = x25519.X25519PrivateKey.from_private_bytes(bytes(range(32)))
    out = r.run("piv ecdh 9e", ["piv", "ecdh", "9e", peer.public_key().public_bytes_raw().hex(),
                                "--pin", "123456"])
    expected = peer.exchange(x25519.X25519PublicKey.from_public_bytes(key_9e))
    check("X25519 agrees with python-cryptography", out.strip() == expected.hex())

    # Keys OpenSSL wrote, imported, then used.
    for slot, algorithm, options in [("83", "EC", ["-pkeyopt", "ec_paramgen_curve:P-256"]),
                                     ("84", "RSA", ["-pkeyopt", "rsa_keygen_bits:2048"]),
                                     ("85", "ED25519", [])]:
        key = f"key-{slot}.pem"
        good, why = openssl("genpkey", "-algorithm", algorithm, *options, "-out", r.path(key))
        check("OpenSSL writes a key", good, why)
        r.run(f"piv import {slot}", ["piv", "import", slot, key], files=[key])
        good, why = openssl("req", "-new", "-x509", "-key", r.path(key), "-subj",
                            f"/CN=imported {slot}", "-days", "30", "-out",
                            r.path(f"cert-{slot}.pem"))
        r.run(f"piv write-cert {slot}", ["piv", "write-cert", slot, f"cert-{slot}.pem"],
              files=[f"cert-{slot}.pem"])
        sig = f"sig-{slot}.bin"
        r.run(f"piv sign {slot}", ["piv", "sign", slot, "message.txt", "--pin", "123456",
                                   "--out", sig], files=["message.txt"], outputs=[sig])
        good, why = openssl("pkey", "-in", r.path(key), "-pubout", "-out",
                            r.path(f"pub-{slot}.pem"))
        if algorithm == "ED25519":
            good, why = openssl("pkeyutl", "-verify", "-pubin", "-inkey", r.path(f"pub-{slot}.pem"),
                                "-rawin", "-in", r.path("message.txt"), "-sigfile", r.path(sig))
        else:
            good, why = openssl("dgst", "-sha256", "-verify", r.path(f"pub-{slot}.pem"),
                                "-signature", r.path(sig), r.path("message.txt"))
        check("OpenSSL verifies a signature by an imported key", good, f"{slot}: {why}")

    # An X25519 key OpenSSL wrote, imported, then agreeing with its file.
    good, why = openssl("genpkey", "-algorithm", "X25519", "-out", r.path("key-86.pem"))
    check("OpenSSL writes a key", good, why)
    r.run("piv import 86 x25519", ["piv", "import", "86", "key-86.pem"], files=["key-86.pem"])
    with open(r.path("key-86.pem"), "rb") as f:
        mine = serialization.load_pem_private_key(f.read(), None)
    peer = x25519.X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    out = r.run("piv ecdh 86", ["piv", "ecdh", "86", peer.public_key().public_bytes_raw().hex(),
                                "--pin", "123456"])
    check("an imported X25519 key agrees with its file",
          out.strip() == mine.exchange(peer.public_key()).hex(), out)

    out = r.run("piv read-cert 9a", ["piv", "read-cert", "9a"])
    check("the certificate reads back as written", out == certificates["9a"])
    err = r.run("piv write-cert, wrong key", ["piv", "write-cert", "9d", "cert-9a.pem"],
                ok=False, files=["cert-9a.pem"])
    check("a certificate for another key is refused", "another key" in err, err)
    err = r.run("piv attest", ["piv", "attest", "9a"], ok=False)
    check("CanoKey has no attestation key, and says so", "6A88" in err, err)

    # PINs.
    err = r.run("piv wrong PIN", ["piv", "sign", "9a", "message.txt", "--pin", "000000"],
                ok=False, files=["message.txt"])
    check("a wrong PIN counts down", "2 tries left" in err, err)
    r.run("piv change-pin", ["piv", "change-pin", "--pin", "123456", "--new", "24681357"])
    r.run("piv change-puk", ["piv", "change-puk", "--puk", "12345678", "--new", "87654321"])
    for i in range(3):
        r.run(f"piv block PIN {i}", ["piv", "sign", "9a", "message.txt", "--pin", "999999"],
              ok=False, files=["message.txt"])
    r.run("piv unblock-pin", ["piv", "unblock-pin", "--puk", "87654321", "--new", "13572468"])
    management = "00112233445566778899AABBCCDDEEFF0011223344556677"
    r.run("piv set-management-key", ["piv", "set-management-key", "--new", management,
                                     "--type", "aes192"])

    if yubikit:
        from yubikit.piv import PivSession
        connection = yubikit()
        try:
            yubikit_piv(PivSession(connection), certificates, management)
        finally:
            connection.close()

    r.run("piv write-cert, new management key",
          ["piv", "write-cert", "9a", "cert-9a.pem", "--management-key", management],
          files=["cert-9a.pem"])
    r.run("piv reset", ["piv", "reset"])
    out = r.run("piv info, after reset", ["piv", "info"])
    check("a reset leaves no keys", "slot 9a" not in out, out)


def yubikit_piv(piv, certificates, management):
    """yubikit's reading of what the example wrote: the 9a certificate,
    the PIN, and the management key with the type the card now reports."""
    from cryptography.hazmat.primitives import serialization
    from yubikit.piv import SLOT
    check("yubikit reads the certificate the example wrote",
          piv.get_certificate(SLOT.AUTHENTICATION).public_bytes(serialization.Encoding.PEM)
          .decode() == certificates["9a"])
    # CanoKey reports PIV version 0.0.0, so yubikit takes it for a card
    # older than metadata (5.3) and assumes the management key is 3DES.
    # The type comes from the card's own metadata instead, read and
    # parsed here with yubikit's TLV code rather than the example's.
    from yubikit.core import Tlv
    from yubikit.piv import MANAGEMENT_KEY_TYPE
    metadata = Tlv.parse_dict(piv.protocol.send_apdu(0, 0xF7, 0, 0x9B))
    piv._management_key_type = MANAGEMENT_KEY_TYPE(metadata[0x01][0])
    check("the card reports the management key type the example set",
          piv.management_key_type == MANAGEMENT_KEY_TYPE.AES192, repr(piv.management_key_type))
    for what, attempt in [("the PIN", lambda: piv.verify_pin("13572468")),
                          ("the management key",
                           lambda: piv.authenticate(bytes.fromhex(management)))]:
        try:
            attempt()
            check(f"yubikit accepts {what} the example set", True)
        except Exception as e:  # noqa: BLE001
            check(f"yubikit accepts {what} the example set", False, repr(e))


# -------------------------------------------------------------- OpenPGP --

def gpg(home, *args, data=None):
    result = subprocess.run(["gpg", "--homedir", home, "--batch"] + list(args), input=data,
                            capture_output=True)
    return result.returncode == 0, (result.stdout + result.stderr).decode()


def check_openpgp(r, yubikit):
    r.run("openpgp status, factory", ["openpgp", "status"])
    fingerprints = {}
    for slot, algorithm in [("sig", "ed25519"), ("dec", "x25519"), ("aut", "p256")]:
        out = r.run(f"openpgp generate {slot} {algorithm}",
                    ["openpgp", "generate", slot, algorithm, "--admin-pin", "12345678",
                     "--time", str(T)])
        fingerprints[slot] = out.split("fingerprint ")[1].strip()
    exported_ok = check_export(r, "first", fingerprints)

    if yubikit:
        # yubikit's OpenPgpSession first asks for a YubiKey-only version
        # instruction, which CanoKey refuses; its parser of the
        # application-related data (6E) is used directly instead.
        from yubikit.core.smartcard import AID, SmartCardProtocol
        from yubikit.openpgp import KEY_REF, ApplicationRelatedData
        connection = yubikit()
        try:
            protocol = SmartCardProtocol(connection)
            protocol.select(AID.OPENPGP)
            related = ApplicationRelatedData.parse(protocol.send_apdu(0, 0xCA, 0x00, 0x6E))
        finally:
            connection.close()
        theirs = related.discretionary.fingerprints
        times = related.discretionary.generation_times
        for slot, ref in [("sig", KEY_REF.SIG), ("dec", KEY_REF.DEC), ("aut", KEY_REF.AUT)]:
            check("yubikit reads the fingerprint the example registered",
                  theirs[ref].hex().upper() == fingerprints[slot], slot)
            check("yubikit reads the creation time the example registered",
                  times[ref] == T, f"{slot}: {times[ref]}")

    # RSA on the card, and keys from files OpenSSL wrote.
    out = r.run("openpgp generate sig rsa2048",
                ["openpgp", "generate", "sig", "rsa2048", "--admin-pin", "12345678",
                 "--time", str(T + 1)])
    fingerprints["sig"] = out.split("fingerprint ")[1].strip()
    for slot, algorithm, options in [("dec", "EC", ["-pkeyopt", "ec_paramgen_curve:P-384"]),
                                     ("aut", "ED25519", []), ("dec", "X25519", [])]:
        key = f"pgp-{slot}-{algorithm.lower()}.pem"
        openssl("genpkey", "-algorithm", algorithm, *options, "-out", r.path(key))
        out = r.run(f"openpgp import {slot}", ["openpgp", "import", slot, key, "--admin-pin",
                                               "12345678", "--time", str(T + 2)], files=[key])
        fingerprints[slot] = out.split("fingerprint ")[1].strip()
    if exported_ok:
        check_export(r, "second", fingerprints)

    r.run("openpgp change-pin", ["openpgp", "change-pin", "--pin", "123456", "--new",
                                 "654321"])
    err = r.run("openpgp wrong PIN", ["openpgp", "sign", "message.txt", "--pin", "123456"],
                ok=False, files=["message.txt"])
    # CanoKey answers a wrong OpenPGP PIN with 6982 rather than 63Cx, so
    # the count is read from the status instead.
    check("a wrong OpenPGP PIN is refused", "Wrong PIN" in err, err)
    out = r.run("openpgp status, after a wrong PIN", ["openpgp", "status"])
    check("a wrong OpenPGP PIN counts down", "user 2," in out, out)
    r.run("openpgp reset-pin", ["openpgp", "reset-pin", "--admin-pin", "12345678", "--new",
                                "123456"])
    r.run("openpgp change-admin-pin", ["openpgp", "change-admin-pin", "--admin-pin",
                                       "12345678", "--new", "87654321"])
    out = r.run("openpgp status, keys", ["openpgp", "status"])
    for slot in ("signature", "decryption", "authentication"):
        check("the status names the key", fingerprints[slot[:3]] in out, f"{slot}: {out}")


def check_export(r, label, fingerprints):
    home = tempfile.mkdtemp(prefix="gnupg-", dir=r.work)
    os.chmod(home, 0o700)
    exported = f"public-{label}.asc"
    r.run(f"openpgp export, {label}",
          ["openpgp", "export", "--user-id", "Card Holder <card@example.org>", "--pin", "123456",
           "--time", str(T + 10), "--out", exported], outputs=[exported])
    good, why = gpg(home, "--import", r.path(exported))
    if not check("GnuPG imports the exported key", good, why):
        return False
    good, listing = gpg(home, "--check-sigs", "--with-colons", "--with-subkey-fingerprints")
    check("GnuPG checks every self-signature",
          listing.count("\nsig:!") == 3 and "sig:-" not in listing, listing)
    for slot, fingerprint in fingerprints.items():
        check("GnuPG computes the fingerprint the card holds",
              f"fpr:::::::::{fingerprint}:" in listing, f"{label} {slot}")
    signature = f"message-{label}.sig"
    r.run(f"openpgp sign, {label}", ["openpgp", "sign", "message.txt", "--pin", "123456",
                                     "--time", str(T + 20), "--out", signature],
          files=["message.txt"], outputs=[signature])
    good, why = gpg(home, "--verify", r.path(signature), r.path("message.txt"))
    check("GnuPG verifies the card's signature", good and "Good signature" in why, why)
    return True


# ----------------------------------------------------------------- OATH --

def check_oath(r, yubikit):
    secrets = {
        "Example:alice": (base64.b32decode("JBSWY3DPEHPK3PXP"), "sha1", 6, 30),
        "60/bob": (b"12345678901234567890123456789012", "sha256", 8, 60),
        "carol": (b"1234567890123456789012345678901234567890123456789012345678901234",
                  "sha512", 8, 30),
    }
    r.run("oath add alice", ["oath", "add", "alice", "JBSWY3DPEHPK3PXP", "--issuer", "Example",
                             "--time", str(T)])
    r.run("oath add bob", ["oath", "add", "bob",
                           base64.b32encode(secrets["60/bob"][0]).decode(), "--hash", "sha256",
                           "--digits", "8", "--period", "60", "--time", str(T)])
    r.run("oath add carol", ["oath", "add", "carol",
                             base64.b32encode(secrets["carol"][0]).decode(), "--hash", "sha512",
                             "--digits", "8", "--time", str(T)])
    r.run("oath add counter", ["oath", "add", "counter", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                               "--hotp"])
    r.run("oath add touch", ["oath", "add", "touch", "JBSWY3DPEHPK3PXP", "--touch"])
    out = r.run("oath list", ["oath", "list"])
    check("the list has every credential", all(n in out for n in
                                               list(secrets) + ["counter", "touch"]), out)
    out = r.run("oath code", ["oath", "code", "--time", str(T)])
    codes = dict(line.rsplit("  ", 1) for line in out.splitlines())
    for name, (secret, hash_name, digits, period) in secrets.items():
        check("a TOTP code agrees with RFC 6238 computed here",
              codes.get(name) == totp(secret, T // period, digits, hash_name),
              f"{name}: {codes.get(name)}")
    out = r.run("oath code bob", ["oath", "code", "60/bob", "--time", str(T + 3600)])
    check("one code by name, at its own period",
          out.strip() == totp(secrets["60/bob"][0], (T + 3600) // 60, 8, "sha256"), out)
    # CanoKey counts before computing, so its first HOTP code is RFC 4226's
    # count 1; a YubiKey's is count 0. Either way the codes run in order.
    first = r.run("oath code counter", ["oath", "code", "counter"]).strip()
    second = r.run("oath code counter again", ["oath", "code", "counter"]).strip()
    hotp = [totp(b"12345678901234567890", c) for c in range(4)]
    check("HOTP codes are RFC 4226's, in order",
          [first, second] in ([hotp[0], hotp[1]], [hotp[1], hotp[2]]), f"{first} {second}")

    r.run("oath set-password", ["oath", "set-password", "--new", "correct horse"])
    err = r.run("oath list, no password", ["oath", "list"], ok=False)
    check("a locked application asks for the password", "--password" in err, err)
    err = r.run("oath list, wrong password", ["oath", "list", "--password", "wrong"], ok=False)
    check("a wrong password is refused", "wrong" in err, err)
    if yubikit:
        from yubikit.oath import OathSession
        connection = yubikit()
        try:
            session = OathSession(connection)
            session.validate(session.derive_key("correct horse"))
            check("yubikit unlocks the password the example set", True)
            names = sorted(c.id.decode() for c in session.list_credentials())
            check("yubikit lists what the example stored",
                  names == sorted(list(secrets) + ["counter", "touch"]), repr(names))
        except Exception as e:  # noqa: BLE001
            check("yubikit unlocks the password the example set", False, repr(e))
        finally:
            connection.close()
    r.run("oath delete", ["oath", "delete", "touch", "--password", "correct horse"])
    r.run("oath remove-password", ["oath", "remove-password", "--password", "correct horse"])
    out = r.run("oath list, after", ["oath", "list"])
    check("a deleted credential is gone", "touch" not in out, out)


# ------------------------------------------------------------------ OTP --

def check_otp(r, yubikit):
    key = bytes(range(0x30, 0x44))
    r.run("otp status", ["otp", "status"])
    r.run("otp program", ["otp", "program", "1", key.hex()])
    r.run("otp program touch", ["otp", "program", "2", key.hex(), "--touch"])
    for challenge in [b"abc", b"ab\0", b"", bytes(range(64)), b"\x07" * 20]:
        out = r.run(f"otp challenge {challenge.hex()[:8]}",
                    ["otp", "challenge", "1", challenge.hex()])
        stripped = challenge.rstrip(challenge[-1:]) if len(challenge) == 64 else challenge
        check("the response is HMAC-SHA1 of the challenge",
              out.strip() == hmac.new(key, stripped, hashlib.sha1).hexdigest(),
              f"{challenge.hex()}: {out}")
    if not yubikit:
        return
    # The same operations from yubikit, and the bytes compared.
    from yubikit.yubiotp import SLOT, HmacSha1SlotConfiguration, YubiOtpSession
    before = len(r.card.exchanges())
    connection = yubikit()
    try:
        session = YubiOtpSession(connection)
        session.put_configuration(SLOT.ONE, HmacSha1SlotConfiguration(key))
        session.put_configuration(SLOT.TWO, HmacSha1SlotConfiguration(key).require_touch(True))
        session.calculate_hmac_sha1(SLOT.ONE, b"ab\0")
    finally:
        connection.close()
    time.sleep(0.2)
    yubikit_sent = [c for c, _ in r.card.exchanges()[before:]]
    before = len(r.card.exchanges())
    r.run("otp program, again", ["otp", "program", "1", key.hex()])
    r.run("otp program touch, again", ["otp", "program", "2", key.hex(), "--touch"])
    r.run("otp challenge, again", ["otp", "challenge", "1", "616200"])
    ours_sent = [c for c, _ in r.card.exchanges()[before:]]
    # yubikit sends extended-length APDUs to what it takes for a recent
    # YubiKey, the example short ones; what is compared is the
    # instruction, the parameters and the data field.
    def commands(sent):
        out = []
        for command in sent:
            apdu = bytes.fromhex(command)
            if apdu[1] == 0x01 and apdu[2] in (0x01, 0x03, 0x30):
                body = (apdu[7:7 + int.from_bytes(apdu[5:7], "big")] if apdu[4] == 0
                        else apdu[5:5 + apdu[4]])
                out.append((apdu[1:4].hex(), body.hex()))
        return out
    check("yubikit and the example send the same configurations and challenge",
          commands(ours_sent) == commands(yubikit_sent) and len(commands(ours_sent)) == 3,
          f"\nours   {commands(ours_sent)}\ntheirs {commands(yubikit_sent)}")


# ---------------------------------------------------------------- PC/SC --

def check_pcsc(r, prefix, card):
    conf = os.path.join(r.work, "reader.d")
    os.makedirs(conf, exist_ok=True)
    with open(os.path.join(conf, "reader.conf"), "w") as f:
        f.write(f'FRIENDLYNAME "allcrypt virtual card"\nDEVICENAME {card.port}\n'
                f"LIBPATH {prefix}/lib/ifd-tcpcard.so\nCHANNELID 0\n")
    daemon = subprocess.Popen([os.path.join(prefix, "sbin", "pcscd"), "-f", "-c", conf, "-i"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    library = os.path.join(prefix, "lib")
    env = dict(os.environ, LD_LIBRARY_PATH=library)
    try:
        listing = subprocess.run([r.ours, "readers"], capture_output=True, env=env, text=True)
        check("the example lists the reader through PC/SC",
              "allcrypt virtual card" in listing.stdout, listing.stdout + listing.stderr)
        through = ["--reader", "allcrypt"]
        old_env, r.env = r.env, env
        out = r.run("info through PC/SC", ["info"], transport=through)
        check("every application answers through PC/SC", "OpenPGP" in out, out)
        out = r.run("openpgp status through PC/SC", ["openpgp", "status"], transport=through)

        out = r.run("piv generate through PC/SC", ["piv", "generate", "9a", "p256",
                                                   "--self-sign", "PC/SC", "--pin", "123456",
                                                   "--time", str(T)], transport=through)
        with open(r.path("cert-pcsc.pem"), "w") as f:
            f.write(pem_block(out))
        good, why = openssl("verify", "-attime", str(T + 60), "-CAfile", r.path("cert-pcsc.pem"),
                            r.path("cert-pcsc.pem"))
        check("OpenSSL verifies a certificate the card signed through PC/SC", good, why)
        r.env = old_env

        # GnuPG's scdaemon reaches the same card through the same reader and
        # decrypts with the key the example generated and registered - where
        # this machine has an scdaemon.
        scdaemon = subprocess.run(["gpgconf", "--list-components"], capture_output=True,
                                  text=True).stdout
        path = next((line.split(":")[2] for line in scdaemon.splitlines()
                     if line.startswith("scdaemon:")), "")
        if not os.path.exists(path):
            print("skipped: GnuPG through PC/SC - this machine has no scdaemon")
            return
        home = tempfile.mkdtemp(prefix="gnupg-pcsc-", dir=r.work)
        os.chmod(home, 0o700)
        with open(os.path.join(home, "scdaemon.conf"), "w") as f:
            f.write(f"pcsc-driver {library}/libpcsclite.so.1\ndisable-ccid\n")
        with open(os.path.join(home, "gpg-agent.conf"), "w") as f:
            f.write("allow-loopback-pinentry\n")
        r.env = env
        r.run("openpgp generate dec, for GnuPG", ["openpgp", "generate", "dec", "x25519",
                                                  "--admin-pin", "87654321", "--time", str(T)],
              transport=through)
        r.run("openpgp export, for GnuPG", ["openpgp", "export", "--user-id", "PC/SC",
                                            "--pin", "123456", "--time", str(T + 10),
                                            "--out", "public-pcsc.asc"], transport=through,
              outputs=["public-pcsc.asc"])
        r.env = old_env
        gpg(home, "--import", r.path("public-pcsc.asc"))
        good, status = gpg(home, "--card-status")
        check("GnuPG reads the card through PC/SC", good, status)
        result = subprocess.run(["gpg", "--homedir", home, "--batch", "--trust-model", "always",
                                 "--encrypt", "--armor", "-r", "PC/SC"],
                                input=b"for the card's eyes only\n", capture_output=True)
        check("GnuPG encrypts to the card's key", result.returncode == 0, result.stderr.decode())
        result = subprocess.run(["gpg", "--homedir", home, "--batch", "--pinentry-mode",
                                 "loopback", "--passphrase", "123456", "--decrypt"],
                                input=result.stdout, capture_output=True)
        check("GnuPG decrypts with the card, through PC/SC",
              result.stdout == b"for the card's eyes only\n", result.stderr.decode())
        subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)
    finally:
        daemon.terminate()
        daemon.wait()


# ---------------------------------------------------------------- main --

def write_fixture(recorded):
    lines = ["# Conversations between examples/products/smartcard and the virtual",
             "# card of scripts/witness/cardsim.py (CanoKey, and an emulated YubiKey",
             "# OTP application), written by scripts/check_smartcard.py --record.",
             "# Each record runs the example with `arg` words, the named input",
             "# files written first, against a card that answers from",
             "# `exchanges` and refuses anything else; `output` is what it",
             "# printed (or the error, when `ok = false`; `-` for nothing) and",
             "# `written` the files it wrote.", "", "[conversations]"]
    for entry in recorded:
        lines.append(f"name = {entry['name']}")
        # `""` for an empty word, which a field cannot hold either.
        lines.extend(f"arg = {word or chr(34) * 2}" for word in entry["words"])
        lines.extend(f"file = {name} {data.hex()}" for name, data in entry["files"].items())
        lines.append(f"ok = {'true' if entry['ok'] else 'false'}")
        # "-" for nothing printed: a field's value cannot be empty.
        lines.append(f"output = {entry['output'].hex() or '-'}")
        lines.extend(f"written = {name} {data.hex()}"
                     for name, data in entry["outputs"].items())
        lines.append(f"exchanges = {entry['exchanges']}")
    path = os.path.join(FIXTURES, "smartcard.vec")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{len(recorded)} conversations -> {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--card", default="/opt/canokey/apdu-replay")
    parser.add_argument("--yubikit", default="/opt/yubikit/yubikey-manager",
                        help="a yubikey-manager checkout; skipped when absent")
    parser.add_argument("--pcsc", help="pcsc-lite's prefix, with the witness driver in lib/")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()

    connect = None
    if os.path.isdir(args.yubikit):
        sys.path.insert(0, args.yubikit)
        from yubikit.core import TRANSPORT
        from yubikit.core.smartcard import SmartCardConnection

        class TcpCard(SmartCardConnection):
            """yubikit's view of cardsim.py's line protocol."""

            def __init__(self, port):
                self.sock = socket.create_connection(("127.0.0.1", port))
                self.stream = self.sock.makefile("rw", newline="\n")

            @property
            def transport(self):
                return TRANSPORT.USB

            def send_and_receive(self, apdu):
                self.stream.write(apdu.hex().upper() + "\n")
                self.stream.flush()
                body = bytes.fromhex(self.stream.readline().strip()[5:])
                return body[2:], int.from_bytes(body[:2], "big")

            def close(self):
                # The file object holds the socket open until it is closed
                # too, and the card serves one client at a time.
                self.stream.close()
                self.sock.close()
    else:
        TcpCard = None
        print(f"no yubikit at {args.yubikit}: its checks are skipped")

    work = tempfile.mkdtemp(prefix="check-smartcard-")
    card = Card(args.card, work)
    try:
        runner = Runner(args.ours, card, work, args.record)
        if TcpCard is not None:
            connect = lambda: TcpCard(card.port)  # noqa: E731
        for section in (check_piv, check_openpgp, check_oath, check_otp):
            section(runner, connect)
        if args.pcsc:
            check_pcsc(runner, args.pcsc, card)
    finally:
        card.close()

    for kind, count in sorted(COUNTS.items()):
        print(f"{count:4}  {kind}")
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILED")
        sys.exit(1)
    if args.record:
        write_fixture(runner.recorded)
    shutil.rmtree(work)
    print("\nall agree")


if __name__ == "__main__":
    main()
