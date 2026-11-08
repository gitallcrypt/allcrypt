#!/usr/bin/env python3
"""Checks /opt/rc4hmacwitness before any vector is written from it, and
holds the three witnesses' interfaces for the generator.

    python3 scripts/witness/rc4hmac/selftest.py [/opt/rc4hmacwitness]

1. String-to-key: the three agree on passwords in ASCII, Latin-1,
   Cyrillic and outside the Basic Multilingual Plane (a UTF-16 surrogate
   pair).
2. Encryption: each ciphertext MIT and Kerby make, under random
   confounders, is opened by all three where they have the type - MIT
   and Kerby for type 24 as well as 23 - and impacket, given the
   confounder read back out of it, makes the same bytes. A ciphertext
   with a byte changed is refused by all of them.
3. The -138 checksum and the PRF: the three agree.

MIT Kerberos's answers are the ones `examples/products/fixtures/kerberos.vec`
already records for the product example; the check here is that the
other two agree with this build of it.
"""

import hashlib
import hmac
import importlib
import os
import random
import struct
import subprocess
import sys
import tempfile

ENCTYPES = (23, 24)
WEAK_CONF = """[libdefaults]
    allow_weak_crypto = true
    allow_rc4 = true
"""


def message_type(usage):
    """RFC 4757 section 3, with usage 9 kept as MIT and the erratum have it."""
    return {3: 8, 23: 13}.get(usage, usage)


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)


def confounder_of(enctype, key, usage, ciphertext):
    """The confounder inside a ciphertext, read back with RFC 4757's own
    steps; the generator stores it so the test can encrypt the same
    bytes. Not a witness: it only reads, and what it reads is checked by
    impacket making the same ciphertext from it."""
    t = struct.pack("<I", message_type(usage))
    salt = b"fortybits\0" + t if enctype == 24 else t
    k1 = bytearray(hmac.new(key, salt, hashlib.md5).digest())
    if enctype == 24:
        k1[7:] = b"\xab" * 9
    k3 = hmac.new(bytes(k1), ciphertext[:16], hashlib.md5).digest()
    return rc4(k3, ciphertext[16:24])


def hexa(b):
    return b.hex() or "-"


class Process:
    def __init__(self, argv, env=None):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, env=env)

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()


class Mit:
    name = "mit-krb5"
    enctypes = ENCTYPES

    def __init__(self, out):
        self.conf = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        self.conf.write(WEAK_CONF)
        self.conf.close()
        env = dict(os.environ, KRB5_CONFIG=self.conf.name)
        self.p = Process([os.path.join(out, "mit-krb5")], env)

    def _ask(self, line):
        answer = self.p.ask(line)
        if answer.startswith("ERR"):
            raise ValueError(answer)
        return bytes.fromhex("" if answer == "-" else answer)

    def encrypt(self, enctype, key, usage, plain):
        return self._ask(f"encrypt {enctype} {key.hex()} {usage} {hexa(plain)}")

    def decrypt(self, enctype, key, usage, cipher):
        return self._ask(f"decrypt {enctype} {key.hex()} {usage} {hexa(cipher)}")

    def checksum(self, key, usage, data):
        return self._ask(f"mkcksum -138 23 {key.hex()} {usage} {hexa(data)}")

    def prf(self, key, data):
        return self._ask(f"prf 23 {key.hex()} {hexa(data)}")

    def s2k(self, password):
        return self._ask(f"s2k 23 {hexa(password.encode())} - -")


class Kerby:
    name = "kerby"
    enctypes = ENCTYPES

    def __init__(self, out):
        self.p = Process([os.path.join(out, "kerby")])

    def _ask(self, line):
        answer = self.p.ask(line)
        if answer.startswith("error"):
            raise ValueError(answer)
        return bytes.fromhex("" if answer == "-" else answer)

    def encrypt(self, enctype, key, usage, plain):
        return self._ask(f"encrypt {enctype} {key.hex()} {usage} {hexa(plain)}")

    def decrypt(self, enctype, key, usage, cipher):
        return self._ask(f"decrypt {enctype} {key.hex()} {usage} {hexa(cipher)}")

    def checksum(self, key, usage, data):
        return self._ask(f"checksum {key.hex()} {usage} {hexa(data)}")

    def prf(self, key, data):
        return self._ask(f"prf {key.hex()} {hexa(data)}")

    def s2k(self, password):
        return self._ask(f"s2k {hexa(password.encode())}")


class Impacket:
    """impacket's krb5/crypto.py, imported from the unpacked wheel. It has
    no type 24, and it takes the confounder rather than drawing one."""
    name = "impacket"
    enctypes = (23,)

    def __init__(self, out):
        sys.path.insert(0, os.path.join(out, "impacket"))
        self.c = importlib.import_module("impacket.krb5.crypto")
        sys.path.pop(0)

    def _key(self, key):
        return self.c.Key(23, key)

    def encrypt_with(self, key, usage, plain, confounder):
        return self.c._RC4.encrypt(self._key(key), usage, plain, confounder)

    def decrypt(self, enctype, key, usage, cipher):
        assert enctype == 23
        try:
            return self.c._RC4.decrypt(self._key(key), usage, cipher)
        except Exception as e:
            raise ValueError(f"impacket: {e}") from None

    def checksum(self, key, usage, data):
        return self.c._HMACMD5.checksum(self._key(key), usage, data)

    def prf(self, key, data):
        return self.c._RC4.prf(self._key(key), data)

    def s2k(self, password):
        return self.c._RC4.string_to_key(password, b"", None).contents


def witnesses(out):
    return Mit(out), Kerby(out), Impacket(out)


PASSWORDS = ["password", "", "Jurišić", "пароль", "\U0001f511 key", "a" * 300]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/rc4hmacwitness"
    mit, kerby, imp = witnesses(out)
    for pw in PASSWORDS:
        keys = {w.name: w.s2k(pw) for w in (mit, kerby, imp)}
        if len(set(keys.values())) != 1:
            sys.exit(f"string-to-key disagrees on {pw!r}: {keys}")
    rng = random.Random(4757)
    count = 0
    for enctype in ENCTYPES:
        for usage in (1, 2, 3, 8, 9, 13, 23, 1024):
            for length in (0, 1, 17):
                key, plain = rng.randbytes(16), rng.randbytes(length)
                for maker in (mit, kerby):
                    ct = maker.encrypt(enctype, key, usage, plain)
                    for w in (mit, kerby, imp):
                        if enctype not in w.enctypes:
                            continue
                        if w.decrypt(enctype, key, usage, ct) != plain:
                            sys.exit(f"{w.name} does not open {maker.name}'s {enctype} {usage}")
                        bad = bytearray(ct)
                        bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
                        try:
                            w.decrypt(enctype, key, usage, bytes(bad))
                            sys.exit(f"{w.name} opens a changed ciphertext")
                        except ValueError:
                            pass
                    if enctype == 23:
                        conf = confounder_of(enctype, key, usage, ct)
                        if imp.encrypt_with(key, usage, plain, conf) != ct:
                            sys.exit(f"impacket does not make {maker.name}'s ciphertext")
                    count += 1
    for usage in (1, 3, 9, 13, 23, 1024):
        key, data = rng.randbytes(16), rng.randbytes(usage % 37)
        if len({w.checksum(key, usage, data) for w in (mit, kerby, imp)}) != 1:
            sys.exit(f"the checksums disagree at usage {usage}")
        if len({w.prf(key, data) for w in (mit, kerby, imp)}) != 1:
            sys.exit("the PRFs disagree")
    print(f"rc4-hmac witnesses: string-to-key, {count} ciphertexts opened across MIT "
          f"Kerberos, Kerby and impacket, checksums and PRF agree")


if __name__ == "__main__":
    main()
