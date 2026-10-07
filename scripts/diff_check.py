#!/usr/bin/env python3
"""Run every differential corpus against an independent implementation.

The library's testing bar (docs/extending.md, "Testing checklist") is that
nothing counts as tested until it has been compared with a second
implementation over hundreds of inputs. The `tools/src/bin/diff_*.rs`
programs print those corpora; this script is the other half, and committing
it is the point — otherwise "verified against OpenSSL" is a claim in a
commit message rather than something anyone can re-run.

References used, none of them ours:

    hashlib          - the hash functions
    hmac             - HMAC
    cryptography     - OpenSSL, for the ciphers, HKDF, and the curves
    int              - Python's own arbitrary precision integers, for bignum
    written here     - where nothing on the machine has the algorithm:
                       Kuznyechik, Magma, Streebog, GOST R 34.11-94,
                       ML-KEM, ML-DSA and others, each from its standard and
                       each a second reading rather than a second opinion

Usage:

    python3 scripts/diff_check.py              # everything
    python3 scripts/diff_check.py ec ecdsa     # only those corpora

Each corpus is regenerated with `cargo run --release -p allcrypt-tools --bin ...` unless a
dump file is passed with --dump. Exits non-zero on the first mismatch, and
prints the offending line.
"""

import argparse
import fractions
import functools
import hashlib
import hmac as pyhmac
import math
import operator
import pathlib
import re
import shutil
import subprocess
import os
import sys

#: The repository root. `rfcs/` holds the documents some of the
#: references below are read out of rather than transcribed.
ROOT = pathlib.Path(__file__).resolve().parent.parent

# `scripts/rfc_oids.py` sits beside this file, and this script is run
# from the repository root - so its directory is not on the path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# --------------------------------------------------------------- helpers ---

class Mismatch(Exception):
    pass


def unhex(s):
    """Hex to bytes. "-" means empty - see the note in tools/src/bin/diff_rsa.rs."""
    return b"" if s == "-" else bytes.fromhex(s)


def bigint(s):
    """The Rust side prints BigUint as hex, with "0" for zero."""
    return int(s, 16) if s else 0


def run_example(name):
    """Regenerate a corpus. stderr carries the example's own self-checks and
    is passed through, since those are assertions too."""
    proc = subprocess.run(
        ["cargo", "run", "--release", "--quiet", "-p", "allcrypt-tools", "--bin", name],
        capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"example {name} failed")
    for line in proc.stderr.splitlines():
        if line.strip() and not line.startswith(("   ", "    ")):
            print(f"  [{name}] {line}")
    return proc.stdout.splitlines()


# ------------------------------------------------------------ hash/stream ---

HASHLIB = {
    "md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256",
    "sha384": "sha384", "sha512": "sha512",
    "sha512_224": "sha512_224", "sha512_256": "sha512_256",
    "blake2b": "blake2b", "blake2s": "blake2s",
    # Still in this OpenSSL's default provider; in 3.0 it moved to
    # `legacy` on some builds, so the day it vanishes this row
    # disappears from the check rather than failing. The unit
    # tests hold the published vectors either way.
    "ripemd160": "ripemd160",
    # SM3, GB/T 32905-2016. This OpenSSL provides it, so hashlib does -
    # a real independent opinion rather than a second reading of the
    # standard, which is more than the GOST hashes get.
    "sm3": "sm3",
    "sha3_224": "sha3_224", "sha3_256": "sha3_256",
    "sha3_384": "sha3_384", "sha3_512": "sha3_512",
}


# ------------------------------------------ pre-standard Keccak, here ---
#
# `hashlib` has SHA-3 and not the 2012 Keccak submission it came from -
# the two differ in one byte of padding, `0x06` against `0x01`. So the
# reference for the `keccak_*` rows is written here from FIPS 202's
# description of the permutation, with the original padding.
#
# The same arrangement as the GOST and Salsa20 rows, with one unusually
# good check available: `_keccak_selftest` pins it against **Ethereum
# function selectors**, which are the first four bytes of
# `keccak256(signature)` and are fixed by consensus in the ERC-20
# standard, in every block explorer and in millions of deployed
# contracts. Nothing in this repository could have influenced them.

_KECCAK_RC = []
_lfsr = 1
for _ in range(24):
    _c = 0
    for _j in range(7):
        _c |= (_lfsr & 1) << ((1 << _j) - 1)
        _feedback = _lfsr & 0x80
        _lfsr = (_lfsr << 1) & 0xff
        if _feedback:
            _lfsr ^= 0x71
    _KECCAK_RC.append(_c)

_KECCAK_RHO = [0] * 25
_x, _y = 1, 0
for _t in range(24):
    _KECCAK_RHO[_x + 5 * _y] = ((_t + 1) * (_t + 2) // 2) % 64
    _x, _y = _y, (2 * _x + 3 * _y) % 5


def _keccak_f(state):
    rotl = lambda v, n: ((v << n) | (v >> (64 - n))) & 0xffffffffffffffff
    for rc in _KECCAK_RC:
        parity = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
                  for x in range(5)]
        for x in range(5):
            d = parity[(x + 4) % 5] ^ rotl(parity[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= d
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(
                    state[x + 5 * y], _KECCAK_RHO[x + 5 * y])
        for y in range(5):
            row = [moved[x + 5 * y] for x in range(5)]
            for x in range(5):
                state[x + 5 * y] = row[x] ^ (
                    (~row[(x + 1) % 5] & 0xffffffffffffffff) & row[(x + 2) % 5])
        state[0] ^= rc
    return state


def keccak_sponge(data, rate, padding, length):
    import struct
    state = [0] * 25
    filled = 0
    def absorb(byte):
        nonlocal filled
        state[filled // 8] ^= byte << (8 * (filled % 8))
        filled += 1
        if filled == rate:
            _keccak_f(state)
            filled = 0
    for byte in data:
        absorb(byte)
    block = bytearray(rate - filled)
    block[0] = padding
    block[-1] |= 0x80
    for byte in block:
        absorb(byte)
    out = bytearray()
    while len(out) < length:
        take = min(rate, length - len(out))
        for i in range(take):
            out.append((state[i // 8] >> (8 * (i % 8))) & 0xff)
        if len(out) < length:
            _keccak_f(state)
    return bytes(out)


def _keccak_selftest():
    """Ethereum function selectors, which no library here produced."""
    def selector(signature):
        return keccak_sponge(signature, 136, 0x01, 32)[:4].hex()
    assert selector(b"transfer(address,uint256)") == "a9059cbb", \
        "the Keccak reference in this file is wrong"
    assert selector(b"balanceOf(address)") == "70a08231"
    # And SHA-3 of the same string is not the selector, which is the
    # whole point of the padding byte.
    assert keccak_sponge(b"transfer(address,uint256)", 136, 0x06, 32)[:4].hex() \
        != "a9059cbb"


_keccak_selftest()


# ------------------------------------------------- Salsa20, written here ---
#
# Nothing on a normal machine implements Salsa20 - python-cryptography
# has ChaCha20 and not its ancestor - so the reference is a second
# reading of Bernstein's specification rather than somebody else's code.
# The same arrangement as the GOST and SSLv3 rows, and the same caveat:
# this is weaker evidence than an independent implementation, which is
# why it is written from the document and not from the Rust.
#
# It is pinned to RFC 7914 section 8's published Salsa20/8 core vector by
# `_salsa_selftest` below, so a shortcut here cannot drift unnoticed.

def _salsa_quarter(x, a, b, c, d):
    rot = lambda v, n: ((v << n) | (v >> (32 - n))) & 0xffffffff
    x[b] ^= rot((x[a] + x[d]) & 0xffffffff, 7)
    x[c] ^= rot((x[b] + x[a]) & 0xffffffff, 9)
    x[d] ^= rot((x[c] + x[b]) & 0xffffffff, 13)
    x[a] ^= rot((x[d] + x[c]) & 0xffffffff, 18)


def salsa_core(block, rounds):
    """The bare permutation with the feed-forward addition."""
    import struct
    x = list(struct.unpack("<16I", block))
    start = list(x)
    for _ in range(rounds // 2):
        _salsa_quarter(x, 0, 4, 8, 12)
        _salsa_quarter(x, 5, 9, 13, 1)
        _salsa_quarter(x, 10, 14, 2, 6)
        _salsa_quarter(x, 15, 3, 7, 11)
        _salsa_quarter(x, 0, 1, 2, 3)
        _salsa_quarter(x, 5, 6, 7, 4)
        _salsa_quarter(x, 10, 11, 8, 9)
        _salsa_quarter(x, 15, 12, 13, 14)
    return struct.pack("<16I", *[(a + b) & 0xffffffff for a, b in zip(x, start)])


def salsa20(key, nonce, data, rounds=20):
    import struct
    sigma = b"expand 32-byte k"
    tau = b"expand 16-byte k"
    if len(key) == 32:
        constants, k0, k1 = sigma, key[:16], key[16:]
    else:
        constants, k0, k1 = tau, key[:16], key[:16]
    c = struct.unpack("<4I", constants)
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        state = [0] * 16
        state[0], state[5], state[10], state[15] = c
        state[1:5] = struct.unpack("<4I", k0)
        state[11:15] = struct.unpack("<4I", k1)
        state[6:8] = struct.unpack("<2I", nonce)
        state[8] = counter & 0xffffffff
        state[9] = (counter >> 32) & 0xffffffff
        out += salsa_core(struct.pack("<16I", *state), rounds)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out))


def _salsa_selftest():
    """RFC 7914 section 8's published Salsa20/8 core vector.

    Without this the reference above is only a transcription that agrees
    with itself, which is exactly the failure mode these corpora exist to
    rule out.
    """
    got = salsa_core(bytes.fromhex(
        "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d"
        "ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e"), 8)
    want = bytes.fromhex(
        "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29"
        "b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81")
    assert got == want, "the Salsa20 reference in this file is wrong"


_salsa_selftest()


# The three byte patterns the examples use. These must match the `data`,
# `key` and `iv` helpers in tools/src/bin/diff_*.rs exactly - a mismatch here
# makes every comparison fail, which is at least loud.

def corpus_data(n):
    return bytes(((i * 167 + 13) & 0xff) for i in range(n))


def keypattern(n):
    return bytes(((i * 89 + 7) & 0xff) for i in range(n))


def ivpattern(n):
    return bytes(((i * 211 + 5) & 0xff) for i in range(n))


def check_hash_stream(lines):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    _md4_selftest()
    _whirlpool_probe()
    if not _WHIRLPOOL:
        print("  [whirlpool] this OpenSSL has no whirlpool; those rows are "
              "skipped and only the vendored vectors cover it")
    else:
        print("  [whirlpool] checked against OpenSSL's legacy provider")
    checked = 0
    for line in lines:
        tag, got = line.split(" ", 1)
        parts = tag.split("/")
        algo = parts[0]

        if algo in HASHLIB:
            n = int(parts[1])
            want = hashlib.new(HASHLIB[algo], corpus_data(n)).hexdigest()
        elif algo == "whirlpool":
            # No `hashlib` and no `cryptography`, but OpenSSL's legacy
            # provider has it - so unlike MD2 this is a real second
            # opinion rather than a second reading of the spec. A
            # subprocess per length is affordable here because the hash
            # corpus has three hundred rows rather than the block
            # corpus's twelve thousand.
            if not _WHIRLPOOL:
                continue
            want = _openssl_digest("whirlpool", corpus_data(int(parts[1]))).hex()
        elif algo == "md2":
            # No independent implementation exists on this machine, so
            # the reference is a second reading of RFC 1319 written in
            # this file - the same position the GOST hashes are in.
            want = md2(corpus_data(int(parts[1]))).hex()
        elif algo == "md4":
            # Written independently here and pinned to OpenSSL's legacy
            # provider by `_md4_selftest`.
            want = md4(corpus_data(int(parts[1]))).hex()
        elif algo == "sha0":
            continue  # hashlib has no SHA-0; covered by tests/test_sha1.rs
        elif algo == "chacha20":
            n = int(parts[1])
            key = keypattern(32)
            nonce = ivpattern(12)
            # cryptography's ChaCha20 takes a 16 byte nonce: 4 byte counter
            # (little endian) followed by the 12 byte nonce, per RFC 8439.
            full_nonce = (0).to_bytes(4, "little") + nonce
            enc = Cipher(algorithms.ChaCha20(key, full_nonce), None).encryptor()
            want = (enc.update(corpus_data(n)) + enc.finalize()).hex()
        elif algo in ("blake2blen", "blake2slen"):
            size = int(parts[1])
            which = hashlib.blake2b if algo == "blake2blen" else hashlib.blake2s
            want = which(corpus_data(100), digest_size=size).hexdigest()
        elif algo in ("blake2bkey", "blake2skey"):
            key_len = int(parts[1])
            which = hashlib.blake2b if algo == "blake2bkey" else hashlib.blake2s
            size = 64 if algo == "blake2bkey" else 32
            want = which(corpus_data(100), key=keypattern(key_len),
                         digest_size=size).hexdigest()
        elif algo == "blake2bfull":
            want = hashlib.blake2b(corpus_data(100), key=keypattern(16),
                                   salt=corpus_data(16), person=keypattern(16),
                                   digest_size=64).hexdigest()
        elif algo == "blake2sfull":
            want = hashlib.blake2s(corpus_data(100), key=keypattern(16),
                                   salt=corpus_data(8), person=keypattern(8),
                                   digest_size=32).hexdigest()
        elif algo.startswith("keccak_"):
            bits = int(algo.split("_")[1])
            n = int(parts[1])
            want = keccak_sponge(corpus_data(n), 200 - 2 * (bits // 8),
                                 0x01, bits // 8).hex()
        elif algo.startswith("shake_"):
            bits = int(algo.split("_")[1])
            out_len = int(parts[1])
            which = hashlib.shake_128 if bits == 128 else hashlib.shake_256
            want = which(corpus_data(100)).hexdigest(out_len)
        elif algo in ("salsa20", "salsa12", "salsa8"):
            n = int(parts[1])
            want = salsa20(keypattern(32), ivpattern(8), corpus_data(n),
                           int(algo[5:])).hex()
        elif algo == "salsa20short":
            n = int(parts[1])
            want = salsa20(keypattern(16), ivpattern(8), corpus_data(n)).hex()
        elif algo == "chacha20stream":
            continue  # streaming equivalence, checked inside the example
        elif algo == "rc4":
            keylen, n = int(parts[1]), int(parts[2])
            want = rc4(keypattern(keylen), corpus_data(n)).hex()
        elif algo == "zipcrypto-dec":
            # CPython's zipfile decrypts traditional PKWARE encryption
            # (and cannot encrypt).
            import zipfile
            pwlen, n = int(parts[1]), int(parts[2])
            want = zipfile._ZipDecrypter(keypattern(pwlen))(corpus_data(n)).hex()
        elif algo == "zipcrypto-enc":
            # Encryption is checked by decrypting ours back: the plaintext
            # must come out, which it cannot if the keys absorbed the
            # wrong byte.
            import zipfile
            pwlen, n = int(parts[1]), int(parts[2])
            back = zipfile._ZipDecrypter(keypattern(pwlen))(bytes.fromhex(got))
            if back != corpus_data(n):
                raise Mismatch(f"{tag}: zipfile does not decrypt ours to the plaintext")
            want = got
        else:
            # **Not `continue`.** This was a silent skip, so a row whose
            # name did not match anything here vanished from the check
            # and only made the total smaller - and the total is a
            # number nobody remembers. The rows that genuinely have no
            # reference (`sha0`, `chacha20stream`) say so by name above;
            # anything else is a corpus and a checker that have drifted
            # apart, which is the failure this whole script exists to
            # prevent.
            raise Mismatch(f"corpus row {tag!r} has no checker. Either add "
                           f"one or name it as a deliberate skip.")

        if got != want:
            raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
        checked += 1
    return checked


# ------------------------------------------------------- MD2 and MD4 ---
#
# Neither is in `hashlib` and neither is in `cryptography`. OpenSSL 3
# still has MD4 behind the `legacy` provider, so that is a real
# independent opinion; **MD2 has none on this machine at all**, which
# puts it in the same position as the GOST hashes - the reference is a
# second reading of the specification, written here.
#
# Two rules follow from that, and they are the ones `_kuz_selftest`
# taught this file:
#
# 1. The Python MD4 below is *typed from RFC 1320* - a genuinely
#    separate transcription from the Rust one, which parses its tables
#    out of the document. Two independent readings that agree is the
#    whole point, so do not "simplify" this by sharing a table.
# 2. It is pinned to OpenSSL at import time by `_md4_selftest`, across
#    the padding boundary, so a typo here fails immediately and loudly
#    rather than making every corpus row disagree.
#
# MD2 gets no such pin. What it gets instead is a **different parser
# over the same document** for the permutation, because 256 numbers
# typed by hand with nothing to check them against is exactly the
# mistake this repository keeps making.

_RFC_1319 = (ROOT / "rfcs" / "rfc1319.txt").read_text(encoding="utf-8")

#: Whether this OpenSSL still has Whirlpool. Decided once, and printed,
#: because a check that quietly disappears is a hole that looks like a
#: pass - and OpenSSL 3 already moved this one to the legacy provider.
_WHIRLPOOL = None


def _md2_pi():
    """RFC 1319's PI_SUBST, read out of the appendix.

    `src/hash_functions/md2.rs` parses the same table with a `const fn`
    that works line by line; this one works on the whole block. Two
    parsers written differently agreeing on 256 bytes says something
    about the parse that either one alone does not.
    """
    start = _RFC_1319.index("static unsigned char PI_SUBST[256] = {")
    body = _RFC_1319[start + len("static unsigned char PI_SUBST[256] = {"):]
    body = body[:body.index("};")]
    table = []
    for line in body.split("\n"):
        # Page furniture carries letters or brackets; a table row is
        # digits, commas and spaces. Same discriminator as the Rust
        # parser, reached from the other end.
        if not line.strip() or not re.fullmatch(r"[\d,\s]+", line):
            continue
        table.extend(int(value) for value in re.findall(r"\d+", line))
    if len(table) != 256:
        raise Mismatch(f"RFC 1319's PI_SUBST parsed to {len(table)} entries")
    if sorted(table) != list(range(256)):
        raise Mismatch("RFC 1319's PI_SUBST did not parse to a permutation")
    return table


_MD2_PI = _md2_pi()


def md2(message):
    """MD2, from RFC 1319 sections 3.1 to 3.5.

    The checksum follows the RFC's **reference code**, which
    XOR-assigns where the prose assigns - see `CHECKSUM_DISAGREEMENT`
    in `src/hash_functions/md2.rs` and RFC 6149. Writing the prose
    version here would make this disagree with the Rust for every
    message longer than one block, which is at least loud.
    """
    pad = 16 - (len(message) % 16)
    message = bytes(message) + bytes([pad]) * pad

    checksum = bytearray(16)
    for at in range(0, len(message), 16):
        t = checksum[15]
        for i in range(16):
            checksum[i] ^= _MD2_PI[message[at + i] ^ t]
            t = checksum[i]

    state = bytearray(48)
    for block in [message[at:at + 16] for at in range(0, len(message), 16)] \
            + [bytes(checksum)]:
        for i in range(16):
            state[16 + i] = block[i]
            state[32 + i] = block[i] ^ state[i]
        t = 0
        for round_number in range(18):
            for j in range(48):
                state[j] ^= _MD2_PI[t]
                t = state[j]
            t = (t + round_number) & 0xff
    return bytes(state[:16])


def md4(message):
    """MD4, from RFC 1320 section 3.4.

    The three round tables are **typed here on purpose**: the Rust side
    reads them out of the document, so a disagreement means one of the
    two readings is wrong, which is what a differential check is for.
    `_md4_selftest` says which by bringing OpenSSL in as a third party.
    """
    def f(x, y, z): return (x & y) | (~x & 0xffffffff) & z
    def g(x, y, z): return (x & y) | (x & z) | (y & z)
    def h(x, y, z): return x ^ y ^ z
    def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff

    message = bytes(message)
    bits = len(message) * 8
    message += b"\x80"
    while len(message) % 64 != 56:
        message += b"\x00"
    message += bits.to_bytes(8, "little")

    a, b_, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    # The three round tables, typed from RFC 1320 3.4. Round 3's message
    # order is the one everybody gets wrong; it is written out rather
    # than generated so that a reader can check it against the document
    # line by line.
    def table(order, rotations):
        return [(k, rotations[i % 4]) for i, k in enumerate(order)]

    round1 = table(list(range(16)), [3, 7, 11, 19])
    round2 = table([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
                   [3, 5, 9, 13])
    round3 = table([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
                   [3, 9, 11, 15])
    for name, order in (("1", round1), ("2", round2), ("3", round3)):
        if sorted(k for k, _ in order) != list(range(16)):
            raise Mismatch(f"MD4 round {name} does not use each word once")

    for at in range(0, len(message), 64):
        block = message[at:at + 64]
        x = [int.from_bytes(block[i * 4:i * 4 + 4], "little")
             for i in range(16)]
        aa, bb, cc, dd = a, b_, c, d
        registers = [a, b_, c, d]
        for table, mix, add in ((round1, f, 0),
                                (round2, g, 0x5a827999),
                                (round3, h, 0x6ed9eba1)):
            for i, (k, s) in enumerate(table):
                target = [0, 3, 2, 1][i % 4]
                p, q, r = (target + 1) % 4, (target + 2) % 4, (target + 3) % 4
                registers[target] = rotl(
                    (registers[target]
                     + mix(registers[p], registers[q], registers[r])
                     + x[k] + add) & 0xffffffff, s)
        a = (aa + registers[0]) & 0xffffffff
        b_ = (bb + registers[1]) & 0xffffffff
        c = (cc + registers[2]) & 0xffffffff
        d = (dd + registers[3]) & 0xffffffff

    return b"".join(word.to_bytes(4, "little") for word in (a, b_, c, d))


def _openssl_digest(name, data):
    """One digest from the `openssl` binary, or None if this build has
    no such algorithm. The legacy provider is asked for explicitly,
    because OpenSSL 3 moved MD4 and Whirlpool there."""
    try:
        done = subprocess.run(
            ["openssl", "dgst", f"-{name}", "-provider", "legacy",
             "-provider", "default", "-binary"],
            input=data, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout


def _whirlpool_available():
    return _openssl_digest("whirlpool", b"") is not None


def _openssl_md4(data):
    """OpenSSL's MD4, from the legacy provider, or None if this build
    has none. Kept to the self-test rather than used per row, because a
    subprocess for each of three hundred lengths is slow enough that
    somebody would shrink the corpus to fit it - which is how
    `diff_check`'s Kuznyechik row ended up sweeping nothing."""
    try:
        done = subprocess.run(
            ["openssl", "dgst", "-md4", "-provider", "legacy",
             "-provider", "default", "-binary"],
            input=data, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout


def _whirlpool_probe():
    global _WHIRLPOOL
    if _WHIRLPOOL is None:
        _WHIRLPOOL = _whirlpool_available()
    return _WHIRLPOOL


def _md4_selftest():
    """Pin the MD4 above to OpenSSL, across the padding boundary.

    Reports which reference is in play rather than skipping silently: a
    check that disappears is a hole that looks like a pass, and the
    difference between "agrees with OpenSSL" and "agrees with a second
    reading of the RFC" is exactly what a reader of this script's output
    wants to know.
    """
    lengths = [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 200]
    available = _openssl_md4(b"") is not None
    if not available:
        print("  [md4] this OpenSSL has no legacy MD4; the md4 rows are "
              "checked against a second reading of RFC 1320 only")
        return
    for n in lengths:
        data = corpus_data(n)
        theirs = _openssl_md4(data)
        if md4(data) != theirs:
            raise Mismatch(
                f"the MD4 written in this script disagrees with OpenSSL at "
                f"{n} bytes: {md4(data).hex()} vs {theirs.hex()}")
    print(f"  [md4] pinned to OpenSSL's legacy provider at "
          f"{len(lengths)} lengths")


def rc4(key, data):
    """RC4 in five lines, from RFC 6229's description. OpenSSL has dropped
    RC4 in most builds, and writing the reference out is safer than skipping
    the check - this is short enough to be obviously right."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)


# --------------------------------------------------------------- mac/kdf ---

def check_mac_kdf(lines):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    HASHES = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
              "sha512": hashes.SHA512()}
    checked = 0
    for line in lines:
        tag, got = line.split(" ", 1)
        parts = tag.split("/")

        if parts[0] == "hmac":
            algo, keylen, n = parts[1], int(parts[2]), int(parts[3])
            if algo not in HASHLIB:
                continue
            want = pyhmac.new(keypattern(keylen), corpus_data(n),
                              HASHLIB[algo]).hexdigest()
        elif parts[0] == "pbkdf2":
            # pbkdf2/<hash>/<password length>/<salt length>/<c>/<dklen>
            algo = parts[1]
            pwlen, saltlen = int(parts[2]), int(parts[3])
            iterations, dklen = int(parts[4]), int(parts[5])
            if algo not in HASHLIB:
                continue
            # hashlib's, which is OpenSSL's, and entirely independent of
            # anything in this repository.
            want = hashlib.pbkdf2_hmac(algo, keypattern(pwlen),
                                       corpus_data(saltlen), iterations,
                                       dklen).hex()
        elif parts[0] == "scrypt":
            n, r, pp, dklen = (int(parts[1]), int(parts[2]),
                               int(parts[3]), int(parts[4]))
            want = hashlib.scrypt(keypattern(13), salt=corpus_data(17),
                                  n=n, r=r, p=pp, dklen=dklen,
                                  maxmem=1 << 27).hex()
        elif parts[0] == "argon2id":
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            memory, passes, lanes, dklen = (int(parts[1]), int(parts[2]),
                                            int(parts[3]), int(parts[4]))
            want = Argon2id(salt=corpus_data(16), length=dklen,
                            iterations=passes, lanes=lanes,
                            memory_cost=memory).derive(keypattern(13)).hex()
        elif parts[0] in ("hkdf", "hkdfnosalt"):
            algo, length = parts[1], int(parts[2])
            if algo not in HASHES:
                continue
            salt = None if parts[0] == "hkdfnosalt" else keypattern(13)
            kdf = HKDF(algorithm=HASHES[algo], length=length, salt=salt,
                       info=corpus_data(10))
            want = kdf.derive(corpus_data(22)).hex()
        elif parts[0] == "hkdfextract":
            # HKDF-Extract is HMAC keyed by the salt (RFC 5869 2.2).
            # This row was skipped by a bare `continue` until the checker
            # started refusing rows it does not know.
            want = pyhmac.new(keypattern(13), corpus_data(22), "sha256").hexdigest()
        elif parts[0] in ("kbkdfctr", "kbkdffb"):
            # kbkdf<mode>/<prf>/<key len>/<label len>/<context len>[/<iv len>]/<length>
            prf, kl, ll, cl, n = parts[1], int(parts[2]), int(parts[3]), int(parts[4]), \
                int(parts[-1])
            key, label, context = keypattern(kl), corpus_data(ll), corpus_data(cl + 50)[50:]
            kind, name = prf.split("-", 1)
            if parts[0] == "kbkdfctr":
                from cryptography.hazmat.primitives.kdf.kbkdf import (
                    KBKDFCMAC, KBKDFHMAC, CounterLocation, Mode)
                from cryptography.hazmat.primitives.ciphers import algorithms
                if kind == "hmac":
                    kdf = KBKDFHMAC(getattr(hashes, name.upper())(), Mode.CounterMode, n, 4, 4,
                                    CounterLocation.BeforeFixed, label, context, None)
                else:
                    kdf = KBKDFCMAC(algorithms.AES, Mode.CounterMode, n, 4, 4,
                                    CounterLocation.BeforeFixed, label, context, None)
                want = kdf.derive(key).hex()
            else:
                algorithm = name.upper() if kind == "hmac" else f"AES-{kl * 8}-CBC"
                iv_len = int(parts[5])
                want = openssl_kbkdf("FEEDBACK", kind.upper(), algorithm, key, label,
                                     context, corpus_data(iv_len) if iv_len else None, n).hex()
        elif parts[0] in ("concat", "x963"):
            from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
            from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
            name, zl, il, n = parts[1], int(parts[2]), int(parts[3]), int(parts[4])
            algorithm = getattr(hashes, name.upper())()
            kind = ConcatKDFHash if parts[0] == "concat" else X963KDF
            want = kind(algorithm, n, corpus_data(il)).derive(keypattern(zl)).hex()
        elif parts[0] == "s2k":
            # RFC 9580 3.7.1.3, written as the definition reads: the whole
            # repeated string built, then hashed; a further context per
            # digest, preloaded with that many zero octets.
            name, pl, sl, count, n = parts[1], *map(int, parts[2:])
            unit = corpus_data(sl) + keypattern(pl)
            total = max(count, len(unit))
            string = (unit * (total // len(unit) + 1))[:total] if unit else b""
            out, preload = b"", 0
            while len(out) < n:
                out += hashlib.new(name, bytes(preload) + string).digest()
                preload += 1
            want = out[:n].hex()
        elif parts[0] == "7zkey":
            # 7-Zip's 7zAes.cpp: SHA-256 of (salt, password, round as
            # UInt64 little endian) for every round; 0x3f is the raw key.
            pl, sl, cycles = map(int, parts[1:])
            salt, password = corpus_data(sl), keypattern(pl)
            if cycles == 0x3f:
                want = (salt + password)[:32].ljust(32, b"\0").hex()
            else:
                h = hashlib.sha256()
                for i in range(1 << cycles):
                    h.update(salt + password + i.to_bytes(8, "little"))
                want = h.hexdigest()
        elif parts[0] == "keepass":
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            enc = Cipher(algorithms.AES(corpus_data(32)), modes.ECB()).encryptor()
            block = keypattern(32)
            for _ in range(int(parts[1])):
                block = enc.update(block)
            want = hashlib.sha256(block).hexdigest()
        elif parts[0] in ("afmerge", "afsplit"):
            # LUKS1 on-disk format 2.4, AFmerge and AFsplit.
            name, kl, stripes = parts[1], int(parts[2]), int(parts[3])
            size = hashlib.new(name).digest_size

            def diffuse(block):
                pieces = [block[i:i + size] for i in range(0, len(block), size)]
                return b"".join(hashlib.new(name, i.to_bytes(4, "big") + p).digest()[:len(p)]
                                for i, p in enumerate(pieces))

            if parts[0] == "afmerge":
                stripes_ = corpus_data(kl * stripes + 5)
                target = stripes_[(stripes - 1) * kl:stripes * kl]
            else:
                stripes_ = corpus_data(kl * (stripes - 1))
                target = keypattern(kl)
            d = bytes(kl)
            for j in range(stripes - 1):
                d = diffuse(bytes(a ^ b for a, b in zip(d, stripes_[j * kl:(j + 1) * kl])))
            want = bytes(a ^ b for a, b in zip(d, target)).hex()
        elif parts[0] in ("cbcmac", "cbcmaczero"):
            # cbcmac/<cipher>/<key length>/<zero|iv>/<length>: the last
            # block of OpenSSL's CBC encryption, after zero padding for
            # the `cbcmaczero` rows.
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit
            name, keylen, which, n = parts[1], int(parts[2]), parts[3], int(parts[4])
            key = keypattern(keylen)
            algo = {"des": lambda: decrepit.TripleDES(key * 3),
                    "3des": lambda: decrepit.TripleDES(key),
                    "aes": lambda: algorithms.AES(key)}[name]()
            bs = algo.block_size // 8
            iv = bytes(bs) if which == "zero" else corpus_data(bs + 3)[3:]
            data = corpus_data(n)
            if parts[0] == "cbcmaczero":
                data += bytes(-len(data) % bs) if data else bytes(bs)
            enc = Cipher(algo, modes.CBC(iv)).encryptor()
            want = (enc.update(data) + enc.finalize())[-bs:].hex()
        else:
            # The TLS PRFs have no OpenSSL entry point; they are checked in
            # tests against vectors derived from RFC 5246 and 2246.
            if not parts[0].startswith("prf"):
                raise Mismatch(f"corpus row {tag!r} has no checker")
            continue

        if got != want:
            raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
        checked += 1
    return checked


# ---------------------------------------------------------------- bignum ---

def check_bignum(lines):
    checked = 0
    for line in lines:
        parts = line.split()
        op = parts[0]

        if op in ("add", "mul", "sub", "div", "rem", "gcd", "inv", "cmp"):
            a, b, result = bigint(parts[1]), bigint(parts[2]), parts[3]
        elif op in ("shl", "shr"):
            a, shift, result = bigint(parts[1]), int(parts[2]), parts[3]
        elif op == "bitlen":
            a, result = bigint(parts[1]), parts[3]
        elif op in ("modpow", "modmul", "modadd", "modsub"):
            a, b, m, result = (bigint(parts[1]), bigint(parts[2]),
                               bigint(parts[3]), parts[4])
        else:
            continue

        import math
        if op == "add":
            want = a + b
        elif op == "mul":
            want = a * b
        elif op == "sub":
            want = a - b
        elif op == "div":
            want = a // b
        elif op == "rem":
            want = a % b
        elif op == "gcd":
            want = math.gcd(a, b)
        elif op == "inv":
            try:
                want = pow(a, -1, b)
            except ValueError:
                want = None
        elif op == "cmp":
            want = None
        elif op == "shl":
            want = a << shift
        elif op == "shr":
            want = a >> shift
        elif op == "bitlen":
            want = a.bit_length()
        elif op == "modpow":
            want = pow(a, b, m)
        elif op == "modmul":
            want = (a * b) % m
        elif op == "modadd":
            want = (a + b) % m
        elif op == "modsub":
            want = (a - b) % m

        if op == "cmp":
            expect = {1: "gt", -1: "lt", 0: "eq"}[(a > b) - (a < b)]
            ok = result == expect
            want = expect
        elif op == "bitlen":
            ok = int(result) == want
        elif op == "inv" and want is None:
            ok = result == "none"
            want = "none"
        else:
            ok = bigint(result) == want
            want = hex(want)[2:]

        if not ok:
            raise Mismatch(f"{line}\n  ref : {want}")
        checked += 1
    return checked


# -------------------------------------------------------------------- ec ---

def _curves():
    from cryptography.hazmat.primitives.asymmetric import ec
    return {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
            "secp256k1": ec.SECP256K1()}



# The GOST curves, which `cryptography` does not have. Short Weierstrass,
# so the arithmetic below is the textbook one - written out because a row
# in the corpus that nothing can check counts towards the total and proves
# nothing.
#
# The parameters are from the gost-engine project and are *verified here*
# rather than trusted: `_gost_curve` checks that G is on the curve and
# that n*G is the identity, which between them pin down every one of p, a,
# b, Gx, Gy and n.
_GOST_CURVE_PARAMS = {
    "gost256-a": dict(
        p="fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
        a="fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94",
        b="a6",
        n="ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893",
        x="1",
        y="8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"),
    "gost256-b": dict(
        p="8000000000000000000000000000000000000000000000000000000000000c99",
        a="8000000000000000000000000000000000000000000000000000000000000c96",
        b="3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b",
        n="800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f",
        x="1",
        y="3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc"),
    "gost256-c": dict(
        p="9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b",
        a="9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598",
        b="805a",
        n="9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9",
        x="0",
        y="41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67"),
    "gost512-a": dict(
        p="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
        a="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4",
        b="e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265"
          "ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760",
        n="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          "27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
        x="3",
        y="7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921"
          "df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4"),
    # The two cofactor-four sets, whose Weierstrass form RFC 7836 gives
    # alongside the twisted Edwards one. `h` is here because these are
    # the only curves in this file where it is not one, and the ladder
    # below has to reject a point outside the prime order subgroup the
    # same way the Rust does.
    "gost256-tc26-a": dict(
        p="fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
        a="c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335",
        b="295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513",
        n="400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67",
        h=4,
        x="91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28",
        y="32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c"),
    "gost512-c": dict(
        p="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
        a="dc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e1430645"
          "46e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3",
        b="b4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade0"
          "38cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1",
        n="3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          "c98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed",
        h=4,
        x="e2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043a"
          "a27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148",
        y="f5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9b"
          "e18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f"),
    "gost512-b": dict(
        p="8000000000000000000000000000000000000000000000000000000000000000"
          "000000000000000000000000000000000000000000000000000000000000006f",
        a="8000000000000000000000000000000000000000000000000000000000000000"
          "000000000000000000000000000000000000000000000000000000000000006c",
        b="687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b289f"
          "3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c5140116",
        n="8000000000000000000000000000000000000000000000000000000000000001"
          "49a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd",
        x="2",
        y="1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec7335"
          "dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41bd"),
}


class _Weierstrass:
    """y^2 = x^3 + ax + b over GF(p), with the identity as None."""

    def __init__(self, name, params):
        self.name = name
        self.p = int(params["p"], 16)
        self.a = int(params["a"], 16) % self.p
        self.b = int(params["b"], 16) % self.p
        self.n = int(params["n"], 16)
        self.h = params.get("h", 1)
        self.g = (int(params["x"], 16), int(params["y"], 16))
        self.size = (self.p.bit_length() + 7) // 8

        # Not trusted on sight: these two facts pin down every parameter.
        if not self.on_curve(self.g):
            raise Mismatch(f"{name}: G is not on the curve, so a parameter "
                           f"in this file is wrong")
        if self.mul(self.n, self.g) is not None:
            raise Mismatch(f"{name}: n*G is not the identity, so n or G is wrong")

    def on_curve(self, point):
        x, y = point
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, first, second):
        if first is None:
            return second
        if second is None:
            return first
        if first[0] == second[0] and (first[1] + second[1]) % self.p == 0:
            return None
        if first == second:
            slope = ((3 * first[0] * first[0] + self.a)
                     * pow(2 * first[1], -1, self.p)) % self.p
        else:
            slope = ((second[1] - first[1])
                     * pow(second[0] - first[0], -1, self.p)) % self.p
        x = (slope * slope - first[0] - second[0]) % self.p
        return (x, (slope * (first[0] - x) - first[1]) % self.p)

    def mul(self, scalar, point):
        result, addend = None, point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1
        return result

    def uncompressed(self, point):
        return (b"\x04" + point[0].to_bytes(self.size, "big")
                + point[1].to_bytes(self.size, "big"))

    def compressed(self, point):
        return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(self.size, "big")


# sm2p256v1, GB/T 32918.5-2017. `cryptography` refuses this curve - it
# raises "Curve 1.2.156.10197.1.301 is not supported" - so the rows for
# it go through the same textbook arithmetic as the GOST ones, and are a
# second reading rather than somebody else's code.
#
# **The real independent check on SM2 is elsewhere**, in
# `pytests/test_sm2.py`, which drives the `openssl` binary and exchanges
# signatures and ciphertexts with it in both directions. These rows
# cover the plain scalar multiplication and encoding that file does not
# reach; the parameters are the ones `scripts/make_sm2_curve.py` prints
# out of OpenSSL, which is also where `curves.rs` got them, so the two
# are one source rather than two typings. `_gost_curve` verifies them
# anyway - G on the curve, n*G the identity.
_GOST_CURVE_PARAMS["sm2p256v1"] = dict(
    p="fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
    a="fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
    b="28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
    n="fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
    x="32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
    y="bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")

_GOST_CURVES = {}


def _gost_curve(name):
    if name not in _GOST_CURVES:
        _GOST_CURVES[name] = _Weierstrass(name, _GOST_CURVE_PARAMS[name])
    return _GOST_CURVES[name]


def check_ec(lines):
    """Scalar multiplication, point encoding and ECDH against OpenSSL.

    The ECDH rows also settle a *convention* the arithmetic cannot:
    python-cryptography's `exchange` returns the x coordinate padded to
    the field width, leading zeros and all, which is what RFC 4492 5.10
    requires and the opposite of the finite-field rule in RFC 5246
    8.1.2. A row whose secret starts with 0x00 is the only kind that
    can tell the two apart, and one random pair in 256 has one - so
    `tools/src/bin/diff_ec.rs` searches for them rather than waiting, and
    this counts them. None found means the search stopped working and
    the rows went quiet, which is worse than their being absent.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    curves = _curves()
    checked = 0
    zero_led_secrets = 0
    for line in lines:
        parts = line.split()
        op, name = parts[0], parts[1]

        # OpenSSL for the curves it has; the arithmetic above for the GOST
        # ones, which it does not. A curve with neither is an error rather
        # than a skipped row - a corpus row nothing checks counts towards
        # the total and proves nothing.
        if name in curves:
            curve = curves[name]
            if op in ("mulg", "comp"):
                k, got = bigint(parts[2]), parts[3]
                reference = ec.derive_private_key(k, curve).public_key()
                fmt = (serialization.PublicFormat.CompressedPoint if op == "comp"
                       else serialization.PublicFormat.UncompressedPoint)
                want = reference.public_bytes(
                    encoding=serialization.Encoding.X962, format=fmt).hex()
            elif op == "ecdh":
                da, db, got = bigint(parts[2]), bigint(parts[3]), parts[4]
                a = ec.derive_private_key(da, curve)
                b = ec.derive_private_key(db, curve)
                want = a.exchange(ec.ECDH(), b.public_key()).hex()
                if want.startswith("00"):
                    zero_led_secrets += 1
            else:
                continue
        elif name in _GOST_CURVE_PARAMS:
            reference = _gost_curve(name)
            if op in ("mulg", "comp"):
                k, got = bigint(parts[2]), parts[3]
                point = reference.mul(k, reference.g)
                want = (reference.compressed(point) if op == "comp"
                        else reference.uncompressed(point)).hex()
            elif op == "ecdh":
                da, db, got = bigint(parts[2]), bigint(parts[3]), parts[4]
                shared = reference.mul(da, reference.mul(db, reference.g))
                want = shared[0].to_bytes(reference.size, "big").hex()
                if want.startswith("00"):
                    zero_led_secrets += 1
            else:
                continue
        else:
            raise Mismatch(f"no reference for curve {name!r}: neither OpenSSL "
                           f"nor this file has it, so the row cannot be checked")

        if got != want:
            raise Mismatch(f"{op} {name}\n  ours: {got}\n  ref : {want}")
        checked += 1

    if zero_led_secrets == 0:
        raise Mismatch(
            "no ECDH shared secret in the corpus begins with a zero byte, "
            "so nothing here distinguishes 'pad to the field width' from "
            "'strip the leading zeros' - the two rules TLS uses for the "
            "two Diffie-Hellman families, one of which is a one-in-256 "
            "interoperability failure when applied to the other")
    return checked


def check_x25519(lines):
    """X25519 against OpenSSL, over inputs nobody wrote down.

    `cryptography` clamps the private key and ignores the u coordinate's
    top bit exactly as RFC 7748 says, so its `exchange` is directly
    comparable with our raw primitive - including for the rows where the
    "public key" is an arbitrary 32 byte string that lands on the twist.
    Those rows are the ones that catch an implementation which validates
    the u coordinate: it would refuse input the specification requires it
    to accept, and interoperate until the day a peer sends one.

    The all-zero result is the one case where the two differ, and by
    design: `cryptography` raises rather than returning it, so the checker
    asserts that we produced zero where it refused.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)

    base = bytes([9] + [0] * 31)
    checked = 0
    twisted = 0
    for line in lines:
        parts = line.split()
        op = parts[0]

        if op == "clamp":
            # A statement about our own function, checked here so the
            # claim lives with the rest of the corpus: a scalar and its
            # clamped form are the same key.
            scalar, clamped = unhex(parts[1]), unhex(parts[2])
            if clamped[0] & 7 or clamped[31] & 128 or not clamped[31] & 64:
                raise Mismatch(f"clamp produced {clamped.hex()}, which is "
                               f"not clamped")
            key = X25519PrivateKey.from_private_bytes(scalar)
            want = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            other = X25519PrivateKey.from_private_bytes(clamped)
            if other.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw) != want:
                raise Mismatch("a scalar and its clamped form gave different "
                               "public keys in OpenSSL")
            checked += 1
            continue

        if op == "pub":
            scalar, got = unhex(parts[1]), parts[2]
            point = base
        elif op in ("dh", "raw"):
            scalar, point, got = unhex(parts[1]), unhex(parts[2]), parts[3]
        else:
            continue

        key = X25519PrivateKey.from_private_bytes(scalar)
        try:
            want = key.exchange(X25519PublicKey.from_public_bytes(point)).hex()
        except ValueError:
            # OpenSSL refuses to return an all-zero secret. So do we, at
            # the key exchange level - the corpus is the raw primitive,
            # which is where the zero is visible.
            if got != "00" * 32:
                raise Mismatch(f"{op}: OpenSSL refused the exchange as "
                               f"degenerate but we returned {got}")
            twisted += 1
            checked += 1
            continue

        if got != want:
            raise Mismatch(f"{op} {parts[1]} {hexof(point)}\n"
                           f"  ours: {got}\n  ref : {want}")
        checked += 1
    return checked


def check_x448(lines):
    """X448 against OpenSSL, over inputs nobody wrote down.

    Same arrangement as `check_x25519`, and the differences are the
    reason this is a second function rather than a parameter on that one:

      * **56 bytes everywhere**, so the degenerate answer is `"00" * 56`.
        Writing 32 here would make every low-order row pass by never
        matching, which is the failure a shared function invites.
      * **Two low bits and bit 447** in the clamp check, where X25519 has
        three low bits, bit 254 set and bit 255 clear. Curve448's
        cofactor is 4 rather than 8, and the field is a whole number of
        bytes so there is no bit above the top one to clear. A clamped
        scalar is a valid scalar under either rule, so a check copied
        from the other function would pass on a wrong clamp.
      * **No spare high bit.** X25519's corpus sets it on some rows to
        exercise the "ignore it" rule; there is no such bit here, and the
        equivalent - a coordinate at or above p - has to be constructed,
        which `diff_x448.rs` does and asserts the count of.

    `cryptography` clamps the private key exactly as RFC 7748 says, so
    its `exchange` is directly comparable with our raw primitive,
    including on the rows whose "public key" is an arbitrary 56 byte
    string that lands on the twist. Those are the rows that catch an
    implementation which validates the u coordinate: it would refuse
    input the specification requires it to accept, and interoperate
    until the day a peer sends one.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x448 import (
        X448PrivateKey, X448PublicKey)

    base = bytes([5] + [0] * 55)
    checked = 0
    twisted = 0
    for line in lines:
        parts = line.split()
        op = parts[0]

        if op == "clamp":
            scalar, clamped = unhex(parts[1]), unhex(parts[2])
            if len(clamped) != 56:
                raise Mismatch(f"a clamped X448 scalar is 56 bytes, got "
                               f"{len(clamped)}")
            if clamped[0] & 3 or not clamped[55] & 128:
                raise Mismatch(f"clamp produced {clamped.hex()}, which is not "
                               f"clamped the X448 way - two low bits cleared "
                               f"and bit 447 set")
            key = X448PrivateKey.from_private_bytes(scalar)
            want = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            other = X448PrivateKey.from_private_bytes(clamped)
            if other.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw) != want:
                raise Mismatch("a scalar and its clamped form gave different "
                               "public keys in OpenSSL")
            checked += 1
            continue

        if op == "pub":
            scalar, got = unhex(parts[1]), parts[2]
            point = base
        elif op in ("dh", "raw"):
            scalar, point, got = unhex(parts[1]), unhex(parts[2]), parts[3]
        else:
            continue

        key = X448PrivateKey.from_private_bytes(scalar)
        try:
            want = key.exchange(X448PublicKey.from_public_bytes(point)).hex()
        except ValueError:
            # OpenSSL refuses to return an all-zero secret. So do we, at
            # the key exchange level - the corpus is the raw primitive,
            # which is where the zero is visible.
            if got != "00" * 56:
                raise Mismatch(f"{op}: OpenSSL refused the exchange as "
                               f"degenerate but we returned {got}")
            twisted += 1
            checked += 1
            continue

        if got != want:
            raise Mismatch(f"{op} {parts[1]} {hexof(point)}\n"
                           f"  ours: {got}\n  ref : {want}")
        checked += 1

    if twisted == 0:
        raise Mismatch("no row produced the degenerate all-zero secret, so "
                       "the low-order points are not in the corpus")
    return checked


def hexof(value):
    return value.hex() if isinstance(value, (bytes, bytearray)) else value


def check_dh(lines):
    """Finite-field Diffie-Hellman against two independent references.

    Python's own `pow(g, x, p)` checks the arithmetic; python-cryptography's
    DH exchange checks the *convention*, which is the part that cannot be
    derived from first principles. OpenSSL pads the shared secret to the
    width of the modulus, we pad it too, and TLS 1.2 then strips the zeros
    again - three rules that only interoperate if all three are right, and
    a mismatch shows up roughly one handshake in 256 rather than always.

    The small-prime rows in the corpus exist to make that one-in-256 a
    routine occurrence: with a 192 bit modulus, a secret short enough to
    need padding turns up constantly.
    """
    from cryptography.hazmat.primitives.asymmetric import dh

    checked = 0
    padded_secrets = 0
    for line in lines:
        parts = line.split()
        op = parts[0]
        if op == "pub":
            _label, p_hex, g_hex, x_hex, got = parts[1:6]
            p_value, g_value, x = bigint(p_hex), bigint(g_hex), bigint(x_hex)
            width = (p_value.bit_length() + 7) // 8
            want = pow(g_value, x, p_value).to_bytes(width, "big").hex()
        elif op == "dh":
            _label, p_hex, g_hex, a_hex, b_hex, got = parts[1:7]
            p_value, g_value = bigint(p_hex), bigint(g_hex)
            a, b = bigint(a_hex), bigint(b_hex)
            width = (p_value.bit_length() + 7) // 8
            secret = pow(pow(g_value, b, p_value), a, p_value)
            want = secret.to_bytes(width, "big").hex()
            if want.startswith("00"):
                padded_secrets += 1

            # And the same exchange through OpenSSL, for the groups it will
            # accept. It refuses a modulus this small for a real exchange,
            # so this arm runs on the standard groups only - which is fine,
            # because what it is checking is the padding convention and
            # that does not depend on the size.
            if p_value.bit_length() >= 1024:
                parameters = dh.DHParameterNumbers(p_value, g_value)
                side_a = dh.DHPrivateNumbers(
                    a, dh.DHPublicNumbers(pow(g_value, a, p_value), parameters))
                public_b = dh.DHPublicNumbers(pow(g_value, b, p_value), parameters)
                openssl = side_a.private_key().exchange(public_b.public_key())
                if openssl.hex() != want:
                    raise Mismatch(f"dh: OpenSSL and Python disagree, which "
                                   f"means this checker is wrong\n"
                                   f"  openssl: {openssl.hex()}\n"
                                   f"  python : {want}")
        else:
            continue

        if got != want:
            raise Mismatch(f"{op}\n  ours: {got}\n  ref : {want}")
        checked += 1

    # A corpus that never produced a short secret would test the padding
    # rule not at all while looking like it did.
    if padded_secrets == 0:
        raise Mismatch("no shared secret in the corpus needed padding, so "
                       "the padding rule was never exercised")
    return checked


def check_ecdsa(lines):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    curves = _curves()
    HASHES = {"sha1": hashes.SHA1(), "sha224": hashes.SHA224(),
              "sha256": hashes.SHA256(), "sha512": hashes.SHA512()}

    checked = 0
    for line in lines:
        _, name, hash_name, public_hex, digest_hex, r_hex, s_hex = line.split()
        curve = curves[name]
        public = ec.EllipticCurvePublicKey.from_encoded_point(
            curve, unhex(public_hex))
        r, s = bigint(r_hex), bigint(s_hex)

        # OpenSSL verifying our signature is the real check: it is the
        # direction that proves the signature is valid rather than merely
        # self-consistent.
        der = utils.encode_dss_signature(r, s)
        try:
            public.verify(der, unhex(digest_hex),
                          ec.ECDSA(utils.Prehashed(HASHES[hash_name])))
        except InvalidSignature:
            raise Mismatch(f"OpenSSL rejected our {name}/{hash_name} signature\n"
                           f"  r = {r_hex}\n  s = {s_hex}")
        checked += 1
    return checked


# ------------------------------------------------------------------- RSA ---

def _oaep_encode(hash_name, mgf_name, label, message, seed, k):
    """EME-OAEP encoding, RFC 8017 7.1.1 step 2, from hashlib."""
    import hashlib

    def mgf1(seed_bytes, length):
        out = b""
        counter = 0
        while len(out) < length:
            out += hashlib.new(mgf_name, seed_bytes + counter.to_bytes(4, "big")).digest()
            counter += 1
        return out[:length]
    h = hashlib.new(hash_name, label).digest()
    db = h + bytes(k - len(message) - 2 * len(h) - 2) + b"\x01" + message
    masked_db = bytes(a ^ b for a, b in zip(db, mgf1(seed, k - len(h) - 1)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, mgf1(masked_db, len(h))))
    return b"\x00" + masked_seed + masked_db


def check_rsa(lines):
    """Rebuild each key inside OpenSSL and make it do the other half of
    every operation.

    There is no ASN.1 in the library yet, so the key arrives as its raw
    components. Reassembling it through RSAPrivateNumbers is itself a check:
    `private_key()` recomputes and validates the CRT parameters, so a key
    whose dp, dq or qinv is wrong is rejected here rather than silently
    working because our own code made the same mistake twice.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa as ref_rsa
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    from cryptography.exceptions import InvalidSignature

    HASHES = {"md5": hashes.MD5(), "sha1": hashes.SHA1(),
              "sha256": hashes.SHA256(), "sha512": hashes.SHA512()}
    OAEP_HASHES = {"sha1": hashes.SHA1(), "sha224": hashes.SHA224(),
                   "sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
                   "sha512": hashes.SHA512()}

    private = {}
    public = {}
    checked = 0

    for line in lines:
        parts = line.split()
        op = parts[0]

        if op == "key":
            index = int(parts[1])
            n, e, d, p, q, dp, dq, qinv = (bigint(x) for x in parts[2:10])
            numbers = ref_rsa.RSAPrivateNumbers(
                p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qinv,
                public_numbers=ref_rsa.RSAPublicNumbers(e=e, n=n))
            # Raises if anything is inconsistent, including a composite
            # "prime" or a d that does not invert e.
            private[index] = numbers.private_key()
            public[index] = private[index].public_key()
            checked += 1

        elif op == "sign":
            index, hash_name = int(parts[1]), parts[2]
            digest, signature = unhex(parts[3]), unhex(parts[4])
            try:
                public[index].verify(
                    signature, digest, padding.PKCS1v15(),
                    asym_utils.Prehashed(HASHES[hash_name]))
            except InvalidSignature:
                raise Mismatch(f"OpenSSL rejected our key {index} {hash_name} signature")

            # And the other direction: OpenSSL signs, and the bytes must be
            # identical, since PKCS#1 v1.5 signing is deterministic.
            theirs = private[index].sign(
                digest, padding.PKCS1v15(),
                asym_utils.Prehashed(HASHES[hash_name]))
            if theirs != signature:
                raise Mismatch(f"key {index} {hash_name} signature differs\n"
                               f"  ours: {signature.hex()}\n  ref : {theirs.hex()}")
            checked += 1

        elif op == "enc":
            index = int(parts[1])
            message, ciphertext = unhex(parts[2]), unhex(parts[3])
            # Our padding is random, so the bytes cannot be compared; what
            # can be compared is what OpenSSL gets back out.
            recovered = private[index].decrypt(ciphertext, padding.PKCS1v15())
            if recovered != message:
                raise Mismatch(f"OpenSSL decrypted key {index} to "
                               f"{recovered.hex()}, wanted {message.hex()}")
            checked += 1

        elif op == "oaep":
            # Seeded, so two checks: OpenSSL decrypts to the message, and
            # an encoding written here from RFC 8017 7.1.1 gives the same
            # ciphertext byte for byte. The second is a reading of the
            # RFC by the same reader; the first is not.
            index, hash_name, mgf_name = int(parts[1]), parts[2], parts[3]
            label, seed, message, ciphertext = (unhex(x) for x in parts[4:8])
            recovered = private[index].decrypt(ciphertext, padding.OAEP(
                mgf=padding.MGF1(OAEP_HASHES[mgf_name]), algorithm=OAEP_HASHES[hash_name],
                label=label or None))
            if recovered != message:
                raise Mismatch(f"OpenSSL OAEP-decrypted key {index} {hash_name}/{mgf_name} "
                               f"to {recovered.hex()}, wanted {message.hex()}")
            numbers = public[index].public_numbers()
            k = (numbers.n.bit_length() + 7) // 8
            em = _oaep_encode(hash_name, mgf_name, label, message, seed, k)
            if pow(int.from_bytes(em, "big"), numbers.e, numbers.n).to_bytes(k, "big") \
                    != ciphertext:
                raise Mismatch(f"key {index} OAEP {hash_name}/{mgf_name} ciphertext differs "
                               f"from the RFC's encoding of the same seed")
            checked += 1

        elif op == "raw":
            index, m, c = int(parts[1]), bigint(parts[2]), bigint(parts[3])
            numbers = public[index].public_numbers()
            if pow(m, numbers.e, numbers.n) != c:
                raise Mismatch(f"raw RSAEP differs for key {index}")
            checked += 1

    return checked


# ------------------------------------------------------------------ X.509 ---

def check_x509(lines):
    """Parse certificates we built with OpenSSL, and compare every field
    against what our own parser read out of the same bytes.

    Three things fail here if any one of them is wrong: our encoder, our
    parser, or the agreement between them. An encoder and parser written
    together can agree on something neither the spec nor OpenSSL agrees
    with, which is the failure this corpus exists to catch.
    """
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric import rsa as ref_rsa
    from cryptography.hazmat.primitives.asymmetric import dsa as ref_dsa
    from cryptography.exceptions import InvalidSignature

    certificates = {}
    fields = {}
    checked = 0
    verified = 0

    key_identifiers = 0
    for line in lines:
        kind, label, rest = line.split(" ", 2)
        if kind == "keyid":
            # **The only independent opinion anywhere on which bytes a
            # key identifier is computed over.**
            #
            # RFC 5280 4.2.1.2 method 1 says "the SHA-1 hash of the value
            # of the BIT STRING subjectPublicKey (excluding the tag,
            # length, and number of unused bits)". The three readings -
            # the whole SubjectPublicKeyInfo, the BIT STRING's TLV, or
            # its contents - are all self-consistent, so a chain built
            # entirely with the wrong one links up perfectly and matches
            # nothing anybody else produced. Only somebody else's
            # computation from the same key can say.
            spki_hex, got = rest.split(" ")
            public_key = serialization.load_der_public_key(unhex(spki_hex))
            want = x509.SubjectKeyIdentifier.from_public_key(
                public_key).digest.hex()
            if got != want:
                raise Mismatch(f"key identifier {label}\n  ours: {got}\n"
                               f"  ref : {want}")
            key_identifiers += 1
            checked += 1
            continue
        if kind == "cert":
            certificates[label] = x509.load_der_x509_certificate(unhex(rest))
        elif kind == "field":
            name, _, value = rest.partition(" ")
            fields.setdefault(label, {})[name] = value

    def epoch(moment):
        # cryptography returns naive UTC for the legacy properties and
        # aware datetimes for the _utc ones; normalise to seconds.
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        return int(moment.timestamp())

    SIG_NAMES = {
        "sha256WithRSAEncryption": "rsa-sha256",
        "sha384WithRSAEncryption": "rsa-sha384",
        "sha512WithRSAEncryption": "rsa-sha512",
        "sha1WithRSAEncryption": "rsa-sha1",
        "ecdsa-with-SHA256": "ecdsa-sha256",
        "ecdsa-with-SHA384": "ecdsa-sha384",
        "ecdsa-with-SHA512": "ecdsa-sha512",
        "dsa-with-sha1": "dsa-sha1",
        "dsa-with-sha224": "dsa-sha224",
        "dsa-with-sha256": "dsa-sha256",
    }
    # python-cryptography knows the two NIST-arc DSA OIDs by number but has
    # no name for them, so they are matched by dotted string.
    SIG_DOTTED = {"2.16.840.1.101.3.4.3.3": "dsa-sha384",
                  "2.16.840.1.101.3.4.3.4": "dsa-sha512"}
    CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384",
                   "secp521r1": "P-521",
                   "secp256k1": "secp256k1"}

    for label, certificate in certificates.items():
        ours = fields[label]

        def compare(name, theirs):
            if str(ours[name]) != str(theirs):
                raise Mismatch(f"{label}.{name}\n  ours: {ours[name]}\n"
                               f"  ref : {theirs}")

        compare("version", certificate.version.value + 1)
        compare("serial", f"{certificate.serial_number:x}".zfill(
            len(ours["serial"])))
        compare("not_before", epoch(certificate.not_valid_before_utc))
        compare("not_after", epoch(certificate.not_valid_after_utc))

        def common_name(name):
            values = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            return values[0].value if values else ""

        compare("subject_cn", common_name(certificate.subject))
        compare("issuer_cn", common_name(certificate.issuer))
        compare("sig_alg", SIG_DOTTED.get(
            certificate.signature_algorithm_oid.dotted_string,
            SIG_NAMES.get(certificate.signature_algorithm_oid._name,
                          certificate.signature_algorithm_oid._name)))

        key = certificate.public_key()
        if isinstance(key, ref_rsa.RSAPublicKey):
            compare("public_key", f"rsa-{key.key_size}")
        elif isinstance(key, ec.EllipticCurvePublicKey):
            compare("public_key", f"ec-{CURVE_NAMES[key.curve.name]}")
        elif isinstance(key, ref_dsa.DSAPublicKey):
            compare("public_key", f"dsa-{key.key_size}")

        # The TBS bytes are what the signature covers, so a mismatch here
        # means our parser sliced the wrong range - which would make every
        # signature check meaningless.
        compare("tbs_sha256", hashlib.sha256(certificate.tbs_certificate_bytes).hexdigest())

        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints).value
            compare("is_ca", str(constraints.ca).lower())
            compare("path_len", constraints.path_length
                    if constraints.path_length is not None else "-")
        except x509.ExtensionNotFound:
            compare("is_ca", "false")
            compare("path_len", "-")

        try:
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            entries = []
            for entry in san:
                if isinstance(entry, x509.DNSName):
                    entries.append(f"dns:{entry.value}")
                elif isinstance(entry, x509.IPAddress):
                    entries.append(f"ip:{entry.value.packed.hex()}")
                elif isinstance(entry, x509.RFC822Name):
                    entries.append(f"email:{entry.value}")
                elif isinstance(entry, x509.UniformResourceIdentifier):
                    entries.append(f"uri:{entry.value}")
            compare("sans", ",".join(entries) if entries else "-")
        except x509.ExtensionNotFound:
            compare("sans", "-")

        # And the signature itself. The corpus names the signing
        # certificate, so there is no guessing about which key to use -
        # which matters for the mixed cases, where an RSA CA signs an EC
        # leaf and the obvious guess is the wrong one.
        issuer = certificates.get(ours["signer"])
        if issuer is None:
            raise Mismatch(f"{label} names signer {ours['signer']}, "
                           f"which is not in the corpus")
        dotted = certificate.signature_algorithm_oid.dotted_string
        if dotted in SIG_DOTTED:
            # Unnamed there, so `signature_hash_algorithm` raises; the
            # hash is the one the OID's number says.
            from cryptography.hazmat.primitives import hashes as ref_hashes
            hash_name = {"dsa-sha384": ref_hashes.SHA384(),
                         "dsa-sha512": ref_hashes.SHA512()}[SIG_DOTTED[dotted]]
        else:
            hash_name = certificate.signature_hash_algorithm
        key = issuer.public_key()
        try:
            if isinstance(key, ref_rsa.RSAPublicKey):
                key.verify(certificate.signature,
                           certificate.tbs_certificate_bytes,
                           padding.PKCS1v15(), hash_name)
            elif isinstance(key, ref_dsa.DSAPublicKey):
                key.verify(certificate.signature,
                           certificate.tbs_certificate_bytes, hash_name)
            else:
                key.verify(certificate.signature,
                           certificate.tbs_certificate_bytes,
                           ec.ECDSA(hash_name))
        except InvalidSignature:
            raise Mismatch(f"OpenSSL rejected the signature on {label}")
        verified += 1

        checked += 1

    # A skipped signature check is not coverage, so say how many ran.
    print(f"  (OpenSSL verified {verified} of {len(certificates)} signatures, "
          f"and checked {key_identifiers} key identifiers)")
    if key_identifiers == 0:
        raise Mismatch(
            "no key identifier rows in the corpus. Nothing else here can "
            "tell which of the three readings of RFC 5280 4.2.1.2 method 1 "
            "we use: every one of them is self-consistent, so a chain built "
            "with the wrong one links up perfectly and matches nothing "
            "anybody else produced")
    return checked


# ----------------------------------------------------- the real trust store ---

def check_roots(lines):
    """Compare our parse of the machine's own CA bundle against OpenSSL's.

    This is the corpus the other X.509 tests cannot be: a few hundred real
    certificates issued by real CAs over twenty-five years, carrying every
    encoding quirk that survives in production. Certificates we generate
    ourselves all look the way we think certificates look.

    It is also the check on strictness. A parser that refuses real roots is
    not strict, it is broken - so an `unparsed` line is a failure here, not
    a skip.
    """
    import datetime
    from cryptography import x509

    certificates = {}
    fields = {}
    bundles = []
    checked = 0
    signatures = 0

    for line in lines:
        kind, rest = line.split(" ", 1)
        if kind == "bundle":
            path, count = rest.rsplit(" ", 1)
            bundles.append((path, int(count)))
            continue
        if kind == "unparsed":
            label, _, reason = rest.split(" ", 2)
            raise Mismatch(f"we could not parse a real root: {label}\n  {reason}")
        label, rest = rest.split(" ", 1)
        if kind == "cert":
            certificates[label] = x509.load_der_x509_certificate(unhex(rest))
        elif kind == "field":
            name, _, value = rest.partition(" ")
            fields.setdefault(label, {})[name] = value

    if not bundles:
        print("  (no system CA bundle on this machine; nothing to compare)")
        return 0

    def epoch(moment):
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        return int(moment.timestamp())

    def common_name(name):
        values = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return values[0].value if values else ""

    for label, certificate in certificates.items():
        ours = fields[label]

        def compare(name, theirs):
            if str(ours[name]) != str(theirs):
                raise Mismatch(f"{label}.{name}\n  ours: {ours[name]}\n"
                               f"  ref : {theirs}")

        compare("version", certificate.version.value + 1)
        compare("serial", f"{certificate.serial_number:x}".zfill(len(ours["serial"])))
        compare("not_before", epoch(certificate.not_valid_before_utc))
        compare("not_after", epoch(certificate.not_valid_after_utc))
        compare("subject_cn", common_name(certificate.subject))
        compare("issuer_cn", common_name(certificate.issuer))
        # The TBS range is what every signature check depends on.
        compare("tbs_sha256",
                hashlib.sha256(certificate.tbs_certificate_bytes).hexdigest())
        compare("self_issued",
                str(certificate.subject == certificate.issuer).lower())

        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints).value
            compare("is_ca", str(constraints.ca).lower())
        except x509.ExtensionNotFound:
            compare("is_ca", "false")

        # Every root is self-signed, so our own verifier had to accept its
        # own signature - which makes this a verification corpus too.
        if ours["self_issued"] == "true":
            if ours["self_signature"] != "ok":
                raise Mismatch(f"our verifier rejected the self-signature on "
                               f"{label} ({common_name(certificate.subject)}): "
                               f"{ours['self_signature']}")
            signatures += 1

        checked += 1

    for path, count in bundles:
        present = sum(1 for label in certificates if label.startswith(path + "#"))
        if present != count:
            raise Mismatch(f"{path}: {count} certificates present, {present} parsed")
        print(f"  ({path}: {present} real roots, all parsed)")
    print(f"  (our verifier accepted {signatures} real self-signatures)")
    return checked


# ------------------------------------------------------- TLS record layer ---

def ssl3_expand(secret, seed, length):
    """SSLv3's key derivation, from RFC 6101 section 6.2.2.

        MD5(secret + SHA('A'   + secret + seed)) +
        MD5(secret + SHA('BB'  + secret + seed)) +
        MD5(secret + SHA('CCC' + secret + seed)) + ...

    Written from the specification's text. Two details here are mistakes
    both ends of a handshake would make together and never notice: the
    secret appears **twice** in each round, inside the SHA-1 and again in
    front of the MD5; and the salt is a letter repeated, not a letter with
    a counter after it.
    """
    out = b""
    letter = ord("A")
    while len(out) < length:
        salt = bytes([letter]) * (letter - ord("A") + 1)
        inner = hashlib.sha1(salt + secret + seed).digest()
        out += hashlib.md5(secret + inner).digest()
        letter += 1
    return out[:length]


def ssl3_finished(master, handshake_messages, side):
    """SSLv3's Finished, from RFC 6101 section 5.6.9. 36 bytes.

        MD5(master + pad2 + MD5(messages + Sender + master + pad1)) +
        SHA(master + pad2 + SHA(messages + Sender + master + pad1))

    The pad lengths differ per hash - 48 for MD5, 40 for SHA-1 - and using
    one length for both produces a Finished that agrees with nobody. The
    sender constants are "CLNT" and "SRVR" as four byte numbers.
    """
    sender = b"\x43\x4c\x4e\x54" if side == "client" else b"\x53\x52\x56\x52"
    out = b""
    for name, pad_len in (("md5", 48), ("sha1", 40)):
        inner = hashlib.new(
            name, handshake_messages + sender + master + b"\x36" * pad_len).digest()
        out += hashlib.new(name, master + b"\x5c" * pad_len + inner).digest()
    return out


def tls10_prf(secret, label, seed, length):
    """The TLS 1.0/1.1 PRF, from RFC 2246 section 5.

    The secret is split in half - odd lengths overlap by one byte - one
    half drives P_MD5 and the other P_SHA-1, and the two streams are
    XORed. Written from the RFC; the same construction is checked against
    our `tls10_prf` in pytests/test_allcrypt.py, so an error here would
    have to be shared by two independent transcriptions.
    """
    import hmac as pyhmac

    def p_hash(name, key, data, want):
        out, a = b"", data
        while len(out) < want:
            a = pyhmac.new(key, a, name).digest()
            out += pyhmac.new(key, a + data, name).digest()
        return out[:want]

    half = (len(secret) + 1) // 2
    s1, s2 = secret[:half], secret[len(secret) - half:]
    md5 = p_hash("md5", s1, label + seed, length)
    sha = p_hash("sha1", s2, label + seed, length)
    return bytes(a ^ b for a, b in zip(md5, sha))


# --------------------------------------------------- TLS 1.3 key schedule ---

def _tls13_hkdf_extract(hash_name, salt, ikm):
    """HKDF-Extract (RFC 5869 section 2.2), written out rather than taken
    from `cryptography` - its HKDF class does extract-and-expand in one go
    and will not hand over the intermediate PRK, which is exactly the value
    TLS 1.3 chains from."""
    size = hashlib.new(hash_name).digest_size
    if not salt:
        salt = b"\x00" * size
    return pyhmac.new(salt, ikm, hash_name).digest()


def _tls13_hkdf_expand(hash_name, prk, info, length):
    """HKDF-Expand (RFC 5869 section 2.3)."""
    size = hashlib.new(hash_name).digest_size
    out, previous, counter = b"", b"", 1
    while len(out) < length:
        previous = pyhmac.new(prk, previous + info + bytes([counter]),
                            hash_name).digest()
        out += previous
        counter += 1
    return out[:length]


def _tls13_expand_label(hash_name, secret, label, context, length):
    """HKDF-Expand-Label, RFC 8446 section 7.1:

        struct {
            uint16 length = Length;
            opaque label<7..255> = "tls13 " + Label;
            opaque context<0..255> = Context;
        } HkdfLabel;

    Transcribed from the RFC's text, not from our Rust. The three things
    worth transcribing independently are all here: the prefix has a
    trailing space, the single length byte covers the *prefixed* label,
    and the uint16 at the front is the output length rather than the
    structure's."""
    prefixed = b"tls13 " + label
    info = (length.to_bytes(2, "big")
            + bytes([len(prefixed)]) + prefixed
            + bytes([len(context)]) + context)
    return _tls13_hkdf_expand(hash_name, secret, info, length)


def _tls13_derive_secret(hash_name, secret, label, transcript_hash):
    """Derive-Secret, RFC 8446 section 7.1. The context is the transcript
    hash, which for an empty message list is Hash("") - not nothing."""
    size = hashlib.new(hash_name).digest_size
    return _tls13_expand_label(hash_name, secret, label, transcript_hash, size)


def check_tls13_keys(lines):
    """The TLS 1.3 key schedule against RFC 8446 section 7.1.

    Two references, deliberately:

    `cryptography`'s HKDF (OpenSSL's) is checked against this file's own
    HKDF first, so the primitive underneath is confirmed by a real
    independent implementation. Everything above the primitive - the
    HkdfLabel encoding, the three Extract stages and the labels - is
    transcribed from the RFC here, because that is where the mistakes live
    and no library exposes those steps separately.

    Each of the four things this is really checking produces a schedule
    that agrees with itself and with nobody else:

      * "tls13 " with the trailing space, and its length in the byte;
      * Hash("") as the context for an empty message list;
      * the *derived* secret as the salt for the next Extract;
      * Hash.length zero bytes as the IKM when there is no PSK.
    """
    # Confirm this file's HKDF against OpenSSL's before trusting it as a
    # reference. `cryptography` only offers extract-and-expand together,
    # which is why the pieces are written out above - but the combination
    # is comparable and that is enough to pin the primitive.
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _h
    for name, algorithm in [("sha256", _h.SHA256()), ("sha384", _h.SHA384())]:
        ikm, salt, info = b"\x0b" * 22, b"\x00" * 13, b"\xf0\xf1\xf2"
        theirs = HKDF(algorithm=algorithm, length=42, salt=salt,
                      info=info).derive(ikm)
        ours = _tls13_hkdf_expand(name, _tls13_hkdf_extract(name, salt, ikm),
                                  info, 42)
        if ours != theirs:
            raise Mismatch(f"this file's HKDF disagrees with OpenSSL's for "
                           f"{name}, so it cannot be used as a reference\n"
                           f"  here   : {ours.hex()}\n"
                           f"  openssl: {theirs.hex()}")

    checked = 0
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        kind, hash_name = parts[0], parts[1]

        if kind == "label":
            # A label can contain a space ("c hs traffic"), so the fields
            # after it are found from the end rather than by position.
            secret = unhex(parts[2])
            label = " ".join(parts[3:-3]).encode()
            context, length, got = unhex(parts[-3]), int(parts[-2]), parts[-1]
            want = _tls13_expand_label(hash_name, secret, label, context, length)
            if got != want.hex():
                raise Mismatch(f"HKDF-Expand-Label {hash_name} {label!r} "
                               f"-> {length}\n  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif kind == "earlysecret":
            psk, got = unhex(parts[2]), parts[3]
            size = hashlib.new(hash_name).digest_size
            # No PSK means Hash.length zero bytes, not an empty input.
            # HKDF-Extract substitutes zeros for an empty *salt* and never
            # for the IKM, so this asymmetry has to be written out.
            want = _tls13_hkdf_extract(hash_name, b"\x00" * size,
                                       psk if psk else b"\x00" * size)
            if got != want.hex():
                raise Mismatch(f"TLS 1.3 early secret {hash_name}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif kind == "derived":
            secret, got = unhex(parts[2]), parts[3]
            empty = hashlib.new(hash_name).digest()
            want = _tls13_derive_secret(hash_name, secret, b"derived", empty)
            if got != want.hex():
                raise Mismatch(f"TLS 1.3 derived secret {hash_name}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif kind == "handshake":
            early, shared, got = unhex(parts[2]), unhex(parts[3]), parts[4]
            empty = hashlib.new(hash_name).digest()
            salt = _tls13_derive_secret(hash_name, early, b"derived", empty)
            want = _tls13_hkdf_extract(hash_name, salt, shared)
            if got != want.hex():
                raise Mismatch(f"TLS 1.3 handshake secret {hash_name}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif kind == "master":
            handshake, got = unhex(parts[2]), parts[3]
            size = hashlib.new(hash_name).digest_size
            empty = hashlib.new(hash_name).digest()
            salt = _tls13_derive_secret(hash_name, handshake, b"derived", empty)
            want = _tls13_hkdf_extract(hash_name, salt, b"\x00" * size)
            if got != want.hex():
                raise Mismatch(f"TLS 1.3 master secret {hash_name}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif kind == "traffic":
            secret = unhex(parts[2])
            label = " ".join(parts[3:-2]).encode()
            transcript, got = unhex(parts[-2]), parts[-1]
            want = _tls13_derive_secret(hash_name, secret, label, transcript)
            if got != want.hex():
                raise Mismatch(f"TLS 1.3 traffic secret {hash_name} {label!r}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif kind == "keys":
            secret, key_len, iv_len = unhex(parts[2]), int(parts[3]), int(parts[4])
            key, iv, fin = parts[5], parts[6], parts[7]
            size = hashlib.new(hash_name).digest_size
            want_key = _tls13_expand_label(hash_name, secret, b"key", b"", key_len)
            # **The IV's length is an input, not a truncation.** It goes
            # into the HkdfLabel structure that Expand-Label hashes, so
            # the 8, 12 and 16 byte answers share no prefix - which is
            # why RFC 9367's suites, whose IV is the cipher's block,
            # could not simply take the first eight bytes of a twelve
            # byte one. It is also not a function of the key length, so
            # both are swept.
            want_iv = _tls13_expand_label(hash_name, secret, b"iv", b"", iv_len)
            want_fin = _tls13_expand_label(hash_name, secret, b"finished", b"", size)
            for label, ours, theirs in [("key", key, want_key), ("iv", iv, want_iv),
                                        ("finished key", fin, want_fin)]:
                if ours != theirs.hex():
                    raise Mismatch(f"TLS 1.3 traffic {label} {hash_name}\n"
                                   f"  ours: {ours}\n  ref : {theirs.hex()}")
            checked += 1

        elif kind == "update":
            secret, got = unhex(parts[2]), parts[4]
            size = hashlib.new(hash_name).digest_size
            # "traffic upd" takes a literally empty context, not Hash("") -
            # it is Expand-Label directly rather than Derive-Secret.
            want = _tls13_expand_label(hash_name, secret, b"traffic upd", b"", size)
            if got != want.hex():
                raise Mismatch(f"TLS 1.3 key update {hash_name}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif kind == "finished":
            key, transcript, got = unhex(parts[2]), unhex(parts[3]), parts[4]
            want = pyhmac.new(key, transcript, hash_name).digest()
            if got != want.hex():
                raise Mismatch(f"TLS 1.3 Finished {hash_name}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

    if not checked:
        raise Mismatch("the TLS 1.3 key schedule corpus was empty")
    return checked


# ------------------------------------------------------ TLS 1.3 record layer ---

def check_tls13_record(lines):
    """TLS 1.3 protected records, RFC 8446 section 5.

    The AEAD underneath is OpenSSL's through `cryptography`, so that part
    has a genuine second implementation. It is also the part least likely
    to be wrong. What this is really checking is the three things wrapped
    around it, computed here from the RFC's text:

      * TLSInnerPlaintext - content, then the *real* content type, then
        the zero padding. The type before the padding, so it is found by
        scanning back;
      * the nonce - static IV XOR the sequence number, left-padded to
        twelve bytes. Nothing on the wire says which nonce was used, so
        padding it on the wrong side is invisible until a real peer
        refuses every record;
      * the additional data - the five byte wire header, whose length
        field counts the ciphertext *plus the tag*. TLS 1.2's AAD was
        seq || type || version || plaintext_len, and none of those fields
        survive.
    """
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESCCM, AESGCM, ChaCha20Poly1305)

    def sealer(aead, key, tag_len):
        if aead == "aes-gcm":
            return AESGCM(key)
        if aead == "chacha20-poly1305":
            return ChaCha20Poly1305(key)
        if aead in ("aes-ccm", "aes-ccm-8"):
            return AESCCM(key, tag_length=tag_len)
        raise Mismatch(f"no reference AEAD for {aead!r}")

    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "record":
            continue
        aead, key, iv = parts[1], unhex(parts[2]), unhex(parts[3])
        sequence, content_type, padding = int(parts[4]), int(parts[5]), int(parts[6])
        plaintext, got = unhex(parts[7]), parts[8]
        tag_len = 8 if aead == "aes-ccm-8" else 16

        # The nonce: the counter goes in the LAST eight bytes.
        nonce = bytearray(iv)
        counter = sequence.to_bytes(8, "big")
        for i in range(8):
            nonce[len(nonce) - 8 + i] ^= counter[i]

        inner = plaintext + bytes([content_type]) + b"\x00" * padding
        # 0x17 = application_data, 0x0303 = the legacy version every
        # protected TLS 1.3 record claims, and the length covers the tag.
        aad = b"\x17\x03\x03" + (len(inner) + tag_len).to_bytes(2, "big")

        want = sealer(aead, key, tag_len).encrypt(bytes(nonce), inner, aad)
        if got != want.hex():
            raise Mismatch(
                f"TLS 1.3 record {aead} seq {sequence} type {content_type} "
                f"pad {padding} len {len(plaintext)}\n"
                f"  ours: {got[:96]}...\n  ref : {want.hex()[:96]}...")
        checked += 1

    if not checked:
        raise Mismatch("the TLS 1.3 record corpus was empty")
    return checked



# ------------------------------------------------------------------ GOST ---
#
# Kuznyechik, Magma and Streebog, written from GOST R 34.12-2015 and
# GOST R 34.11-2012. See check_gost for why there is no second library to
# compare against.

# The GOST constant tables. Written out here rather than derived
# because they cannot be derived - they are the standards' choices.
# See the note in check_gost for where they came from and how they
# were checked.
_KUZ_PI = bytes((
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6,
))

_STREEBOG_A = (
    0x641c314b2b8ee083, 0xc83862965601dd1b, 0x8d70c431ac02a736, 0x07e095624504536c,
    0x0edd37c48a08a6d8, 0x1ca76e95091051ad, 0x3853dc371220a247, 0x70a6a56e2440598e,
    0xa48b474f9ef5dc18, 0x550b8e9e21f7a530, 0xaa16012142f35760, 0x492c024284fbaec0,
    0x9258048415eb419d, 0x39b008152acb8227, 0x727d102a548b194e, 0xe4fa2054a80b329c,
    0xf97d86d98a327728, 0xeffa11af0964ee50, 0xc3e9224312c8c1a0, 0x9bcf4486248d9f5d,
    0x2b838811480723ba, 0x561b0d22900e4669, 0xac361a443d1c8cd2, 0x456c34887a3805b9,
    0x5b068c651810a89e, 0xb60c05ca30204d21, 0x71180a8960409a42, 0xe230140fc0802984,
    0xd960281e9d1d5215, 0xafc0503c273aa42a, 0x439da0784e745554, 0x86275df09ce8aaa8,
    0x0321658cba93c138, 0x0642ca05693b9f70, 0x0c84890ad27623e0, 0x18150f14b9ec46dd,
    0x302a1e286fc58ca7, 0x60543c50de970553, 0xc0a878a0a1330aa6, 0x9d4df05d5f661451,
    0xaccc9ca9328a8950, 0x4585254f64090fa0, 0x8a174a9ec8121e5d, 0x092e94218d243cba,
    0x125c354207487869, 0x24b86a840e90f0d2, 0x486dd4151c3dfdb9, 0x90dab52a387ae76f,
    0x46b60f011a83988e, 0x8c711e02341b2d01, 0x05e23c0468365a02, 0x0ad97808d06cb404,
    0x14aff010bdd87508, 0x2843fd2067adea10, 0x5086e740ce47c920, 0xa011d380818e8f40,
    0x83478b07b2468764, 0x1b8e0b0e798c13c8, 0x3601161cf205268d, 0x6c022c38f90a4c07,
    0xd8045870ef14980e, 0xad08b0e0c3282d1c, 0x47107ddd9b505a38, 0x8e20faa72ba0b470,
)

_STREEBOG_PI = bytes((
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6,
))

_STREEBOG_C = (
    bytes((
    0x07, 0x45, 0xa6, 0xf2, 0x59, 0x65, 0x80, 0xdd, 0x23, 0x4d, 0x74, 0xcc, 0x36, 0x74, 0x76, 0x05,
    0x15, 0xd3, 0x60, 0xa4, 0x08, 0x2a, 0x42, 0xa2, 0x01, 0x69, 0x67, 0x92, 0x91, 0xe0, 0x7c, 0x4b,
    0xfc, 0xc4, 0x85, 0x75, 0x8d, 0xb8, 0x4e, 0x71, 0x16, 0xd0, 0x45, 0x2e, 0x43, 0x76, 0x6a, 0x2f,
    0x1f, 0x7c, 0x65, 0xc0, 0x81, 0x2f, 0xcb, 0xeb, 0xe9, 0xda, 0xca, 0x1e, 0xda, 0x5b, 0x08, 0xb1,
    )),
    bytes((
    0xb7, 0x9b, 0xb1, 0x21, 0x70, 0x04, 0x79, 0xe6, 0x56, 0xcd, 0xcb, 0xd7, 0x1b, 0xa2, 0xdd, 0x55,
    0xca, 0xa7, 0x0a, 0xdb, 0xc2, 0x61, 0xb5, 0x5c, 0x58, 0x99, 0xd6, 0x12, 0x6b, 0x17, 0xb5, 0x9a,
    0x31, 0x01, 0xb5, 0x16, 0x0f, 0x5e, 0xd5, 0x61, 0x98, 0x2b, 0x23, 0x0a, 0x72, 0xea, 0xfe, 0xf3,
    0xd7, 0xb5, 0x70, 0x0f, 0x46, 0x9d, 0xe3, 0x4f, 0x1a, 0x2f, 0x9d, 0xa9, 0x8a, 0xb5, 0xa3, 0x6f,
    )),
    bytes((
    0xb2, 0x0a, 0xba, 0x0a, 0xf5, 0x96, 0x1e, 0x99, 0x31, 0xdb, 0x7a, 0x86, 0x43, 0xf4, 0xb6, 0xc2,
    0x09, 0xdb, 0x62, 0x60, 0x37, 0x3a, 0xc9, 0xc1, 0xb1, 0x9e, 0x35, 0x90, 0xe4, 0x0f, 0xe2, 0xd3,
    0x7b, 0x7b, 0x29, 0xb1, 0x14, 0x75, 0xea, 0xf2, 0x8b, 0x1f, 0x9c, 0x52, 0x5f, 0x5e, 0xf1, 0x06,
    0x35, 0x84, 0x3d, 0x6a, 0x28, 0xfc, 0x39, 0x0a, 0xc7, 0x2f, 0xce, 0x2b, 0xac, 0xdc, 0x74, 0xf5,
    )),
    bytes((
    0x2e, 0xd1, 0xe3, 0x84, 0xbc, 0xbe, 0x0c, 0x22, 0xf1, 0x37, 0xe8, 0x93, 0xa1, 0xea, 0x53, 0x34,
    0xbe, 0x03, 0x52, 0x93, 0x33, 0x13, 0xb7, 0xd8, 0x75, 0xd6, 0x03, 0xed, 0x82, 0x2c, 0xd7, 0xa9,
    0x3f, 0x35, 0x5e, 0x68, 0xad, 0x1c, 0x72, 0x9d, 0x7d, 0x3c, 0x5c, 0x33, 0x7e, 0x85, 0x8e, 0x48,
    0xdd, 0xe4, 0x71, 0x5d, 0xa0, 0xe1, 0x48, 0xf9, 0xd2, 0x66, 0x15, 0xe8, 0xb3, 0xdf, 0x1f, 0xef,
    )),
    bytes((
    0x57, 0xfe, 0x6c, 0x7c, 0xfd, 0x58, 0x17, 0x60, 0xf5, 0x63, 0xea, 0xa9, 0x7e, 0xa2, 0x56, 0x7a,
    0x16, 0x1a, 0x27, 0x23, 0xb7, 0x00, 0xff, 0xdf, 0xa3, 0xf5, 0x3a, 0x25, 0x47, 0x17, 0xcd, 0xbf,
    0xbd, 0xff, 0x0f, 0x80, 0xd7, 0x35, 0x9e, 0x35, 0x4a, 0x10, 0x86, 0x16, 0x1f, 0x1c, 0x15, 0x7f,
    0x63, 0x23, 0xa9, 0x6c, 0x0c, 0x41, 0x3f, 0x9a, 0x99, 0x47, 0x47, 0xad, 0xac, 0x6b, 0xea, 0x4b,
    )),
    bytes((
    0x6e, 0x7d, 0x64, 0x46, 0x7a, 0x40, 0x68, 0xfa, 0x35, 0x4f, 0x90, 0x36, 0x72, 0xc5, 0x71, 0xbf,
    0xb6, 0xc6, 0xbe, 0xc2, 0x66, 0x1f, 0xf2, 0x0a, 0xb4, 0xb7, 0x9a, 0x1c, 0xb7, 0xa6, 0xfa, 0xcf,
    0xc6, 0x8e, 0xf0, 0x9a, 0xb4, 0x9a, 0x7f, 0x18, 0x6c, 0xa4, 0x42, 0x51, 0xf9, 0xc4, 0x66, 0x2d,
    0xc0, 0x39, 0x30, 0x7a, 0x3b, 0xc3, 0xa4, 0x6f, 0xd9, 0xd3, 0x3a, 0x1d, 0xae, 0xae, 0x4f, 0xae,
    )),
    bytes((
    0x93, 0xd4, 0x14, 0x3a, 0x4d, 0x56, 0x86, 0x88, 0xf3, 0x4a, 0x3c, 0xa2, 0x4c, 0x45, 0x17, 0x35,
    0x04, 0x05, 0x4a, 0x28, 0x83, 0x69, 0x47, 0x06, 0x37, 0x2c, 0x82, 0x2d, 0xc5, 0xab, 0x92, 0x09,
    0xc9, 0x93, 0x7a, 0x19, 0x33, 0x3e, 0x47, 0xd3, 0xc9, 0x87, 0xbf, 0xe6, 0xc7, 0xc6, 0x9e, 0x39,
    0x54, 0x09, 0x24, 0xbf, 0xfe, 0x86, 0xac, 0x51, 0xec, 0xc5, 0xaa, 0xee, 0x16, 0x0e, 0xc7, 0xf4,
    )),
    bytes((
    0x1e, 0xe7, 0x02, 0xbf, 0xd4, 0x0d, 0x7f, 0xa4, 0xd9, 0xa8, 0x51, 0x59, 0x35, 0xc2, 0xac, 0x36,
    0x2f, 0xc4, 0xa5, 0xd1, 0x2b, 0x8d, 0xd1, 0x69, 0x90, 0x06, 0x9b, 0x92, 0xcb, 0x2b, 0x89, 0xf4,
    0x9a, 0xc4, 0xdb, 0x4d, 0x3b, 0x44, 0xb4, 0x89, 0x1e, 0xde, 0x36, 0x9c, 0x71, 0xf8, 0xb7, 0x4e,
    0x41, 0x41, 0x6e, 0x0c, 0x02, 0xaa, 0xe7, 0x03, 0xa7, 0xc9, 0x93, 0x4d, 0x42, 0x5b, 0x1f, 0x9b,
    )),
    bytes((
    0xdb, 0x5a, 0x23, 0x83, 0x51, 0x44, 0x61, 0x72, 0x60, 0x2a, 0x1f, 0xcb, 0x92, 0xdc, 0x38, 0x0e,
    0x54, 0x9c, 0x07, 0xa6, 0x9a, 0x8a, 0x2b, 0x7b, 0xb1, 0xce, 0xb2, 0xdb, 0x0b, 0x44, 0x0a, 0x80,
    0x84, 0x09, 0x0d, 0xe0, 0xb7, 0x55, 0xd9, 0x3c, 0x24, 0x42, 0x89, 0x25, 0x1b, 0x3a, 0x7d, 0x3a,
    0xde, 0x5f, 0x16, 0xec, 0xd8, 0x9a, 0x4c, 0x94, 0x9b, 0x22, 0x31, 0x16, 0x54, 0x5a, 0x8f, 0x37,
    )),
    bytes((
    0xed, 0x9c, 0x45, 0x98, 0xfb, 0xc7, 0xb4, 0x74, 0xc3, 0xb6, 0x3b, 0x15, 0xd1, 0xfa, 0x98, 0x36,
    0xf4, 0x52, 0x76, 0x3b, 0x30, 0x6c, 0x1e, 0x7a, 0x4b, 0x33, 0x69, 0xaf, 0x02, 0x67, 0xe7, 0x9f,
    0x03, 0x61, 0x33, 0x1b, 0x8a, 0xe1, 0xff, 0x1f, 0xdb, 0x78, 0x8a, 0xff, 0x1c, 0xe7, 0x41, 0x89,
    0xf3, 0xf3, 0xe4, 0xb2, 0x48, 0xe5, 0x2a, 0x38, 0x52, 0x6f, 0x05, 0x80, 0xa6, 0xde, 0xbe, 0xab,
    )),
    bytes((
    0x1b, 0x2d, 0xf3, 0x81, 0xcd, 0xa4, 0xca, 0x6b, 0x5d, 0xd8, 0x6f, 0xc0, 0x4a, 0x59, 0xa2, 0xde,
    0x98, 0x6e, 0x47, 0x7d, 0x1d, 0xcd, 0xba, 0xef, 0xca, 0xb9, 0x48, 0xea, 0xef, 0x71, 0x1d, 0x8a,
    0x79, 0x66, 0x84, 0x14, 0x21, 0x80, 0x01, 0x20, 0x61, 0x07, 0xab, 0xeb, 0xbb, 0x6b, 0xfa, 0xd8,
    0x94, 0xfe, 0x5a, 0x63, 0xcd, 0xc6, 0x02, 0x30, 0xfb, 0x89, 0xc8, 0xef, 0xd0, 0x9e, 0xcd, 0x7b,
    )),
    bytes((
    0x20, 0xd7, 0x1b, 0xf1, 0x4a, 0x92, 0xbc, 0x48, 0x99, 0x1b, 0xb2, 0xd9, 0xd5, 0x17, 0xf4, 0xfa,
    0x52, 0x28, 0xe1, 0x88, 0xaa, 0xa4, 0x1d, 0xe7, 0x86, 0xcc, 0x91, 0x18, 0x9d, 0xef, 0x80, 0x5d,
    0x9b, 0x9f, 0x21, 0x30, 0xd4, 0x12, 0x20, 0xf8, 0x77, 0x1d, 0xdf, 0xbc, 0x32, 0x3c, 0xa4, 0xcd,
    0x7a, 0xb1, 0x49, 0x04, 0xb0, 0x80, 0x13, 0xd2, 0xba, 0x31, 0x16, 0xf1, 0x67, 0xe7, 0x8e, 0x37,
    )),
)


_KUZ_PI_INV = bytes(_KUZ_PI.index(i) for i in range(256))
# GOST R 34.12-2015 4.1.2, most significant byte first.
_KUZ_L = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)


def _kuz_gf(a, b):
    """GF(2^8) modulo x^8 + x^7 + x^6 + x + 1. Not AES's polynomial: the
    two agree often enough that the wrong one still looks like a cipher."""
    product = 0
    while b:
        if b & 1:
            product ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x1C3
    return product & 0xFF


def _kuz_r(block):
    total = 0
    for byte, coefficient in zip(block, _KUZ_L):
        total ^= _kuz_gf(byte, coefficient)
    return bytes([total]) + block[:15]


def _kuz_r_inv(block):
    shifted = block[1:] + block[:1]
    total = 0
    for byte, coefficient in zip(shifted, _KUZ_L):
        total ^= _kuz_gf(byte, coefficient)
    return shifted[:15] + bytes([total])


def _kuz_l(block):
    for _ in range(16):
        block = _kuz_r(block)
    return block


def _kuz_l_inv(block):
    for _ in range(16):
        block = _kuz_r_inv(block)
    return block


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _kuz_round_keys(key):
    keys = [key[:16], key[16:]]
    constants = [_kuz_l(bytes(15) + bytes([i])) for i in range(1, 33)]
    for pair in range(4):
        left, right = keys[2 * pair], keys[2 * pair + 1]
        for step in range(8):
            nxt = _xor(_kuz_l(bytes(_KUZ_PI[b] for b in
                                    _xor(constants[8 * pair + step], left))), right)
            left, right = nxt, left
        keys += [left, right]
    return keys


# `L` is XOR-linear over GF(2), so `L(S(x))` is the XOR of one table
# lookup per byte position. The table is **built from the functions
# above** at import time rather than transcribed from anywhere, so this
# is the same reading of the standard with the work done once: the
# corpus runs 8 KB records through this and a spec-shaped inner loop is
# a thousand times too slow for that.
#
# `_kuz_selftest` below checks the two paths agree, so the shortcut
# cannot quietly become a second implementation.
_KUZ_LS = [[int.from_bytes(_kuz_l(bytes(position) + bytes([_KUZ_PI[value]])
                                  + bytes(15 - position)), "big")
            for value in range(256)]
           for position in range(16)]

_KUZ_SCHEDULES = {}


def _kuz_schedule(key):
    """The round keys for one key, computed once.

    Recomputing them per block costs 512 applications of `R`, which
    dwarfs the eight rounds they are then used for."""
    cached = _KUZ_SCHEDULES.get(key)
    if cached is None:
        cached = [int.from_bytes(k, "big") for k in _kuz_round_keys(key)]
        _KUZ_SCHEDULES[key] = cached
    return cached


def kuznyechik_encrypt_block(key, block):
    keys = _kuz_schedule(key)
    state = int.from_bytes(block, "big")
    for round_key in keys[:9]:
        state ^= round_key
        out = 0
        for position in range(16):
            out ^= _KUZ_LS[position][(state >> (8 * (15 - position))) & 0xFF]
        state = out
    return (state ^ keys[9]).to_bytes(16, "big")


def kuznyechik_decrypt_block(key, block):
    keys = [k.to_bytes(16, "big") for k in _kuz_schedule(key)]
    state = _xor(keys[9], block)
    for round_key in reversed(keys[:9]):
        state = _xor(round_key, bytes(_KUZ_PI_INV[b] for b in _kuz_l_inv(state)))
    return state


def _kuz_selftest():
    """The table-driven encryption must equal the spec-shaped one.

    Without this the shortcut above is a second implementation that the
    corpus would then be comparing the Rust against, which is the exact
    thing this file exists not to do."""
    def slowly(key, block):
        keys = _kuz_round_keys(key)
        state = block
        for round_key in keys[:9]:
            state = _kuz_l(bytes(_KUZ_PI[b] for b in _xor(round_key, state)))
        return _xor(keys[9], state)

    for key, block in [(bytes(32), bytes(16)),
                       (bytes(range(32)), bytes(range(16))),
                       (bytes([0xFF] * 32), bytes([0x5A] * 16))]:
        fast = kuznyechik_encrypt_block(key, block)
        if fast != slowly(key, block):
            raise Mismatch("the Kuznyechik LS table disagrees with the "
                           "spec-shaped implementation it was built from")
        if kuznyechik_decrypt_block(key, fast) != block:
            raise Mismatch("Kuznyechik does not round trip")


_kuz_selftest()


# id-tc26-gost-28147-param-Z. Row j acts on nibble j counting from the
# least significant end.
_MAGMA_SBOX = (
    (12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1),
    (6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15),
    (11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0),
    (12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11),
    (7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12),
    (5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0),
    (8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7),
    (1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2),
)


def _magma_round(value, key):
    total = (value + key) & 0xFFFFFFFF
    out = 0
    for position, row in enumerate(_MAGMA_SBOX):
        out |= row[(total >> (4 * position)) & 0xF] << (4 * position)
    return ((out << 11) | (out >> 21)) & 0xFFFFFFFF


# The same treatment as Kuznyechik's LS table, and for the same reason:
# built from `_magma_round` above at import time, not transcribed.
#
# The substitution acts on disjoint nibbles and the rotation is
# XOR-linear, so `t` decomposes into four byte lookups - but only after
# a constant is taken out. `_magma_round(b << 8p, 0)` substitutes the
# *six other* nibbles too, all zero, and row[0] is not zero in any of
# these rows; so `z = _magma_round(0, 0)` appears in every entry, and
# XORing four of them together would leave three copies behind. Removing
# it from each entry and adding it once at the end is exact.
_MAGMA_Z = _magma_round(0, 0)
_MAGMA_T = [[_magma_round(byte << (8 * position), 0) ^ _MAGMA_Z
             for byte in range(256)]
            for position in range(4)]


def _magma_round_fast(value, key):
    total = (value + key) & 0xFFFFFFFF
    return (_MAGMA_T[0][total & 0xFF]
            ^ _MAGMA_T[1][(total >> 8) & 0xFF]
            ^ _MAGMA_T[2][(total >> 16) & 0xFF]
            ^ _MAGMA_T[3][(total >> 24) & 0xFF]
            ^ _MAGMA_Z)


def _magma_selftest():
    """The table must agree with `_magma_round` everywhere it is used.

    Same standing as `_kuz_selftest`: a shortcut that drifts from the
    function it was derived from is a second implementation, and then
    the corpus is comparing the Rust against it rather than against the
    standard."""
    state = 0x12345678
    for step in range(4096):
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        key = (state ^ 0xA5A5_5A5A) & 0xFFFFFFFF
        if _magma_round_fast(state, key) != _magma_round(state, key):
            raise Mismatch(f"the Magma round table disagrees with the "
                           f"spec-shaped round at step {step}")
    for value in (0, 0xFFFFFFFF):
        for key in (0, 0xFFFFFFFF):
            if _magma_round_fast(value, key) != _magma_round(value, key):
                raise Mismatch("the Magma round table disagrees at an extreme")


_magma_selftest()


def _magma_transform(key, block, forward):
    # Big endian, unlike GOST 28147-89, which reads the same bytes little
    # endian and is therefore a different cipher with the same key.
    subkeys = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(8)]
    schedule = subkeys * 3 + subkeys[::-1]
    if not forward:
        schedule = schedule[::-1]
    left = int.from_bytes(block[:4], "big")
    right = int.from_bytes(block[4:], "big")
    for step in range(31):
        left, right = right, left ^ _magma_round_fast(right, schedule[step])
    left ^= _magma_round_fast(right, schedule[31])
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def magma_encrypt_block(key, block):
    return _magma_transform(key, block, True)


def magma_decrypt_block(key, block):
    return _magma_transform(key, block, False)


_GOST_CIPHERS = {
    "kuznyechik": (16, kuznyechik_encrypt_block, kuznyechik_decrypt_block),
    "magma": (8, magma_encrypt_block, magma_decrypt_block),
}


def _gost_cbc(name, key, iv, data):
    size, encrypt, _ = _GOST_CIPHERS[name]
    out, previous = b"", iv
    for offset in range(0, len(data), size):
        previous = encrypt(key, _xor(previous, data[offset:offset + size]))
        out += previous
    return out


def _gost_ctr(name, key, iv, data):
    """The counter is the whole IV incremented as a big endian integer,
    which is what `modes.rs` does for every cipher here. RFC 9189's own
    CTR-ACPKM uses a half-width counter and is a different thing; this
    checks the generic mode, not that one."""
    size, encrypt, _ = _GOST_CIPHERS[name]
    counter = int.from_bytes(iv, "big")
    out = b""
    for offset in range(0, len(data), size):
        keystream = encrypt(key, counter.to_bytes(size, "big"))
        chunk = data[offset:offset + size]
        out += _xor(keystream[:len(chunk)], chunk)
        counter = (counter + 1) % (1 << (8 * size))
    return out


_STREEBOG_LPS = [[0] * 256 for _ in range(8)]
for _position in range(8):
    for _value in range(256):
        _acc = 0
        for _bit in range(8):
            if _STREEBOG_PI[_value] & (1 << _bit):
                _acc ^= _STREEBOG_A[8 * _position + _bit]
        _STREEBOG_LPS[_position][_value] = _acc


def _sb_words(data):
    return [int.from_bytes(data[8 * i:8 * i + 8], "little") for i in range(8)]


def _sb_bytes(words):
    return b"".join(w.to_bytes(8, "little") for w in words)


def _sb_lps(state):
    out = [0] * 8
    for position, word in enumerate(state):
        row = _STREEBOG_LPS[position]
        for shift in range(8):
            out[shift] ^= row[(word >> (8 * shift)) & 0xFF]
    return out


def _sb_xlps(a, b):
    return _sb_lps([x ^ y for x, y in zip(a, b)])


def _sb_g(h, n, m):
    key = _sb_xlps(h, n)
    data = _sb_xlps(key, m)
    for constant in _STREEBOG_C[:11]:
        key = _sb_xlps(key, _sb_words(constant))
        data = _sb_xlps(key, data)
    key = _sb_xlps(key, _sb_words(_STREEBOG_C[11]))
    data = [x ^ y for x, y in zip(key, data)]
    data = [x ^ y for x, y in zip(data, h)]
    return [x ^ y for x, y in zip(data, m)]


def _sb_add(a, b):
    total = (int.from_bytes(_sb_bytes(a), "little")
             + int.from_bytes(_sb_bytes(b), "little")) % (1 << 512)
    return _sb_words(total.to_bytes(64, "little"))


def streebog(message, size=512):
    """GOST R 34.11-2012. The 256 bit form is not a truncation: its IV is
    sixty-four 0x01 bytes and the digest is the *last* 32 bytes."""
    h = _sb_words(bytes(64) if size == 512 else bytes([1]) * 64)
    n = [0] * 8
    sigma = [0] * 8
    while len(message) >= 64:
        m = _sb_words(message[:64])
        message = message[64:]
        h = _sb_g(h, n, m)
        n = _sb_add(n, _sb_words((512).to_bytes(64, "little")))
        sigma = _sb_add(sigma, m)

    padded = bytearray(64)
    padded[:len(message)] = message
    padded[len(message)] = 1          # immediately after, not at the end
    m = _sb_words(bytes(padded))
    h = _sb_g(h, n, m)
    sigma = _sb_add(sigma, m)
    n = _sb_add(n, _sb_words((len(message) * 8).to_bytes(64, "little")))

    h = _sb_g(h, [0] * 8, n)
    h = _sb_g(h, [0] * 8, sigma)
    digest = _sb_bytes(h)
    return digest if size == 512 else digest[32:]


# ---------------------------------------------------- GOST R 34.11-94 ---
#
# A second reading of RFC 5831, in a different language and by a
# different route. The S-boxes are the two tables in RFC 4357 section
# 11.2 - read out of the vendored document here rather than typed, the
# same way `src/hash_functions/gost94.rs` reads them, which means this
# reference and the Rust cannot disagree about *which* table while
# agreeing about everything else.
#
# What the two readings can still share is a misreading of the
# algorithm, which is why the unit tests pin every intermediate of
# RFC 5831's own worked examples. That is the division of labour: the
# document's vectors say the algorithm is right, and this says the
# implementation does the same thing on six hundred other inputs.

def _g94_sboxes():
    """The two parameter sets, out of RFC 4357 section 11.2's dump."""
    text = (ROOT / "rfcs" / "rfc4357.txt").read_text(encoding="utf-8")
    lines = text.split("\n")
    out = {}
    for marker in ("id-GostR3411-94-TestParamSet",
                   "id-GostR3411-94-CryptoProParamSet"):
        start = max(i for i, line in enumerate(lines)
                    if line.strip().startswith(":")
                    and line.strip().endswith(marker))
        packed = b""
        for line in lines[start + 1:]:
            if "Popov," in line or "RFC 4357" in line:
                continue
            stripped = line.strip()
            if not stripped.startswith(":"):
                continue
            rest = stripped[1:].strip()
            words = rest.split()
            if not words or not all(len(w) == 2 and
                                    all(c in "0123456789ABCDEF" for c in w)
                                    for w in words):
                continue
            packed += bytes.fromhex("".join(words))
            if len(packed) >= 64:
                break
        assert len(packed) >= 64, marker
        packed = packed[:64]
        # byte 4i + j holds pi[2j](i) and pi[2j+1](i), high nibble first
        sbox = [[0] * 16 for _ in range(8)]
        for value in range(16):
            for pair in range(4):
                byte = packed[4 * value + pair]
                sbox[2 * pair][value] = byte >> 4
                sbox[2 * pair + 1][value] = byte & 0xf
        out[marker] = sbox
    return out


_G94_SBOXES = None


def _g94_sbox(name):
    global _G94_SBOXES
    if _G94_SBOXES is None:
        _G94_SBOXES = _g94_sboxes()
    return _G94_SBOXES[name]


def _g94_encrypt(key, block, sbox):
    """GOST 28147-89 in ECB, one block, written out here rather than
    reused from `_GOST_CIPHERS` so that the hash's reference does not
    inherit the cipher reference's reading of the key schedule."""
    k = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]
    n1 = int.from_bytes(block[0:4], "little")
    n2 = int.from_bytes(block[4:8], "little")

    def f(x):
        s = 0
        for i in range(8):
            s |= sbox[i][(x >> (4 * i)) & 0xf] << (4 * i)
        return ((s << 11) | (s >> 21)) & 0xFFFFFFFF

    order = list(range(8)) * 3 + list(reversed(range(8)))
    for step, j in enumerate(order):
        if step < 31:
            n1, n2 = n2 ^ f((n1 + k[j]) & 0xFFFFFFFF), n1
        else:
            n2 ^= f((n1 + k[j]) & 0xFFFFFFFF)
    return n1.to_bytes(4, "little") + n2.to_bytes(4, "little")


def _g94_p(w):
    """The byte transposition: output group g takes every eighth input
    byte from offset g."""
    out = bytearray(32)
    for group in range(8):
        for step in range(4):
            out[4 * group + step] = w[group + 8 * step]
    return bytes(out)


def _g94_a(x):
    """A(X) = (x1 xor x2) || x4 || x3 || x2, low part first."""
    return bytes(x[8:32]) + bytes(a ^ b for a, b in zip(x[0:8], x[8:16]))


def _g94_psi(x):
    words = [int.from_bytes(x[2 * i:2 * i + 2], "little") for i in range(16)]
    fresh = (words[0] ^ words[1] ^ words[2] ^ words[3]
             ^ words[12] ^ words[15])
    words = words[1:] + [fresh]
    return b"".join(w.to_bytes(2, "little") for w in words)


def _g94_psi_n(x, times):
    for _ in range(times):
        x = _g94_psi(x)
    return x


def _g94_xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# C[3] of RFC 5831 section 5.1, written here as the document writes it
# and expanded rather than transcribed as hex.
_G94_C3 = bytes(int("".join(bits[i:i + 8]), 2)
                for bits in ["1" * 8 + "0" * 8 + "1" * 16 + "0" * 24
                             + "1" * 16 + "0" * 8 + ("0" * 8 + "1" * 8) * 2
                             + "1" * 8 + "0" * 8 + ("0" * 8 + "1" * 8) * 4
                             + ("1" * 8 + "0" * 8) * 4]
                for i in range(0, 256, 8))[::-1]


def _g94_chi(m, h, sbox):
    keys = []
    u, v = h, m
    keys.append(_g94_p(_g94_xor(u, v)))
    for which in (2, 3, 4):
        u = _g94_a(u)
        if which == 3:
            u = _g94_xor(u, _G94_C3)
        v = _g94_a(_g94_a(v))
        keys.append(_g94_p(_g94_xor(u, v)))
    s = b"".join(_g94_encrypt(keys[i], h[8 * i:8 * i + 8], sbox)
                 for i in range(4))
    inner = _g94_xor(_g94_psi_n(s, 12), m)
    return _g94_psi_n(_g94_xor(_g94_psi(inner), h), 61)


def gost94(data, param_set):
    """GOST R 34.11-94, RFC 5831, with the named RFC 4357 parameter set.

    **The loop condition is `>` and not `>=`.** The standard's step 2
    takes the remaining part when it is 256 bits *or fewer*, so a
    message that exactly fills a block is one block and not a block
    plus a padded empty one. Every other hash in this file is the other
    way round, and writing this one like its neighbours gives a wrong
    digest for every message whose length is a multiple of 32 bytes -
    which was caught here by RFC 5831's own 32 byte example.
    """
    sbox = _g94_sbox(param_set)
    h = bytes(32)
    sigma = 0
    bits = 0
    at = 0
    while len(data) - at > 32:
        block = data[at:at + 32]
        h = _g94_chi(block, h, sbox)
        bits += 256
        sigma = (sigma + int.from_bytes(block, "little")) % (1 << 256)
        at += 32

    tail = bytes(data[at:]) + bytes(32 - (len(data) - at))
    bits += (len(data) - at) * 8
    h = _g94_chi(tail, h, sbox)
    sigma = (sigma + int.from_bytes(tail, "little")) % (1 << 256)
    h = _g94_chi(bits.to_bytes(32, "little"), h, sbox)
    return _g94_chi(sigma.to_bytes(32, "little"), h, sbox)


_G94_NAMES = {"gost94": "id-GostR3411-94-CryptoProParamSet",
              "gost94_test": "id-GostR3411-94-TestParamSet"}


def check_gost(lines):
    """Kuznyechik, Magma and Streebog against a reference written from the
    GOST standards.

    **There is no second library to compare against.** The OpenSSL this
    runs on is built without the GOST engine - `openssl list
    -digest-algorithms` has no Streebog, `-cipher-algorithms` has no
    Magma or Kuznyechik - and `python-cryptography` has never offered any
    of them. So the reference here is the specification, transcribed in a
    different language by a different route. That catches a transcription
    error in the Rust; it would not catch a misreading of the standard
    that both transcriptions shared. Same claim, and the same caveat, as
    `check_ssl3_keys`.

    The constant tables cannot be checked that way, so they were not
    transcribed at all. Kuznyechik's `pi` is byte-identical between
    RustCrypto's `kuznyechik` crate and the `gostcrypto` Python package.
    Streebog's `A`, `PI` and `C` together reproduce the gost-engine
    project's precomputed linear table byte for byte, and its `C` matches
    that project's constants word for word. Magma's S-box is the
    `id-tc26-gost-28147-param-Z` table already in `src/block_ciphers/
    gost.rs`, and a unit test pins the two copies together. The unit tests
    then check each algorithm against its standard's published vectors,
    which is what says the tables are the right ones rather than merely
    two copies of the same wrong one.
    """
    checked = 0
    for line in lines:
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "block":
            name, key, plaintext, got = (parts[1], unhex(parts[2]),
                                         unhex(parts[3]), parts[4])
            _, encrypt, decrypt = _GOST_CIPHERS[name]
            want = encrypt(key, plaintext)
            if got != want.hex():
                raise Mismatch(f"{name} block\n  ours: {got}\n  ref : {want.hex()}")
            if decrypt(key, want) != plaintext:
                raise Mismatch(f"{name}: the reference does not round trip")
            checked += 1

        elif parts[0] in ("cbc", "ctr"):
            mode, name = parts[0], parts[1]
            key, iv, plaintext, got = (unhex(parts[2]), unhex(parts[3]),
                                       unhex(parts[4]), parts[5])
            runner = _gost_cbc if mode == "cbc" else _gost_ctr
            want = runner(name, key, iv, plaintext)
            if got != want.hex():
                raise Mismatch(f"{name} {mode} {len(plaintext)} bytes\n"
                               f"  ours: {got[:64]}\n  ref : {want.hex()[:64]}")
            checked += 1

        elif parts[0] == "hash":
            size, message, got = int(parts[1]), unhex(parts[2]), parts[3]
            want = streebog(message, size)
            if got != want.hex():
                raise Mismatch(f"streebog-{size} of {len(message)} bytes\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif parts[0] == "gost94":
            name, message, got = parts[1], unhex(parts[2]), parts[3]
            want = gost94(message, _G94_NAMES[name])
            if got != want.hex():
                raise Mismatch(f"{name} of {len(message)} bytes\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

    if not checked:
        raise Mismatch("the GOST corpus was empty")
    return checked



# ------------------------------------------------------------------ CMAC ---

def _cmac_double(block, rb):
    """Multiply by x in GF(2^b)."""
    carry = block[0] >> 7
    doubled = bytearray(len(block))
    for i in range(len(block) - 1):
        doubled[i] = ((block[i] << 1) | (block[i + 1] >> 7)) & 0xFF
    doubled[-1] = (block[-1] << 1) & 0xFF
    if carry:
        doubled[-1] ^= rb
    return bytes(doubled)


def _cmac_reference(encrypt_block, block_size, message):
    """CMAC, NIST SP 800-38B, from the specification.

    `encrypt_block` is the keyed cipher. Rb is the low coefficients of the
    irreducible polynomial for the block size - 0x87 for 128 bits, 0x1b
    for 64 - and using one for both gives a MAC that is self-consistent
    and agrees with nobody.
    """
    rb = {16: 0x87, 8: 0x1B}[block_size]
    subkey_one = _cmac_double(encrypt_block(bytes(block_size)), rb)
    subkey_two = _cmac_double(subkey_one, rb)

    # The empty message is *padded*, so the test is on both halves.
    complete = len(message) > 0 and len(message) % block_size == 0
    if complete:
        head, last = message[:-block_size], message[-block_size:]
        subkey = subkey_one
    else:
        head = message[:len(message) - len(message) % block_size] \
            if len(message) % block_size else message
        last = message[len(head):] + b"\x80"
        last += bytes(block_size - len(last))
        subkey = subkey_two

    last = bytes(a ^ b for a, b in zip(last, subkey))
    chain = bytes(block_size)
    for offset in range(0, len(head), block_size):
        chain = encrypt_block(bytes(a ^ b for a, b in
                                    zip(chain, head[offset:offset + block_size])))
    return encrypt_block(bytes(a ^ b for a, b in zip(chain, last)))


def check_windows_hashes(lines):
    """The NT and LM password hashes (MS-NLMP 3.3.1).

    NT: this file's MD4 - pinned to OpenSSL's by `_md4_selftest` - over
    the password as UTF-16 little endian.

    LM: the construction written out here from MS-NLMP, over
    python-cryptography's DES: ASCII letters uppercased, zero padding to
    fourteen bytes, each seven bytes made a DES key by inserting a parity
    bit after every seven bits, `KGS!@#$%` encrypted under each. The
    insertion is done on a string of bits, as the specification states
    it, rather than by the shifts the Rust uses. Samba's and impacket's
    LM code, run once, produced `vectors/windows_hashes.vec`, which the
    Rust tests read.
    """
    import warnings
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def des(key, block):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            encryptor = Cipher(algorithms.TripleDES(key), modes.ECB()).encryptor()
        return encryptor.update(block) + encryptor.finalize()

    def lm(password):
        upper = bytes(c - 32 if 0x61 <= c <= 0x7a else c for c in password)
        padded = upper.ljust(14, b"\0")
        out = b""
        for half in (padded[:7], padded[7:]):
            bits = "".join(f"{byte:08b}" for byte in half)
            key = bytes(int(bits[7 * i:7 * i + 7] + "0", 2) for i in range(8))
            out += des(key, b"KGS!@#$%")
        return out

    checked = {"lm": 0, "nt": 0}
    for line in lines:
        parts = line.split()
        if not parts or parts[0] not in checked:
            continue
        password, got = unhex(parts[1]), parts[2]
        if parts[0] == "lm":
            want = lm(password).hex()
        else:
            want = md4(password.decode("utf-8").encode("utf-16-le")).hex()
        if got != want:
            raise Mismatch(f"{parts[0]} hash of {parts[1]}: ours {got}, reference {want}")
        checked[parts[0]] += 1
    if checked["lm"] < 78 or checked["nt"] < 10:
        raise Mismatch(f"too few rows: {checked}")
    return sum(checked.values())


def check_poly1305(lines):
    """Poly1305 on its own, against OpenSSL's through python-cryptography.

    The AEAD corpus reaches Poly1305 only with keys ChaCha produced; these
    rows choose the keys, including the largest clamped r with all-ones
    messages, which is where the limbs and carries reach their bounds.
    """
    from cryptography.hazmat.primitives.poly1305 import Poly1305 as Theirs

    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "poly1305":
            continue
        key, message, got = unhex(parts[1]), unhex(parts[2]), parts[3]
        want = Theirs.generate_tag(key, message).hex()
        if got != want:
            raise Mismatch(f"poly1305 key {parts[1]} length {len(message)}: "
                           f"ours {got}, OpenSSL {want}")
        checked += 1
    if checked < 1000:
        raise Mismatch(f"only {checked} Poly1305 rows; the corpus has shrunk")
    return checked


def check_cmac(lines):
    """CMAC - which GOST calls OMAC - over every block cipher here.

    Two halves, proving different things.

    **AES, Triple DES and Blowfish** go to OpenSSL's own CMAC through
    `python-cryptography`. A real independent implementation, and between
    them they cover a 128 bit block and a 64 bit one - so both values of
    Rb, the padding rule and both subkeys are checked by somebody else's
    code.

    **Kuznyechik and Magma** have no CMAC anywhere on this machine, so
    those go to the construction written out above from NIST SP 800-38B,
    driven by *this file's own* ciphers from `check_gost` rather than by
    ours. So both halves compare against an independent implementation;
    what differs is that the first half's mode is somebody else's and the
    second half's is a second reading of the specification.

    A cipher with no reference at all is an error rather than a skip. A
    corpus row that nothing checks is worse than no row: it counts
    towards "513 cases checked" and checks nothing.
    """
    from cryptography.hazmat.primitives import cmac as their_cmac
    from cryptography.hazmat.primitives.ciphers import algorithms

    def openssl_algorithm(name, key):
        # Triple DES and Blowfish are deprecated in `cryptography` and
        # still present. They are here because they are 64 bit blocks it
        # implements and we do too, which is the only way to get somebody
        # else's opinion on the 0x1b case of Rb.
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if name == "aes":
                return algorithms.AES(key)
            if name == "3des":
                return algorithms.TripleDES(key)
            if name == "blowfish":
                return algorithms.Blowfish(key)
        return None

    checked = 0
    by_openssl = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "cmac":
            continue
        name, key, message, got = (parts[1], unhex(parts[2]),
                                   unhex(parts[3]), parts[4])

        algorithm = openssl_algorithm(name, key)
        if algorithm is not None:
            theirs = their_cmac.CMAC(algorithm)
            theirs.update(message)
            want = theirs.finalize()
            by_openssl += 1
        elif name in _GOST_CIPHERS:
            # Driven by *this file's* Kuznyechik and Magma, written from
            # GOST R 34.12-2015 - not by ours. So this half is still a
            # comparison against an independent implementation, of a
            # construction the half above has just checked against
            # OpenSSL.
            block_size, encrypt, _ = _GOST_CIPHERS[name]

            def encrypt_block(block, encrypt=encrypt, key=key):
                return encrypt(key, block)

            want = _cmac_reference(encrypt_block, block_size, message)
        else:
            raise Mismatch(f"no reference for CMAC over {name!r}; the corpus "
                           f"must not carry a row nothing can check")

        if got != want.hex():
            raise Mismatch(f"CMAC {name} over {len(message)} bytes\n"
                           f"  ours: {got}\n  ref : {want.hex()}")
        checked += 1

    if not by_openssl:
        raise Mismatch("no CMAC row reached OpenSSL, so nothing independent "
                       "was checked")
    if not checked:
        raise Mismatch("the CMAC corpus was empty")
    return checked



# ----------------------------------------------------------------- ACPKM ---

# RFC 8645 section 4.1. Thirty-two bytes, which fills a 256 bit key in
# two Kuznyechik blocks or four Magma ones - which is why the standard
# stops there.
_ACPKM_D = bytes(range(0x80, 0xA0))


def _acpkm_next(encrypt_block, block_size, key_size):
    """K_{i+1} = MSB_|K|( E_K(D_1) || E_K(D_2) || ... )."""
    out = b""
    for offset in range(0, key_size, block_size):
        out += encrypt_block(_ACPKM_D[offset:offset + block_size])
    return out[:key_size]


def check_acpkm(lines):
    """ACPKM and CTR-ACPKM, RFC 8645, against a second reading of it.

    Nothing on this machine implements either - the same position as the
    GOST primitives underneath, and the same caveat. What this does catch
    is the two mistakes that are invisible locally:

      * the counter restarting with the key instead of running across the
        whole message;
      * the key changing a block early or late, which gives a ciphertext
        that is right for one section and wrong afterwards.

    AES rows are here for a reason: ACPKM is defined over any block
    cipher, and running it over one whose correctness is not in question
    separates a mistake in the re-keying from a mistake in Kuznyechik.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def engine(name, key):
        """A keyed single-block encryptor, from the most independent
        implementation available for each cipher."""
        if name == "aes":
            def encrypt(block, key=key):
                worker = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
                return worker.update(block) + worker.finalize()
            return encrypt, 16
        block_size, cipher_encrypt, _ = _GOST_CIPHERS[name]
        return (lambda block, key=key: cipher_encrypt(key, block)), block_size

    checked = 0
    for line in lines:
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "acpkm":
            name, key, got = parts[1], unhex(parts[2]), parts[3]
            encrypt, block_size = engine(name, key)
            want = _acpkm_next(encrypt, block_size, len(key))
            if got != want.hex():
                raise Mismatch(f"ACPKM next key for {name}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            checked += 1

        elif parts[0] == "ctracpkm":
            name, key, nonce = parts[1], unhex(parts[2]), unhex(parts[3])
            section, plaintext, got = int(parts[4]), unhex(parts[5]), parts[6]

            encrypt, block_size = engine(name, key)
            if len(nonce) * 2 != block_size:
                raise Mismatch(f"{name}: the nonce must be half a block")

            counter = int.from_bytes(nonce + bytes(block_size - len(nonce)), "big")
            out = bytearray()
            current = key
            in_section = 0
            for offset in range(0, len(plaintext), block_size):
                # The key changes on a *section* boundary, and the
                # constructor guarantees sections are whole blocks - so
                # this is the only place it can change.
                if in_section == section:
                    current = _acpkm_next(encrypt, block_size, len(current))
                    encrypt, _ = engine(name, current)
                    in_section = 0
                keystream = encrypt(counter.to_bytes(block_size, "big"))
                # And the counter carries on regardless.
                counter = (counter + 1) % (1 << (8 * block_size))
                chunk = plaintext[offset:offset + block_size]
                out += bytes(a ^ b for a, b in zip(keystream, chunk))
                in_section += len(chunk)

            # `unhex` rather than comparing hex strings: an empty
            # ciphertext is printed "-" by the corpus and "" by `.hex()`,
            # and a zero-length message is a case worth keeping.
            if unhex(got) != bytes(out):
                raise Mismatch(
                    f"CTR-ACPKM {name} section {section} over "
                    f"{len(plaintext)} bytes\n"
                    f"  ours: {got[:96]}\n  ref : {bytes(out).hex()[:96]}")
            checked += 1

    if not checked:
        raise Mismatch("the ACPKM corpus was empty")
    return checked



# ------------------------------------------------------------------ OIDs ---

def _encode_oid(dotted):
    """Encode an OID from its dotted form, X.690 section 8.19.

    Written out rather than taken from a library, because the point is to
    be independent of `asn1::encode_oid` - the Rust test compares each
    constant against *that*, so if it were wrong every constant would
    match it and every one would be wrong.

    The first two arcs are packed into one byte as `40*a + b`, which is
    why 2.5.4.3 starts 0x55 and why an OID whose second arc is 40 or more
    under arc 2 still works (the packing is not bounded there, only under
    arcs 0 and 1).
    """
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2:
        raise Mismatch(f"{dotted!r} has fewer than two arcs")
    if parts[0] > 2 or (parts[0] < 2 and parts[1] > 39):
        raise Mismatch(f"{dotted!r} is not a valid OID")

    def base128(value):
        out = [value & 0x7F]
        value >>= 7
        while value:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        return bytes(reversed(out))

    encoded = base128(40 * parts[0] + parts[1])
    for arc in parts[2:]:
        encoded += base128(arc)
    return encoded


def _openssl_oid_names():
    """OpenSSL's own object table, as dotted -> short name.

    A second independent source, and the only one that carries the
    PKCS#5 and PKCS#12 password-based encryption OIDs -
    `python-cryptography`'s `x509.oid` tables are about certificates and
    have never had them.

    `openssl asn1parse -genstr OID:<dotted>` encodes the OID and prints
    what OpenSSL calls it, which is a lookup in `obj_dat.h` - a table
    nobody here wrote. An OID OpenSSL does not know comes back as the
    dotted form again, which is how `_check_oids_against_openssl` tells
    "they agree" from "they have never heard of it".
    """
    return {}


def _openssl_name_for(dotted):
    """What OpenSSL calls this OID, or `None` if it does not know it."""
    if not shutil.which("openssl"):
        return None
    try:
        output = subprocess.run(
            ["openssl", "asn1parse", "-genstr", f"OID:{dotted}"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if output.returncode != 0:
        return None
    for line in output.stdout.splitlines():
        if "OBJECT" in line:
            # `d=0  hl=2 l=9 prim: OBJECT  :pbeWithMD2AndDES-CBC`. The
            # name is after the *last* colon, not the first - the header
            # fields carry their own.
            name = line.rsplit(":", 1)[-1].strip()
            # OpenSSL echoes the number back when it has no name for it.
            return None if name == dotted else name
    return None


def _their_oid_table():
    """Every OID `python-cryptography` knows, as name -> dotted.

    Their names, not ours. The mapping between the two is written out in
    `_OID_EQUIVALENTS` below, and a name there that does not exist in this
    table is an error rather than a skip.
    """
    from cryptography.x509 import oid as their_oid

    table = {}
    for holder in ["NameOID", "SignatureAlgorithmOID", "ExtensionOID",
                   "ExtendedKeyUsageOID", "PublicKeyAlgorithmOID",
                   "AuthorityInformationAccessOID", "AttributeOID",
                   "CertificatePoliciesOID", "CRLEntryExtensionOID",
                   "OCSPExtensionOID"]:
        group = getattr(their_oid, holder, None)
        if group is None:
            continue
        for attribute in dir(group):
            if attribute.startswith("_"):
                continue
            value = getattr(group, attribute)
            if hasattr(value, "dotted_string"):
                table[f"{holder}.{attribute}"] = value.dotted_string
    return table


# Our constant -> the same thing in python-cryptography's tables.
#
# Hand-written, and deliberately so: it maps *our name* to *their name*,
# and the check is that the two agree about the number. A mistake in this
# map is a test failure - either the name does not exist over there, or
# the numbers disagree - rather than a silently unchecked constant.
#
# `None` means "they do not have it", and each one says why. Those are the
# entries this check does not cover, written down so the coverage of the
# check is visible rather than implied.
_OID_EQUIVALENTS = {
    # RFC 8410's arc. python-cryptography has the two signature ones in
    # `SignatureAlgorithmOID`; the two key agreement ones are not in any
    # of its tables, so they go to OpenSSL's object table instead -
    # which is a different table written by different people, and the
    # point of this check.
    "ID_ED25519":          "SignatureAlgorithmOID.ED25519",
    "ID_ED448":            "SignatureAlgorithmOID.ED448",
    "ID_X25519":           "openssl:X25519",
    "ID_X448":             "openssl:X448",

    # RFC 9881's three. Neither python-cryptography 46 nor the OpenSSL
    # 3.0 on PATH here has a name for them; OpenSSL 3.5 does, and it
    # reads and writes certificates carrying these numbers in
    # `scripts/check_mldsa_witness.py` and `vectors/ml_dsa_openssl.vec`.
    # The vendored RFC 9881 states each one too (`_OID_IN_RFCS`).
    "ID_ML_DSA_44":        None,
    "ID_ML_DSA_65":        None,
    "ID_ML_DSA_87":        None,

    # Password based encryption, PKCS#5 and PKCS#12. None of these is in
    # python-cryptography's `x509.oid` - those tables are about
    # certificates - so they are checked against OpenSSL's object table,
    # which is a different table written by different people.
    "PBE_MD2_DES":         "openssl:pbeWithMD2AndDES-CBC",
    "PBE_MD5_DES":         "openssl:pbeWithMD5AndDES-CBC",
    "PBE_MD2_RC2":         "openssl:pbeWithMD2AndRC2-CBC",
    "PBE_MD5_RC2":         "openssl:pbeWithMD5AndRC2-CBC",
    "PBE_SHA1_DES":        "openssl:pbeWithSHA1AndDES-CBC",
    "PBE_SHA1_RC2":        "openssl:pbeWithSHA1AndRC2-CBC",
    "PBKDF2":              "openssl:PBKDF2",
    # Java's key protectors, on Sun's arc. Neither OpenSSL nor
    # python-cryptography names them; the JDK's keytool writes keys
    # under both, which `scripts/check_keystore.py` reads.
    "JKS_KEY_PROTECTOR":   None,
    "JCE_KEY_PROTECTOR":   None,
    "PBES2":               "openssl:PBES2",
    "HMAC_WITH_SHA1":      "openssl:hmacWithSHA1",
    "HMAC_WITH_SHA224":    "openssl:hmacWithSHA224",
    "HMAC_WITH_SHA256":    "openssl:hmacWithSHA256",
    "HMAC_WITH_SHA384":    "openssl:hmacWithSHA384",
    "HMAC_WITH_SHA512":    "openssl:hmacWithSHA512",
    "HMAC_WITH_SHA512_224": "openssl:hmacWithSHA512-224",
    "HMAC_WITH_SHA512_256": "openssl:hmacWithSHA512-256",
    "PBE_SHA1_128_RC4":    "openssl:pbeWithSHA1And128BitRC4",
    "PBE_SHA1_RC4_40":     "openssl:pbeWithSHA1And40BitRC4",
    "PBE_SHA1_3DES":       "openssl:pbeWithSHA1And3-KeyTripleDES-CBC",
    "PBE_SHA1_2DES":       "openssl:pbeWithSHA1And2-KeyTripleDES-CBC",
    "PBE_SHA1_RC2_128":    "openssl:pbeWithSHA1And128BitRC2-CBC",
    "PBE_SHA1_RC2_40":     "openssl:pbeWithSHA1And40BitRC2-CBC",
    "DES_CBC":             "openssl:des-cbc",
    "DES_EDE3_CBC":        "openssl:des-ede3-cbc",
    "RC2_CBC":             "openssl:rc2-cbc",
    "AES128_CBC":          "openssl:aes-128-cbc",
    "AES192_CBC":          "openssl:aes-192-cbc",
    "AES256_CBC":          "openssl:aes-256-cbc",

    "RSA_ENCRYPTION":      "PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5",
    "SHA1_WITH_RSA":       "SignatureAlgorithmOID.RSA_WITH_SHA1",
    "SHA224_WITH_RSA":     "SignatureAlgorithmOID.RSA_WITH_SHA224",
    "SHA256_WITH_RSA":     "SignatureAlgorithmOID.RSA_WITH_SHA256",
    "SHA384_WITH_RSA":     "SignatureAlgorithmOID.RSA_WITH_SHA384",
    "SHA512_WITH_RSA":     "SignatureAlgorithmOID.RSA_WITH_SHA512",
    "RSASSA_PSS":          "SignatureAlgorithmOID.RSASSA_PSS",
    "MD5_WITH_RSA":        "SignatureAlgorithmOID.RSA_WITH_MD5",
    # Deleted from cryptography years ago, and from OpenSSL's defaults
    # long before that. Nothing on this machine has it, and it is kept
    # here because certificates signed with it still exist - which is the
    # whole point of this library. Genuinely unchecked.
    "MD2_WITH_RSA":        None,
    "EC_PUBLIC_KEY":       "PublicKeyAlgorithmOID.EC_PUBLIC_KEY",
    "ECDSA_WITH_SHA1":     "SignatureAlgorithmOID.ECDSA_WITH_SHA1",
    "ECDSA_WITH_SHA224":   "SignatureAlgorithmOID.ECDSA_WITH_SHA224",
    "ECDSA_WITH_SHA256":   "SignatureAlgorithmOID.ECDSA_WITH_SHA256",
    "ECDSA_WITH_SHA384":   "SignatureAlgorithmOID.ECDSA_WITH_SHA384",
    "ECDSA_WITH_SHA512":   "SignatureAlgorithmOID.ECDSA_WITH_SHA512",
    # DSA: the key and all five signature OIDs are in python-cryptography,
    # the NIST-arc pair by number only (it has no name for them).
    "ID_DSA":              "PublicKeyAlgorithmOID.DSA",
    "DSA_WITH_SHA1":       "SignatureAlgorithmOID.DSA_WITH_SHA1",
    "DSA_WITH_SHA224":     "SignatureAlgorithmOID.DSA_WITH_SHA224",
    "DSA_WITH_SHA256":     "SignatureAlgorithmOID.DSA_WITH_SHA256",
    "DSA_WITH_SHA384":     "SignatureAlgorithmOID.DSA_WITH_SHA384",
    "DSA_WITH_SHA512":     "SignatureAlgorithmOID.DSA_WITH_SHA512",
    # The named curves are in `ec.EllipticCurveOID`, handled separately
    # below because that class is not in `x509.oid`.
    "PRIME256V1":          "curve:SECP256R1",
    "SECP384R1":           "curve:SECP384R1",
    "SECP521R1":           "curve:SECP521R1",
    "SECP256K1":           "curve:SECP256K1",
    # The bare hash OIDs are not in any of their public tables; they are
    # only reachable through internal maps that change between releases.
    # They are checked by a different route instead:
    # `oids.rs::test_the_bare_hash_oids_match_the_digest_info_prefixes`
    # ties each to the PKCS#1 DigestInfo prefix in rsa.rs, and those
    # prefixes are compared against OpenSSL byte for byte by
    # pytests/test_rsa.py - a v1.5 signature is deterministic, so
    # identical bytes mean identical OIDs.
    "SHA1":                None,
    "SHA256":              None,
    "SHA384":              None,
    "SHA512":              None,
    # The nine added for SLH-DSA's pre-hash go to OpenSSL's object table
    # rather than to None: python-cryptography has no table of bare hash
    # OIDs, but OpenSSL names every one of these, and that is a different
    # table written by different people from the dotted strings in
    # oids.rs. Six of the nine are not in any vendored RFC, so this is
    # their only independent check.
    "SHA224":              "openssl:sha224",
    "SHA512_224":          "openssl:sha512-224",
    "SHA512_256":          "openssl:sha512-256",
    "SHA3_224":            "openssl:sha3-224",
    "SHA3_256":            "openssl:sha3-256",
    "SHA3_384":            "openssl:sha3-384",
    "SHA3_512":            "openssl:sha3-512",
    "SHAKE128":            "openssl:shake128",
    "SHAKE256":            "openssl:shake256",
    "COMMON_NAME":         "NameOID.COMMON_NAME",
    "SURNAME":             "NameOID.SURNAME",
    "SERIAL_NUMBER":       "NameOID.SERIAL_NUMBER",
    "COUNTRY":             "NameOID.COUNTRY_NAME",
    "LOCALITY":            "NameOID.LOCALITY_NAME",
    "STATE_OR_PROVINCE":   "NameOID.STATE_OR_PROVINCE_NAME",
    "STREET_ADDRESS":      "NameOID.STREET_ADDRESS",
    "ORGANIZATION":        "NameOID.ORGANIZATION_NAME",
    "ORGANIZATIONAL_UNIT": "NameOID.ORGANIZATIONAL_UNIT_NAME",
    "TITLE":               "NameOID.TITLE",
    "GIVEN_NAME":          "NameOID.GIVEN_NAME",
    "EMAIL_ADDRESS":       "NameOID.EMAIL_ADDRESS",
    "DOMAIN_COMPONENT":    "NameOID.DOMAIN_COMPONENT",
    "USER_ID":             "NameOID.USER_ID",
    "SUBJECT_KEY_ID":      "ExtensionOID.SUBJECT_KEY_IDENTIFIER",
    "KEY_USAGE":           "ExtensionOID.KEY_USAGE",
    "SUBJECT_ALT_NAME":    "ExtensionOID.SUBJECT_ALTERNATIVE_NAME",
    "ISSUER_ALT_NAME":     "ExtensionOID.ISSUER_ALTERNATIVE_NAME",
    "BASIC_CONSTRAINTS":   "ExtensionOID.BASIC_CONSTRAINTS",
    "NAME_CONSTRAINTS":    "ExtensionOID.NAME_CONSTRAINTS",
    "CRL_DISTRIBUTION":    "ExtensionOID.CRL_DISTRIBUTION_POINTS",
    "CRL_NUMBER":          "ExtensionOID.CRL_NUMBER",
    "DELTA_CRL_INDICATOR": "ExtensionOID.DELTA_CRL_INDICATOR",
    "ISSUING_DISTRIBUTION_POINT": "ExtensionOID.ISSUING_DISTRIBUTION_POINT",
    "FRESHEST_CRL":        "ExtensionOID.FRESHEST_CRL",
    "CRL_REASON_CODE":     "CRLEntryExtensionOID.CRL_REASON",
    "AD_OCSP":             "AuthorityInformationAccessOID.OCSP",
    "AD_CA_ISSUERS":       "AuthorityInformationAccessOID.CA_ISSUERS",
    "OCSP_NONCE":          "OCSPExtensionOID.NONCE",
    "OCSP_NOCHECK":        "ExtensionOID.OCSP_NO_CHECK",
    # python-cryptography names no constant for these two: it parses a
    # response without needing the responseType OID by name, and it has
    # no archive-cutoff support. Both are read back out of RFC 6960 in
    # `_OID_IN_RFCS` instead, which is the stronger of the two checks
    # anyway - it compares against the document that assigns them.
    "OCSP_BASIC":          None,
    "OCSP_ARCHIVE_CUTOFF": None,
    "CERTIFICATE_ISSUER":  "CRLEntryExtensionOID.CERTIFICATE_ISSUER",
    "INVALIDITY_DATE":     "CRLEntryExtensionOID.INVALIDITY_DATE",
    "CERTIFICATE_POLICIES": "ExtensionOID.CERTIFICATE_POLICIES",
    "AUTHORITY_KEY_ID":    "ExtensionOID.AUTHORITY_KEY_IDENTIFIER",
    "EXT_KEY_USAGE":       "ExtensionOID.EXTENDED_KEY_USAGE",
    "EKU_SERVER_AUTH":     "ExtendedKeyUsageOID.SERVER_AUTH",
    "EKU_CLIENT_AUTH":     "ExtendedKeyUsageOID.CLIENT_AUTH",
    "EKU_CODE_SIGNING":    "ExtendedKeyUsageOID.CODE_SIGNING",
    "EKU_EMAIL":           "ExtendedKeyUsageOID.EMAIL_PROTECTION",
    "EKU_TIME_STAMPING":   "ExtendedKeyUsageOID.TIME_STAMPING",
    "EKU_OCSP_SIGNING":    "ExtendedKeyUsageOID.OCSP_SIGNING",
    "EKU_ANY":             "ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE",
    "AUTHORITY_INFO_ACCESS": "ExtensionOID.AUTHORITY_INFORMATION_ACCESS",

    # GOST. python-cryptography carries exactly two of these - the pair
    # that names a *signature*, which is the pair a certificate parser
    # over there needs. Everything else on the TC 26 arc is absent
    # because OpenSSL's GOST support lives in an engine that this build
    # does not have, which is the same reason the algorithms themselves
    # have no differential reference.
    "GOST3410_12_256_WITH_DIGEST":
        "SignatureAlgorithmOID.GOSTR3410_2012_WITH_3411_2012_256",
    "GOST3410_12_512_WITH_DIGEST":
        "SignatureAlgorithmOID.GOSTR3410_2012_WITH_3411_2012_512",
    # The key-algorithm OIDs, one arc away from the signature ones above.
    # Covered indirectly: they share every arc but the last two with a
    # pair this table does check, so a mistyped prefix fails there.
    "GOST3410_12_256":     None,
    "GOST3410_12_512":     None,
    # The bare digest OIDs, in the same position as SHA256 and friends
    # above: not in any public table over there.
    "GOST3411_12_256":     None,
    "GOST3411_12_512":     None,
    # Curve parameter sets. `ec.EllipticCurveOID` has no 1.2.643 entry -
    # python-cryptography cannot do arithmetic on these curves, so it has
    # no name for them. `test_the_parameter_sets_name_our_curves` in
    # `src/x509/oids.rs` is what covers the mapping instead.
    "GOST_2001_CRYPTOPRO_A": None,
    "GOST_2001_CRYPTOPRO_B": None,
    "GOST_2001_CRYPTOPRO_C": None,
    "GOST_2001_CRYPTOPRO_XCHA": None,
    "GOST_2001_CRYPTOPRO_XCHB": None,
    # The 2001-era algorithm OIDs, from RFC 4357's ASN.1 module.
    # `cryptography` has no name for any of them - it does not
    # implement GOST at all - so the check that they are right is
    # `_check_oids_against_rfcs` below, which reads the module out of
    # the vendored document.
    "GOST3410_2001": None,
    "GOST3410_94": None,
    "GOST3411_94": None,
    "GOST3411_94_WITH_GOST3410_2001": None,
    "GOST3411_94_WITH_GOST3410_94": None,
    "GOST3411_94_CRYPTOPRO_PARAMSET": None,
    "GOST3411_94_TEST_PARAMSET": None,
    "GOST_28147_CRYPTOPRO_A": None,
    "GOST_2012_256_PARAMSET_A": None,
    "GOST_2012_256_PARAMSET_B": None,
    "GOST_2012_256_PARAMSET_C": None,
    "GOST_2012_256_PARAMSET_D": None,
    "GOST_2012_512_PARAMSET_TEST": None,
    "GOST_2012_512_PARAMSET_A": None,
    "GOST_2012_512_PARAMSET_B": None,
    "GOST_2012_512_PARAMSET_C": None,
    # The S-box parameter set RFC 9189's CNT_IMIT suite names. RFC 9189
    # section 4.3.1 prints the number, which is where this one came from.
    "GOST_28147_PARAM_Z":  None,
}


def check_oids(lines):
    """`src/x509/oids.rs`, against an encoder and a table that are not ours.

    A wrong OID is close to the worst bug available in this library. One
    that never matches means an extension is silently unrecognised - and
    an unrecognised *critical* extension must cause rejection, while an
    unrecognised basicConstraints means not noticing that a leaf
    certificate claims to be a CA.

    The Rust test in `oids.rs` checks each constant against
    `asn1::encode_oid`. That is necessary and not sufficient for two
    reasons, and this covers both:

      * if `encode_oid` were wrong, every constant would agree with it and
        every one would be wrong. So the dotted form is re-encoded here by
        an encoder written from X.690.
      * nothing checked that the dotted string is the number the world
        assigns to that *name*. Both sides of that comparison were typed
        from one glance at one document. So each constant's name is looked
        up in python-cryptography's tables, which are OpenSSL's.

    Constants with no counterpart over there are listed as `None` in
    `_OID_EQUIVALENTS` with a reason, and this prints how many - so the
    coverage of the check is visible rather than implied. A constant
    missing from that map entirely is an error: adding one to `oids.rs`
    must not quietly land outside the check.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    theirs = _their_oid_table()
    curves = {name: getattr(ec.EllipticCurveOID, name).dotted_string
              for name in dir(ec.EllipticCurveOID) if not name.startswith("_")}

    checked = 0
    cross_checked = 0
    unmapped = []
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "oid":
            continue
        name, dotted, got = parts[1], parts[2], unhex(parts[3])

        want = _encode_oid(dotted)
        if got != want:
            raise Mismatch(f"{name} ({dotted})\n"
                           f"  ours: {got.hex()}\n  ref : {want.hex()}")
        checked += 1

        if name not in _OID_EQUIVALENTS:
            raise Mismatch(
                f"{name} is in oids.rs and not in _OID_EQUIVALENTS. Add it, "
                f"with None and a reason if no other library has it - a new "
                f"constant must not land outside this check silently.")

        equivalent = _OID_EQUIVALENTS[name]
        if equivalent is None:
            unmapped.append(name)
            continue

        if equivalent.startswith("openssl:"):
            # Checked against OpenSSL's object table instead, which is
            # the only thing on this machine that carries the
            # password-based encryption OIDs.
            want = equivalent.split(":", 1)[1]
            got = _openssl_name_for(dotted)
            if got is None:
                raise Mismatch(
                    f"{name}: OpenSSL does not know {dotted}. Either the "
                    f"number is wrong, or this needs to become None with a "
                    f"reason.")
            if got != want:
                raise Mismatch(
                    f"{name}: we say {dotted} is {want!r}, OpenSSL says "
                    f"{got!r}. One of us has the wrong number for this name.")
            cross_checked += 1
            continue

        if equivalent.startswith("curve:"):
            their_dotted = curves.get(equivalent.split(":", 1)[1])
        else:
            their_dotted = theirs.get(equivalent)
        if their_dotted is None:
            raise Mismatch(
                f"{name} maps to {equivalent!r}, which python-cryptography "
                f"does not have. The map is wrong, or their table moved.")
        if their_dotted != dotted:
            raise Mismatch(
                f"{name}: we say {dotted}, {equivalent} says {their_dotted}. "
                f"One of us has the wrong number for this name.")
        cross_checked += 1

    if not checked:
        raise Mismatch("the OID corpus was empty")

    from_rfcs = _check_oids_against_rfcs(lines)

    print(f"  ({cross_checked} of {checked} cross-checked against "
          f"python-cryptography; {len(unmapped)} have no counterpart there: "
          f"{', '.join(unmapped)} - see the notes in _OID_EQUIVALENTS for "
          f"how each of those is covered, or that it is not)")
    print(f"  ({from_rfcs} of {checked} read back out of the RFCs in rfcs/)")
    return checked


#: Our constant -> the name the standard that defines it gives it.
#:
#: Same discipline as `_OID_EQUIVALENTS` and a different source. It maps
#: *our name* to *the RFC's name*, and the check is that the RFC's
#: number for that name is ours - which catches the one thing a check by
#: value cannot see: a dotted string that is a perfectly real OID, just
#: not the one we think it is.
#:
#: python-cryptography knows fifty-two of these. The RFCs know
#: seventy-three, including every GOST one - which OpenSSL here has no
#: name for at all, its GOST engine not being built.
#:
#: `None` means no vendored RFC defines it, with the reason. A constant
#: missing from this map entirely is an error, for the same reason as
#: over there: a new constant must not land outside the check silently.
_OID_IN_RFCS = {
    # RFC 8410 section 3 states all four as `id-Name OBJECT IDENTIFIER
    # ::= { 1 3 101 nnn }`, which is the arc-list shape `rfc_oids.py`
    # already reads. Vendored for that.
    "ID_ED25519":          "id-Ed25519",
    "ID_ED448":            "id-Ed448",
    "ID_X25519":           "id-X25519",
    "ID_X448":             "id-X448",
    # RFC 3279 section 2.3.2 and 2.2.2, RFC 5758 section 3.1.
    "ID_DSA":              "id-dsa",
    "DSA_WITH_SHA1":       "id-dsa-with-sha1",
    "DSA_WITH_SHA224":     "id-dsa-with-sha224",
    "DSA_WITH_SHA256":     "id-dsa-with-sha256",
    # NIST's CSOR arc, assigned by no RFC vendored here; python-cryptography
    # has both numbers (`_OID_EQUIVALENTS`).
    "DSA_WITH_SHA384":     None,
    "DSA_WITH_SHA512":     None,
    # RFC 9881 section 2, stated as named arcs.
    "ID_ML_DSA_44":        "id-ml-dsa-44",
    "ID_ML_DSA_65":        "id-ml-dsa-65",
    "ID_ML_DSA_87":        "id-ml-dsa-87",

    # Password based encryption. RFC 8018 assigns the PKCS#5 ones and
    # the PBKDF2 PRFs; RFC 7292 assigns the PKCS#12 ones.
    #
    # Two spellings below are not typos here: RFC 7292 names the
    # PKCS#12 schemes `pbeWithSHAAnd..`, without the `1` that OpenSSL
    # and everyone else puts in `SHA1`, and it spells the 40 bit RC2 one
    # `pbewithSHAAnd40BitRC2-CBC` with a lowercase `w` - a typo in the
    # document that the document is nevertheless the authority for.
    "PBE_MD2_DES":         "pbeWithMD2AndDES-CBC",
    "PBE_MD5_DES":         "pbeWithMD5AndDES-CBC",
    "PBE_MD2_RC2":         "pbeWithMD2AndRC2-CBC",
    "PBE_MD5_RC2":         "pbeWithMD5AndRC2-CBC",
    "PBE_SHA1_DES":        "pbeWithSHA1AndDES-CBC",
    "PBE_SHA1_RC2":        "pbeWithSHA1AndRC2-CBC",
    "PBKDF2":              "id-PBKDF2",
    # Sun's arc; no RFC assigns either.
    "JKS_KEY_PROTECTOR":   None,
    "JCE_KEY_PROTECTOR":   None,
    "PBES2":               "id-PBES2",
    "HMAC_WITH_SHA1":      "id-hmacWithSHA1",
    "HMAC_WITH_SHA224":    "id-hmacWithSHA224",
    "HMAC_WITH_SHA256":    "id-hmacWithSHA256",
    "HMAC_WITH_SHA384":    "id-hmacWithSHA384",
    "HMAC_WITH_SHA512":    "id-hmacWithSHA512",
    "HMAC_WITH_SHA512_224": "id-hmacWithSHA512-224",
    "HMAC_WITH_SHA512_256": "id-hmacWithSHA512-256",
    "PBE_SHA1_128_RC4":    "pbeWithSHAAnd128BitRC4",
    "PBE_SHA1_RC4_40":     "pbeWithSHAAnd40BitRC4",
    "PBE_SHA1_3DES":       "pbeWithSHAAnd3-KeyTripleDES-CBC",
    "PBE_SHA1_2DES":       "pbeWithSHAAnd2-KeyTripleDES-CBC",
    "PBE_SHA1_RC2_128":    "pbeWithSHAAnd128BitRC2-CBC",
    "PBE_SHA1_RC2_40":     "pbewithSHAAnd40BitRC2-CBC",
    "DES_CBC":             "desCBC",
    "DES_EDE3_CBC":        "des-EDE3-CBC",
    "RC2_CBC":             "rc2CBC",
    # RFC 8018 calls the AES ones `-PAD` because in PBES2 the plaintext
    # is always padded; the OID is the same one everybody else calls
    # `aes-128-cbc`.
    "AES128_CBC":          "aes128-CBC-PAD",
    "AES192_CBC":          "aes192-CBC-PAD",
    "AES256_CBC":          "aes256-CBC-PAD",

    "RSA_ENCRYPTION":      "rsaEncryption",
    "SHA1_WITH_RSA":       "sha1WithRSAEncryption",
    "SHA224_WITH_RSA":     "sha224WithRSAEncryption",
    "SHA256_WITH_RSA":     "sha256WithRSAEncryption",
    "SHA384_WITH_RSA":     "sha384WithRSAEncryption",
    "SHA512_WITH_RSA":     "sha512WithRSAEncryption",
    "RSASSA_PSS":          "id-RSASSA-PSS",
    "MD5_WITH_RSA":        "md5WithRSAEncryption",
    "MD2_WITH_RSA":        "md2WithRSAEncryption",
    "EC_PUBLIC_KEY":       "id-ecPublicKey",
    "ECDSA_WITH_SHA1":     "ecdsa-with-SHA1",
    "ECDSA_WITH_SHA224":   "ecdsa-with-SHA224",
    "ECDSA_WITH_SHA256":   "ecdsa-with-SHA256",
    "ECDSA_WITH_SHA384":   "ecdsa-with-SHA384",
    "ECDSA_WITH_SHA512":   "ecdsa-with-SHA512",
    # RFC 5480 names the curves by their SEC 2 names, which is where
    # they come from.
    "PRIME256V1":          "secp256r1",
    "SECP384R1":           "secp384r1",
    "SECP521R1":           "secp521r1",
    # secp256k1 is in SEC 2 and in no RFC. RFC 5480 lists the curves it
    # recommends and this is not one of them - it is Bitcoin's curve,
    # and it is here because certificates using it exist. Covered by
    # python-cryptography instead, which does have a name for it.
    "SECP256K1":           None,
    "SHA1":                "id-sha1",
    "SHA224":              "id-sha224",
    "SHA256":              "id-sha256",
    "SHA384":              "id-sha384",
    "SHA512":              "id-sha512",
    # RFC 4055 stops at SHA-512. The truncated SHA-512s are in NIST's
    # CSOR and the SHA-3 family and the SHAKEs are too - no RFC vendored
    # here assigns them, and RFC 8702, which uses the SHAKE OIDs, does
    # not state their arcs in a shape `rfc_oids.py` reads. All six are
    # covered by OpenSSL's object table instead, above.
    "SHA512_224":          None,
    "SHA512_256":          None,
    "SHA3_224":            None,
    "SHA3_256":            None,
    "SHA3_384":            None,
    "SHA3_512":            None,
    "SHAKE128":            None,
    "SHAKE256":            None,
    # RFC 5280's DN attributes, stated as `name AttributeType ::= ...`.
    "COMMON_NAME":         "id-at-commonName",
    "SURNAME":             "id-at-surname",
    "SERIAL_NUMBER":       "id-at-serialNumber",
    "COUNTRY":             "id-at-countryName",
    "LOCALITY":            "id-at-localityName",
    "STATE_OR_PROVINCE":   "id-at-stateOrProvinceName",
    # RFC 5280 has no `id-at-streetAddress`; RFC 4519 states it in
    # LDAP's schema syntax as `street`, which is the fourth shape the
    # parser handles.
    "STREET_ADDRESS":      "street",
    "ORGANIZATION":        "id-at-organizationName",
    "ORGANIZATIONAL_UNIT": "id-at-organizationalUnitName",
    "TITLE":               "id-at-title",
    "GIVEN_NAME":          "id-at-givenName",
    "EMAIL_ADDRESS":       "id-emailAddress",
    "DOMAIN_COMPONENT":    "id-domainComponent",
    # Likewise LDAP-only. RFC 4519 states it as `uid`.
    "USER_ID":             "uid",
    "SUBJECT_KEY_ID":      "id-ce-subjectKeyIdentifier",
    "KEY_USAGE":           "id-ce-keyUsage",
    "SUBJECT_ALT_NAME":    "id-ce-subjectAltName",
    "ISSUER_ALT_NAME":     "id-ce-issuerAltName",
    "BASIC_CONSTRAINTS":   "id-ce-basicConstraints",
    "NAME_CONSTRAINTS":    "id-ce-nameConstraints",
    "CRL_NUMBER":          "id-ce-cRLNumber",
    "CRL_REASON_CODE":     "id-ce-cRLReasons",
    "AD_OCSP":             "id-ad-ocsp",
    "AD_CA_ISSUERS":       "id-ad-caIssuers",
    "OCSP_BASIC":          "id-pkix-ocsp-basic",
    "OCSP_NONCE":          "id-pkix-ocsp-nonce",
    "OCSP_NOCHECK":        "id-pkix-ocsp-nocheck",
    "OCSP_ARCHIVE_CUTOFF": "id-pkix-ocsp-archive-cutoff",
    "INVALIDITY_DATE":     "id-ce-invalidityDate",
    "DELTA_CRL_INDICATOR": "id-ce-deltaCRLIndicator",
    "ISSUING_DISTRIBUTION_POINT": "id-ce-issuingDistributionPoint",
    "CERTIFICATE_ISSUER":  "id-ce-certificateIssuer",
    "FRESHEST_CRL":        "id-ce-freshestCRL",
    "CRL_DISTRIBUTION":    "id-ce-cRLDistributionPoints",
    "CERTIFICATE_POLICIES": "id-ce-certificatePolicies",
    "AUTHORITY_KEY_ID":    "id-ce-authorityKeyIdentifier",
    "EXT_KEY_USAGE":       "id-ce-extKeyUsage",
    "EKU_SERVER_AUTH":     "id-kp-serverAuth",
    "EKU_CLIENT_AUTH":     "id-kp-clientAuth",
    "EKU_CODE_SIGNING":    "id-kp-codeSigning",
    "EKU_EMAIL":           "id-kp-emailProtection",
    "EKU_TIME_STAMPING":   "id-kp-timeStamping",
    "EKU_OCSP_SIGNING":    "id-kp-OCSPSigning",
    "EKU_ANY":             "anyExtendedKeyUsage",
    "AUTHORITY_INFO_ACCESS": "id-pe-authorityInfoAccess",
    # GOST, from RFC 9215 (keys and signatures), RFC 7836 (the TC 26
    # parameter sets) and RFC 4357 (the CryptoPro ones). None of these
    # has a python-cryptography name except the two signature OIDs, so
    # the RFCs are the only check the other thirteen have.
    "GOST3410_12_256":     "id-tc26-gost3410-12-256",
    "GOST3410_12_512":     "id-tc26-gost3410-12-512",
    "GOST3411_12_256":     "id-tc26-gost3411-12-256",
    "GOST3411_12_512":     "id-tc26-gost3411-12-512",
    "GOST3410_12_256_WITH_DIGEST": "id-tc26-signwithdigest-gost3410-12-256",
    "GOST3410_12_512_WITH_DIGEST": "id-tc26-signwithdigest-gost3410-12-512",
    "GOST_2001_CRYPTOPRO_A": "id-GostR3410-2001-CryptoPro-A-ParamSet",
    "GOST_2001_CRYPTOPRO_B": "id-GostR3410-2001-CryptoPro-B-ParamSet",
    "GOST_2001_CRYPTOPRO_C": "id-GostR3410-2001-CryptoPro-C-ParamSet",
    "GOST_2001_CRYPTOPRO_XCHA": "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
    "GOST_2001_CRYPTOPRO_XCHB": "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
    "GOST3410_2001": "id-GostR3410-2001",
    "GOST3410_94": "id-GostR3410-94",
    "GOST3411_94": "id-GostR3411-94",
    "GOST3411_94_WITH_GOST3410_2001": "id-GostR3411-94-with-GostR3410-2001",
    "GOST3411_94_WITH_GOST3410_94": "id-GostR3411-94-with-GostR3410-94",
    "GOST3411_94_CRYPTOPRO_PARAMSET": "id-GostR3411-94-CryptoProParamSet",
    "GOST3411_94_TEST_PARAMSET": "id-GostR3411-94-TestParamSet",
    "GOST_28147_CRYPTOPRO_A": "id-Gost28147-89-CryptoPro-A-ParamSet",
    "GOST_2012_256_PARAMSET_A": "id-tc26-gost-3410-2012-256-paramSetA",
    "GOST_2012_256_PARAMSET_B": "id-tc26-gost-3410-2012-256-paramSetB",
    "GOST_2012_256_PARAMSET_C": "id-tc26-gost-3410-2012-256-paramSetC",
    "GOST_2012_256_PARAMSET_D": "id-tc26-gost-3410-2012-256-paramSetD",
    "GOST_2012_512_PARAMSET_TEST": "id-tc26-gost-3410-2012-512-paramSetTest",
    "GOST_2012_512_PARAMSET_A": "id-tc26-gost-3410-2012-512-paramSetA",
    "GOST_2012_512_PARAMSET_B": "id-tc26-gost-3410-2012-512-paramSetB",
    "GOST_2012_512_PARAMSET_C": "id-tc26-gost-3410-2012-512-paramSetC",
    "GOST_28147_PARAM_Z":  "id-tc26-gost-28147-param-Z",
}

#: The parser must keep finding roughly what it finds today.
#:
#: A parser that quietly stops handling one of the RFCs' shapes turns
#: constants into "not found", which the census below already catches -
#: but it would also stop finding the hundreds of names nobody here
#: maps, and nothing would notice that. A floor well under the current
#: count fails on a real regression and not on an RFC being added.
_RFC_NAMES_FLOOR = 250


def _check_oids_against_rfcs(lines):
    """Every constant, against the RFC that defines it.

    The third opinion, and the widest: `scripts/rfc_oids.py` reads the
    documents in `rfcs/` and this asks each of them for the number it
    assigns to the name we believe the constant has.
    """
    import rfc_oids

    # The parser's own tests first, so a parser that has stopped
    # handling one of the four shapes fails by that shape's name rather
    # than as a pile of missing constants.
    rfc_oids.tests()

    by_name, _ = rfc_oids.load()
    if len(by_name) < _RFC_NAMES_FLOOR:
        raise Mismatch(
            f"rfc_oids resolved only {len(by_name)} names from rfcs/, and the "
            f"floor is {_RFC_NAMES_FLOOR}. The parser has stopped handling "
            f"something, or a document went missing.")

    found = 0
    absent = []
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "oid":
            continue
        name, dotted = parts[1], parts[2]

        if name not in _OID_IN_RFCS:
            raise Mismatch(
                f"{name} is in oids.rs and not in _OID_IN_RFCS. Add it, with "
                f"None and a reason if no vendored RFC defines it - a new "
                f"constant must not land outside this check silently.")

        rfc_name = _OID_IN_RFCS[name]
        if rfc_name is None:
            absent.append(name)
            continue

        theirs = by_name.get(rfc_name)
        if theirs is None:
            raise Mismatch(
                f"{name} maps to {rfc_name!r}, which no document in rfcs/ "
                f"defines. The map is wrong, or the parser stopped finding it.")
        if theirs != dotted:
            raise Mismatch(
                f"{name}: we say {dotted}, and the RFC says {rfc_name} is "
                f"{theirs}. One of us has the wrong number for this name.")
        found += 1

    if absent:
        print(f"  (no vendored RFC defines: {', '.join(absent)})")
    return found



# --------------------------------------------------- GOST R 34.10-2012 ---

def check_gost3410(lines):
    """GOST R 34.10-2012 signatures, against a reading of the standard.

    Verification is the whole check. A signature scheme that signs and
    verifies against itself proves only that its two halves agree; what
    has to be true is that the equation is the standard's and the byte
    conventions are everyone's. So this recomputes the verification here
    and accepts or rejects each signature.

    The two conventions only this can catch:

      * the digest is read **little endian**, which is what OpenSSL's
        GOST engine does (`BN_lebin2bn`) and what makes Streebog's
        array-order output come out as the standard's number;
      * the signing equation is `s = r*d + k*e` with no inversion, so
        verification needs `e^-1` where ECDSA needs `s^-1`. Getting that
        backwards gives a scheme that is internally consistent and is not
        GOST.

    And one that is not a convention at all: the wire order is `s || r`,
    the opposite of ECDSA's. Two integers of the same width swapped is a
    signature of the right length that parses cleanly, so the split is
    done here from the standard rather than from our encoder.

    Nothing on this machine implements GOST R 34.10, so this is a second
    reading of the standard rather than somebody else's code - the same
    claim and the same caveat as the rest of the GOST work.
    """
    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "sign":
            continue
        name = parts[1]
        private = int.from_bytes(unhex(parts[2]), "big")
        public = (int.from_bytes(unhex(parts[3]), "big"),
                  int.from_bytes(unhex(parts[4]), "big"))
        digest, signature = unhex(parts[5]), unhex(parts[6])

        curve = _gost_curve(name)
        width = (curve.n.bit_length() + 7) // 8

        # The key is recomputed rather than trusted: this never has to
        # take our scalar multiplication on faith.
        if curve.mul(private, curve.g) != public:
            raise Mismatch(f"{name}: d*G is not the public key in the row")

        if len(signature) != 2 * width:
            raise Mismatch(f"{name}: signature is {len(signature)} bytes, "
                           f"expected {2 * width}")
        # s first. The opposite of ECDSA.
        sig_s = int.from_bytes(signature[:width], "big")
        sig_r = int.from_bytes(signature[width:], "big")
        if not (0 < sig_r < curve.n and 0 < sig_s < curve.n):
            raise Mismatch(f"{name}: a signature component is out of range")

        # Little endian, then reduce, then zero becomes one.
        e = int.from_bytes(digest, "little") % curve.n or 1

        v = pow(e, -1, curve.n)
        z1 = sig_s * v % curve.n
        z2 = (curve.n - sig_r) * v % curve.n
        point = curve.add(curve.mul(z1, curve.g), curve.mul(z2, public))
        if point is None or point[0] % curve.n != sig_r:
            raise Mismatch(
                f"GOST R 34.10 signature on {name} does not verify\n"
                f"  r = {sig_r:x}\n  s = {sig_s:x}")

        # And the mistakes must *not* verify, or this check would pass on
        # an implementation that made them.
        big_endian = int.from_bytes(digest, "big") % curve.n or 1
        if big_endian != e:
            wrong_v = pow(big_endian, -1, curve.n)
            wrong = curve.add(curve.mul(sig_s * wrong_v % curve.n, curve.g),
                              curve.mul((curve.n - sig_r) * wrong_v % curve.n,
                                        public))
            if wrong is not None and wrong[0] % curve.n == sig_r:
                raise Mismatch(f"{name}: the signature verifies under *both* "
                               f"digest readings, so this check proves nothing")
        checked += 1

    if not checked:
        raise Mismatch("the GOST R 34.10 corpus was empty")
    return checked



# ------------------------------------------------------------------- VKO ---

def _vko(curve, private, peer, ukm_value, bits, cofactor=True):
    """VKO_GOSTR3410_2012_{256,512}, RFC 7836 section 4.3, with the UKM
    already an integer.

    Taking the number rather than the wire bytes is deliberate: the wire
    form is little endian and RFC 9189's KEG reads its UKM big endian
    from a hash prefix, so the two callers disagree about byte order and
    neither should inherit the other's.

    `cofactor` picks between the two readings of the scalar, and there
    is no default that is right for both callers:

      * `True` is RFC 7836's `K = (m/q * UKM * x mod q) * (y*P)`, where
        `m/q` is the cofactor `h`;
      * `False` is what OpenSSL's GOST engine computes -
        `BN_mod_mul(X, ukm, priv, order)` in `VKO_compute_key`, with no
        `m/q` anywhere.

    They are the same number on every curve with `h = 1`, which is every
    curve RFC 9189's suites are keyed on, and differ on `gost256-tc26-a`
    and `gost512-c`, where `m = 4q`. No document settles it and no
    published vector exists for either, so both are checked and the
    caller says which it meant - the TLS path means the deployed one,
    because the point of that code is to reach a box running
    gost-engine.
    """
    value = ukm_value % curve.n
    if value == 0:
        raise Mismatch("the UKM is zero mod n")
    h = curve.h if cofactor else 1
    point = curve.mul(h * value * private % curve.n, peer)
    if point is None:
        raise Mismatch("the exchange produced the identity")
    blob = (point[0].to_bytes(curve.size, "little")
            + point[1].to_bytes(curve.size, "little"))
    return streebog(blob, bits)


def check_vko(lines):
    """VKO key agreement, RFC 7836 section 4.3, against a reading of it.

    **This corpus matters more than most, because VKO is symmetric.**
    Both sides compute `ukm * da * db * G`, and the order of the
    multiplications does not matter - so a round trip between two ends of
    the same implementation produces a matching key whichever way round
    the UKM is read and whichever way round the coordinates are
    serialised. Every one of those mistakes is invisible from inside and
    produces a key a real peer will not have. Only a second
    implementation can see it.

    The three conventions:

      * the UKM is a **little endian** integer;
      * both coordinates are written **little endian**, x then y, each
        padded to the *field's* width - not the group order's, a
        different number with the same byte length on every curve here;
      * the digest size follows the key, not the curve.

    And the fourth thing, which is not a byte order: **the cofactor.**
    RFC 7836's formula is `K = (m/q * UKM * x mod q) * (y*P)` and `m/q`
    is `h`. Both readings are in the corpus, as `vko` and
    `vkonocofactor` rows, and only the first matches anything: the
    second was once believed to be OpenSSL's GOST engine, on a
    misreading of `VKO_compute_key`, and `vectors/gost_engine.vec`
    showed the engine applies the cofactor too - inside its point
    multiplication. The rows stay because the *distinction* is what
    keeps `vko_using` honest: they coincide on every curve with `h = 1`,
    and `diff_vko.rs` asserts they differ on the two where `h = 4`, so
    neither kind can quietly turn into the other.

    That is also the clearest thing this corpus cannot do. It agreed
    with itself at every length and on every curve while the TLS key
    exchange was pointed at the wrong reading, because both sides of it
    were the same reading. `tests/test_gost_engine_vectors.rs` is what
    found it.

    Both directions are recomputed, so a mistake on one side alone is
    visible rather than cancelling.
    """
    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] not in ("vko", "vkonocofactor"):
            continue
        cofactor = parts[0] == "vko"
        name = parts[1]
        da = int.from_bytes(unhex(parts[2]), "big")
        db = int.from_bytes(unhex(parts[3]), "big")
        ukm, bits, got = unhex(parts[4]), int(parts[5]), parts[6]

        curve = _gost_curve(name)
        width = curve.size

        qa = curve.mul(da, curve.g)
        qb = curve.mul(db, curve.g)

        def kek(private, peer, cofactor=cofactor):
            # The wire UKM is little endian; `_vko` takes the number.
            return _vko(curve, private, peer,
                        int.from_bytes(ukm, "little"), bits, cofactor)

        # `h` for this row's reading, so the wrong-reading checks below
        # isolate the byte order rather than passing because the
        # cofactor already made the values differ.
        h = curve.h if cofactor else 1

        want = kek(da, qb)
        # Both directions, so a mistake on one side alone does not cancel.
        if kek(db, qa) != want:
            raise Mismatch(f"{name}: the reference disagrees with itself")

        if got != want.hex():
            raise Mismatch(f"VKO ({parts[0]}) on {name} at {bits} bits\n"
                           f"  ours: {got}\n  ref : {want.hex()}")

        # And the mistakes must not also produce this key, or the check
        # would pass on an implementation that made them.
        if len(set(ukm)) > 1:
            big_endian = int.from_bytes(ukm, "big") % curve.n
            if big_endian and big_endian != int.from_bytes(ukm, "little") % curve.n:
                point = curve.mul(h * big_endian * da % curve.n, qb)
                blob = (point[0].to_bytes(width, "little")
                        + point[1].to_bytes(width, "little"))
                if streebog(blob, bits) == want:
                    raise Mismatch(f"{name}: the key is the same under both "
                                   f"UKM readings, so this proves nothing")

        point = curve.mul(
            h * (int.from_bytes(ukm, "little") % curve.n) * da % curve.n, qb)
        swapped = (point[0].to_bytes(width, "big")
                   + point[1].to_bytes(width, "big"))
        if swapped != (point[0].to_bytes(width, "little")
                       + point[1].to_bytes(width, "little")):
            if streebog(swapped, bits) == want:
                raise Mismatch(f"{name}: the key is the same under both "
                               f"coordinate orders, so this proves nothing")
        checked += 1

    if not checked:
        raise Mismatch("the VKO corpus was empty")
    return checked


def _hmac_streebog256(key, message):
    """HMAC (RFC 2104) over Streebog-256, whose block is 64 bytes.

    Written out rather than handed to Python's `hmac`, which needs a
    hashlib-shaped object and this reference is a plain function. The
    block size is the trap: Streebog-256 has a 32 byte digest and a 64
    byte block, so an HMAC that pads to the *digest* length agrees with
    itself and with nothing else.
    """
    block = 64
    if len(key) > block:
        key = streebog(key, 256)
    key = key + bytes(block - len(key))
    inner = streebog(bytes(b ^ 0x36 for b in key) + message, 256)
    return streebog(bytes(b ^ 0x5C for b in key) + inner, 256)


def _kdf_gostr3411_2012_256(key, label, seed):
    """RFC 7836 section 4.5.

    The framing is the whole content of this function, and every byte of
    it is load bearing. `KDF(K, label, seed)` is the R = 1, L = 256 case
    of the tree KDF in section 4.4, so:

      * the leading `0x01` is the block counter, not padding;
      * the `0x00` separates label from seed;
      * the trailing `0x01 0x00` is `STR_2(256)`, the output length.

    Drop any of them and the result is a perfectly deterministic function
    that is not this one.
    """
    framed = b"\x01" + label + b"\x00" + seed + b"\x01\x00"
    return _hmac_streebog256(key, framed)


# RFC 9189 section 8.1.1. The two suites re-key at different rates: a 64
# bit block wears out sooner, so Magma changes its lower levels more
# often and its top level less.
_TLSTREE_PARAMS = {
    "magma": (0xFFFFFFC000000000, 0xFFFFFFFFFE000000, 0xFFFFFFFFFFFFF000),
    "kuznyechik": (0xFFFFFFFF00000000, 0xFFFFFFFFFFF80000, 0xFFFFFFFFFFFFFFC0),
}


def check_tlstree(lines):
    """RFC 7836's KDF and RFC 9189's TLSTREE, against a reading of them.

    Nothing on this machine implements either, so the reference above is
    written from the RFCs' prose. Weaker than OpenSSL, and the strongest
    thing available; the RFCs' own vectors live in the unit tests and
    this corpus covers the space between them.

    What that space is for. Every mistake worth worrying about here is a
    *framing* mistake - the counter byte, the separator, the trailing
    length, the endianness of `STR_8` - and framing mistakes hide behind
    fixed lengths. The corpus sweeps label and seed lengths across the 64
    byte Streebog block in both directions, and walks the sequence number
    across every mask boundary of both suites.

    The checks that stop it passing vacuously:

      * `STR_8` is **big endian** (RFC 9189 section 3, which also defines
        a little endian `str_8` and uses both), and the reference asserts
        the reversed reading gives a *different* key;
      * the suites' constants are not interchangeable, and the reference
        asserts the other suite's constants give a different key wherever
        the two masks actually differ at that sequence number. At
        sequence 0 every mask is zero and the suites agree, which is
        why that assertion is conditional rather than absent.
    """
    checked = 0
    for line in lines:
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "kdf":
            key, label, seed, got = (unhex(parts[1]), unhex(parts[2]),
                                     unhex(parts[3]), parts[4])
            want = _kdf_gostr3411_2012_256(key, label, seed)
            if got != want.hex():
                raise Mismatch(f"KDF_GOSTR3411_2012_256 with a {len(label)} "
                               f"byte label and a {len(seed)} byte seed\n"
                               f"  ours: {got}\n  ref : {want.hex()}")

            # Unframed HMAC must not also produce it, or a KDF that
            # dropped the counter and the length would pass here.
            if _hmac_streebog256(key, label + seed).hex() == got:
                raise Mismatch("the framed and unframed inputs agree, so this "
                               "row proves nothing about the framing")
            checked += 1
            continue

        if parts[0] != "tlstree":
            continue

        suite, root, sequence = parts[1], unhex(parts[2]), int(parts[3])
        got = (parts[4], parts[5], parts[6])
        masks = _TLSTREE_PARAMS[suite]

        def levels(constants, big_endian=True):
            order = "big" if big_endian else "little"
            key = root
            out = []
            for level, mask in enumerate(constants, start=1):
                key = _kdf_gostr3411_2012_256(
                    key, f"level{level}".encode(),
                    (sequence & mask).to_bytes(8, order))
                out.append(key)
            return out

        want = levels(masks)
        if list(got) != [k.hex() for k in want]:
            raise Mismatch(
                f"TLSTREE for {suite} at sequence {sequence}\n"
                f"  ours: {' '.join(got)}\n"
                f"  ref : {' '.join(k.hex() for k in want)}")

        # STR_8 is big endian. Where the masked value is not a
        # palindrome, the reversed reading must give a different key.
        for mask in masks:
            masked = (sequence & mask).to_bytes(8, "big")
            if masked != masked[::-1]:
                if levels(masks, big_endian=False) == want:
                    raise Mismatch(
                        f"{suite} at {sequence}: the key is the same under "
                        f"both readings of STR_8, so this proves nothing")
                break

        # The other suite's constants must give a different key wherever
        # the masks actually differ - which they do not at sequence 0,
        # where every masked value is zero.
        other = _TLSTREE_PARAMS["kuznyechik" if suite == "magma" else "magma"]
        if any(sequence & a != sequence & b for a, b in zip(masks, other)):
            if levels(other) == want:
                raise Mismatch(
                    f"{suite} at {sequence}: the two suites' constants give "
                    f"the same key, so this proves nothing")
        checked += 1

    if not checked:
        raise Mismatch("the TLSTREE corpus was empty")
    return checked


_CTR_OMAC_SUITES = {
    # cipher, block/MAC length, ACPKM section size, TLSTREE constants
    "magma": ("magma", 8, 1024, _TLSTREE_PARAMS["magma"]),
    "kuznyechik": ("kuznyechik", 16, 4096, _TLSTREE_PARAMS["kuznyechik"]),
}


def _ctr_acpkm(name, key, iv, data):
    """CTR-ACPKM, RFC 8645 section 4.2, as RFC 9189 uses it.

    The counter block is `IV || 0^{n/2}` - the IV occupies the top half
    and the counter the bottom - and it runs across section boundaries
    rather than restarting when the key changes.
    """
    block_size, encrypt, _ = _GOST_CIPHERS[name]
    counter = int.from_bytes(iv + bytes(block_size - len(iv)), "big")
    out, current, in_section = bytearray(), key, 0
    section = _CTR_OMAC_SUITES[name][2]
    for offset in range(0, len(data), block_size):
        if in_section == section:
            current = _acpkm_next(lambda b, k=current: encrypt(k, b),
                                  block_size, len(current))
            in_section = 0
        chunk = data[offset:offset + block_size]
        keystream = encrypt(current, counter.to_bytes(block_size, "big"))
        out += _xor(keystream[:len(chunk)], chunk)
        counter = (counter + 1) % (1 << (8 * block_size))
        in_section += block_size
    return bytes(out)


def _omac(name, key, message):
    """OMAC (GOST R 34.13-2015), which is CMAC with a GOST block cipher.

    The tag is the whole block - 16 bytes for Kuznyechik, 8 for Magma -
    rather than truncated to a common length.
    """
    block_size, encrypt, _ = _GOST_CIPHERS[name]
    return _cmac_reference(lambda block: encrypt(key, block), block_size, message)


def check_ctr_omac(lines):
    """RFC 9189 section 4.1.1 record protection, against a reading of it.

    The primitives underneath each have a corpus of their own, so this
    one is about the composition, and the reference is assembled here
    from the pieces rather than taken from the Rust:

      * `K_ENC_n` and `K_MAC_n` are TLSTREE over the two connection keys
        at the record's sequence number;
      * `IV_n` is `sender_write_IV` **plus** the sequence number, modulo
        2^((n/2)*8) - the IV's own width, not 64 bits;
      * the MAC input is RFC 5246's, `seq | type | version | length |
        fragment`, under OMAC with `K_MAC_n`;
      * the record is `ENC(K_ENC_n, IV_n, fragment | MAC)` - the MAC is
        *inside* the ciphertext.

    The assertions that stop it passing vacuously:

      * the encrypt-then-MAC ordering (MAC over the ciphertext, appended
        in the clear) must give a different record. It has the same
        length, so nothing about the shape of a row rules it out;
      * XORing the sequence number into the IV instead of adding it must
        give a different record wherever the two differ;
      * the other suite's ACPKM section size must give a different
        record wherever the message is long enough to reach a boundary.
    """
    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "ctromac":
            continue

        suite = parts[1]
        enc_root, mac_root, iv = unhex(parts[2]), unhex(parts[3]), unhex(parts[4])
        sequence, content_type = int(parts[5]), int(parts[6])
        version, plaintext, got = unhex(parts[7]), unhex(parts[8]), parts[9]
        name, block, section, masks = _CTR_OMAC_SUITES[suite]

        if len(iv) * 2 != block:
            raise Mismatch(f"{suite}: the IV must be half a block")

        def tlstree(root):
            key = root
            for level, mask in enumerate(masks, start=1):
                key = _kdf_gostr3411_2012_256(
                    key, f"level{level}".encode(),
                    (sequence & mask).to_bytes(8, "big"))
            return key

        enc_key, mac_key = tlstree(enc_root), tlstree(mac_root)
        width = len(iv)
        record_iv = ((int.from_bytes(iv, "big") + sequence)
                     % (1 << (8 * width))).to_bytes(width, "big")

        framed = (sequence.to_bytes(8, "big") + bytes([content_type])
                  + version + len(plaintext).to_bytes(2, "big") + plaintext)
        tag = _omac(name, mac_key, framed)
        if len(tag) != block:
            raise Mismatch(f"{suite}: the OMAC tag must be a whole block")

        want = _ctr_acpkm(name, enc_key, record_iv, plaintext + tag)
        if got != want.hex():
            raise Mismatch(f"CTR_OMAC {suite} at sequence {sequence}, "
                           f"{len(plaintext)} byte fragment\n"
                           f"  ours: {got[:96]}\n  ref : {want.hex()[:96]}")

        # Encrypt-then-MAC has the same length and round-trips against
        # itself, so only a reference that tries it can rule it out.
        body = _ctr_acpkm(name, enc_key, record_iv, plaintext)
        swapped = body + _omac(
            name, mac_key,
            sequence.to_bytes(8, "big") + bytes([content_type]) + version
            + len(body).to_bytes(2, "big") + body)
        if swapped.hex() == got:
            raise Mismatch(f"{suite} at {sequence}: authenticate-then-encrypt "
                           f"and encrypt-then-MAC agree, so this proves "
                           f"nothing about the order")

        # The IV is added to, not XORed with. Where the two differ, the
        # record must differ.
        xored = (int.from_bytes(iv, "big") ^ sequence) % (1 << (8 * width))
        if xored != int.from_bytes(record_iv, "big"):
            other = _ctr_acpkm(name, enc_key, xored.to_bytes(width, "big"),
                               plaintext + tag)
            if other.hex() == got:
                raise Mismatch(f"{suite} at {sequence}: adding and XORing the "
                               f"sequence number into the IV agree, so this "
                               f"proves nothing")

        # The section sizes differ between the suites, and only a record
        # long enough to cross the smaller one can tell them apart.
        other_section = 1024 if section == 4096 else 4096
        if len(plaintext) + block > min(section, other_section):
            saved = _CTR_OMAC_SUITES[suite]
            _CTR_OMAC_SUITES[suite] = (name, block, other_section, masks)
            try:
                other = _ctr_acpkm(name, enc_key, record_iv, plaintext + tag)
            finally:
                _CTR_OMAC_SUITES[suite] = saved
            if other.hex() == got:
                raise Mismatch(f"{suite} at {sequence}: a {other_section} byte "
                               f"section gives the same record over {len(plaintext)} "
                               f"bytes, so this proves nothing about the size")
        checked += 1

    if not checked:
        raise Mismatch("the CTR_OMAC corpus was empty")
    return checked


# The parameter set and algorithm OIDs a GOST SubjectPublicKeyInfo
# carries, DER encoded. Written out here rather than imported from the
# Rust, which is the point of this file.
_GOST_SPKI_OIDS = {
    #  curve      -> (algorithm,           paramSet,              digest)
    "gost256-a": ("1.2.643.7.1.1.1.1", "1.2.643.2.2.35.1", "1.2.643.7.1.1.2.2"),
    "gost256-b": ("1.2.643.7.1.1.1.1", "1.2.643.2.2.35.2", "1.2.643.7.1.1.2.2"),
    "gost256-c": ("1.2.643.7.1.1.1.1", "1.2.643.2.2.35.3", "1.2.643.7.1.1.2.2"),
    "gost512-a": ("1.2.643.7.1.1.1.2", "1.2.643.7.1.2.1.2.1", "1.2.643.7.1.1.2.3"),
    "gost512-b": ("1.2.643.7.1.1.1.2", "1.2.643.7.1.2.1.2.2", "1.2.643.7.1.1.2.3"),
    "gost256-tc26-a": ("1.2.643.7.1.1.1.1", "1.2.643.7.1.2.1.1.1",
                       "1.2.643.7.1.1.2.2"),
    "gost512-c": ("1.2.643.7.1.1.1.2", "1.2.643.7.1.2.1.2.3", "1.2.643.7.1.1.2.3"),
}


def _der(tag, content):
    """One DER TLV. Only the short and two-byte long forms, which is all
    a key transport message needs."""
    if len(content) < 0x80:
        length = bytes([len(content)])
    elif len(content) < 0x100:
        length = bytes([0x81, len(content)])
    else:
        length = bytes([0x82, len(content) >> 8, len(content) & 0xFF])
    return bytes([tag]) + length + content


def _keg(curve, private, peer, h, bits):
    """KEG, RFC 9189 section 8.3.1.

    Two branches that are not variations on each other. The 256 bit one
    runs VKO-256 through the tree KDF to reach 64 bytes; the 512 bit one
    returns VKO-512 **unchanged**, because it already is 64 bytes.
    Running the KDF there too is the obvious thing to do and is wrong.

    **`cofactor=True`**, RFC 7836's reading, which matters on exactly
    two curves. This said `False` until `vectors/gost_engine.vec` was
    written, on the argument that the key exchange has to reach a real
    server and a real server runs OpenSSL's GOST engine, whose
    `VKO_compute_key` has no `m/q` term. The argument was right and the
    premise was wrong - the engine applies the cofactor inside
    `gost_ec_point_mul`, which `VKO_compute_key` says in a `#if 0`
    comment three lines down - so both readings pointed the same way
    after all. RFC 9189's own suites are keyed on curves with `h = 1`,
    where the question does not arise, but a certificate on
    `id-tc26-gost-3410-2012-512-paramSetC` reaches this code and there
    the two readings are different points. See docs/pitfalls.md 7o.
    """
    # UKM = INT(H[1..16]): **big endian**, RFC 9189 section 3. VKO's own
    # wire UKM is little endian, which is why `_vko` takes the number.
    ukm = int.from_bytes(h[:16], "big") or 1
    if bits == 256:
        k_exp = _vko(curve, private, peer, ukm, 256, cofactor=True)
        return _kdf_tree_gostr3411_2012_256(k_exp, b"kdf tree", h[16:24], 1, 512)
    return _vko(curve, private, peer, ukm, 512, cofactor=True)


def _kdf_tree_gostr3411_2012_256(key, label, seed, counter_bytes, bits):
    """RFC 7836 section 4.4. `[L]_b` has no leading zero bytes."""
    length = bits.to_bytes(4, "big").lstrip(b"\x00") or b"\x00"
    out = b""
    for block in range(1, (bits + 255) // 256 + 1):
        out += _hmac_streebog256(
            key, block.to_bytes(counter_bytes, "big") + label + b"\x00"
                 + seed + length)
    return out[:bits // 8]


def _kexp15(name, block, secret, mac_key, enc_key, iv):
    """KExp15, RFC 9189 section 8.2.1: `CTR(K_ENC, IV, S | OMAC(K_MAC, IV | S))`.

    The CTR is the plain one from GOST R 34.13-2015 - counter block
    `IV || 0^{n/2}` - with no ACPKM. The message is far inside one
    section, so the two agree here and the choice is invisible.
    """
    tag = _omac(name, mac_key, iv + secret)
    body = secret + tag
    block_size, encrypt, _ = _GOST_CIPHERS[name]
    counter = int.from_bytes(iv + bytes(block_size - len(iv)), "big")
    out = bytearray()
    for offset in range(0, len(body), block_size):
        chunk = body[offset:offset + block_size]
        out += _xor(encrypt(enc_key, counter.to_bytes(block_size, "big"))[:len(chunk)],
                    chunk)
        counter = (counter + 1) % (1 << (8 * block_size))
    return bytes(out)


def _gost_spki(name, point, little_endian=True, algorithm_id=None):
    """A GOST SubjectPublicKeyInfo, RFC 9215 section 4.3.

    `BIT STRING { OCTET STRING { x || y } }` - the double wrapping is
    real - with both coordinates little endian and padded to the field's
    width. `little_endian=False` builds the wrong one, so the checker
    can assert it differs.

    **`algorithm_id` is supplied by the caller for a ClientKeyExchange**,
    because there the client does not choose it: it copies the server's.
    `oids.gost_curve_for` is many-to-one - RFC 4357's `XchA` is
    CryptoPro-A to the digit and TC 26's `paramSetB` is too - so building
    the OID from the curve name is a *choice*, and a client that made it
    answered a server on `XchA` with the CryptoPro spelling. CryptoPro
    refuses that with `decode_error`. With no `algorithm_id` this falls
    back to the canonical one, which is right for a certificate we are
    writing ourselves.
    """
    curve = _gost_curve(name)
    order = "little" if little_endian else "big"
    raw = (point[0].to_bytes(curve.size, order)
           + point[1].to_bytes(curve.size, order))

    if algorithm_id is None:
        algorithm, param_set, digest = _GOST_SPKI_OIDS[name]
        def oid(dotted):
            return _der(0x06, _encode_oid(dotted))
        algorithm_id = _der(0x30, oid(algorithm)
                                  + _der(0x30, oid(param_set) + oid(digest)))
    return _der(0x30, algorithm_id + _der(0x03, b"\x00" + _der(0x04, raw)))


def check_gost_kex(lines):
    """RFC 9189 section 4.2.4.1's ClientKeyExchange, against a reading of it.

    The unit tests reproduce Appendix A.1.3.1 byte for byte, which pins
    one exchange on one curve. This covers the rest of the space, and
    the reason it needs to is that the message stacks four independent
    byte-order decisions, each of which works perfectly between two
    implementations that made it the same way:

      * `UKM = INT(H[1..16])` is big endian while VKO's wire UKM is
        little endian;
      * the shared point is hashed with little endian coordinates;
      * the ephemeral key's coordinates are little endian again in the
        SubjectPublicKeyInfo;
      * `seed = H[17..24]` and `IV = H[25..]` are adjacent slices.

    Each is recomputed the wrong way here and asserted to give a
    different message, so no row can pass vacuously. The 512 bit curves
    additionally pin KEG's other branch, which is VKO-512 with no KDF.
    """
    checked = 0
    # The parameter set OIDs the corpus actually used, so a row set that
    # quietly loses the non-canonical spellings is an error rather than a
    # smaller number. `XchA` and TC 26's `paramSetB` are CryptoPro-A's
    # curve under other names, and they are the rows that catch a client
    # rebuilding the OID from the curve.
    spellings = set()
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "kex":
            continue

        name, suite = parts[1], parts[2]
        d_eph = int.from_bytes(unhex(parts[3]), "big")
        d_s = int.from_bytes(unhex(parts[4]), "big")
        client_random, server_random = unhex(parts[5]), unhex(parts[6])
        pms, h_row = unhex(parts[7]), unhex(parts[8])
        mac_row, enc_row = parts[9], parts[10]
        # The AlgorithmIdentifier the row was built with. Carried in the
        # corpus rather than derived, for the reason in `_gost_spki`.
        algorithm_id, got = unhex(parts[11]), parts[12]

        curve = _gost_curve(name)
        bits = 256 if curve.size == 32 else 512
        cipher, block, _, _ = _CTR_OMAC_SUITES[suite]

        h = streebog(client_random + server_random, 256)
        if h != h_row:
            raise Mismatch(f"{name}: H = Streebog-256(r_c | r_s)\n"
                           f"  ours: {h_row.hex()}\n  ref : {h.hex()}")

        q_s = curve.mul(d_s, curve.g)
        q_eph = curve.mul(d_eph, curve.g)

        material = _keg(curve, d_eph, q_s, h, bits)
        if len(material) != 64:
            raise Mismatch(f"{name}: KEG produced {len(material)} bytes")
        mac_key, enc_key = material[:32], material[32:]
        if (mac_key.hex(), enc_key.hex()) != (mac_row, enc_row):
            raise Mismatch(f"KEG for {name}\n"
                           f"  ours: {mac_row} {enc_row}\n"
                           f"  ref : {mac_key.hex()} {enc_key.hex()}")
        # Both sides must reach it, which is what makes it an exchange.
        if _keg(curve, d_s, q_eph, h, bits) != material:
            raise Mismatch(f"{name}: the two sides disagree about KEG")

        iv = h[24:24 + block // 2]
        wrapped = _kexp15(cipher, block, pms, mac_key, enc_key, iv)
        spellings.add(algorithm_id.hex())
        body = _der(0x30, _der(0x04, wrapped)
                          + _gost_spki(name, q_eph,
                                       algorithm_id=algorithm_id))
        if got != body.hex():
            raise Mismatch(f"ClientKeyExchange for {name} {suite}\n"
                           f"  ours: {got[:96]}\n  ref : {body.hex()[:96]}")

        # ---- the wrong readings, each of which must differ ----

        # The UKM read little endian.
        other_ukm = int.from_bytes(h[:16], "little") or 1
        if other_ukm != (int.from_bytes(h[:16], "big") or 1):
            other = _vko(curve, d_eph, q_s, other_ukm, bits, cofactor=True)
            if bits == 256:
                other = _kdf_tree_gostr3411_2012_256(other, b"kdf tree",
                                                     h[16:24], 1, 512)
            if other == material:
                raise Mismatch(f"{name}: the UKM's byte order does not change "
                               f"the export keys, so this proves nothing")

        # The seed taken from where the IV lives, one slice along.
        if bits == 256 and h[16:24] != h[24:32]:
            k_exp = _vko(curve, d_eph, q_s,
                         int.from_bytes(h[:16], "big") or 1, 256,
                         cofactor=True)
            if _kdf_tree_gostr3411_2012_256(k_exp, b"kdf tree", h[24:32],
                                            1, 512) == material:
                raise Mismatch(f"{name}: the seed's offset does not matter, "
                               f"so this proves nothing")

        # The 512 branch run through the KDF as well, which is the
        # mistake the two branches invite.
        if bits == 512:
            through = _kdf_tree_gostr3411_2012_256(material, b"kdf tree",
                                                   h[16:24], 1, 512)
            if through == material:
                raise Mismatch(f"{name}: the tree KDF is the identity here, "
                               f"so the 512 branch is not pinned")

        # The public key written big endian.
        if _der(0x30, _der(0x04, wrapped)
                + _gost_spki(name, q_eph, little_endian=False)).hex() == got:
            raise Mismatch(f"{name}: the coordinates' byte order does not "
                           f"change the message, so this proves nothing")

        # Encrypt-then-MAC inside KExp15, which has the same length.
        block_size, encrypt, _ = _GOST_CIPHERS[cipher]
        counter = int.from_bytes(iv + bytes(block_size - len(iv)), "big")
        encrypted = bytearray()
        for offset in range(0, len(pms), block_size):
            chunk = pms[offset:offset + block_size]
            encrypted += _xor(
                encrypt(enc_key, counter.to_bytes(block_size, "big"))[:len(chunk)],
                chunk)
            counter = (counter + 1) % (1 << (8 * block_size))
        if bytes(encrypted) + _omac(cipher, mac_key, iv + bytes(encrypted)) == wrapped:
            raise Mismatch(f"{name}: KExp15's two orderings agree, so this "
                           f"proves nothing about the order")
        checked += 1

    if not checked:
        raise Mismatch("the GOST key exchange corpus was empty")

    # Seven curves, plus a second spelling for each of the two that have
    # one, is nine distinct AlgorithmIdentifiers. Fewer means the
    # exchange-set rows have gone, and with them the only thing in this
    # corpus that distinguishes echoing the peer's OID from rebuilding it.
    if len(spellings) < 9:
        raise Mismatch(
            f"only {len(spellings)} distinct AlgorithmIdentifiers in the "
            f"corpus; the exchange parameter set rows are missing, so "
            f"nothing here would notice a client that canonicalised the "
            f"peer's OID")
    return checked


# ------------------------------------------------- GOST 28147-89 ---
#
# The older cipher, and **not** Magma despite sharing a round function
# and this S-box. GOST 28147-89 reads its key words and both halves of
# its block **little endian**; GOST R 34.12-2015 reads the same bytes
# big endian and is therefore a different cipher with the same key. A
# test in `src/block_ciphers/magma.rs` asserts the two disagree.

def _gost28147_words(key):
    """The eight subkeys, little endian (RFC 5830 section 3)."""
    return [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]


def _gost28147_transform(key, block, forward):
    subkeys = _gost28147_words(key)
    # Three passes forward then one backward, which is what makes
    # decryption the same code with the schedule reversed.
    schedule = subkeys * 3 + subkeys[::-1]
    if not forward:
        schedule = schedule[::-1]

    n1 = int.from_bytes(block[:4], "little")
    n2 = int.from_bytes(block[4:], "little")
    for step in range(32):
        # The round function is the same one Magma uses - the ciphers
        # differ in how bytes become words, not in `f`.
        n1, n2 = n2 ^ _magma_round_fast(n1, schedule[step]), n1
    # **Crossed**, and this is where the cipher and the MAC differ.
    # RFC 5830's thirty-second round does not swap the halves; the loop
    # above swaps on every step, so it has done one swap too many and
    # the halves are written back exchanged to undo it. The sixteen
    # round MAC transform *does* swap on its last step, so it writes
    # them uncrossed - the two look like the same loop and end in
    # opposite states.
    return n2.to_bytes(4, "little") + n1.to_bytes(4, "little")


def gost28147_encrypt_block(key, block):
    return _gost28147_transform(key, block, True)


def gost28147_decrypt_block(key, block):
    return _gost28147_transform(key, block, False)


def gost28147_mac_block(key, block):
    """One step of the MAC's 16 round reduced transform (RFC 5830 section 5).

    Sixteen rounds, not thirty-two: the imitovstavka uses two passes of
    the schedule rather than four. A MAC built on the full cipher is
    self-consistent and is not this.
    """
    subkeys = _gost28147_words(key)
    schedule = subkeys * 2
    n1 = int.from_bytes(block[:4], "little")
    n2 = int.from_bytes(block[4:], "little")
    for step in range(16):
        n1, n2 = n2 ^ _magma_round_fast(n1, schedule[step]), n1
    # **Uncrossed**, unlike the full cipher above. Every one of these
    # sixteen rounds swaps the halves, while the cipher's thirty-second
    # round does not - so the two transforms end in opposite states and
    # write their halves in opposite orders. Copying the cipher's line
    # here gives a MAC that is perfectly self-consistent.
    return n1.to_bytes(4, "little") + n2.to_bytes(4, "little")


def gost28147imit(iv, key, message, mesh=False):
    """`gost28147IMIT(IV, K, M)`, RFC 9189 section 8.4.

    CBC-MAC over the reduced transform, zero padded, with the IV XORed
    into the first block and the first four bytes of the final state as
    the tag. `mesh` turns on the CryptoPro key meshing RFC 9189 section
    4.3.2 asks for - which re-keys and, unlike the cipher's meshing,
    **leaves the chaining state alone**.

    **Never fewer than two blocks.** GOST 28147-89 section 4.1 defines
    the imitovstavka only for a message of two blocks or more and says
    nothing about a shorter one, so this is not something a closer
    reading settles - there is nothing there to read. gost-engine's
    `gost_imit_final` runs an extra all-zero block through whenever no
    full block has been MACed yet, which is the same rule, and
    `vectors/gost_engine.vec` is where that came from. This reference
    and `src/block_ciphers/gost.rs` were both a block short for a
    one-block message until an implementation outside this repository
    was asked - which is the entire argument for that file.
    """
    padded = message + bytes((-len(message)) % 8)
    if 0 < len(padded) <= 8:
        padded += bytes(8)
    state = bytes(iv)
    count = 0
    for offset in range(0, len(padded), 8):
        if mesh and count == _MESH_SECTION:
            key = _cryptopro_next_key(key)
            count = 0
        state = gost28147_mac_block(key, _xor(state, padded[offset:offset + 8]))
        count += 8
    return state[:4]


#: RFC 4357 section 2.3.2's constant, and its section size.
_MESH_C = bytes([
    0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
    0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
    0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
    0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B])
_MESH_SECTION = 1024


def _cryptopro_next_key(key):
    """`K[i+1] = decryptECB(K[i], C)` - a **decryption**, unlike ACPKM."""
    return b"".join(gost28147_decrypt_block(key, _MESH_C[i:i + 8])
                    for i in range(0, 32, 8))


def _gost_cnt_step(counter):
    """RFC 5830 section 6: `+C2 mod 2^32` on the low word and
    `+C1 mod 2^32-1` on the high one.

    The high word's modulus is the trap: a carry out of the top folds
    back into the low bit, so `wrapping_add` then `% 0xffffffff` comes
    out one too low whenever the sum exceeds 2^32.
    """
    low = (int.from_bytes(counter[:4], "little") + 0x01010101) & 0xFFFFFFFF
    high = int.from_bytes(counter[4:], "little") + 0x01010104
    if high > 0xFFFFFFFF:
        high = (high & 0xFFFFFFFF) + 1
    return low.to_bytes(4, "little") + high.to_bytes(4, "little")


def _cnt_keystream(key, iv, length):
    """CNT with CryptoPro meshing, as one stream (RFC 9189 section 4.3.3).

    The two meshing details that are each off by one step: `IVn` is the
    counter that produced the *last* gamma block, and the meshed IV is
    stepped before it is used.
    """
    counter = _gost_cnt_step(gost28147_encrypt_block(key, iv))
    out = bytearray()
    previous = counter
    count = 0
    while len(out) < length:
        if count == _MESH_SECTION:
            key = _cryptopro_next_key(key)
            counter = _gost_cnt_step(gost28147_encrypt_block(key, previous))
            count = 0
        previous = counter
        out += gost28147_encrypt_block(key, counter)
        counter = _gost_cnt_step(counter)
        count += 8
    return bytes(out[:length])


def _rfc4357_packed_sbox(marker):
    """The 64 packed bytes RFC 4357 prints under a parameter set's OID.

    Sections 11.1 and 11.2 both use this shape, so one reader does the
    encryption sets and the hash sets alike. Read out of the document
    rather than transcribed for the same reason as everything else
    here - and it means this reference and the Rust cannot disagree
    about *which* table while agreeing about the algorithm.
    """
    lines = (ROOT / "rfcs" / "rfc4357.txt").read_text(
        encoding="utf-8").split("\n")
    start = max(i for i, line in enumerate(lines)
                if line.strip().startswith(":")
                and line.strip().endswith(marker))
    packed = b""
    for line in lines[start + 1:]:
        if "Popov," in line or "RFC 4357" in line:
            continue
        stripped = line.strip()
        if stripped.startswith("--") or not stripped.startswith(":"):
            continue
        words = stripped[1:].strip().split()
        if not words or not all(len(w) == 2 and
                                all(c in "0123456789ABCDEF" for c in w)
                                for w in words):
            continue
        packed += bytes.fromhex("".join(words))
        if len(packed) >= 64:
            break
    assert len(packed) >= 64, marker
    sbox = [[0] * 16 for _ in range(8)]
    for value in range(16):
        for pair in range(4):
            byte = packed[4 * value + pair]
            sbox[2 * pair][value] = byte >> 4
            sbox[2 * pair + 1][value] = byte & 0xF
    return sbox


_SBOX_CACHE = {}


def _sbox_28147(marker):
    if marker not in _SBOX_CACHE:
        _SBOX_CACHE[marker] = _rfc4357_packed_sbox(marker)
    return _SBOX_CACHE[marker]


def _gost28147_with_sbox(key, block, sbox, forward=True):
    """GOST 28147-89 on an arbitrary S-box, the slow way.

    `_gost28147_transform` above is specialised to
    `id-tc26-gost-28147-param-Z` through Magma's precomputed table; the
    2001 suite uses `id-Gost28147-89-CryptoPro-A-ParamSet`, and the
    table is the whole cipher. A dozen corpus rows do not need the fast
    path.
    """
    subkeys = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]
    schedule = subkeys * 3 + subkeys[::-1]
    if not forward:
        schedule = schedule[::-1]

    def f(value, subkey):
        total = (value + subkey) & 0xFFFFFFFF
        out = 0
        for i in range(8):
            out |= sbox[i][(total >> (4 * i)) & 0xF] << (4 * i)
        return ((out << 11) | (out >> 21)) & 0xFFFFFFFF

    n1 = int.from_bytes(block[:4], "little")
    n2 = int.from_bytes(block[4:], "little")
    for step in range(32):
        n1, n2 = n2 ^ f(n1, schedule[step]), n1
    return n2.to_bytes(4, "little") + n1.to_bytes(4, "little")


def _gost_mac_block_with_sbox(key, block, sbox):
    """The MAC's sixteen round transform, which does *not* cross its
    halves at the end - see `gost28147_mac_block`."""
    subkeys = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]
    schedule = subkeys * 2

    def f(value, subkey):
        total = (value + subkey) & 0xFFFFFFFF
        out = 0
        for i in range(8):
            out |= sbox[i][(total >> (4 * i)) & 0xF] << (4 * i)
        return ((out << 11) | (out >> 21)) & 0xFFFFFFFF

    n1 = int.from_bytes(block[:4], "little")
    n2 = int.from_bytes(block[4:], "little")
    for step in range(16):
        n1, n2 = n2 ^ f(n1, schedule[step]), n1
    return n1.to_bytes(4, "little") + n2.to_bytes(4, "little")


def _imit_with_sbox(iv, key, message, sbox):
    state = iv
    padded = message + bytes(-len(message) % 8)
    for offset in range(0, len(padded), 8):
        state = _gost_mac_block_with_sbox(
            key, _xor(state, padded[offset:offset + 8]), sbox)
    return state[:4]


def _cp_divers_with_sbox(ukm, key, sbox):
    """RFC 4357 section 6.5 on an arbitrary S-box."""
    current = key
    for byte in ukm:
        first = second = 0
        for index in range(8):
            word = int.from_bytes(current[4 * index:4 * index + 4], "little")
            if byte & (1 << index):
                first = (first + word) & 0xFFFFFFFF
            else:
                second = (second + word) & 0xFFFFFFFF
        s = first.to_bytes(4, "little") + second.to_bytes(4, "little")
        out = bytearray()
        feedback = s
        for offset in range(0, 32, 8):
            gamma = _gost28147_with_sbox(current, feedback, sbox)
            block = _xor(gamma, current[offset:offset + 8])
            out += block
            feedback = block
        current = bytes(out)
    return bytes(current)


def _kexp28147_with_sbox(secret, key, iv, sbox):
    """CryptoPro Key Wrap, RFC 4357 section 6.3: `UKM | ECB(CEK) | MAC`,
    where the MAC is over the *plaintext* key."""
    mac = _imit_with_sbox(iv, key, secret, sbox)
    encrypted = b"".join(_gost28147_with_sbox(key, secret[o:o + 8], sbox)
                         for o in range(0, len(secret), 8))
    return iv + encrypted + mac


def _vko_2001(curve, private, peer, ukm):
    """VKO GOST R 34.10-2001, RFC 4357 section 5.2.

    `K = ((UKM*x) mod q) . (y.P)`, then GOST R 34.11-94 of the point.
    **No cofactor**, where the 2012 version has `m/q` - every curve a
    2001 key can be on has cofactor one, so this follows the document
    rather than the newer formula.

    The UKM is read little endian, like every other GOST integer that
    arrives as bytes.
    """
    value = int.from_bytes(ukm, "little") % curve.n
    if value == 0:
        raise Mismatch("the UKM is zero mod n")
    point = curve.mul(value * private % curve.n, peer)
    if point is None:
        raise Mismatch("the exchange produced the identity")
    blob = (point[0].to_bytes(curve.size, "little")
            + point[1].to_bytes(curve.size, "little"))
    return gost94(blob, "id-GostR3411-94-CryptoProParamSet")


_SBOX_2001 = "id-Gost28147-89-CryptoPro-A-ParamSet"


def check_cnt_imit(lines):
    """RFC 9189's CNT_IMIT suite, against a reading of the standards.

    Nothing on this machine implements any of it, so the reference above
    is written from RFC 5830 (the cipher, its CNT mode and its MAC), RFC
    4357 (the meshing and CPDivers) and RFC 9189 (how they compose). The
    RFCs' own vectors are in the unit tests; this covers the space
    between them, which for this suite means the re-keying.

    Every re-keying mistake here is **right for the first 1024 octets
    and wrong afterwards**, so the rows straddle that boundary from both
    sides and the record rows carry whole connections - a boundary
    falling inside a record and one falling between two records are
    different cases.

    The assertions that stop it passing vacuously:

      * the cipher's meshing must change the stream where it fires, and
        the reference computes the unmeshed stream to check that;
      * the MAC keeps its chaining state across a re-key, so the
        reference also computes the variant that re-derives it and
        asserts the two differ.
    """
    checked = 0
    for line in lines:
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "imit":
            key, iv = unhex(parts[1]), unhex(parts[2])
            message, got = unhex(parts[3]), parts[4]
            want = gost28147imit(iv, key, message)
            if got != want.hex():
                raise Mismatch(f"gostIMIT28147 over {len(message)} bytes\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            # The full 32 round cipher would give a different MAC, and a
            # MAC built on it is self-consistent.
            full = gost28147_encrypt_block(key, bytes(8))
            if full[:4].hex() == got and not message:
                raise Mismatch("the MAC looks like the full transform")
            checked += 1
            continue

        if parts[0] in ("vko2001", "keg2001", "wrap2001"):
            curve = _gost_curve(parts[1])
            private = int(parts[2], 16)
            peer = (int(parts[3], 16), int(parts[4], 16))
            ukm = unhex(parts[5])
            if not curve.on_curve(peer):
                raise Mismatch(f"{parts[1]}: the peer point is not on the curve")

            kek = _vko_2001(curve, private, peer, ukm)
            if parts[0] == "vko2001":
                if parts[6] != kek.hex():
                    raise Mismatch(f"VKO 2001 on {parts[1]}\n"
                                   f"  ours: {parts[6]}\n  ref : {kek.hex()}")
                # And it must not be the 2012 agreement, which differs
                # only in the hash over the same point - so a corpus
                # that could not tell them apart would prove nothing
                # about the one thing most likely to be wrong.
                # `cofactor=False` so the two differ in the hash and in
                # nothing else, which is what this check claims to be
                # about. Every curve a 2001 key can be on has `h = 1`,
                # so it changes no value here - it keeps the claim true
                # if one ever appears that does not.
                modern = _vko(curve, private, peer,
                              int.from_bytes(ukm, "little"), 256,
                              cofactor=False)
                if modern.hex() == parts[6]:
                    raise Mismatch("the 2001 and 2012 agreements produced the "
                                   "same key, so the hash is not being chosen")
                checked += 1
                continue

            k_exp = _cp_divers_with_sbox(ukm, kek, _sbox_28147(_SBOX_2001))
            if parts[0] == "keg2001":
                if parts[6] != k_exp.hex():
                    raise Mismatch(f"KEG 2001 on {parts[1]}\n"
                                   f"  ours: {parts[6]}\n  ref : {k_exp.hex()}")
                checked += 1
                continue

            secret, got = unhex(parts[6]), parts[7]
            want = _kexp28147_with_sbox(secret, k_exp, ukm,
                                        _sbox_28147(_SBOX_2001))
            if got != want.hex():
                raise Mismatch(f"the 2001 wrap on {parts[1]}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            # The wrap's S-box is the other half of the same question:
            # param-Z would produce a blob of the same length that no
            # 2001 peer can open.
            other = _kexp28147_with_sbox(secret, k_exp, ukm,
                                         _sbox_28147(
                                             "id-Gost28147-89-CryptoPro-B-ParamSet"))
            if other.hex() == got:
                raise Mismatch("two parameter sets wrapped identically")
            checked += 1
            continue

        if parts[0] == "divers":
            ukm, key, got = unhex(parts[1]), unhex(parts[2]), parts[3]
            want = _cp_divers(ukm, key)
            if got != want.hex():
                raise Mismatch(f"CPDivers with UKM {parts[1]}\n"
                               f"  ours: {got}\n  ref : {want.hex()}")
            if want == key:
                raise Mismatch("CPDivers returned its input")
            checked += 1
            continue

        if parts[0] != "cntimit":
            continue

        enc_key, mac_key, iv = unhex(parts[1]), unhex(parts[2]), unhex(parts[3])
        lengths = [int(n) for n in parts[4].split(",")]
        records = parts[5:]
        if len(records) != len(lengths):
            raise Mismatch(f"{len(lengths)} lengths and {len(records)} records")

        # The MAC chain and the keystream both run for the connection.
        mac_input = b""
        stream = b""
        for sequence, length in enumerate(lengths):
            content_type = [0x17, 0x16, 0x15][sequence % 3]
            version = b"\x03\x03" if length % 2 == 0 else b"\x03\x02"
            plaintext = bytes(((i * 53 + (sequence % 256) * 29 + 17) & 0xFF)
                              for i in range(length))
            mac_input += (sequence.to_bytes(8, "big") + bytes([content_type])
                          + version + length.to_bytes(2, "big") + plaintext)
            tag = gost28147imit(bytes(8), mac_key, mac_input, mesh=True)
            stream += plaintext + tag

        keystream = _cnt_keystream(enc_key, iv, len(stream))
        wire = _xor(keystream, stream)

        at = 0
        for sequence, length in enumerate(lengths):
            want = wire[at:at + length + 4]
            if records[sequence] != want.hex():
                raise Mismatch(
                    f"CNT_IMIT record {sequence} of {len(lengths)}, "
                    f"{length} bytes\n"
                    f"  ours: {records[sequence][:96]}\n"
                    f"  ref : {want.hex()[:96]}")
            at += length + 4

        # Where the stream is long enough to mesh, not meshing must give
        # a different answer - or these rows say nothing about it.
        if len(stream) > _MESH_SECTION:
            unmeshed = bytearray()
            counter = _gost_cnt_step(gost28147_encrypt_block(enc_key, iv))
            while len(unmeshed) < len(stream):
                unmeshed += gost28147_encrypt_block(enc_key, counter)
                counter = _gost_cnt_step(counter)
            if bytes(unmeshed[:len(stream)]) == keystream:
                raise Mismatch("meshing does not change the keystream, so "
                               "these rows prove nothing about it")

        # And where the MAC's input is long enough, re-deriving its
        # chaining state on a re-key must differ from keeping it.
        if len(mac_input) > _MESH_SECTION:
            if _imit_meshing_the_other_way(mac_key, mac_input) == tag:
                raise Mismatch("the MAC's two meshing readings agree, so "
                               "these rows prove nothing about it")
        checked += 1

    if not checked:
        raise Mismatch("the CNT_IMIT corpus was empty")
    return checked


def _imit_meshing_the_other_way(key, message):
    """The MAC with its chaining state re-derived on each re-key.

    The wrong reading, computed so the checker can assert it differs.
    gost-engine passes NULL for the MAC's IV when meshing, with a
    comment that CryptoPro does not treat a MAC's internal state as an
    IV - nothing in RFC 4357 says so, because it does not distinguish
    the two callers.
    """
    padded = message + bytes((-len(message)) % 8)
    state = bytes(8)
    count = 0
    for offset in range(0, len(padded), 8):
        if count == _MESH_SECTION:
            key = _cryptopro_next_key(key)
            state = gost28147_encrypt_block(key, state)
            count = 0
        state = gost28147_mac_block(key, _xor(state, padded[offset:offset + 8]))
        count += 8
    return state[:4]


def _cp_divers(ukm, key):
    """The CryptoPro KEK diversification algorithm, RFC 4357 section 6.5."""
    current = key
    for byte in ukm:
        first = second = 0
        for index in range(8):
            word = int.from_bytes(current[4 * index:4 * index + 4], "little")
            if byte & (1 << index):
                first = (first + word) & 0xFFFFFFFF
            else:
                second = (second + word) & 0xFFFFFFFF
        s = first.to_bytes(4, "little") + second.to_bytes(4, "little")

        # CFB with full block feedback: the key encrypts itself under
        # itself with S as the IV.
        out = bytearray()
        feedback = s
        for offset in range(0, 32, 8):
            gamma = gost28147_encrypt_block(current, feedback)
            block = _xor(gamma, current[offset:offset + 8])
            out += block
            feedback = block
        current = bytes(out)
    return current


def check_export_keys(lines):
    """The export suites' second key expansion.

    OpenSSL removed the export suites in 1.1.0 and this build offers none,
    so the reference is RFC 2246 section 6.3.1 (and RFC 6101 section 6.2.2
    for SSLv3) transcribed here. Same standing as the SSLv3 corpus: it
    catches a transcription error in the Rust, not a misreading shared by
    both.

    What it pins is the three things a round trip cannot:

      * the expansion happens at all - five bytes of key material become
        sixteen, or eight for DES40;
      * the IVs come from a separate PRF pass with an **empty secret**,
        not from the key block;
      * SSLv3 uses a bare MD5 and swaps the randoms for the server side.
    """
    # (expanded key length, IV length) per export cipher.
    SUITES = {
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5":        (16, 0, 16),
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5":    (16, 8, 16),
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":     (8, 8, 20),
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA": (8, 8, 20),
    }

    checked = 0
    pending = {}
    for line in lines:
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "exportiv":
            key = (parts[1], parts[2])
            if unhex(parts[3]) != pending.get(key):
                raise Mismatch(f"export {key}: server IV\n"
                               f"  ours: {parts[3]}\n"
                               f"  ref : {pending.get(key, b'').hex()}")
            checked += 1
            continue

        if parts[0] != "export":
            continue

        name, version = parts[1], parts[2]
        master, client_random, server_random = (
            unhex(parts[3]), unhex(parts[4]), unhex(parts[5]))
        expanded, iv_len, mac_len = SUITES[name]

        forward = client_random + server_random
        backward = server_random + client_random

        # The key block first: five bytes of key material per direction,
        # and **no IV** - which is the part that shifts every byte after
        # it if an implementation takes one here as well.
        needed = 2 * (mac_len + 5)
        if version == "SSLv3":
            block = ssl3_expand(master, backward, needed)
        else:
            block = tls10_prf(master, b"key expansion", backward, needed)

        at = 0

        def take(n):
            nonlocal at
            piece = block[at:at + n]
            at += n
            return piece

        client_mac, server_mac = take(mac_len), take(mac_len)
        short_client, short_server = take(5), take(5)

        # Then the expansion.
        if version == "SSLv3":
            client_key = hashlib.md5(short_client + forward).digest()[:expanded]
            server_key = hashlib.md5(short_server + backward).digest()[:expanded]
            client_iv = hashlib.md5(forward).digest()[:iv_len]
            server_iv = hashlib.md5(backward).digest()[:iv_len]
        else:
            client_key = tls10_prf(short_client, b"client write key",
                                   forward, expanded)
            server_key = tls10_prf(short_server, b"server write key",
                                   forward, expanded)
            iv_block = tls10_prf(b"", b"IV block", forward, 2 * iv_len)
            client_iv, server_iv = iv_block[:iv_len], iv_block[iv_len:]

        for label, ours, theirs in [
            ("client MAC key", unhex(parts[6]), client_mac),
            ("server MAC key", unhex(parts[7]), server_mac),
            ("client key", unhex(parts[8]), client_key),
            ("server key", unhex(parts[9]), server_key),
            ("client IV", unhex(parts[10]), client_iv),
        ]:
            if ours != theirs:
                raise Mismatch(f"export {name} at {version}: {label}\n"
                               f"  ours: {ours.hex()}\n"
                               f"  ref : {theirs.hex()}")

        # The expansion has to have happened. Five bytes in, more out.
        if len(client_key) <= 5:
            raise Mismatch(f"export {name}: key of {len(client_key)} bytes was "
                           f"not expanded")
        pending[(name, version)] = server_iv
        checked += 1

    if not checked:
        raise Mismatch("no export key expansion cases in the corpus")
    return checked


def check_ssl3_keys(lines):
    """SSLv3's key schedule against a reference written from RFC 6101.

    This is the one corpus in this file with no independent implementation
    behind it, and it is worth being plain about why: OpenSSL removed
    SSLv3 and this build has it compiled out (`ssl.HAS_SSLv3` is False),
    so there is nothing on this machine to compare against. The reference
    is the specification, transcribed in a different language by a
    different route - which catches a transcription error in our Rust but
    would not catch a misreading of the RFC that both transcriptions
    shared.

    That is a weaker claim than "agrees with OpenSSL", and it is the
    strongest one available for a protocol every implementation has
    deleted. Which is, of course, the whole reason this library exists.
    """
    # The key block split, per suite: MAC length, key length, IV length.
    # Written out here rather than asked of our own code, since "does the
    # split match what we think it is" is exactly what is being checked.
    SUITES = {
        "TLS_RSA_WITH_AES_128_CBC_SHA":  (20, 16, 16),
        "TLS_RSA_WITH_AES_256_CBC_SHA":  (20, 32, 16),
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA": (20, 24, 8),
        "TLS_RSA_WITH_DES_CBC_SHA":      (20, 8, 8),
        "TLS_RSA_WITH_RC4_128_MD5":      (16, 16, 0),
        "TLS_RSA_WITH_RC4_128_SHA":      (20, 16, 0),
        "TLS_RSA_WITH_NULL_MD5":         (16, 0, 0),
    }

    checked = 0
    pending = {}
    for line in lines:
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "master":
            premaster, client_random, server_random, got = (
                unhex(parts[1]), unhex(parts[2]), unhex(parts[3]), parts[4])
            want = ssl3_expand(premaster, client_random + server_random, 48)
            if got != want.hex():
                raise Mismatch(f"SSLv3 master secret\n  ours: {got}\n"
                               f"  ref : {want.hex()}")
            checked += 1

        elif parts[0] == "keyblock":
            name = parts[1]
            master, client_random, server_random = (
                unhex(parts[2]), unhex(parts[3]), unhex(parts[4]))
            mac_len, key_len, iv_len = SUITES[name]
            # Note the order: server random first here, client random
            # first for the master secret above. Getting them the same way
            # round in both places is a silent failure that only shows at
            # the Finished check.
            block = ssl3_expand(master, server_random + client_random,
                                2 * (mac_len + key_len + iv_len))
            at = 0

            def take(n):
                nonlocal at
                piece = block[at:at + n]
                at += n
                return piece

            want = [take(mac_len), take(mac_len), take(key_len), take(key_len),
                    take(iv_len)]
            server_iv = take(iv_len)
            got = [unhex(p) for p in parts[5:10]]
            labels = ["client MAC key", "server MAC key", "client key",
                      "server key", "client IV"]
            for label, ours, theirs in zip(labels, got, want):
                if ours != theirs:
                    raise Mismatch(f"SSLv3 key block {name}: {label}\n"
                                   f"  ours: {ours.hex()}\n"
                                   f"  ref : {theirs.hex()}")
            pending[name] = server_iv
            checked += 1

        elif parts[0] == "keyblockiv":
            name, got = parts[1], unhex(parts[2])
            if got != pending.get(name):
                raise Mismatch(f"SSLv3 key block {name}: server IV\n"
                               f"  ours: {got.hex()}\n"
                               f"  ref : {pending.get(name, b'').hex()}")
            checked += 1

        elif parts[0] == "finished":
            side, master, messages, got = (
                parts[1], unhex(parts[2]), unhex(parts[3]), parts[4])
            want = ssl3_finished(master, messages, side)
            if got != want.hex():
                raise Mismatch(f"SSLv3 {side} Finished\n  ours: {got}\n"
                               f"  ref : {want.hex()}")
            checked += 1

    if not checked:
        raise Mismatch("no SSLv3 key schedule cases in the corpus")
    return checked


def ssl3_mac(hash_name, mac_key, sequence, content_type, fragment):
    """SSLv3's record MAC, from RFC 6101 section 5.2.3.1.

    Written from the specification's text rather than from our code, which
    is the only kind of check available here: this OpenSSL has SSLv3
    compiled out entirely (`ssl.HAS_SSLv3` is False), so there is no
    implementation on this machine to compare against.

        hash(MAC_write_secret + pad_2 +
             hash(MAC_write_secret + pad_1 + seq_num + type + length + fragment))

    Three things differ from the HMAC that replaced it, and all three are
    mistakes two implementations could make together and never notice:

      * the pads are concatenated rather than XORed into the key, and they
        are 48 bytes for MD5 and 40 for SHA-1 - not one block each;
      * there is no key shortening or padding, so a long MAC key is used
        as it is;
      * **the record's version is not covered**, because SSLv3 had only
        one. A port of the TLS input with HMAC swapped out is still wrong.
    """
    pad_len = {"md5": 48, "sha1": 40}[hash_name]
    header = (sequence.to_bytes(8, "big") + bytes([content_type])
              + len(fragment).to_bytes(2, "big"))
    inner = hashlib.new(hash_name,
                        mac_key + b"\x36" * pad_len + header + fragment).digest()
    return hashlib.new(hash_name, mac_key + b"\x5c" * pad_len + inner).digest()


def check_tls_record(lines):
    """Rebuild each record from RFC 5246 section 6.2.3.2 and compare.

    The reference here is written from the RFC using OpenSSL's AES and
    Python's hmac, not from our code. MAC-then-encrypt with TLS's N+1
    padding has several details that are easy to get consistently wrong -
    the sequence number in the MAC, the length field being the *plaintext*
    length, the padding byte counting itself - and a round trip against
    ourselves would not notice any of them.

    The explicit IV is random per record, so the bytes cannot be predicted.
    The IV is taken from the record we produced and the rest recomputed,
    which still pins the MAC input, the padding and the encryption.
    """
    import hmac as pyhmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    VERSIONS = {"SSLv3": b"\x03\x00", "TLSv1": b"\x03\x01",
                "TLSv1.1": b"\x03\x02", "TLSv1.2": b"\x03\x03"}
    HEADER = 5

    suites = {}
    checked = 0

    # AES, plus the two OpenSSL keeps only in `decrepit` - which is where
    # a library that deprecates rather than deletes puts things, and is
    # the same position this one takes.
    def algorithm(name, key):
        if name == "aes":
            return algorithms.AES(key)
        from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit
        if name == "3des":
            return decrepit.TripleDES(key)
        if name == "des":
            # No single-DES type exists anywhere any more. TripleDES with
            # the key repeated *is* DES - that is what EDE mode is for.
            return decrepit.TripleDES(key * 3)
        raise Mismatch(f"no reference for cipher {name!r}")

    def encrypt(name, key, iv, data):
        enc = Cipher(algorithm(name, key), modes.CBC(iv)).encryptor()
        return enc.update(data) + enc.finalize()

    for line in lines:
        parts = line.split()
        kind = parts[0]

        if kind == "suite":
            label, version, cipher = parts[1], parts[2], parts[3]
            suites[label] = {
                "version": VERSIONS[version],
                "version_name": version,
                "key": unhex(parts[4]),
                "mac_key": unhex(parts[5]),
                "iv": unhex(parts[6]),
                "explicit_iv": version in ("TLSv1.1", "TLSv1.2"),
                "sequence": 0,
                "cipher": cipher,
                # An 8 byte block is not a smaller 16 byte one: the padding
                # and the explicit IV are both block-sized, so every length
                # in the corpus lands differently for DES than for AES.
                "block": 16 if cipher == "aes" else 8,
            }
            continue

        if kind == "hash":
            suites[parts[1]]["hash"] = parts[2]
            continue

        if kind == "etm":
            suites[parts[1]]["etm"] = parts[2] == "true"
            continue

        if kind == "plain":
            payload, record = unhex(parts[2]), unhex(parts[3])
            # Framing only: 2^14 fragments, five byte headers, nothing else.
            rebuilt = b""
            chunks = [payload[i:i + 16384] for i in range(0, len(payload), 16384)] \
                or [b""]
            for chunk in chunks:
                rebuilt += bytes([22]) + b"\x03\x03" \
                    + len(chunk).to_bytes(2, "big") + chunk
            if rebuilt != record:
                raise Mismatch(f"plaintext framing differs\n"
                               f"  ours: {record.hex()[:80]}\n"
                               f"  ref : {rebuilt.hex()[:80]}")
            checked += 1
            continue

        if kind != "record":
            continue

        label, _index, content_type = parts[1], int(parts[2]), int(parts[3])
        payload, record = unhex(parts[4]), unhex(parts[5])
        suite = suites[label]

        # Header must say what we expect before anything else is checked.
        if record[0] != content_type or record[1:3] != suite["version"]:
            raise Mismatch(f"{label}: record header differs")
        if int.from_bytes(record[3:5], "big") != len(record) - HEADER:
            raise Mismatch(f"{label}: record length field is wrong")
        fragment = record[HEADER:]

        sequence = suite["sequence"]
        suite["sequence"] += 1
        mac_len = hashlib.new(suite["hash"]).digest_size

        def mac_over(body, length_of):
            """RFC 5246 6.2.3.1 / RFC 7366: seq || type || version ||
            length || body. What `length` counts is the difference between
            the two constructions - the plaintext for MAC-then-encrypt, the
            IV and ciphertext together for encrypt-then-MAC.

            SSLv3 takes the other path entirely: a different construction
            over an input that does not include the version."""
            if suite["version_name"] == "SSLv3":
                # `length_of` and `len(body)` are the same in every SSLv3
                # case here, since SSLv3 predates encrypt-then-MAC.
                return ssl3_mac(suite["hash"], suite["mac_key"], sequence,
                                content_type, body)
            header = (sequence.to_bytes(8, "big") + bytes([content_type])
                      + suite["version"] + length_of.to_bytes(2, "big"))
            return pyhmac.new(suite["mac_key"], header + body,
                              suite["hash"]).digest()

        if suite.get("etm"):
            # RFC 7366: encrypt the padded plaintext, then MAC the IV and
            # ciphertext together, and append the MAC.
            if len(fragment) < mac_len:
                raise Mismatch(f"{label}: fragment shorter than the MAC")
            body, their_mac = fragment[:-mac_len], fragment[-mac_len:]

            block_size = suite["block"]
            padding_len = block_size - (len(payload) % block_size)
            block = payload + bytes([padding_len - 1]) * padding_len

            if suite["explicit_iv"]:
                iv, ciphertext = body[:block_size], body[block_size:]
            else:
                iv, ciphertext = suite["iv"], body

            expected = encrypt(suite["cipher"], suite["key"], iv, block)
            if expected != ciphertext:
                raise Mismatch(f"{label} seq {sequence}: EtM ciphertext differs\n"
                               f"  ours: {ciphertext.hex()[:80]}\n"
                               f"  ref : {expected.hex()[:80]}")

            expected_mac = mac_over(body, len(body))
            if expected_mac != their_mac:
                raise Mismatch(f"{label} seq {sequence}: EtM MAC differs\n"
                               f"  ours: {their_mac.hex()}\n"
                               f"  ref : {expected_mac.hex()}")
        else:
            mac = mac_over(payload, len(payload))

            # TLS padding: N+1 bytes of value N, filling to a block
            # boundary. It always adds at least one byte, and the byte
            # counts itself.
            unpadded = len(payload) + len(mac)
            block_size = suite["block"]
            padding_len = block_size - (unpadded % block_size)
            block = payload + mac + bytes([padding_len - 1]) * padding_len

            if suite["explicit_iv"]:
                iv, ciphertext = fragment[:block_size], fragment[block_size:]
            else:
                iv, ciphertext = suite["iv"], fragment

            expected = encrypt(suite["cipher"], suite["key"], iv, block)
            if expected != ciphertext:
                raise Mismatch(f"{label} seq {sequence}: ciphertext differs\n"
                               f"  ours: {ciphertext.hex()[:80]}\n"
                               f"  ref : {expected.hex()[:80]}")

        if not suite["explicit_iv"]:
            # TLS 1.0 chains the IV from the last block of this record.
            suite["iv"] = ciphertext[-block_size:]

        checked += 1

    return checked


# ------------------------------------------------- the cipher suite registry ---

def check_suites(lines):
    """Compare our cipher suite registry against OpenSSL's.

    A wrong code in that table is invisible in every other test: the suite
    simply never matches, so nothing fails and nothing logs - the suite
    that was supposed to let us talk to some old box quietly does not
    exist. OpenSSL knows the real numbers.

    OpenSSL will not list suites its build dropped, so a suite it does not
    know is reported rather than failed. What is failed is a suite it
    *does* know where the code or the name disagrees.
    """
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        # SECLEVEL=0 so the weak suites are listed too; without it OpenSSL
        # hides exactly the ones this library exists to keep.
        context.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except ssl.SSLError:
        context.set_ciphers("ALL")

    # OpenSSL's id is 0x03000000 | the two byte code.
    theirs_by_code = {}
    for entry in context.get_ciphers():
        theirs_by_code[entry["id"] & 0xffff] = entry

    checked = 0
    unknown = []
    modern, legacy, insecure = [], [], []

    for line in lines:
        parts = line.split()
        if parts[0] == "selection":
            values = parts[2].split(",") if len(parts) > 2 else []
            if parts[1] == "modern":
                modern = values
            else:
                legacy = values
            continue
        if parts[0] == "insecure":
            insecure = parts[1].split(",") if len(parts) > 1 else []
            continue
        if parts[0] != "suite":
            continue

        code_hex, name, openssl_name = parts[1], parts[2], parts[3]
        code = int(code_hex, 16)
        theirs = theirs_by_code.get(code)
        if theirs is None:
            unknown.append(f"{code_hex} {name}")
            continue

        # The IANA name is the one that must match exactly. OpenSSL's own
        # short name is advisory - it differs by build and by era.
        if theirs["name"] != name and theirs["name"] != openssl_name:
            raise Mismatch(f"0x{code_hex}: we call it {name} / {openssl_name}, "
                           f"OpenSSL calls it {theirs['name']}")
        checked += 1

    # The claim the whole registry rests on: nothing broken is offered by
    # default. Checked here rather than only in a unit test, because it is
    # a property of the table and the table is what changes.
    for code in modern:
        if code in insecure:
            raise Mismatch(f"0x{code} is insecure and in the default selection")
    if not modern:
        raise Mismatch("the default selection is empty")
    for code in insecure:
        if code in legacy:
            raise Mismatch(f"0x{code} is insecure and in the legacy selection")

    print(f"  (default offers {len(modern)}, legacy {len(legacy)}, "
          f"{len(insecure)} insecure suites offered by neither)")
    if unknown:
        print(f"  ({len(unknown)} suites this OpenSSL build does not know: "
              f"{', '.join(u.split()[1] for u in unknown[:4])}"
              f"{', ...' if len(unknown) > 4 else ''})")
    return checked


# ----------------------------------------------------------- block cipher ---

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------------ TEA and XTEA ---
#
# Neither is in python-cryptography and neither is in OpenSSL, so the
# reference is written here from Wheeler and Needham's papers - the same
# position the GOST ciphers are in.
#
# The *primitive* is already settled by 196 published vectors that
# `src/block_ciphers/tea.rs` parses out of Crypto++'s and Botan's files,
# including a chain that sweeps every round count from 1 to 64. What
# these rows are for is the **modes over a 64 bit block at every awkward
# length**, which no vector file covers - and `_tea_selftest` pins this
# implementation to two of those published vectors so a typo here cannot
# quietly redefine what the corpus is checking.

_TEA_DELTA = 0x9e3779b9


def _tea_words(data, at):
    return (int.from_bytes(data[at:at + 4], "big"),
            int.from_bytes(data[at + 4:at + 8], "big"))


def tea_block(which, key, block):
    """One TEA or XTEA block encryption. Big endian, 32 cycles."""
    mask = 0xffffffff
    k = [int.from_bytes(key[i * 4:i * 4 + 4], "big") for i in range(4)]
    v0, v1 = _tea_words(block, 0)
    total = 0
    for _ in range(32):
        if which == "tea":
            total = (total + _TEA_DELTA) & mask
            v0 = (v0 + ((((v1 << 4) & mask) + k[0]) ^ ((v1 + total) & mask)
                        ^ (((v1 >> 5) + k[1]) & mask))) & mask
            v1 = (v1 + ((((v0 << 4) & mask) + k[2]) ^ ((v0 + total) & mask)
                        ^ (((v0 >> 5) + k[3]) & mask))) & mask
        else:
            v0 = (v0 + (((((v1 << 4) & mask) ^ (v1 >> 5)) + v1)
                        ^ (total + k[total & 3]))) & mask
            total = (total + _TEA_DELTA) & mask
            v1 = (v1 + (((((v0 << 4) & mask) ^ (v0 >> 5)) + v0)
                        ^ (total + k[(total >> 11) & 3]))) & mask
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def tea_mode(which, key, mode, iv, data):
    """The five modes over `tea_block`. See `_block_mode`, which is
    shared with RC5 because neither has an independent library here and
    two copies of CBC would be two chances to write it wrongly."""
    return _block_mode(lambda blk: tea_block(which, key, blk), 8, mode, iv,
                       data)


def _tea_selftest():
    """Pin the block function above to two published vectors.

    Without this, a typo here would make the whole corpus disagree and
    the natural reading would be that the Rust is wrong. These two are
    the first row of Wheeler's TEA chain and XTEA's one-cycle answer for
    a zero key - both stated in `src/block_ciphers/tea.rs`, which parses
    them out of the vendored files rather than carrying them.
    """
    first = tea_block("tea", bytes(16), bytes(8)).hex()
    if first != "41ea3a0a94baa940":
        raise Mismatch(f"the TEA written in this script is wrong: {first}")
    # XTEA at 32 cycles over the same input, from Botan's file via the
    # Rust unit tests. A different cipher, so a copy-paste of TEA fails.
    if tea_block("xtea", bytes(16), bytes(8)) == tea_block("tea", bytes(16),
                                                           bytes(8)):
        raise Mismatch("the TEA and XTEA references are the same function")


# -------------------------------------------------------------- RC5 ---
#
# RFC 2040, and nothing else on this machine has it - it was patented
# until 2015, which is why it is missing from so much otherwise complete
# software. The 29 published vectors in `src/block_ciphers/rc5.rs` settle
# the primitive; these rows are for the modes at every awkward length.

_RC5_P32 = 0xb7e15163
_RC5_Q32 = 0x9e3779b9


def _rc5_schedule(key, rounds):
    """RFC 2040 sections 5.3 to 5.5."""
    mask = 0xffffffff
    words = (len(key) + 3) // 4
    if words == 0:
        raise Mismatch("RC5 with an empty key")
    l = [0] * words
    for i, byte in enumerate(key):
        l[i // 4] |= byte << (8 * (i % 4))

    table = 2 * (rounds + 1)
    s = [0] * table
    s[0] = _RC5_P32
    for i in range(1, table):
        s[i] = (s[i - 1] + _RC5_Q32) & mask

    def rotl(x, n):
        n &= 31
        return ((x << n) | (x >> (32 - n))) & mask if n else x

    a = b = i = j = 0
    for _ in range(3 * max(table, words)):
        a = s[i] = rotl((s[i] + a + b) & mask, 3)
        b = l[j] = rotl((l[j] + a + b) & mask, (a + b) & mask)
        i = (i + 1) % table
        j = (j + 1) % words
    return s


def rc5_block(key, block, rounds=12):
    """One RC5-32/rounds block encryption. **Little endian**, which is
    the opposite of TEA next door."""
    mask = 0xffffffff
    s = _rc5_schedule(key, rounds)

    def rotl(x, n):
        n &= 31
        return ((x << n) | (x >> (32 - n))) & mask if n else x

    a = (int.from_bytes(block[0:4], "little") + s[0]) & mask
    b = (int.from_bytes(block[4:8], "little") + s[1]) & mask
    for i in range(1, rounds + 1):
        a = (rotl(a ^ b, b) + s[2 * i]) & mask
        b = (rotl(b ^ a, a) + s[2 * i + 1]) & mask
    return a.to_bytes(4, "little") + b.to_bytes(4, "little")


def rc5_mode(key, mode, iv, data, rounds=12):
    """The five modes over `rc5_block`, from their definitions."""
    return _block_mode(lambda blk: rc5_block(key, blk, rounds), 8, mode, iv,
                       data)


def _block_mode(encrypt_block, block, mode, iv, data):
    """ECB, CBC, CFB, OFB and CTR built from a block encryption.

    One implementation for the ciphers no independent library has. CTR
    counts up over the whole block, big endian, which is what
    `modes.rs`'s `ctr_next` does.
    """
    out = bytearray()
    if mode == "ecb":
        for i in range(0, len(data), block):
            out.extend(encrypt_block(data[i:i + block]))
    elif mode == "cbc":
        state = bytes(iv)
        for i in range(0, len(data), block):
            state = encrypt_block(xor(data[i:i + block], state))
            out.extend(state)
    elif mode == "cfb":
        state = bytes(iv)
        for i in range(0, len(data), block):
            piece = data[i:i + block]
            chunk = xor(piece, encrypt_block(state)[:len(piece)])
            out.extend(chunk)
            state = bytes(chunk)
    elif mode in ("ofb", "ctr"):
        stream = bytearray()
        state = bytearray(iv)
        while len(stream) < len(data):
            keyblock = encrypt_block(bytes(state))
            stream.extend(keyblock)
            if mode == "ofb":
                state = bytearray(keyblock)
            else:
                for i in range(len(state) - 1, -1, -1):
                    state[i] = (state[i] + 1) & 0xff
                    if state[i]:
                        break
        out.extend(xor(data, bytes(stream[:len(data)])))
    else:
        raise Mismatch(f"no reference for mode {mode!r}")
    return bytes(out)


def _rc5_selftest():
    """Pin the block function above to RFC 2040's first vector.

    `R = 0 Key = 00 IV = 0 P = 0` gives `7a7bba4d79111d1e`, and CBC with
    an all-zero IV over one block is ECB of that block - so the RFC's
    CBC row is a statement about the primitive.
    """
    got = rc5_block(b"\x00", bytes(8), rounds=0).hex()
    if got != "7a7bba4d79111d1e":
        raise Mismatch(f"the RC5 written in this script is wrong: {got}")


# ------------------------------------------------------------- ARIA ---
#
# RFC 5794, and **OpenSSL has it** - so unlike TEA and RC5 there is a
# real third party here. What OpenSSL does not give cheaply is three
# hundred lengths in five modes without three hundred subprocesses, so
# the pattern is the one `_md4_selftest` established: a reference
# written here, pinned to OpenSSL at import across the modes and key
# sizes, and then used for the sweep.
#
# The S-boxes and the diffusion layer are **read out of the vendored RFC
# by a different parser** from the Rust one - `src/block_ciphers/aria.rs`
# works line by line in a `const fn`, this one on the whole block. 1024
# table bytes and 112 diffusion indices are far too many to transcribe
# twice, and two parsers written differently agreeing on them says
# something neither alone does.

_RFC_5794 = (ROOT / "rfcs" / "rfc5794.txt").read_text(encoding="utf-8")


def _aria_tables():
    """The four S-boxes and the diffusion layer, from RFC 5794."""
    boxes = []
    for name in ("SB1:", "SB2:", "SB3:", "SB4:"):
        at = _RFC_5794.index(name) + len(name)
        table, row = [], 0
        for line in _RFC_5794[at:].split("\n"):
            tokens = line.split()
            # A data row is seventeen hex tokens: the row index and
            # sixteen values. **An entry may be one digit**: SB4 prints
            # `09` as ` 9`, alone in the document, and a parser wanting
            # two would drop that row.
            if len(tokens) != 17 or not all(
                    len(t) <= 2 and all(c in "0123456789abcdefABCDEF"
                                        for c in t) for t in tokens):
                continue
            if int(tokens[0], 16) != row * 16:
                raise Mismatch(f"{name} row out of order: {tokens[0]}")
            table.extend(int(t, 16) for t in tokens[1:])
            row += 1
            if row == 16:
                break
        if len(table) != 256:
            raise Mismatch(f"{name} parsed to {len(table)} entries")
        boxes.append(table)

    at = _RFC_5794.index("y0  = x")
    diffusion = []
    for i in range(16):
        line_start = _RFC_5794.index(f"y{i}", at)
        line_end = _RFC_5794.index("\n", line_start)
        terms = [int(m) for m in re.findall(r"x(\d+)",
                                            _RFC_5794[line_start:line_end])]
        if len(terms) != 7:
            raise Mismatch(f"ARIA diffusion row y{i} has {len(terms)} terms")
        diffusion.append(terms)
        at = line_end

    # The properties RFC 5794 states about its own tables. A parser
    # cannot arrange these by accident.
    for x in range(256):
        if boxes[2][boxes[0][x]] != x or boxes[3][boxes[1][x]] != x:
            raise Mismatch("ARIA's S-boxes do not invert each other")
    if boxes[0][0x23] != 0x26 or boxes[3][0xef] != 0xd3:
        raise Mismatch("ARIA's S-boxes fail the RFC's own spot checks")

    constants = []
    for name in ("C1 =  0x", "C2 =  0x", "C3 =  0x"):
        at = _RFC_5794.index(name) + len(name)
        constants.append(bytes.fromhex(_RFC_5794[at:at + 32]))
    return boxes, diffusion, constants


_ARIA_SB, _ARIA_A, _ARIA_C = _aria_tables()


def _aria_diffuse(x):
    return bytes(
        functools.reduce(operator.xor, (x[t] for t in row))
        for row in _ARIA_A)


def _aria_sl(x, offset):
    return bytes(_ARIA_SB[(i + offset) % 4][b] for i, b in enumerate(x))


def _aria_fo(d, rk):
    return _aria_diffuse(_aria_sl(xor(d, rk), 0))


def _aria_fe(d, rk):
    return _aria_diffuse(_aria_sl(xor(d, rk), 2))


def _aria_rotr(x, n):
    value = int.from_bytes(x, "big")
    n %= 128
    rotated = ((value >> n) | (value << (128 - n))) & ((1 << 128) - 1)
    return rotated.to_bytes(16, "big")


def _aria_round_keys(key):
    rounds = {16: 12, 24: 14, 32: 16}.get(len(key))
    if rounds is None:
        raise Mismatch(f"ARIA key length {len(key)}")
    kl, kr = key[:16], key[16:].ljust(16, b"\x00")
    offset = {16: 0, 24: 1, 32: 2}[len(key)]
    ck = [_ARIA_C[(offset + i) % 3] for i in range(3)]

    w0 = kl
    w1 = xor(_aria_fo(w0, ck[0]), kr)
    w2 = xor(_aria_fe(w1, ck[1]), w0)
    w3 = xor(_aria_fo(w2, ck[2]), w1)
    w = [w0, w1, w2, w3]

    rotl = lambda i, n: _aria_rotr(w[i], 128 - n)
    rotr = lambda i, n: _aria_rotr(w[i], n)
    ek = [
        xor(w[0], rotr(1, 19)), xor(w[1], rotr(2, 19)),
        xor(w[2], rotr(3, 19)), xor(rotr(0, 19), w[3]),
        xor(w[0], rotr(1, 31)), xor(w[1], rotr(2, 31)),
        xor(w[2], rotr(3, 31)), xor(rotr(0, 31), w[3]),
        xor(w[0], rotl(1, 61)), xor(w[1], rotl(2, 61)),
        xor(w[2], rotl(3, 61)), xor(rotl(0, 61), w[3]),
        xor(w[0], rotl(1, 31)), xor(w[1], rotl(2, 31)),
        xor(w[2], rotl(3, 31)), xor(rotl(0, 31), w[3]),
        xor(w[0], rotl(1, 19)),
    ]
    return ek[:rounds + 1], rounds


def aria_block(key, block):
    """One ARIA block encryption, from RFC 5794 sections 2.2 and 2.3."""
    ek, rounds = _aria_round_keys(key)
    p = bytes(block)
    for i in range(1, rounds):
        p = (_aria_fo if i % 2 else _aria_fe)(p, ek[i - 1])
    return xor(_aria_sl(xor(p, ek[rounds - 1]), 2), ek[rounds])


def aria_mode(key, mode, iv, data):
    return _block_mode(lambda blk: aria_block(key, blk), 16, mode, iv, data)


def _openssl_aria(key, mode, iv, data):
    """OpenSSL's ARIA, or None if this build has none."""
    name = f"aria-{len(key) * 8}-{mode}"
    command = ["openssl", "enc", f"-{name}", "-nopad", "-K", key.hex()]
    if mode != "ecb":
        command += ["-iv", iv.hex()]
    try:
        done = subprocess.run(command, input=data, capture_output=True,
                              check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout


def _aria_selftest():
    """Pin the ARIA above to OpenSSL, over every key size and mode.

    Reports which reference is in play rather than skipping silently:
    "agrees with OpenSSL" and "agrees with a second reading of the RFC"
    are different claims and a reader of this script's output wants to
    know which one the ARIA rows carry.
    """
    checked = 0
    for key_len in (16, 24, 32):
        key = keypattern(key_len)
        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr"):
            iv = ivpattern(16)
            data = corpus_data(64)
            theirs = _openssl_aria(key, mode, iv, data)
            if theirs is None:
                print("  [aria] this OpenSSL has no ARIA; the aria rows are "
                      "checked against a second reading of RFC 5794 only")
                return
            # OpenSSL's `cfb` is full-block CFB, which is what our mode
            # does; `cfb1` and `cfb8` are the other two and are not
            # offered here.
            ours = aria_mode(key, mode, iv, data)
            if ours != theirs:
                raise Mismatch(
                    f"the ARIA written in this script disagrees with OpenSSL "
                    f"at {key_len * 8} bits in {mode}: {ours.hex()} vs "
                    f"{theirs.hex()}")
            checked += 1
    print(f"  [aria] pinned to OpenSSL at {checked} key size and mode "
          f"combinations")


def ecb_one_block(factory, key, data):
    """One ECB block encryption, however this OpenSSL will give us one.

    RC2 is the awkward case: this build offers it in CBC and in nothing
    else, not even ECB. CBC with an all-zero IV over a single block *is*
    ECB of that block - that is the definition of CBC, not a trick - so a
    fresh CBC context per block gives the primitive back.
    """
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    try:
        enc = Cipher(factory(key), modes.ECB()).encryptor()
        return enc.update(data) + enc.finalize()
    except UnsupportedAlgorithm:
        enc = Cipher(factory(key), modes.CBC(bytes(len(data)))).encryptor()
        return enc.update(data) + enc.finalize()


def ecb_keystream(factory, key, iv, length, block, feedback):
    """The CTR or OFB keystream, built from single block ECB encryptions.

    CTR counts up over the whole block, big endian, which is what our
    `ctr_next` does; OFB feeds each output block back in as the next input.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    out = bytearray()
    state = bytearray(iv)
    while len(out) < length:
        keyblock = ecb_one_block(factory, key, bytes(state))
        out.extend(keyblock)
        if feedback:
            state = bytearray(keyblock)
        else:
            for i in range(len(state) - 1, -1, -1):
                state[i] = (state[i] + 1) & 0xff
                if state[i]:
                    break
    return bytes(out[:length])


from openssl_ctypes import openssl_cts, openssl_kbkdf  # noqa: E402


def check_block(lines):
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Blowfish moved to the "decrepit" module in cryptography 43 rather than
    # being removed - which is the same position this library takes about
    # weak algorithms, so it is nice to see.
    try:
        from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit
        blowfish = decrepit.Blowfish
    except ImportError:
        blowfish = getattr(algorithms, "Blowfish", None)

    # Triple DES is in decrepit too. Single DES has no type of its own
    # anywhere any more, so it goes through TripleDES with the key
    # repeated - which is not a workaround but the definition: EDE with
    # three equal keys *is* DES, and that compatibility is the only reason
    # the middle operation is a decryption.
    triple = getattr(decrepit, "TripleDES", None) if "decrepit" in dir() else None
    if triple is None:
        try:
            from cryptography.hazmat.decrepit.ciphers import algorithms as _d
            triple = _d.TripleDES
        except ImportError:
            triple = getattr(algorithms, "TripleDES", None)

    def des_factory(key):
        return triple(key * 3) if triple else None

    # RC2 is in decrepit as well, at one key length only: cryptography
    # accepts 128 bit keys and nothing else, which happens to be exactly
    # what TLS's export suites expand to. The other lengths are covered by
    # the RFC 2268 vectors in the unit tests, and the effective-key-length
    # parameter - which no library interface exposes - by `diff_rc2`.
    try:
        from cryptography.hazmat.decrepit.ciphers import algorithms as _rc2mod
        rc2 = _rc2mod.RC2
    except (ImportError, AttributeError):
        rc2 = None

    # The decrepit set. Every one of these is in python-cryptography
    # today; CAST5, IDEA and SEED are already in `hazmat.decrepit` and
    # Camellia and SM4 are the two that have not moved yet. Looked up
    # rather than imported directly so that the day one of them goes,
    # this skips that row loudly rather than failing to import.
    def maybe(module, name):
        return getattr(module, name, None)

    _tea_selftest()
    _rc5_selftest()
    _aria_selftest()
    ALGOS = {"aes": algorithms.AES, "blowfish": blowfish,
             "des": des_factory, "3des": triple, "rc2": rc2,
             "cast5": maybe(decrepit, "CAST5") or maybe(algorithms, "CAST5"),
             "idea": maybe(decrepit, "IDEA") or maybe(algorithms, "IDEA"),
             "seed": maybe(decrepit, "SEED") or maybe(algorithms, "SEED"),
             "camellia": maybe(algorithms, "Camellia") or maybe(decrepit, "Camellia"),
             "sm4": maybe(algorithms, "SM4") or maybe(decrepit, "SM4")}
    checked = 0
    skipped = 0
    for line in lines:
        if " " not in line:
            continue
        tag, got = line.split(" ", 1)
        parts = tag.split("/")
        if len(parts) != 4:
            continue
        algo, keylen, mode, n = parts[0], int(parts[1]), parts[2], int(parts[3])

        key = keypattern(keylen)
        if algo == "aria":
            iv = ivpattern(16)
            if mode in ("ecb", "cbc") and n % 16:
                continue
            want = aria_mode(key, mode, iv, corpus_data(n)).hex()
            if got != want:
                raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
            checked += 1
            continue
        if algo == "rc5":
            iv = ivpattern(8)
            if mode in ("ecb", "cbc") and n % 8:
                continue
            want = rc5_mode(key, mode, iv, corpus_data(n)).hex()
            if got != want:
                raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
            checked += 1
            continue
        if algo in ("tea", "xtea"):
            # No independent library has these, so the reference is the
            # one written above from the papers.
            iv = ivpattern(8)
            if mode in ("ecb", "cbc") and n % 8:
                continue
            want = tea_mode(algo, key, mode, iv, corpus_data(n)).hex()
            if got != want:
                raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
            checked += 1
            continue

        if mode.startswith("cbc-cs"):
            # OpenSSL's own CTS, through its EVP interface: python-
            # cryptography has no ciphertext stealing.
            variant = mode[4:7].upper()
            decrypting = mode.endswith("-dec")
            name = f"{algo.upper()}-{keylen * 8}-CBC-CTS"
            want = openssl_cts(name, variant, key, ivpattern(16), corpus_data(n),
                               encrypt=not decrypting).hex()
            if got != want:
                raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
            checked += 1
            continue
        if mode == "ctr-le":
            # The whole block one little-endian counter from the IV:
            # OpenSSL's AES-ECB over those counters, XORed in.
            counter = int.from_bytes(ivpattern(16), "little")
            blocks = []
            ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            for i in range((n + 15) // 16):
                blocks.append(ecb.update(((counter + i) % (1 << 128)).to_bytes(16, "little")))
            want = xor(corpus_data(n), b"".join(blocks)[:n]).hex()
            if got != want:
                raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
            checked += 1
            continue

        factory = ALGOS.get(algo)
        if factory is None:
            skipped += 1
            continue

        block = 16 if algo in ("aes", "seed", "camellia", "sm4") else 8
        iv = ivpattern(block)
        data = corpus_data(n)

        if mode == "ecb":
            m = modes.ECB()
        elif mode == "cbc":
            m = modes.CBC(iv)
        elif mode == "ctr":
            m = modes.CTR(iv)
        elif mode == "ofb":
            m = modes.OFB(iv)
        elif mode == "cfb":
            m = modes.CFB(iv)
        else:
            # Not `continue`: a mode with no checker here would vanish
            # from the count rather than fail.
            raise Mismatch(f"corpus row {tag!r} has no checker")

        if mode in ("ecb", "cbc") and n % block:
            continue  # not block aligned; our side errors and prints nothing

        try:
            enc = Cipher(factory(key), m).encryptor()
            want = (enc.update(data) + enc.finalize()).hex()
        except UnsupportedAlgorithm:
            # This OpenSSL build will not do, say, Blowfish in CTR. Build the
            # keystream from its ECB instead, which is still an independent
            # implementation of the cipher - CTR and OFB are *defined* as ECB
            # over a counter or a feedback chain, so this is the definition,
            # not our code a second time.
            if mode == "ctr":
                want = xor(data, ecb_keystream(factory, key, iv, len(data), block,
                                               feedback=False)).hex()
            elif mode == "ofb":
                want = xor(data, ecb_keystream(factory, key, iv, len(data), block,
                                               feedback=True)).hex()
            elif mode == "ecb":
                want = b"".join(
                    ecb_one_block(factory, key, data[i:i + block])
                    for i in range(0, len(data), block)).hex()
            elif mode == "cfb":
                # C_i = P_i XOR E(C_{i-1}), starting from the IV. Full
                # block CFB, which is what our mode does.
                out, state = bytearray(), iv
                for i in range(0, len(data), block):
                    piece = data[i:i + block]
                    keyblock = ecb_one_block(factory, key, state)
                    chunk = xor(piece, keyblock[:len(piece)])
                    out.extend(chunk)
                    state = bytes(chunk)
                want = bytes(out).hex()
            else:
                skipped += 1
                continue
        if got != want:
            raise Mismatch(f"{tag}\n  ours: {got}\n  ref : {want}")
        checked += 1

    if skipped:
        # GOST is the one with no reference here. It is covered by the
        # RFC 5830 vectors in tests/test_gost.rs and by gost-engine's
        # answers in vectors/gost_engine.vec, which is what docs/status.md
        # ticks it on - not this corpus.
        print(f"  (skipped {skipped} lines: no independent reference available)")
    return checked


def check_gcm(lines):
    """Every GCM case against OpenSSL's own AES-GCM.

    The specification's six vectors are in the unit tests. This is the part
    they do not cover: a partial final block, additional data at and either
    side of a block boundary, a nonce that is not 96 bits so J0 comes from
    GHASH rather than directly, and plaintexts long enough for the
    counter's low bytes to carry.

    Both directions are checked. Verifying the tag we produced against
    OpenSSL is the one that matters, because the keystream does not depend
    on GHASH at all - a comparison of ciphertext alone passes with the
    authentication completely broken.

    A forgery check goes with each case: one flipped bit in the tag must
    make OpenSSL refuse it too. That pins the tag as a real authenticator
    rather than a value the two implementations happen to agree on.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "gcm":
            continue
        _, key, nonce, aad, plaintext, ciphertext, tag = parts
        key, nonce = unhex(key), unhex(nonce)
        aad, plaintext = unhex(aad), unhex(plaintext)
        ours, our_tag = unhex(ciphertext), unhex(tag)

        # OpenSSL returns ciphertext||tag as one buffer.
        theirs = AESGCM(key).encrypt(nonce, plaintext, aad or None)
        if theirs != ours + our_tag:
            raise Mismatch(
                f"GCM key={len(key)*8} nonce={len(nonce)} aad={len(aad)} "
                f"len={len(plaintext)}:\n  ours   {(ours + our_tag).hex()}"
                f"\n  openssl {theirs.hex()}")

        back = AESGCM(key).decrypt(nonce, ours + our_tag, aad or None)
        if back != plaintext:
            raise Mismatch(f"GCM decrypt disagreed at len={len(plaintext)}")

        forged = bytearray(ours + our_tag)
        forged[-1] ^= 0x01
        try:
            AESGCM(key).decrypt(nonce, bytes(forged), aad or None)
        except InvalidTag:
            pass
        else:
            raise Mismatch("a flipped tag bit was accepted by OpenSSL, so "
                           "this case proves nothing about authentication")
        checked += 1
    return checked


def check_ocb(lines):
    """Every OCB case against OpenSSL's AES-OCB (python-cryptography's
    `AESOCB3`), both directions, with a flipped tag bit refused.

    OpenSSL takes 12 to 15 byte nonces and a 16 byte tag here, so the
    other tag lengths are covered by RFC 7253's iterated vectors in the
    unit tests rather than by this corpus. The corpus is required to
    reach every value of the nonce's low six bits, which choose the
    window into `Stretch`.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
    from cryptography.exceptions import InvalidTag

    checked = 0
    bottoms = set()
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "ocb":
            continue
        _, key, nonce, aad, plaintext, ciphertext, tag = parts
        key, nonce = unhex(key), unhex(nonce)
        aad, plaintext = unhex(aad), unhex(plaintext)
        ours, our_tag = unhex(ciphertext), unhex(tag)
        bottoms.add(nonce[-1] & 0x3F)
        reference = AESOCB3(key)
        theirs = reference.encrypt(nonce, plaintext, aad or None)
        if theirs != ours + our_tag:
            raise Mismatch(
                f"OCB key={len(key)*8} nonce={len(nonce)} aad={len(aad)} "
                f"len={len(plaintext)}:\n  ours    {(ours + our_tag).hex()}\n"
                f"  openssl {theirs.hex()}")
        if reference.decrypt(nonce, ours + our_tag, aad or None) != plaintext:
            raise Mismatch(f"OCB decrypt disagreed at len={len(plaintext)}")
        forged = bytearray(ours + our_tag)
        forged[-1] ^= 0x01
        try:
            reference.decrypt(nonce, bytes(forged), aad or None)
        except InvalidTag:
            pass
        else:
            raise Mismatch("a flipped tag bit was accepted by OpenSSL")
        checked += 1
    if len(bottoms) != 64:
        raise Mismatch(f"the corpus reached {len(bottoms)} of the 64 nonce bottoms")
    return checked


def check_ccm(lines):
    """Every CCM case against OpenSSL's own AES-CCM.

    The RFC 3610 vectors are in the unit tests and cover two nonce lengths
    and one tag length. What this covers is the formatting, which is where
    CCM implementations actually diverge: the plaintext's zero padding
    either side of a block boundary, the additional data's length prefix
    either side of 65280 where it changes from two bytes to six, and every
    legal nonce length - each of which is a different block layout rather
    than a different value, because the nonce's length decides how wide
    the length field and the counter are.

    Both directions, and a forgery check with each case: one flipped bit
    must make OpenSSL refuse it too. Without that, a tag is only a value
    the two implementations agree on rather than an authenticator - and
    the keystream does not depend on the CBC-MAC at all, so comparing
    ciphertext alone would pass with the authentication entirely broken.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from cryptography.exceptions import InvalidTag

    checked = 0
    tag_lengths = set()
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "ccm":
            continue
        _, key, nonce, aad, plaintext, ciphertext, tag = parts
        key, nonce = unhex(key), unhex(nonce)
        aad, plaintext = unhex(aad), unhex(plaintext)
        ours, our_tag = unhex(ciphertext), unhex(tag)
        tag_lengths.add(len(our_tag))

        reference = AESCCM(key, tag_length=len(our_tag))
        theirs = reference.encrypt(nonce, plaintext, aad or None)
        if theirs != ours + our_tag:
            raise Mismatch(
                f"CCM key={len(key)*8} nonce={len(nonce)} aad={len(aad)} "
                f"len={len(plaintext)} tag={len(our_tag)}:\n"
                f"  ours    {(ours + our_tag).hex()}\n"
                f"  openssl {theirs.hex()}")

        back = reference.decrypt(nonce, ours + our_tag, aad or None)
        if back != plaintext:
            raise Mismatch(f"CCM decrypt disagreed at len={len(plaintext)}")

        forged = bytearray(ours + our_tag)
        forged[-1] ^= 0x01
        try:
            reference.decrypt(nonce, bytes(forged), aad or None)
        except InvalidTag:
            pass
        else:
            raise Mismatch("a flipped tag bit was accepted by OpenSSL, so "
                           "this case proves nothing about authentication")
        checked += 1

    # A corpus that only ever used one tag length would leave the M field
    # of B0 constant, and a wrong encoding of it would never show.
    if len(tag_lengths) < 7:
        raise Mismatch(f"the corpus used tag lengths {sorted(tag_lengths)}; "
                       f"all seven legal ones are meant to appear")
    return checked


def check_tls_stream_records(lines):
    """The RC4 and NULL record construction, against a reference written
    here from RFC 5246 section 6.2.3.1.

    This corpus exists because **OpenSSL cannot be the reference**. It
    deleted RC4, so `cryptography` cannot produce a single byte of it, and
    the usual approach of "compare against the thing everybody else uses"
    has nothing to compare against. That is the general problem this whole
    library has, in its sharpest form: the algorithms worth keeping are the
    ones every reference implementation has removed.

    So the reference is written from the specification on this side -
    RC4 from Schneier's description in twelve lines, and the record
    construction from the RFC - and the two are compared. Two
    implementations from the same document agreeing is weaker evidence than
    two implementations of a living standard agreeing, and it is what there
    is. It is still enough to catch the mistakes that matter, because the
    interesting ones are structural rather than arithmetic: a keystream
    restarted per record, a MAC over the wrong bytes, a sequence number
    that does not advance.

    The keystream continuity is the one to watch. RC4's state runs for the
    whole connection, so a reference that restarts the cipher per record
    agrees on the first record of every suite and disagrees on all the
    rest - which is why this checks many records in a row rather than one.
    """
    import hmac as pyhmac

    def rc4(key):
        """RC4 as a generator of keystream bytes. From the algorithm, not
        from a library - there is no library left that has it."""
        state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + state[i] + key[i % len(key)]) % 256
            state[i], state[j] = state[j], state[i]
        i = j = 0
        while True:
            i = (i + 1) % 256
            j = (j + state[i]) % 256
            state[i], state[j] = state[j], state[i]
            yield state[(state[i] + state[j]) % 256]

    VERSIONS = {"SSLv3": b"\x03\x00", "TLSv1": b"\x03\x01",
                "TLSv1.1": b"\x03\x02", "TLSv1.2": b"\x03\x03"}
    HEADER = 5

    suites, checked = {}, 0

    for line in lines:
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "streamsuite":
            _, label, version, cipher, key, mac_key = parts
            suites[label] = {
                "version": version,
                "cipher": cipher,
                "key": unhex(key),
                "mac_key": unhex(mac_key),
                "sequence": 0,
            }
            # One keystream per suite, started here and never restarted.
            suites[label]["stream"] = (
                None if cipher == "null" else rc4(unhex(key)))
            continue

        if parts[0] == "streamhash":
            suites[parts[1]]["hash"] = parts[2]
            continue

        if parts[0] != "streamrecord":
            continue

        _, label, _index, content_type, payload, produced = parts
        suite = suites[label]
        payload = unhex(payload)
        produced = unhex(produced)
        content_type = int(content_type)
        version_bytes = VERSIONS[suite["version"]]

        # MAC over seq_num || type || version || length || fragment - or,
        # for SSLv3, a different construction over an input with no
        # version in it at all.
        if suite["version"] == "SSLv3":
            mac = ssl3_mac(suite["hash"], suite["mac_key"], suite["sequence"],
                           content_type, payload)
        else:
            mac_input = (suite["sequence"].to_bytes(8, "big")
                         + bytes([content_type]) + version_bytes
                         + len(payload).to_bytes(2, "big") + payload)
            mac = pyhmac.new(suite["mac_key"], mac_input, suite["hash"]).digest()
        suite["sequence"] += 1

        fragment = payload + mac
        if suite["stream"] is not None:
            fragment = bytes(b ^ next(suite["stream"]) for b in fragment)

        expected = (bytes([content_type]) + version_bytes
                    + len(fragment).to_bytes(2, "big") + fragment)

        if produced != expected:
            raise Mismatch(
                f"{label} record {_index} ({len(payload)} bytes):\n"
                f"  ours      {produced.hex()}\n"
                f"  reference {expected.hex()}")
        if len(produced) != HEADER + len(payload) + len(mac):
            raise Mismatch(f"{label}: unexpected record length")
        checked += 1

    if not checked:
        raise Mismatch("no stream-cipher records in the corpus")
    return checked


def check_chachapoly(lines):
    """ChaCha20-Poly1305 against OpenSSL's own.

    The lengths are the point. This construction pads the additional data
    and the ciphertext to 16 byte boundaries separately and then appends
    two little-endian 64 bit byte counts - not GCM's big-endian bit counts.
    Every one of those is invisible at the aligned lengths a handful of
    vectors happen to use.
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.exceptions import InvalidTag

    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "chachapoly":
            continue
        _, key, nonce, aad, plaintext, ciphertext, tag = parts
        key, nonce = unhex(key), unhex(nonce)
        aad, plaintext = unhex(aad), unhex(plaintext)
        ours, our_tag = unhex(ciphertext), unhex(tag)

        theirs = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad or None)
        if theirs != ours + our_tag:
            raise Mismatch(
                f"ChaCha20-Poly1305 aad={len(aad)} len={len(plaintext)}:\n"
                f"  ours    {(ours + our_tag).hex()}\n"
                f"  openssl {theirs.hex()}")

        back = ChaCha20Poly1305(key).decrypt(nonce, ours + our_tag, aad or None)
        if back != plaintext:
            raise Mismatch(f"decrypt disagreed at len={len(plaintext)}")

        forged = bytearray(ours + our_tag)
        forged[-1] ^= 0x01
        try:
            ChaCha20Poly1305(key).decrypt(nonce, bytes(forged), aad or None)
        except InvalidTag:
            pass
        else:
            raise Mismatch("a flipped tag bit was accepted by OpenSSL, so this "
                           "case proves nothing about authentication")
        checked += 1
    return checked


# ------------------------------------------------------------------ main ---


def check_name_constraints(lines):
    """`src/x509/name_constraints.rs`, against a path verifier that is not ours.

    RFC 5280 4.2.1.10 is reproduced in that module's own unit tests,
    example by example. That is not enough on its own: the matcher and
    the tests were read off the same page by the same reader, so they
    agree on any misreading. A name-constraint bug is silent in the
    dangerous direction - a subtree read one label too wide admits
    certificates and reports nothing - so it needs a second opinion.

    python-cryptography 42 and later carry a path verifier (webpki's
    logic, not OpenSSL's) that enforces name constraints. It covers
    **dNSName and iPAddress only**; it accepts a chain with
    directoryName, rfc822Name or uniformResourceIdentifier constraints
    whatever the names are. `tools/src/bin/diff_name_constraints.rs`
    therefore emits no rows for those forms, because a row that would
    agree however we behaved is worse than no row.

    The corpus is in pairs - one leaf inside each subtree and one
    outside, identical otherwise - and this requires the reference to
    **distinguish** them. If it rejected both, for one of the several
    policy reasons it has that we do not share, our rejection would
    agree with it and prove nothing. Both totals are asserted below.

    Its first run found a real bug that every test here had missed:
    `x509::builder` wrote GeneralizedTime for every validity date, and
    RFC 5280 4.1.2.5 requires UTCTime through 2049. Our own parser
    accepts both, as a relying party must, so every test that built a
    certificate and read it back agreed with itself.
    """
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.x509.verification import PolicyBuilder, Store

    # The same instant `tools/src/bin/diff_name_constraints.rs` verifies at.
    when = datetime.datetime(2023, 11, 14)

    checked = 0
    accepted = 0
    rejected = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "chain":
            continue
        _, ours, subject, root_hex, intermediate_hex, leaf_hex = parts
        root = x509.load_der_x509_certificate(unhex(root_hex))
        intermediate = x509.load_der_x509_certificate(unhex(intermediate_hex))
        leaf = x509.load_der_x509_certificate(unhex(leaf_hex))

        if subject.startswith("ip:"):
            wanted = x509.IPAddress(ipaddress.ip_address(subject[3:]))
        else:
            wanted = x509.DNSName(subject)

        verifier = (PolicyBuilder().store(Store([root])).time(when)
                    .build_server_verifier(wanted))
        try:
            verifier.verify(leaf, [intermediate])
            theirs, reason = "accept", ""
        except Exception as e:                       # their own exception type
            theirs, reason = "reject", str(e)

        if theirs != ours:
            raise Mismatch(
                f"name constraints disagree for {subject}:\n"
                f"  ours:   {ours}\n"
                f"  theirs: {theirs} {reason}")
        checked += 1
        accepted += theirs == "accept"
        rejected += theirs == "reject"

    if not checked:
        raise Mismatch("the name constraint corpus is empty")
    # A corpus the reference rejects wholesale agrees with every
    # rejection and checks nothing. Both halves have to be non-empty,
    # and the generator emits them in pairs so they should be close to
    # equal.
    if not accepted or not rejected:
        raise Mismatch(
            f"the reference {'accepted' if rejected else 'rejected'} every "
            f"one of {checked} chains, so it is not distinguishing them and "
            f"the corpus proves nothing")
    print(f"  ({accepted} accepted and {rejected} rejected, by both)")
    return checked



# `openssl verify -crl_check`'s exit reasons, mapped onto the corpus's
# three words. Anything not in here is an error rather than an
# "unknown": a row whose reference failed for a reason nobody
# anticipated is a row that proves nothing, and folding it into the
# inconclusive bucket is exactly how such a row would hide.
_OPENSSL_CRL_VERDICTS = {
    "certificate revoked":            "revoked",
    "unable to get certificate CRL":  "unknown",
    "CRL has expired":                "unknown",
    "CRL is not yet valid":           "unknown",
    "CRL signature failure":          "unknown",
    "different CRL scope":            "unknown",
    "unhandled critical CRL extension": "unknown",
    "unable to get CRL issuer certificate": "unknown",
    "unsupported CRL feature":        "unknown",
}


def check_crl(lines):
    """`src/x509/crl.rs`, against `openssl verify -crl_check`.

    Two things at once, and neither is enough alone. Our CRL *encoder*
    is checked by somebody else's parser, because a CRL nobody else can
    read is not a CRL and our writer and reader were written together.
    And our *verdict* is checked against theirs, because `crl::check`
    has a three-valued answer with a dozen routes to each value and
    every wrong route fails in the same direction: a revoked certificate
    looking clean.

    **One CRL per row.** `openssl verify -CRLfile` uses only the first
    CRL it finds for an issuer - two complete CRLs where the second
    revokes gives "OK", and swapping them gives "certificate revoked".
    So a multi-CRL row would be compared against a verdict formed from
    half the input. Delta merging, `removeFromCRL`, reason partitioning
    and indirect CRLs are therefore covered by `crl.rs`'s own tests and
    by nothing else, which `docs/pitfalls.md` records.

    All three verdicts must appear, or the comparison is not
    distinguishing anything.
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("openssl"):
        raise ImportError("the openssl command is not on PATH")

    def pem(label, der):
        import base64
        body = base64.b64encode(der).decode()
        wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
        return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"

    checked = 0
    seen = {"revoked": 0, "clean": 0, "unknown": 0}
    with tempfile.TemporaryDirectory() as workspace:
        root_path = os.path.join(workspace, "root.pem")
        leaf_path = os.path.join(workspace, "leaf.pem")
        crl_path = os.path.join(workspace, "crl.pem")

        for line in lines:
            parts = line.split()
            if not parts or parts[0] != "row":
                continue
            _, ours, root_hex, leaf_hex, crl_hex = parts

            with open(root_path, "w") as f:
                f.write(pem("CERTIFICATE", unhex(root_hex)))
            with open(leaf_path, "w") as f:
                f.write(pem("CERTIFICATE", unhex(leaf_hex)))

            command = ["openssl", "verify", "-crl_check", "-extended_crl",
                       "-CAfile", root_path, "-attime", "1700000000"]
            if crl_hex != "-":
                with open(crl_path, "w") as f:
                    f.write(pem("X509 CRL", unhex(crl_hex)))
                command += ["-CRLfile", crl_path]
            command.append(leaf_path)

            result = subprocess.run(command, capture_output=True, text=True)
            output = (result.stdout + result.stderr)

            if result.returncode == 0:
                theirs = "clean"
            else:
                theirs = None
                for phrase, verdict in _OPENSSL_CRL_VERDICTS.items():
                    if phrase in output:
                        theirs = verdict
                        break
                if theirs is None:
                    raise Mismatch(
                        "openssl refused a CRL row for a reason this checker "
                        "does not know, so the row cannot be compared:\n"
                        f"  ours: {ours}\n  openssl: {output.strip()}")

            if theirs != ours:
                raise Mismatch(
                    f"CRL verdicts disagree:\n"
                    f"  ours:    {ours}\n"
                    f"  openssl: {theirs} ({output.strip()})")
            seen[theirs] += 1
            checked += 1

    if not checked:
        raise Mismatch("the CRL corpus is empty")
    missing = [word for word, count in seen.items() if not count]
    if missing:
        raise Mismatch(
            f"the CRL corpus never produced {', '.join(missing)}, so the "
            f"comparison is not distinguishing the three verdicts")
    print(f"  ({seen['clean']} clean, {seen['revoked']} revoked, "
          f"{seen['unknown']} inconclusive, agreed by both)")
    return checked



def check_ocsp(lines):
    """`src/x509/ocsp.rs`, against `openssl ocsp`.

    Our encoder against their parser, and our verdict against theirs.
    A response nobody else can read is not a response, and our writer
    and reader were written together - so a round trip through both
    agrees with itself whatever it got wrong.

    A `req` row carries the request as well, which is how the CertID
    hashes other than SHA-1 get checked: `openssl ocsp -cert` builds
    its own CertID with SHA-1 and finds no answer otherwise. Those rows
    check our request encoder at the same time.

    **The clock.** `openssl ocsp` checks thisUpdate and nextUpdate
    against the current time and has no flag to fix it, while our
    verdict is computed at a fixed instant. Every row's times are
    chosen to read the same way at both, so a disagreement is about
    correctness rather than about which day it is.

    All three verdicts must appear.
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("openssl"):
        raise ImportError("the openssl command is not on PATH")

    def pem(label, der):
        import base64
        body = base64.b64encode(der).decode()
        wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
        return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"

    checked = 0
    seen = {"revoked": 0, "clean": 0, "unknown": 0}
    with_request = 0
    with tempfile.TemporaryDirectory() as workspace:
        root_path = os.path.join(workspace, "root.pem")
        leaf_path = os.path.join(workspace, "leaf.pem")
        response_path = os.path.join(workspace, "response.der")
        request_path = os.path.join(workspace, "request.der")

        for line in lines:
            parts = line.split()
            if not parts or parts[0] not in ("row", "req"):
                continue
            kind, ours, root_hex, leaf_hex, response_hex = parts[:5]
            request_hex = parts[5] if kind == "req" else None

            with open(root_path, "w") as f:
                f.write(pem("CERTIFICATE", unhex(root_hex)))
            with open(leaf_path, "w") as f:
                f.write(pem("CERTIFICATE", unhex(leaf_hex)))
            with open(response_path, "wb") as f:
                f.write(unhex(response_hex))

            command = ["openssl", "ocsp", "-respin", response_path,
                       "-issuer", root_path, "-CAfile", root_path, "-no_nonce"]
            if request_hex:
                with open(request_path, "wb") as f:
                    f.write(unhex(request_hex))
                command += ["-reqin", request_path]
            else:
                command += ["-cert", leaf_path]

            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout + result.stderr

            if request_hex:
                # With `-reqin`, openssl verifies the response and does
                # not do a status lookup, so these rows check a
                # narrower thing: that our request and response encode
                # to something it accepts, and that the answer is
                # in them. They exist because they are the only way to
                # exercise a CertID hash other than SHA-1 - `-cert`
                # builds its own with SHA-1 and finds nothing.
                #
                # Narrower is not nothing: a CertID hash we got wrong
                # makes *us* say unknown, and an encoding it got wrong
                # makes openssl refuse.
                if "Response verify OK" not in output:
                    raise Mismatch(
                        "openssl would not verify a response this library "
                        f"built:\n  {output.strip()}")
                if ours == "unknown":
                    raise Mismatch(
                        "openssl verified a response that we could not use, "
                        "which for these rows means the CertID did not match")
                seen[ours] += 1
                checked += 1
                with_request += 1
                continue

            # A response whose signature or signer is not acceptable, or
            # whose times are out, gives no status at all - which is our
            # `Unknown`. Otherwise the line names the answer.
            if "Response verify OK" not in output:
                theirs = "unknown"
            elif ": revoked" in output:
                theirs = "revoked"
            elif ": good" in output:
                theirs = "clean"
            elif ": unknown" in output or "No Status found" in output \
                    or "Status times invalid" in output:
                theirs = "unknown"
            else:
                raise Mismatch(
                    "openssl gave an OCSP answer this checker does not know, "
                    "so the row cannot be compared:\n"
                    f"  ours: {ours}\n  openssl: {output.strip()}")

            if theirs != ours:
                raise Mismatch(
                    f"OCSP verdicts disagree:\n"
                    f"  ours:    {ours}\n"
                    f"  openssl: {theirs} ({output.strip()})")
            seen[theirs] += 1
            checked += 1

    if not checked:
        raise Mismatch("the OCSP corpus is empty")
    missing = [word for word, count in seen.items() if not count]
    if missing:
        raise Mismatch(
            f"the OCSP corpus never produced {', '.join(missing)}, so the "
            f"comparison is not distinguishing the three verdicts")
    print(f"  ({seen['clean']} clean, {seen['revoked']} revoked, "
          f"{seen['unknown']} inconclusive, agreed by both; "
          f"{with_request} of those carried a request, which checks our "
          f"request encoding and the non-SHA-1 CertID hashes)")
    return checked


def check_tls_premaster(lines):
    """The TLS premaster secret, for the two families with opposite rules.

    RFC 5246 section 8.1.2 strips the leading zero bytes of a
    finite-field shared secret. RFC 4492 section 5.10 forbids stripping
    them from the elliptic-curve x coordinate. Applying either rule to
    the other family produces a premaster that is self-consistent,
    interoperates 255 times in 256, and fails the 256th connection with
    `bad_record_mac`.

    Every row in this corpus has a leading zero in the raw shared value,
    so every row can tell the two rules apart. The check is therefore
    two-sided: our answer must equal what the row's own RFC says *and*
    differ from what the other one says. A one-sided check would pass if
    both rules were implemented as the same rule.
    """
    from cryptography.hazmat.primitives.asymmetric import dh, ec

    curves = _curves()
    checked = 0
    families = set()
    for line in lines:
        parts = line.split()
        op = parts[0]
        if op == "ecdhe":
            name, da_hex, db_hex, got = parts[1:5]
            if name not in curves:
                raise Mismatch(f"no reference for curve {name!r}, so this row "
                               f"cannot be checked")
            curve = curves[name]
            a = ec.derive_private_key(bigint(da_hex), curve)
            b = ec.derive_private_key(bigint(db_hex), curve)
            shared = a.exchange(ec.ECDH(), b.public_key())
            want = shared.hex()
            other = shared.lstrip(b"\x00").hex()
        elif op == "dhe":
            p_hex, g_hex, a_hex, b_hex, got = parts[1:6]
            p_value, g_value = bigint(p_hex), bigint(g_hex)
            a, b = bigint(a_hex), bigint(b_hex)
            width = (p_value.bit_length() + 7) // 8
            parameters = dh.DHParameterNumbers(p_value, g_value)
            side_a = dh.DHPrivateNumbers(
                a, dh.DHPublicNumbers(pow(g_value, a, p_value), parameters))
            public_b = dh.DHPublicNumbers(pow(g_value, b, p_value), parameters)
            shared = side_a.private_key().exchange(public_b.public_key())
            # OpenSSL hands back the secret padded to the width of the
            # modulus; TLS 1.2 then strips it.
            if len(shared) != width:
                raise Mismatch("the reference exchange came back unpadded, so "
                               "this row cannot distinguish the two rules")
            want = shared.lstrip(b"\x00").hex()
            other = shared.hex()
        else:
            raise Mismatch(f"unknown row type {op!r}")

        if got != want:
            raise Mismatch(f"{op}\n  ours: {got}\n  ref : {want}")
        if want == other:
            raise Mismatch(
                f"{op}: the two rules give the same answer for this row, so "
                f"it distinguishes nothing - the shared value has no leading "
                f"zero byte and the generator's search is broken")
        checked += 1
        families.add(op)

    if families != {"ecdhe", "dhe"}:
        raise Mismatch(
            f"only {sorted(families) or 'nothing'} in the corpus: the point "
            f"of it is that the two families disagree, which one family "
            f"alone cannot show")
    return checked


def check_elgamal(lines):
    """ElGamal against Python's own integers.

    **There is no second implementation.** OpenSSL dropped ElGamal and
    python-cryptography never had it, so unlike Diffie-Hellman there is
    nothing here that can do a key exchange with us and tell us we agree
    on a convention. What is left is the arithmetic, and `pow(g, x, p)`
    is a genuinely independent implementation of that.

    So the corpus is shaped to make the conventions checkable from the
    arithmetic: the `enc` rows carry a chosen `k` so both ciphertext
    components can be recomputed, `dec` checks the inversion, `live`
    checks that a ciphertext with an unknown `k` is still internally
    consistent, and `sig` verifies a whole signature.
    """
    checked = 0
    kinds = set()
    for line in lines:
        parts = line.split()
        op = parts[0]
        kinds.add(op)

        if op == "enc":
            _label, p_hex, g_hex, y_hex, m_hex, k_hex, c1_hex, c2_hex = parts[1:9]
            p_value = bigint(p_hex)
            want_c1 = pow(bigint(g_hex), bigint(k_hex), p_value)
            want_c2 = (bigint(m_hex) * pow(bigint(y_hex), bigint(k_hex),
                                           p_value)) % p_value
            if bigint(c1_hex) != want_c1 or bigint(c2_hex) != want_c2:
                raise Mismatch(f"elgamal enc {parts[1]}:\n"
                               f"  ours: {c1_hex} {c2_hex}\n"
                               f"  ref : {want_c1:x} {want_c2:x}")

        elif op == "dec":
            _label, p_hex, _g_hex, x_hex, c1_hex, c2_hex, m_hex = parts[1:8]
            p_value = bigint(p_hex)
            # m = c2 * (c1^x)^-1 mod p, with the inverse taken by Python
            # rather than by Fermat - a different route to the same
            # value, which is the point.
            shared = pow(bigint(c1_hex), bigint(x_hex), p_value)
            want = (bigint(c2_hex) * pow(shared, -1, p_value)) % p_value
            if bigint(m_hex) != want:
                raise Mismatch(f"elgamal dec {parts[1]}:\n"
                               f"  ours: {m_hex}\n  ref : {want:x}")

        elif op == "live":
            # `k` was drawn inside `encrypt`, so the ciphertext cannot be
            # predicted. What can be checked is that it is *consistent*:
            # `c2 / m` must equal `c1^x`, which is only true if the same
            # `k` produced both components.
            _label, p_hex, _g_hex, x_hex, m_hex, c1_hex, c2_hex = parts[1:8]
            p_value = bigint(p_hex)
            c1, c2, m = bigint(c1_hex), bigint(c2_hex), bigint(m_hex)
            if not 2 <= c1 <= p_value - 2:
                raise Mismatch(f"elgamal live {parts[1]}: c1 is degenerate")
            shared = pow(c1, bigint(x_hex), p_value)
            if (m * shared) % p_value != c2:
                raise Mismatch(f"elgamal live {parts[1]}: the two ciphertext "
                               f"components do not share a k")

        elif op == "sig":
            _label, p_hex, g_hex, y_hex, digest_hex, r_hex, s_hex = parts[1:8]
            p_value = bigint(p_hex)
            r, s = bigint(r_hex), bigint(s_hex)
            m = int(digest_hex, 16) % (p_value - 1)
            left = (pow(bigint(y_hex), r, p_value)
                    * pow(r, s, p_value)) % p_value
            right = pow(bigint(g_hex), m, p_value)
            if left != right:
                raise Mismatch(f"elgamal sig {parts[1]}: the verification "
                               f"equation does not hold")
            # And the range conditions a verifier must enforce, so a
            # signer that emitted an out-of-range value would be caught
            # here rather than by our own verifier agreeing with itself.
            if not 1 <= r < p_value or not 1 <= s < p_value - 1:
                raise Mismatch(f"elgamal sig {parts[1]}: r or s is out of "
                               f"range")

        else:
            raise Mismatch(f"corpus row {op!r} has no checker.")
        checked += 1

    if kinds != {"enc", "dec", "live", "sig"}:
        raise Mismatch(
            f"only {sorted(kinds)} in the corpus: encryption, decryption and "
            f"signing check different things and one of them alone proves "
            f"much less")
    print(f"  ({checked} rows; no independent ElGamal exists on this "
          f"machine, so the reference is Python's own integers)")
    return checked


# ------------------------------------------------------------------- MGM ---

def _mgm_block_encrypt(cipher, key, block):
    """`E_K` for the four ciphers the corpus uses.

    Kuznyechik and Magma come from this file's own readings of GOST R
    34.12-2015; AES and DES come from python-cryptography, which is a
    genuinely independent opinion and is why the corpus carries rows on
    two ciphers the standard never mentions. MGM is a mode, so a mode
    bug shows on all four and a cipher bug on one.
    """
    if cipher == "kuznyechik":
        return kuznyechik_encrypt_block(key, block)
    if cipher == "magma":
        return magma_encrypt_block(key, block)

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit
    except ImportError:
        decrepit = algorithms
    if cipher == "aes":
        algorithm = algorithms.AES(key)
    elif cipher == "des":
        algorithm = getattr(decrepit, "TripleDES", None) or algorithms.TripleDES
        # Single DES as the degenerate 3DES: K1 = K2 = K3 is DES, which
        # is how python-cryptography reaches it at all.
        algorithm = algorithm(key * 3)
    else:
        raise Mismatch(f"no reference block cipher for {cipher!r}")
    worker = Cipher(algorithm, modes.ECB()).encryptor()
    return worker.update(block) + worker.finalize()


def _mgm_gf_mul(a, b, block):
    """`a (x) b` in GF(2^n), RFC 9058 section 3.

    **MSB first**, which is the thing to get wrong: the leading bit of
    the string is the highest-degree coefficient, where GHASH reverses
    the bits inside each byte and XTS is little endian at the byte level
    too. All three are GF(2^128) and no two agree.

    The reduction polynomials are `w^128 + w^7 + w^2 + w + 1` and
    `w^64 + w^4 + w^3 + w + 1`, so the constants are 0x87 and 0x1b.
    """
    reduction = {16: 0x87, 8: 0x1B}[block]
    bits = block * 8
    top = 1 << (bits - 1)
    mask = (1 << bits) - 1
    x = int.from_bytes(a, "big")
    y = int.from_bytes(b, "big")
    product = 0
    for _ in range(bits):
        # Horner from the highest degree down, which is left to right.
        carried = product & top
        product = (product << 1) & mask
        if carried:
            product ^= reduction
        if x & top:
            product ^= y
        x = (x << 1) & mask
    return product.to_bytes(block, "big")


def _mgm_incr(value, block, left):
    """`incr_l` and `incr_r`: add one to one half, modulo 2^{n/2}.

    Written as one function taking which half, because the two differ in
    exactly that and a second copy is a second place to get the modulus
    wrong. **Neither carries into the other half**, which is what makes
    the two counter sequences independent - and every vector in RFC
    9058's appendix is far too short to reach a wrap, so this is checked
    by rows in the corpus rather than by the document.
    """
    half = block // 2
    high, low = value[:half], value[half:]
    if left:
        high = ((int.from_bytes(high, "big") + 1) % (1 << (half * 8))
                ).to_bytes(half, "big")
    else:
        low = ((int.from_bytes(low, "big") + 1) % (1 << (half * 8))
               ).to_bytes(half, "big")
    return high + low


def _mgm(cipher, key, icn, aad, data, tag_len, block, encrypting=True):
    """MGM-Encrypt / MGM-Decrypt, RFC 9058 section 4.

    One function for both because they differ only in which of the two
    strings is the plaintext: the keystream is its own inverse and the
    tag is always over the ciphertext. Returning both lets the checker
    assert that the tag was taken over the *ciphertext* rather than the
    plaintext - encrypt-and-MAC round-trips against itself perfectly,
    which is why that mistake needs a second implementation to see.
    """
    if len(icn) != block:
        raise Mismatch("the ICN is one block")
    if icn[0] & 0x80:
        raise Mismatch("the ICN's top bit is the domain separator")
    if not aad and not data:
        raise Mismatch("RFC 9058 section 6 forbids both inputs empty")

    # 1. The counter mode. Y_1 = E_K(0 || ICN), then incr_r.
    other = bytearray(data)
    if data:
        y = _mgm_block_encrypt(cipher, key, bytes([icn[0] & 0x7F]) + icn[1:])
        for offset in range(0, len(data), block):
            gamma = _mgm_block_encrypt(cipher, key, y)
            chunk = data[offset:offset + block]
            for i, byte in enumerate(chunk):
                other[offset + i] = byte ^ gamma[i]
            y = _mgm_incr(y, block, left=False)
    other = bytes(other)
    ciphertext = other if encrypting else data

    # 2, 3. The multilinear function. Z_1 = E_K(1 || ICN), then incr_l.
    z = _mgm_block_encrypt(cipher, key, bytes([icn[0] | 0x80]) + icn[1:])
    total = bytes(block)
    for part in (aad, ciphertext):
        for offset in range(0, len(part), block):
            chunk = part[offset:offset + block]
            # Zero padded on the right; the lengths below are what keeps
            # `A` and `A || 0x00` apart.
            chunk = chunk + bytes(block - len(chunk))
            h = _mgm_block_encrypt(cipher, key, z)
            total = _xor(total, _mgm_gf_mul(h, chunk, block))
            z = _mgm_incr(z, block, left=True)

    # len(A) || len(C), each n/2 bytes, **in bits**.
    half = block // 2
    lengths = ((len(aad) * 8).to_bytes(half, "big")
               + (len(ciphertext) * 8).to_bytes(half, "big"))
    h = _mgm_block_encrypt(cipher, key, z)
    total = _xor(total, _mgm_gf_mul(h, lengths, block))

    tag = _mgm_block_encrypt(cipher, key, total)[:tag_len]
    return other, tag


def check_mgm(lines):
    """MGM (RFC 9058), against a second reading of the standard.

    **Nothing on this machine implements MGM**, so this is a reading of
    the document rather than another library - the same standing as the
    other GOST corpora here. What it is worth comes from the sweep: the
    four worked examples in the RFC are checked byte for byte by
    `src/block_ciphers/mgm.rs` and cover one ragged tail each, no
    counter wrap, one block size per example and no truncated tag.

    Three things every row asserts beyond the ciphertext and tag, each
    of which is invisible from inside a single implementation:

      * **the tag is over the ciphertext**, not the plaintext. The
        checker computes the encrypt-and-MAC tag as well and requires it
        to differ, so a library that made that mistake could not pass.
      * **the two counter chains are different**. It recomputes the tag
        with `incr_r` in place of `incr_l` and requires that to differ
        too - the two sequences share their first element, so a row
        short enough never to step either counter would be silent.
      * **the field is MSB first**. It multiplies under GHASH's
        convention as well and requires a different answer.
    """
    checked = 0
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "mgm":
            continue
        cipher, tag_len = parts[1], int(parts[2])
        key, icn = unhex(parts[3]), unhex(parts[4])
        aad, plaintext = unhex(parts[5]), unhex(parts[6])
        got_c, got_tag = parts[7], parts[8]
        block = len(icn)

        ciphertext, tag = _mgm(cipher, key, icn, aad, plaintext, tag_len, block)
        # "-" for empty, the convention the whole corpus uses.
        ours = ciphertext.hex() if ciphertext else "-"
        if ours != got_c:
            raise Mismatch(f"MGM ciphertext, {cipher} tag {tag_len}, "
                           f"|A|={len(aad)} |P|={len(plaintext)}\n"
                           f"  ours: {got_c}\n  ref : {ours}")
        if tag.hex() != got_tag:
            raise Mismatch(f"MGM tag, {cipher} tag {tag_len}, "
                           f"|A|={len(aad)} |P|={len(plaintext)}\n"
                           f"  ours: {got_tag}\n  ref : {tag.hex()}")

        # Decryption is the same function the other way round, and must
        # return what went in.
        back, back_tag = _mgm(cipher, key, icn, aad, ciphertext, tag_len,
                              block, encrypting=False)
        if back != plaintext or back_tag != tag:
            raise Mismatch(f"{cipher}: the reference does not round trip")

        # ---- the wrong readings, each of which must differ ----

        # The tag over the plaintext: encrypt-and-MAC.
        if plaintext and plaintext != ciphertext:
            wrong = _mgm_tag_over(cipher, key, icn, aad, plaintext, tag_len, block)
            if wrong == tag:
                raise Mismatch(f"{cipher}: the tag is the same over the "
                               f"plaintext, so this row proves nothing")

        # `incr_r` driving the authentication instead of `incr_l`. The
        # two agree until something steps, which needs more than one
        # multiplicand - so rows with a single block are skipped rather
        # than passing vacuously.
        if len(aad) + len(ciphertext) > block:
            wrong = _mgm_tag_over(cipher, key, icn, aad, ciphertext, tag_len,
                                  block, left=False)
            if wrong == tag:
                raise Mismatch(f"{cipher}: the two counter chains are "
                               f"interchangeable, so this row proves nothing")

        # GHASH's field instead of this one.
        wrong = _mgm_tag_over(cipher, key, icn, aad, ciphertext, tag_len,
                              block, ghash_field=True)
        if wrong == tag:
            raise Mismatch(f"{cipher}: the tag does not depend on the field's "
                           f"convention, so this row proves nothing")
        checked += 1

    if not checked:
        raise Mismatch("the MGM corpus was empty")
    return checked


def _mgm_tag_over(cipher, key, icn, aad, data, tag_len, block,
                  left=True, ghash_field=False):
    """The tag alone, with one decision changed, for the checks above.

    Separate from `_mgm` so the real path cannot take a flag: a
    reference with a "do it wrong" switch is one edit away from having
    the switch stuck on, and then every row agrees with a mistake.
    """
    z = _mgm_block_encrypt(cipher, key, bytes([icn[0] | 0x80]) + icn[1:])
    total = bytes(block)
    for part in (aad, data):
        for offset in range(0, len(part), block):
            chunk = part[offset:offset + block]
            chunk = chunk + bytes(block - len(chunk))
            h = _mgm_block_encrypt(cipher, key, z)
            if ghash_field:
                total = _xor(total, _ghash_style_mul(h, chunk, block))
            else:
                total = _xor(total, _mgm_gf_mul(h, chunk, block))
            z = _mgm_incr(z, block, left=left)

    half = block // 2
    lengths = ((len(aad) * 8).to_bytes(half, "big")
               + (len(data) * 8).to_bytes(half, "big"))
    h = _mgm_block_encrypt(cipher, key, z)
    if ghash_field:
        total = _xor(total, _ghash_style_mul(h, lengths, block))
    else:
        total = _xor(total, _mgm_gf_mul(h, lengths, block))
    return _mgm_block_encrypt(cipher, key, total)[:tag_len]


def _ghash_style_mul(a, b, block):
    """The same field with GHASH's bit order, for the contrast above.

    GCM numbers the bits of each byte the other way round and reduces
    with 0xE1 at the top rather than 0x87 at the bottom. It is a
    perfectly good multiplication in GF(2^n) and it is not this one.
    """
    reduction = {16: 0xE1 << (8 * 15), 8: 0xE1 << (8 * 7)}[block]
    bits = block * 8
    mask = (1 << bits) - 1
    y = int.from_bytes(b, "big")
    product = 0
    for i in range(bits):
        if (int.from_bytes(a, "big") >> (bits - 1 - i)) & 1:
            product ^= y
        carried = y & 1
        y >>= 1
        if carried:
            y ^= reduction
        y &= mask
    return product.to_bytes(block, "big")


# ---------------------------------------------------------------- ML-KEM ---
#
# A second ML-KEM, written here from FIPS 203 rather than from
# `src/pq/ml_kem/`, so that something other than NIST's 195 fixed cases
# has an opinion about ours.
#
# **Independent where it can be, by construction rather than by
# intention.** The routes differ from the Rust ones wherever the
# standard leaves room:
#
#   * The hashes are hashlib's SHA3-256, SHA3-512, SHAKE-128 and
#     SHAKE-256, not our Keccak.
#   * The NTT is not a butterfly network. FIPS 203's NTT is, by
#     definition, the residues of `f` modulo the 128 quadratics
#     `X^2 - gamma_i`; here each residue is computed directly from that
#     definition - two polynomial evaluations at `gamma_i` - and the
#     inverse is interpolation at the 128 roots of `Y^128 + 1`, which
#     the `gamma_i` are. A wrong twiddle order, a wrong layer split or a
#     missing final scaling in a butterfly network has no counterpart
#     here to share it.
#   * `Compress` and `Decompress` are exact rational rounding with
#     `fractions.Fraction`, not an integer formula.
#   * The encodings go through an explicit bit list, FIPS 203's
#     `BitsToBytes`/`BytesToBits`, not a shift accumulator.
#
# What cannot differ is what the standard fixes: the parameter table,
# the order of the XOF's index bytes, the PRF counter, the FO transform.
# Those are written from the algorithm listings, and NIST's vectors are
# what settles them; `_ml_kem_selftest` runs this file's ML-KEM against
# the vendored ones before it is trusted with anything.

_KEM_Q = 3329
_KEM_ZETA = 17

#: name -> (k, eta1, eta2, du, dv), FIPS 203 table 2.
_KEM_SETS = {
    "ML-KEM-512": (2, 3, 2, 10, 4),
    "ML-KEM-768": (3, 2, 2, 10, 4),
    "ML-KEM-1024": (4, 2, 2, 11, 5),
}


def _bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


@functools.lru_cache(maxsize=None)
def _kem_gammas():
    """`gamma_i = zeta^(2*BitRev7(i) + 1)`, the roots of `Y^128 + 1`."""
    return [pow(_KEM_ZETA, 2 * _bitrev7(i) + 1, _KEM_Q) for i in range(128)]


@functools.lru_cache(maxsize=None)
def _kem_power_rows():
    """`gamma_i^m` for every `i` and `m < 128`, and the inverse powers."""
    q = _KEM_Q
    forward = [[pow(g, m, q) for m in range(128)] for g in _kem_gammas()]
    backward = [[pow(g, -m, q) for m in range(128)] for g in _kem_gammas()]
    return forward, backward


def _kem_ntt(f):
    """The residue of `f` modulo each `X^2 - gamma_i`, from the definition.

    `X^(2m) = gamma^m` and `X^(2m+1) = gamma^m * X` in that quotient, so
    the residue is `E(gamma) + O(gamma) X` with `E` and `O` the even and
    odd halves of `f`.
    """
    q = _KEM_Q
    even, odd = f[0::2], f[1::2]
    out = []
    for row in _kem_power_rows()[0]:
        out.append(sum(map(operator.mul, even, row)) % q)
        out.append(sum(map(operator.mul, odd, row)) % q)
    return out


def _kem_intt(f_hat):
    """Interpolate `E` and `O` back from their values at the 128 roots.

    The `gamma_i` are the 128 distinct roots of `Y^128 + 1`, and for
    exponents in `(-128, 128)` the sum of `gamma_i^k` over all `i` is 128
    at `k = 0` and 0 otherwise, so the coefficient of `Y^j` is
    `128^-1 * sum_i value_i * gamma_i^-j`.
    """
    q = _KEM_Q
    scale = pow(128, -1, q)
    backward = _kem_power_rows()[1]
    even_values, odd_values = f_hat[0::2], f_hat[1::2]
    out = [0] * 256
    for j in range(128):
        column = [backward[i][j] for i in range(128)]
        out[2 * j] = scale * sum(map(operator.mul, even_values, column)) % q
        out[2 * j + 1] = scale * sum(map(operator.mul, odd_values, column)) % q
    return out


def _kem_multiply(f_hat, g_hat):
    """Products in each `Z_q[X]/(X^2 - gamma_i)`."""
    q = _KEM_Q
    out = []
    for i, gamma in enumerate(_kem_gammas()):
        a0, a1 = f_hat[2 * i], f_hat[2 * i + 1]
        b0, b1 = g_hat[2 * i], g_hat[2 * i + 1]
        out.append((a0 * b0 + a1 * b1 * gamma) % q)
        out.append((a0 * b1 + a1 * b0) % q)
    return out


def _kem_add(f, g):
    return [(a + b) % _KEM_Q for a, b in zip(f, g)]


def _kem_sub(f, g):
    return [(a - b) % _KEM_Q for a, b in zip(f, g)]


def _kem_bits(data):
    """FIPS 203 `BytesToBits`: little-endian within each byte."""
    return [(byte >> i) & 1 for byte in data for i in range(8)]


def _kem_from_bits(bits):
    """FIPS 203 `BitsToBytes`."""
    assert len(bits) % 8 == 0
    return bytes(sum(bits[8 * n + i] << i for i in range(8))
                 for n in range(len(bits) // 8))


def _kem_encode(f, d):
    bits = []
    for value in f:
        assert 0 <= value < (2 ** d if d < 12 else _KEM_Q)
        bits.extend((value >> i) & 1 for i in range(d))
    return _kem_from_bits(bits)


def _kem_decode(data, d):
    bits = _kem_bits(data)
    assert len(bits) == 256 * d
    modulus = 2 ** d if d < 12 else _KEM_Q
    return [sum(bits[i * d + j] << j for j in range(d)) % modulus
            for i in range(256)]


def _kem_round(value):
    """Round half up, which is what FIPS 203 section 2.3 specifies."""
    return math.floor(value + fractions.Fraction(1, 2))


def _kem_compress(f, d):
    return [_kem_round(fractions.Fraction(2 ** d * x, _KEM_Q)) % 2 ** d
            for x in f]


def _kem_decompress(f, d):
    return [_kem_round(fractions.Fraction(_KEM_Q * y, 2 ** d)) for y in f]


def _kem_sample_ntt(seed34):
    """FIPS 203 algorithm 7, reading SHAKE-128 three bytes at a time."""
    length = 840
    while True:
        stream = hashlib.shake_128(seed34).digest(length)
        out = []
        at = 0
        while len(out) < 256 and at + 3 <= len(stream):
            c0, c1, c2 = stream[at], stream[at + 1], stream[at + 2]
            at += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = c1 // 16 + 16 * c2
            if d1 < _KEM_Q:
                out.append(d1)
            if d2 < _KEM_Q and len(out) < 256:
                out.append(d2)
        if len(out) == 256:
            return out
        # Ran out before 256 values: squeeze further. hashlib's SHAKE
        # output for a longer length extends the shorter one, so asking
        # again from the start is the same stream.
        length *= 2


def _kem_cbd(data, eta):
    """FIPS 203 algorithm 8."""
    bits = _kem_bits(data)
    assert len(bits) == 512 * eta
    out = []
    for i in range(256):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        out.append((x - y) % _KEM_Q)
    return out


def _kem_prf(eta, seed, counter):
    return hashlib.shake_256(seed + bytes([counter])).digest(64 * eta)


def _kem_matrix(rho, k):
    """`A_hat[i][j] = SampleNTT(rho || j || i)`."""
    return [[_kem_sample_ntt(rho + bytes([j, i])) for j in range(k)]
            for i in range(k)]


def _kem_pke_keygen(name, d):
    k, eta1, _eta2, _du, _dv = _KEM_SETS[name]
    expanded = hashlib.sha3_512(d + bytes([k])).digest()
    rho, sigma = expanded[:32], expanded[32:]
    a_hat = _kem_matrix(rho, k)
    s = [_kem_cbd(_kem_prf(eta1, sigma, n), eta1) for n in range(k)]
    e = [_kem_cbd(_kem_prf(eta1, sigma, k + n), eta1) for n in range(k)]
    s_hat = [_kem_ntt(p) for p in s]
    e_hat = [_kem_ntt(p) for p in e]
    t_hat = []
    for i in range(k):
        total = e_hat[i]
        for j in range(k):
            total = _kem_add(total, _kem_multiply(a_hat[i][j], s_hat[j]))
        t_hat.append(total)
    ek = b"".join(_kem_encode(p, 12) for p in t_hat) + rho
    dk = b"".join(_kem_encode(p, 12) for p in s_hat)
    return ek, dk


def _kem_pke_encrypt(name, ek, m, r):
    k, eta1, eta2, du, dv = _KEM_SETS[name]
    t_hat = [_kem_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k:]
    a_hat = _kem_matrix(rho, k)
    y = [_kem_cbd(_kem_prf(eta1, r, n), eta1) for n in range(k)]
    e1 = [_kem_cbd(_kem_prf(eta2, r, k + n), eta2) for n in range(k)]
    e2 = _kem_cbd(_kem_prf(eta2, r, 2 * k), eta2)
    y_hat = [_kem_ntt(p) for p in y]
    u = []
    for i in range(k):
        total = [0] * 256
        for j in range(k):
            # The transpose: row i of A^T is column i of A.
            total = _kem_add(total, _kem_multiply(a_hat[j][i], y_hat[j]))
        u.append(_kem_add(_kem_intt(total), e1[i]))
    mu = _kem_decompress(_kem_decode(m, 1), 1)
    inner = [0] * 256
    for j in range(k):
        inner = _kem_add(inner, _kem_multiply(t_hat[j], y_hat[j]))
    v = _kem_add(_kem_add(_kem_intt(inner), e2), mu)
    c1 = b"".join(_kem_encode(_kem_compress(p, du), du) for p in u)
    c2 = _kem_encode(_kem_compress(v, dv), dv)
    return c1 + c2


def _kem_pke_decrypt(name, dk_pke, c):
    k, _eta1, _eta2, du, dv = _KEM_SETS[name]
    width = 32 * du
    u = [_kem_decompress(_kem_decode(c[width * i:width * (i + 1)], du), du)
         for i in range(k)]
    v = _kem_decompress(_kem_decode(c[width * k:], dv), dv)
    s_hat = [_kem_decode(dk_pke[384 * i:384 * (i + 1)], 12) for i in range(k)]
    inner = [0] * 256
    for j in range(k):
        inner = _kem_add(inner, _kem_multiply(s_hat[j], _kem_ntt(u[j])))
    w = _kem_sub(v, _kem_intt(inner))
    return _kem_encode(_kem_compress(w, 1), 1)


def ml_kem_keygen(name, d, z):
    ek, dk_pke = _kem_pke_keygen(name, d)
    return ek, dk_pke + ek + hashlib.sha3_256(ek).digest() + z


def ml_kem_encaps(name, ek, m):
    """`(K, c)`, FIPS 203 algorithm 17."""
    expanded = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
    shared, r = expanded[:32], expanded[32:]
    return shared, _kem_pke_encrypt(name, ek, m, r)


def ml_kem_decaps(name, dk, c):
    """FIPS 203 algorithm 18, with the comparison as plain `==`.

    Timing does not matter in a reference; what matters is that the
    choice between `K'` and `J(z || c)` is FIPS 203's.
    """
    k = _KEM_SETS[name][0]
    dk_pke = dk[:384 * k]
    ek = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:]
    m = _kem_pke_decrypt(name, dk_pke, c)
    expanded = hashlib.sha3_512(m + h).digest()
    shared, r = expanded[:32], expanded[32:]
    rejection = hashlib.shake_256(z + c).digest(32)
    return shared if _kem_pke_encrypt(name, ek, m, r) == c else rejection


def ml_kem_modulus_check(name, ek):
    k = _KEM_SETS[name][0]
    if len(ek) != 384 * k + 32:
        return False
    return all(_kem_encode(_kem_decode(ek[384 * i:384 * (i + 1)], 12), 12)
               == ek[384 * i:384 * (i + 1)] for i in range(k))


def ml_kem_hash_check(name, dk):
    k = _KEM_SETS[name][0]
    if len(dk) != 768 * k + 96:
        return False
    return (hashlib.sha3_256(dk[384 * k:768 * k + 32]).digest()
            == dk[768 * k + 32:768 * k + 64])


def _ml_kem_selftest():
    """This file's ML-KEM against NIST's vectors, before it is trusted.

    A reference that disagreed with the standard would make every
    mismatch below ambiguous, and every match worthless. So all 195 of
    the vendored ACVP cases run first - key generation, encapsulation,
    decapsulation on both FO paths, and both key checks on keys NIST says
    to refuse - and the corpus is only read if they pass. The parse
    asserts each section's declared count, as the Rust reader does.
    """
    path = ROOT / "vectors" / "ml_kem.vec"
    sections = []
    case = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            mode, name, count = line[1:-1].split()
            sections.append((mode, name, int(count), []))
            case = None
            continue
        key, _, value = line.partition(" =")
        if key == "tcId":
            case = {}
            sections[-1][3].append(case)
        case[key] = value.strip()

    def digest(data):
        return hashlib.sha256(data).hexdigest().upper()

    checked = 0
    rejected = 0
    for mode, name, count, cases in sections:
        if len(cases) != count:
            raise Mismatch(f"ml_kem.vec: [{mode} {name}] declares {count} "
                           f"cases and holds {len(cases)}")
        for c in cases:
            where = f"ML-KEM self-test, {mode} {name} tcId {c['tcId']}"
            if mode == "keyGen":
                ek, dk = ml_kem_keygen(name, unhex(c["d"]), unhex(c["z"]))
                ok = (digest(ek) == c["ekDigest"]
                      and digest(dk) == c["dkDigest"])
            elif mode == "encapsulation":
                shared, ct = ml_kem_encaps(name, unhex(c["ek"]),
                                           unhex(c["m"]))
                ok = shared == unhex(c["k"]) and digest(ct) == c["cDigest"]
            elif mode == "decapsulation":
                dk, ct = unhex(c["dk"]), unhex(c["c"])
                shared = ml_kem_decaps(name, dk, ct)
                ok = shared == unhex(c["k"])
                rejected += shared == hashlib.shake_256(dk[-32:] + ct).digest(32)
            elif mode == "encapsulationKeyCheck":
                ok = (ml_kem_modulus_check(name, unhex(c["ek"]))
                      == (c["testPassed"] == "true"))
            elif mode == "decapsulationKeyCheck":
                ok = (ml_kem_hash_check(name, unhex(c["dk"]))
                      == (c["testPassed"] == "true"))
            else:
                raise Mismatch(f"ml_kem.vec: unknown section {mode!r}")
            if not ok:
                raise Mismatch(f"{where}: this script's ML-KEM disagrees "
                               f"with NIST, so it cannot referee ours")
            checked += 1
    if checked != 195 or rejected != 15:
        raise Mismatch(f"ML-KEM self-test: {checked} cases and {rejected} "
                       f"implicit rejections, expected 195 and 15")
    return checked


def check_ml_kem(lines):
    """ML-KEM against the second implementation above.

    Every `kem` row is three checks - key generation, encapsulation, and
    decapsulation of the honest ciphertext - and every `rej` row is the
    implicit-rejection path, recomputed here, `J(z || c)` included.
    """
    nist = _ml_kem_selftest()
    print(f"  (reference first matched all {nist} of NIST's ML-KEM vectors)")

    checked = 0
    kinds = {}
    verdicts = {"ekchk": set(), "dkchk": set()}
    for line in lines:
        parts = line.split()
        op, name = parts[0], parts[1]
        kinds[op] = kinds.get(op, 0) + 1
        if name not in _KEM_SETS:
            raise Mismatch(f"ml_kem: unknown parameter set {name!r}")

        if op == "kem":
            d, z, m, ek, dk, shared, ct, shared_dec = map(unhex, parts[2:10])
            want_ek, want_dk = ml_kem_keygen(name, d, z)
            if (ek, dk) != (want_ek, want_dk):
                raise Mismatch(f"ml_kem keygen {name} d={parts[2]}: keys "
                               f"differ (ek {ek == want_ek}, dk "
                               f"{dk == want_dk})")
            want_shared, want_ct = ml_kem_encaps(name, ek, m)
            if (shared, ct) != (want_shared, want_ct):
                raise Mismatch(f"ml_kem encaps {name} m={parts[4]}: shared "
                               f"{shared == want_shared}, ciphertext "
                               f"{ct == want_ct}")
            if shared_dec != ml_kem_decaps(name, dk, ct) or shared_dec != shared:
                raise Mismatch(f"ml_kem decaps {name} m={parts[4]}: the "
                               f"honest ciphertext did not give the "
                               f"encapsulated secret")

        elif op == "rej":
            dk, ct, shared = map(unhex, parts[2:5])
            want = ml_kem_decaps(name, dk, ct)
            if shared != want:
                raise Mismatch(f"ml_kem rej {name}:\n  ours: {parts[4]}\n"
                               f"  ref : {want.hex()}")
            if want != hashlib.shake_256(dk[-32:] + ct).digest(32):
                raise Mismatch(f"ml_kem rej {name}: an altered ciphertext "
                               f"was accepted by the reference - the "
                               f"corpus row is not testing rejection")

        elif op in ("ekchk", "dkchk"):
            key, claimed = unhex(parts[2]), parts[3]
            check = ml_kem_modulus_check if op == "ekchk" else ml_kem_hash_check
            want = "true" if check(name, key) else "false"
            if claimed != want:
                raise Mismatch(f"ml_kem {op} {name}: ours says {claimed}, "
                               f"the reference says {want}")
            verdicts[op].add(want)

        else:
            raise Mismatch(f"corpus row {op!r} has no checker.")
        checked += 1

    if set(kinds) != {"kem", "rej", "ekchk", "dkchk"}:
        raise Mismatch(f"only {sorted(kinds)} in the ML-KEM corpus")
    for op, seen in verdicts.items():
        # Both verdicts must occur, or a check hard-wired to one answer
        # would agree with the reference on every row.
        if seen != {"true", "false"}:
            raise Mismatch(f"ml_kem {op}: only {sorted(seen)} verdicts in "
                           f"the corpus")
    print(f"  ({kinds['kem']} key pairs and encapsulations, {kinds['rej']} "
          f"implicit rejections, {kinds['ekchk'] + kinds['dkchk']} key "
          f"checks)")
    return checked


# ---------------------------------------------------------------- ML-DSA ---
#
# A second ML-DSA, written here from FIPS 204 rather than from
# `src/pq/ml_dsa/`.
#
# **Its arithmetic takes a different road.** The Rust code multiplies in
# the NTT domain, as the standard's algorithms do. This one multiplies in
# the ring itself, by Kronecker substitution: a polynomial with
# coefficients below 2^23 is packed into one Python integer, 64 bits per
# coefficient, two such integers are multiplied by Python's own bignum
# multiplication, and the product's coefficients are read back out and
# folded with `X^256 = -1`. No twiddle, no butterfly, no bit reversal.
#
# The one place the NTT cannot be avoided is `A`: FIPS 204 samples it
# directly in the transformed domain. It is brought out by interpolation
# rather than by an inverse butterfly network - the transformed
# coefficients are the values of `a` at the 256 roots `gamma_i` of
# `X^256 + 1`, so `a_j = 256^-1 * sum_i a_hat_i * gamma_i^-j` - and cached
# per `rho`.
#
# Hashes are hashlib's; pre-hash OIDs come from OpenSSL's object table
# (`ssl._txt2obj`) and are encoded by `_encode_oid` above. The rest -
# samplers, rounding, encodings, the rejection loop - is written from the
# algorithm listings, so it is a second *reading* rather than a second
# opinion, and `_ml_dsa_selftest` runs NIST's vectors through it before
# it is trusted.

_DSA_Q = 8380417
_DSA_D = 13

#: name -> (k, l, eta, tau, lambda, gamma1, gamma2, omega), FIPS 204 table 1.
_DSA_SETS = {
    "ML-DSA-44": (4, 4, 2, 39, 128, 1 << 17, (_DSA_Q - 1) // 88, 80),
    "ML-DSA-65": (6, 5, 4, 49, 192, 1 << 19, (_DSA_Q - 1) // 32, 55),
    "ML-DSA-87": (8, 7, 2, 60, 256, 1 << 19, (_DSA_Q - 1) // 32, 75),
}

def _dsa_mul(a, b):
    """`a * b` in `Z_q[X]/(X^256 + 1)` by Kronecker substitution."""
    pack = lambda f: int.from_bytes(b"".join(c.to_bytes(8, "little")
                                             for c in f), "little")
    raw = (pack(a) * pack(b)).to_bytes(8 * 512, "little")
    wide = [int.from_bytes(raw[8 * i:8 * i + 8], "little") for i in range(512)]
    return [(wide[i] - wide[i + 256]) % _DSA_Q for i in range(256)]


def _dsa_add(a, b):
    return [(x + y) % _DSA_Q for x, y in zip(a, b)]


def _dsa_sub(a, b):
    return [(x - y) % _DSA_Q for x, y in zip(a, b)]


@functools.lru_cache(maxsize=None)
def _dsa_inverse_powers():
    """`gamma_i^-j` for all `i, j < 256`, with
    `gamma_i = 1753^(2*BitRev8(i) + 1)`."""
    q = _DSA_Q
    rows = []
    for i in range(256):
        rev = int(f"{i:08b}"[::-1], 2)
        inverse = pow(pow(1753, 2 * rev + 1, q), -1, q)
        row = [1] * 256
        for j in range(1, 256):
            row[j] = row[j - 1] * inverse % q
        rows.append(row)
    # Transposed, so a coefficient is one dot product.
    return [list(column) for column in zip(*rows)]


def _dsa_interpolate(values):
    """The polynomial whose values at the 256 `gamma_i` are `values`."""
    scale = pow(256, -1, _DSA_Q)
    return [scale * sum(map(operator.mul, values, column)) % _DSA_Q
            for column in _dsa_inverse_powers()]


class _Shake:
    """A SHAKE stream read incrementally; hashlib's output for a longer
    length extends the shorter one."""

    def __init__(self, which, data):
        self.which, self.data, self.buffer, self.at = which, data, b"", 0

    def take(self, n):
        while self.at + n > len(self.buffer):
            self.buffer = self.which(self.data).digest(
                max(2 * len(self.buffer), 1024))
        out = self.buffer[self.at:self.at + n]
        self.at += n
        return out


def _dsa_rej_ntt(seed):
    stream = _Shake(hashlib.shake_128, seed)
    out = []
    while len(out) < 256:
        b0, b1, b2 = stream.take(3)
        value = ((b2 & 127) << 16) | (b1 << 8) | b0
        if value < _DSA_Q:
            out.append(value)
    return out


def _dsa_half_byte(b, eta):
    if eta == 2 and b < 15:
        return (2 - b % 5) % _DSA_Q
    if eta == 4 and b < 9:
        return (4 - b) % _DSA_Q
    return None


def _dsa_rej_bounded(seed, eta):
    stream = _Shake(hashlib.shake_256, seed)
    out = []
    while len(out) < 256:
        (byte,) = stream.take(1)
        for nibble in (byte & 15, byte >> 4):
            value = _dsa_half_byte(nibble, eta)
            if value is not None and len(out) < 256:
                out.append(value)
    return out


def _dsa_sample_in_ball(seed, tau):
    stream = _Shake(hashlib.shake_256, seed)
    signs = int.from_bytes(stream.take(8), "little")
    c = [0] * 256
    for count, i in enumerate(range(256 - tau, 256)):
        (j,) = stream.take(1)
        while j > i:
            (j,) = stream.take(1)
        c[i] = c[j]
        c[j] = _DSA_Q - 1 if (signs >> count) & 1 else 1
    return c


@functools.lru_cache(maxsize=16)
def _dsa_matrix(rho, k, l):
    """`A` in the ring - `ExpandA`'s output, interpolated back."""
    return tuple(tuple(tuple(_dsa_interpolate(_dsa_rej_ntt(rho + bytes([s, r]))))
                       for s in range(l)) for r in range(k))


def _dsa_bits(value, width):
    return [(value >> i) & 1 for i in range(width)]


def _dsa_pack(values, width):
    bits = []
    for value in values:
        bits.extend(_dsa_bits(value, width))
    return bytes(sum(bits[8 * n + i] << i for i in range(8))
                 for n in range(len(bits) // 8))


def _dsa_unpack(data, width, count=256):
    bits = [(byte >> i) & 1 for byte in data for i in range(8)]
    return [sum(bits[width * n + i] << i for i in range(width))
            for n in range(count)]


def _dsa_signed(value):
    return value - _DSA_Q if value > _DSA_Q // 2 else value


def _dsa_bit_pack(f, a, b):
    return _dsa_pack([b - _dsa_signed(x) for x in f], (a + b).bit_length())


def _dsa_bit_unpack(data, a, b):
    return [(b - z) % _DSA_Q for z in _dsa_unpack(data, (a + b).bit_length())]


def _dsa_mod_pm(r, a):
    r %= a
    return r - a if r > a // 2 else r


def _dsa_power2round(r):
    r0 = _dsa_mod_pm(r, 1 << _DSA_D)
    return (r - r0) >> _DSA_D, r0


def _dsa_decompose(r, gamma2):
    r0 = _dsa_mod_pm(r, 2 * gamma2)
    if r - r0 == _DSA_Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * gamma2), r0


def _dsa_use_hint(h, r, gamma2):
    m = (_DSA_Q - 1) // (2 * gamma2)
    r1, r0 = _dsa_decompose(r, gamma2)
    if h and r0 > 0:
        return (r1 + 1) % m
    if h:
        return (r1 - 1) % m
    return r1


def _dsa_norm(polys):
    return max(abs(_dsa_signed(x)) for f in polys for x in f)


def _dsa_w1_encode(w1, gamma2):
    width = ((_DSA_Q - 1) // (2 * gamma2) - 1).bit_length()
    return b"".join(_dsa_pack(f, width) for f in w1)


def _dsa_hint_pack(h, omega):
    positions, counts = [], []
    for f in h:
        positions.extend(j for j, bit in enumerate(f) if bit)
        counts.append(len(positions))
    return bytes(positions + [0] * (omega - len(positions)) + counts)


def _dsa_hint_unpack(data, omega, k):
    h, index = [], 0
    for i in range(k):
        end = data[omega + i]
        if end < index or end > omega:
            return None
        f = [0] * 256
        first = index
        while index < end:
            if index > first and data[index - 1] >= data[index]:
                return None
            f[data[index]] = 1
            index += 1
        h.append(f)
    if any(data[index:omega]):
        return None
    return h


def _dsa_h(data, n):
    return hashlib.shake_256(data).digest(n)


def ml_dsa_keygen(name, xi):
    k, l, eta, _tau, _lam, _g1, _g2, _omega = _DSA_SETS[name]
    expanded = _dsa_h(xi + bytes([k, l]), 128)
    rho, rho_prime, key = expanded[:32], expanded[32:96], expanded[96:]
    a = _dsa_matrix(rho, k, l)
    s1 = [_dsa_rej_bounded(rho_prime + r.to_bytes(2, "little"), eta)
          for r in range(l)]
    s2 = [_dsa_rej_bounded(rho_prime + (l + r).to_bytes(2, "little"), eta)
          for r in range(k)]
    t1, t0 = [], []
    for r in range(k):
        t = s2[r]
        for s in range(l):
            t = _dsa_add(t, _dsa_mul(a[r][s], s1[s]))
        pairs = [_dsa_power2round(x) for x in t]
        t1.append([p[0] for p in pairs])
        t0.append([p[1] % _DSA_Q for p in pairs])
    pk = rho + b"".join(_dsa_pack(f, 10) for f in t1)
    tr = _dsa_h(pk, 64)
    half = 1 << (_DSA_D - 1)
    sk = (rho + key + tr
          + b"".join(_dsa_bit_pack(f, eta, eta) for f in s1 + s2)
          + b"".join(_dsa_bit_pack(f, half - 1, half) for f in t0))
    return pk, sk


def _dsa_decode_sk(name, sk):
    k, l, eta = _DSA_SETS[name][:3]
    width = 32 * (2 * eta).bit_length()
    at = 128
    polys = []
    for _ in range(l + k):
        polys.append(_dsa_bit_unpack(sk[at:at + width], eta, eta))
        at += width
    half = 1 << (_DSA_D - 1)
    t0 = []
    for _ in range(k):
        t0.append(_dsa_bit_unpack(sk[at:at + 32 * _DSA_D], half - 1, half))
        at += 32 * _DSA_D
    return sk[:32], sk[32:64], sk[64:128], polys[:l], polys[l:], t0


def ml_dsa_sign_mu(name, sk, mu, rnd):
    k, l, eta, tau, lam, gamma1, gamma2, omega = _DSA_SETS[name]
    beta = tau * eta
    rho, key, _tr, s1, s2, t0 = _dsa_decode_sk(name, sk)
    a = _dsa_matrix(rho, k, l)
    rho2 = _dsa_h(key + rnd + mu, 64)
    width = 1 + (gamma1 - 1).bit_length()
    kappa = 0
    while True:
        y = [_dsa_bit_unpack(_dsa_h(rho2 + (kappa + r).to_bytes(2, "little"),
                                    32 * width), gamma1 - 1, gamma1)
             for r in range(l)]
        kappa += l
        w = []
        for r in range(k):
            acc = [0] * 256
            for s in range(l):
                acc = _dsa_add(acc, _dsa_mul(a[r][s], y[s]))
            w.append(acc)
        w1 = [[_dsa_decompose(x, gamma2)[0] for x in f] for f in w]
        c_tilde = _dsa_h(mu + _dsa_w1_encode(w1, gamma2), lam // 4)
        c = _dsa_sample_in_ball(c_tilde, tau)
        z = [_dsa_add(y[s], _dsa_mul(c, s1[s])) for s in range(l)]
        w_minus = [_dsa_sub(w[r], _dsa_mul(c, s2[r])) for r in range(k)]
        if _dsa_norm(z) >= gamma1 - beta:
            continue
        r0 = max(abs(_dsa_decompose(x, gamma2)[1]) for f in w_minus for x in f)
        if r0 >= gamma2 - beta:
            continue
        ct0 = [_dsa_mul(c, t0[r]) for r in range(k)]
        if _dsa_norm(ct0) >= gamma2:
            continue
        h = []
        for r in range(k):
            row = []
            for j in range(256):
                before = (w_minus[r][j] + ct0[r][j]) % _DSA_Q
                after = w_minus[r][j]
                row.append(int(_dsa_decompose(before, gamma2)[0]
                               != _dsa_decompose(after, gamma2)[0]))
            h.append(row)
        if sum(map(sum, h)) > omega:
            continue
        return (c_tilde + b"".join(_dsa_bit_pack(f, gamma1 - 1, gamma1)
                                   for f in z)
                + _dsa_hint_pack(h, omega))


def ml_dsa_verify_mu(name, pk, mu, signature):
    k, l, eta, tau, lam, gamma1, gamma2, omega = _DSA_SETS[name]
    beta = tau * eta
    width = 32 * (1 + (gamma1 - 1).bit_length())
    if len(signature) != lam // 4 + l * width + omega + k:
        return False
    rho = pk[:32]
    t1 = [_dsa_unpack(pk[32 + 320 * r:32 + 320 * (r + 1)], 10)
          for r in range(k)]
    c_tilde = signature[:lam // 4]
    z = [_dsa_bit_unpack(signature[lam // 4 + width * s:lam // 4 + width * (s + 1)],
                         gamma1 - 1, gamma1) for s in range(l)]
    h = _dsa_hint_unpack(signature[lam // 4 + width * l:], omega, k)
    if h is None or _dsa_norm(z) >= gamma1 - beta:
        return False
    a = _dsa_matrix(rho, k, l)
    c = _dsa_sample_in_ball(c_tilde, tau)
    w1 = []
    for r in range(k):
        acc = [0] * 256
        for s in range(l):
            acc = _dsa_add(acc, _dsa_mul(a[r][s], z[s]))
        approx = _dsa_sub(acc, _dsa_mul(c, [(x << _DSA_D) % _DSA_Q
                                            for x in t1[r]]))
        w1.append([_dsa_use_hint(h[r][j], approx[j], gamma2)
                   for j in range(256)])
    return _dsa_h(mu + _dsa_w1_encode(w1, gamma2), lam // 4) == c_tilde


#: ACVP's pre-hash name -> (hashlib constructor, output length, OpenSSL's
#: name for the OID). The OID itself comes from OpenSSL's table.
_DSA_PREHASH = {
    "SHA2-224": ("sha224", None, "SHA224"),
    "SHA2-256": ("sha256", None, "SHA256"),
    "SHA2-384": ("sha384", None, "SHA384"),
    "SHA2-512": ("sha512", None, "SHA512"),
    "SHA2-512/224": ("sha512_224", None, "SHA512-224"),
    "SHA2-512/256": ("sha512_256", None, "SHA512-256"),
    "SHA3-224": ("sha3_224", None, "SHA3-224"),
    "SHA3-256": ("sha3_256", None, "SHA3-256"),
    "SHA3-384": ("sha3_384", None, "SHA3-384"),
    "SHA3-512": ("sha3_512", None, "SHA3-512"),
    "SHAKE-128": ("shake_128", 32, "SHAKE128"),
    "SHAKE-256": ("shake_256", 64, "SHAKE256"),
}


def _dsa_wrap(message, context, prehash):
    """`M'` for the external interface."""
    import ssl
    if prehash is None:
        return bytes([0, len(context)]) + context + message
    constructor, length, openssl_name = _DSA_PREHASH[prehash]
    digest = hashlib.new(constructor, message)
    digest = digest.digest(length) if length else digest.digest()
    contents = _encode_oid(ssl._txt2obj(openssl_name, name=True)[3])
    oid = bytes([0x06, len(contents)]) + contents
    return bytes([1, len(context)]) + context + oid + digest


def _dsa_mu(pk, message_prime):
    return _dsa_h(_dsa_h(pk, 64) + message_prime, 64)


def _dsa_read(name):
    """`[(mode, parameter_set, [case])]` from a vendored ML-DSA file, each
    section's declared count asserted."""
    sections = []
    for line in (ROOT / "vectors" / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            mode, parameter_set, count = line[1:-1].split()
            sections.append((mode, parameter_set, int(count), []))
            continue
        key, _, value = line.partition(" =")
        if key == "tcId":
            sections[-1][3].append({})
        sections[-1][3][-1][key] = value.strip()
    for mode, parameter_set, count, cases in sections:
        if len(cases) != count:
            raise Mismatch(f"{name}: [{mode} {parameter_set}] declares "
                           f"{count} cases and holds {len(cases)}")
    return sections


def _ml_dsa_selftest():
    """This file's ML-DSA against every vendored NIST case, before it is
    trusted: 75 key generations, 72 signatures, 60 verifications."""
    def digest(data):
        return hashlib.sha256(data).hexdigest().upper()

    checked = 0
    for mode, name, _count, cases in _dsa_read("ml_dsa.vec"):
        for c in cases:
            where = f"ML-DSA self-test, {mode} {name} tcId {c['tcId']}"
            if mode == "keyGen":
                pk, sk = ml_dsa_keygen(name, unhex(c["seed"]))
                ok = digest(pk) == c["pkDigest"] and digest(sk) == c["skDigest"]
            else:
                sk = unhex(c["sk"])
                rnd = unhex(c["rnd"]) if "rnd" in c else bytes(32)
                if "mu" in c:
                    mu = unhex(c["mu"])
                else:
                    message = unhex(c["message"])
                    if "-external-" in mode:
                        message = _dsa_wrap(message, unhex(c["context"]),
                                            c.get("hashAlg"))
                    mu = _dsa_h(sk[64:128] + message, 64)
                signature = ml_dsa_sign_mu(name, sk, mu, rnd)
                ok = digest(signature) == c["signatureDigest"]
            if not ok:
                raise Mismatch(f"{where}: this script's ML-DSA disagrees "
                               f"with NIST, so it cannot referee ours")
            checked += 1
    for mode, name, _count, cases in _dsa_read("ml_dsa_sigver.vec"):
        for c in cases:
            pk = unhex(c["pk"])
            if "mu" in c:
                mu = unhex(c["mu"])
            else:
                message = unhex(c["message"])
                if "-external-" in mode:
                    message = _dsa_wrap(message, unhex(c["context"]),
                                        c.get("hashAlg"))
                mu = _dsa_mu(pk, message)
            got = ml_dsa_verify_mu(name, pk, mu, unhex(c["signature"]))
            if got != (c["testPassed"] == "true"):
                raise Mismatch(f"ML-DSA self-test, {mode} {name} tcId "
                               f"{c['tcId']} ({c['reason']}): this script's "
                               f"verifier disagrees with NIST")
            checked += 1
    if checked != 207:
        raise Mismatch(f"ML-DSA self-test ran {checked} cases, not 207")
    return checked


def check_ml_dsa(lines):
    """ML-DSA against the second implementation above.

    `key` rows are key generation from a seed; `sig` rows a deterministic
    or hedged signature, recomputed here from the same `mu` and `rnd`;
    `ver` rows a verdict on a signature that is honest, altered, or made
    for a different message - recomputed here.
    """
    nist = _ml_dsa_selftest()
    print(f"  (reference first matched all {nist} of NIST's ML-DSA vectors)")

    checked = 0
    kinds = {}
    verdicts = set()
    for line in lines:
        parts = line.split()
        op, name = parts[0], parts[1]
        if name not in _DSA_SETS:
            raise Mismatch(f"ml_dsa: unknown parameter set {name!r}")
        kinds[op] = kinds.get(op, 0) + 1
        if op == "key":
            seed, pk, sk = map(unhex, parts[2:5])
            if (pk, sk) != ml_dsa_keygen(name, seed):
                raise Mismatch(f"ml_dsa keygen {name} seed={parts[2]}")
        elif op == "sig":
            sk, mu, rnd, signature = map(unhex, parts[2:6])
            if signature != ml_dsa_sign_mu(name, sk, mu, rnd):
                raise Mismatch(f"ml_dsa sign {name} mu={parts[3][:16]}...")
        elif op == "ver":
            pk, mu, signature = map(unhex, parts[2:5])
            claimed = parts[5]
            want = "true" if ml_dsa_verify_mu(name, pk, mu, signature) \
                else "false"
            if claimed != want:
                raise Mismatch(f"ml_dsa verify {name}: ours {claimed}, "
                               f"reference {want}")
            verdicts.add(want)
        else:
            raise Mismatch(f"corpus row {op!r} has no checker.")
        checked += 1
    if set(kinds) != {"key", "sig", "ver"} or verdicts != {"true", "false"}:
        raise Mismatch(f"ML-DSA corpus has {sorted(kinds)} rows and "
                       f"{sorted(verdicts)} verdicts")
    print(f"  ({kinds['key']} key pairs, {kinds['sig']} signatures, "
          f"{kinds['ver']} verifications)")
    return checked


# BitLocker's sector encryption. AES is OpenSSL's, through
# python-cryptography: ECB for the IV and Elephant's sector key, CBC, XTS.
# The diffusers are written as Linux's dm-crypt writes them - four
# statements per loop turn, three running indices, each wrapped only where
# it can wrap - which is a different shape from the library's modular
# indexing.

def _bl_rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xffffffff if r else x


def _bl_diffuser_a_encrypt(d):
    n = len(d)
    for _ in range(5):
        i1, i2, i3 = n - 1, n - 3, n - 6
        while i1 > 0:
            d[i1] = (d[i1] - (d[i2] ^ d[i3])) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1
            d[i1] = (d[i1] - (d[i2] ^ _bl_rotl(d[i3], 13))) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1
            if i2 < 0:
                i2 += n
            d[i1] = (d[i1] - (d[i2] ^ d[i3])) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1
            if i3 < 0:
                i3 += n
            d[i1] = (d[i1] - (d[i2] ^ _bl_rotl(d[i3], 9))) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1


def _bl_diffuser_b_encrypt(d):
    n = len(d)
    for _ in range(3):
        i1, i2, i3 = n - 1, 1, 4
        while i1 > 0:
            d[i1] = (d[i1] - (d[i2] ^ _bl_rotl(d[i3], 25))) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1
            if i3 < 0:
                i3 += n
            d[i1] = (d[i1] - (d[i2] ^ d[i3])) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1
            if i2 < 0:
                i2 += n
            d[i1] = (d[i1] - (d[i2] ^ _bl_rotl(d[i3], 10))) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1
            d[i1] = (d[i1] - (d[i2] ^ d[i3])) & 0xffffffff
            i1 -= 1; i2 -= 1; i3 -= 1


def _bl_encrypt(method, key, offset, sector):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def ecb(k, block):
        return Cipher(algorithms.AES(k), modes.ECB()).encryptor().update(block)

    if method.startswith("aes-xts"):
        tweak = (offset // len(sector)).to_bytes(16, "little")
        enc = Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor()
        return enc.update(sector) + enc.finalize()
    elephant = "elephant" in method
    cbc_key = key[:len(key) // 2] if elephant else key
    if elephant:
        tweak_key = key[len(key) // 2:]
        block = offset.to_bytes(8, "little") + bytes(8)
        sector_key = ecb(tweak_key, block) + ecb(tweak_key, block[:15] + b"\x80")
        sector = bytes(b ^ sector_key[i % 32] for i, b in enumerate(sector))
        d = [int.from_bytes(sector[i:i + 4], "little") for i in range(0, len(sector), 4)]
        _bl_diffuser_a_encrypt(d)
        _bl_diffuser_b_encrypt(d)
        sector = b"".join(w.to_bytes(4, "little") for w in d)
    iv = ecb(cbc_key, offset.to_bytes(8, "little") + bytes(8))
    enc = Cipher(algorithms.AES(cbc_key), modes.CBC(iv)).encryptor()
    return enc.update(sector) + enc.finalize()


def check_wifi(lines):
    """Michael and TKIP written out from IEEE 802.11 and the Linux
    kernel, and WEP's RC4 + CRC-32 ICV with python's zlib."""
    import zlib

    def michael(key, data):
        l = int.from_bytes(key[:4], "little")
        r = int.from_bytes(key[4:], "little")
        padded = data + b"\x5a" + b"\x00" * 4
        padded += b"\x00" * (-len(padded) % 4)

        def blk(l, r):
            m = 0xffffffff
            r ^= ((l << 17) | (l >> 15)) & m
            l = (l + r) & m
            r ^= ((l & 0xff00ff00) >> 8) | ((l & 0x00ff00ff) << 8)
            l = (l + r) & m
            r ^= ((l << 3) | (l >> 29)) & m
            l = (l + r) & m
            r ^= ((l >> 2) | (l << 30)) & m
            l = (l + r) & m
            return l, r
        for i in range(0, len(padded), 4):
            l ^= int.from_bytes(padded[i:i + 4], "little")
            l, r = blk(l, r)
        return l.to_bytes(4, "little") + r.to_bytes(4, "little")

    # TKIP, from Linux net/mac80211/tkip.c, with its S-box table.
    sbox = _tkip_sbox()

    def s(v):
        hi = sbox[v >> 8]
        return sbox[v & 0xff] ^ (((hi & 0xff) << 8) | (hi >> 8))

    def tkip_key(tk, ta, tsc):
        def le16(b, i):
            return b[i] | (b[i + 1] << 8)

        def ror1(v):
            return ((v >> 1) | (v << 15)) & 0xffff
        iv32, iv16 = tsc >> 16, tsc & 0xffff
        p = [iv32 & 0xffff, iv32 >> 16, le16(ta, 0), le16(ta, 2), le16(ta, 4)]
        for i in range(8):
            j = 2 * (i & 1)
            p[0] = (p[0] + s(p[4] ^ le16(tk, j))) & 0xffff
            p[1] = (p[1] + s(p[0] ^ le16(tk, 4 + j))) & 0xffff
            p[2] = (p[2] + s(p[1] ^ le16(tk, 8 + j))) & 0xffff
            p[3] = (p[3] + s(p[2] ^ le16(tk, 12 + j))) & 0xffff
            p[4] = (p[4] + s(p[3] ^ le16(tk, j)) + i) & 0xffff
        p = p + [(p[4] + iv16) & 0xffff]
        for i in range(6):
            p[i] = (p[i] + s(p[(i + 5) % 6] ^ le16(tk, 2 * i))) & 0xffff
        p[0] = (p[0] + ror1(p[5] ^ le16(tk, 12))) & 0xffff
        p[1] = (p[1] + ror1(p[0] ^ le16(tk, 14))) & 0xffff
        for i in range(2, 6):
            p[i] = (p[i] + ror1(p[i - 1])) & 0xffff
        out = bytes([iv16 >> 8, ((iv16 >> 8) | 0x20) & 0x7f, iv16 & 0xff,
                     ((p[5] ^ le16(tk, 0)) >> 1) & 0xff])
        return out + b"".join(w.to_bytes(2, "little") for w in p)

    def rc4(key, data):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xff
            s[i], s[j] = s[j], s[i]
        out = bytearray()
        i = j = 0
        for b in data:
            i = (i + 1) & 0xff
            j = (j + s[i]) & 0xff
            s[i], s[j] = s[j], s[i]
            out.append(b ^ s[(s[i] + s[j]) & 0xff])
        return bytes(out)

    tk = keypattern(16)
    ta = bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
    mkey = keypattern(8)
    checked = 0
    for line in lines:
        tag, got = line.split(" ", 1)
        kind, arg = tag.split("/")
        if kind == "michael":
            want = michael(mkey, corpus_data(int(arg))).hex()
        elif kind == "tkip":
            want = tkip_key(tk, ta, int(arg, 16)).hex()
        elif kind == "wep":
            n = int(arg)
            body = corpus_data(n) + (zlib.crc32(corpus_data(n)) & 0xffffffff).to_bytes(4, "little")
            want = rc4(bytes([1, 2, 3]) + keypattern(13), body).hex()
        else:
            raise Mismatch(f"corpus row {tag!r} has no checker")
        if got != want:
            raise Mismatch(f"{tag}: got {got[:32]}... want {want[:32]}...")
        checked += 1
    return checked


def _tkip_sbox():
    """The TKIP S-box built from the AES S-box, the way the Rust does."""
    def gf_mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi:
                a ^= 0x1b
            b >>= 1
        return p
    aes = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            inv = 1
            power = x
            e = 254
            while e:
                if e & 1:
                    inv = gf_mul(inv, power)
                power = gf_mul(power, power)
                e >>= 1
        aes[x] = inv ^ ((inv << 1 | inv >> 7) & 0xff) ^ ((inv << 2 | inv >> 6) & 0xff) \
            ^ ((inv << 3 | inv >> 5) & 0xff) ^ ((inv << 4 | inv >> 4) & 0xff) ^ 0x63
    return [((gf_mul(aes[i], 2) << 8) | gf_mul(aes[i], 3)) for i in range(256)]


def check_bitlocker(lines):
    keylen = {"aes-cbc-elephant-128": 32, "aes-cbc-elephant-256": 64, "aes-cbc-128": 16,
              "aes-cbc-256": 32, "aes-xts-128": 32, "aes-xts-256": 64}
    checked = 0
    methods = set()
    for line in lines:
        tag, got = line.split(" ", 1)
        parts = tag.split("/")
        if parts[0] != "bl" or parts[1] not in keylen:
            raise Mismatch(f"corpus row {tag!r} has no checker")
        method, size, offset, seed = parts[1], int(parts[2]), int(parts[3]), int(parts[4])
        sector = corpus_data(size + seed)[seed:]
        want = _bl_encrypt(method, keypattern(keylen[method]), offset, sector).hex()
        if got != want:
            raise Mismatch(f"{tag}: got {got[:32]}... want {want[:32]}...")
        methods.add((method, size))
        checked += 1
    if len(methods) != 12:
        raise Mismatch(f"the BitLocker corpus covers {sorted(methods)}, not every method at "
                       "both sector sizes")
    return checked


CORPORA = {
    "block": ("diff_dump", check_block),
    "hash": ("diff_hash_stream", check_hash_stream),
    "mackdf": ("diff_mac_kdf", check_mac_kdf),
    "bignum": ("diff_bignum", check_bignum),
    "ec": ("diff_ec", check_ec),
    "ecdsa": ("diff_ecdsa", check_ecdsa),
    "dh": ("diff_dh", check_dh),
    "elgamal": ("diff_elgamal", check_elgamal),
    "x25519": ("diff_x25519", check_x25519),
    "x448": ("diff_x448", check_x448),
    "rsa": ("diff_rsa", check_rsa),
    "x509": ("diff_x509", check_x509),
    "roots": ("diff_roots", check_roots),
    "gcm": ("diff_gcm", check_gcm),
    "ccm": ("diff_ccm", check_ccm),
    "ocb": ("diff_ocb", check_ocb),
    "chachapoly": ("diff_chachapoly", check_chachapoly),
    "tlsrecord": ("diff_tls_record", check_tls_record),
    "ssl3keys": ("diff_ssl3_keys", check_ssl3_keys),
    "tls13keys": ("diff_tls13_keys", check_tls13_keys),
    "tls13record": ("diff_tls13_record", check_tls13_record),
    "gost": ("diff_gost", check_gost),
    "cmac": ("diff_cmac", check_cmac),
    "poly1305": ("diff_poly1305", check_poly1305),
    "windows": ("diff_windows_hashes", check_windows_hashes),
    "bitlocker": ("diff_bitlocker", check_bitlocker),
    "wifi": ("diff_wifi", check_wifi),
    "acpkm": ("diff_acpkm", check_acpkm),
    "oids": ("diff_oids", check_oids),
    "gost3410": ("diff_gost3410", check_gost3410),
    "vko": ("diff_vko", check_vko),
    "tlstree": ("diff_tlstree", check_tlstree),
    "gostkex": ("diff_gost_kex", check_gost_kex),
    "ctromac": ("diff_ctr_omac", check_ctr_omac),
    "cntimit": ("diff_cnt_imit", check_cnt_imit),
    "mgm": ("diff_mgm", check_mgm),
    "exportkeys": ("diff_export_keys", check_export_keys),
    "tlsstream": ("diff_tls_record", check_tls_stream_records),
    "suites": ("diff_suites", check_suites),
    "nameconstraints": ("diff_name_constraints", check_name_constraints),
    "crl": ("diff_crl", check_crl),
    "ocsp": ("diff_ocsp", check_ocsp),
    "premaster": ("diff_tls_premaster", check_tls_premaster),
    "mlkem": ("diff_ml_kem", check_ml_kem),
    "mldsa": ("diff_ml_dsa", check_ml_dsa),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", metavar="CORPUS",
                        help=f"which to check, from {', '.join(CORPORA)} "
                             f"(default: all)")
    parser.add_argument("--dump", help="read one corpus from a file instead "
                                       "of regenerating it")
    args = parser.parse_args()

    wanted = args.corpora or list(CORPORA)
    unknown = [c for c in wanted if c not in CORPORA]
    if unknown:
        raise SystemExit(f"unknown corpus {unknown[0]!r}; "
                         f"choose from {', '.join(CORPORA)}")
    if args.dump and len(wanted) != 1:
        raise SystemExit("--dump needs exactly one corpus name")

    total = 0
    failed = []
    for key in wanted:
        example, checker = CORPORA[key]
        print(f"{key}: generating...", flush=True)
        if args.dump:
            lines = open(args.dump).read().splitlines()
        else:
            lines = run_example(example)
        try:
            n = checker(lines)
        except Mismatch as e:
            print(f"{key}: MISMATCH\n{e}")
            failed.append(key)
            continue
        except ImportError as e:
            print(f"{key}: skipped, {e}")
            continue
        total += n
        print(f"{key}: {n} cases checked, 0 mismatches")

    print(f"\n{total} cases checked against independent implementations")
    if failed:
        raise SystemExit(f"FAILED: {', '.join(failed)}")


if __name__ == "__main__":
    main()
