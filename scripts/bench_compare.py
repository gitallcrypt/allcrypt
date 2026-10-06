#!/usr/bin/env python3
"""
Set this library's speed beside OpenSSL's on the same machine.

Runs `tools/src/bin/bench_speed.rs` (release builds) and, for every row it
prints that OpenSSL also has, `openssl speed` over the same 16 KiB
buffers; the password KDFs go through `hashlib` and Argon2id through
python-cryptography, both of which are OpenSSL underneath. Rows OpenSSL
does not have are printed with our numbers alone.

One column per build of ours, as `docs/building.md` ("Building for
speed") describes them: `portable` (a plain `--release`), `x86-64-v3`
(`-C target-cpu=x86-64-v3`, AVX2), `ni` (the `aes-ni` and `sha-ni`
features, the opt-in hardware paths) and `v3+ni`, both together. Each
build has its own target directory under `target/bench/`, so the next
run only rebuilds what changed. On a processor without AVX2
the `x86-64-v3` builds are skipped - the binary would not start - and
off x86-64 there is only the portable one. The ratio is the best of our
columns against OpenSSL.

The AES, SHA-1 and SHA-256 rows get one more OpenSSL column, "no NI", with
the instructions they would use masked off through `OPENSSL_ia32cap`:
AES-NI and PCLMULQDQ for AES, which leaves OpenSSL's vector-permute AES,
and the SHA extensions for the hashes, which leaves its AVX2 code. That
is the fair comparison for the portable build, which has no hardware
path.

    python3 scripts/bench_compare.py            # everything, every build
    python3 scripts/bench_compare.py aes        # rows whose name contains "aes"
    python3 scripts/bench_compare.py --builds portable,ni aes

Development tool, not a test: the numbers depend on the machine and on what
else it is doing. Nothing here needs the network.
"""

import os
import platform
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LEGACY = ["-provider", "legacy", "-provider", "default"]

# Our row name -> (openssl -evp name, extra arguments).
BULK = {
    "hash/md4": ("md4", LEGACY), "hash/md5": ("md5", []), "hash/sha1": ("sha1", []),
    "hash/sha256": ("sha256", []), "hash/sha512": ("sha512", []),
    "hash/sha3_256": ("sha3-256", []), "hash/blake2b": ("blake2b512", []),
    "hash/blake2s": ("blake2s256", []), "hash/ripemd160": ("ripemd160", LEGACY),
    "hash/whirlpool": ("whirlpool", LEGACY), "hash/sm3": ("sm3", []),
    "cipher/aes-128-ecb": ("aes-128-ecb", []), "cipher/aes-128-ctr": ("aes-128-ctr", []),
    "cipher/aes-256-ctr": ("aes-256-ctr", []), "cipher/aes-128-cbc": ("aes-128-cbc", []),
    "cipher/aes-128-cbc-dec": ("aes-128-cbc", ["-decrypt"]),
    "cipher/aes-256-xts": ("aes-256-xts", []),
    "cipher/des-64-cbc": ("des-cbc", LEGACY), "cipher/3des-192-cbc": ("des-ede3-cbc", []),
    "cipher/blowfish-128-cbc": ("bf-cbc", LEGACY), "cipher/cast5-128-cbc": ("cast5-cbc", LEGACY),
    "cipher/idea-128-cbc": ("idea-cbc", LEGACY), "cipher/rc2-128-cbc": ("rc2-cbc", LEGACY),
    "cipher/seed-128-cbc": ("seed-cbc", LEGACY),
    "cipher/camellia-128-cbc": ("camellia-128-cbc", []),
    "cipher/aria-128-cbc": ("aria-128-cbc", []), "cipher/sm4-128-cbc": ("sm4-cbc", []),
    "stream/chacha20": ("chacha20", []), "stream/rc4": ("rc4", LEGACY),
    "aead/aes-gcm-128": ("aes-128-gcm", []), "aead/aes-gcm-256": ("aes-256-gcm", []),
    "aead/chacha20-poly1305": ("chacha20-poly1305", []),
    "aead/aes-ccm-128": ("aes-128-ccm", []),
}

# Our row name -> (openssl speed algorithm, column: 0 sign / 1 verify).
PUBLIC_KEY = {
    "pk/rsa2048-sign": ("rsa2048", 0), "pk/rsa2048-verify": ("rsa2048", 1),
    "pk/ecdsa-p256-sign": ("ecdsap256", 0), "pk/ecdsa-p256-verify": ("ecdsap256", 1),
    "pk/ed25519-sign": ("ed25519", 0), "pk/ed25519-verify": ("ed25519", 1),
    "pk/ed448-sign": ("ed448", 0), "pk/ed448-verify": ("ed448", 1),
    "pk/x25519": ("ecdhx25519", 0), "pk/x448": ("ecdhx448", 0),
}

# AES-NI (bit 57) and PCLMULQDQ (bit 33) of OPENSSL_ia32cap's first word.
NO_AESNI = "~0x200000200000000"
# The SHA extensions: bit 29 of the second word, CPUID leaf 7's EBX. Never
# set the variable empty - OpenSSL reads that as "no capabilities at all".
NO_SHANI = ":~0x20000000"


def without_hardware(name):
    """The `OPENSSL_ia32cap` mask for this row's hardware path, if it has
    one."""
    if "aes" in name:
        return NO_AESNI
    if name in ("hash/sha1", "hash/sha256"):
        return NO_SHANI
    return None


# Build name -> (cargo arguments, RUSTFLAGS).
BUILDS = {
    "portable": ([], ""),
    "x86-64-v3": ([], "-C target-cpu=x86-64-v3"),
    "ni": (["--features", "allcrypt/aes-ni,allcrypt/sha-ni"], ""),
    "v3+ni": (["--features", "allcrypt/aes-ni,allcrypt/sha-ni"], "-C target-cpu=x86-64-v3"),
}


def cpu_flags():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("flags"):
                    return set(line.split(":", 1)[1].split())
    except OSError:
        pass
    return set()


def available_builds():
    """The builds this machine can run: x86-64-v3 needs AVX2 and its
    companions, and off x86-64 neither option means anything."""
    if platform.machine().lower() not in ("x86_64", "amd64"):
        return ["portable"]
    flags = cpu_flags()
    v3 = {"avx2", "bmi1", "bmi2", "fma", "movbe"} <= flags
    return [name for name in BUILDS if v3 or "v3" not in name]


def ours(filter_text, build):
    arguments, rustflags = BUILDS[build]
    target = os.path.join(ROOT, "target", "bench", build)
    env = dict(os.environ, CARGO_TARGET_DIR=target, RUSTFLAGS=rustflags)
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "allcrypt-tools",
                    "--bin", "bench_speed", *arguments], cwd=ROOT, check=True, env=env)
    binary = os.path.join(target, "release", "bench_speed")
    out = subprocess.run([binary, filter_text], capture_output=True, text=True,
                         check=True).stdout
    rows = {}
    for line in out.splitlines():
        name, value, unit = line.split("\t")
        rows[name] = (float(value), unit)
    if not rows:
        raise SystemExit(f"bench_speed printed nothing for filter {filter_text!r}")
    return rows


def openssl_speed(args, env=None):
    return subprocess.run(["openssl", "speed", "-seconds", "1", "-bytes", "16384", *args],
                          capture_output=True, text=True, env=env).stdout


def openssl_bulk(name, env=None):
    algorithm, extra = BULK[name]
    match = re.search(r"([\d.]+)k\s*$", openssl_speed([*extra, "-evp", algorithm], env).strip())
    # Thousands of bytes per second; None when this OpenSSL lacks it.
    return float(match.group(1)) / 1000 if match else None


def openssl_public_key(name):
    algorithm, column = PUBLIC_KEY[name]
    lines = openssl_speed([algorithm]).strip().splitlines()
    if not lines:
        return None
    tokens = lines[-1].split()
    try:
        return float(tokens[-1]) if algorithm.startswith("ecdh") else float(tokens[-2 + column])
    except (ValueError, IndexError):
        return None


def per_second(function, seconds=1.0):
    function()
    start, calls = time.perf_counter(), 0
    while time.perf_counter() - start < seconds:
        function()
        calls += 1
    return calls / (time.perf_counter() - start)


def reference_kdf(name):
    import hashlib
    if name == "kdf/pbkdf2-sha256-10000":
        return per_second(lambda: hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 10000, 32))
    if name == "kdf/pbkdf2-sha1-4096":
        return per_second(lambda: hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 4096, 32))
    if name == "kdf/scrypt-16384-8-1":
        return per_second(lambda: hashlib.scrypt(b"password", salt=b"salt", n=16384, r=8, p=1,
                                                 maxmem=64 << 20, dklen=32))
    if name == "kdf/argon2id-65536-3-1":
        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        except ImportError:
            return None
        return per_second(lambda: Argon2id(salt=b"saltsalt", length=32, iterations=3, lanes=1,
                                           memory_cost=65536).derive(b"password"), 2.0)
    return None


def main():
    arguments = sys.argv[1:]
    builds = available_builds()
    if "--builds" in arguments:
        at = arguments.index("--builds")
        wanted = arguments[at + 1].split(",")
        del arguments[at:at + 2]
        unknown = [b for b in wanted if b not in BUILDS]
        if unknown:
            raise SystemExit(f"no build {', '.join(unknown)}; the builds are "
                             f"{', '.join(BUILDS)}")
        skipped = [b for b in wanted if b not in builds]
        if skipped:
            print(f"skipped on this machine: {', '.join(skipped)}")
        builds = [b for b in wanted if b in builds]
    filter_text = arguments[0] if arguments else ""
    results = {build: ours(filter_text, build) for build in builds}
    x86 = platform.machine().lower() in ("x86_64", "amd64")
    version = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
    print(f"allcrypt against {version}, 16 KiB buffers\n")
    header = f"{'':30}" + "".join(f" {build:>10}" for build in builds)
    header += f" {'OpenSSL':>10} {'ratio':>7}"
    if x86:
        header += f" {'no NI':>10}"
    print(header)
    for name, (_, unit) in results[builds[0]].items():
        values = [results[build].get(name, (None, unit))[0] for build in builds]
        value = max(v for v in values if v is not None)
        if name in BULK:
            reference = openssl_bulk(name)
        elif name in PUBLIC_KEY:
            reference = openssl_public_key(name)
        elif name.startswith("kdf/"):
            reference = reference_kdf(name)
        else:
            reference = None
        line = f"{name:30}" + "".join(f" {v:10.1f}" if v is not None else f" {'-':>10}"
                                      for v in values)
        if reference:
            line += f" {reference:10.1f} {value / reference:6.2f}x"
        else:
            line += f" {'-':>10} {'':>7}"
        mask = without_hardware(name) if x86 and name in BULK else None
        if mask:
            software = openssl_bulk(name, dict(os.environ, OPENSSL_ia32cap=mask))
            if software:
                line += f" {software:10.1f}"
        print(f"{line}  {unit}")


if __name__ == "__main__":
    main()
