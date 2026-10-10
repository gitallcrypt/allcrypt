#!/usr/bin/env python3
"""Check the C interface: the header against the Rust, and C against both.

    python3 scripts/check_c_api.py            # header, then build and run
    python3 scripts/check_c_api.py --static   # the same, linked statically too

Four checks, in order:

1. **The header says what the library exports.** Every `#[no_mangle]`
   function in `src/capi.rs` has a prototype in `include/allcrypt.h` with
   the same parameters - names and types, in order - and the same return
   type, and the header declares nothing else; the `ALLCRYPT_*` constants
   agree. A C compiler cannot see a mismatch here: a header that says
   `size_t` where the library takes `uint32_t` compiles, links and passes
   the wrong argument. This part needs no compiler and no build.

2. **Clippy over `capi.rs`**, which the gate's `cargo clippy` never
   compiles: the module exists only with the feature on.

3. **C, through the header, gets the right answers.** The library is
   built with `c-api`, `tests/c/test_capi.c` is compiled against the
   header with every warning an error (and the header once more as C++),
   linked, and run with key files written here by python-cryptography.
   The program checks round trips and refusals itself; every value it
   prints is compared here with hashlib or python-cryptography. Every
   function in the header must be called by the program.

4. **The C in `README.md` and `docs/c.md` compiles and runs**, each ```c block as a
   program of its own, the same way `check_docs.py` runs the Rust and
   Python ones.

Without a C compiler (`$CC`, `cc`, `gcc` or `clang`) only the first two
run, and the script says so. The third also needs the `openssl` command,
for one key file. Nothing here uses the network.
"""

import argparse
import hashlib
import hmac
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST = os.path.join(ROOT, "src", "capi.rs")
HEADER = os.path.join(ROOT, "include", "allcrypt.h")
TEST = os.path.join(ROOT, "tests", "c", "test_capi.c")
DOCS = [os.path.join(ROOT, "README.md"), os.path.join(ROOT, "docs", "c.md")]
TARGET = os.path.join(ROOT, "target", "c-api")

# How each Rust parameter type is spelled in C. Opaque types are the
# same word on both sides, because `capi.rs` names them after the C type.
SCALARS = {
    "c_int": "int", "usize": "size_t", "u32": "uint32_t", "u64": "uint64_t",
    "c_char": "char", "u8": "uint8_t",
}


def c_type(rust: str) -> str:
    """`*const u8` -> `const uint8_t *`, `*mut *mut allcrypt_hash` ->
    `allcrypt_hash **`."""
    rust = rust.strip()
    if rust.startswith("*const "):
        inner = c_type(rust[len("*const "):])
        return ("const " + inner + " *") if not inner.endswith("*") else inner + " const *"
    if rust.startswith("*mut "):
        inner = c_type(rust[len("*mut "):])
        return inner + (" *" if not inner.endswith("*") else "*")
    return SCALARS.get(rust, rust)


def normalise(c: str) -> str:
    c = re.sub(r"\s+", " ", c.strip())
    c = re.sub(r"\s*\*\s*", " *", c)
    c = c.replace("* *", "**")
    return c.strip()


def rust_functions() -> dict:
    text = open(RUST, encoding="utf-8").read()
    found = {}
    pattern = re.compile(
        r'#\[no_mangle\]\s*pub (?:unsafe )?extern "C" fn (\w+)\s*\((.*?)\)\s*(?:->\s*([^{]+?))?\s*\{',
        re.S)
    for name, params, ret in pattern.findall(text):
        args = []
        for param in filter(None, (p.strip() for p in params.split(","))):
            pname, ptype = param.split(":", 1)
            args.append((pname.strip(), normalise(c_type(ptype))))
        found[name] = (normalise(c_type(ret)) if ret else "void", args)
    return found


def header_functions() -> dict:
    text = open(HEADER, encoding="utf-8").read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    found = {}
    for ret, name, params in re.findall(r"([\w\s\*]+?)\s*\b(allcrypt_\w+)\s*\(([^)]*)\)\s*;",
                                        text):
        args = []
        if params.strip() != "void":
            for param in params.split(","):
                param = param.strip()
                array = re.match(r"(.*?)(\w+)\s*\[\s*\d+\s*\]$", param)
                if array:
                    ptype, pname = array.group(1) + " *", array.group(2)
                else:
                    m = re.match(r"(.*?)(\w+)$", param)
                    ptype, pname = m.group(1), m.group(2)
                args.append((pname, normalise(ptype)))
        found[name] = (normalise(ret), args)
    return found


def constants(path: str, pattern: str) -> dict:
    text = open(path, encoding="utf-8").read()
    return {name: int(value) for name, value in re.findall(pattern, text)}


def check_header() -> list:
    problems = []
    rust, header = rust_functions(), header_functions()
    if len(rust) < 60:
        problems.append(f"found only {len(rust)} functions in capi.rs; the parser is lost")
    for name in sorted(set(rust) - set(header)):
        problems.append(f"{name} is exported but not in the header")
    for name in sorted(set(header) - set(rust)):
        problems.append(f"{name} is in the header but not exported")
    for name in sorted(set(rust) & set(header)):
        if rust[name] != header[name]:
            problems.append(f"{name}: the library has {rust[name]}, the header {header[name]}")
    ours = constants(RUST, r"pub const (ALLCRYPT_\w+): c_int = (-?\d+);")
    theirs = constants(HEADER, r"#define (ALLCRYPT_\w+) \(?(-?\d+)\)?")
    if ours != theirs or len(ours) != 3:
        problems.append(f"constants: the library has {ours}, the header {theirs}")
    print(f"header: {len(rust)} functions and {len(ours)} constants compared")
    return problems


def compiler():
    for candidate in (os.environ.get("CC"), "cc", "gcc", "clang"):
        if candidate and shutil.which(candidate):
            return candidate
    return None


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        sys.exit(f"{' '.join(command)} failed:\n{result.stdout}\n{result.stderr}")
    return result


def library_names():
    if sys.platform == "darwin":
        return "liballcrypt.dylib", "liballcrypt.a"
    return "liballcrypt.so", "liballcrypt.a"


def build(static: bool):
    common = ["cargo", "build", "--release", "--lib", "--features", "c-api",
              "--target-dir", TARGET]
    run(common, cwd=ROOT)
    flags = []
    if static:
        rustc = ["cargo", "rustc", "--release", "--lib", "--features", "c-api",
                 "--target-dir", TARGET, "--crate-type", "staticlib", "--",
                 "--print", "native-static-libs"]
        output = run(rustc, cwd=ROOT).stderr
        match = re.search(r"native-static-libs: (.*)", output)
        flags = match.group(1).split() if match else []
    return os.path.join(TARGET, "release"), flags


def write_keys(directory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
    pkcs8 = serialization.PrivateFormat.PKCS8
    pem = serialization.Encoding.PEM
    plain = serialization.NoEncryption()
    keys = {
        "ec.pem": ec.generate_private_key(ec.SECP256R1()),
        "ed25519.pem": ed25519.Ed25519PrivateKey.generate(),
        "ed448.pem": ed448.Ed448PrivateKey.generate(),
    }
    for name, key in keys.items():
        with open(os.path.join(directory, name), "wb") as f:
            f.write(key.private_bytes(pem, pkcs8, plain))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(directory, "rsa_encrypted.pem"), "wb") as f:
        f.write(key.private_bytes(pem, pkcs8,
                                  serialization.BestAvailableEncryption(b"correct horse")))
    numbers = key.private_numbers()
    with open(os.path.join(directory, "rsa_primes.txt"), "w") as f:
        for value in (numbers.p, numbers.q, numbers.public_numbers.e):
            f.write(f"{value:x}".rjust((value.bit_length() + 7) // 8 * 2, "0") + "\n")
    keys["rsa"] = key
    # The Ed25519 key again, encrypted under the *empty* password, which
    # is a password: the C interface's NULL means "none" and a non-NULL
    # empty one means this. python-cryptography reads b"" as "none", so
    # the file comes from OpenSSL.
    if not shutil.which("openssl"):
        sys.exit("the openssl command is needed to write a key encrypted under the empty "
                 "password")
    run(["openssl", "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-passout", "pass:",
         "-in", os.path.join(directory, "ed25519.pem"),
         "-out", os.path.join(directory, "ed25519_empty_password.pem")])
    return keys


def compare(output: dict, keys: dict, version: str) -> list:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as h
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, utils, x25519
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    msg = bytes(i % 256 for i in range(1000))
    problems, checked = [], []

    def same(label, expected):
        checked.append(label)
        if label not in output:
            problems.append(f"{label}: not printed")
        elif output[label] != expected.hex():
            problems.append(f"{label}: {output[label]} where the reference gives {expected.hex()}")

    def verifies(label, check):
        checked.append(label)
        try:
            check(bytes.fromhex(output[label]))
        except (InvalidSignature, ValueError, KeyError) as error:
            problems.append(f"{label}: the reference refuses it ({error!r})")

    if output.get("version") != version:
        problems.append(f"version {output.get('version')} where Cargo.toml says {version}")

    # Hashes: every one hashlib has. The names differ only in spelling.
    hashed = 0
    for label in [k for k in output if k.startswith("hash_") and k != "hash_empty_sha256"]:
        name = label[len("hash_"):]
        if name.startswith("shake"):
            continue
        try:
            reference = hashlib.new(name, msg[:200]).digest()
        except ValueError:
            continue
        same(label, reference)
        hashed += 1
    if hashed < 15:
        problems.append(f"only {hashed} hashes had a reference; expected at least 15")
    same("hash_empty_sha256", hashlib.sha256().digest())
    same("shake128", hashlib.shake_128(msg[:200]).digest(100))
    same("shake256", hashlib.shake_256(msg[:200]).digest(64))

    same("hmac_sha256", hmac.new(msg[:100], msg[100:400], "sha256").digest())
    same("hmac_sha512_longkey", hmac.new(msg[:200], msg[:10], "sha512").digest())

    same("pbkdf2_sha256", hashlib.pbkdf2_hmac("sha256", msg[:10], msg[10:26], 1000, 40))
    same("hkdf_sha256", HKDF(h.SHA256(), 42, msg[:13], msg[35:45]).derive(msg[13:35]))
    same("hkdf_sha256_nosalt", HKDF(h.SHA256(), 42, None, b"").derive(msg[13:35]))
    same("scrypt", hashlib.scrypt(msg[:8], salt=msg[8:24], n=1024, r=8, p=1, dklen=64))
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        same("argon2id", Argon2id(salt=msg[16:32], length=32, iterations=3, lanes=2,
                                  memory_cost=64).derive(msg[:16]))
        same("argon2id_secret_ad", Argon2id(salt=msg[16:32], length=32, iterations=3, lanes=2,
                                            memory_cost=64, ad=msg[40:52],
                                            secret=msg[32:40]).derive(msg[:16]))
    except Exception as error:   # an OpenSSL without Argon2
        print(f"  argon2: no reference here ({error})")

    def encrypt(algorithm, mode, data):
        e = Cipher(algorithm, mode).encryptor()
        return e.update(data) + e.finalize()

    padded = msg[:100] + bytes([12] * 12)
    same("aes128_cbc", encrypt(algorithms.AES(msg[32:48]), modes.CBC(msg[64:80]), padded))
    same("aes256_ctr", encrypt(algorithms.AES(msg[32:64]), modes.CTR(msg[64:80]), msg[:333]))
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        TripleDES = algorithms.TripleDES
    same("tdes_ecb", encrypt(TripleDES(msg[32:56]), modes.ECB(), msg[:64]))
    if output.get("rc2_40_cbc", "") in ("", output.get("aes128_cbc")):
        problems.append("rc2_40_cbc: missing")

    sealed = AESGCM(msg[32:64]).encrypt(msg[64:76], msg[:150], msg[80:100])
    same("aead_aes-gcm_ct", sealed[:-16])
    same("aead_aes-gcm_tag", sealed[-16:])
    sealed = ChaCha20Poly1305(msg[32:64]).encrypt(msg[64:76], msg[:150], msg[80:100])
    same("aead_chacha20-poly1305_ct", sealed[:-16])
    same("aead_chacha20-poly1305_tag", sealed[-16:])
    # A 12-byte nonce with the block counter starting at 0, as RFC 8439's
    # ChaCha20 block function takes it; python-cryptography's 16-byte
    # nonce is the counter, little endian, followed by those 12 bytes.
    same("chacha20", encrypt(algorithms.ChaCha20(msg[32:64], bytes(4) + msg[64:76]), None,
                             msg[:300]))

    public = x25519.X25519PrivateKey.from_private_bytes(msg[100:132]).public_key()
    same("x25519_public", public.public_bytes(Encoding.Raw, PublicFormat.Raw))

    scalar = ec.derive_private_key(int.from_bytes(msg[1:33], "big"), ec.SECP256R1())
    same("ec_p256_public", scalar.public_key().public_bytes(Encoding.X962,
                                                           PublicFormat.UncompressedPoint))
    same("ec_p256_public_compressed", scalar.public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint))
    loaded = keys["ec.pem"].public_key()
    same("ec_loaded_public", loaded.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))
    digest = hashlib.sha256(msg[:300]).digest()

    def ecdsa(signature):
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        loaded.verify(utils.encode_dss_signature(r, s), digest,
                      ec.ECDSA(utils.Prehashed(h.SHA256())))
    verifies("ec_signature", ecdsa)

    seed = ed25519.Ed25519PrivateKey.from_private_bytes(msg[7:39])
    same("ed25519_public", seed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    same("ed25519_signature", seed.sign(msg[:123]))
    same("ed25519_empty_password_public", keys["ed25519.pem"].public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw))
    ed448 = keys["ed448.pem"]
    same("ed448_loaded_seed", ed448.private_bytes_raw())
    same("ed448_loaded_public", ed448.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    rsa = keys["rsa"]
    numbers = rsa.public_key().public_numbers()
    same("rsa_n", numbers.n.to_bytes(256, "big"))
    same("rsa_e", numbers.e.to_bytes(3, "big"))
    digest = hashlib.sha256(msg[:500]).digest()
    prehashed = utils.Prehashed(h.SHA256())
    same("rsa_pkcs1_signature", rsa.sign(digest, padding.PKCS1v15(), prehashed))
    verifies("rsa_pss_signature", lambda s: rsa.public_key().verify(
        s, digest, padding.PSS(padding.MGF1(h.SHA256()), 32), prehashed))

    def opens(label, scheme):
        checked.append(label)
        try:
            if rsa.decrypt(bytes.fromhex(output[label]), scheme) != msg[9:59]:
                problems.append(f"{label}: decrypts to something else")
        except (ValueError, KeyError) as error:
            problems.append(f"{label}: the reference refuses it ({error!r})")
    opens("rsa_oaep_ciphertext", padding.OAEP(padding.MGF1(h.SHA256()), h.SHA256(), msg[:4]))
    opens("rsa_pkcs1_ciphertext", padding.PKCS1v15())
    # Unpadded RSA has no reference in python-cryptography; Python's own
    # integers are one, and an independent one.
    same("rsa_raw_ciphertext", pow(int.from_bytes(msg[9:59], "big"), numbers.e,
                                   numbers.n).to_bytes(256, "big"))

    print(f"run: {len(checked)} values compared with hashlib and python-cryptography")
    return problems


def check_program(cc: str, static: bool) -> list:
    problems = []
    called = set(re.findall(r"\b(allcrypt_[a-z0-9_]+)\s*\(", open(TEST).read()))
    for name in sorted(set(header_functions()) - called):
        problems.append(f"{name} is never called by {os.path.relpath(TEST, ROOT)}")

    libdir, static_flags = build(static)
    version = re.search(r'^version = "(.*)"', open(os.path.join(ROOT, "Cargo.toml")).read(),
                        re.M).group(1)
    warnings = ["-std=c99", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
    include = ["-I", os.path.join(ROOT, "include")]
    cxx = shutil.which("c++")
    if cxx:
        run([cxx, "-x", "c++", "-fsyntax-only", "-Wall", "-Werror", *include, HEADER])
    with tempfile.TemporaryDirectory() as work:
        keys = write_keys(work)
        links = [("shared", ["-L", libdir, "-lallcrypt", f"-Wl,-rpath,{libdir}"])]
        if static:
            links.append(("static", [os.path.join(libdir, library_names()[1]),
                                     *static_flags]))
        for kind, link in links:
            program = os.path.join(work, f"test_capi_{kind}")
            run([cc, *warnings, *include, TEST, "-o", program, *link])
            result = subprocess.run([program, work], capture_output=True, text=True,
                                    timeout=600)
            if result.returncode != 0 or not result.stdout.endswith("done\n"):
                problems.append(f"test_capi ({kind}) failed:\n{result.stderr}")
                continue
            output = dict(line.split(" ", 1) for line in result.stdout.splitlines()
                          if " " in line)
            problems += [f"({kind}) {p}" for p in compare(output, keys, version)]

        blocks = []
        for doc in DOCS:
            found = re.findall(r"```c\n(.*?)```", open(doc, encoding="utf-8").read(), re.S)
            if not found:
                problems.append(f"{os.path.relpath(doc, ROOT)} has no ```c block")
            blocks += [(os.path.relpath(doc, ROOT), block) for block in found]
        for i, (doc, block) in enumerate(blocks):
            source = os.path.join(work, f"doc{i}.c")
            open(source, "w").write(block)
            program = os.path.join(work, f"doc{i}")
            compiled = subprocess.run([cc, *warnings, *include, source, "-o", program,
                                       "-L", libdir, "-lallcrypt", f"-Wl,-rpath,{libdir}"],
                                      capture_output=True, text=True)
            if compiled.returncode != 0:
                problems.append(f"{doc}, C block {i + 1}, does not compile:\n{compiled.stderr}")
                continue
            ran = subprocess.run([program], capture_output=True, text=True, timeout=120)
            if ran.returncode != 0:
                problems.append(f"{doc}, C block {i + 1}, exits {ran.returncode}:\n"
                                f"{ran.stdout}{ran.stderr}")
        print(f"docs: {len(blocks)} C blocks compiled and run")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--static", action="store_true",
                        help="also link the test program statically")
    args = parser.parse_args()
    problems = check_header()
    lint = subprocess.run(["cargo", "clippy", "--lib", "--features", "c-api", "--target-dir",
                           TARGET], cwd=ROOT, capture_output=True, text=True)
    warnings = [line for line in lint.stderr.splitlines()
                if line.startswith(("warning", "error")) and "generated" not in line]
    if lint.returncode != 0 or warnings:
        problems.append("clippy with c-api:\n" + lint.stderr)
    print(f"clippy: {len(warnings)} warnings with c-api")
    cc = compiler()
    if cc is None:
        print("no C compiler ($CC, cc, gcc or clang): the header was compared, "
              "nothing was compiled")
    elif not problems:
        problems += check_program(cc, args.static)
    for problem in problems:
        print("FAIL", problem)
    if problems:
        sys.exit(1)
    print("ok")


if __name__ == "__main__":
    main()
