#!/usr/bin/env python3
"""Generate `vectors/gost_engine.vec` from OpenSSL's gost-engine.

For a long time GOST was the one family here with **no independent
opinion**: nothing on this machine implemented any of them, so the
differential reference was a second reading of the spec.
`scripts/diff_check.py`'s Kuznyechik and Magma are ours, written from the
standard a second time, and two readings by the same reader agree about
the same mistakes.

This closes that. It drives OpenSSL's gost-engine - a separate project,
written by other people, deployed in front of real servers - and writes
what it says into a vector file the test suite reads offline. The
implementations stay entirely our own; the engine is a witness, never a
dependency.

    python3 scripts/make_gost_vectors.py --engines ~/gost-engine/build/bin

`--engines` is the directory holding `gost.so`, or set `OPENSSL_ENGINES`
and leave it out. **This is a development tool, not a test.** The gate
never builds it, never runs it, and never needs the engine; what ships
is the file it writes.

## Where each section comes from, and why it is not all one route

Three routes, because no one of them reaches everything:

  * `openssl enc` for the block cipher modes and ACPKM.
  * `openssl dgst` for the three digests, **through stdin** - `-in`
    with an engine digest does not work on this OpenSSL.
  * `scripts/gost_engine_probe.c`, built here with `cc`, for MGM,
    OMAC and KExp15. The command line cannot express an AEAD, and for
    the MACs it produces *wrong answers without saying so* - see that
    file's header.

## Two traps in `openssl enc` that this works around

**A short `-iv` is zero-extended in silence.** Give four bytes to a
cipher that wants eight and you get a valid vector for a different IV.
So every IV here is exactly the length the engine reports, and the
lengths are asked for rather than assumed: `gost_engine_probe
--lengths` prints `EVP_CIPHER_get_iv_length` for each cipher. That is
not a formality - the engine's CTR modes take **half a block**, so
`kuznyechik-ctr` wants eight bytes where `kuznyechik-cbc` wants
sixteen, and `magma-ctr` wants four.

**`-nopad` is not optional.** Without it `enc` appends PKCS#7 and the
vector no longer says what the mode does.

## Determinism, and where it stops

Every key, IV and input for the ciphers, digests, MGM, OMAC and KExp15
is derived from a counter, so re-running this and diffing shows exactly
the rows where the engine's answer changed - and nothing else. Nothing
there is random and nothing carries a timestamp.

**The `vko-*` and `sign-*` sections are different.** `openssl pkey`
cannot be handed a chosen scalar, so their keys are generated fresh on
every run, and a GOST signature is randomised anyway - the same message
under the same key signs differently every time, which is not a defect
but the nonce doing its job. Those rows therefore change on every
regeneration. That costs nothing: what the file is evidence for is that
our code agrees with the engine on *some* keys, and a fresh set each
time is if anything a wider claim than a fixed one.

The header records the OpenSSL and gost-engine versions, because those
are the provenance; if a deterministic section changes, the versions in
it should say why.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROBE_SOURCE = os.path.join(HERE, "gost_engine_probe.c")
DEFAULT_OUTPUT = os.path.join(ROOT, "vectors", "gost_engine.vec")


# ---------------------------------------------------------------- lengths

def openssl(args, env, stdin=None):
    """Run `openssl`, returning stdout, and raise on anything else.

    No fallback and no default: a vector built from a command that
    failed is worse than a missing section, because it looks like
    evidence.
    """
    done = subprocess.run(["openssl"] + args, env=env, input=stdin,
                          capture_output=True)
    if done.returncode != 0:
        message = done.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"openssl {' '.join(args[:3])}: {message}")
    return done.stdout


def build_probe(work):
    """Compile and return the path to `gost_engine_probe`.

    Built here rather than committed as a binary, and built with `cc`
    rather than through a makefile, because it is nine hundred lines of
    nothing and the alternative is a build system for one file.
    """
    binary = os.path.join(work, "gost_engine_probe")
    compiler = os.environ.get("CC", "cc")
    if shutil.which(compiler) is None:
        raise RuntimeError(
            f"no C compiler ({compiler}); the MGM, OMAC and KExp15 "
            f"sections cannot be generated without one")
    done = subprocess.run(
        # `-ldl` because the probe reaches `gost_kexp15` by `dlsym`:
        # the engine registers KExp15 as a cipher whose encrypting
        # half is `#if 0`'d out, so EVP is not a route to it.
        [compiler, "-O2", "-Wall", "-Wextra", "-o", binary, PROBE_SOURCE,
         "-lcrypto", "-ldl"],
        capture_output=True)
    if done.returncode != 0:
        raise RuntimeError("cannot build the probe:\n"
                           + done.stderr.decode(errors="replace"))
    return binary


def probe_lengths(binary, env):
    """`{name: (key_len, iv_len, block_size)}`, from the engine itself."""
    done = subprocess.run([binary, "--lengths"], env=env, capture_output=True)
    if done.returncode != 0:
        raise RuntimeError("the probe could not report cipher lengths:\n"
                           + done.stderr.decode(errors="replace"))
    lengths = {}
    for line in done.stdout.decode().splitlines():
        name, *fields = line.split()
        values = dict(field.split("=") for field in fields)
        lengths[name] = (int(values["key"]), int(values["iv"]),
                         int(values["block"]))
    if not lengths:
        raise RuntimeError("the probe reported no cipher lengths at all")
    return lengths


# ------------------------------------------------------------- the inputs

def filler(length, seed):
    """The same deterministic filler the C probe uses, so a key built
    here and a key built there are built the same way and a row can be
    reproduced from either side."""
    return bytes((i * 37 + seed * 101 + 11) & 0xff for i in range(length))


# The message lengths, and what each is the only one to reach.
#
# Zero is here because an empty input is where a mode's final-block
# handling has nothing to work with. One and `block - 1` bracket the
# partial tail. Exact multiples are where a padding mistake is
# invisible. The large ones are past any counter's first byte, which is
# the only place a carry can show.
CIPHER_LENGTHS = [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                  127, 128, 129, 255, 256, 257, 1000]

# Digests get their own sweep, longer and finer, because a hash's
# padding is decided by the message length mod its block and Streebog's
# block is 64 bytes. Every residue near a boundary is covered.
DIGEST_LENGTHS = ([0, 1, 2, 3] + list(range(55, 70)) + [100, 111, 112, 113,
                  127, 128, 129, 200, 255, 256, 257, 1000, 4096])


# The block-cipher rows. Each is `(section, cipher, mode-is-blocked)`;
# the second field is the engine's name for it, which is also the
# section name because there is nothing to be gained from a second
# spelling.
#
# `gost89` is **CFB**, not ECB - the engine reports a block size of one
# for it - and there is no route to GOST 28147-89 ECB through `enc` at
# all. Three modes under two parameter sets still pin the block
# function, which is what the ECB rows would have been for.
#
# `gost89-cnt` is CryptoPro-A and `gost89-cnt-12` is
# id-tc26-gost-28147-param-Z. The engine's `CRYPT_PARAMS` control is
# how the others would be reached; it is not settable from `enc`, and
# a configuration file that sets it was tried and changed nothing.
CIPHER_SECTIONS = [
    "kuznyechik-ecb", "kuznyechik-cbc", "kuznyechik-cfb", "kuznyechik-ofb",
    "kuznyechik-ctr", "kuznyechik-ctr-acpkm",
    "magma-ecb", "magma-cbc", "magma-ctr", "magma-ctr-acpkm",
    "gost89", "gost89-cbc", "gost89-cnt", "gost89-cnt-12",
]

# ACPKM re-keys every N bytes and N is not a parameter here: the engine
# uses 4096 for Kuznyechik and 1024 for Magma. Measured rather than
# read - encrypt the same input under `-ctr` and `-ctr-acpkm` and the
# first byte where they differ is N - and `check()` re-measures it, so
# a build with different section sizes fails loudly instead of writing
# rows nothing can reproduce.
ACPKM_SECTION = {"kuznyechik-ctr-acpkm": 4096, "magma-ctr-acpkm": 1024}

# A section that never re-keys is an ACPKM test that tests CTR. These
# lengths cross the boundary three times for Magma and once for
# Kuznyechik, and the odd ones land mid-block on a boundary, which is
# where a counter that restarts instead of running on shows up.
ACPKM_LENGTHS = {
    "magma-ctr-acpkm": [1023, 1024, 1025, 2048, 3072, 4097],
    "kuznyechik-ctr-acpkm": [4095, 4096, 4097, 8192, 12289],
}

DIGEST_SECTIONS = ["md_gost94", "md_gost12_256", "md_gost12_512"]

# The engine's parameter-set names, and which of our curves each is.
#
# **XA and XB are aliases**, and including them is the point: RFC 4357's
# XchA is CryptoPro-A and XchB is CryptoPro-C, which
# `curves.rs::test_the_exchange_sets_are_the_curves_we_map_them_to`
# asserts from the documents. Deriving under the engine's XA and our A
# is that claim checked by somebody else.
#
# `TCA` and 512 `C` matter most: `gost256-tc26-a` and `gost512-c` have
# **cofactor four**, and they are the only curves here where the two
# readings of VKO's `m/q` term give different answers. RFC 7836 writes
# the cofactor in; gost-engine's `VKO_compute_key` shows no `m/q`, but
# its `gost_ec_point_mul` applies the cofactor, so the rows on these two
# curves are what shows the engine follows the document.
CURVE_SETS = [
    ("gost2012_256", "A", "gost256-a"),
    ("gost2012_256", "B", "gost256-b"),
    ("gost2012_256", "C", "gost256-c"),
    ("gost2012_256", "TCA", "gost256-tc26-a"),
    ("gost2012_256", "XA", "gost256-a"),
    ("gost2012_256", "XB", "gost256-c"),
    ("gost2012_512", "A", "gost512-a"),
    ("gost2012_512", "B", "gost512-b"),
    ("gost2012_512", "C", "gost512-c"),
]

# VKO's hash is **not** decided by the key's size. `-pkeyopt vko:512`
# on a 256 bit key derives 64 bytes and `vko:256` on a 512 bit key
# derives 32, so both are swept on both - four combinations per curve.
# Our `Curve::vko` takes `digest_bits` for the same reason, and a
# version that inferred it from the curve would agree with the engine
# on half of these rows.
VKO_DIGEST_BITS = [256, 512]

# Which digest each key size signs with. Not a choice: `gost2012_512`
# with `md_gost12_256` is refused outright as an invalid digest type.
SIGN_DIGEST = {"gost2012_256": "md_gost12_256",
               "gost2012_512": "md_gost12_512"}

# The messages signed. A short one, one that is exactly a Streebog
# block, and one several blocks long, because the digest is the input to
# the signature and its padding is where the boundaries are.
SIGN_MESSAGE_LENGTHS = [1, 64, 200]


def encrypt(env, work, cipher, key, iv, data):
    path = os.path.join(work, "input.bin")
    with open(path, "wb") as out:
        out.write(data)
    args = ["enc", "-engine", "gost", "-" + cipher, "-K", key.hex(),
            "-in", path, "-nopad"]
    if iv:
        args += ["-iv", iv.hex()]
    return openssl(args, env)


def digest(env, name, data):
    """`openssl dgst` on **stdin**.

    `-in <file>` with an engine digest on this OpenSSL produces no
    output and no error. Redirecting works, which is the sort of
    difference that is only ever found by trying both.
    """
    text = openssl(["dgst", "-engine", "gost", "-" + name], env,
                   stdin=data).decode()
    return bytes.fromhex(text.strip().rsplit("= ", 1)[-1])


# -------------------------------------------------------------- the file

def emit(out, fields):
    out.write("\n")
    for name, value in fields:
        out.write(f"{name} = {value.hex() if isinstance(value, bytes) else value}\n")


def cipher_section(out, env, work, section, lengths, counts):
    key_len, iv_len, _ = lengths[section]
    rows = ACPKM_LENGTHS.get(section, CIPHER_LENGTHS)
    out.write(f"\n[{section}]\n")
    written = 0
    for index, length in enumerate(rows):
        # ECB and CBC take whole blocks only; `enc -nopad` refuses a
        # partial one rather than padding it, which is the right
        # refusal and means those rows do not exist to be generated.
        _, _, block = lengths[section]
        if block > 1 and length % block != 0:
            continue
        key = filler(key_len, index)
        iv = filler(iv_len, index + 41) if iv_len else b""
        data = filler(length, index + 83)
        fields = [("Key", key)]
        if iv_len:
            fields.append(("IV", iv))
        if section in ACPKM_SECTION:
            fields.append(("Section", str(ACPKM_SECTION[section])))
        fields += [("In", data),
                   ("Out", encrypt(env, work, section, key, iv, data))]
        emit(out, fields)
        written += 1
    counts[section] = written


def digest_section(out, env, section, counts):
    out.write(f"\n[{section}]\n")
    for index, length in enumerate(DIGEST_LENGTHS):
        data = filler(length, index + 7)
        emit(out, [("In", data), ("Out", digest(env, section, data))])
    counts[section] = len(DIGEST_LENGTHS)


# --------------------------------------------------- keys and signatures

def hex_integer(text):
    """Normalise a hex integer to an even number of digits.

    **`openssl pkey -text` prints these as numbers, not as byte
    strings**, so a coordinate whose top byte is small comes out one
    digit short - a 63 digit X on a 256 bit curve, about one key in
    sixteen. Left-padded here rather than in the reader, so the file
    holds bytes like every other field and nothing downstream has to
    know. The reader still parses it as a big-endian integer, so the
    width carries no meaning beyond being even.
    """
    cleaned = text.strip().upper()
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return cleaned


def keypair(env, work, algorithm, paramset, tag):
    """Generate a key with the engine and read its scalar and point back.

    `openssl pkey -text -noout` prints the private scalar and the public
    X and Y as big-endian hex, which is all the vector file needs - so
    nothing here parses a GOST private key, and a bug in our PKCS#8
    reader cannot make a row wrong.

    **These keys are fresh on every run**, so the VKO and signature
    sections change when this is re-run even if the engine has not. That
    is unavoidable rather than sloppy: `openssl pkey` cannot be given a
    scalar, and a GOST signature is randomised anyway - see the header
    this writes.
    """
    path = os.path.join(work, f"{tag}.pem")
    openssl(["genpkey", "-engine", "gost", "-algorithm", algorithm,
             "-pkeyopt", f"paramset:{paramset}", "-out", path], env)
    public = os.path.join(work, f"{tag}.pub.pem")
    openssl(["pkey", "-engine", "gost", "-in", path, "-pubout",
             "-out", public], env)

    text = openssl(["pkey", "-engine", "gost", "-in", path, "-text",
                    "-noout"], env).decode()
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        for label, key in (("Private key:", "d"), ("X:", "x"), ("Y:", "y")):
            if line.startswith(label):
                fields[key] = hex_integer(line[len(label):])
    missing = {"d", "x", "y"} - set(fields)
    if missing:
        raise RuntimeError(
            f"`openssl pkey -text` did not print {sorted(missing)} for a "
            f"{algorithm} {paramset} key; its output format has changed and "
            f"every key in this file would be silently wrong")
    return path, public, fields


def vko_section(out, env, work, counts):
    for algorithm, paramset, curve in CURVE_SETS:
        ours, _, mine = keypair(env, work, algorithm, paramset, "vko-a")
        _, theirs_pub, theirs = keypair(env, work, algorithm, paramset,
                                        "vko-b")
        section = f"vko-{paramset.lower()}-{algorithm.split('_')[1]}"
        out.write(f"\n[{section}]\n")
        written = 0
        for index, bits in enumerate(VKO_DIGEST_BITS):
            ukm = filler(8, index + 61)
            derived = openssl(
                ["pkeyutl", "-engine", "gost", "-derive", "-inkey", ours,
                 "-peerkey", theirs_pub, "-pkeyopt", f"ukmhex:{ukm.hex()}",
                 "-pkeyopt", f"vko:{bits}"], env)
            if len(derived) * 8 != bits:
                raise RuntimeError(
                    f"vko:{bits} derived {len(derived)} bytes; the hash is "
                    f"not the one asked for")
            emit(out, [("Curve", curve),
                       ("DigestBits", str(bits)),
                       ("Private", mine["d"]),
                       ("PeerX", theirs["x"]),
                       ("PeerY", theirs["y"]),
                       ("UKM", ukm),
                       ("Out", derived)])
            written += 1
        counts[section] = written


def sign_section(out, env, work, counts):
    for algorithm, paramset, curve in CURVE_SETS:
        key, public, fields = keypair(env, work, algorithm, paramset, "sign")
        section = f"sign-{paramset.lower()}-{algorithm.split('_')[1]}"
        digest_name = SIGN_DIGEST[algorithm]
        out.write(f"\n[{section}]\n")
        written = 0
        for index, length in enumerate(SIGN_MESSAGE_LENGTHS):
            message = filler(length, index + 97)
            message_path = os.path.join(work, "signed.bin")
            with open(message_path, "wb") as handle:
                handle.write(message)
            signature_path = os.path.join(work, "signed.sig")
            openssl(["dgst", "-engine", "gost", "-" + digest_name,
                     "-sign", key, "-out", signature_path, message_path], env)
            with open(signature_path, "rb") as handle:
                signature = handle.read()
            if not signature:
                raise RuntimeError(f"{digest_name} produced no signature")

            # **Verified by the engine before it is written.** A
            # signature is a pile of bytes of the right length whatever
            # went wrong, and a row that the signer itself rejects would
            # send the reader looking at our verifier.
            openssl(["dgst", "-engine", "gost", "-" + digest_name,
                     "-verify", public, "-signature", signature_path,
                     message_path], env)

            emit(out, [("Curve", curve),
                       ("Digest", digest_name),
                       ("PublicX", fields["x"]),
                       ("PublicY", fields["y"]),
                       ("In", message),
                       ("Sig", signature)])
            written += 1
        counts[section] = written


# ------------------------------------------------------------ the checks

def check_acpkm_section_sizes(env, work, lengths):
    """Measure where ACPKM diverges from plain CTR, and insist it is
    where `ACPKM_SECTION` says.

    The section size is the one number in this file that is neither
    stated by the engine nor written in a row, and a wrong one makes
    every ACPKM row unreproducible while looking exactly like a right
    one. So it is measured on every run.
    """
    for acpkm, expected in ACPKM_SECTION.items():
        plain = acpkm.replace("-acpkm", "")
        _, iv_len, _ = lengths[acpkm]
        key, iv = filler(32, 1), filler(iv_len, 2)
        data = filler(expected * 2, 3)
        a = encrypt(env, work, plain, key, iv, data)
        b = encrypt(env, work, acpkm, key, iv, data)
        first = next((i for i in range(len(a)) if a[i] != b[i]), None)
        if first is None:
            raise RuntimeError(
                f"{acpkm} never diverged from {plain} over "
                f"{len(data)} bytes, so nothing in its rows is about "
                f"re-keying at all")
        if first != expected:
            raise RuntimeError(
                f"{acpkm} re-keys after {first} bytes, not {expected}; "
                f"ACPKM_SECTION is wrong and every row it labels is "
                f"unreproducible")


def check_vko_is_symmetric(env, work):
    """Both parties must derive the same key - and that being true
    proves nothing about either implementation.

    VKO computes `ukm*da*db*G`, so two implementations making the same
    mistake agree perfectly and so do the two ends of one. This is here
    only to catch the engine being driven wrongly - a `-peerkey` that
    is not the other party's, say - because that failure would produce
    rows our code cannot match and would read as a bug in ours.
    """
    algorithm, paramset = "gost2012_256", "A"
    a_key, a_pub, _ = keypair(env, work, algorithm, paramset, "sym-a")
    b_key, b_pub, _ = keypair(env, work, algorithm, paramset, "sym-b")
    ukm = filler(8, 5).hex()
    options = ["-pkeyopt", f"ukmhex:{ukm}", "-pkeyopt", "vko:256"]
    one = openssl(["pkeyutl", "-engine", "gost", "-derive", "-inkey", a_key,
                   "-peerkey", b_pub] + options, env)
    two = openssl(["pkeyutl", "-engine", "gost", "-derive", "-inkey", b_key,
                   "-peerkey", a_pub] + options, env)
    if one != two:
        raise RuntimeError("the two parties derived different VKO keys, so "
                           "this is not being driven as a key agreement")
    if len(set(one)) == 1:
        raise RuntimeError("the derived key is a constant byte")


def check_the_digests_are_three_things(env):
    """The three digests must disagree, and Streebog's two must not be
    a truncation of each other.

    `md_gost12_256` is Streebog-512 with a different IV, not its first
    32 bytes, and an implementation that truncates agrees with the
    right answer nowhere - but a *generator* that fetched the same
    value twice would produce a file where they matched, and the test
    reading it would then pass on a truncating implementation.
    """
    data = filler(200, 11)
    answers = {name: digest(env, name, data) for name in DIGEST_SECTIONS}
    if len(set(answers.values())) != len(answers):
        raise RuntimeError("two of the digests returned the same bytes")
    short, long_ = answers["md_gost12_256"], answers["md_gost12_512"]
    if long_[:len(short)] == short:
        raise RuntimeError(
            "Streebog-256 came back as the first half of Streebog-512, "
            "which it is not - the generator fetched the wrong thing")


def check_a_short_iv_would_have_been_accepted(env, work, lengths):
    """Prove the trap this script works around is real.

    `enc` zero-extends a short `-iv` rather than refusing it. If that
    ever changes, the work-around costs nothing - but if it is *still*
    true and somebody simplifies the IV handling away, this says so.
    """
    _, iv_len, _ = lengths["kuznyechik-cbc"]
    key, data = filler(32, 1), filler(16, 2)
    short = filler(iv_len // 2, 5)
    padded = short + bytes(iv_len - len(short))
    if encrypt(env, work, "kuznyechik-cbc", key, short, data) != \
       encrypt(env, work, "kuznyechik-cbc", key, padded, data):
        raise RuntimeError(
            "`openssl enc` no longer zero-extends a short -iv; the "
            "comment in this file saying it does is now wrong")


# ----------------------------------------------------------------- main

def versions(env, binary):
    openssl_version = openssl(["version"], env).decode().strip()
    listing = openssl(["engine", "gost", "-c"], env).decode().strip()
    _ = binary
    return openssl_version, listing.splitlines()[0]


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engines", metavar="DIR",
                        default=os.environ.get("OPENSSL_ENGINES"),
                        help="the directory holding gost.so")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.engines:
        parser.error("pass --engines DIR or set OPENSSL_ENGINES; this "
                     "needs OpenSSL's gost-engine, which is not a "
                     "dependency of the library and is not built here")
    if not os.path.exists(os.path.join(args.engines, "gost.so")):
        parser.error(f"no gost.so in {args.engines}")

    env = dict(os.environ, OPENSSL_ENGINES=os.path.abspath(args.engines))

    with tempfile.TemporaryDirectory() as work:
        binary = build_probe(work)
        lengths = probe_lengths(binary, env)
        openssl_version, engine_line = versions(env, binary)

        check_the_digests_are_three_things(env)
        check_acpkm_section_sizes(env, work, lengths)
        check_a_short_iv_would_have_been_accepted(env, work, lengths)
        check_vko_is_symmetric(env, work)

        counts = {}
        body = []
        import io
        out = io.StringIO()
        for section in CIPHER_SECTIONS:
            cipher_section(out, env, work, section, lengths, counts)
        for section in DIGEST_SECTIONS:
            digest_section(out, env, section, counts)
        vko_section(out, env, work, counts)
        sign_section(out, env, work, counts)
        body.append(out.getvalue())

        probe = subprocess.run([binary], env=env, capture_output=True)
        if probe.returncode != 0:
            raise RuntimeError("the probe failed:\n"
                               + probe.stderr.decode(errors="replace"))
        body.append(probe.stdout.decode())

    header = [
        "# GOST test vectors from OpenSSL's gost-engine.",
        "#",
        "# Generated by scripts/make_gost_vectors.py. Do not edit: every",
        "# number here is somebody else's answer, and a hand edit makes it",
        "# ours again, which is the one thing this file exists not to be.",
        "#",
        f"# {openssl_version}",
        f"# {engine_line}",
        "#",
        "# The implementations under test are entirely our own code. This",
        "# engine is a witness and not a dependency: nothing in the build,",
        "# the test gate or the library links it, and the tests that read",
        "# this file need no network and no engine.",
        "#",
        "# Section names are the engine's own cipher and digest names.",
        "# `gost89` is CFB and `gost89-cbc` is CBC; `gost89-cnt` uses",
        "# CryptoPro-A and `gost89-cnt-12` uses id-tc26-gost-28147-param-Z.",
        "# The CTR modes' IV is half a block, which is why it is eight",
        "# bytes for Kuznyechik and four for Magma.",
        "#",
        "# **The cipher, digest, MGM, OMAC and KExp15 rows are",
        "# deterministic** - every key, IV and input comes from a counter,",
        "# so re-running the generator changes them only where the engine's",
        "# answer changed. The `vko-*` and `sign-*` rows are not: their keys",
        "# are generated fresh (`openssl pkey` cannot be handed a scalar)",
        "# and a GOST signature is randomised, so those change on every run",
        "# by design. Diff the deterministic sections when looking for drift.",
        "#",
        "# A `vko-` or `sign-` section is named for the engine's parameter",
        "# set and key size and carries the curve it means, because two of",
        "# them are aliases: RFC 4357's XchA is CryptoPro-A and XchB is",
        "# CryptoPro-C. `vko-tca-256` and `vko-c-512` are on the two curves",
        "# here with a cofactor of four, which are the only places the two",
        "# readings of VKO's `m/q` term differ. RFC 7836 writes the term in,",
        "# and those rows are what show the engine applies it.",
        "#",
        "# Counts, asserted by the test that reads this:",
    ]
    for section in CIPHER_SECTIONS + DIGEST_SECTIONS:
        header.append(f"#   {section:<24} {counts[section]}")
    for section in sorted(counts):
        if section.startswith(("vko-", "sign-")):
            header.append(f"#   {section:<24} {counts[section]}")

    with open(args.output, "w") as handle:
        handle.write("\n".join(header) + "\n")
        for piece in body:
            handle.write(piece)

    total = sum(counts.values())
    print(f"{args.output}: {total} rows from the command line, plus the "
          f"probe's MGM, OMAC and KExp15 sections")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:                                # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
