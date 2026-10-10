#!/usr/bin/env python3
"""
Run tools/src/bin/ct_bignum.rs under valgrind and check each case against what it
is supposed to be.

The technique is ctgrind: mark a secret's bytes "undefined" and let memcheck
report every conditional jump, conditional move and memory index that depends
on them. See the header of tools/src/bin/ct_bignum.rs for what it does and does
not catch.

**Why there are cases expected to fail.** A harness that only ever asserts
"no reports" passes just as well when it has stopped working - when the
client requests are not reaching valgrind, when the optimiser folded the
secret away, when the example silently exits early. So half the table is
code known to be variable time, and a clean result from any of those rows
fails the run. They are the reason to believe the other half.

    python3 scripts/ct_check.py              # the whole table
    python3 scripts/ct_check.py pow_ct       # one case, with the reports
    python3 scripts/ct_check.py --aes-ni     # with the `aes-ni` feature

**`--aes-ni`** builds the harness with the hardware AES feature into its
own target directory and runs the same table, with one row changed:
`aes_block_table` must come back clean, because the one-block path is
then `aesenc` rather than a table lookup. That row is the claim the
feature's documentation makes about the chained modes, measured. On a
processor without AES-NI the library falls back to the portable code, the
row reports as before, and the run fails - correctly, since the claim
does not hold there.

Needs valgrind and binutils - objdump and addr2line for the division
scan, and c++filt to read the names a valgrind older than 3.20 leaves
mangled. No network.
"""

import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AES_NI = "--aes-ni" in sys.argv
BINARY = os.path.join(ROOT, "target", *(["aes-ni"] if AES_NI else []), "release", "ct_bignum")

CLEAN = "clean"
LEAKS = "leaks"

# (case, expectation, why). The "why" is the whole point of the table: a row
# marked LEAKS without a reason is a bug somebody forgot about, and a row
# marked CLEAN without one is a claim nobody checked.
CASES = [
    # ---- the constant-time path -------------------------------------
    ("pow_ct", CLEAN,
     "Montgomery ladder over fixed-width Secrets, public loop bound."),
    ("pow_ct_short", CLEAN,
     "the same with a short exponent: the bound is the modulus's width, so "
     "a short secret must be indistinguishable from a long one."),
    ("montgomery_mul", CLEAN,
     "CIOS plus the conditional subtract, which is where LLVM turned a "
     "branchless select back into a branch and a memcpy."),
    ("montgomery_add_sub", CLEAN,
     "modular add and subtract, both of which choose between two results."),
    ("inverse_prime", CLEAN,
     "Fermat inversion: an exponentiation, so it inherits pow_ct."),
    ("secret_compare", CLEAN,
     "ct_lt, ct_eq, ct_is_zero and bit, folded together so none can be "
     "optimised away."),
    ("secret_bytes", CLEAN,
     "fixed-width serialisation, which must not trim leading zeros."),

    # ---- the call sites, with the leaks named -------------------------
    #
    # A `set` expectation means "this leaks, and only in these places". Every
    # function named is argued in the `why` beside it; a name that turns up
    # and is not in the set fails the run.
    #
    # **Names rather than a count**, and there are two separate reasons.
    #
    # The first: this table held exact counts for about an hour, and they
    # broke the first time an unrelated change shifted the optimiser's
    # inlining - `ecdsa_sign` went from 21 reports to 8 with nothing in ECDSA
    # touched, because the count is the number of *distinct stacks*.
    #
    # The second is worse, and turned up in a breakage sweep of the
    # constant-time EC code, when the ladder in `ec::ct` was the path
    # every curve signed through:
    # **a regression can make the count go down.** Replacing the ladder's
    # masked `cond_swap` with a real `if bit { mem::swap }` - a genuine,
    # serious leak of the scalar - took `ecdsa_sign` from 9 reports to 5,
    # because the different code shape merged several stacks. A count would
    # have read that as an improvement. The name `Field::scalar_mul` appearing
    # where it had not before is what catches it.
    #
    # A name is a property of the code; a count is a property of the build.
    ("rsa_private", {"allcrypt::publickey_ciphers::rsa::RsaPrivateKey::raw",
                     # `normalise` and `UnknownInlinedFun` are the *same*
                     # site - the declassify at the end - under different
                     # inlining. Which symbol comes out shifts with
                     # unrelated changes, which is the third time this
                     # table has learnt that lesson.
                     #
                     # `UnknownInlinedFun` is the weakest entry here,
                     # because it names nothing: it means "inlined, symbol
                     # lost". A new leak that inlines the same way would
                     # hide behind it. There is no better handle while the
                     # frame has no symbol, and saying so is the honest
                     # version of pretending otherwise.
                     "normalise", "UnknownInlinedFun"},
     "both are the final declassify(): the plaintext leaves as a BigUint, "
     "which normalises it. That is the API boundary - the caller asked for "
     "the number. Everything before it, including the CRT reductions by the "
     "secret primes and the Bellcore check, is fixed width."),
    # OAEP's padding check, apart from the private operation above. The
    # hashing, the masks, the label comparison and the scan for the
    # separator are all branch-free on the block; what is reported is
    # where the answer becomes public. Two things: the verdict, and the
    # message's length, which is the separator's position.
    ("rsa_oaep_decode", {"allcrypt::publickey_ciphers::rsa::oaep_verdict",
                         # The rest are the length: slicing at the
                         # separator, allocating and filling a vector that
                         # long (`unlikely` is the allocator's overflow
                         # check on the size), and freeing it. Generic
                         # names, as weak as `UnknownInlinedFun` on the
                         # rsa_private row - a new secret-length allocation
                         # inlined here would hide behind them.
                         "index<u8>", "to_vec<u8, alloc::alloc::Global>",
                         "alloc::raw_vec::RawVecInner<A>::try_allocate_in", "alloc",
                         "malloc", "memmove", "unlikely", "UnknownInlinedFun",
                         # The allocator's own size test, which a valgrind
                         # without the inlined frame's name reports under
                         # the allocator's symbol rather than `alloc`.
                         "__rustc::__rdl_alloc",
                         # The harness's side: the branch on success and
                         # the message's free, both of the output. Its own
                         # function so that neither is reported as `run`.
                         "ct_bignum::oaep_output"},
     "the one branch on the folded verdict - success or failure, which "
     "the caller learns anyway - and the message's length, the "
     "separator's position, as the returned vector is sliced, allocated, "
     "copied and freed. `oaep_verdict` is never inlined so that nothing "
     "else can hide behind its name: nothing reports inside the scan or "
     "the label comparison, which is what Manger's attack would need."),
    # EdDSA. Two leaks were found here and both are closed. The first
    # version's `multiply` iterated `scalar.bit_len()` times, announcing
    # the nonce's magnitude on every signature; then it ran a fixed count
    # but still branched on each bit, over BigUint. Signing now runs on
    # `ec::edwards` (fixed-limb fields, complete formulas, a four-bit
    # window read with masks) and does its arithmetic mod L with
    # `Montgomery` on `Secret`s. Replacing the masked table lookup with
    # an `if` makes this row report again.
    ("eddsa_sign", CLEAN,
     "Ed25519 signing: key expansion, both scalar multiplications by the "
     "base point, the reductions of the hashes mod L and S = r + k*s, "
     "with the private key secret."),
    ("ed448_sign", CLEAN,
     "the same for Ed448: SHAKE256 expansion, the 57 byte scalars and a "
     "context string, over field448."),
    ("xeddsa_sign", CLEAN,
     "XEdDSA signing in both forms, on the same arithmetic as Ed25519; the "
     "specification form's choice between the key and its negation is a "
     "mask."),
    # The Montgomery ladders, on the fixed-limb fields `ec::field25519`
    # and `ec::field448`. Both were BigUint ladders that swapped their
    # registers with an `if` on the scalar bit, under a comment saying
    # the swap was masked; neither had a row here, which is how that
    # survived.
    ("x25519", CLEAN,
     "the ladder, the masked swaps and the Fermat inversion, with the "
     "scalar secret and the point public."),
    ("x448", CLEAN,
     "the same ladder over 2^448 - 2^224 - 1, 448 iterations."),
    # `exchange` is the ladder plus the refusal of an all-zero secret.
    # That refusal is the verdict and may branch; it was `iter().all`,
    # whose early exit also said where the first non-zero byte was, and
    # reported from inside `all` rather than from `exchange`.
    ("x25519_exchange", {"allcrypt::ec::x25519::exchange"},
     "the verdict on the all-zero secret, and nothing before it."),
    ("x448_exchange", {"allcrypt::ec::x448::exchange"},
     "the same for X448."),
    # SM2's two rows, and they are **positive controls rather than
    # clean rows** - the honest classification of where this is.
    #
    # What has been fixed, both found by this harness: the nonce's
    # `k*G` and the private key's own `d*G` were going through
    # `Curve::scalar_mul`, which is double-and-add. The first gives up
    # the private key outright - `s = (1+d)^-1 (k - r d)` solves for
    # `d` given `k` - and the second runs a variable-time
    # multiplication on the key once per signature, because `Z_A` needs
    # the public key and signing derives it. `Curve::scalar_mul` no
    # longer appears in either row, which is what says both are closed.
    #
    # What is left is the arithmetic *around* the ladder, and it is all
    # `BigUint`: `(1 + d)^-1` by extended Euclid, `r*d`, and the
    # reductions mod n. Closing it means the `Secret`/`Montgomery`
    # treatment `ecdsa::sign` already got, which is a piece of work in
    # its own right. **Status: open** - docs/pitfalls.md section 7d.
    #
    # Listed as LEAKS rather than with a name set on purpose. A name set
    # here would have to hold thirty generic symbols (`alloc`, `index`,
    # `eq`) to pass, and a list like that names nothing - it would go
    # green for any new leak that allocated. The table's rule is named
    # leaks or none; this is none, said out loud.
    ("sm2_sign", LEAKS,
     "the signing equation is still BigUint: (1 + d)^-1 by extended "
     "Euclid, r*d, and the reductions mod n. k*G and d*G are on the "
     "ladder and Curve::scalar_mul does not appear, which is the part "
     "that matters; the rest is open."),
    ("sm2_decrypt", LEAKS,
     "d*C1 is the ladder on a Secret, but its coordinates leave as "
     "BigUint to be hashed, which normalises them - and they are "
     "secret, since the KDF over them is the keystream. The same shape "
     "as Curve::ecdh, which has no row here either."),
    ("dh_shared", {"allcrypt::publickey_ciphers::dh::DhGroup::shared_secret"},
     "the degenerate-value test. Three ct_eq masks are folded into one "
     "before anything branches, and the single branch decides whether to "
     "abort the handshake - which tells the peer anyway."),
    ("ecdsa_sign", {
        # The rejection test, folded to one mask and branched once. RFC 6979
        # rejection sampling is a branch on the candidate by construction.
        "allcrypt::ec::ecdsa::<impl allcrypt::ec::Curve>::sign",
        # The same test when `unmask`, the one function that turns a mask
        # into a bool, is not inlined into `sign`.
        "unmask",
        # The publication boundary: `r` and `s` are half a signature each and
        # the nonce's point leaves `ec::fixed` through `publish`, which
        # decides whether it is the identity and normalises its
        # coordinates. `normalise` and `UnknownInlinedFun` are that same
        # site, and `Secret::declassify`, under different inlining - see
        # the note on the rsa_private row.
        "allcrypt::ec::fixed::publish",
        "normalise", "UnknownInlinedFun",
        # The private key's *limb count*, read once per signature by
        # `Secret::from_biguint`. Unavoidable while the key arrives as a
        # BigUint, and the same on every call with the same key.
        "cmp",
        "is_some_and<core::cmp::Ordering, fn(core::cmp::Ordering) -> bool>",
        # Whether the nonce is below the order, which decides between the
        # base point's table and the general window: one bit, the same
        # on every call because a nonce that is not was already rejected.
        # `docs/pitfalls.md`, "The base point's table assumes a scalar
        # below the order".
        "allcrypt::ec::Curve::scalar_mul_secret_bytes",
     },
     "what is left: the RFC 6979 rejection test, the declassification of "
     "the nonce's point and of r and s, the private key's limb count, and "
     "the nonce-below-the-order test that chooses the base point's table. "
     "The field arithmetic and the nonce's magnitude are gone - k*G runs "
     "on ec::fixed and the nonce never becomes a BigUint."),
    # GOST R 34.10-2012 signing, on the same path as ECDSA: the nonce
    # from `next_bytes` into a Secret, k*G on ec::fixed, and
    # `s = r*d + k*e` in the Montgomery domain over n. It ran `r*d` and
    # `k*e` through BigUint's Knuth division - the private key and the
    # nonce as dividends, on every signature - under a comment calling
    # it the constant-time path, and had no row here, which is how that
    # survived. What the row names is the ECDSA set, plus one thing of
    # its own.
    ("gost_sign", {
        # The same sites as ecdsa_sign, argued there: the two folded
        # range tests (the key's once, the nonce's per candidate) and
        # the `unmask` they go through, the publication boundary for
        # the nonce's point and for r and s, the key's limb count, and
        # the base-point-table choice.
        "allcrypt::ec::gost3410::<impl allcrypt::ec::Curve>::gost_sign",
        "unmask",
        "allcrypt::ec::fixed::publish",
        "normalise", "UnknownInlinedFun",
        "cmp",
        "is_some_and<core::cmp::Ordering, fn(core::cmp::Ordering) -> bool>",
        "allcrypt::ec::Curve::scalar_mul_secret_bytes",
        # **Streebog's table lookups, on the private key.** RFC 6979
        # derives the nonce with HMAC over `int2octets(x)`, and the
        # hash here is Streebog, whose `lps` is a 256 entry table read
        # once per byte of state. The byte selecting the entry is a
        # function of the key, so the index is secret: a cache-timing
        # channel in the hash function rather than in the signer, of
        # the kind the AES rows measure. ecdsa_sign does not show it
        # because SHA-256 has no data-indexed table. Closing it means a
        # Streebog without table lookups on secret input; the row
        # names it so that a regression in the signer cannot hide
        # behind it. **Status: open** - the hash, not the signature
        # equation.
        "lps", "allcrypt::hash_functions::streebog::lps",
        # The same table read with `lps` inlined into its one caller,
        # `xlps`, which is the name some toolchains report it under
        # (streebog.rs's `lps` line, through `xlps`).
        "allcrypt::hash_functions::streebog::xlps",
     },
     "the ECDSA set - the rejection tests, the publication of the "
     "nonce's point and of r and s, the key's limb count and the "
     "base-point-table choice - and Streebog's S-box table indexed by "
     "bytes of the private key inside the RFC 6979 HMAC chain, which is "
     "open and belongs to the hash. The signing equation and the nonce's "
     "magnitude are gone from the list."),

    # ---- ML-KEM ------------------------------------------------------
    #
    # The secret parts of `dk` - `dk_pke` and `z` - are marked, and for
    # encapsulation the 32 byte `m`. Clean means: no branch and no index
    # anywhere in decryption, re-encryption, the FO comparison or the
    # choice between the two secrets.
    #
    # They were not clean on the first run. The public encode, compress
    # and decompress functions check every coefficient's range, which is
    # a branch per coefficient; on these paths the coefficients are
    # secret. K-PKE now calls `_unchecked` versions whose inputs are in
    # range by construction, and asserts that in debug builds.
    ("ml_kem_decaps", CLEAN,
     "decapsulation of an honest ciphertext: decryption, re-encryption, "
     "the folded comparison and the masked select."),
    ("ml_kem_decaps_reject", CLEAN,
     "the same with the ciphertext altered, so the implicit-rejection "
     "secret is chosen. Must look exactly like the row above."),
    ("ml_kem_encaps", CLEAN,
     "encapsulation with a secret m: G, the PRF, the CBD samples, the "
     "NTT and the compression of u and v."),
    ("ml_kem_compress_checked", {
        # The range check in the scalar `compress`, which valgrind names
        # by its bare inlined name with debug info, and by its path
        # without. The bare name is weak in the way the rsa_private note
        # describes - another `compress` would hide behind it - and this
        # row only exists to show the marking reaches ML-KEM at all.
        "compress", "allcrypt::pq::ml_kem::ring::compress",
        "allcrypt::pq::ml_kem::ring::Poly::compress"},
     "the control for the three rows above: the public, checked "
     "Poly::compress on a secret polynomial branches on each "
     "coefficient's range. If this comes back clean, so would a "
     "regression in the rows above."),

    # ---- ML-DSA signing ----------------------------------------------
    #
    # K, s1, s2 and t0 marked secret; mu public; rnd zero. Signing is a
    # rejection loop and FIPS 204 does not ask for it to be constant time
    # as a whole - the number of attempts is visible to anyone timing it.
    # What it must not reveal is anything about s1, s2 or t0 *beyond*
    # that. So this row names three places and argues each:
    #
    # The first run named more. Decompose's top-value test, the centred
    # reductions, the infinity norms and the hint count all branched on
    # secrets; they are arithmetic now, through `bignum::ct::opaque` so
    # the optimiser cannot turn them back - which it did once, to a
    # conditional move in Decompose, until the masks went through it.
    ("ml_dsa_sign", {
        # The rejection decision: one branch on whether the attempt is
        # kept. Its outcome is the attempt count, which timing reveals
        # anyway. `accepted` combines the four bounds with `&`, so which
        # bound failed is not separately visible.
        "sign_with", "allcrypt::pq::ml_dsa::sign_with",
        "allcrypt::pq::ml_dsa::sign_mu",
        # SampleInBall, on c-tilde: rejection sampling and writes indexed
        # by its output, by FIPS 204's design. c-tilde is a hash of mu and
        # of the high bits of w = A*y - the commitment, not the key - and
        # for the attempt that is returned it is the first field of the
        # signature. For rejected attempts it is never published; whether
        # its timing then matters is not something this table can settle,
        # and it is listed rather than argued away.
        "allcrypt::pq::ml_dsa::sample::sample_in_ball",
        # HintBitPack, which runs once, on the returned attempt's hint -
        # the last field of the signature.
        "allcrypt::pq::ml_dsa::encode::hint_bit_pack",
     },
     "the rejection decision, the challenge sampled from the commitment, "
     "and the packing of the published hint. Decompose, the centred "
     "reductions, the norms and the hint bits are branchless."),

    # ---- the variable-time path: these are the positive controls ------
    ("mod_inverse", LEAKS,
     "extended Euclid. The loop count is the continued-fraction expansion "
     "of the input; there is no way to make this constant time in place, "
     "which is why inverse_prime exists."),
    ("mod_pow_ct_biguint", LEAKS,
     "the exponentiation is clean and the final declassify() normalises the "
     "result, which is one branch on it. Expected, documented at "
     "Secret::declassify, and a control: if this ever comes back clean, "
     "either BigUint stopped normalising or the harness stopped working."),
    ("add", LEAKS,
     "BigUint::add decides whether to push a carry limb and then drops "
     "leading zeros. The representation is the leak, not the function."),
    ("mul", LEAKS, "same: the product is normalised."),
    ("cmp", LEAKS,
     "Ord on BigUint compares limb counts first and returns early. Secret "
     "deliberately has no Ord for this reason."),
    ("rem", LEAKS, "Knuth division: the quotient estimate loop branches."),
    ("mod_pow_public", LEAKS,
     "square-and-multiply skips the multiply on a zero bit, so the running "
     "time tracks the exponent's Hamming weight. Correct for public "
     "exponents and the reason pow_ct exists for the rest."),
    ("to_bytes", LEAKS,
     "BigUint::to_bytes_be scans for the first non-zero byte. Secret::"
     "to_bytes_be is the fixed-width one."),

    # ---- AES and GHASH ----------------------------------------------
    ("aes_blocks", CLEAN,
     "the bitsliced path: key schedule, sixteen-block, four-block and "
     "padded batches, both directions, secret key and data."),
    ("aes_block_table", LEAKS,
     "the one-block table path indexes TE and SBOX with state bytes. "
     "Documented in block_ciphers/aes.rs and docs/pitfalls.md, and the "
     "control for the AES rows: the same key and data through the "
     "bitsliced path must come back clean."),
    ("aes_gcm_seal", CLEAN,
     "AES-GCM encryption through api::aead_encrypt: H and the tag mask "
     "from encrypt_blocks, the batched keystream, and GHASH by integer "
     "multiplication."),
    ("aes_xts", {"allcrypt::api::xts_halves"},
     "XTS both ways with a ragged length: the tweak key, the batches and "
     "the stolen blocks all go through encrypt_blocks/decrypt_blocks, and "
     "the tweak doubling folds its reduction with a mask. The one report "
     "is the verdict of the key-halves check - an equal pair is refused, "
     "so the answer is public - after halves_differ has compared every "
     "byte. It found two leaks before it read this way: the comparison "
     "was `==`, which stops at the first differing byte, and the doubling "
     "branched on the tweak's top bit."),
    ("aes_ctr_cbc_decrypt", CLEAN,
     "CTR and multi-block CBC decryption through CipherStream and "
     "AnyBlockCipher, which must forward to the batch path."),
    ("ghash", CLEAN,
     "GHASH with a secret H and secret data: bmul64 and the reduction "
     "are multiplies, shifts and XORs."),

    # ---- ChaCha20 and Poly1305 --------------------------------------
    ("poly1305", CLEAN,
     "Poly1305 with a secret key and data: the four-block and one-block "
     "paths, the powers of r, and the final reduction, whose subtraction "
     "of p is a mask."),
    ("chacha20_poly1305_seal", CLEAN,
     "ChaCha20-Poly1305 encryption through api::aead_encrypt: the "
     "keystream is additions, rotations and XORs."),

    # ---- NaCl ---------------------------------------------------------
    ("secretbox_seal", CLEAN,
     "both secretbox constructions with a secret key and message: HSalsa20 "
     "and HChaCha20, the stream from byte 32, and Poly1305."),
    ("secretbox_open", {"allcrypt::nacl::secretbox_decrypt_detached"},
     "opening under a secret key; the only branch allowed is the verdict."),
    ("box_beforenm", {"allcrypt::ec::x25519::exchange"},
     "the box key from a secret X25519 private key, both H-functions; the "
     "only branch allowed is exchange's all-zero refusal, the verdict."),
]

REPORT = re.compile(r"^==\d+== [A-Z]")

# The innermost function name on a valgrind frame, without the line number.
# Names rather than counts, and names rather than file:line, because both of
# the others move for reasons that are not behaviour: the count is the number
# of *distinct stacks*, which changes when the optimiser inlines differently,
# and the line number changes when somebody edits the file above it. A
# regression adds a name.
# Only the **innermost** frame - valgrind's `at`. That is the instruction
# that branched; everything after it is the call stack down to `main`, most
# of which is Rust's runtime and appears in every report.
#
# A frame in a library valgrind preloads has no source line - `at 0x..:
# bcmp (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)` - and
# matched nothing here once, so its report counted and named nobody: a
# slice `==` on a secret, which is `bcmp`, the textbook variable-time
# comparison, passed a row that names its neighbours. Both forms match.
FRAME = re.compile(r"^==\d+==\s+at 0x[0-9A-Fa-f]+: (.+) \((?:[^()]*:\d+|in [^()]*)\)\s*$")


# **One function, two spellings.** rustc demangles a method one of two
# ways depending on the symbol-mangling scheme the toolchain uses: the
# legacy scheme writes `allcrypt::ec::ecdsa::<impl allcrypt::ec::Curve>::sign`
# (the module the `impl` block sits in, then the type), and the v0 scheme
# writes `<allcrypt::ec::Curve>::sign::<allcrypt::hash_functions::sha2::SHA256>`
# (the type, then the method, then its generic arguments). A toolchain
# that changed scheme turned every method name in this table into a
# "new" leak - `rsa_private`, `dh_shared` and `ecdsa_sign` all failed on
# the same sites they name, with nothing in the library changed - while
# free functions such as `normalise` and `unmask`, which both schemes
# spell alike, kept matching. Both sides of every comparison go through
# `canonical`, so a row is written once and holds under either.
IMPL_BLOCK = re.compile(r"^(?:[\w:]+::)?<impl ([^<> ]+)>::(.+)$")
BARE_TYPE = re.compile(r"^<([^<> ]+)>::(.+)$")


# **A valgrind that cannot demangle.** valgrind 3.18 (Ubuntu 22.04's)
# predates the v0 mangling scheme and prints those symbols raw -
# `_RNvNtNtCs5vfiX6lVPxq_8allcrypt2ec5fixed7publish` for
# `allcrypt::ec::fixed::publish` - so on such a machine no name in this
# table could match, and every row that names sites failed while the
# report counts were identical to a newer valgrind's. binutils, which the
# division scan already needs, has a demangler that reads both schemes;
# anything still mangled after it is a reason to stop, not a leak.
MANGLED = re.compile(r"^_(?:R|ZN)[0-9A-Za-z_$.]+$")
CRATE_HASH = re.compile(r"\[[0-9a-f]{16}\]")
LEGACY_HASH = re.compile(r"::h[0-9a-f]{16}$")


def demangled(names):
    """`{name: readable name}` for every name in `names`; a name valgrind
    already demangled maps to itself."""
    raw = sorted(name for name in names if MANGLED.match(name))
    result = {name: name for name in names}
    if not raw:
        return result
    if shutil.which("c++filt") is None:
        sys.exit("ct_check: valgrind printed mangled Rust names ({}) and "
                 "c++filt (binutils) is not installed to read them."
                 .format(raw[0]))
    out = subprocess.run(["c++filt"], input="\n".join(raw) + "\n",
                         capture_output=True, text=True, check=True).stdout.splitlines()
    for name, readable in zip(raw, out):
        readable = LEGACY_HASH.sub("", CRATE_HASH.sub("", readable.strip()))
        if MANGLED.match(readable):
            sys.exit("ct_check: valgrind printed {} mangled, and this c++filt "
                     "cannot demangle it either. A valgrind of 3.20 or later, "
                     "or binutils 2.37 or later, reads Rust's v0 symbols."
                     .format(name))
        result[name] = readable
    return result


def strip_trailing_generics(name):
    """`name` without a final `<...>` or `::<...>`, matched by counting
    brackets from the end. A regular expression cannot do it: a generic
    argument can be `fn(Ordering) -> bool`, whose `->` is not a bracket."""
    if not name.endswith(">"):
        return name
    depth = 0
    i = len(name) - 1
    while i >= 0:
        ch = name[i]
        if ch == ">" and not (i > 0 and name[i - 1] == "-"):
            depth += 1
        elif ch == "<":
            depth -= 1
            if depth == 0:
                head = name[:i]
                if head.endswith("::"):
                    head = head[:-2]
                # `<Type>::method` is not trailing generics: an opening
                # bracket at the very start belongs to the path.
                return head if head else name
        i -= 1
    return name


def canonical(name):
    """`Type::method` for a method in either demangling, with any trailing
    generic arguments dropped; anything else unchanged. A trait method,
    `<Type as Trait>::method`, is spelled the same way by both schemes
    and is left alone."""
    name = strip_trailing_generics(name.strip())
    for pattern in (IMPL_BLOCK, BARE_TYPE):
        match = pattern.match(name)
        if match:
            return "{}::{}".format(match.group(1), match.group(2))
    return name


def canonical_self_test():
    """The pairs this was written for, so a third spelling - or an edit
    that breaks one of these - fails here rather than as a leak report
    nobody can explain."""
    same = [
        ("allcrypt::ec::ecdsa::<impl allcrypt::ec::Curve>::sign",
         "<allcrypt::ec::Curve>::sign::<allcrypt::hash_functions::sha2::SHA256>"),
        ("allcrypt::publickey_ciphers::rsa::RsaPrivateKey::raw",
         "<allcrypt::publickey_ciphers::rsa::RsaPrivateKey>::raw"),
        ("allcrypt::ec::Curve::scalar_mul_secret_bytes",
         "<allcrypt::ec::Curve>::scalar_mul_secret_bytes"),
        ("is_some_and<core::cmp::Ordering, fn(core::cmp::Ordering) -> bool>",
         "is_some_and::<core::cmp::Ordering, fn(core::cmp::Ordering) -> bool>"),
    ]
    different = [
        ("allcrypt::ec::Curve::sign", "allcrypt::ec::Curve::gost_sign"),
        ("<allcrypt::ec::Curve as core::fmt::Debug>::fmt", "allcrypt::ec::Curve::fmt"),
        ("normalise", "unmask"),
    ]
    if shutil.which("c++filt") is not None:
        # Symbols as valgrind 3.18 prints them, from a real run.
        same += [
            ("allcrypt::ec::ecdsa::<impl allcrypt::ec::Curve>::sign",
             demangled(["_RINvMs0_NtNtCs5vfiX6lVPxq_8allcrypt2ec5ecdsaNtB8_5Curve4sign"
                        "NtNtNtBa_14hash_functions4sha26SHA256ECsjQDPo3FSvkt_9ct_bignum"])
             ["_RINvMs0_NtNtCs5vfiX6lVPxq_8allcrypt2ec5ecdsaNtB8_5Curve4sign"
              "NtNtNtBa_14hash_functions4sha26SHA256ECsjQDPo3FSvkt_9ct_bignum"]),
            ("allcrypt::ec::fixed::publish",
             demangled(["_RNvNtNtCs5vfiX6lVPxq_8allcrypt2ec5fixed7publish"])
             ["_RNvNtNtCs5vfiX6lVPxq_8allcrypt2ec5fixed7publish"]),
        ]
    for a, b in same:
        if canonical(a) != canonical(b):
            sys.exit("ct_check: {!r} and {!r} name one function and no longer "
                     "match ({!r} against {!r}).".format(a, b, canonical(a), canonical(b)))
    for a, b in different:
        if canonical(a) == canonical(b):
            sys.exit("ct_check: {!r} and {!r} are different functions and "
                     "now match as {!r}.".format(a, b, canonical(a)))


def build():
    """Release build with debug info, so the reports name a line."""
    env = dict(os.environ, CARGO_PROFILE_RELEASE_DEBUG="2")
    command = ["cargo", "build", "--release", "-p", "allcrypt-tools", "--bin", "ct_bignum"]
    if AES_NI:
        command += ["--features", "aes-ni", "--target-dir", os.path.join(ROOT, "target", "aes-ni")]
    if os.environ.get("CARGO_NET_OFFLINE") == "true" or "--offline" in sys.argv:
        command.append("--offline")
    result = subprocess.run(command, cwd=ROOT, env=env)
    if result.returncode != 0:
        sys.exit("ct_check: the harness did not build.")


def sites(text):
    """The set of functions that actually branched on a secret.

    One name per report: valgrind's innermost `at` frame. The stack under
    it is the way down to `main` and is the same in every report, and the
    "Uninitialised value was created by" block that `--track-origins`
    appends has an `at` frame of its own - the harness's own `classify` -
    which is where the secret was *marked*, not where it leaked.
    """
    found = set()
    collecting = False
    for line in text.splitlines():
        if REPORT.match(line):
            collecting = True
            continue
        if "was created by" in line:
            collecting = False
            continue
        if not collecting:
            continue
        match = FRAME.match(line)
        if match:
            found.add(match.group(1).strip())
            collecting = False        # only the innermost frame
    readable = demangled(found)
    return {readable[name] for name in found}


def run(case):
    """Returns (report_count, the reports as text)."""
    proc = subprocess.run(
        ["valgrind", "-q", "--track-origins=yes", BINARY, case],
        cwd=ROOT, capture_output=True, text=True,
    )
    if proc.returncode not in (0,):
        # The harness itself failed - an unknown case, a panic. That is not a
        # clean result, it is no result.
        sys.exit("ct_check: case {!r} exited {}:\n{}"
                 .format(case, proc.returncode, proc.stderr[:2000]))
    reports = [line for line in proc.stderr.splitlines() if REPORT.match(line)]
    return len(reports), proc.stderr


def list_check():
    """The harness's own list of cases against this table. A case written
    in the harness and left out of the table is never run; one in the
    table and not the harness fails as an unknown case. The harness's
    list had fallen two rows behind before this check."""
    listed = subprocess.run([BINARY, "--list"], capture_output=True, text=True,
                            check=True).stdout.split()
    table = [name for name, _, _ in CASES]
    if sorted(listed) != sorted(table):
        sys.exit("ct_check: the harness and the table list different cases.\n"
                 "  only in the harness: {}\n  only in the table: {}".format(
                     sorted(set(listed) - set(table)), sorted(set(table) - set(listed))))


def self_test():
    """
    Prove the marking reaches valgrind before believing any CLEAN row.

    Without this, a build where the client requests do nothing - a different
    architecture, a valgrind that does not recognise them - reports every
    case clean and the whole run is a green light for nothing.
    """
    proc = subprocess.run(["valgrind", "-q", BINARY, "--self-test"],
                          cwd=ROOT, capture_output=True, text=True)
    if "not under valgrind" in proc.stdout:
        sys.exit("ct_check: the harness did not see valgrind. The client "
                 "requests are not working, so every result would be "
                 "meaningless.")
    if not any(REPORT.match(line) for line in proc.stderr.splitlines()):
        sys.exit("ct_check: the self-test branched on a value marked secret "
                 "and valgrind said nothing. Marking is not working; no "
                 "CLEAN result below would mean anything.")


#: Source files whose code runs on secrets, and from which no division may
#: come. Valgrind cannot see this: a `div` is not a branch, but its
#: latency depends on its operands on many processors, and a division on a
#: secret in ML-KEM is the KyberSlash leak. `byte_decode` had one - `value
#: % modulus` with the modulus chosen at run time - until the first
#: version of this scan, which covered ML-KEM and ML-DSA by symbol name.
#:
#: Attribution is by the debug line table's whole inline chain
#: (`addr2line -i`), not by the enclosing symbol: much of this code is
#: inlined into the harness's own `run`, and a `div_ceil` written here is
#: inlined from the standard library and attributed to `core` by its
#: innermost frame. A division is charged to every listed file anywhere in
#: its chain.
CONSTANT_TIME_SOURCES = re.compile(
    r"(^|/)src/(bignum/(ct|montgomery|fixed)"
    r"|ec/(fixed|ct|field25519|field448|edwards|x25519|x448|eddsa|xeddsa|ecdsa)"
    r"|mac/poly1305|stream_ciphers/(chacha|chacha_simd|salsa20|chacha20poly1305)"
    r"|block_ciphers/(aes|aes_ni|ghash|gcm)|nacl"
    r"|pq/ml_(kem|dsa)(/[a-z_0-9]+)?"
    r"|publickey_ciphers/(rsa|dh))\.rs:\d+")

#: Divisions in those files that are on public values, each with the
#: source text that identifies it and the reason. Matched against the
#: line's text rather than its number, so an edit above it does not
#: invalidate the entry; a division that matches nothing here fails.
PUBLIC_DIVISIONS = [
    ("src/bignum/montgomery.rs", "table.chunks_exact(k)",
     "the table's length over the limb count: both are the modulus's "
     "width, which is public."),
    ("src/block_ciphers/aes.rs", "if i % nk == 0",
     "the key schedule's word index modulo the key's length in words, "
     "neither of which is secret. The `i % nk == 4` below it reuses the "
     "remainder."),
    ("src/ec/eddsa.rs", "bytes.chunks(width)",
     "the hash's length over the group order's width in bytes: a "
     "64 or 114 byte digest split into fixed-width pieces."),
]

#: Somewhere a division is known to be, so that a scan which finds none
#: in the files above is known to be able to find one at all: a function
#: in the harness that does nothing but divide two run-time values.
DIVISION_CONTROL = "tools/src/bin/ct_bignum.rs"

#: A division too wide for one instruction is a call into the compiler's
#: runtime instead, and is the same leak.
DIVISION = re.compile(r"\t(i?div)\s|<__(u?)(div|mod)[dt]i3>")
ADDRESS = re.compile(r"^\s*([0-9a-f]+):")
LOCATION = re.compile(r"^(.*?):(\d+)(?: \(discriminator \d+\))?$")


def inline_chains(addresses):
    """`{address: [(function, file, line), ...]}`, innermost frame first."""
    chains = {}
    addresses = sorted(addresses)
    for start in range(0, len(addresses), 500):
        batch = addresses[start:start + 500]
        out = subprocess.run(["addr2line", "-a", "-i", "-f", "-C", "-e", BINARY]
                             + ["0x" + a for a in batch],
                             capture_output=True, text=True, check=True).stdout
        current = None
        lines = out.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("0x"):
                current = format(int(line, 16), "x")
                chains[current] = []
                i += 1
                continue
            function = line
            location = lines[i + 1] if i + 1 < len(lines) else "??:0"
            match = LOCATION.match(location)
            file, number = (match.group(1), int(match.group(2))) if match else (location, 0)
            chains[current].append((function, file, number))
            i += 2
    return chains


def source_line(file, number):
    try:
        with open(os.path.join(ROOT, file)) as handle:
            return handle.read().splitlines()[number - 1].strip()
    except (OSError, IndexError):
        return ""


def division_scan():
    """Fail if a division in the harness binary comes from code that runs
    on secrets, other than the public ones listed with their reasons."""
    for tool in ("objdump", "addr2line"):
        if shutil.which(tool) is None:
            sys.exit("ct_check: {} is not installed (binutils). See "
                     "docs/building.md.".format(tool))
    text = subprocess.run(["objdump", "-d", "--no-show-raw-insn", BINARY],
                          capture_output=True, text=True, check=True).stdout
    divisions = [ADDRESS.match(line).group(1) for line in text.splitlines()
                 if DIVISION.search(line) and ADDRESS.match(line)]
    chains = inline_chains(divisions)
    control = 0
    offending = []
    allowed_seen = set()
    for address in divisions:
        chain = chains.get(address, [])
        if any(file.endswith(DIVISION_CONTROL) for _, file, _ in chain):
            control += 1
            continue
        for function, file, number in chain:
            located = "{}:{}".format(file, number)
            if not CONSTANT_TIME_SOURCES.search(located):
                continue
            text_here = source_line(file, number)
            allowed = [i for i, (name, fragment, _) in enumerate(PUBLIC_DIVISIONS)
                       if file.endswith(name) and fragment in text_here]
            if allowed:
                allowed_seen.update(allowed)
            else:
                offending.append("{} in {}\n        {}".format(
                    located[located.find("src/"):], function, text_here))
    if control == 0:
        sys.exit("ct_check: the division scan found no division in the "
                 "harness's control function. The scan is not reading the "
                 "disassembly, so a clean result would mean nothing.")
    if offending:
        sys.exit("ct_check: division on a constant-time path (a division "
                 "whose operands are public belongs in PUBLIC_DIVISIONS with "
                 "its reason):\n    " + "\n    ".join(sorted(set(offending))))
    stale = [PUBLIC_DIVISIONS[i][:2] for i in range(len(PUBLIC_DIVISIONS))
             if i not in allowed_seen]
    print("division scan: {} divisions in the binary, none on a constant-time "
          "path; {} public ones listed and found{}; {} in the control"
          .format(len(divisions), len(allowed_seen),
                  ", {} listed and not found: {}".format(len(stale), stale) if stale else "",
                  control))


def main():
    if shutil.which("valgrind") is None:
        sys.exit("ct_check: valgrind is not installed. See docs/building.md.")
    canonical_self_test()
    build()
    list_check()
    self_test()
    division_scan()

    wanted = [c for c in sys.argv[1:] if not c.startswith("-")]
    cases = CASES
    if AES_NI:
        cases = [(name, CLEAN, "with the aes-ni feature the one-block path is "
                  "aesenc, which takes the same time for every key and block")
                 if name == "aes_block_table" else (name, expectation, why)
                 for name, expectation, why in CASES]
    table = [row for row in cases if not wanted or row[0] in wanted]
    if wanted and not table:
        sys.exit("ct_check: no such case: {}".format(", ".join(wanted)))

    failures = []
    for case, expectation, why in table:
        count, text = run(case)
        extra = set()
        if isinstance(expectation, set):
            # It must leak - a clean result here means the harness stopped
            # looking - and every place it leaks must be named.
            named = {canonical(name) for name in expectation}
            extra = {name for name in sites(text) if canonical(name) not in named}
            ok = count > 0 and not extra
            label = "only the named"
        else:
            ok = (LEAKS if count else CLEAN) == expectation
            label = expectation
        print("{:<22} {:>3} report(s)  expected {:<16} {}"
              .format(case, count, label, "ok" if ok else "FAIL"))
        if not ok:
            failures.append((case, expectation, count, why, text, extra))
        elif wanted and count:
            # A row that passes shows its reports only when it was asked
            # for by name. `wanted` once doubled as the label above, so by
            # here it was always a non-empty string and a whole-table run
            # printed every passing row's reports - some fourteen thousand
            # lines, with the verdicts lost among them.
            print(text)

    if failures:
        print()
        for case, expectation, count, why, text, extra in failures:
            if isinstance(expectation, set):
                if count == 0:
                    print("{}: this leaks in places that are listed, and it "
                          "reported nothing.".format(case))
                    print("  The harness has stopped measuring. Expected: {}"
                          .format(why))
                else:
                    print("{}: leaks somewhere that is not accounted for."
                          .format(case))
                    for name in sorted(extra):
                        print("    new: {}".format(name))
                    print("  The accounted ones: {}".format(why))
                    print(indent(text))
                continue
            if expectation is CLEAN:
                print("{}: expected constant time, got {} report(s)."
                      .format(case, count))
                print("  {}".format(why))
                print(indent(text))
            elif expectation is LEAKS:
                print("{}: expected this to be variable time and it reported "
                      "nothing.".format(case))
                print("  {}".format(why))
                print("  Either the code was fixed - in which case move the "
                      "row to CLEAN and say so in the commit - or the harness "
                      "has stopped measuring anything.")
            elif count > expectation:
                print("{}: {} reports, and only {} are accounted for."
                      .format(case, count, expectation))
                print("  The accounted ones: {}".format(why))
                print(indent(text))
            else:
                print("{}: {} reports where {} were expected. Something was "
                      "fixed.".format(case, count, expectation))
                print("  The old accounting: {}".format(why))
                print("  Lower the number and say in the commit which one "
                      "went, or the next regression will hide under the "
                      "slack.")
        sys.exit(1)

    print()
    exact = [r for r in table if isinstance(r[1], set)]
    print("{} cases: {} constant time, {} leaking only where named, "
          "{} variable time and known to be."
          .format(len(table),
                  sum(1 for r in table if r[1] is CLEAN),
                  len(exact),
                  sum(1 for r in table if r[1] is LEAKS)))


def indent(text):
    return "\n".join("    " + line for line in text.splitlines()[:40])


if __name__ == "__main__":
    main()
