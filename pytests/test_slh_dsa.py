"""SLH-DSA (FIPS 205) through the Python bindings.

The bindings are translation only - every byte of the scheme is in
`src/pq/slh_dsa.rs` and checked there against all 264 of NIST's ACVP
vectors. So what these tests are for is the *surface*: that the arguments
mean what the docstrings say, that the defaults are the safe ones, and
that the thing a Python caller reaches for produces the same bytes the
Rust side does.

**One of them reads NIST's vectors directly**, rather than only round
tripping. A round trip through one implementation agrees with itself
whatever it got wrong, and there is no second implementation of SLH-DSA on
this machine to differ against - not python-cryptography, and not OpenSSL
3.0. So `test_the_bindings_produce_nists_signatures` parses
`vectors/slh_dsa.vec` and compares, which makes these tests independent of
the Rust ones rather than a restatement of them.

Only the fast parameter sets: a key at the `s` sets is a second and a
signature is several, and `docs/post-quantum.md` has the measurements.
"""

import hashlib
import pathlib

import pytest

import allcrypt

FAST = "SLH-DSA-SHAKE-128f"
VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "slh_dsa.vec"


def _sections():
    """`(mode, parameter_set, count, [case])` for every section in the file.

    A small reimplementation of the reader in `tests/test_slh_dsa.rs`,
    deliberately: a Python test that imported the Rust reader's answer
    would be testing the bindings against the same parse, and the point
    here is to reach NIST's numbers by a second route.
    """
    out = []
    current = None
    case = {}
    for line in VECTORS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            if case:
                out[-1][3].append(case)
                case = {}
            mode, parameter_set, count = line[1:-1].split()
            out.append((mode, parameter_set, int(count), []))
            continue
        key, _, value = line.partition(" =")
        value = value.strip()
        if key == "tcId" and case:
            out[-1][3].append(case)
            case = {}
        case[key] = value
    if case:
        out[-1][3].append(case)
    return out


@pytest.fixture(scope="module")
def sections():
    found = _sections()
    # The same count assertion the Rust reader makes, and for the same
    # reason: a parse that silently found nothing would turn every loop
    # below into a pass.
    assert len(found) == 84, "twelve keyGen sections and seventy-two sigGen"
    for mode, parameter_set, count, cases in found:
        assert len(cases) == count, f"{mode} {parameter_set}"
    return found


@pytest.fixture(scope="module")
def key():
    return allcrypt.SlhDsaKey.generate(FAST)


def test_the_parameter_sets_are_the_twelve_fips_205_approves():
    names = allcrypt.slh_dsa_parameter_sets()
    assert len(names) == 12
    assert len(set(names)) == 12
    for level in ("128", "192", "256"):
        for family in ("SHA2", "SHAKE"):
            for shape in ("s", "f"):
                assert f"SLH-DSA-{family}-{level}{shape}" in names


def test_the_pre_hashes_are_the_twelve_fips_205_approves():
    names = allcrypt.slh_dsa_pre_hashes()
    assert names == ["SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
                     "SHA2-512/224", "SHA2-512/256", "SHA3-224", "SHA3-256",
                     "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256"]


def test_a_generated_key_has_the_documented_shape(key):
    assert key.parameter_set == FAST
    assert len(key.private_bytes()) == 64
    assert len(key.public_bytes()) == 32
    # The public key is the tail of the private one, which a caller
    # writing a key file needs to know.
    assert key.private_bytes()[32:] == key.public_bytes()
    assert key.public_key().public_bytes() == key.public_bytes()
    assert "SLH-DSA-SHAKE-128f" in repr(key)


def test_two_generated_keys_differ(key):
    other = allcrypt.SlhDsaKey.generate(FAST)
    assert other.private_bytes() != key.private_bytes()


def test_a_key_round_trips_through_its_bytes(key):
    again = allcrypt.SlhDsaKey.from_private(FAST, key.private_bytes())
    assert again.private_bytes() == key.private_bytes()
    # And the imported key signs what the original verifies.
    assert key.verify(b"a message", again.sign(b"a message"))


def test_an_imported_private_key_can_be_checked_against_its_own_seeds(key):
    assert key.recompute_public() is True

    # A private key whose public root does not match its seeds is well
    # formed and importable - there is nothing in the length to object to
    # - so `recompute_public` is the only thing that says so.
    broken = bytearray(key.private_bytes())
    broken[-1] ^= 1
    assert allcrypt.SlhDsaKey.from_private(FAST, bytes(broken)) \
        .recompute_public() is False


def test_the_wrong_length_is_refused_rather_than_padded(key):
    for length in (0, 63, 65):
        with pytest.raises(ValueError, match="private key is 64 bytes"):
            allcrypt.SlhDsaKey.from_private(FAST, b"\x00" * length)
    for length in (0, 31, 33):
        with pytest.raises(ValueError, match="public key is 32 bytes"):
            allcrypt.SlhDsaPublicKey.from_public(FAST, b"\x00" * length)


def test_an_unknown_name_is_refused_with_the_alternatives(key):
    with pytest.raises(ValueError, match="Unknown SLH-DSA parameter set"):
        allcrypt.SlhDsaKey.generate("SPHINCS+-SHAKE-128f")
    with pytest.raises(ValueError, match="Unknown pre-hash"):
        key.sign(b"m", prehash="SHA-256")
    # A misspelt pre-hash must not fall back to the pure form: that would
    # be a signature under a different domain separator than the caller
    # asked for.
    with pytest.raises(ValueError):
        key.verify(b"m", key.sign(b"m"), prehash="sha2-256")


def test_signing_is_hedged_by_default_and_deterministic_on_request(key):
    once = key.sign(b"a message")
    twice = key.sign(b"a message")
    assert once != twice, "the default should draw fresh randomness"
    assert key.verify(b"a message", once)
    assert key.verify(b"a message", twice)

    fixed = key.sign_deterministic(b"a message")
    assert fixed == key.sign_deterministic(b"a message")
    assert fixed not in (once, twice)
    assert key.verify(b"a message", fixed)


def test_a_signature_is_refused_for_anything_it_does_not_cover(key):
    signature = key.sign(b"a message", b"context", prehash="SHA2-256")

    assert key.verify(b"a message", signature, b"context", prehash="SHA2-256")
    # Each of the four inputs, changed one at a time.
    assert not key.verify(b"other", signature, b"context", prehash="SHA2-256")
    assert not key.verify(b"a message", signature, b"other", prehash="SHA2-256")
    assert not key.verify(b"a message", signature, b"context", prehash="SHA3-256")
    assert not key.verify(b"a message", signature, b"context")

    # And a different key.
    assert not allcrypt.SlhDsaKey.generate(FAST).verify(
        b"a message", signature, b"context", prehash="SHA2-256")

    # A truncated or lengthened signature is False, not an exception: a
    # caller handed a corrupt signature wants "did not verify".
    assert not key.verify(b"a message", signature[:-1], b"context",
                          prehash="SHA2-256")
    assert not key.verify(b"a message", signature + b"\x00", b"context",
                          prehash="SHA2-256")


def test_a_context_over_255_bytes_is_refused_rather_than_truncated(key):
    assert key.verify(b"m", key.sign(b"m", b"x" * 255), b"x" * 255)
    with pytest.raises(ValueError, match="at most 255 bytes"):
        key.sign(b"m", b"x" * 256)
    with pytest.raises(ValueError, match="at most 255 bytes"):
        key.verify(b"m", b"\x00" * 100, b"x" * 256)


def test_every_pre_hash_signs_and_verifies_only_as_itself(key):
    signatures = {name: key.sign_deterministic(b"a message", prehash=name)
                  for name in allcrypt.slh_dsa_pre_hashes()}
    # Twelve distinct signatures: the hash function's OID is part of what
    # gets signed, so no two agree even where the digests are the same
    # length.
    assert len(set(signatures.values())) == 12

    for name, signature in signatures.items():
        for other in signatures:
            assert key.verify(b"a message", signature, prehash=other) \
                == (name == other), f"{name} signature under {other}"


def test_a_public_key_verifies_without_the_private_half(key):
    public = allcrypt.SlhDsaPublicKey.from_public(FAST, key.public_bytes())
    assert public.parameter_set == FAST
    assert public.public_bytes() == key.public_bytes()
    assert "SLH-DSA-SHAKE-128f" in repr(public)

    signature = key.sign(b"a message", b"ctx")
    assert public.verify(b"a message", signature, b"ctx")
    assert not public.verify(b"a message", signature, b"other")
    assert not hasattr(public, "sign")


def test_the_bindings_produce_nists_signatures(sections):
    """The whole independent check, and the reason this file is not a round trip.

    NIST's `sigGen` cases state a private key, a message and - for the
    external sections - a context and optionally a pre-hash. The vector
    file keeps each signature's SHA-256 rather than its bytes, which is
    enough: a deterministic signature has one right answer.

    Restricted to the fast parameter sets, which is what keeps this in the
    seconds rather than the minutes.
    """
    checked = 0
    algorithms = set()
    for mode, parameter_set, _count, cases in sections:
        if not parameter_set.endswith("f"):
            continue
        # **Two whole families of case are unreachable from Python, both on
        # purpose.** The `internal` sections are FIPS 205's internal
        # interface, which the bindings do not expose - a signature made
        # with it is not one another implementation's default verifier
        # accepts, so the facade offers only the external interface. And
        # the `hedged` sections state the `opt_rand` the signer used, which
        # the bindings draw themselves rather than accept, because an
        # argument for it is an invitation to pass a counter.
        #
        # Both are covered against NIST by `tests/test_slh_dsa.rs`, which
        # calls the layer underneath. Skipping them here is a statement
        # about the surface rather than a gap in the checking.
        if not mode.startswith("sigGen-external") or mode.endswith("hedged"):
            continue
        external = True
        for case in cases:
            key = allcrypt.SlhDsaKey.from_private(
                parameter_set, bytes.fromhex(case["sk"]))
            message = bytes.fromhex(case["message"])
            context = bytes.fromhex(case.get("context", "")) if external else b""
            prehash = case.get("hashAlg") or None
            if prehash:
                algorithms.add(prehash)

            signature = key.sign_deterministic(message, context, prehash)
            assert len(signature) == int(case["signatureLength"])
            assert signature[:256].hex().upper() == case["signaturePrefix"]
            assert hashlib.sha256(signature).hexdigest().upper() \
                == case["signatureDigest"], \
                f"{mode} {parameter_set} tcId {case['tcId']}"

            # Our own verifier on bytes that are now known to be NIST's.
            assert key.verify(message, signature, context, prehash)
            checked += 1

    assert checked == 18, ("the fast external deterministic cases: twelve "
                           "pre-hash, at two per parameter set, and six pure")

    # **Nine of the twelve, not all twelve**, and the number is measured
    # rather than hoped for: ACVP varies `hashAlg` per test, and the
    # deterministic half of the fast pre-hash groups happens to carry nine
    # of them. The other three - SHA2-384, SHA3-512, SHAKE-256 - are
    # reached against NIST's bytes by `tests/test_slh_dsa.rs`, which also
    # runs the hedged cases, and through *these bindings* by
    # `test_every_pre_hash_signs_and_verifies_only_as_itself` above, which
    # exercises all twelve without an external answer to compare to.
    #
    # So: twelve exercised through Python, nine of them against NIST from
    # Python, twelve against NIST from Rust. Asserting the exact set means
    # a change to the vector file's caps shows up here as a failure rather
    # than as quietly less coverage.
    assert sorted(algorithms) == [
        "SHA2-224", "SHA2-256", "SHA2-512", "SHA2-512/224", "SHA2-512/256",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHAKE-128",
    ], sorted(algorithms)


SIGVER = VECTORS.parent / "slh_dsa_sigver.vec"


def test_the_bindings_refuse_what_nist_refuses():
    """NIST's external `sigVer` cases through `SlhDsaPublicKey.verify`.

    Every other test here can only show that good signatures verify; these
    include signatures ACVP altered on purpose - the message, `R`, the
    FORS signature, the hypertree signature, one byte short, one byte
    long - and the bindings must return `False` for each, not raise. The
    internal-interface sections are skipped because the bindings do not
    expose that interface.

    Parsed here rather than through the Rust reader, for the same reason
    `_sections` is.
    """
    sections = []
    case = None
    for line in SIGVER.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            interface, parameter_set, count = line[1:-1].split()
            sections.append((interface, parameter_set, int(count), []))
            continue
        key, _, value = line.partition(" =")
        if key == "tcId":
            case = {}
            sections[-1][3].append(case)
        case[key] = value.strip()
    assert len(sections) == 6
    for interface, parameter_set, count, cases in sections:
        assert len(cases) == count == 7, f"{interface} {parameter_set}"

    refused = {}
    checked = 0
    for interface, parameter_set, _count, cases in sections:
        if interface == "sigVer-internal":
            continue
        for case in cases:
            public = allcrypt.SlhDsaPublicKey.from_public(
                parameter_set, bytes.fromhex(case["pk"]))
            prehash = case.get("hashAlg") if interface.endswith("preHash") \
                else None
            got = public.verify(bytes.fromhex(case["message"]),
                                bytes.fromhex(case["signature"]),
                                bytes.fromhex(case["context"]), prehash)
            want = case["testPassed"] == "true"
            assert got is want, (f"{parameter_set} {interface} tcId "
                                 f"{case['tcId']}: {case['reason']}")
            if not want:
                refused[case["reason"]] = refused.get(case["reason"], 0) + 1
            checked += 1
    assert checked == 28
    # Six refusal reasons, each from four external sections.
    assert sorted(refused.values()) == [4] * 6, refused
