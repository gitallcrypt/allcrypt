"""ML-DSA (FIPS 204) through the Python bindings.

Translation only - the scheme is in `src/pq/ml_dsa/` and checked against
NIST's ACVP vectors there. These tests read the same vector files through
their own parser, so the bindings are held to NIST's numbers by a second
route rather than to the Rust tests' reading of them.

What the bindings reach: the external interface, pure and pre-hash,
hedged and deterministic. The internal interface and the external-`mu`
variant are Rust-only, so those sections are skipped here.
"""

import hashlib
import pathlib

import pytest

import allcrypt

ROOT = pathlib.Path(__file__).resolve().parent.parent
SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


def _read(name):
    """`[(mode, parameter_set, [case])]`, each section's count asserted."""
    sections = []
    declared = []
    case = None
    for line in (ROOT / "vectors" / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            mode, parameter_set, count = line[1:-1].split()
            sections.append((mode, parameter_set, []))
            declared.append(int(count))
            continue
        key, _, value = line.partition(" =")
        if key == "tcId":
            case = {}
            sections[-1][2].append(case)
        case[key] = value.strip()
    for (mode, parameter_set, cases), count in zip(sections, declared):
        assert len(cases) == count, f"{mode} {parameter_set}"
    return sections


@pytest.fixture(scope="module")
def vectors():
    sections = _read("ml_dsa.vec")
    assert sum(len(c) for _m, _p, c in sections) == 147
    return sections


@pytest.fixture(scope="module")
def sigver():
    sections = _read("ml_dsa_sigver.vec")
    assert sum(len(c) for _m, _p, c in sections) == 60
    return sections


def _digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def test_parameter_sets():
    assert allcrypt.ml_dsa_parameter_sets() == SETS


def test_from_seed_gives_nists_keys(vectors):
    checked = 0
    for mode, parameter_set, cases in vectors:
        if mode != "keyGen":
            continue
        for case in cases:
            key = allcrypt.MlDsaKey.from_seed(parameter_set,
                                              bytes.fromhex(case["seed"]))
            assert _digest(key.public_bytes()) == case["pkDigest"]
            assert _digest(key.private_bytes()) == case["skDigest"]
            assert key.seed() == bytes.fromhex(case["seed"])
            checked += 1
    assert checked == 75


def test_deterministic_signatures_are_nists(vectors):
    """NIST's deterministic external signatures, from NIST's private keys.

    `from_private` recomputes the public key, so this also checks that
    each of NIST's private keys is self-consistent by our reading.
    """
    algorithms = set()
    checked = 0
    for mode, parameter_set, cases in vectors:
        if not (mode.startswith("sigGen-external")
                and mode.endswith("-deterministic")):
            continue
        for case in cases:
            key = allcrypt.MlDsaKey.from_private(parameter_set,
                                                 bytes.fromhex(case["sk"]))
            prehash = case.get("hashAlg")
            message = bytes.fromhex(case["message"])
            context = bytes.fromhex(case["context"])
            signature = key.sign_deterministic(message, context, prehash)
            assert len(signature) == int(case["signatureLength"])
            assert _digest(signature) == case["signatureDigest"], case["tcId"]
            assert key.verify(message, signature, context, prehash)
            if prehash:
                algorithms.add(prehash)
            checked += 1
    assert checked == 18
    assert len(algorithms) >= 6, sorted(algorithms)


def test_the_bindings_refuse_what_nist_refuses(sigver):
    refused = {}
    checked = 0
    for mode, parameter_set, cases in sigver:
        if not mode.startswith("sigVer-external"):
            continue
        for case in cases:
            public = allcrypt.MlDsaPublicKey.from_public(
                parameter_set, bytes.fromhex(case["pk"]))
            got = public.verify(bytes.fromhex(case["message"]),
                                bytes.fromhex(case["signature"]),
                                bytes.fromhex(case["context"]),
                                case.get("hashAlg"))
            want = case["testPassed"] == "true"
            assert got is want, f"{parameter_set} {mode} {case['reason']}"
            if not want:
                refused[case["reason"]] = refused.get(case["reason"], 0) + 1
            checked += 1
    assert checked == 30
    assert sorted(refused.values()) == [6] * 4, refused


@pytest.mark.parametrize("parameter_set", SETS)
def test_round_trip(parameter_set):
    key = allcrypt.MlDsaKey.generate(parameter_set)
    signature = key.sign(b"message", b"ctx")
    public = key.public_key()
    assert public.verify(b"message", signature, b"ctx")
    assert not public.verify(b"message", signature, b"other")
    assert not public.verify(b"message", signature[:-1], b"ctx")
    assert key.sign(b"message") != key.sign(b"message"), "hedged"
    assert key.sign_deterministic(b"m") == key.sign_deterministic(b"m")


def test_an_inconsistent_private_key_is_refused():
    key = allcrypt.MlDsaKey.generate("ML-DSA-44")
    private = bytearray(key.private_bytes())
    private[64] ^= 1                                  # tr
    with pytest.raises(ValueError, match="tr is not"):
        allcrypt.MlDsaKey.from_private("ML-DSA-44", bytes(private))
    assert allcrypt.MlDsaKey.from_private(
        "ML-DSA-44", key.private_bytes()).public_bytes() == key.public_bytes()


def test_malformed_inputs_raise():
    key = allcrypt.MlDsaKey.generate("ML-DSA-65")
    with pytest.raises(ValueError, match="at most 255"):
        key.sign(b"m", b"x" * 256)
    with pytest.raises(ValueError, match="Unknown pre-hash"):
        key.sign(b"m", None, "MD5")
    with pytest.raises(ValueError, match="32 bytes"):
        allcrypt.MlDsaKey.from_seed("ML-DSA-65", b"\0" * 31)
    with pytest.raises(ValueError, match="Unknown ML-DSA parameter set"):
        allcrypt.MlDsaKey.generate("Dilithium3")


def test_repr_names_the_set_and_nothing_else():
    key = allcrypt.MlDsaKey.generate("ML-DSA-87")
    assert repr(key) == "<allcrypt.MlDsaKey ML-DSA-87>"
    assert repr(key.public_key()) == "<allcrypt.MlDsaPublicKey ML-DSA-87>"
