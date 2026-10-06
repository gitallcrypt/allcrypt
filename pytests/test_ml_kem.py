"""ML-KEM (FIPS 203) through the Python bindings.

The bindings are translation only - every byte of the scheme is in
`src/pq/ml_kem/` and checked there against NIST's 195 ACVP cases. What
these tests are for is the *surface*: that the methods mean what the
docstrings say, that an altered ciphertext is not an exception, and that
the keys a Python caller imports are checked the way FIPS 203 requires.

**They read NIST's vectors directly** rather than only round tripping,
because nothing else on this machine implements ML-KEM and a round trip
through one implementation agrees with itself whatever it got wrong.
`MlKemKey.from_seed(d + z)` must give NIST's key, and the two import
functions must refuse exactly the keys NIST's key-check cases refuse.

The Python surface has no way to choose `m` for an encapsulation, on
purpose, so NIST's encapsulation cases are not reachable from here; the
decapsulation cases are, and include both FO paths.
"""

import hashlib
import pathlib

import pytest

import allcrypt

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "ml_kem.vec"
SETS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


def _sections():
    """`(mode, parameter_set, count, [case])` for every section in the file.

    A small reimplementation of the reader in `tests/test_ml_kem.rs`,
    deliberately, so that NIST's numbers are reached by a second route.
    """
    out = []
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
        if key == "tcId" and case:
            out[-1][3].append(case)
            case = {}
        case[key] = value.strip()
    if case:
        out[-1][3].append(case)
    return out


@pytest.fixture(scope="module")
def cases():
    found = _sections()
    # A parse that silently found nothing would turn every loop below
    # into a pass, so the shape is asserted before anything is used.
    assert len(found) == 15, "five functions times three parameter sets"
    by_mode = {}
    for mode, parameter_set, count, section in found:
        assert len(section) == count, f"{mode} {parameter_set}"
        for case in section:
            by_mode.setdefault(mode, []).append((parameter_set, case))
    assert {mode: len(c) for mode, c in by_mode.items()} == {
        "keyGen": 75, "encapsulation": 30, "decapsulation": 30,
        "encapsulationKeyCheck": 30, "decapsulationKeyCheck": 30}
    return by_mode


def test_parameter_sets():
    assert allcrypt.ml_kem_parameter_sets() == SETS


def test_from_seed_gives_nists_keys(cases):
    for parameter_set, case in cases["keyGen"]:
        seed = bytes.fromhex(case["d"]) + bytes.fromhex(case["z"])
        key = allcrypt.MlKemKey.from_seed(parameter_set, seed)
        assert key.parameter_set == parameter_set
        dk = key.private_bytes()
        assert len(dk) == int(case["dkLength"])
        assert hashlib.sha256(dk).hexdigest().upper() == case["dkDigest"]
        assert (hashlib.sha256(key.public_bytes()).hexdigest().upper()
                == case["ekDigest"])


def test_decapsulation_matches_nist_on_both_paths(cases):
    """NIST's decapsulation cases, imported through `from_private`.

    Classified by whether NIST's answer is `J(z || c)` - computed here with
    hashlib's SHAKE-256 - so that both FO paths are known to be exercised
    through the bindings, not merely assumed to be.
    """
    rejected = 0
    for parameter_set, case in cases["decapsulation"]:
        dk = bytes.fromhex(case["dk"])
        ciphertext = bytes.fromhex(case["c"])
        key = allcrypt.MlKemKey.from_private(parameter_set, dk)
        expected = bytes.fromhex(case["k"])
        assert key.decapsulate(ciphertext) == expected, case["tcId"]
        rejected += expected == hashlib.shake_256(dk[-32:] + ciphertext).digest(32)
    assert rejected == 15


def test_imports_refuse_exactly_the_keys_nist_refuses(cases):
    refused = 0
    for parameter_set, case in cases["encapsulationKeyCheck"]:
        ek = bytes.fromhex(case["ek"])
        if case["testPassed"] == "true":
            allcrypt.MlKemPublicKey.from_public(parameter_set, ek)
        else:
            assert case["testPassed"] == "false"
            with pytest.raises(ValueError, match="modulus check"):
                allcrypt.MlKemPublicKey.from_public(parameter_set, ek)
            refused += 1
    for parameter_set, case in cases["decapsulationKeyCheck"]:
        dk = bytes.fromhex(case["dk"])
        if case["testPassed"] == "true":
            allcrypt.MlKemKey.from_private(parameter_set, dk)
        else:
            assert case["testPassed"] == "false"
            with pytest.raises(ValueError, match="hash check"):
                allcrypt.MlKemKey.from_private(parameter_set, dk)
            refused += 1
    assert refused == 30


@pytest.mark.parametrize("parameter_set", SETS)
def test_round_trip(parameter_set):
    key = allcrypt.MlKemKey.generate(parameter_set)
    public = allcrypt.MlKemPublicKey.from_public(parameter_set,
                                                 key.public_bytes())
    shared, ciphertext = public.encapsulate()
    assert len(shared) == 32
    assert key.decapsulate(ciphertext) == shared
    # Fresh randomness per call.
    assert public.encapsulate()[0] != shared
    assert key.public_key().public_bytes() == public.public_bytes()


def test_an_altered_ciphertext_is_not_an_exception():
    key = allcrypt.MlKemKey.generate("ML-KEM-768")
    shared, ciphertext = key.public_key().encapsulate()
    altered = bytearray(ciphertext)
    altered[-1] ^= 1
    # Accepted as bytearray too, like every other byte argument.
    other = key.decapsulate(altered)
    assert other != shared
    z = key.private_bytes()[-32:]
    assert other == hashlib.shake_256(z + bytes(altered)).digest(32)


def test_malformed_inputs_raise():
    key = allcrypt.MlKemKey.generate("ML-KEM-512")
    with pytest.raises(ValueError, match="767 bytes and should be 768"):
        key.decapsulate(b"\x00" * 767)
    with pytest.raises(ValueError, match="64 bytes"):
        allcrypt.MlKemKey.from_seed("ML-KEM-512", b"\x00" * 32)
    with pytest.raises(ValueError, match="Unknown ML-KEM parameter set"):
        allcrypt.MlKemKey.generate("Kyber512")
    with pytest.raises(ValueError, match="should be 800"):
        allcrypt.MlKemPublicKey.from_public("ML-KEM-512", b"\x00" * 32)


def test_repr_names_the_set_and_nothing_else():
    key = allcrypt.MlKemKey.generate("ML-KEM-1024")
    assert repr(key) == "<allcrypt.MlKemKey ML-KEM-1024>"
    assert repr(key.public_key()) == "<allcrypt.MlKemPublicKey ML-KEM-1024>"
