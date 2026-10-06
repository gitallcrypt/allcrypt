"""GOST R 34.12-2015 and GOST R 34.11-2012, from Python.

Kuznyechik, Magma and Streebog. Every one of them reached with no change
to `src/python.rs` at all, which is the design invariant working: adding
an algorithm to `api.rs` makes it reachable from Python.

**There is nothing on this machine to compare against.** This OpenSSL is
built without the GOST engine and `hashlib` has never had Streebog, so
these tests are the standards' published vectors plus the structural
checks that catch the mistakes those vectors do not - and
`scripts/diff_check.py` carries a second implementation written from the
standards. See `docs/pitfalls.md`.
"""

import hashlib

import pytest

import allcrypt


KUZNYECHIK_KEY = bytes.fromhex(
    "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
MAGMA_KEY = bytes.fromhex(
    "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")


def ecb(name, key, data, decrypt=False):
    cipher = allcrypt.Cipher(name, key)
    engine = cipher.decryptor("ecb") if decrypt else cipher.encryptor("ecb")
    return engine.update(data) + engine.finalize()


# ------------------------------------------------------- the block ciphers ---

def test_kuznyechik_matches_the_standard():
    """GOST R 34.12-2015 section A.1."""
    plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
    ciphertext = ecb("kuznyechik", KUZNYECHIK_KEY, plaintext)
    assert ciphertext.hex() == "7f679d90bebc24305a468d42b9d4edcd"
    assert ecb("kuznyechik", KUZNYECHIK_KEY, ciphertext, decrypt=True) == plaintext


def test_magma_matches_the_standard():
    """GOST R 34.12-2015 section A.2."""
    plaintext = bytes.fromhex("fedcba9876543210")
    ciphertext = ecb("magma", MAGMA_KEY, plaintext)
    assert ciphertext.hex() == "4ee901e5c2d8ca3d"
    assert ecb("magma", MAGMA_KEY, ciphertext, decrypt=True) == plaintext


def test_the_names_openssl_uses_reach_the_same_cipher():
    """`grasshopper` is what the gost-engine calls Kuznyechik, so it is
    what somebody arriving from OpenSSL will type."""
    block = bytes(16)
    expected = ecb("kuznyechik", KUZNYECHIK_KEY, block)
    for alias in ["kuznechik", "grasshopper", "KUZNYECHIK"]:
        assert ecb(alias, KUZNYECHIK_KEY, block) == expected


@pytest.mark.parametrize("name,size", [("kuznyechik", 16), ("magma", 8)])
def test_they_appear_in_the_catalogue(name, size):
    assert name in allcrypt.block_ciphers_available
    for length in [0, 16, 24, 31, 33]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Cipher(name, bytes(length)).encryptor("ecb")


@pytest.mark.parametrize("name,key,size", [
    ("kuznyechik", KUZNYECHIK_KEY, 16),
    ("magma", MAGMA_KEY, 8),
])
@pytest.mark.parametrize("mode", ["cbc", "ctr", "cfb", "ofb"])
def test_every_mode_round_trips(name, key, size, mode):
    """A new cipher implements two block functions and gets all five
    modes. This is the check that it really did."""
    data = bytes(range(size * 4))
    iv = bytes([0x5a] * size)

    encryptor = allcrypt.Cipher(name, key).encryptor(mode, iv)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    assert ciphertext != data

    decryptor = allcrypt.Cipher(name, key).decryptor(mode, iv)
    assert decryptor.update(ciphertext) + decryptor.finalize() == data


# -------------------------------------------------------------- Streebog ---

def test_streebog_matches_the_standard():
    """GOST R 34.11-2012 section A.1.

    The standard writes messages and digests as 512 bit numbers, most
    significant byte on the left, while every implementation works on byte
    strings in order. So the standard's hex is reversed on both sides here
    - and once reversed, the message is the ASCII digits it was always
    meant to be. An implementer who does not know that gets a wrong answer
    and cannot tell whether the code or the byte order is at fault.
    """
    message = b"012345678901234567890123456789012345678901234567890123456789012"
    assert len(message) == 63

    want_512 = bytes.fromhex(
        "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
        "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b")[::-1]
    assert allcrypt.new("streebog512", message).digest() == want_512

    want_256 = bytes.fromhex(
        "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")[::-1]
    assert allcrypt.new("streebog256", message).digest() == want_256


def test_the_empty_message():
    """The two values every implementation quotes, in the order OpenSSL's
    GOST engine prints them."""
    assert allcrypt.new("streebog256", b"").hexdigest() == (
        "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")
    assert allcrypt.new("streebog512", b"").hexdigest() == (
        "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7"
        "362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a")


def test_streebog_256_is_not_a_truncation():
    """Its IV is sixty-four 0x01 bytes, so the two diverge from the first
    compression. An implementation that truncated would pass every length
    test and agree with nobody."""
    for message in [b"", b"abc", bytes(200)]:
        long = allcrypt.new("streebog512", message).digest()
        short = allcrypt.new("streebog256", message).digest()
        assert len(short) == 32 and len(long) == 64
        assert short != long[:32]
        assert short != long[32:]


def test_it_behaves_like_a_hashlib_object():
    """`copy`, incremental `update`, `digest_size`, `block_size`, and a
    `digest` that does not consume the state."""
    hash_object = allcrypt.new("streebog512")
    assert hash_object.digest_size == 64
    assert hash_object.block_size == 64

    hash_object.update(b"abc")
    forked = hash_object.copy()
    first = hash_object.digest()
    assert hash_object.digest() == first, "digest must not consume the state"

    forked.update(b"def")
    assert forked.digest() == allcrypt.new("streebog512", b"abcdef").digest()


@pytest.mark.parametrize("name", ["streebog256", "streebog512"])
def test_streaming_in_ragged_pieces_equals_one_call(name):
    """The check this library exists to run: SHA-1 here once padded with a
    16 byte length field and passed every vector in its suite."""
    message = bytes((i * 31 + 7) & 0xFF for i in range(300))
    for length in list(range(0, 200)) + [255, 256, 257, 300]:
        data = message[:length]
        whole = allcrypt.new(name, data).digest()
        for chunk in (1, 7, 63, 64, 65):
            piecewise = allcrypt.new(name)
            for offset in range(0, len(data), chunk):
                piecewise.update(data[offset:offset + chunk])
            assert piecewise.digest() == whole, f"{length} in chunks of {chunk}"


def test_streebog_is_not_any_hash_we_already_had():
    """A sanity check that costs nothing: a wiring mistake that routed
    `streebog256` to SHA-256 would pass every structural test above."""
    message = b"the quick brown fox"
    ours = allcrypt.new("streebog256", message).digest()
    for other in ("sha256", "sha3_256", "blake2s"):
        try:
            assert ours != hashlib.new(other, message).digest()
        except ValueError:
            continue


def test_hmac_works_over_streebog():
    """HMAC needs `block_size`, and a hash that reported the wrong one
    would produce a MAC that is self-consistent and agrees with nothing.
    Streebog's block is 64 bytes even for the 512 bit digest, which is the
    case that catches an implementation assuming block == 2 * digest."""
    key = bytes(range(32))
    mac = allcrypt.Hmac(key, b"message", "streebog512").digest()
    assert len(mac) == 64
    assert mac != allcrypt.Hmac(key, b"message", "streebog256").digest()

    # And it must agree with itself streamed, which is what block_size
    # being wrong would break in a way the length check cannot see.
    streamed = allcrypt.Hmac(key, digestmod="streebog512")
    streamed.update(b"mess")
    streamed.update(b"age")
    assert streamed.digest() == mac


# ------------------------------------------------- GOST R 34.10-2012 ---

GOST_CURVES = ["gost256-a", "gost256-b", "gost256-c", "gost512-a", "gost512-b",
               "gost256-tc26-a", "gost512-c"]

# The two with a cofactor of four, which is the only place the two
# readings of VKO's scalar differ. Named rather than derived, because a
# list derived from the same table the code uses would follow it into a
# mistake.
COFACTOR_FOUR = ["gost256-tc26-a", "gost512-c"]


@pytest.mark.parametrize("curve", GOST_CURVES)
def test_the_gost_curves_are_available(curve):
    assert curve in allcrypt.curves_available
    key = allcrypt.EcKey.generate(curve)
    assert key.curve == curve


@pytest.mark.parametrize("curve", GOST_CURVES)
def test_sign_and_verify(curve):
    key = allcrypt.EcKey.generate(curve)
    digest = allcrypt.new("streebog256", b"a message").digest()

    signature = key.sign_gost(digest)
    assert key.verify_gost(digest, signature)
    assert key.public_key().verify_gost(digest, signature)

    # Every part of the input has to matter.
    other = allcrypt.new("streebog256", b"another message").digest()
    assert not key.verify_gost(other, signature)
    assert not allcrypt.EcKey.generate(curve).verify_gost(digest, signature)


@pytest.mark.parametrize("curve", GOST_CURVES)
def test_the_signature_is_two_components_of_the_group_orders_width(curve):
    key = allcrypt.EcKey.generate(curve)
    digest = allcrypt.new("streebog512", b"x").digest()
    signature = key.sign_gost(digest, "streebog512")
    expected = 64 if curve.startswith("gost256") else 128
    assert len(signature) == expected

    # Halves swapped is the ECDSA wire order, and must not verify.
    half = len(signature) // 2
    swapped = signature[half:] + signature[:half]
    assert not key.verify_gost(digest, swapped)


def test_signing_is_deterministic():
    """The nonce is derived through RFC 6979 rather than drawn, so the
    same key and digest give the same signature. GOST does not
    standardise that; the failure mode of a repeated nonce is identical
    to ECDSA's, so it is used anyway - see src/ec/gost3410.rs."""
    key = allcrypt.EcKey.generate("gost256-a")
    digest = allcrypt.new("streebog256", b"twice").digest()
    assert key.sign_gost(digest) == key.sign_gost(digest)


def test_gost_and_ecdsa_signatures_do_not_verify_as_each_other():
    """Two different equations over the same curve, and a library that
    carries both must not confuse them. The signatures are also the same
    length, so nothing about the shape gives it away."""
    key = allcrypt.EcKey.generate("gost256-a")
    digest = allcrypt.new("streebog256", b"which one").digest()

    gost = key.sign_gost(digest)
    ecdsa = key.sign(digest, "streebog256")
    assert len(gost) == len(ecdsa)

    assert key.verify_gost(digest, gost)
    assert key.verify(digest, ecdsa)
    assert not key.verify_gost(digest, ecdsa)
    assert not key.verify(digest, gost)


def test_a_wrong_length_signature_raises_rather_than_returning_false():
    """"Not a signature at all" and "a signature that is wrong" are
    different bugs, and a caller that treats an error as valid should not
    be able to."""
    key = allcrypt.EcKey.generate("gost256-a")
    digest = allcrypt.new("streebog256", b"x").digest()
    for length in [0, 63, 65, 128]:
        with pytest.raises(allcrypt.CryptoError):
            key.verify_gost(digest, bytes(length))


# ------------------------------------------------------- VKO (RFC 7836) ---

@pytest.mark.parametrize("curve", GOST_CURVES)
def test_vko_both_sides_agree(curve):
    a = allcrypt.EcKey.generate(curve)
    b = allcrypt.EcKey.generate(curve)
    ukm = b"a shared nonce"

    for bits in (256, 512):
        ours = a.vko(b.public_bytes(), ukm, bits)
        theirs = b.vko(a.public_bytes(), ukm, bits)
        assert ours == theirs
        assert len(ours) == bits // 8


def test_the_ukm_changes_the_key_and_is_read_as_a_number():
    """VKO is symmetric, so two implementations that both read the UKM
    backwards agree perfectly. The byte order is only visible from
    outside - `scripts/diff_check.py` does that - but that it is read as
    a *number* at all is visible here."""
    a = allcrypt.EcKey.generate("gost256-a")
    b = allcrypt.EcKey.generate("gost256-a")
    peer = b.public_bytes()

    assert a.vko(peer, b"one", 256) != a.vko(peer, b"two", 256)
    assert a.vko(peer, bytes([1, 2, 3, 4]), 256) != \
        a.vko(peer, bytes([4, 3, 2, 1]), 256)


def test_a_zero_ukm_is_refused():
    """A zero UKM makes the scalar zero and the point the identity, which
    every pair of keys agrees on - a shared secret an observer has too."""
    a = allcrypt.EcKey.generate("gost256-a")
    peer = allcrypt.EcKey.generate("gost256-a").public_bytes()
    for ukm in (b"", bytes(16)):
        with pytest.raises(allcrypt.CryptoError):
            a.vko(peer, ukm, 256)


@pytest.mark.parametrize("curve", GOST_CURVES)
def test_the_two_cofactor_readings_differ_exactly_where_the_cofactor_does(curve):
    """RFC 7836 puts `m/q` in VKO's scalar; the other reading leaves it
    out, so on a curve with `h = 4` the two reach different points.

    The assertion is in both directions. That they *agree* on the seven
    curves with `h = 1` is what says `"without-cofactor"` has not
    quietly become a different algorithm; that they *differ* on the two
    with `h = 4` is what says the argument is doing anything at all.
    Without the second half a binding that ignored the keyword entirely
    would pass this test on every curve.

    Only the first reading matches anything. `vectors/gost_engine.vec`
    settled that OpenSSL's GOST engine follows the document - it had
    been read as omitting the term, and the TLS key exchange was
    pointed at the wrong one because of it.
    """
    a = allcrypt.EcKey.generate(curve)
    b = allcrypt.EcKey.generate(curve)
    ukm = b"a shared nonce"

    spec = a.vko(b.public_bytes(), ukm, 256, "as-specified")
    without = a.vko(b.public_bytes(), ukm, 256, "without-cofactor")
    assert a.vko(b.public_bytes(), ukm, 256) == spec, "the default moved"

    # Both readings are agreements: the other side reaches the same key.
    assert b.vko(a.public_bytes(), ukm, 256, "without-cofactor") == without

    if curve in COFACTOR_FOUR:
        assert spec != without
    else:
        assert spec == without


def test_the_old_cofactor_name_is_refused_and_says_why():
    """`"as-deployed"` claimed to be what OpenSSL's GOST engine does and
    named the one reading it does not.

    Refused rather than aliased, because a caller who asked for "what
    the equipment does" and silently got the other reading would derive
    a key no peer shares - on two curves only, which is the shape that
    takes longest to find.
    """
    a = allcrypt.EcKey.generate("gost256-a")
    b = allcrypt.EcKey.generate("gost256-a")
    with pytest.raises(ValueError) as caught:
        a.vko(b.public_bytes(), b"ukm", 256, "as-deployed")
    message = str(caught.value)
    assert "does apply" in message, message
    assert "as-specified" in message, message


def test_an_unknown_cofactor_reading_is_refused():
    """Not defaulted. A caller who spells it wrong gets a key that
    agrees with nobody on exactly the curves the keyword exists for."""
    a = allcrypt.EcKey.generate("gost256-tc26-a")
    peer = allcrypt.EcKey.generate("gost256-tc26-a").public_bytes()
    for name in ["", "rfc7836", "as specified", "AS-DEPLOYED", "openssl"]:
        with pytest.raises(allcrypt.CryptoError):
            a.vko(peer, b"ukm", 256, name)


def test_vko_is_not_ecdh():
    a = allcrypt.EcKey.generate("gost256-a")
    peer = allcrypt.EcKey.generate("gost256-a").public_bytes()
    assert a.vko(peer, b"ukm", 256) != a.exchange(peer)


def test_only_the_two_digest_sizes_are_accepted():
    a = allcrypt.EcKey.generate("gost256-a")
    peer = allcrypt.EcKey.generate("gost256-a").public_bytes()
    for bits in (0, 128, 384, 1024):
        with pytest.raises(allcrypt.CryptoError):
            a.vko(peer, b"ukm", bits)
