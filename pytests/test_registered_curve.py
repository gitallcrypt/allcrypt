"""A curve this library does not carry, supplied by the caller.

`register_oid(..., curve=)` moves a *name*: it says that an OID means a
curve already compiled in. `curve_parameters=` is different in kind - it
supplies the curve itself, seven numbers, and is the second registration
that carries cryptography rather than naming it. The first is a GOST
S-box, and the reason is the same: a short Weierstrass curve **is** its
parameters, distributed as a parameter set rather than as code.

**Brainpool P-256r1 is the curve used throughout, and the choice
matters.** This library does not implement it, `cryptography` does, and
RFC 5639 section 3.4 publishes the parameters - so every check here is
against an implementation that is not ours, on numbers neither of us
chose. A toy curve would leave the primality tests and Hasse's bound
untested at any realistic size, and a curve we already carry would prove
only that the built-in table still works.

What the checks below establish, in order: the parameters are used rather
than quietly replaced (the public key matches), the signing is right in
both directions (each side verifies the other), the key agreement is
right (a one-sided test passes on two implementations that are wrong the
same way), and a certificate carrying the OID becomes readable - which is
the thing the registry exists for.
"""

import hashlib

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import allcrypt

#: RFC 5639 section 3.4. Hex, as the document prints it.
BRAINPOOL_P256R1 = dict(
    name="brainpoolP256r1",
    p="A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
    a="7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
    b="26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
    gx="8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
    gy="547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
    n="A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
    cofactor=1,
)

#: Its own OID, from RFC 5639 section 4.
BRAINPOOL_OID = "1.3.36.3.3.2.8.1.1.7"

FIELD_BYTES = 32


@pytest.fixture
def brainpool():
    """Register it, and take it away again.

    **Registrations are process-wide**, so a test that leaves one behind
    changes what every later test in the session sees. That is not
    hypothetical bookkeeping: `curves_available` and every OID lookup
    would answer differently, and the failure would land in an unrelated
    file.
    """
    allcrypt.register_oid(BRAINPOOL_OID, curve_parameters=BRAINPOOL_P256R1)
    try:
        yield "brainpoolP256r1"
    finally:
        allcrypt.forget_oid(BRAINPOOL_OID)


def their_key():
    """A Brainpool key from `cryptography`, and the same key as ours."""
    theirs = ec.generate_private_key(ec.BrainpoolP256R1())
    scalar = theirs.private_numbers().private_value
    ours = allcrypt.EcKey.from_private(
        "brainpoolP256r1", scalar.to_bytes(FIELD_BYTES, "big"))
    return theirs, ours


def their_public_bytes(theirs):
    return theirs.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def test_the_curve_appears_once_registered(brainpool):
    listed = allcrypt.registered_oids()
    assert (BRAINPOOL_OID, "curve-parameters", "brainpoolP256r1 (256 bit)") \
        in listed
    # And it is usable by name, which is how the rest of the library asks.
    key = allcrypt.EcKey.generate(brainpool)
    assert key.curve == "brainpoolP256r1"
    assert key.key_size == 256


def test_forgetting_it_really_removes_the_curve():
    """The fixture's cleanup, checked rather than assumed.

    **Registered and forgotten inside this test**, not left to run after
    the ones above: a test whose meaning depends on the order the file
    happens to execute in is one that passes for the wrong reason as soon
    as anything reorders it, and `pytest-randomly` is installed here. This
    way it fails if `forget_oid` does not work, whenever it runs.
    """
    allcrypt.register_oid(BRAINPOOL_OID, curve_parameters=BRAINPOOL_P256R1)
    assert allcrypt.EcKey.generate("brainpoolP256r1").key_size == 256

    assert allcrypt.forget_oid(BRAINPOOL_OID) is True
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcKey.generate("brainpoolP256r1")
    # Forgetting it twice says there was nothing to forget.
    assert allcrypt.forget_oid(BRAINPOOL_OID) is False


def test_the_public_key_matches_openssls(brainpool):
    """**The check that the parameters were used at all.**

    From the same private scalar, the public point is determined by the
    curve. If any of `p`, `a`, `b`, `gx` or `gy` were being ignored or
    misread, this is where it shows - and it is the one check that a
    self-consistent wrong curve cannot pass.
    """
    del brainpool
    theirs, ours = their_key()
    assert ours.public_bytes(False) == their_public_bytes(theirs)


def test_signing_agrees_in_both_directions(brainpool):
    """Each side verifies the other.

    One direction alone passes on an implementation that is consistently
    wrong: it would verify its own signatures happily. ECDSA is also
    randomised, so the two sides cannot be compared byte for byte - only
    by each accepting the other's.
    """
    del brainpool
    theirs, ours = their_key()
    message = b"a message"
    digest = hashlib.sha256(message).digest()

    ours_signature = ours.sign(digest, "sha256")
    r = int.from_bytes(ours_signature[:FIELD_BYTES], "big")
    s = int.from_bytes(ours_signature[FIELD_BYTES:], "big")
    # Raises if it does not verify, which is the assertion.
    theirs.public_key().verify(utils.encode_dss_signature(r, s), message,
                               ec.ECDSA(hashes.SHA256()))

    their_der = theirs.sign(message, ec.ECDSA(hashes.SHA256()))
    r2, s2 = utils.decode_dss_signature(their_der)
    their_signature = (r2.to_bytes(FIELD_BYTES, "big")
                       + s2.to_bytes(FIELD_BYTES, "big"))
    assert ours.public_key().verify(digest, their_signature)

    # And a wrong signature is refused, so the above is not vacuous.
    tampered = bytearray(their_signature)
    tampered[-1] ^= 1
    assert not ours.public_key().verify(digest, bytes(tampered))


def test_key_agreement_agrees(brainpool):
    """ECDH, ours against theirs.

    Both ends computed, because a shared secret is symmetric: two
    implementations with the same mistake agree with each other and with
    nobody, and a self-exchange proves nothing at all.
    """
    theirs, _ = their_key()
    ours = allcrypt.EcKey.generate(brainpool)

    from_ours = ours.exchange(their_public_bytes(theirs))
    from_theirs = theirs.exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
            ec.BrainpoolP256R1(), ours.public_bytes(False)))
    assert from_ours == from_theirs
    assert len(from_ours) == FIELD_BYTES


def test_a_certificate_on_the_registered_curve_becomes_readable(brainpool):
    """**The reason the registry exists.**

    A certificate whose key is on a curve this library does not carry came
    back as `UnsupportedCurve` - readable but not usable. Registering the
    OID makes it a key, and this checks the whole path: the OID in the
    certificate's `AlgorithmIdentifier`, through the registry, to a point
    we can compute on.

    The certificate is built by `cryptography`, so the encoding is
    somebody else's.
    """
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    theirs, ours = their_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "brainpool.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(theirs.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=30))
                   .sign(theirs, hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)

    fields = allcrypt.Certificate(der).to_dict()
    assert fields["publicKeyType"] == f"EC {brainpool}", fields["publicKeyType"]
    # An EC key has no parameter-set field: a named curve maps one to one
    # onto its OID, so the type name already carries everything.
    assert fields["publicKeyParameterSet"] is None


def test_the_same_certificate_is_unreadable_without_the_registration():
    """The control. Without it the curve is *named* and not usable, which
    is the state the registration changes - and without this test the one
    above would pass just as well if the parser had always understood
    Brainpool."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    theirs = ec.generate_private_key(ec.BrainpoolP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "brainpool.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(theirs.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=30))
                   .sign(theirs, hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)

    fields = allcrypt.Certificate(der).to_dict()
    assert "unsupported" in fields["publicKeyType"].lower(), \
        fields["publicKeyType"]
    assert BRAINPOOL_OID in fields["publicKeyType"]


def test_integers_and_hex_are_both_accepted():
    """A specification prints hex; a caller who computed the numbers has
    ints. Refusing either means the caller converting, which is one more
    place for a digit to go missing."""
    as_ints = {key: (int(value, 16) if isinstance(value, str) and key != "name"
                     else value)
               for key, value in BRAINPOOL_P256R1.items()}
    allcrypt.register_oid("1.3.36.3.3.2.8.1.1.7", curve_parameters=as_ints)
    try:
        assert allcrypt.EcKey.generate("brainpoolP256r1").curve \
            == "brainpoolP256r1"
    finally:
        allcrypt.forget_oid("1.3.36.3.3.2.8.1.1.7")

    # And hex with the separators a document uses.
    spaced = dict(BRAINPOOL_P256R1)
    spaced["p"] = "0x" + " ".join(
        BRAINPOOL_P256R1["p"][i:i + 8]
        for i in range(0, len(BRAINPOOL_P256R1["p"]), 8))
    allcrypt.register_oid("1.3.36.3.3.2.8.1.1.7", curve_parameters=spaced)
    try:
        assert allcrypt.EcKey.generate("brainpoolP256r1").key_size == 256
    finally:
        allcrypt.forget_oid("1.3.36.3.3.2.8.1.1.7")


@pytest.mark.parametrize("field,value,expected", [
    ("p", int(BRAINPOOL_P256R1["p"], 16) - 2, "not prime"),
    ("n", int(BRAINPOOL_P256R1["n"], 16) * 2, "not prime"),
    ("gy", int(BRAINPOOL_P256R1["gy"], 16) + 1, "not on the curve"),
    ("cofactor", 7, "cofactor"),
    ("name", "P-256", "already a curve"),
])
def test_parameters_that_are_not_a_curve_are_refused(field, value, expected):
    """Each of these produces something that still computes.

    A composite `p` leaves most of the arithmetic working; a doubled `n`
    still satisfies `n*G = 0`; a moved `gy` is a perfectly good number; a
    guessed cofactor is only wrong where the cofactor is used. Every one
    of them would give a working-looking curve with no security argument,
    so each is refused at registration rather than discovered later.

    The full set of checks, including the singular-curve and
    anomalous-curve ones that need a curve of their own, is in
    `ec::curves::tests::test_each_parameter_check_rejects_what_it_is_for`.
    """
    broken = dict(BRAINPOOL_P256R1)
    broken[field] = value
    with pytest.raises(allcrypt.CryptoError) as caught:
        allcrypt.register_oid("1.3.36.3.3.2.8.1.1.99",
                              curve_parameters=broken)
    assert expected in str(caught.value), str(caught.value)
    # Nothing was registered, so nothing needs forgetting - checked,
    # because a half-registration would leave the curve usable.
    assert allcrypt.forget_oid("1.3.36.3.3.2.8.1.1.99") is False


def test_a_missing_or_misspelt_field_is_an_error():
    """**A misspelt key must not read as a missing field with a default.**

    `cofator` for `cofactor` would otherwise register a curve with a
    cofactor of whatever the default was, and the cofactor is exactly the
    parameter a caller is most likely not to know.
    """
    for bad in [{key: value for key, value in BRAINPOOL_P256R1.items()
                 if key != "cofactor"},
                dict(BRAINPOOL_P256R1, cofator=1)]:
        with pytest.raises(ValueError) as caught:
            allcrypt.register_oid("1.3.36.3.3.2.8.1.1.98",
                                  curve_parameters=bad)
        text = str(caught.value)
        assert "cofactor" in text or "cofator" in text, text


def test_only_one_meaning_at_a_time():
    """An OID names one thing, so the keywords are exclusive."""
    with pytest.raises(ValueError) as caught:
        allcrypt.register_oid("1.3.36.3.3.2.8.1.1.97", curve="P-256",
                              curve_parameters=BRAINPOOL_P256R1)
    assert "exactly one" in str(caught.value)


def test_a_negative_int_is_refused():
    """`a = -3` is how every specification *describes* these curves, and
    it is not what the field element is. Refused rather than reduced,
    because reducing it needs `p` and would silently accept a value the
    caller meant differently."""
    with pytest.raises(ValueError) as caught:
        allcrypt.register_oid("1.3.36.3.3.2.8.1.1.96",
                              curve_parameters=dict(BRAINPOOL_P256R1, a=-3))
    assert "negative" in str(caught.value)


def test_a_certificate_can_be_issued_on_the_registered_curve(brainpool):
    """**The other direction, which was missing.**

    Registering a curve made a certificate on it *readable*. Writing one
    still refused, because `x509::builder` matched the curve name against
    three constants - so a caller who registered a curve to talk to a box
    could read its certificate and not issue one of their own, and the
    only way out was editing that match and rebuilding, which is the thing
    the registry exists to avoid.

    OpenSSL reads what we wrote and verifies the signature, which is what
    makes this more than a round trip through our own encoder.
    """
    from cryptography import x509

    authority = allcrypt.CertificateAuthority(
        "brainpool CA", "20250101000000Z", "20350101000000Z", brainpool)
    parsed = x509.load_der_x509_certificate(authority.certificate)
    assert parsed.public_key().curve.name == "brainpoolP256r1"
    # Raises if the signature does not verify, which is the assertion.
    parsed.public_key().verify(parsed.signature, parsed.tbs_certificate_bytes,
                               ec.ECDSA(hashes.SHA256()))

    leaf_der = authority.issue("brainpool.test", "20250101000000Z",
                               "20350101000000Z")[0]
    leaf = x509.load_der_x509_certificate(leaf_der)
    assert leaf.subject.rfc4514_string() == "CN=brainpool.test"


def test_issuing_refuses_a_curve_registered_under_two_oids(brainpool):
    """A certificate names one curve, so two OIDs for it is ambiguous.

    Reading is unaffected - each OID resolves to this curve, which is the
    whole reason the registry exists - but choosing which one a
    certificate claims would be choosing for the caller.
    """
    allcrypt.register_oid("1.3.6.1.4.1.99999.7.1",
                          curve_parameters=BRAINPOOL_P256R1)
    try:
        with pytest.raises(allcrypt.CryptoError) as caught:
            allcrypt.CertificateAuthority("ambiguous", "20250101000000Z",
                                          "20350101000000Z", brainpool)
        text = str(caught.value)
        assert "2 OIDs" in text, text
        assert BRAINPOOL_OID in text and "1.3.6.1.4.1.99999.7.1" in text, text
    finally:
        allcrypt.forget_oid("1.3.6.1.4.1.99999.7.1")

    # With one registration again, it issues.
    assert allcrypt.CertificateAuthority(
        "fine now", "20250101000000Z", "20350101000000Z", brainpool)


@pytest.mark.parametrize("spelling", [
    "brainpoolP256r1", "brainpoolp256r1", "BRAINPOOLP256R1",
    "brainpool_p256r1".replace("_p", "P"),      # the registered spelling
])
def test_the_name_folds_the_way_a_built_in_name_folds(brainpool, spelling):
    """**A registered curve must not be a second class of curve.**

    `curves::by_name` folds case, and reads `_` and a space as `-`, for
    every built-in name. Registered curves were compared exactly, and the
    asymmetry surfaced somewhere unrelated: `api::ca_key` lowercases its
    `key_type` before looking the curve up, so
    `CertificateAuthority(..., "brainpoolP256r1")` failed with `Unknown
    curve "brainpoolp256r1"` while `EcKey.generate` with the same string
    worked. The lowercase spelling in the error was the only clue that
    anything had folded it.
    """
    del brainpool
    assert allcrypt.EcKey.generate(spelling).key_size == 256
    # Through the path that folds the name on the way in, which is the one
    # that failed.
    assert allcrypt.CertificateAuthority(
        "folded", "20250101000000Z", "20350101000000Z", spelling)


def test_a_name_that_folds_onto_a_built_in_is_refused():
    """`P_256` is `P-256` to `by_name`, so registering it would be
    shadowed just as surely as the exact spelling - and the caller would
    believe their parameters were in use while running P-256."""
    for spelling in ["P_256", "p-256", "P 256"]:
        with pytest.raises(allcrypt.CryptoError) as caught:
            allcrypt.register_oid("1.3.6.1.4.1.99999.7.2",
                                  curve_parameters=dict(BRAINPOOL_P256R1,
                                                        name=spelling))
        assert "already a curve" in str(caught.value), spelling


# ------------------------------------- reading a parameter set back out ---
#
# `curve_parameters` is the counterpart of `gost_sbox`: the usual way to
# register a parameter set is to read one out and change what differs.

def test_curve_parameters_are_hex_big_endian_and_whole_bytes():
    """**The byte order, stated and checked.**

    Every value is hex, big-endian, no `0x`, and an even number of digits
    so it is a whole number of bytes and `bytes.fromhex` takes it. Strings
    rather than ints on purpose: an int has no byte order until something
    serialises it, and this is the boundary where that is easiest to get
    wrong.
    """
    parameters = allcrypt.curve_parameters("P-256")
    assert set(parameters) == {"name", "p", "a", "b", "gx", "gy", "n",
                               "cofactor"}
    for key, value in parameters.items():
        if key == "name":
            continue
        assert len(value) % 2 == 0, (key, value)
        assert not value.startswith("0x")
        bytes.fromhex(value)                      # raises if it is not hex

    # Big-endian: the most significant byte first. P-256's p is
    # 2^256 - 2^224 + 2^192 + 2^96 - 1, so it begins ff and ends ff, while
    # its `a` is p - 3 and so ends fc - which only holds one way round.
    assert parameters["p"].startswith("ffffffff")
    assert parameters["a"].endswith("fc")
    assert int(parameters["p"], 16) - int(parameters["a"], 16) == 3
    assert parameters["cofactor"] == "01"

    # And the value is the number FIPS 186-4 publishes, read big-endian.
    assert int(parameters["n"], 16) == int(
        "ffffffff00000000ffffffffffffffff"
        "bce6faada7179e84f3b9cac2fc632551", 16)


def test_a_built_in_curve_registered_under_another_name_behaves_identically():
    """**Read a curve out, register it as if the library lacked it, and
    check the two are the same group.**

    This is the round-trip the registration path has to satisfy: whatever
    `curve_parameters` reports must be enough to rebuild the curve, with no
    parameter that only the built-in table knows. A missing or misread
    field gives a curve that still computes - and then disagrees here.

    Compared by *arithmetic*, not by the numbers coming back the same:
    from one private scalar the two must produce the same public key, and
    the same ECDH secret against the same peer. That is what says it is the
    same group rather than the same dictionary.
    """
    parameters = allcrypt.curve_parameters("secp256k1")
    parameters["name"] = "secp256k1-restored"
    allcrypt.register_oid("1.3.6.1.4.1.99999.9.1",
                          curve_parameters=parameters)
    try:
        scalar = bytes(range(1, 33))
        built_in = allcrypt.EcKey.from_private("secp256k1", scalar)
        restored = allcrypt.EcKey.from_private("secp256k1-restored", scalar)
        assert restored.public_bytes(False) == built_in.public_bytes(False)
        assert restored.key_size == built_in.key_size

        peer = allcrypt.EcKey.generate("secp256k1")
        assert restored.exchange(peer.public_bytes(False)) \
            == built_in.exchange(peer.public_bytes(False))

        # A signature made on one verifies on the other, which it cannot
        # do across two different groups.
        digest = bytes(range(32))
        assert built_in.public_key().verify(
            digest, restored.sign(digest, "sha256"))
    finally:
        allcrypt.forget_oid("1.3.6.1.4.1.99999.9.1")

    # Gone again, and the built-in is untouched - a registration is
    # consulted after the compiled-in table and can never replace it.
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.EcKey.generate("secp256k1-restored")
    assert allcrypt.EcKey.generate("secp256k1").key_size == 256


def test_the_sec1_point_is_big_endian_x_then_y():
    """Where the other byte order lives.

    `public_bytes(False)` is SEC1 uncompressed: `04 || X || Y`, each
    coordinate big-endian and padded to the field width - 32 bytes here,
    even when the value is small. **GOST is the exception in this library
    and writes its certificate keys little-endian** (RFC 9215 section 4.3),
    which is the one place a caller has to think about it;
    `tests/test_live_gost_certificates.rs` checks that against real
    certificates.
    """
    key = allcrypt.EcKey.generate("P-256")
    point = key.public_bytes(False)
    assert len(point) == 1 + 32 + 32
    assert point[0] == 0x04

    # The coordinates are on the curve when read big-endian, which is the
    # check that the order is what it says: y^2 = x^3 - 3x + b mod p.
    parameters = allcrypt.curve_parameters("P-256")
    p = int(parameters["p"], 16)
    a = int(parameters["a"], 16)
    b = int(parameters["b"], 16)
    x = int.from_bytes(point[1:33], "big")
    y = int.from_bytes(point[33:], "big")
    assert (y * y - (x * x * x + a * x + b)) % p == 0

    # Read the other way round it is not a point, so this is not vacuous.
    flipped_x = int.from_bytes(point[1:33], "little")
    flipped_y = int.from_bytes(point[33:], "little")
    assert (flipped_y * flipped_y
            - (flipped_x ** 3 + a * flipped_x + b)) % p != 0


def test_an_sbox_read_out_and_registered_back():
    """The same round trip for a GOST S-box, which is the other parameter
    set a caller can supply.

    **Eight rows of sixteen nibbles, and the order is the table's own.**
    Row 0 is the first substitution applied to the low nibble group; each
    row is a permutation of 0..16 and the entries are *values*, not packed
    bytes, so there is no byte order to get wrong - only row order, which
    is checked here by registering the table unchanged and requiring the
    cipher to agree, then by reversing one row and requiring it not to.
    """
    rows = [list(row) for row in
            allcrypt.gost_sbox("id-Gost28147-89-CryptoPro-A-ParamSet")]
    assert len(rows) == 8 and all(len(row) == 16 for row in rows)
    assert all(sorted(row) == list(range(16)) for row in rows)

    key, block = bytes(range(32)), bytes(range(8))
    built_in = allcrypt.Cipher("gost", key,
                               "id-Gost28147-89-CryptoPro-A-ParamSet")
    reference = built_in.encryptor("ecb").update(block)

    allcrypt.register_oid("1.3.6.1.4.1.99999.9.2", gost_sbox=rows)
    try:
        same = allcrypt.Cipher("gost", key, "1.3.6.1.4.1.99999.9.2")
        assert same.encryptor("ecb").update(block) == reference, \
            "the table read out and registered back is a different cipher"
    finally:
        allcrypt.forget_oid("1.3.6.1.4.1.99999.9.2")

    # One row reversed is a different cipher, so the check above is about
    # the rows and not about the key.
    rows[0] = list(reversed(rows[0]))
    allcrypt.register_oid("1.3.6.1.4.1.99999.9.2", gost_sbox=rows)
    try:
        other = allcrypt.Cipher("gost", key, "1.3.6.1.4.1.99999.9.2")
        assert other.encryptor("ecb").update(block) != reference
    finally:
        allcrypt.forget_oid("1.3.6.1.4.1.99999.9.2")


# --------------------------------------- an order wider than the field ---

#: A 64-bit curve, y^2 = x^3 - 3x + b, whose prime order exceeds 2^64.
#: Hasse's bound allows n up to p + 1 + 2*sqrt(p), so with p just below
#: 2^64 the order can need a second 64-bit limb where the field needs one.
#: Found by computing the order of a random point by baby-step
#: giant-step over the Hasse interval, for random b, until the order was
#: prime and above 2^64. Too small to protect anything, and chosen for
#: that shape alone.
WIDE_ORDER = dict(
    name="wide-order-test",
    p=18446744073709551427,
    a=18446744073709551424,
    b=9282164822705471486,
    gx=4409624146494191346,
    gy=17525437172555526583,
    n=18446744077528333607,
    cofactor=1,
)

#: IANA's documentation enterprise number (RFC 5612).
WIDE_ORDER_OID = "1.3.6.1.4.1.32473.1.1"


def _reference_mul(k, point):
    """`k * point` on WIDE_ORDER, affine double-and-add in plain ints: a
    reference that shares no code with the library."""
    p, a = WIDE_ORDER["p"], WIDE_ORDER["a"]

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
        else:
            slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (slope * slope - x1 - x2) % p
        return x3, (slope * (x1 - x3) - y1) % p

    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


@pytest.fixture
def wide_order():
    allcrypt.register_oid(WIDE_ORDER_OID, curve_parameters=WIDE_ORDER)
    try:
        yield WIDE_ORDER["name"]
    finally:
        allcrypt.forget_oid(WIDE_ORDER_OID)


def test_a_scalar_wider_than_the_field_is_a_key_on_a_wide_order_curve(wide_order):
    """A private key in [2^64, n) on this curve needs two limbs, and the
    ladder sized its scalar by the field's one. `EcKey.from_private`
    panicked, which Python saw as a `PanicException`, and `generate`
    panicked on about one key in five billion."""
    n = WIDE_ORDER["n"]
    G = (WIDE_ORDER["gx"], WIDE_ORDER["gy"])
    for d in (n - 1, 2**64, 2**64 + 12345):
        key = allcrypt.EcKey.from_private(wide_order, d.to_bytes(9, "big"))
        x, y = _reference_mul(d, G)
        assert key.public_bytes(False) == b"\x04" + x.to_bytes(8, "big") \
            + y.to_bytes(8, "big")
        # RFC 5915 width: the order's nine bytes, not the field's eight,
        # and it round-trips.
        assert key.private_bytes() == d.to_bytes(9, "big")


def test_ecdh_on_a_wide_order_curve(wide_order):
    n = WIDE_ORDER["n"]
    G = (WIDE_ORDER["gx"], WIDE_ORDER["gy"])
    d1, d2 = n - 2, 2**64 + 7
    one = allcrypt.EcKey.from_private(wide_order, d1.to_bytes(9, "big"))
    two = allcrypt.EcKey.from_private(wide_order, d2.to_bytes(9, "big"))
    expected = _reference_mul(d1 * d2, G)[0].to_bytes(8, "big")
    assert one.exchange(two.public_bytes(False)) == expected
    assert two.exchange(one.public_bytes(False)) == expected


def test_signing_on_a_wide_order_curve(wide_order):
    key = allcrypt.EcKey.from_private(wide_order,
                                      (WIDE_ORDER["n"] - 1).to_bytes(9, "big"))
    digest = hashlib.sha256(b"wide").digest()
    signature = key.sign(digest, "sha256")
    assert key.verify(digest, signature)
    assert not key.verify(hashlib.sha256(b"other").digest(), signature)
