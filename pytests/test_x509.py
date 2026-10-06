"""X.509 parsing and chain verification, against certificates OpenSSL built.

`tools/src/bin/diff_x509.rs` covers the direction where we build a certificate
and OpenSSL reads it. This is the other one, which is the direction that
matters for a TLS client: OpenSSL (through `cryptography`) builds real
certificates and chains, and our code has to read and judge them correctly.

The tests that matter most are the ones where verification must **fail**.
A verifier that accepts everything passes every happy-path test.
"""

import datetime
import ipaddress

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import allcrypt

NOW = int(datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc).timestamp())


def moment(year, month=1, day=1):
    return datetime.datetime(year, month, day, tzinfo=datetime.timezone.utc)


def name(common_name, **extra):
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    for oid_name, value in extra.items():
        attributes.append(x509.NameAttribute(getattr(NameOID, oid_name), value))
    return x509.Name(attributes)


def make_cert(subject, issuer, subject_key, signer_key, *, serial=1,
              not_before=None, not_after=None, ca=False, path_length=None,
              sans=None, key_usage=None, eku=None, hash_algorithm=None,
              extra_extensions=(), basic_constraints=None):
    """Build a certificate with OpenSSL. Everything our verifier looks at is
    a parameter here, so a test can break exactly one thing."""
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer)
               .public_key(subject_key.public_key())
               .serial_number(serial)
               .not_valid_before(not_before or moment(2020))
               .not_valid_after(not_after or moment(2035)))

    # `basic_constraints` forces the extension to be present with an
    # explicit value - including cA=FALSE, which is different from the
    # extension being absent and has to be tested separately.
    if basic_constraints is not None:
        builder = builder.add_extension(basic_constraints, critical=True)
    elif ca or path_length is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if sans is not None:
        entries = []
        for entry in sans:
            if isinstance(entry, str) and entry.replace(".", "").isdigit():
                entries.append(x509.IPAddress(ipaddress.ip_address(entry)))
            else:
                entries.append(x509.DNSName(entry))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(entries), critical=False)
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    for extension, critical in extra_extensions:
        builder = builder.add_extension(extension, critical=critical)

    certificate = builder.sign(signer_key, hash_algorithm or hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.DER)


def usage(**flags):
    defaults = dict(digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False)
    defaults.update(flags)
    return x509.KeyUsage(**defaults)


CA_USAGE = usage(key_cert_sign=True, crl_sign=True)
LEAF_USAGE = usage(digital_signature=True, key_encipherment=True)


class Chain:
    """A root, an intermediate and a leaf, all built by OpenSSL."""

    def __init__(self, *, leaf_kwargs=None, intermediate_kwargs=None,
                 root_kwargs=None, key_factory=None):
        key_factory = key_factory or (lambda: ec.generate_private_key(ec.SECP256R1()))
        self.root_key = key_factory()
        self.intermediate_key = key_factory()
        self.leaf_key = key_factory()

        root_name = name("Test Root")
        intermediate_name = name("Test Intermediate")

        # Each level's defaults are a dict the caller can override one key
        # of, so a test breaks exactly one thing and everything else stays
        # valid. Passing overrides as extra kwargs instead would collide.
        def settings(defaults, overrides):
            merged = dict(defaults)
            merged.update(overrides or {})
            return merged

        self.root = make_cert(
            root_name, root_name, self.root_key, self.root_key,
            **settings(dict(serial=1, ca=True, key_usage=CA_USAGE), root_kwargs))
        self.intermediate = make_cert(
            intermediate_name, root_name, self.intermediate_key, self.root_key,
            **settings(dict(serial=2, ca=True, path_length=0, key_usage=CA_USAGE),
                       intermediate_kwargs))
        self.leaf = make_cert(
            name("leaf.test"), intermediate_name, self.leaf_key,
            self.intermediate_key,
            **settings(dict(serial=3, sans=["leaf.test"], key_usage=LEAF_USAGE,
                            eku=[ExtendedKeyUsageOID.SERVER_AUTH]), leaf_kwargs))

    def verify(self, **options):
        settings = dict(now=NOW, hostname="leaf.test", purpose="server")
        settings.update(options)
        return allcrypt.verify_chain([self.leaf, self.intermediate],
                                     [self.root], **settings)


# ------------------------------------------------------------------ parsing ---

def test_parses_an_openssl_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    der = make_cert(name("parse.test", ORGANIZATION_NAME="Example AB",
                         COUNTRY_NAME="SE"),
                    name("Test Root"), key, key, serial=0x1234,
                    sans=["parse.test", "www.parse.test"],
                    key_usage=LEAF_USAGE,
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])

    certificate = allcrypt.Certificate(der)
    fields = certificate.to_dict()

    assert fields["version"] == 3
    assert fields["serialNumber"] == "1234"
    assert fields["commonName"] == "parse.test"
    assert fields["issuerCommonName"] == "Test Root"
    assert fields["signatureAlgorithm"] == "ECDSA with sha256"
    assert fields["publicKeyType"] == "EC P-256"
    assert fields["isCA"] is False
    assert ("DNS", "parse.test") in fields["subjectAltName"]
    assert ("DNS", "www.parse.test") in fields["subjectAltName"]
    assert "digitalSignature" in fields["keyUsage"]
    assert fields["extendedKeyUsage"] == ["1.3.6.1.5.5.7.3.1"]
    assert fields["unrecognisedCritical"] == []

    # Subject attributes come back in the ssl.getpeercert() shape.
    flat = {pair[0]: pair[1] for group in fields["subject"] for pair in group}
    assert flat["CN"] == "parse.test"
    assert flat["O"] == "Example AB"
    assert flat["C"] == "SE"

    assert certificate.der == der
    assert certificate.tbs == x509.load_der_x509_certificate(der).tbs_certificate_bytes


@pytest.mark.parametrize("key_factory,expected", [
    (lambda: ec.generate_private_key(ec.SECP256R1()), "EC P-256"),
    (lambda: ec.generate_private_key(ec.SECP384R1()), "EC P-384"),
    (lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), "RSA"),
])
def test_public_key_types(key_factory, expected):
    key = key_factory()
    der = make_cert(name("key.test"), name("key.test"), key, key)
    fields = allcrypt.Certificate(der).to_dict()
    assert fields["publicKeyType"] == expected
    if expected == "RSA":
        assert fields["publicKeyBits"] == 2048
    # No parameter set for these: an EC named curve maps one-to-one onto
    # its OID, so `publicKeyType` already carries everything the OID
    # would, and RSA has none at all. GOST is the exception - see below.
    assert fields["publicKeyParameterSet"] is None


def test_a_gost_key_reports_its_parameter_set_and_not_just_its_curve():
    """`publicKeyType` cannot tell CryptoPro-A from CryptoPro-XchA.

    They are the same domain parameters under two OIDs, so both come back
    as `gost256-a`, and a TLS ClientKeyExchange that names the wrong one
    is refused with a fatal `decode_error`. Two of the three real
    CryptoPro certificates in `vectors/live/` are on XchA, which is how
    that reached a user.

    The certificate here is one of those three - not a generated one,
    because our builder would write whichever spelling we told it to and
    the interesting case is the one somebody else chose.
    `tests/test_live_gost_certificates.rs` asserts the same field per
    certificate and that at least two of them are on an exchange set.
    """
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "vectors", "live",
                        "tlsgost-256.cryptopro.ru-0.der")
    with open(path, "rb") as handle:
        fields = allcrypt.Certificate(handle.read()).to_dict()

    assert fields["publicKeyType"] == "GOST R 34.10-2012 gost256-a"
    # id-GostR3410-2001-CryptoPro-XchA-ParamSet, which is *not*
    # 1.2.643.2.2.35.1 - the canonical CryptoPro-A spelling of the same
    # curve, and what this library used to substitute for it.
    assert fields["publicKeyParameterSet"] == "1.2.643.2.2.36.0"
    # The server names it in its own subject, which is the cheapest
    # independent confirmation available that the OID above is read right.
    assert "XchA" in fields["commonName"]


# SHA-1 is missing from this list because modern OpenSSL builds refuse to
# *produce* a SHA-1 signature at all, so `cryptography` cannot build the
# certificate. Our own builder can, and src/x509/verify.rs tests that a
# SHA-1 chain is refused by default and accepted under a legacy policy.
@pytest.mark.parametrize("hash_algorithm,expected", [
    (hashes.SHA256(), "ECDSA with sha256"),
    (hashes.SHA384(), "ECDSA with sha384"),
    (hashes.SHA512(), "ECDSA with sha512"),
])
def test_signature_algorithms(hash_algorithm, expected):
    key = ec.generate_private_key(ec.SECP384R1())
    der = make_cert(name("sig.test"), name("sig.test"), key, key,
                    hash_algorithm=hash_algorithm)
    assert allcrypt.Certificate(der).to_dict()["signatureAlgorithm"] == expected


def test_malformed_certificates_are_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    der = make_cert(name("trunc.test"), name("trunc.test"), key, key)

    for bad in (b"", b"\x30", der[:-1], der[:len(der) // 2], der + b"\x00",
                bytes(len(der))):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Certificate(bad)

    # Truncating at every offset must raise, never crash the interpreter.
    for cut in range(len(der)):
        try:
            allcrypt.Certificate(der[:cut])
        except allcrypt.CryptoError:
            pass


# ------------------------------------------------------------- verification ---

def test_a_good_chain_verifies():
    Chain().verify()


def test_a_tampered_certificate_fails():
    chain = Chain()
    broken = bytearray(chain.leaf)
    broken[-1] ^= 0x01
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([bytes(broken), chain.intermediate], [chain.root],
                              now=NOW, hostname="leaf.test")


def test_an_untrusted_root_is_refused():
    chain = Chain()
    other = Chain()
    with pytest.raises(allcrypt.CryptoError) as info:
        allcrypt.verify_chain([chain.leaf, chain.intermediate], [other.root],
                              now=NOW, hostname="leaf.test")
    assert "trusted root" in str(info.value)


def test_no_roots_never_verifies():
    chain = Chain()
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([chain.leaf, chain.intermediate], [],
                              now=NOW, hostname="leaf.test")


def test_hostname_must_match():
    chain = Chain()
    chain.verify(hostname="leaf.test")
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(hostname="evil.test")
    # The error says what the certificate does cover, because "verify failed"
    # with no reason is what makes these impossible to debug.
    assert "leaf.test" in str(info.value)


def test_expiry():
    chain = Chain(leaf_kwargs=dict(not_before=moment(2020),
                                   not_after=moment(2021),
                                   sans=["leaf.test"], key_usage=LEAF_USAGE,
                                   eku=[ExtendedKeyUsageOID.SERVER_AUTH]))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "Expired" in str(info.value)

    # Inside the window it is fine.
    chain.verify(now=int(moment(2020, 6, 1).timestamp()))

    # And before it.
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(now=int(moment(2019).timestamp()))
    assert "Not valid until" in str(info.value)


def test_an_expired_intermediate_fails():
    """Easy to check the leaf's dates and forget everything above it."""
    chain = Chain(intermediate_kwargs=dict(not_before=moment(2020),
                                           not_after=moment(2021)))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "Expired" in str(info.value)


def test_a_leaf_cannot_sign_a_certificate():
    """The bug that keeps coming back: without a basicConstraints check, a
    certificate anybody can buy can sign one for a bank."""
    chain = Chain(intermediate_kwargs=dict(
        ca=False, path_length=None, key_usage=LEAF_USAGE,
        basic_constraints=x509.BasicConstraints(ca=False, path_length=None)))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "not a CA" in str(info.value)


def test_an_intermediate_without_basic_constraints_fails():
    # ca=False and path_length=None together mean no basicConstraints
    # extension is added at all - which for a v3 certificate must be
    # treated as "not a CA", not as "unspecified, assume yes".
    chain = Chain(intermediate_kwargs=dict(ca=False, path_length=None,
                                           key_usage=CA_USAGE))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "basicConstraints" in str(info.value)


def test_path_length_is_enforced():
    chain = Chain(root_kwargs=dict(path_length=0))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "pathLen" in str(info.value)


def test_key_cert_sign_is_required_of_an_issuer():
    chain = Chain(intermediate_kwargs=dict(key_usage=usage(digital_signature=True)))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "keyCertSign" in str(info.value)


def test_extended_key_usage():
    chain = Chain(leaf_kwargs=dict(sans=["leaf.test"], key_usage=LEAF_USAGE,
                                   eku=[ExtendedKeyUsageOID.CLIENT_AUTH]))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(purpose="server")
    assert "extendedKeyUsage" in str(info.value)

    chain.verify(purpose="client")


def test_unknown_critical_extension_is_fatal():
    """Critical means: if you do not understand this, do not use me."""
    unknown = x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00")
    chain = Chain(leaf_kwargs=dict(
        sans=["leaf.test"], key_usage=LEAF_USAGE,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra_extensions=[(unknown, True)]))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "Critical extension" in str(info.value)

    # The same extension, not critical, is ignored as it should be.
    chain = Chain(leaf_kwargs=dict(
        sans=["leaf.test"], key_usage=LEAF_USAGE,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra_extensions=[(unknown, False)]))
    chain.verify()


def test_rsa_chain():
    """The RSA path through certificate verification, end to end."""
    chain = Chain(key_factory=lambda: rsa.generate_private_key(
        public_exponent=65537, key_size=2048))
    chain.verify()

    # And the key size floor.
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(min_rsa_bits=4096)
    assert "bits" in str(info.value)


def test_a_small_rsa_key_is_refused_by_default():
    chain = Chain(key_factory=lambda: rsa.generate_private_key(
        public_exponent=65537, key_size=1024))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "1024" in str(info.value)

    # But talking to something old is the point of this library, so it is
    # available by asking.
    chain.verify(min_rsa_bits=1024)


def test_wildcards_through_the_bindings():
    chain = Chain(leaf_kwargs=dict(sans=["*.leaf.test"], key_usage=LEAF_USAGE,
                                   eku=[ExtendedKeyUsageOID.SERVER_AUTH]))
    chain.verify(hostname="www.leaf.test")
    for bad in ("leaf.test", "a.b.leaf.test", "www.evil.test"):
        with pytest.raises(allcrypt.CryptoError):
            chain.verify(hostname=bad)


def test_ip_address_san():
    chain = Chain(leaf_kwargs=dict(sans=["192.0.2.1"], key_usage=LEAF_USAGE,
                                   eku=[ExtendedKeyUsageOID.SERVER_AUTH]))
    chain.verify(hostname="192.0.2.1")
    with pytest.raises(allcrypt.CryptoError):
        chain.verify(hostname="192.0.2.2")

    fields = allcrypt.Certificate(chain.leaf).to_dict()
    assert ("IP Address", "192.0.2.1") in fields["subjectAltName"]


def test_chain_order_matters():
    """A chain given the wrong way round must not verify. Some
    implementations helpfully reorder it; that helpfulness has hidden real
    misconfigurations."""
    chain = Chain()
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([chain.intermediate, chain.leaf], [chain.root],
                              now=NOW, purpose="any")


def test_unknown_purpose_is_refused():
    chain = Chain()
    with pytest.raises(allcrypt.CryptoError):
        chain.verify(purpose="banana")


# -------------------------------------------------------- name constraints ---
#
# These matter more than most of the file: the certificates are encoded by
# OpenSSL, so they check our *parser* against somebody else's writer as
# well as checking the enforcement. A nameConstraints extension has two
# implicit context tags wrapping a list of sequences, and an encoding we
# read only our own way would pass every Rust test and fail on everything
# real.


def constrained(permitted=None, excluded=None, level="intermediate"):
    """A chain whose root or intermediate carries a nameConstraints."""
    extension = x509.NameConstraints(permitted_subtrees=permitted,
                                     excluded_subtrees=excluded)
    # Critical, which is what RFC 5280 requires of a conforming CA - so
    # these also prove the extension stopped counting as an unrecognised
    # critical one, which used to refuse the chain for the wrong reason.
    kwargs = dict(serial=2, ca=True, path_length=0, key_usage=CA_USAGE,
                  extra_extensions=[(extension, True)])
    if level == "intermediate":
        return lambda **leaf: Chain(intermediate_kwargs=kwargs,
                                    leaf_kwargs=leaf)
    root = dict(serial=1, ca=True, key_usage=CA_USAGE,
                extra_extensions=[(extension, True)])
    return lambda **leaf: Chain(root_kwargs=root, leaf_kwargs=leaf)


def test_a_permitted_dns_subtree_is_enforced():
    build = constrained(permitted=[x509.DNSName("example.test")])

    inside = build(sans=["www.example.test"], key_usage=LEAF_USAGE,
                   eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    inside.verify(hostname="www.example.test")

    outside = build(sans=["www.other.test"], key_usage=LEAF_USAGE,
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    with pytest.raises(allcrypt.CryptoError) as info:
        outside.verify(hostname="www.other.test")
    assert "permitted subtree" in str(info.value)


def test_the_label_boundary_is_what_stops_a_lookalike():
    """`evilexample.test` shares a suffix with `example.test` and is not
    below it. A matcher written with a bare suffix test accepts it, and
    that is the whole attack."""
    build = constrained(permitted=[x509.DNSName("example.test")])
    lookalike = build(sans=["evilexample.test"], key_usage=LEAF_USAGE,
                      eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    with pytest.raises(allcrypt.CryptoError):
        lookalike.verify(hostname="evilexample.test")


def test_an_excluded_subtree_beats_a_permitted_one():
    build = constrained(permitted=[x509.DNSName("example.test")],
                        excluded=[x509.DNSName("bad.example.test")])

    good = build(sans=["good.example.test"], key_usage=LEAF_USAGE,
                 eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    good.verify(hostname="good.example.test")

    bad = build(sans=["www.bad.example.test"], key_usage=LEAF_USAGE,
                eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    with pytest.raises(allcrypt.CryptoError) as info:
        bad.verify(hostname="www.bad.example.test")
    assert "excluded" in str(info.value)


def test_a_constraint_on_the_root_reaches_the_leaf():
    """The case that matters in practice: a private root added to a store
    and confined to its owner's names. The intermediate says nothing, so
    only a check that runs over the whole path once a root is chosen can
    see it."""
    build = constrained(permitted=[x509.DNSName("example.test")], level="root")

    inside = build(sans=["in.example.test"], key_usage=LEAF_USAGE,
                   eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    inside.verify(hostname="in.example.test")

    outside = build(sans=["in.other.test"], key_usage=LEAF_USAGE,
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    with pytest.raises(allcrypt.CryptoError):
        outside.verify(hostname="in.other.test")


def test_an_ip_subtree_is_enforced():
    """The constraint's iPAddress is an address *and mask*, eight bytes
    where a subjectAltName's is four. `cryptography` writes it from an
    `ip_network`, so this checks our reading against their writing."""
    build = constrained(
        permitted=[x509.IPAddress(ipaddress.ip_network("192.0.2.0/24"))])

    inside = build(sans=["192.0.2.7"], key_usage=LEAF_USAGE,
                   eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    inside.verify(hostname="192.0.2.7")

    outside = build(sans=["198.51.100.7"], key_usage=LEAF_USAGE,
                    eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    with pytest.raises(allcrypt.CryptoError):
        outside.verify(hostname="198.51.100.7")


def test_an_unconstrained_name_form_is_not_constrained():
    """RFC 5280: "Restrictions apply only when the specified name form is
    present." A mail constraint says nothing about a DNS name."""
    build = constrained(permitted=[x509.RFC822Name("example.test")])
    chain = build(sans=["www.other.test"], key_usage=LEAF_USAGE,
                  eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    chain.verify(hostname="www.other.test")


def test_a_directory_name_subtree_is_enforced():
    """The one form RFC 5280 says every conforming application must
    handle - and the one python-cryptography's own path verifier does
    not, which is why it is here and not in the differential corpus."""
    base = x509.DirectoryName(x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org")]))
    extension = x509.NameConstraints(permitted_subtrees=[base],
                                     excluded_subtrees=None)
    intermediate = dict(serial=2, ca=True, path_length=0, key_usage=CA_USAGE,
                        extra_extensions=[(extension, True)])

    def leaf_for(organisation):
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
            x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")])
        chain = Chain(intermediate_kwargs=intermediate)
        chain.leaf = make_cert(subject, name("Test Intermediate"),
                               chain.leaf_key, chain.intermediate_key,
                               serial=3, sans=["leaf.test"],
                               key_usage=LEAF_USAGE,
                               eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        return chain

    leaf_for("Example Org").verify()
    with pytest.raises(allcrypt.CryptoError):
        leaf_for("Other Org").verify()


def test_a_nonsense_base_distance_is_refused_rather_than_ignored():
    """RFC 5280 requires minimum to be zero and maximum absent, and says
    an application meeting other values must process them or reject.
    Ignoring them widens the subtree, so this rejects - at parse time,
    because the extension cannot be understood at all.

    Hand-encoded: `cryptography` will not write a non-zero minimum."""
    # SEQUENCE { [0] { SEQUENCE { [2] "example.test", [0] 01 } } }
    base = b"example.test"
    subtree = b"\x82" + bytes([len(base)]) + base + b"\x80\x01\x01"
    subtree = b"\x30" + bytes([len(subtree)]) + subtree
    permitted = b"\xa0" + bytes([len(subtree)]) + subtree
    value = b"\x30" + bytes([len(permitted)]) + permitted

    chain = Chain(intermediate_kwargs=dict(
        serial=2, ca=True, path_length=0, key_usage=CA_USAGE,
        extra_extensions=[(x509.UnrecognizedExtension(
            x509.ObjectIdentifier("2.5.29.30"), value), True)]))
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify()
    assert "minimum" in str(info.value) or "BaseDistance" in str(info.value)


# -------------------------------------------------------------- revocation ---
#
# The CRLs here are built by OpenSSL, so these check our *parser* against
# somebody else's writer as well as checking the logic. A nameConstraints
# or a CRL we only ever read back from our own encoder would agree with
# itself whatever both got wrong.


def make_crl(issuer_name, signer_key, entries, *, this_update=None,
             next_update=None, number=1, extra_extensions=()):
    """Build a CRL with OpenSSL. `entries` is (serial, reason) pairs."""
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(issuer_name)
               .last_update(this_update or moment(2023))
               .next_update(next_update or moment(2033))
               .add_extension(x509.CRLNumber(number), critical=False))
    for extension, critical in extra_extensions:
        builder = builder.add_extension(extension, critical=critical)
    for serial, reason in entries:
        entry = (x509.RevokedCertificateBuilder()
                 .serial_number(serial)
                 .revocation_date(moment(2023)))
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(signer_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER)


class RevocableChain(Chain):
    """A chain whose intermediate may sign CRLs.

    The default `Chain` intermediate has keyCertSign and not cRLSign,
    which is a real configuration and one our checker refuses to accept
    a CRL from - see `test_an_intermediate_without_crl_sign_is_refused`.
    """

    def __init__(self, **kwargs):
        merged = dict(serial=2, ca=True, path_length=0,
                      key_usage=usage(key_cert_sign=True, crl_sign=True))
        merged.update(kwargs.pop("intermediate_kwargs", None) or {})
        super().__init__(intermediate_kwargs=merged, **kwargs)

    def crl(self, entries, **kwargs):
        return make_crl(name("Test Intermediate"), self.intermediate_key,
                        entries, **kwargs)

    def root_crl(self, entries, **kwargs):
        return make_crl(name("Test Root"), self.root_key, entries, **kwargs)


def test_a_revoked_certificate_is_refused():
    chain = RevocableChain()
    # The leaf's serial is 3.
    chain.verify(crls=[chain.crl([])])
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(crls=[chain.crl([(3, None)])])
    assert "revoked" in str(info.value)


def test_another_serial_on_the_list_leaves_this_one_alone():
    chain = RevocableChain()
    chain.verify(crls=[chain.crl([(4, None), (5, None), (99, None)])])


def test_revocation_is_soft_fail_by_default_and_hard_on_request():
    chain = RevocableChain()
    # No CRL at all: fine by default.
    chain.verify()
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(require_revocation=True)
    assert "could not be established" in str(info.value)
    # Satisfied once both levels are covered.
    chain.verify(crls=[chain.root_crl([]), chain.crl([])],
                 require_revocation=True)


def test_a_revoked_intermediate_is_refused():
    """The case revocation exists for: the CA's key was compromised, so
    everything below it is suspect. Only a check that walks the whole
    chain sees it."""
    chain = RevocableChain()
    with pytest.raises(allcrypt.CryptoError) as info:
        # The intermediate's serial is 2, revoked by the root.
        chain.verify(crls=[chain.root_crl([(2, None)])])
    assert "revoked" in str(info.value)


def test_an_intermediate_without_crl_sign_is_refused():
    """RFC 5280 4.2.1.3: that bit is what permits signing a CRL, and a
    CA may keep separate keys for certificates and CRLs - one
    certificate with keyCertSign and one with cRLSign."""
    chain = Chain(intermediate_kwargs=dict(
        serial=2, ca=True, path_length=0,
        key_usage=usage(key_cert_sign=True)))      # no cRLSign
    crl = make_crl(name("Test Intermediate"), chain.intermediate_key,
                   [(3, None)])
    # Not evidence, so the chain is simply unrevoked as far as anyone
    # can tell - and under hard fail that is a failure to establish.
    chain.verify(crls=[crl])
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(crls=[crl], require_revocation=True)
    assert "cRLSign" in str(info.value)


def test_a_crl_from_the_wrong_key_is_not_evidence():
    chain = RevocableChain()
    other = RevocableChain()
    # The right issuer name, the wrong key.
    forged = make_crl(name("Test Intermediate"), other.intermediate_key,
                      [(3, None)])
    chain.verify(crls=[forged])
    with pytest.raises(allcrypt.CryptoError):
        chain.verify(crls=[forged], require_revocation=True)


def test_a_stale_crl_revokes_but_cannot_clear():
    """A revocation does not become untrue because the list carrying it
    is old. An absence from an old list is what proves nothing."""
    chain = RevocableChain()
    stale = dict(this_update=moment(2019), next_update=moment(2021))

    # Silent and stale: no conclusion.
    with pytest.raises(allcrypt.CryptoError):
        chain.verify(crls=[chain.root_crl([]), chain.crl([], **stale)],
                     require_revocation=True)
    # Stale and listing us: still revoked, even under soft fail.
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(crls=[chain.crl([(3, None)], **stale)])
    assert "revoked" in str(info.value)


def test_crl_status_reports_three_values_not_two():
    """A boolean cannot say "nothing could be established", and that is
    the answer every way of getting a CRL check wrong produces."""
    chain = RevocableChain()
    leaf, intermediate = chain.leaf, chain.intermediate

    assert allcrypt.crl_status(leaf, intermediate, [chain.crl([])], NOW) \
        == ("not_revoked", "")

    status, detail = allcrypt.crl_status(
        leaf, intermediate, [chain.crl([(3, x509.ReasonFlags.key_compromise)])],
        NOW)
    assert status == "revoked"
    assert "keyCompromise" in detail

    status, detail = allcrypt.crl_status(leaf, intermediate, [], NOW)
    assert status == "unknown"
    assert "no CRL" in detail


def test_the_distribution_points_come_back():
    """Where to fetch a CRL, reported and never fetched - nothing in
    this library opens a socket."""
    point = x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(
            "http://crl.example.test/ca.crl")],
        relative_name=None, reasons=None, crl_issuer=None)
    chain = Chain(leaf_kwargs=dict(
        serial=3, sans=["leaf.test"], key_usage=LEAF_USAGE,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra_extensions=[(x509.CRLDistributionPoints([point]), False)]))
    assert allcrypt.crl_distribution_points(chain.leaf) == \
        ["http://crl.example.test/ca.crl"]

    # A certificate with no such extension reports nothing rather than
    # raising: not having one is ordinary.
    assert allcrypt.crl_distribution_points(Chain().leaf) == []


def test_a_delta_crl_alone_cannot_clear_anything():
    """It lists only what changed since its base, so every older
    revocation is absent from it."""
    chain = RevocableChain()
    delta = chain.crl([], number=5, extra_extensions=[
        (x509.DeltaCRLIndicator(3), True)])
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(crls=[chain.root_crl([]), delta],
                     require_revocation=True)
    assert "delta" in str(info.value)


# -------------------------------------------------------------------- OCSP ---
#
# The responses here are built by OpenSSL, so these check our *parser*
# against somebody else's writer. An OCSP response has three levels of
# nesting, an OCTET STRING holding DER, and four context tags whose
# implicitness differs - a reader that only ever met its own writer's
# output would agree with whatever both got wrong.

from cryptography.x509 import ocsp as pyocsp


def make_response(chain, status, *, signer_key=None, responder=None,
                  revocation_time=None, reason=None, certs=None,
                  this_update=None, next_update=None, about=None,
                  about_issuer=None, nonce=None):
    """Build a BasicOCSPResponse with OpenSSL."""
    leaf = x509.load_der_x509_certificate(about or chain.leaf)
    issuer = x509.load_der_x509_certificate(
        about_issuer or chain.intermediate)
    builder = pyocsp.OCSPResponseBuilder().add_response(
        cert=leaf, issuer=issuer, algorithm=hashes.SHA1(),
        cert_status=status,
        this_update=this_update or moment(2023),
        next_update=next_update or moment(2033),
        revocation_time=revocation_time, revocation_reason=reason)
    builder = builder.responder_id(
        pyocsp.OCSPResponderEncoding.NAME,
        x509.load_der_x509_certificate(responder or chain.intermediate))
    if certs:
        builder = builder.certificates(
            [x509.load_der_x509_certificate(c) for c in certs])
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    signed = builder.sign(signer_key or chain.intermediate_key, hashes.SHA256())
    return signed.public_bytes(serialization.Encoding.DER)


def test_a_stapled_response_gives_all_three_answers():
    chain = RevocableChain()
    good = make_response(chain, pyocsp.OCSPCertStatus.GOOD)
    chain.verify(ocsp=[good])

    revoked = make_response(chain, pyocsp.OCSPCertStatus.REVOKED,
                            revocation_time=moment(2023),
                            reason=x509.ReasonFlags.key_compromise)
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(ocsp=[revoked])
    assert "revoked" in str(info.value)

    # **unknown is not good.** The responder is saying it cannot speak
    # for this certificate.
    unknown = make_response(chain, pyocsp.OCSPCertStatus.UNKNOWN)
    chain.verify(ocsp=[unknown])                 # soft fail lets it through
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(ocsp=[unknown], crls=[chain.root_crl([])],
                     require_revocation=True)
    assert "unknown" in str(info.value)


def test_a_response_about_another_certificate_answers_for_nothing():
    """Signed by a real CA, valid, and about somebody else - which is
    the shape of a response harvested from another connection."""
    chain = RevocableChain()
    other = RevocableChain()
    elsewhere = make_response(chain, pyocsp.OCSPCertStatus.GOOD,
                              about=other.leaf,
                              about_issuer=other.intermediate)
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(ocsp=[elsewhere], crls=[chain.root_crl([])],
                     require_revocation=True)
    assert "says nothing about this certificate" in str(info.value)


def test_a_delegated_responder_needs_ocsp_signing():
    """RFC 6960 4.2.2.2: a delegated responder must carry
    id-kp-OCSPSigning *and* be issued by the CA in question. Without
    the first, every customer of a CA could answer for every other."""
    chain = RevocableChain()
    responder_key = ec.generate_private_key(ec.SECP256R1())

    def responder_cert(eku):
        return make_cert(name("Test Responder"), name("Test Intermediate"),
                         responder_key, chain.intermediate_key, serial=9,
                         key_usage=LEAF_USAGE, eku=eku)

    proper = responder_cert([ExtendedKeyUsageOID.OCSP_SIGNING])
    improper = responder_cert([ExtendedKeyUsageOID.SERVER_AUTH])

    accepted = make_response(chain, pyocsp.OCSPCertStatus.REVOKED,
                             revocation_time=moment(2023),
                             reason=x509.ReasonFlags.superseded,
                             signer_key=responder_key, responder=proper,
                             certs=[proper])
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(ocsp=[accepted])
    assert "revoked" in str(info.value)

    refused = make_response(chain, pyocsp.OCSPCertStatus.REVOKED,
                            revocation_time=moment(2023),
                            reason=x509.ReasonFlags.superseded,
                            signer_key=responder_key, responder=improper,
                            certs=[improper])
    # Not an answer at all, so the chain verifies under soft fail.
    chain.verify(ocsp=[refused])
    with pytest.raises(allcrypt.CryptoError) as info:
        chain.verify(ocsp=[refused], crls=[chain.root_crl([])],
                     require_revocation=True)
    assert "id-kp-OCSPSigning" in str(info.value)


def test_the_nonce_has_to_come_back():
    """A nonce is the only defence against a replayed response: without
    one a captured "good" is valid until its nextUpdate."""
    chain = RevocableChain()
    sent = b"\x5a" * 16

    matching = make_response(chain, pyocsp.OCSPCertStatus.GOOD, nonce=sent)
    assert allcrypt.ocsp_status(chain.leaf, chain.intermediate, matching,
                                NOW, nonce=sent) == ("not_revoked", "")

    different = make_response(chain, pyocsp.OCSPCertStatus.GOOD,
                              nonce=b"\xa5" * 16)
    status, detail = allcrypt.ocsp_status(chain.leaf, chain.intermediate,
                                          different, NOW, nonce=sent)
    assert status == "unknown" and "not the one" in detail

    absent = make_response(chain, pyocsp.OCSPCertStatus.GOOD)
    status, detail = allcrypt.ocsp_status(chain.leaf, chain.intermediate,
                                          absent, NOW, nonce=sent)
    assert status == "unknown" and "replay" in detail


def test_our_request_is_one_openssl_understands():
    """The round trip our encoder cannot check on its own."""
    chain = RevocableChain()
    nonce = b"\x11" * 16
    der = allcrypt.ocsp_request(chain.leaf, chain.intermediate, "sha1", nonce)

    theirs = pyocsp.load_der_ocsp_request(der)
    leaf = x509.load_der_x509_certificate(chain.leaf)
    assert theirs.serial_number == leaf.serial_number
    assert isinstance(theirs.hash_algorithm, hashes.SHA1)
    assert theirs.extensions.get_extension_for_class(x509.OCSPNonce).value \
        .nonce == nonce

    # And the CertID hashes are the ones their own builder computes -
    # which is what checks our reading of "the value (excluding tag and
    # length) of the subject public key field".
    mine = pyocsp.OCSPRequestBuilder().add_certificate(
        leaf, x509.load_der_x509_certificate(chain.intermediate),
        hashes.SHA1()).build()
    assert theirs.issuer_name_hash == mine.issuer_name_hash
    assert theirs.issuer_key_hash == mine.issuer_key_hash

    for hash_name, hash_class in [("sha256", hashes.SHA256),
                                  ("sha384", hashes.SHA384),
                                  ("sha512", hashes.SHA512)]:
        der = allcrypt.ocsp_request(chain.leaf, chain.intermediate, hash_name)
        theirs = pyocsp.load_der_ocsp_request(der)
        assert isinstance(theirs.hash_algorithm, hash_class)
        mine = pyocsp.OCSPRequestBuilder().add_certificate(
            leaf, x509.load_der_x509_certificate(chain.intermediate),
            hash_class()).build()
        assert theirs.issuer_key_hash == mine.issuer_key_hash


def test_the_responder_urls_come_back():
    point = x509.AccessDescription(
        x509.oid.AuthorityInformationAccessOID.OCSP,
        x509.UniformResourceIdentifier("http://ocsp.example.test/"))
    # caIssuers points at the issuer's *certificate*; an OCSP request
    # sent there reaches a file server, so it must not be reported.
    issuers = x509.AccessDescription(
        x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
        x509.UniformResourceIdentifier("http://certs.example.test/ca.cer"))
    chain = Chain(leaf_kwargs=dict(
        serial=3, sans=["leaf.test"], key_usage=LEAF_USAGE,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra_extensions=[
            (x509.AuthorityInformationAccess([point, issuers]), False)]))
    assert allcrypt.ocsp_responders(chain.leaf) == \
        ["http://ocsp.example.test/"]
    assert allcrypt.ocsp_responders(Chain().leaf) == []


def test_an_unsigned_error_status_is_never_an_answer():
    """responseStatus sits outside the signature, so tryLater and
    unauthorized are bytes anybody can write."""
    chain = RevocableChain()
    for status in [pyocsp.OCSPResponseStatus.MALFORMED_REQUEST,
                   pyocsp.OCSPResponseStatus.INTERNAL_ERROR,
                   pyocsp.OCSPResponseStatus.TRY_LATER,
                   pyocsp.OCSPResponseStatus.SIG_REQUIRED,
                   pyocsp.OCSPResponseStatus.UNAUTHORIZED]:
        der = pyocsp.OCSPResponseBuilder.build_unsuccessful(status) \
            .public_bytes(serialization.Encoding.DER)
        answer, detail = allcrypt.ocsp_status(chain.leaf, chain.intermediate,
                                              der, NOW)
        assert answer == "unknown", status
        assert "no signed statement" in detail
