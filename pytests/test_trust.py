"""The trust store and PEM handling.

The system store is the interesting one, because it is the only test in the
suite that runs against a few hundred certificates nobody here wrote. If our
parser is over-strict, this is where it shows up.
"""

import base64
import hashlib

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import allcrypt


# ------------------------------------------------------------------- PEM ---

def test_pem_round_trip():
    der = bytes(range(256))
    text = allcrypt.pem_wrap(der)
    assert text.startswith("-----BEGIN CERTIFICATE-----")
    assert allcrypt.pem_certificates(text) == [der]

    # The label is a parameter, and only certificates come back.
    key_text = allcrypt.pem_wrap(b"secret", label="PRIVATE KEY")
    assert allcrypt.pem_certificates(key_text) == []
    assert allcrypt.pem_certificates(text + key_text) == [der]


def test_pem_matches_the_standard_library():
    """Our base64 and Python's must agree, including the line wrapping."""
    der = bytes(range(200))
    ours = allcrypt.pem_wrap(der)
    body = "".join(line for line in ours.splitlines()
                   if not line.startswith("-----"))
    assert base64.b64decode(body) == der
    assert base64.b64encode(der).decode() == body


def test_pem_matches_openssl():
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "pem.test")])
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .sign(key, __import__("cryptography.hazmat.primitives.hashes",
                                         fromlist=["SHA256"]).SHA256()))

    their_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    their_der = certificate.public_bytes(serialization.Encoding.DER)

    # We read theirs...
    assert allcrypt.pem_certificates(their_pem) == [their_der]
    # ...and they read ours.
    reloaded = x509.load_pem_x509_certificate(
        allcrypt.pem_wrap(their_der).encode())
    assert reloaded == certificate


def test_malformed_pem_is_refused():
    for bad in ("-----BEGIN CERTIFICATE-----\nZm9v\n-----END PRIVATE KEY-----\n",
                "-----BEGIN CERTIFICATE-----\nZm9v\n",
                "-----BEGIN CERTIFICATE-----\nZm9!\n-----END CERTIFICATE-----\n"):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.pem_certificates(bad)

    # Text with no blocks at all is empty, not an error.
    assert allcrypt.pem_certificates("nothing here") == []


# ----------------------------------------------------------- trust stores ---

def a_root(common_name):
    import datetime
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                  critical=True)
                   .sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.DER)


def test_building_a_store():
    store = allcrypt.TrustStore()
    assert len(store) == 0

    store.add_der(a_root("Root One"))
    assert store.add_pem(allcrypt.pem_wrap(a_root("Root Two"))) == 1
    assert len(store) == 2
    assert store.skipped == 0

    subjects = store.subjects()
    assert "CN=Root One" in subjects
    assert "CN=Root Two" in subjects
    assert len(store.roots) == 2


def test_a_broken_entry_is_skipped_and_counted():
    """One bad entry in a bundle of hundreds must not take the rest with it,
    but the count has to be visible - a store that dropped most of its roots
    looks exactly like one that worked."""
    text = (allcrypt.pem_wrap(a_root("Good")) +
            allcrypt.pem_wrap(b"not a certificate") +
            allcrypt.pem_wrap(a_root("Also Good")))
    store = allcrypt.TrustStore()
    assert store.add_pem(text) == 2
    assert len(store) == 2
    assert store.skipped == 1


def test_a_skipped_entry_says_why():
    """The count is not a diagnosis. A run against a distribution bundle
    said "120 roots loaded, 1 skipped as unparseable" and there was no way
    to tell which root, or whether the certificate was malformed or this
    library too strict - and those have opposite remedies."""
    broken = b"not a certificate"
    store = allcrypt.TrustStore()
    store.add_pem(allcrypt.pem_wrap(a_root("Good")) + allcrypt.pem_wrap(broken))

    assert store.skipped == 1
    assert len(store.skipped_reasons) == 1
    reason = store.skipped_reasons[0]
    # Enough to find the entry again in a bundle where it has no subject
    # to be named by: its size, and the head of its digest.
    assert f"{len(broken)} byte" in reason, reason
    digest = hashlib.sha256(broken).hexdigest()[:16]
    assert digest in reason, reason


def test_an_empty_store_from_a_file_is_an_error():
    """Nothing usable is an error, not an empty list. An empty store
    silently becomes "trust nothing" two calls later."""
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.TrustStore.from_file("/nonexistent/ca-bundle.crt")


def test_from_file(tmp_path):
    bundle = tmp_path / "roots.pem"
    bundle.write_text(allcrypt.pem_wrap(a_root("File Root")))

    store = allcrypt.TrustStore.from_file(str(bundle))
    assert store.subjects() == ["CN=File Root"]
    assert store.source == str(bundle)

    empty = tmp_path / "empty.pem"
    empty.write_text("# no certificates\n")
    with pytest.raises(allcrypt.CryptoError) as info:
        allcrypt.TrustStore.from_file(str(empty))
    assert "No usable certificates" in str(info.value)


def test_from_directory(tmp_path):
    (tmp_path / "one.pem").write_text(allcrypt.pem_wrap(a_root("Dir One")))
    (tmp_path / "two.crt").write_text(allcrypt.pem_wrap(a_root("Dir Two")))
    (tmp_path / "ignored.txt").write_text(allcrypt.pem_wrap(a_root("Not Loaded")))

    store = allcrypt.TrustStore.from_directory(str(tmp_path))
    subjects = sorted(store.subjects())
    assert subjects == ["CN=Dir One", "CN=Dir Two"]


# ------------------------------------------------------- the real store ---

def test_the_system_store():
    """The only test here that runs against certificates nobody in this
    project wrote. If the DER parser were over-strict, this is where it
    would show - a parser that refuses real roots is not strict, it is
    broken."""
    try:
        store = allcrypt.TrustStore.system()
    except allcrypt.CryptoError as reason:
        pytest.skip(f"no system trust store on this machine: {reason}")

    # **No assertion on how many roots there are.** This said `> 20` and
    # failed on a machine with a smaller store - a minimal container
    # image, a locked-down build, a device that trusts one internal CA.
    # The number is a property of the machine, not of this code, and
    # `TrustStore.system()` already errors rather than returning an
    # empty store, so there is nothing left for a threshold to catch.
    # Same lesson as `TrustStore::skipped` elsewhere in this project: a
    # count is not a diagnosis.
    print(f"{len(store)} roots from {store.source}")

    assert store.skipped == 0, (
        f"{store.skipped} real roots could not be parsed, from {store.source}:\n"
        + "\n".join(f"  {reason}" for reason in store.skipped_reasons))

    # Every root must parse through the certificate API too, and OpenSSL
    # must agree about each one.
    #
    # `cryptography` emits a deprecation warning while loading some of
    # these: Go Daddy's G2 root, both Starfield G2 roots and the Hellenic
    # academic roots carry serial 0, which RFC 5280 forbids. We accept
    # them deliberately - refusing would mean being unable to verify a
    # large slice of the public web, which is the opposite of the point of
    # this library. See src/x509/mod.rs.
    for der in store.roots:
        ours = allcrypt.Certificate(der)
        theirs = x509.load_der_x509_certificate(der)
        assert ours.tbs == theirs.tbs_certificate_bytes
        assert ours.not_before == int(theirs.not_valid_before_utc.timestamp())
        assert ours.not_after == int(theirs.not_valid_after_utc.timestamp())


def test_a_real_root_verifies_a_chain_it_did_not_issue_is_refused():
    """Sanity: the system store must not accept a certificate nobody in it
    signed. It is the kind of thing that is obviously true and has still
    been wrong in shipped code."""
    try:
        store = allcrypt.TrustStore.system()
    except allcrypt.CryptoError as reason:
        pytest.skip(f"no system trust store: {reason}")

    import time
    stranger = a_root("Nobody's Root")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([stranger], store.roots, now=int(time.time()),
                              purpose="any")


# ------------------------------------------------- cross-signed anchors ---

def cross_signed_pair():
    """A root whose certificate was issued by *another* root.

    That is what a CA transition looks like on the wire: the new CA's key
    and name, certified by the old CA, so clients that do not know the
    new root can still build a path to one they do. Both forms of the new
    root then live in trust stores at once, and the cross-signed one is
    not self-issued.

    Returns ``(cross_der, old_root_der, leaf_der, new_self_signed_der)``.
    """
    import datetime
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    now = datetime.datetime.now(datetime.timezone.utc)
    start, end = now - datetime.timedelta(days=1), now + datetime.timedelta(days=3650)

    def name_of(common_name):
        return x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,
                                             common_name)])

    old_key = ec.generate_private_key(ec.SECP256R1())
    new_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    old_name, new_name = name_of("Old Root"), name_of("New Root")

    def ca(subject, issuer, public_key, signing_key, serial):
        return (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer)
                .public_key(public_key).serial_number(serial)
                .not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                               critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False), critical=True)
                .sign(signing_key, hashes.SHA256())
                .public_bytes(serialization.Encoding.DER))

    old_root = ca(old_name, old_name, old_key.public_key(), old_key, 1)
    new_self = ca(new_name, new_name, new_key.public_key(), new_key, 2)
    # The cross certificate: the new root's name and key, signed by the
    # old root. Subject != issuer, and it is still an anchor.
    cross = ca(new_name, old_name, new_key.public_key(), old_key, 3)

    leaf = (x509.CertificateBuilder()
            .subject_name(name_of("leaf.test")).issuer_name(new_name)
            .public_key(leaf_key.public_key()).serial_number(4)
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("leaf.test")]),
                           critical=False)
            .sign(new_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))

    return cross, old_root, leaf, new_self


def test_a_cross_signed_root_is_not_self_issued():
    """The assumption that broke a test on another machine, stated as a
    fact so it cannot be assumed again."""
    cross, old_root, _leaf, new_self = cross_signed_pair()

    parsed = allcrypt.Certificate(cross)
    assert parsed.subject != parsed.issuer, (
        "the cross certificate is self-issued, so it is not a cross "
        "certificate and this test proves nothing")

    for der in (old_root, new_self):
        one = allcrypt.Certificate(der)
        assert one.subject == one.issuer

    # And a store takes it perfectly happily - being an anchor is a
    # decision about the store, not a property of the bytes.
    store = allcrypt.TrustStore()
    store.add_der(cross)
    assert len(store) == 1
    assert store.skipped == 0


def test_a_cross_signed_root_is_a_usable_anchor():
    """A leaf under the new root must verify against a store holding only
    the *cross* certificate.

    This is the machine the report came from: its store held a root
    signed by another. If anchors were trusted by self-signature rather
    than by presence, every such chain would be refused - and the
    failure would look like a broken certificate rather than a wrong
    assumption here.
    """
    import time
    cross, old_root, leaf, new_self = cross_signed_pair()
    now = int(time.time())

    # The cross certificate alone is enough: it carries the new root's
    # key, which is what signed the leaf.
    allcrypt.verify_chain([leaf], [cross], now=now, purpose="server",
                          hostname="leaf.test")

    # So is the self-signed form of the same root, and so is a store
    # holding both, which is what a real store looks like mid-transition.
    allcrypt.verify_chain([leaf], [new_self], now=now, purpose="server",
                          hostname="leaf.test")
    allcrypt.verify_chain([leaf], [cross, new_self, old_root], now=now,
                          purpose="server", hostname="leaf.test")

    # The old root on its own is not enough. It signed the cross
    # certificate, not the leaf, and nothing sent that certificate - so
    # this must fail rather than chain through an anchor nobody
    # presented.
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.verify_chain([leaf], [old_root], now=now, purpose="server",
                              hostname="leaf.test")

    # With the cross certificate sent as an intermediate, the old root
    # anchors it - the whole point of cross-signing.
    allcrypt.verify_chain([leaf, cross], [old_root], now=now, purpose="server",
                          hostname="leaf.test")
