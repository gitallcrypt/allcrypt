"""SSLv3, which nothing else on this machine can speak.

This Python's OpenSSL is built without SSLv3 - ``ssl.HAS_SSLv3`` is False -
so there is no server to hand a ClientHello to and no implementation to
compare bytes with. That is not an accident of this container; it is the
state of every current TLS library, and it is the reason this file exists.

What that leaves testable here is the plumbing and the decisions: the
version on the wire, the absence of extensions, and the floor that keeps a
context from reaching SSLv3 without being told to. The constructions
themselves - the key expansion, the record MAC and the 36 byte Finished -
are pinned in ``scripts/diff_check.py`` against references written from
RFC 6101, and in the Rust unit tests. Neither half is worth much alone.
"""

import ssl
import time

import pytest

import allcrypt
import allcrypt_ssl

NOW = int(time.time())


def client_hello(**options):
    """The raw ClientHello record a fresh client emits."""
    settings = dict(now=NOW, verify=False, ciphers="legacy")
    settings.update(options)
    return allcrypt.TlsClient("example.test", allcrypt.TrustStore(),
                              **settings).take_outgoing()


def parse_hello(record):
    """(record_version, hello_version, extension_bytes) from a ClientHello."""
    record_version = record[1:3]
    body = record[5 + 4:]                       # past the record and handshake headers
    hello_version = body[0:2]

    offset = 2 + 32                             # version, random
    offset += 1 + body[offset]                  # session_id
    suites_len = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2 + suites_len                    # cipher_suites
    offset += 1 + body[offset]                  # compression_methods
    return record_version, hello_version, body[offset:]


def test_an_ssl3_hello_carries_no_extensions():
    """Extensions arrived with RFC 3546, two years after SSLv3. A server
    old enough to speak nothing else is old enough to drop a hello that
    has them - and it drops it in a way that looks like a network failure
    rather than a protocol one, which is the single most likely reason an
    SSLv3 client fails while looking correct.

    The cost is real: no SNI, so a name-based virtual host answers with
    its default certificate. That is what SSLv3 is.
    """
    record_version, hello_version, extensions = parse_hello(
        client_hello(min_version="SSLv3", max_version="SSLv3"))

    assert hello_version == b"\x03\x00"
    assert extensions == b"", f"{len(extensions)} bytes of extensions"

    # The record version too: a server that has never seen a 0x0301 record
    # may refuse one, and claiming a version above our own ceiling would
    # be a lie in the one direction that matters.
    assert record_version == b"\x03\x00"


def test_a_tls_hello_still_carries_its_extensions():
    """The complement of the test above - otherwise "no extensions" could
    be true because the client never sends any."""
    _record_version, hello_version, extensions = parse_hello(
        client_hello(min_version="TLSv1", max_version="TLSv1.2"))
    assert hello_version == b"\x03\x03"
    assert len(extensions) > 20, "the TLS hello lost its extensions"


def test_the_shim_does_not_reach_ssl3_without_being_told():
    """POODLE is a property of the version, not of a suite: SSLv3's CBC
    padding bytes are unspecified, so a receiver may not check them, so an
    attacker learns a byte at a time. The only fix is not to speak it.

    So the floor stays at TLS 1.0 for a context that has not said
    otherwise - including ``create_legacy_context``, which lowers almost
    everything else.
    """
    for context in [allcrypt_ssl.create_default_context(),
                    allcrypt_ssl.create_legacy_context()]:
        assert context.minimum_version != ssl.TLSVersion.SSLv3
        # And the sentinel "whatever you can do" must not resolve to it
        # either, which is what `_OUR_LOWEST` is for.
        assert allcrypt_ssl.SSLContext._bounded(
            ssl.TLSVersion.MINIMUM_SUPPORTED,
            allcrypt_ssl._OUR_LOWEST) != ssl.TLSVersion.SSLv3


def test_asking_for_ssl3_explicitly_works():
    """A version this library refuses to reach at all would be a version
    it has not implemented. The point is that reaching it is a decision."""
    context = allcrypt_ssl.create_legacy_context()
    context.minimum_version = ssl.TLSVersion.SSLv3
    assert context.minimum_version == ssl.TLSVersion.SSLv3
    assert allcrypt_ssl.SSLContext._bounded(
        ssl.TLSVersion.SSLv3, allcrypt_ssl._OUR_LOWEST) == ssl.TLSVersion.SSLv3


def test_the_ssl3_key_schedule_is_not_the_tls_one():
    """The same inputs must not produce the same master secret. They would
    if the version were ignored, and nothing later in a handshake would
    say which construction had been used - both ends would simply agree on
    the wrong one and fail against everyone else.
    """
    premaster = bytes(range(48))
    client_random = bytes([0x11]) * 32
    server_random = bytes([0x22]) * 32

    ssl3 = allcrypt.tls_master_secret("SSLv3", premaster, client_random,
                                      server_random)
    tls10 = allcrypt.tls_master_secret("TLSv1", premaster, client_random,
                                       server_random)
    assert len(ssl3) == len(tls10) == 48
    assert ssl3 != tls10

    # And the expansion is deterministic, which is what makes the
    # differential corpus meaningful.
    assert ssl3 == allcrypt.tls_master_secret("SSLv3", premaster,
                                              client_random, server_random)


def test_the_ssl3_record_mac_is_not_hmac():
    """SSLv3's MAC concatenates the pads rather than XORing them into the
    key, and - the part a port of the TLS code would miss - does not cover
    the record's version at all."""
    mac_key = bytes(range(20))
    fragment = b"a record"

    ours = allcrypt.ssl3_record_mac("sha1", mac_key, 0, 23, fragment)
    assert len(ours) == 20

    # A reference written here from RFC 6101 section 5.2.3.1. Twelve lines,
    # which is the whole construction - and the only check available,
    # since nothing on this machine implements it.
    import hashlib
    header = (0).to_bytes(8, "big") + bytes([23]) + len(fragment).to_bytes(2, "big")
    inner = hashlib.sha1(mac_key + b"\x36" * 40 + header + fragment).digest()
    expected = hashlib.sha1(mac_key + b"\x5c" * 40 + inner).digest()
    assert ours == expected

    # The sequence number is covered, or records could be replayed.
    assert allcrypt.ssl3_record_mac("sha1", mac_key, 1, 23, fragment) != ours
    # So is the content type.
    assert allcrypt.ssl3_record_mac("sha1", mac_key, 0, 22, fragment) != ours


def test_ssl3_has_no_mac_for_sha256():
    """The pads are 48 bytes for MD5 and 40 for SHA-1, chosen to fill whole
    blocks of each. SHA-256 has no value in the specification, so any
    choice would be ours - and would agree with nobody."""
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.ssl3_record_mac("sha256", bytes(32), 0, 23, b"x")
