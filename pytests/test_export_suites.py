"""The export-grade suites, which nothing can negotiate any more.

OpenSSL removed them in 1.1.0 and this build offers none, so - like SSLv3 -
there is no handshake to run and no implementation to compare bytes with.
RC2 itself is the exception: `cryptography` keeps it in its decrepit
module, so the cipher is checked against OpenSSL directly.

What is left for this file is the plumbing and the decisions, above all
the one FREAK was about: whether a ServerKeyExchange is expected comes
from the negotiated suite and never from the message having arrived.
"""

import os

import pytest

from cryptography.hazmat.decrepit.ciphers.algorithms import RC2
from cryptography.hazmat.primitives.ciphers import Cipher, modes

import allcrypt


@pytest.mark.parametrize("length", [8, 16, 64, 800])
def test_rc2_matches_openssl(length):
    """At 128 bit keys, which is the only length `cryptography` accepts -
    and, not by coincidence, exactly what TLS's export suites expand to."""
    key, iv = os.urandom(16), os.urandom(8)
    data = os.urandom(length)

    ours = allcrypt.Cipher("rc2", key).encrypt("cbc", data, iv)
    enc = Cipher(RC2(key), modes.CBC(iv)).encryptor()
    assert ours == enc.update(data) + enc.finalize()
    assert allcrypt.Cipher("rc2", key).decrypt("cbc", ours, iv) == data


def test_rc2_effective_key_length_is_not_a_length_check():
    """The parameter whose entire purpose is to make a key *weaker*.

    A 16 byte key with 40 effective bits is a different cipher from the
    same 16 bytes unweakened - not a shorter key, and not a length
    validation. TLS's RC2_CBC_40 means the former. An implementation that
    ignored the parameter would round-trip perfectly against itself and
    agree with nobody.
    """
    key, iv = bytes(range(16)), bytes(8)
    plaintext = b"12345678"

    full = allcrypt.Cipher("rc2", key).encrypt("cbc", plaintext, iv)
    weak = allcrypt.Cipher("rc2", key, "40").encrypt("cbc", plaintext, iv)
    assert full != weak

    # OpenSSL's binding exposes no such parameter, so it agrees with the
    # unweakened one - which is what says our default is the ordinary
    # meaning of RC2 rather than something of our own.
    enc = Cipher(RC2(key), modes.CBC(iv)).encryptor()
    assert full == enc.update(plaintext) + enc.finalize()

    # And it round-trips under the same parameter, not under another.
    assert allcrypt.Cipher("rc2", key, "40").decrypt("cbc", weak, iv) == plaintext
    assert allcrypt.Cipher("rc2", key, "56").decrypt("cbc", weak, iv) != plaintext


@pytest.mark.parametrize("effective_bits", [1, 40, 56, 64, 128, 1024])
def test_every_effective_length_round_trips(effective_bits):
    key, iv = os.urandom(16), os.urandom(8)
    data = os.urandom(32)
    param = str(effective_bits)
    sealed = allcrypt.Cipher("rc2", key, param).encrypt("cbc", data, iv)
    assert allcrypt.Cipher("rc2", key, param).decrypt("cbc", sealed, iv) == data


@pytest.mark.parametrize("bad", ["0", "1025", "forty", ""])
def test_impossible_effective_lengths_are_refused(bad):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("rc2", os.urandom(16), bad)


def test_the_rfc_2268_vectors_through_the_binding():
    """Three of RFC 2268 section 5's rows, chosen because they share a key
    and differ only in the effective length - which is the parameter the
    whole cipher is remembered for."""
    key = bytes.fromhex("88bca90e90875a7f0f79c384627bafb2")
    for bits, want in [(64, "1a807d272bbe5db1"), (128, "2269552ab0f85ca6")]:
        # CBC with a zero IV over one block is ECB of that block, which is
        # how the RFC's vectors are stated.
        got = allcrypt.Cipher("rc2", key, str(bits)).encrypt("cbc", bytes(8), bytes(8))
        assert got.hex() == want, f"{bits} effective bits"
