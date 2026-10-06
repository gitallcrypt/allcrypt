"""The AEADs through the Python bindings, against OpenSSL.

AES-GCM, AES-CCM and ChaCha20-Poly1305. The unit tests in Rust cover each one's
specification vectors and `scripts/diff_check.py` covers thousands of
lengths. What is checked here is the binding: that the Python surface is
the one the ecosystem expects, that it agrees byte for byte with
`cryptography`, and that a failure raises rather than returning something.

The first half of this file is GCM-specific, because its nonce rules and
key sizes are its own. The second half is parametrized over both, because
the surface and the definition of a forgery are shared.
"""

import os

import pytest

import allcrypt

cryptography = pytest.importorskip("cryptography")
from cryptography.exceptions import InvalidTag                   # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import (        # noqa: E402
    AESCCM, AESGCM, ChaCha20Poly1305)


KEY_SIZES = [16, 24, 32]

#: Every AEAD, paired with its reference and its key size. The tests below
#: that are about the *construction* take one of these; the ones about AES
#: key sizes or GCM's nonce rules stay specific, because they are.
AEADS = [
    ("aes-gcm", AESGCM, 32),
    ("aes-ccm", AESCCM, 32),
    ("chacha20-poly1305", ChaCha20Poly1305, 32),
]
AEAD_IDS = [name for name, _, _ in AEADS]


@pytest.mark.parametrize("key_size", KEY_SIZES)
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 63, 64, 65, 1000])
def test_matches_openssl(key_size, length):
    """Ciphertext and tag both, over lengths either side of a block."""
    key = os.urandom(key_size)
    nonce = os.urandom(12)
    aad = b"associated data"
    message = os.urandom(length)

    assert allcrypt.Aead(key).encrypt(nonce, message, aad) == \
        AESGCM(key).encrypt(nonce, message, aad)


@pytest.mark.parametrize("aad_length", [0, 1, 15, 16, 17, 100])
def test_additional_data_lengths(aad_length):
    """The additional data is padded to a block boundary of its own, so the
    lengths either side of 16 are where an implementation goes wrong."""
    key, nonce = os.urandom(16), os.urandom(12)
    aad = os.urandom(aad_length)
    message = b"payload"

    ours = allcrypt.Aead(key).encrypt(nonce, message, aad)
    assert ours == AESGCM(key).encrypt(nonce, message, aad or b"")
    assert allcrypt.Aead(key).decrypt(nonce, ours, aad) == message


@pytest.mark.parametrize("nonce_length", [8, 12, 13, 16, 64])
def test_nonce_lengths(nonce_length):
    """A nonce that is not 96 bits is hashed into J0 rather than used
    directly, which is a separate code path from the common case."""
    key = os.urandom(16)
    nonce = os.urandom(nonce_length)
    message = b"a message"

    ours = allcrypt.Aead(key).encrypt(nonce, message)
    assert ours == AESGCM(key).encrypt(nonce, message, None)
    assert allcrypt.Aead(key).decrypt(nonce, ours) == message


@pytest.mark.parametrize("nonce_length", [1, 2, 4, 7])
def test_a_nonce_shorter_than_cryptography_allows(nonce_length):
    """`cryptography` refuses a nonce under 8 bytes. GCM does not: any
    non-empty nonce is defined, and the short ones go through the same
    GHASH derivation as a 60 byte one.

    We accept them, which is this library's whole premise - the limit in
    `cryptography` is a policy about what people should use, and something
    out there is already using one. Only an *empty* nonce is refused, and
    that is not policy: GHASH of nothing is zero, so J0 would be the same
    fixed block for every key.

    A short nonce is still a bad idea, and for the reason GCM is unforgiving
    about: a 1 byte nonce has 256 values, so a repeat is not unlikely but
    certain, and a repeat hands over the authentication key.
    """
    key = os.urandom(16)
    nonce = os.urandom(nonce_length)
    message = b"reaching something old"

    sealed = allcrypt.Aead(key).encrypt(nonce, message, b"aad")
    assert allcrypt.Aead(key).decrypt(nonce, sealed, b"aad") == message

    with pytest.raises(ValueError):
        AESGCM(key).encrypt(nonce, message, b"aad")

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key).encrypt(b"", message, b"aad")


def test_they_can_read_each_others_output():
    """Both directions across the boundary, not just ours-then-theirs."""
    key, nonce, aad = os.urandom(32), os.urandom(12), b"headers"
    message = b"interoperability is the only proof that matters"

    theirs = AESGCM(key).encrypt(nonce, message, aad)
    assert allcrypt.Aead(key).decrypt(nonce, theirs, aad) == message

    ours = allcrypt.Aead(key).encrypt(nonce, message, aad)
    assert AESGCM(key).decrypt(nonce, ours, aad) == message


def test_a_forgery_raises_rather_than_returning():
    """Every way of altering a sealed message must fail, and must fail by
    raising - a decryption that returns unverified plaintext alongside some
    error flag is a decryption whose caller will eventually use it."""
    key, nonce, aad = os.urandom(16), os.urandom(12), b"aad"
    sealed = allcrypt.Aead(key).encrypt(nonce, b"protected", aad)

    for index in range(len(sealed)):
        altered = bytearray(sealed)
        altered[index] ^= 0x01
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(key).decrypt(nonce, bytes(altered), aad)
        # And OpenSSL agrees this is a forgery, so the test is not just
        # asserting that we reject something valid.
        with pytest.raises(InvalidTag):
            AESGCM(key).decrypt(nonce, bytes(altered), aad)

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key).decrypt(nonce, sealed, b"different aad")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key).decrypt(os.urandom(12), sealed, aad)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(os.urandom(16)).decrypt(nonce, sealed, aad)
    # Truncation, including to less than a tag.
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key).decrypt(nonce, sealed[:-1], aad)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key).decrypt(nonce, b"short", aad)


def test_streaming_equals_one_call():
    key, nonce, aad = os.urandom(16), os.urandom(12), b"aad"
    message = os.urandom(500)
    aead = allcrypt.Aead(key)
    expected = aead.encrypt(nonce, message, aad)
    ciphertext, tag = expected[:-16], expected[-16:]

    for size in [1, 7, 16, 17, 64, 256]:
        stream = aead.encryptor(nonce, aad)
        out = b"".join(stream.update(message[i:i + size])
                       for i in range(0, len(message), size))
        assert out == ciphertext, f"encrypting in {size} byte pieces"
        assert stream.tag() == tag

        stream = aead.decryptor(nonce, aad)
        back = b"".join(stream.update(ciphertext[i:i + size])
                        for i in range(0, len(ciphertext), size))
        stream.verify(tag)
        assert back == message, f"decrypting in {size} byte pieces"


def test_a_streaming_verify_that_fails_raises():
    key, nonce = os.urandom(16), os.urandom(12)
    aead = allcrypt.Aead(key)
    sealed = aead.encrypt(nonce, b"protected")

    stream = aead.decryptor(nonce)
    stream.update(sealed[:-16])
    with pytest.raises(allcrypt.CryptoError):
        stream.verify(bytes(16))


def test_the_halves_are_not_interchangeable():
    key, nonce = os.urandom(16), os.urandom(12)
    aead = allcrypt.Aead(key)

    with pytest.raises(allcrypt.CryptoError):
        aead.encryptor(nonce).verify(bytes(16))
    with pytest.raises(allcrypt.CryptoError):
        aead.decryptor(nonce).tag()


def test_bad_construction_fails_at_construction():
    """A key AES does not have is an error when the object is made, not at
    the first encryption - which might be in a different function, hours
    later, with nothing nearby to explain it."""
    for key_size in [0, 1, 15, 17, 31, 33, 64]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(os.urandom(key_size))

    # **The stand-in for "an AEAD we do not have" must be one that cannot
    # become one.** This has now been wrong twice: it named `aes-ccm`
    # until CCM was implemented, and then `aes-eax` until EAX was - and
    # the second time, the comment sitting here was already a warning
    # about the first. So it is a name that is not an algorithm, plus a
    # plausible-looking one over a cipher that does not exist.
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(os.urandom(16), "not-an-aead")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(os.urandom(16), "nonesuch-eax")

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(os.urandom(16)).encrypt(b"", b"data")


def test_the_surface_says_what_it_is():
    key = os.urandom(32)
    aead = allcrypt.Aead(key)
    assert aead.name == "aes-gcm"
    assert aead.tag_size == 16
    assert "aes-gcm" in repr(aead)
    assert "256" in repr(aead)
    assert "aes-gcm" in allcrypt.aeads_available

    # The key must not be in the repr. It is the one thing in the object
    # that must never end up in a log line.
    assert key.hex() not in repr(aead)


def test_an_empty_message_is_still_authenticated():
    """Nothing to encrypt is not nothing to protect: the additional data
    still is, which is how GCM is used as a plain MAC."""
    key, nonce = os.urandom(16), os.urandom(12)
    sealed = allcrypt.Aead(key).encrypt(nonce, b"", b"just the headers")
    assert len(sealed) == 16
    assert sealed == AESGCM(key).encrypt(nonce, b"", b"just the headers")
    assert allcrypt.Aead(key).decrypt(nonce, sealed, b"just the headers") == b""

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key).decrypt(nonce, sealed, b"different headers")


# ---------------------------------------------------- both constructions ---
#
# ChaCha20-Poly1305 shares the surface but nothing underneath: a stream
# cipher instead of a block cipher in counter mode, Poly1305 instead of
# GHASH, sections padded to 16 bytes with a trailer of two little-endian
# byte counts instead of big-endian bit counts. The tests it shares with
# GCM are the ones about the surface and about what a forgery is.


@pytest.mark.parametrize("name,reference,key_size", AEADS, ids=AEAD_IDS)
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 63, 64, 65, 1000])
def test_every_aead_matches_openssl(name, reference, key_size, length):
    key = os.urandom(key_size)
    nonce = os.urandom(12)
    aad = b"associated data"
    message = os.urandom(length)

    assert allcrypt.Aead(key, name).encrypt(nonce, message, aad) == \
        reference(key).encrypt(nonce, message, aad)


@pytest.mark.parametrize("name,reference,key_size", AEADS, ids=AEAD_IDS)
@pytest.mark.parametrize("aad_length", [0, 1, 15, 16, 17, 100])
def test_every_aead_over_additional_data_lengths(name, reference, key_size,
                                                 aad_length):
    """Both constructions pad the additional data to a block boundary of
    their own, so the lengths either side of 16 are where each goes wrong -
    and they go wrong differently, since the block sizes and the trailers
    are not the same."""
    key, nonce = os.urandom(key_size), os.urandom(12)
    aad = os.urandom(aad_length)
    message = b"payload"

    ours = allcrypt.Aead(key, name).encrypt(nonce, message, aad)
    assert ours == reference(key).encrypt(nonce, message, aad or b"")
    assert allcrypt.Aead(key, name).decrypt(nonce, ours, aad) == message


@pytest.mark.parametrize("name,reference,key_size", AEADS, ids=AEAD_IDS)
def test_every_aead_refuses_a_forgery(name, reference, key_size):
    key, nonce, aad = os.urandom(key_size), os.urandom(12), b"aad"
    aead = allcrypt.Aead(key, name)
    sealed = aead.encrypt(nonce, b"protected", aad)

    for index in range(len(sealed)):
        altered = bytearray(sealed)
        altered[index] ^= 0x01
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(key, name).decrypt(nonce, bytes(altered), aad)
        with pytest.raises(InvalidTag):
            reference(key).decrypt(nonce, bytes(altered), aad)

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(nonce, sealed, b"other")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(os.urandom(12), sealed, aad)


@pytest.mark.parametrize("name,reference,key_size", AEADS, ids=AEAD_IDS)
def test_every_aead_streams(name, reference, key_size):
    key, nonce, aad = os.urandom(key_size), os.urandom(12), b"aad"
    message = os.urandom(500)
    aead = allcrypt.Aead(key, name)
    expected = aead.encrypt(nonce, message, aad)
    ciphertext, tag = expected[:-16], expected[-16:]

    if name.startswith("aes-ccm"):
        # CCM genuinely cannot stream: its MAC begins with the message's
        # length, so nothing can be processed before all of it is here.
        # The constructors refuse rather than buffering behind an
        # `update` that would promise constant memory and not deliver it.
        # `cryptography` draws the same line - its AESCCM has no
        # streaming pair either.
        with pytest.raises(allcrypt.CryptoError):
            aead.encryptor(nonce, aad)
        with pytest.raises(allcrypt.CryptoError):
            aead.decryptor(nonce, aad)
        return

    for size in [1, 7, 16, 17, 64, 65, 256]:
        stream = aead.encryptor(nonce, aad)
        out = b"".join(stream.update(message[i:i + size])
                       for i in range(0, len(message), size))
        assert out == ciphertext, f"{name}, {size} byte pieces"
        assert stream.tag() == tag

        stream = aead.decryptor(nonce, aad)
        back = b"".join(stream.update(ciphertext[i:i + size])
                        for i in range(0, len(ciphertext), size))
        stream.verify(tag)
        assert back == message


@pytest.mark.parametrize("name,reference,key_size", AEADS, ids=AEAD_IDS)
def test_every_aead_interoperates_both_ways(name, reference, key_size):
    key, nonce, aad = os.urandom(key_size), os.urandom(12), b"headers"
    message = b"interoperability is the only proof that matters"

    theirs = reference(key).encrypt(nonce, message, aad)
    assert allcrypt.Aead(key, name).decrypt(nonce, theirs, aad) == message

    ours = allcrypt.Aead(key, name).encrypt(nonce, message, aad)
    assert reference(key).decrypt(nonce, ours, aad) == message


def test_chacha20_poly1305_takes_only_a_96_bit_nonce():
    """Unlike GCM, this one has exactly one nonce length.

    RFC 8439 fixes it at 96 bits so the block counter gets a full 32 bits.
    ChaCha's original 8 byte nonce is a different construction with a 64
    bit counter, and accepting it here would quietly produce a function
    that is not the AEAD anyone else implements - so the usual "accept what
    is out there" rule does not apply: there is nothing out there using an
    8 byte nonce with this AEAD, because it does not exist.
    """
    key = os.urandom(32)
    for nonce_length in [0, 1, 8, 11, 13, 16, 24]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(key, "chacha20-poly1305").encrypt(
                os.urandom(nonce_length), b"data")

    assert len(allcrypt.Aead(key, "chacha20-poly1305").encrypt(
        os.urandom(12), b"data")) == 4 + 16


def test_chacha20_poly1305_takes_only_a_256_bit_key():
    for key_size in [0, 16, 24, 31, 33, 64]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(os.urandom(key_size), "chacha20-poly1305")
    assert allcrypt.Aead(os.urandom(32), "chacha20-poly1305").name == \
        "chacha20-poly1305"


def test_the_two_aeads_are_not_the_same_function():
    """A guard against the dispatch collapsing: same key, same nonce, same
    message, and the two must disagree. If a refactor ever routed both
    names to one implementation, every test above would still pass."""
    key, nonce, aad = os.urandom(32), os.urandom(12), b"aad"
    message = b"the same message"

    gcm = allcrypt.Aead(key, "aes-gcm").encrypt(nonce, message, aad)
    chacha = allcrypt.Aead(key, "chacha20-poly1305").encrypt(nonce, message, aad)
    assert gcm != chacha
    assert len(gcm) == len(chacha) == len(message) + 16

    # And neither can open the other's output.
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, "aes-gcm").decrypt(nonce, chacha, aad)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, "chacha20-poly1305").decrypt(nonce, gcm, aad)


# ------------------------------------------------------------------- EAX ---

EAX = [("aes-eax", 16), ("aes-eax", 32), ("twofish-eax", 32),
       ("serpent-eax", 32), ("camellia-eax", 16), ("sm4-eax", 16),
       ("des-eax", 8), ("3des-eax", 24), ("blowfish-eax", 16)]

EAX_IDS = [f"{name}-{length * 8}" for name, length in EAX]


@pytest.mark.parametrize("name,key_len", EAX, ids=EAX_IDS)
def test_eax_round_trips(name, key_len):
    """Nothing here implements EAX, so the reference is the vendored
    Botan vector file, read by the Rust tests - 190 cases over five
    ciphers. What this adds is the Python surface."""
    key = bytes((i * 37 + 11) % 256 for i in range(key_len))
    aead = allcrypt.Aead(key, name)
    out = aead.encrypt(b"a nonce", b"the message", b"header")
    assert allcrypt.Aead(key, name).decrypt(b"a nonce", out, b"header") == b"the message"


@pytest.mark.parametrize("name,key_len", EAX, ids=EAX_IDS)
def test_eax_authenticates_everything(name, key_len):
    key = bytes((i * 37 + 11) % 256 for i in range(key_len))
    aead = allcrypt.Aead(key, name)
    out = aead.encrypt(b"a nonce", b"the message", b"header")

    for index in range(len(out)):
        altered = bytearray(out)
        altered[index] ^= 0x01
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(key, name).decrypt(b"a nonce", bytes(altered), b"header")

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(b"b nonce", out, b"header")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(b"a nonce", out, b"other")


def test_eax_takes_a_nonce_of_any_length():
    """One of the two things EAX has over CCM, whose nonce is 7..13
    bytes and trades off against the maximum message size."""
    key = bytes(16)
    seen = set()
    for length in (0, 1, 7, 13, 16, 100):
        nonce = bytes(length)
        out = allcrypt.Aead(key, "aes-eax").encrypt(nonce, b"message", b"")
        assert allcrypt.Aead(key, "aes-eax").decrypt(nonce, out, b"") == b"message"
        assert out not in seen, f"nonce length {length} collided"
        seen.add(out)


# ------------------------------------------------------------------- OCB ---

OCB = [("aes-ocb", 16), ("aes-ocb", 24), ("aes-ocb", 32), ("camellia-ocb", 16),
       ("twofish-ocb", 32), ("serpent-ocb", 32), ("aria-ocb", 16),
       ("sm4-ocb", 16), ("seed-ocb", 16), ("kuznyechik-ocb", 32)]

OCB_IDS = [f"{name}-{length * 8}" for name, length in OCB]


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000])
@pytest.mark.parametrize("nonce_len", [12, 13, 14, 15])
def test_aes_ocb_matches_openssl(length, nonce_len):
    """OpenSSL's AES-OCB through python-cryptography, both directions.
    It takes 12 to 15 byte nonces and a 16 byte tag; the Rust tests
    carry RFC 7253's vectors for the rest."""
    from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
    for key_len in (16, 24, 32):
        key = bytes((i * 37 + 11) % 256 for i in range(key_len))
        nonce = bytes(range(40, 40 + nonce_len))
        message = bytes((i * 7) % 256 for i in range(length))
        ours = allcrypt.Aead(key, "aes-ocb").encrypt(nonce, message, b"header")
        assert ours == AESOCB3(key).encrypt(nonce, message, b"header")
        theirs = AESOCB3(key).encrypt(nonce, message, None)
        assert allcrypt.Aead(key, "aes-ocb").decrypt(nonce, theirs, b"") == message


@pytest.mark.parametrize("name,key_len", OCB, ids=OCB_IDS)
def test_ocb_authenticates_everything(name, key_len):
    key = bytes((i * 37 + 11) % 256 for i in range(key_len))
    nonce = b"a 15 byte nonce"
    out = allcrypt.Aead(key, name).encrypt(nonce, b"the message", b"header")
    assert allcrypt.Aead(key, name).decrypt(nonce, out, b"header") == b"the message"
    for index in range(len(out)):
        altered = bytearray(out)
        altered[index] ^= 0x01
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(key, name).decrypt(nonce, bytes(altered), b"header")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(b"a 15 byte nonc3", out, b"header")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(nonce, out, b"other")


def test_ocb_refuses_a_64_bit_cipher_and_a_long_nonce():
    """OCB is defined for 128 bit blocks only, and its nonce is at most
    120 bits."""
    assert "des-ocb" not in allcrypt.aeads_available
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(bytes(16), "aes-ocb").encrypt(bytes(16), b"m", b"")


# ------------------------------------------------------------------- MGM ---

MGM = [("kuznyechik-mgm", 32, 16), ("magma-mgm", 32, 8),
       ("aes-mgm", 16, 16), ("aes-mgm", 32, 16), ("twofish-mgm", 32, 16),
       ("sm4-mgm", 16, 16), ("des-mgm", 8, 8), ("3des-mgm", 24, 8),
       ("blowfish-mgm", 16, 8)]

MGM_IDS = [f"{name}-{length * 8}" for name, length, _ in MGM]


@pytest.mark.parametrize("name,key_len,block", MGM, ids=MGM_IDS)
def test_mgm_round_trips(name, key_len, block):
    """Nothing here implements MGM, so the reference is RFC 9058 twice:
    its four worked examples, parsed by the Rust tests, and a second
    reading in `scripts/diff_check.py` over 3,840 cases. What this adds
    is the Python surface - and the nonce rule, which is the thing a
    caller meets first."""
    key = bytes((i * 37 + 11) % 256 for i in range(key_len))
    nonce = bytes([0x11] * block)
    aead = allcrypt.Aead(key, name)
    out = aead.encrypt(nonce, b"the message", b"header")
    assert allcrypt.Aead(key, name).decrypt(nonce, out, b"header") == b"the message"
    assert len(out) == len(b"the message") + block


@pytest.mark.parametrize("name,key_len,block", MGM, ids=MGM_IDS)
def test_mgm_authenticates_everything(name, key_len, block):
    key = bytes((i * 37 + 11) % 256 for i in range(key_len))
    nonce = bytes([0x11] * block)
    other = bytes([0x11] * (block - 1) + [0x12])
    aead = allcrypt.Aead(key, name)
    out = aead.encrypt(nonce, b"the message", b"header")

    for index in range(len(out)):
        altered = bytearray(out)
        altered[index] ^= 0x01
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Aead(key, name).decrypt(nonce, bytes(altered), b"header")

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(other, out, b"header")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Aead(key, name).decrypt(nonce, out, b"other")


@pytest.mark.parametrize("name,key_len,block", MGM, ids=MGM_IDS)
def test_the_mgm_nonce_is_one_block_with_the_top_bit_clear(name, key_len, block):
    """**Refused rather than masked**, which is the whole point.

    MGM runs two counter chains and the top bit is what separates them:
    `0 || ICN` starts the keystream's and `1 || ICN` starts the
    authentication's. An implementation that took a full block and
    masked it quietly would turn two nonces differing only in that bit
    into one nonce - and a repeated nonce is the one thing RFC 9058
    section 6 says destroys the mode's security entirely.
    """
    key = bytes(key_len)
    aead = allcrypt.Aead(key, name)
    with pytest.raises(allcrypt.CryptoError):
        aead.encrypt(bytes([0x80] + [0x11] * (block - 1)), b"m", b"h")
    # And it is the *length* too: a nonce of any other size is refused
    # rather than padded or truncated.
    for length in (block - 1, block + 1, 12):
        if length == block or length <= 0:
            continue
        with pytest.raises(allcrypt.CryptoError):
            aead.encrypt(bytes(length), b"m", b"h")


def test_mgm_refuses_an_empty_message_and_empty_header_together():
    """RFC 9058 section 6: with nothing to authenticate the tag stops
    depending on the nonce, so one captured tag forges every such
    message under that key. Either one alone is fine."""
    key = bytes(32)
    nonce = bytes(16)
    aead = allcrypt.Aead(key, "kuznyechik-mgm")
    with pytest.raises(allcrypt.CryptoError):
        aead.encrypt(nonce, b"", b"")

    only_header = allcrypt.Aead(key, "kuznyechik-mgm").encrypt(nonce, b"", b"h")
    only_message = allcrypt.Aead(key, "kuznyechik-mgm").encrypt(nonce, b"h", b"")
    assert only_header != only_message, \
        "a byte of header and a byte of message give the same tag"


def test_the_two_mgm_block_sizes_are_different_modes():
    """MGM's field polynomial depends on the block size - `w^64 + w^4 +
    w^3 + w + 1` against `w^128 + w^7 + w^2 + w + 1` - so a 64 bit MGM
    built by copying the 128 bit path is self-consistent and wrong.

    Visible from here only as the tag length, which is the block; the
    arithmetic is checked by the corpus.
    """
    key = bytes(32)
    long_tag = allcrypt.Aead(key, "kuznyechik-mgm").encrypt(bytes(16), b"m", b"h")
    short_tag = allcrypt.Aead(key, "magma-mgm").encrypt(bytes(8), b"m", b"h")
    assert len(long_tag) == 1 + 16
    assert len(short_tag) == 1 + 8


# ------------------------------------------------ the tag length is asked ---

TAG_LENGTHS = [("aes-gcm", 16, 16), ("chacha20-poly1305", 32, 16),
               ("aes-ccm", 16, 16), ("aes-ccm-8", 16, 8),
               ("aes-eax", 16, 16), ("twofish-eax", 32, 16),
               ("des-eax", 8, 8), ("3des-eax", 24, 8), ("blowfish-eax", 16, 8),
               ("kuznyechik-mgm", 32, 16), ("magma-mgm", 32, 8),
               ("des-mgm", 8, 8), ("aes-mgm", 16, 16)]


def nonce_for(name, tag_len):
    """**The nonce is not one size either.**

    Twelve bytes for GCM, CCM and ChaCha20-Poly1305, any length for EAX,
    and for MGM exactly one block with the top bit clear - which for
    these rows is the tag length, since MGM's tag is the block. Derived
    rather than tabulated, because a second table of "which AEAD takes
    which nonce" is the same mistake as a table of key lengths, and this
    file already carries the note about that one.
    """
    if name.endswith("-mgm"):
        return bytes([0x11] * tag_len)
    return bytes(12)


@pytest.mark.parametrize("name,key_len,tag_len", TAG_LENGTHS,
                         ids=[n for n, _, _ in TAG_LENGTHS])
def test_the_tag_length_is_what_it_should_be(name, key_len, tag_len):
    key = bytes(key_len)
    out = allcrypt.Aead(key, name).encrypt(nonce_for(name, tag_len),
                                           b"12345678", b"")
    assert len(out) - 8 == tag_len


@pytest.mark.parametrize("name,key_len,tag_len", TAG_LENGTHS,
                         ids=[n for n, _, _ in TAG_LENGTHS])
def test_a_short_tag_round_trips_through_the_one_shot_interface(name, key_len, tag_len):
    """**The regression test for a bug EAX uncovered.**

    `Aead.decrypt` split `ciphertext || tag` sixteen bytes from the end,
    which was true of everything here until it was not. `aes-ccm-8` has
    an eight byte tag - that is its entire reason for existing - so it
    had *never* round-tripped through this interface, and EAX over a 64
    bit block cipher made a second family of the same failure.

    What made it worth a test rather than a fix is the error it gave:
    not "wrong length" but *"the tag does not match, so this ciphertext
    was not produced by whoever holds the key - or was modified after
    it was"*. A caller reading that would conclude their data had been
    tampered with. The length is asked of the AEAD now.
    """
    key = bytes(key_len)
    nonce = nonce_for(name, tag_len)
    aead = allcrypt.Aead(key, name)
    out = aead.encrypt(nonce, b"the message", b"header")
    assert allcrypt.Aead(key, name).decrypt(nonce, out, b"header") == b"the message"


def test_every_aead_in_the_catalogue_round_trips():
    """The catalogue is a promise. A name in it that cannot be used is
    worse than a name that is absent.

    **Every key and nonce length is tried and one must work**, rather
    than a table saying which (docs/pitfalls.md has the full story):
    a table of "which cipher takes which key length" has been wrong
    three times here, and the time it was *right* was worse - it meant
    the loop only ever handed GOST the one length that worked, and
    every other length panicked for years. The same argument applies to
    nonces now that MGM's is the block size rather than twelve.
    """
    checked = 0
    for name in allcrypt.aeads_available:
        worked = None
        # Up to 64: AES-256-CBC-HMAC-SHA512's key is its MAC key and
        # its AES key together.
        for key_len in range(5, 65):
            for nonce_len in (8, 12, 16, 24):
                key = bytes(key_len)
                # MGM's top bit is the domain separator, so a nonce of
                # zeros is a legal one for every AEAD here.
                nonce = bytes(nonce_len)
                try:
                    out = allcrypt.Aead(key, name).encrypt(nonce, b"message", b"")
                    back = allcrypt.Aead(key, name).decrypt(nonce, out, b"")
                except (allcrypt.CryptoError, ValueError):
                    continue
                assert back == b"message", name
                worked = (key_len, nonce_len)
                break
            if worked:
                break
        assert worked, f"{name} is in the catalogue and no key or nonce works"
        checked += 1
    assert checked == len(allcrypt.aeads_available) and checked > 25
