"""RSA bindings, checked against OpenSSL through `cryptography`.

The Rust suite and `tools/src/bin/diff_rsa.rs` cover the primitives and one
direction of each operation. What these tests add is the direction a dump
cannot reach — OpenSSL produces something and *we* have to accept it — plus
the binding layer itself.

Key generation is slow, so the keys are module scoped and generated once.
"""

import hashlib

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as ref_rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

import allcrypt

HASHES = {"md5": hashes.MD5(), "sha1": hashes.SHA1(), "sha224": hashes.SHA224(),
          "sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
          "sha512": hashes.SHA512()}


def number(key_or_bytes):
    return int.from_bytes(key_or_bytes, "big")


@pytest.fixture(scope="module")
def key():
    """One 1024 bit key for the whole module. Small for speed; the size is
    not what any of this is testing."""
    return allcrypt.RsaKey.generate(1024)


@pytest.fixture(scope="module")
def reference(key):
    """The same key, rebuilt inside OpenSSL.

    Reassembling it is itself a check: `private_key()` validates that the
    CRT parameters agree with the primes and that d really inverts e, so a
    key that only works because our code made the same mistake twice is
    rejected here.
    """
    n = key.numbers
    numbers = ref_rsa.RSAPrivateNumbers(
        p=number(n["p"]), q=number(n["q"]), d=number(n["d"]),
        dmp1=number(n["dp"]), dmq1=number(n["dq"]), iqmp=number(n["qinv"]),
        public_numbers=ref_rsa.RSAPublicNumbers(e=number(n["e"]), n=number(n["n"])))
    return numbers.private_key()


def test_generated_key_is_a_real_rsa_key(key, reference):
    assert key.key_size == 1024
    assert key.size == 128
    assert reference.key_size == 1024

    n = key.numbers
    assert number(n["p"]) * number(n["q"]) == number(n["n"])
    assert number(n["e"]) == 65537
    # p and q must be distinct and neither trivially small.
    assert n["p"] != n["q"]
    assert number(n["p"]).bit_length() == number(n["q"]).bit_length() == 512


def test_two_generated_keys_differ():
    """A generator that is stuck would pass everything else."""
    a = allcrypt.RsaKey.generate(512)
    b = allcrypt.RsaKey.generate(512)
    assert a.numbers["n"] != b.numbers["n"]


def test_generate_rejects_silly_sizes():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.RsaKey.generate(256)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.RsaKey.generate(1023)


def test_from_primes_round_trips(key):
    n = key.numbers
    again = allcrypt.RsaKey.from_primes(n["p"], n["q"])
    assert again.numbers == n


def test_from_primes_rejects_composites():
    with pytest.raises(allcrypt.CryptoError):
        # 2^61 - 1 is prime; the other is not.
        allcrypt.RsaKey.from_primes((2**61 - 1).to_bytes(8, "big"),
                                    (10**20 + 4).to_bytes(9, "big"))


# ------------------------------------------------------------- encryption ---

@pytest.mark.parametrize("length", [0, 1, 16, 53, 117])
def test_openssl_decrypts_our_ciphertext(key, reference, length):
    message = bytes((i * 31 + 7) & 0xff for i in range(length))
    ciphertext = key.public_key().encrypt(message)
    assert len(ciphertext) == key.size
    assert reference.decrypt(ciphertext, padding.PKCS1v15()) == message


@pytest.mark.parametrize("length", [0, 1, 16, 53, 117])
def test_we_decrypt_openssl_ciphertext(key, reference, length):
    """The direction a one-way dump cannot check."""
    message = bytes((i * 17 + 3) & 0xff for i in range(length))
    ciphertext = reference.public_key().encrypt(message, padding.PKCS1v15())
    assert key.decrypt(ciphertext) == message


def test_encryption_is_randomised(key):
    a = key.public_key().encrypt(b"same message")
    b = key.public_key().encrypt(b"same message")
    assert a != b, "PKCS#1 v1.5 encryption must be randomised"
    assert key.decrypt(a) == key.decrypt(b) == b"same message"


def test_message_too_long_is_refused(key):
    limit = key.size - 11
    assert len(key.public_key().encrypt(bytes(limit))) == key.size
    with pytest.raises(allcrypt.CryptoError):
        key.public_key().encrypt(bytes(limit + 1))


def test_decryption_failures_are_indistinguishable(key):
    """Bleichenbacher: if the caller can tell which check failed, the server
    is an oracle that decrypts captured traffic. Every failure must produce
    the same message."""
    good = key.public_key().encrypt(b"secret")

    seen = set()
    for bad in (bytes(key.size),
                b"\xff" * key.size,
                good[:-1],
                good + b"\x00",
                bytes([good[0] ^ 0xff]) + good[1:],
                good[:5] + bytes([good[5] ^ 0xff]) + good[6:]):
        with pytest.raises(allcrypt.CryptoError) as info:
            key.decrypt(bad)
        seen.add(str(info.value))

    assert len(seen) == 1, f"errors distinguish failures: {seen}"


# -------------------------------------------------------------- signatures ---

@pytest.mark.parametrize("digestmod", sorted(HASHES))
def test_signatures_match_openssl_byte_for_byte(key, reference, digestmod):
    """PKCS#1 v1.5 signing has no randomness, so a correct implementation
    produces exactly the same bytes OpenSSL does — a much stronger check
    than "it verifies"."""
    digest = allcrypt.new(digestmod, b"a message to sign").digest()

    ours = key.sign(digest, digestmod=digestmod)
    theirs = reference.sign(digest, padding.PKCS1v15(),
                            asym_utils.Prehashed(HASHES[digestmod]))
    assert ours == theirs

    # And OpenSSL must verify ours.
    reference.public_key().verify(ours, digest, padding.PKCS1v15(),
                                  asym_utils.Prehashed(HASHES[digestmod]))


@pytest.mark.parametrize("digestmod", sorted(HASHES))
def test_we_verify_openssl_signatures(key, reference, digestmod):
    digest = allcrypt.new(digestmod, b"signed by openssl").digest()
    theirs = reference.sign(digest, padding.PKCS1v15(),
                            asym_utils.Prehashed(HASHES[digestmod]))
    public = key.public_key()
    assert public.verify(digest, theirs, digestmod=digestmod)

    other = allcrypt.new(digestmod, b"a different message").digest()
    assert not public.verify(other, theirs, digestmod=digestmod)


def test_signing_is_deterministic(key):
    digest = allcrypt.sha256(b"sign me twice").digest()
    assert key.sign(digest) == key.sign(digest)


def test_verification_rejects_tampering(key):
    public = key.public_key()
    digest = allcrypt.sha256(b"authentic").digest()
    signature = key.sign(digest)

    assert public.verify(digest, signature)
    assert not public.verify(allcrypt.sha256(b"forged").digest(), signature)

    for index in (0, 1, 40, len(signature) - 1):
        tampered = bytearray(signature)
        tampered[index] ^= 0x01
        assert not public.verify(digest, bytes(tampered)), f"byte {index}"

    # The wrong hash name means a different DigestInfo prefix.
    assert not public.verify(digest, signature, digestmod="sha512")

    # Wrong length is malformed, not merely invalid.
    with pytest.raises(allcrypt.CryptoError):
        public.verify(digest, signature[:-1])
    with pytest.raises(allcrypt.CryptoError):
        public.verify(digest, b"")


def test_another_keys_signature_is_rejected(key):
    other = allcrypt.RsaKey.generate(1024)
    digest = allcrypt.sha256(b"authentic").digest()
    assert not key.public_key().verify(digest, other.sign(digest))


def test_unknown_digestmod_is_refused(key):
    with pytest.raises(allcrypt.CryptoError):
        key.sign(bytes(32), digestmod="md6")
    with pytest.raises(allcrypt.CryptoError):
        key.public_key().verify(bytes(32), bytes(key.size), digestmod="whirlpool")


def test_key_too_small_for_the_digest():
    """A 512 bit key cannot hold a SHA-512 DigestInfo. That is a size error,
    not a silently truncated signature."""
    small = allcrypt.RsaKey.generate(512)
    with pytest.raises(allcrypt.CryptoError):
        small.sign(hashlib.sha512(b"x").digest(), digestmod="sha512")
    # But SHA-256 fits.
    assert len(small.sign(hashlib.sha256(b"x").digest())) == 64


# ------------------------------------------------------------- public keys ---

def test_public_key_from_numbers(key):
    public = key.public_key()
    rebuilt = allcrypt.RsaPublicKey(public.n, public.e)
    assert rebuilt.key_size == public.key_size
    assert rebuilt.n == public.n and rebuilt.e == public.e

    digest = allcrypt.sha256(b"a message").digest()
    assert rebuilt.verify(digest, key.sign(digest))

    # The default exponent is 65537, so this must be the same key.
    assert allcrypt.RsaPublicKey(public.n).e == public.e


def test_public_key_rejects_nonsense():
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.RsaPublicKey(b"")                      # zero modulus
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.RsaPublicKey((100).to_bytes(1, "big"))  # even modulus
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.RsaPublicKey((15).to_bytes(1, "big"), (1).to_bytes(1, "big"))


# ---------------------------------------------------------------- PSS ---
#
# TLS 1.3 allows no other RSA signature scheme: `rsa_pss_rsae_sha256` and
# its siblings are the whole list (RFC 8446 section 4.2.3), so a client
# without PSS cannot talk to an RSA server at all.
#
# PSS also has to be verified differently from v1.5. v1.5 is deterministic,
# so verification rebuilds the block and compares bytes. PSS carries a salt
# the verifier has never seen, so the block must be *decoded* - and decoding
# a structure an attacker controls is where signature forgeries come from.


@pytest.mark.parametrize("name,algorithm,digestmod", [
    ("sha256", hashes.SHA256, hashlib.sha256),
    ("sha384", hashes.SHA384, hashlib.sha384),
    # SHA-512 is absent on purpose: a 1024 bit key cannot hold a 64 byte
    # hash, a 64 byte salt and two more bytes. OpenSSL refuses to sign it
    # and so do we, which `test_pss_refuses_a_key_that_cannot_hold_it` in
    # the Rust suite covers.
])
def test_pss_accepts_openssl_signatures(key, reference, name, algorithm,
                                        digestmod):
    """The direction a dump cannot reach: OpenSSL signs, we verify."""
    message = b"a message signed by OpenSSL"
    digest = digestmod(message).digest()
    signature = reference.sign(
        message,
        padding.PSS(mgf=padding.MGF1(algorithm()),
                    salt_length=digestmod().digest_size),
        algorithm())

    assert key.public_key().verify_pss(digest, signature, digestmod=name)


@pytest.mark.parametrize("name,algorithm,digestmod", [
    ("sha256", hashes.SHA256, hashlib.sha256),
    ("sha384", hashes.SHA384, hashlib.sha384),
])
def test_openssl_accepts_our_pss_signatures(key, reference, name, algorithm,
                                            digestmod):
    """And the other direction, which is the one that catches an encoder
    agreeing with our own decoder and with nobody else."""
    reference = reference.public_key()

    for _ in range(3):
        message = b"a message signed by us"
        digest = digestmod(message).digest()
        signature = key.sign_pss(digest, digestmod=name)
        reference.verify(
            signature, message,
            padding.PSS(mgf=padding.MGF1(algorithm()),
                        salt_length=digestmod().digest_size),
            algorithm())


def test_pss_is_randomised(key):
    """Two signatures over one digest must differ, and both must verify.
    A PSS that produced the same bytes twice is not using its salt, which
    is the entire difference from v1.5."""
    digest = hashlib.sha256(b"the same message").digest()
    signatures = {key.sign_pss(digest) for _ in range(8)}
    assert len(signatures) == 8, "PSS produced a repeated signature"
    for signature in signatures:
        assert key.public_key().verify_pss(digest, signature)


def test_pss_rejects_a_v15_signature_and_the_reverse(key):
    """The two schemes must not accept each other's signatures. They are
    both 'RSA with SHA-256' and they are not interchangeable."""
    public = key.public_key()
    digest = hashlib.sha256(b"crossed wires").digest()

    assert not public.verify_pss(digest, key.sign(digest))
    assert not public.verify(digest, key.sign_pss(digest))


def test_pss_salt_length_is_required_not_recovered(key):
    """RFC 8017 allows a verifier to take the salt length from the block.
    This one does not: a verifier that accepts any length accepts zero,
    which makes PSS deterministic and discards what it exists for. TLS 1.3
    fixes the length at the hash's own, which is also the default here."""
    public = key.public_key()
    digest = hashlib.sha256(b"salted").digest()
    signature = key.sign_pss(digest, salt_length=32)

    assert public.verify_pss(digest, signature, salt_length=32)
    for wrong in (0, 16, 31, 33, 48):
        assert not public.verify_pss(digest, signature, salt_length=wrong)

    # A zero-salt signature is legal PSS and must not verify as a 32 byte
    # one either, or the length check is only half there.
    flat = key.sign_pss(digest, salt_length=0)
    assert public.verify_pss(digest, flat, salt_length=0)
    assert not public.verify_pss(digest, flat, salt_length=32)


def test_pss_rejects_every_tampering(key):
    """Every single-byte change, refused - and refused as False rather
    than as an exception, so a caller cannot tell which step failed."""
    public = key.public_key()
    digest = hashlib.sha256(b"tamper with me").digest()
    signature = key.sign_pss(digest)

    for index in range(0, len(signature), 7):
        broken = bytearray(signature)
        broken[index] ^= 0x01
        assert not public.verify_pss(digest, bytes(broken))

    other = hashlib.sha256(b"a different message").digest()
    assert not public.verify_pss(other, signature)


# -------------------------------------------------------------------- OAEP ---

# Every pairing OpenSSL takes that a 1024-bit key holds: the hash sets the
# seed's length and hashes the label, MGF1's may differ.
OAEP_PAIRS = [(h, m) for h in ("sha1", "sha224", "sha256", "sha384")
              for m in ("sha1", "sha224", "sha256", "sha384", "sha512")]


def oaep(digestmod, mgf_digestmod, label):
    return padding.OAEP(mgf=padding.MGF1(HASHES[mgf_digestmod]),
                        algorithm=HASHES[digestmod], label=label or None)


@pytest.mark.parametrize("digestmod,mgf_digestmod", OAEP_PAIRS)
@pytest.mark.parametrize("label", [b"", b"a label"])
def test_openssl_decrypts_our_oaep(key, reference, digestmod, mgf_digestmod, label):
    limit = key.size - 2 * hashlib.new(digestmod).digest_size - 2
    for length in (0, 1, limit):
        message = bytes((i * 29 + 11) & 0xff for i in range(length))
        ciphertext = key.public_key().encrypt_oaep(message, digestmod, mgf_digestmod, label)
        assert len(ciphertext) == key.size
        assert reference.decrypt(ciphertext, oaep(digestmod, mgf_digestmod, label)) == message


@pytest.mark.parametrize("digestmod,mgf_digestmod", OAEP_PAIRS)
@pytest.mark.parametrize("label", [b"", b"a label"])
def test_we_decrypt_openssl_oaep(key, reference, digestmod, mgf_digestmod, label):
    limit = key.size - 2 * hashlib.new(digestmod).digest_size - 2
    for length in (0, 1, limit):
        message = bytes((i * 23 + 1) & 0xff for i in range(length))
        ciphertext = reference.public_key().encrypt(message,
                                                    oaep(digestmod, mgf_digestmod, label))
        assert key.decrypt_oaep(ciphertext, digestmod, mgf_digestmod, label) == message


def test_oaep_defaults_are_sha256_with_its_own_mgf_and_no_label(key, reference):
    ciphertext = key.public_key().encrypt_oaep(b"defaults")
    assert reference.decrypt(ciphertext, oaep("sha256", "sha256", b"")) == b"defaults"
    assert key.decrypt_oaep(ciphertext) == b"defaults"


def test_oaep_failures_are_indistinguishable(key):
    """Manger: learning whether the leading byte was zero is enough to
    decrypt. A wrong label, wrong hashes, PKCS#1 v1.5 ciphertext and every
    kind of corruption must all raise the one message."""
    public = key.public_key()
    good = public.encrypt_oaep(b"secret", "sha1", "sha1", b"label")
    assert key.decrypt_oaep(good, "sha1", "sha1", b"label") == b"secret"
    seen = set()
    for bad, args in ((good, ("sha1", "sha1", b"other")),
                      (good, ("sha256", "sha1", b"label")),
                      (good, ("sha1", "sha256", b"label")),
                      (public.encrypt(b"secret"), ("sha1", "sha1", b"label")),
                      (bytes(key.size), ("sha1", "sha1", b"label")),
                      (b"\xff" * key.size, ("sha1", "sha1", b"label")),
                      (good[:-1], ("sha1", "sha1", b"label")),
                      (good[:9] + bytes([good[9] ^ 1]) + good[10:], ("sha1", "sha1", b"label"))):
        with pytest.raises(allcrypt.CryptoError) as info:
            key.decrypt_oaep(bad, *args)
        seen.add(str(info.value))
    assert len(seen) == 1, f"errors distinguish failures: {seen}"


def test_oaep_message_too_long_is_refused(key):
    limit = key.size - 2 * 32 - 2
    assert len(key.public_key().encrypt_oaep(bytes(limit))) == key.size
    with pytest.raises(allcrypt.CryptoError):
        key.public_key().encrypt_oaep(bytes(limit + 1))
