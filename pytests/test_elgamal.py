"""ElGamal through the Python bindings.

**There is no second implementation on this machine.** OpenSSL dropped
ElGamal entirely and `cryptography` has never had it, so unlike RSA or
Diffie-Hellman there is nothing here that can encrypt to us and tell us
we agree on a convention. `scripts/diff_check.py` checks the arithmetic
against Python's own integers, which is a real independent
implementation of `pow(g, x, p)` and nothing more.

That shapes this file. Where a test could be written against an outside
answer it is; where it cannot, the test asserts a *property* that a
wrong implementation would break - the malleability of the raw scheme,
the indistinguishability of the padding failures, the refusal of
degenerate values - rather than comparing our output with our own output
under a different name.

The reason any of this exists is old PGP keyrings: OpenPGP algorithm 16
is ElGamal encryption, and it was GnuPG's default encryption subkey for
years.
"""

import pytest

import allcrypt


def group():
    """The 1024 bit MODP group. Small enough that a test file full of
    exponentiations still runs in a second, and standard rather than
    generated, so the parameters are somebody else's."""
    return allcrypt.DhGroup.modp(1024)


def test_nothing_else_here_can_do_elgamal():
    """The premise of this file, asserted so that the day something can,
    `diff_check.py` gains a real reference and somebody is told."""
    from cryptography.hazmat.primitives.asymmetric import dh, rsa
    import cryptography.hazmat.primitives.asymmetric as asym
    assert not hasattr(asym, "elgamal")
    assert dh and rsa            # the two it does have, for contrast


# --------------------------------------------------------- encryption ---

def test_encrypt_and_decrypt_round_trip():
    key = allcrypt.ElGamalKey.generate(group())
    sealed = key.public_key().encrypt(b"from an old keyring")
    assert key.decrypt(sealed) == b"from an old keyring"


def test_a_ciphertext_is_two_modulus_widths():
    """`c1 || c2`, which is how OpenPGP writes them apart from the MPI
    length prefixes. A ciphertext of one width would mean a component
    was dropped or truncated, and the round trip alone would not say
    so."""
    key = allcrypt.ElGamalKey.generate(group())
    assert key.size == 128
    for message in [b"", b"x", b"a" * (key.size - 11)]:
        assert len(key.public_key().encrypt(message)) == 2 * key.size


def test_encryption_is_randomised():
    """Without a fresh nonce ElGamal is deterministic, and a
    deterministic public key encryption over a small message space can
    be enumerated."""
    key = allcrypt.ElGamalKey.generate(group())
    a = key.public_key().encrypt(b"same")
    b = key.public_key().encrypt(b"same")
    assert a != b
    assert key.decrypt(a) == key.decrypt(b) == b"same"


def test_a_message_one_byte_too_long_is_refused():
    key = allcrypt.ElGamalKey.generate(group())
    assert key.public_key().encrypt(bytes(key.size - 11))
    with pytest.raises(allcrypt.CryptoError):
        key.public_key().encrypt(bytes(key.size - 10))


def test_every_decryption_failure_gives_the_same_message():
    """Bleichenbacher's attack is about *which* check failed. One
    message, no detail - and this asserts it rather than trusting the
    constant to stay in one place.

    It is a property rather than a comparison, which is the shape most
    of this file has to take: there is nothing to compare against.
    """
    key = allcrypt.ElGamalKey.generate(group())
    sealed = key.public_key().encrypt(b"secret")

    messages = set()
    for broken in [sealed[:-1],                       # wrong length
                   bytes(len(sealed)),                # a degenerate c1
                   sealed[:key.size] + bytes(key.size)]:
        with pytest.raises(allcrypt.CryptoError) as refused:
            key.decrypt(broken)
        messages.add(str(refused.value))
    corrupt = bytearray(sealed)
    corrupt[key.size + 5] ^= 1
    with pytest.raises(allcrypt.CryptoError) as refused:
        key.decrypt(bytes(corrupt))
    messages.add(str(refused.value))

    assert len(messages) == 1, messages


def test_a_key_can_be_reloaded_from_its_private_exponent():
    """What reading a PGP secret key does: the file carries `x`, and `y`
    is recomputed rather than trusted."""
    key = allcrypt.ElGamalKey.generate(group())
    sealed = key.public_key().encrypt(b"archived")

    same = allcrypt.ElGamalKey.from_private(group(), key.private_bytes)
    assert same.public_bytes == key.public_bytes
    assert same.decrypt(sealed) == b"archived"


def test_a_degenerate_public_value_is_refused():
    """`y = 0`, `1` or `p-1` each generate a subgroup with one or two
    elements. All three are accepted by a naive constructor and make
    every ciphertext under them forgeable or constant."""
    g = group()
    p = int.from_bytes(g.p, "big")
    for bad in (0, 1, p - 1):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.ElGamalPublicKey(g, bad.to_bytes(128, "big"))
    # And a real one is accepted, so the check is not refusing everything.
    key = allcrypt.ElGamalKey.generate(g)
    assert allcrypt.ElGamalPublicKey(g, key.public_bytes).size == 128


def test_a_public_key_object_encrypts_to_the_same_private_key():
    """The public half has to be usable on its own - that is the whole
    point of a public key - and rebuilding it from bytes must reach the
    same key rather than a lookalike."""
    key = allcrypt.ElGamalKey.generate(group())
    rebuilt = allcrypt.ElGamalPublicKey(group(), key.public_bytes)
    assert key.decrypt(rebuilt.encrypt(b"to the holder")) == b"to the holder"
    assert rebuilt.y == key.public_bytes


# ------------------------------------------------------------ signing ---

def test_sign_and_verify():
    key = allcrypt.ElGamalKey.generate(group())
    digest = allcrypt.new("sha256", b"a message").digest()
    signature = key.sign(digest)
    assert len(signature) == 2 * key.size
    assert key.public_key().verify(digest, signature)


def test_a_signature_does_not_verify_over_another_message():
    key = allcrypt.ElGamalKey.generate(group())
    signature = key.sign(allcrypt.new("sha256", b"a message").digest())
    assert not key.public_key().verify(
        allcrypt.new("sha256", b"another").digest(), signature)


def test_signatures_are_randomised():
    """A repeated nonce gives the private key by subtraction - the same
    arithmetic that broke the PlayStation 3's ECDSA, and the family of
    mistake that made GnuPG withdraw ElGamal signing."""
    key = allcrypt.ElGamalKey.generate(group())
    digest = allcrypt.new("sha256", b"m").digest()
    first, second = key.sign(digest), key.sign(digest)
    assert first != second
    assert key.public_key().verify(digest, first)
    assert key.public_key().verify(digest, second)


def test_a_signature_of_the_wrong_length_is_refused():
    key = allcrypt.ElGamalKey.generate(group())
    digest = allcrypt.new("sha256", b"m").digest()
    signature = key.sign(digest)
    assert not key.public_key().verify(digest, signature[:-1])
    assert not key.public_key().verify(digest, signature + b"\x00")
    assert not key.public_key().verify(digest, b"")


def test_an_out_of_range_signature_is_refused():
    """**Bleichenbacher's 1996 forgery.** A verifier that accepts
    `r >= p` can be handed a forged signature for a chosen message. The
    check is invisible against honest signatures, because an honest `r`
    is `g^k mod p` and so always in range - which is why it needs a test
    of its own rather than being covered by the round trip."""
    key = allcrypt.ElGamalKey.generate(group())
    digest = allcrypt.new("sha256", b"m").digest()
    signature = key.sign(digest)
    size = key.size
    p = int.from_bytes(group().p, "big")

    for bad_r in (0, p):
        forged = bad_r.to_bytes(size, "big") + signature[size:]
        assert not key.public_key().verify(digest, forged), bad_r
    for bad_s in (0, p - 1):
        forged = signature[:size] + bad_s.to_bytes(size, "big")
        assert not key.public_key().verify(digest, forged), bad_s


# ------------------------------------------------------- the bindings ---

def test_it_takes_any_buffer_like_every_other_argument():
    key = allcrypt.ElGamalKey.generate(group())
    sealed = key.public_key().encrypt(bytearray(b"a buffer"))
    assert key.decrypt(memoryview(sealed)) == b"a buffer"


def test_repr_says_what_it_is():
    key = allcrypt.ElGamalKey.generate(group())
    assert "ElGamalKey" in repr(key)
    assert "128" in repr(key)
    assert "ElGamalPublicKey" in repr(key.public_key())
