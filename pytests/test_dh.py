"""Finite-field Diffie-Hellman, against Python's integers and OpenSSL.

The arithmetic is checked against `pow(g, x, p)`, which is as independent a
reference as exists. The *conventions* are checked against OpenSSL through
python-cryptography, because they cannot be derived from anything: the width
a shared secret is encoded to, and whether its leading zero bytes survive,
are agreements rather than facts, and TLS 1.2 and TLS 1.3 made opposite ones.

The tests here that matter most are the ones about a peer public value that
must be refused. Every one of them completes a key exchange in an
implementation that does not check - that is what makes them dangerous, and
what makes "it works against OpenSSL" an insufficient test.
"""

import pytest

from cryptography.hazmat.primitives.asymmetric import dh as _dh

import allcrypt


def as_int(value):
    return int.from_bytes(value, "big")


def as_bytes(value, width):
    return value.to_bytes(width, "big")


@pytest.fixture(scope="module")
def group():
    return allcrypt.DhGroup.modp(1024)


def test_the_built_in_groups_are_the_published_ones(group):
    """RFC 2409 section 6.2 and RFC 3526 section 3. A transcription error
    in a MODP group is not something the arithmetic would notice - both
    sides would simply fail to agree with anyone else."""
    assert group.bits == 1024
    assert as_int(group.g) == 2
    p = as_int(group.p)
    # Both groups are 2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + x)
    # in RFC 3526's construction, which fixes the top and bottom 64 bits.
    assert p >> 960 == (1 << 64) - 1, "the top 64 bits must be all ones"
    assert p & ((1 << 64) - 1) == (1 << 64) - 1, "the low 64 bits too"

    # RFC 3526's six, which `dh::rfc_modp_tests` also checks against the
    # documents' hex and their formula over pi.
    for bits in (1536, 2048, 3072, 4096, 6144, 8192):
        big = allcrypt.DhGroup.modp(bits)
        assert big.bits == bits
        assert as_int(big.p) >> (bits - 64) == (1 << 64) - 1
        assert as_int(big.p) & ((1 << 64) - 1) == (1 << 64) - 1

    with pytest.raises(allcrypt.CryptoError):
        allcrypt.DhGroup.modp(1000)


def test_a_key_pair_matches_pythons_own_arithmetic(group):
    p, g = as_int(group.p), as_int(group.g)
    private, public = group.generate_key_pair()
    assert len(private) == len(public) == 128, "values are padded to p"
    assert as_int(public) == pow(g, as_int(private), p)

    # And a private exponent we supply, rather than one it drew, so the
    # generator is not the only path tested.
    for exponent in [2, 3, 65537, 2 ** 64 + 1, p - 2]:
        ours = group.public_key(as_bytes(exponent, 128))
        assert as_int(ours) == pow(g, exponent, p), exponent


def test_both_sides_agree_and_so_does_openssl(group):
    p, g = as_int(group.p), as_int(group.g)
    a_private, a_public = group.generate_key_pair()
    b_private, b_public = group.generate_key_pair()

    ours = group.shared_secret(a_private, b_public)
    assert ours == group.shared_secret(b_private, a_public)
    assert as_int(ours) == pow(as_int(b_public), as_int(a_private), p)

    # The same exchange through OpenSSL, which is what settles the encoding
    # rather than the value.
    parameters = _dh.DHParameterNumbers(p, g)
    side_a = _dh.DHPrivateNumbers(
        as_int(a_private),
        _dh.DHPublicNumbers(as_int(a_public), parameters)).private_key()
    peer = _dh.DHPublicNumbers(as_int(b_public), parameters).public_key()
    assert side_a.exchange(peer) == ours


def test_a_shared_secret_shorter_than_the_modulus_is_still_padded():
    """The one-in-256 case, made routine.

    A shared secret is a number, and roughly one in 256 of them has a
    leading zero byte. OpenSSL pads to the width of the modulus, so we must
    too - and TLS 1.2 then strips those zeros again (RFC 5246 section
    8.1.2), which is the opposite rule for the same bytes.

    An implementation that gets either wrong interoperates perfectly until
    it does not, and then fails one connection in a way nobody can
    reproduce. The small group here makes short secrets common enough to
    test deliberately instead of waiting for one.
    """
    # 2^128 - 159 is prime. Far too small to use and exactly right here:
    # about one secret in 256 is short, and we can search for one.
    p = 2 ** 128 - 159
    width = 16
    small = allcrypt.DhGroup(as_bytes(p, width), b"\x02")

    peer = as_bytes(pow(2, 12345, p), width)
    for exponent in range(2, 4000):
        secret = small.shared_secret(as_bytes(exponent, width), peer)
        assert len(secret) == width, "the secret must always be p-width"
        assert as_int(secret) == pow(as_int(peer), exponent, p)
        if secret[0] == 0:
            premaster = small.tls_premaster(as_bytes(exponent, width), peer)
            assert premaster == secret.lstrip(b"\x00")
            assert len(premaster) < len(secret), \
                "tls_premaster must strip the zeros the secret keeps"
            return
    pytest.fail("no short secret found in 4000 exponents, which is itself "
                "suspicious - about one in 256 should be short")


@pytest.mark.parametrize("name", ["zero", "one", "p-1", "p", "p+1"])
def test_degenerate_peer_values_are_refused(group, name):
    """`y = 0` makes every shared secret 0. `y = 1` makes it 1. `y = p-1`
    has order 2, so the secret is 1 or p-1 depending on the parity of our
    exponent - one bit of the private key, per handshake, to anyone
    watching. All three complete a key exchange if nobody checks."""
    p = as_int(group.p)
    value = {"zero": 0, "one": 1, "p-1": p - 1, "p": p, "p+1": p + 1}[name]
    peer = as_bytes(value, (p.bit_length() + 7) // 8 + 1)

    private, _public = group.generate_key_pair()
    with pytest.raises(allcrypt.CryptoError):
        group.validate_peer(peer)
    with pytest.raises(allcrypt.CryptoError):
        group.shared_secret(private, peer)


def test_the_ends_of_the_valid_range_are_accepted(group):
    """The complement of the test above: this is a range check, not a
    blanket refusal, and an off-by-one here refuses honest values."""
    p = as_int(group.p)
    for value in [2, 3, p - 3, p - 2]:
        group.validate_peer(as_bytes(value, 128))


def test_a_group_that_is_not_one_is_refused():
    p = as_int(allcrypt.DhGroup.modp(1024).p)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.DhGroup(as_bytes(p + 1, 128), b"\x02")   # even modulus
    for bad_g in [0, 1, p - 1]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.DhGroup(as_bytes(p, 128), as_bytes(bad_g, 128))


def test_the_prime_check_passes_on_a_real_group_and_fails_on_a_composite():
    """A composite modulus is the attack this exists for: the discrete log
    splits by the Chinese remainder theorem into two small ones, and the
    shared secret becomes computable by whoever chose p. Nothing else in a
    handshake notices, because nothing else is wrong."""
    q = 0xf7d1a5c3b98f4e2d0c6b8a3f5e1d9c7b
    r = 0xe3b5c9d7f1a3856942c7e8b1d5f39ca7
    composite = allcrypt.DhGroup(as_bytes(q * r, 32), b"\x02")

    # It behaves perfectly, which is the whole problem.
    a_private, a_public = composite.generate_key_pair()
    b_private, b_public = composite.generate_key_pair()
    assert (composite.shared_secret(a_private, b_public)
            == composite.shared_secret(b_private, a_public))

    with pytest.raises(allcrypt.CryptoError):
        composite.check_prime(16)

    # 1024 bits rather than 2048: this is 24 full-width exponentiations and
    # the point is that the check passes on a real group, which the smaller
    # one makes just as well in a quarter of the time.
    allcrypt.DhGroup.modp(1024).check_prime(16)
