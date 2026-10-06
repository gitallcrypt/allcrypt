"""The OID registry, from Python.

What it is for: a box names a digest, a parameter set or a curve by an
OID this library does not carry, and the alternative to a rebuild is to
say what that OID means.

Every test here registers under `1.3.6.1.4.1.99999`, a private
enterprise arc that nothing standard uses, and removes what it
registered afterwards. Registrations are process-wide - pytest runs
these in one process - so a test that leaked one would change the
answers of whatever ran next, which is the worst kind of flake.
"""

import pytest

import allcrypt


PRIVATE = "1.3.6.1.4.1.99999"


@pytest.fixture
def oid():
    """One private-arc OID per test, cleaned up afterwards."""
    registered = []

    def make(suffix):
        value = f"{PRIVATE}.{suffix}"
        registered.append(value)
        return value

    yield make
    for value in registered:
        allcrypt.forget_oid(value)


def test_a_hash_can_be_named_by_an_oid(oid):
    """The case this exists for: a certificate naming its digest by an
    OID from a standard nobody vendored."""
    name = oid("1.1")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Hash(name, b"")

    allcrypt.register_oid(name, hash="gost94")
    assert (allcrypt.Hash(name, b"abc").hexdigest()
            == allcrypt.Hash("gost94", b"abc").hexdigest())


def test_a_gost_parameter_set_can_be_given_a_table(oid):
    """A GOST cipher **is** its S-box, so this is the one registration
    that carries cryptography rather than a name.

    The table here is a built-in one with a row reversed, which keeps
    it a valid set of permutations while making it a different cipher -
    and the assertion is that it *is* a different cipher, since a
    registration that was quietly ignored would otherwise look like it
    worked.
    """
    name = oid("2.1")
    rows = [list(row) for row in
            allcrypt.gost_sbox("id-Gost28147-89-CryptoPro-A-ParamSet")]
    assert len(rows) == 8 and all(len(row) == 16 for row in rows)
    rows[0] = list(reversed(rows[0]))
    allcrypt.register_oid(name, gost_sbox=rows)

    key, block = b"\x01" * 32, b"\x02" * 8
    builtin = allcrypt.Cipher("gost", key, "id-Gost28147-89-CryptoPro-A-ParamSet")
    custom = allcrypt.Cipher("gost", key, name)
    theirs = builtin.encryptor("ecb").update(block)
    ours = custom.encryptor("ecb").update(block)
    assert ours != theirs, "the registered table changed nothing"

    # And it is a cipher, not merely different: it inverts.
    assert custom.decryptor("ecb").update(ours) == block


def test_a_table_that_is_not_a_permutation_is_refused(oid):
    """The check that matters. A row repeating a value is still sixteen
    entries and is not a permutation, so the round function stops being
    a bijection - and the output still looks like ciphertext."""
    name = oid("2.2")
    # `gost_sbox` hands back bytes per row - a table is bytes, not a
    # list of ints - so a row being edited is turned into a list first.
    rows = [list(row) for row in
            allcrypt.gost_sbox("id-Gost28147-89-CryptoPro-A-ParamSet")]
    rows[2][0] = rows[2][1]
    with pytest.raises(allcrypt.CryptoError, match="not a permutation"):
        allcrypt.register_oid(name, gost_sbox=rows)

    rows = allcrypt.gost_sbox("id-Gost28147-89-CryptoPro-A-ParamSet")
    del rows[7]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.register_oid(name, gost_sbox=rows)


def test_a_curve_parameter_set_can_be_named(oid):
    name = oid("3.1")
    allcrypt.register_oid(name, curve="gost256-a")
    assert (name, "curve", "gost256-a") in allcrypt.registered_oids()


def test_exactly_one_meaning_per_registration(oid):
    name = oid("4.1")
    # A ValueError rather than a CryptoError: this is an argument
    # mistake, not a cryptographic one, and CPython's own functions
    # raise ValueError for "wrong combination of keywords".
    with pytest.raises(ValueError, match="exactly one"):
        allcrypt.register_oid(name, hash="sha256", curve="P-256")
    with pytest.raises(ValueError, match="exactly one"):
        allcrypt.register_oid(name)


def test_a_name_that_does_not_exist_is_refused(oid):
    """Refused at registration rather than at use, where the error
    would arrive in the middle of a handshake."""
    name = oid("5.1")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.register_oid(name, hash="no-such-hash")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.register_oid(name, curve="no-such-curve")
    assert not any(row[0] == name for row in allcrypt.registered_oids())


def test_a_malformed_oid_is_refused(oid):
    """Otherwise it would be stored and never match anything, which
    looks exactly like the feature not working."""
    for bad in ["1.2.three", "", "3.1.1", "1"]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.register_oid(bad, hash="sha256")


def test_a_registration_cannot_shadow_a_built_in(oid):
    """The compiled-in tables are consulted first, so a registration
    reaches only the OIDs this library does not know.

    Without that order, a library that registered an OID would change
    what it meant for every other caller in the process - including for
    certificate verification, which is not somewhere a caller should be
    able to reach from here.
    """
    sha256 = "2.16.840.1.101.3.4.2.1"
    try:
        allcrypt.register_oid(sha256, hash="md5")
        assert len(allcrypt.Hash("sha256", b"abc").digest()) == 32
    finally:
        allcrypt.forget_oid(sha256)


def test_registering_twice_replaces(oid):
    name = oid("6.1")
    allcrypt.register_oid(name, hash="sha256")
    allcrypt.register_oid(name, hash="sha512")
    assert (name, "hash", "sha512") in allcrypt.registered_oids()
    assert len(allcrypt.Hash(name, b"abc").digest()) == 64


def test_forget_says_whether_there_was_one(oid):
    name = oid("7.1")
    allcrypt.register_oid(name, hash="sha256")
    assert allcrypt.forget_oid(name) is True
    assert allcrypt.forget_oid(name) is False
    assert not any(row[0] == name for row in allcrypt.registered_oids())


def test_the_listing_describes_each_kind(oid):
    hash_oid, curve_oid, sbox_oid = oid("8.1"), oid("8.2"), oid("8.3")
    allcrypt.register_oid(hash_oid, hash="streebog256")
    allcrypt.register_oid(curve_oid, curve="P-384")
    allcrypt.register_oid(
        sbox_oid, gost_sbox=allcrypt.gost_sbox("id-tc26-gost-28147-param-Z"))

    listing = dict((row[0], (row[1], row[2]))
                   for row in allcrypt.registered_oids())
    assert listing[hash_oid] == ("hash", "streebog256")
    assert listing[curve_oid] == ("curve", "P-384")
    assert listing[sbox_oid][0] == "gost-param-set"
    assert "8" in listing[sbox_oid][1]


def test_the_builtin_tables_can_be_read_out(oid):
    """`gost_sbox` is how a caller starts from a table that exists,
    which is how a new parameter set is usually built."""
    for name in ["id-Gost28147-89-CryptoPro-A-ParamSet",
                 "id-tc26-gost-28147-param-Z",
                 "id-GostR3411-94-CryptoProParamSet"]:
        rows = allcrypt.gost_sbox(name)
        assert len(rows) == 8
        for row in rows:
            assert sorted(row) == list(range(16))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.gost_sbox("not-a-parameter-set")
