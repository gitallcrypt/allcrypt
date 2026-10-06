"""The algorithm-name enumerations, and that they cannot drift.

`allcrypt.Mode.CBC` and the rest are generated at module init from the
same Rust constants the `*_available` lists come from. That is the whole
point: a hand-written Python enum would be a second place to add a mode,
and the two would disagree the first time somebody added one and forgot.

So the tests here are mostly about the *relationship* between the enum
and the catalogue, not about the members. A test naming members would be
the third copy.

They are `str` subclasses, so every existing call that passes a plain
string keeps working and no boundary has to convert. That is asserted
rather than assumed: it is the property the whole design rests on.
"""

import enum

import pytest

import allcrypt


# (enum, the list it is generated from)
PAIRS = [
    ("Mode", "modes_available"),
    ("HashName", "algorithms_available"),
    ("BlockCipher", "block_ciphers_available"),
    ("StreamCipherName", "stream_ciphers_available"),
    ("AeadName", "aeads_available"),
    ("CurveName", "curves_available"),
]


@pytest.mark.parametrize("enum_name,list_name", PAIRS)
def test_the_enum_holds_exactly_the_catalogue(enum_name, list_name):
    """Neither may grow without the other. This is the test the whole
    arrangement exists for."""
    members = getattr(allcrypt, enum_name)
    catalogue = getattr(allcrypt, list_name)
    assert [m.value for m in members] == list(catalogue)


@pytest.mark.parametrize("enum_name,_", PAIRS)
def test_the_members_are_strings(enum_name, _):
    """The property everything else rests on.

    If these were not `str` subclasses, every call site taking a name
    would need converting and the enum would be a migration rather than
    an addition.
    """
    for member in getattr(allcrypt, enum_name):
        assert isinstance(member, str)
        assert member == member.value


@pytest.mark.parametrize("enum_name,_", PAIRS)
def test_formatting_gives_the_value_not_the_member(enum_name, _):
    """`Enum` overrides `__str__` to produce `"Mode.CBC"`, which would
    make these unusable in any message or path built by formatting.
    Python 3.11's `StrEnum` fixes that; on 3.10 it is put back by hand,
    and this is what holds it."""
    for member in getattr(allcrypt, enum_name):
        assert str(member) == member.value
        assert f"{member}" == member.value
        assert "%s" % member == member.value


@pytest.mark.parametrize("enum_name,_", PAIRS)
def test_lookup_by_value_works(enum_name, _):
    members = getattr(allcrypt, enum_name)
    for member in members:
        assert members(member.value) is member
    with pytest.raises(ValueError):
        members("not-an-algorithm")


@pytest.mark.parametrize("enum_name,_", PAIRS)
def test_the_member_names_are_identifiers(enum_name, _):
    """`aes-gcm` cannot be an attribute name, so the generator maps
    anything that is not a letter or digit to an underscore. A name that
    came out not being an identifier would be unreachable by
    attribute."""
    for member in getattr(allcrypt, enum_name):
        assert member.name.isidentifier(), member.name
        assert member.name == member.name.upper()


def test_the_names_that_clash_with_classes_took_a_suffix():
    """`Hash`, `StreamCipher` and `Aead` are all types in this module.
    The enums for those catalogues carry a `Name` suffix rather than
    shadowing them - a shadowed class is a silent breakage, and the
    breakage would be at import."""
    for shadowed in ("Hash", "StreamCipher", "Aead"):
        assert isinstance(getattr(allcrypt, shadowed), type)
        assert not isinstance(getattr(allcrypt, shadowed), enum.EnumMeta)
    for suffixed in ("HashName", "StreamCipherName", "AeadName"):
        assert isinstance(getattr(allcrypt, suffixed), enum.EnumMeta)

    # And where there is no clash the plain name is used.
    for plain in ("Mode", "BlockCipher", "CurveName"):
        assert isinstance(getattr(allcrypt, plain), enum.EnumMeta)


# ------------------------------------------------- they work as arguments ---

def test_a_mode_enum_and_a_mode_string_give_the_same_bytes():
    key, block = bytes(16), b"sixteen byte blk"
    by_enum = allcrypt.Cipher(allcrypt.BlockCipher.AES, key).encrypt(
        allcrypt.Mode.ECB, block)
    by_string = allcrypt.Cipher("aes", key).encrypt("ecb", block)
    assert by_enum == by_string


def test_a_hash_enum_and_a_hash_string_give_the_same_digest():
    assert (allcrypt.new(allcrypt.HashName.SM3, b"abc").hexdigest()
            == allcrypt.new("sm3", b"abc").hexdigest())


def test_a_curve_enum_is_accepted_where_a_curve_name_is():
    assert allcrypt.EcKey.generate(allcrypt.CurveName.P_256).curve == "P-256"


def test_an_aead_enum_is_accepted_where_an_aead_name_is():
    allcrypt.Aead(bytes(16), allcrypt.AeadName.AES_GCM)


def test_a_stream_cipher_enum_is_accepted_where_its_name_is():
    allcrypt.StreamCipher(allcrypt.StreamCipherName.CHACHA20, bytes(32), bytes(12))


def _constructs(name, key_len):
    try:
        allcrypt.Aead(bytes(key_len), name)
        return True
    except ValueError:
        return False


def test_every_member_of_every_enum_actually_constructs():
    """`tests/test_api.rs` asserts this for the Rust constants. Here it
    is asserted for the enums, which is the same claim reached by a
    different route - and it is what makes the catalogue a promise
    rather than a list.

    Block ciphers are absent: each has its own key length, so a loop
    here would need a table of them, and a table would be a fourth copy
    of the catalogue. `tests/test_api.rs` covers those.
    """
    key, iv, block = bytes(16), bytes(16), bytes(16)
    for mode in allcrypt.Mode:
        cipher = allcrypt.Cipher(allcrypt.BlockCipher.AES, key)
        # ECB has no IV and the rest require one, so the call differs -
        # which is a property of the mode, not of the enum.
        if mode == allcrypt.Mode.ECB:
            assert cipher.encrypt(mode, block)
        else:
            assert cipher.encrypt(mode, block, iv=iv)

    for name in allcrypt.HashName:
        assert allcrypt.new(name).digest_size > 0

    for name in allcrypt.CurveName:
        assert allcrypt.EcKey.generate(name).curve

    for name in allcrypt.AeadName:
        # **Every key length, and at least one must work.** A table of
        # "which AEAD takes which key size" here would be a fourth copy
        # of the catalogue, and it would be wrong the first time one was
        # added - which is exactly what happened when EAX arrived over
        # DES and 3DES. The claim being tested is "this name is usable",
        # so trying the lengths and requiring one to succeed says it
        # without recording anything.
        usable = [n for n in (8, 16, 24, 32, 48, 64) if _constructs(name, n)]
        assert usable, f"{name.value} works at no key length"

    for name in allcrypt.StreamCipherName:
        # RC4 takes no nonce; the others take one. Again a property of
        # the algorithm rather than of the enum.
        nonce = b"" if name in (allcrypt.StreamCipherName.RC4,
                                allcrypt.StreamCipherName.ZIPCRYPTO) else bytes(8)
        if name.value.startswith("chacha"):
            nonce = bytes(12)
        if name.value.startswith("xchacha"):
            nonce = bytes(24)
        allcrypt.StreamCipher(name, bytes(32), nonce)
