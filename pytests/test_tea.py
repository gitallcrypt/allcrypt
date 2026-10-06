"""TEA, XTEA and RC5 through the Python bindings.

Three 64 bit block ciphers that arrived together and share one shape: a
small key, an 8 byte block, and a round count carried in the `Cipher`
constructor's third argument. They are in one file because what is
tested about each is the same claim about that shape - and because the
one place they *disagree*, whether zero rounds is legal, is only worth
asserting side by side.

The Rust unit tests hold 196 published vectors parsed out of Crypto++'s
and Botan's files - including a chain that sweeps every round count from
1 to 64 - and `scripts/diff_check.py` checks both ciphers in every mode
at every awkward length. What is checked here is the binding: that the
round count arrives through the third argument, that the modes are
inherited rather than reimplemented, and that a caller who gets an
argument wrong is told rather than crashed.

The last of those is not theoretical. The catalogue tests used to carry
a table of "which cipher takes which key length", and because GOST's
entry in that table was correct, nothing ever handed GOST a wrong length
- so `GostCrypto::new` **panicked** on every length but 32 for as long
as it has existed. `test_no_cipher_panics_on_a_wrong_key_length` is what
found it, and it is here rather than in Rust because a panic reaching
Python is the case that actually hurts: it arrives as
`pyo3_runtime.PanicException`, which does not inherit from `ValueError`,
so `except allcrypt.CryptoError` around a key length walks straight past
it.
"""

import pytest

import allcrypt


KEY = bytes(16)
BLOCK = bytes(8)

#: The first row of David Wheeler's published TEA chain: zero key, zero
#: block. Written here rather than derived, because a test that computed
#: its own expectation would pass whatever the cipher did - and this one
#: number is the anchor for everything else in the file.
TEA_ZERO = "41ea3a0a94baa940"

#: XTEA after one cycle on the same input is delta in the second word,
#: which is where its own published chain starts.
XTEA_ONE_CYCLE = "000000009e3779b9"


def test_they_are_in_the_catalogue_and_in_the_enum():
    assert "tea" in allcrypt.block_ciphers_available
    assert "xtea" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.TEA == "tea"
    assert allcrypt.BlockCipher.XTEA == "xtea"


@pytest.mark.parametrize("name", ["tea", "xtea"])
def test_the_block_is_eight_bytes(name):
    assert allcrypt.Cipher(name, KEY).block_size == 8


def test_the_published_anchor_vector():
    assert allcrypt.Cipher("tea", KEY).encrypt("ecb", BLOCK).hex() == TEA_ZERO


def test_tea_and_xtea_are_different_ciphers():
    """They share a block size, a key size, a constant and a shape, so a
    binding that wired both names to one implementation would pass every
    round-trip test in this file."""
    assert (allcrypt.Cipher("tea", KEY).encrypt("ecb", BLOCK)
            != allcrypt.Cipher("xtea", KEY).encrypt("ecb", BLOCK))


# ------------------------------------------------------ the round count ---

def test_the_round_count_travels_through_the_third_argument():
    assert (allcrypt.Cipher("xtea", KEY, "1").encrypt("ecb", BLOCK).hex()
            == XTEA_ONE_CYCLE)


def test_leaving_the_round_count_out_means_the_published_cipher():
    """The default has to be the published 32, not "whatever `param`
    parses to when absent". Asserted against the number spelled out,
    because a default of zero or one would still round-trip."""
    assert (allcrypt.Cipher("tea", KEY).encrypt("ecb", BLOCK)
            == allcrypt.Cipher("tea", KEY, "32").encrypt("ecb", BLOCK))
    assert (allcrypt.Cipher("tea", KEY).encrypt("ecb", BLOCK)
            != allcrypt.Cipher("tea", KEY, "31").encrypt("ecb", BLOCK))


@pytest.mark.parametrize("name", ["tea", "xtea"])
def test_every_round_count_round_trips(name):
    """A reduced-round build still has to be a cipher. The published
    vectors cover encryption at each count; this covers the decryption
    path, where the `sum` schedule runs backwards and is the half most
    likely to be written for the standard count only."""
    message = bytes(range(64))
    for rounds in [1, 2, 3, 16, 31, 32, 33, 64]:
        cipher = allcrypt.Cipher(name, KEY, str(rounds))
        out = cipher.encrypt("cbc", message, iv=bytes(8))
        assert cipher.decrypt("cbc", out, iv=bytes(8)) == message, rounds


@pytest.mark.parametrize("name", ["tea", "xtea"])
def test_zero_rounds_is_refused(name):
    """A cipher that silently returns its input is the worst failure
    this library can have, because it looks like it worked."""
    with pytest.raises(allcrypt.CryptoError) as refused:
        allcrypt.Cipher(name, KEY, "0")
    assert "identity" in str(refused.value)


@pytest.mark.parametrize("name", ["tea", "xtea"])
def test_a_round_count_that_is_not_a_number_says_so(name):
    with pytest.raises(allcrypt.CryptoError) as refused:
        allcrypt.Cipher(name, KEY, "thirty-two")
    assert "round count" in str(refused.value)


# ------------------------------------------------------------ the modes ---

@pytest.mark.parametrize("name", ["tea", "xtea"])
def test_every_mode_round_trips(name):
    """The point of implementing only the block function: the modes come
    for free. This checks the wiring, not the modes, which have their
    own tests."""
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher(name, KEY)
        iv = None if mode == "ecb" else bytes(8)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        assert out != message, mode
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


@pytest.mark.parametrize("name", ["tea", "xtea"])
def test_an_iv_of_the_wrong_size_is_refused(name):
    """The IV is the block, which is 8 here and 16 for AES. A mode that
    took whatever it was given would quietly encrypt under a different
    chain."""
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher(name, KEY).encrypt("cbc", bytes(8), iv=bytes(16))


@pytest.mark.parametrize("name", ["tea-eax", "xtea-eax"])
def test_eax_over_them(name):
    """EAX is generic over any block cipher, so these two came with it.
    **The tag is 8 bytes, not 16** - EAX's tag is one CMAC output, which
    is one block, and these blocks are 64 bits. That halves the forgery
    resistance compared with the AES suites, and it is a property of the
    cipher rather than a choice."""
    aead = allcrypt.Aead(KEY, name)
    assert aead.tag_size == 8

    sealed = aead.encrypt(bytes(12), b"the payload", b"header")
    assert aead.decrypt(bytes(12), sealed, b"header") == b"the payload"

    forged = bytearray(sealed)
    forged[-1] ^= 1
    with pytest.raises(allcrypt.CryptoError):
        aead.decrypt(bytes(12), bytes(forged), b"header")


# ----------------------------------------------- errors, not crashes ---

@pytest.mark.parametrize("name", ["tea", "xtea"])
def test_a_wrong_key_length_is_refused_by_name(name):
    for length in [0, 1, 8, 15, 17, 32]:
        with pytest.raises(allcrypt.CryptoError) as refused:
            allcrypt.Cipher(name, bytes(length))
        assert "16 bytes" in str(refused.value), length


def test_no_cipher_panics_on_a_wrong_key_length():
    """**The regression test for a bug that had always been there.**

    `GostCrypto::new` read eight little-endian words out of the key with
    no length check, so anything but 32 bytes indexed past the end and
    panicked. Through pyo3 that arrives as `PanicException`, which is
    not a `ValueError` - so a caller catching `allcrypt.CryptoError`
    around a user-supplied key length got an uncatchable failure
    instead of an error message.

    It survived because the catalogue tests carried a table of which
    cipher takes which key length, and GOST's entry was right: the one
    loop that would have found it always passed the one length that
    works. Those loops now try every length, which is what found it.

    Written over the whole catalogue rather than over GOST, because the
    next cipher to do this will not be GOST.
    """
    for name in allcrypt.block_ciphers_available:
        for length in [0, 1, 5, 7, 8, 9, 15, 16, 17, 23, 24, 31, 32, 56, 100]:
            try:
                allcrypt.Cipher(name, bytes(length))
            except allcrypt.CryptoError:
                pass                      # the right answer for a bad length
            except BaseException as raised:     # noqa: BLE001
                raise AssertionError(
                    f"{name} with a {length} byte key raised "
                    f"{type(raised).__name__}: {raised}") from raised


def test_gost_still_works_at_its_own_key_length():
    """The other half of the fix: the length check must not have been
    written so tightly that the cipher stopped working. A regression
    test for a crash is only half a test if it does not also say the
    normal case still happens."""
    cipher = allcrypt.Cipher("gost", bytes(32))
    out = cipher.encrypt("ecb", bytes(8))
    assert len(out) == 8
    assert cipher.decrypt("ecb", out) == bytes(8)


# ----------------------------------------------------------------- RC5 ---
#
# RC5 lives here rather than in a file of its own because everything
# tested about it is the same claim: a 64 bit block cipher whose round
# count arrives through the third argument. Its 29 published vectors are
# in `src/block_ciphers/rc5.rs`, parsed out of RFC 2040.

def test_rc5_is_in_the_catalogue():
    assert "rc5" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.RC5 == "rc5"
    assert allcrypt.Cipher("rc5", bytes(16)).block_size == 8


def test_rc5_first_published_vector():
    """RFC 2040 section 9, first row. Zero rounds, a one byte key.

    Written out here as well as in Rust because it is the anchor: every
    other claim in this section is relative to the cipher being the one
    RFC 2040 describes.
    """
    assert (allcrypt.Cipher("rc5", bytes(1), "0").encrypt("ecb", bytes(8)).hex()
            == "7a7bba4d79111d1e")


def test_rc5_zero_rounds_is_allowed_where_teas_is_not():
    """**The two ciphers disagree about zero on purpose.**

    TEA with no rounds is the identity function and is refused. RC5 with
    no rounds still adds the first two subkeys, so it is a
    key-dependent transformation and RFC 2040 publishes vectors for it.
    A reader who saw only one of the two would reasonably assume the
    other behaved the same way.
    """
    assert allcrypt.Cipher("rc5", bytes(16), "0").encrypt("ecb", bytes(8)) \
        != bytes(8)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.Cipher("tea", bytes(16), "0")


def test_rc5_takes_any_key_length_from_one_to_255():
    for length in [1, 2, 5, 8, 16, 32, 255]:
        assert allcrypt.Cipher("rc5", bytes(length)).block_size == 8
    for length in [0, 256]:
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.Cipher("rc5", bytes(length))


def test_rc5_every_mode_round_trips():
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("rc5", bytes(16))
        iv = None if mode == "ecb" else bytes(8)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, mode


def test_rc5_eax_has_an_eight_byte_tag():
    aead = allcrypt.Aead(bytes(16), "rc5-eax")
    assert aead.tag_size == 8
    sealed = aead.encrypt(bytes(12), b"payload", b"header")
    assert aead.decrypt(bytes(12), sealed, b"header") == b"payload"
