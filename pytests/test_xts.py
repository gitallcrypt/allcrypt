"""AES-XTS against python-cryptography, which is OpenSSL underneath.

IEEE 1619's own vectors are inside the standard and are not free, so the
independent opinion here is OpenSSL's, swept over every length rather
than pinned at a handful. The Rust tests carry five pinned rows generated
by `scripts/make_xts_vectors.py` from this same reference, so `cargo
test` alone still notices a change; this file is what makes the claim
re-runnable.

Three things about XTS agree with themselves whatever they get wrong, so
a round trip proves nothing about any of them:

  * the tweak is little endian - sector 1 is ``01 00 ... 00``;
  * the multiply by alpha is little endian too, with ``0x87`` folding
    into byte zero;
  * ciphertext stealing writes the last two blocks in the opposite order
    to the tweaks that made them.

Every test below therefore has OpenSSL on one side.
"""

import pytest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import allcrypt


def reference(key, sector, data, encrypt=True):
    tweak = sector.to_bytes(16, "little")
    worker = Cipher(algorithms.AES(key), modes.XTS(tweak))
    worker = worker.encryptor() if encrypt else worker.decryptor()
    return worker.update(data) + worker.finalize()


KEY128 = bytes(range(32))       # two AES-128 keys
KEY256 = bytes(range(64))       # two AES-256 keys


@pytest.mark.parametrize("key", [KEY128, KEY256], ids=["aes128", "aes256"])
def test_every_length_matches_openssl(key):
    """From one block to five, which covers all fifteen partial tails and
    both sides of the stealing boundary."""
    for length in range(16, 81):
        data = bytes((i * 13 + length) % 256 for i in range(length))
        ours = allcrypt.xts_encrypt(key, 7, data)
        assert ours == reference(key, 7, data), f"length {length}"
        assert allcrypt.xts_decrypt(key, 7, ours) == data, f"length {length}"


@pytest.mark.parametrize("key", [KEY128, KEY256], ids=["aes128", "aes256"])
def test_lengths_across_the_batches_match_openssl(key):
    """The data blocks go to AES sixteen at a time, then four at a time,
    then a zero-padded group, with the tweak carried across. Lengths
    either side of 256 and 512 bytes, and a sector's worth with a ragged
    tail, put a stolen block after each kind of group."""
    for length in [*range(240, 276), 319, 320, 321, 511, 512, 513, 4096, 4099]:
        data = bytes((i * 29 + length) % 256 for i in range(length))
        ours = allcrypt.xts_encrypt(key, 3, data)
        assert ours == reference(key, 3, data), f"length {length}"
        assert allcrypt.xts_decrypt(key, 3, ours) == data, f"length {length}"


@pytest.mark.parametrize("key", [KEY128, KEY256], ids=["aes128", "aes256"])
def test_we_decrypt_what_openssl_encrypts(key):
    for length in [16, 17, 31, 32, 33, 48, 64, 512]:
        data = bytes((i * 7 + 3) % 256 for i in range(length))
        ciphertext = reference(key, 99, data)
        assert allcrypt.xts_decrypt(key, 99, ciphertext) == data, f"length {length}"


@pytest.mark.parametrize("sector", [0, 1, 2, 255, 256, 2 ** 32, 2 ** 63,
                                    2 ** 64, 2 ** 70 + 5, 2 ** 127])
def test_the_sector_number_matches_openssl(sector):
    """A big-endian tweak agrees with itself at every sector and with
    OpenSSL at sector 0 alone. Sector 0 is in the list on purpose, so the
    one case that cannot distinguish them is visible rather than absent."""
    data = bytes(range(64))
    assert allcrypt.xts_encrypt(KEY256, sector, data) == reference(KEY256, sector, data)


def test_different_sectors_give_different_ciphertext():
    """The reason the mode exists. An implementation that dropped the
    tweak entirely would round-trip perfectly and fail only this."""
    data = bytes(48)
    seen = {allcrypt.xts_encrypt(KEY128, sector, data) for sector in range(8)}
    assert len(seen) == 8


def test_the_ciphertext_is_the_same_length_as_the_plaintext():
    """The constraint the whole design is built around: a disk sector has
    nowhere to put an IV or a tag."""
    for length in range(16, 65):
        data = bytes(length)
        assert len(allcrypt.xts_encrypt(KEY128, 1, data)) == length


def test_the_two_halves_of_the_key_are_not_interchangeable():
    swapped = KEY128[16:] + KEY128[:16]
    data = bytes(range(32))
    assert allcrypt.xts_encrypt(KEY128, 5, data) != allcrypt.xts_encrypt(swapped, 5, data)


def test_a_short_data_unit_is_refused():
    """Stealing needs a full block to steal from, so under sixteen bytes
    is an error rather than a special case. OpenSSL refuses it too."""
    for length in range(0, 16):
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.xts_encrypt(KEY128, 0, bytes(length))
        with pytest.raises(allcrypt.CryptoError):
            allcrypt.xts_decrypt(KEY128, 0, bytes(length))


@pytest.mark.parametrize("length", [31, 32, 33])
def test_wrong_key_lengths_are_refused(length):
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.xts_encrypt(bytes(length), 0, bytes(32))


def test_duplicated_key_halves_are_refused():
    """Two equal halves collapse the tweak into the data cipher, and
    OpenSSL refuses such a key outright. Matching that is not
    gratuitous strictness: an XTS key with equal halves is a
    configuration mistake, and there is nothing already written with one
    to stay compatible with."""
    duplicated = bytes(range(16)) * 2
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.xts_encrypt(duplicated, 0, bytes(32))
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.xts_decrypt(duplicated, 0, bytes(32))


def test_a_64_bit_block_cipher_is_refused():
    """XTS is defined over a 128 bit block and there is no 64 bit
    variant."""
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.xts_encrypt(bytes(range(16)), 0, bytes(32), cipher="des")


def test_another_128_bit_cipher_works():
    """The mode is generic. Nothing anywhere ships Camellia-XTS or
    SM4-XTS, which is the point of having a generic mode rather than one
    per cipher - and it means only a round trip can check these, which
    the comment says out loud rather than leaving the reader to assume
    OpenSSL agreed."""
    for cipher, key in [("camellia", bytes(range(32))), ("sm4", bytes(range(32))),
                        ("kuznyechik", bytes(range(64)))]:
        for length in [16, 17, 48, 49]:
            data = bytes((i * 5) % 256 for i in range(length))
            ciphertext = allcrypt.xts_encrypt(key, 3, data, cipher=cipher)
            assert len(ciphertext) == length
            assert allcrypt.xts_decrypt(key, 3, ciphertext, cipher=cipher) == data
            assert ciphertext != allcrypt.xts_encrypt(bytes(range(32)), 3, data)


def test_stealing_rewrites_the_last_whole_block():
    """A data unit one byte longer than a whole number of blocks must not
    merely have a byte appended: the last complete block changes too.

    That is the visible signature of ciphertext stealing, and an
    implementation without it produces the other shape."""
    aligned = bytes([0xAA]) * 32
    longer = aligned + b"\xaa"
    first = allcrypt.xts_encrypt(KEY128, 3, aligned)
    second = allcrypt.xts_encrypt(KEY128, 3, longer)
    assert first[:16] == second[:16]
    assert first[16:32] != second[16:32]
    # And OpenSSL does the same, so this is the standard's shape rather
    # than ours.
    assert second == reference(KEY128, 3, longer)
