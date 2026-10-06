"""ARIA (RFC 5794) through the Python bindings, against OpenSSL.

The Rust unit tests hold the RFC's vectors for all three key sizes plus
every round key and intermediate value for the 128 bit one, and
`scripts/diff_check.py` sweeps every mode at every awkward length
against a reference pinned to OpenSSL. What is checked here is the
binding, and the one thing neither of those covers: that a caller can
reach ARIA from Python at all, when `cryptography` cannot.

ARIA is the rare case in this library where a real independent
implementation exists *and* the standard Python stack still cannot get
at it - OpenSSL has had it since 1.1.1, `cryptography` has never exposed
it. So the comparison below is the honest one: our answer against the
`openssl` binary's, not against a second reading of the RFC.
"""

import shutil
import subprocess

import pytest

import allcrypt


KEYS = {16: bytes(range(16)),
        24: bytes(range(24)),
        32: bytes(range(32))}


def _openssl_aria(key, mode, iv, data):
    name = f"aria-{len(key) * 8}-{mode}"
    command = ["openssl", "enc", f"-{name}", "-nopad", "-K", key.hex()]
    if mode != "ecb":
        command += ["-iv", iv.hex()]
    done = subprocess.run(command, input=data, capture_output=True)
    if done.returncode != 0:
        return None
    return done.stdout


def _has_openssl_aria():
    return (shutil.which("openssl") is not None
            and _openssl_aria(bytes(16), "ecb", b"", bytes(16)) is not None)


openssl_aria = pytest.mark.skipif(not _has_openssl_aria(),
                                  reason="this OpenSSL has no ARIA")


def test_cryptography_still_cannot_do_aria():
    """The premise of this file.

    If `cryptography` ever grows ARIA, `scripts/diff_check.py` should
    use it rather than shelling out to `openssl`, and somebody should
    notice. A test that quietly became redundant would not say so.
    """
    from cryptography.hazmat.primitives.ciphers import algorithms
    assert not hasattr(algorithms, "ARIA")


def test_the_published_vector():
    """RFC 5794 Appendix A.1, written out here as the anchor."""
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert (allcrypt.Cipher("aria", KEYS[16]).encrypt("ecb", block).hex()
            == "d718fbd6ab644c739da95f3be6451778")


def test_it_is_in_the_catalogue():
    assert "aria" in allcrypt.block_ciphers_available
    assert allcrypt.BlockCipher.ARIA == "aria"
    assert allcrypt.Cipher("aria", KEYS[16]).block_size == 16


def _compare_with_openssl(key, mode, length):
    iv = bytes(range(100, 116))
    data = bytes((i * 167 + 13) & 0xff for i in range(length))
    cipher = allcrypt.Cipher("aria", key)
    ours = (cipher.encrypt(mode, data) if mode == "ecb"
            else cipher.encrypt(mode, data, iv=iv))
    assert ours == _openssl_aria(key, mode, iv, data), (mode, length)


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("mode", ["ecb", "cbc", "cfb", "ofb", "ctr"])
@pytest.mark.parametrize("length", [16, 32, 64, 992])
@openssl_aria
def test_it_agrees_with_openssl(key_len, mode, length):
    """Every key size against every mode OpenSSL and this library share.

    The lengths are all block-aligned so that every combination really
    runs - ECB and CBC cannot take a ragged length, and a `pytest.skip`
    for those rows would be six cases that look like passes.
    Unaligned input is covered by the test below, over the modes that
    accept it.

    OpenSSL's `cfb` is full-block CFB, which is what our mode is;
    `cfb1` and `cfb8` are different modes and are not offered here.
    """
    _compare_with_openssl(KEYS[key_len], mode, length)


@pytest.mark.parametrize("mode", ["cfb", "ofb", "ctr"])
@pytest.mark.parametrize("length", [1, 15, 17, 31, 1000])
@openssl_aria
def test_the_stream_modes_agree_with_openssl_at_ragged_lengths(mode, length):
    """The partial final block, which is where a mode that assumed
    whole blocks goes wrong - and the only place the three stream modes
    differ from the two block ones."""
    _compare_with_openssl(KEYS[16], mode, length)


@pytest.mark.parametrize("key_len", [16, 24, 32])
def test_every_mode_round_trips(key_len):
    message = bytes(range(64))
    for mode in allcrypt.modes_available:
        cipher = allcrypt.Cipher("aria", KEYS[key_len])
        iv = None if mode == "ecb" else bytes(16)
        out = (cipher.encrypt(mode, message) if iv is None
               else cipher.encrypt(mode, message, iv=iv))
        back = (cipher.decrypt(mode, out) if iv is None
                else cipher.decrypt(mode, out, iv=iv))
        assert back == message, (key_len, mode)


def test_the_three_key_sizes_give_three_different_answers():
    """The key-schedule constants rotate with the key size, so a longer
    key that starts with a shorter one must not agree with it. An
    implementation that ignored the rotation passes the 128 bit vector
    and fails the other two."""
    block = bytes(16)
    answers = {allcrypt.Cipher("aria", KEYS[n]).encrypt("ecb", block)
               for n in (16, 24, 32)}
    assert len(answers) == 3


def test_a_wrong_key_length_is_refused_by_name():
    for length in [0, 1, 8, 15, 17, 23, 25, 31, 33, 64]:
        with pytest.raises(allcrypt.CryptoError) as refused:
            allcrypt.Cipher("aria", bytes(length))
        assert "16, 24 or 32 bytes" in str(refused.value), length


def test_aria_eax():
    """EAX came for free with the generic mode. The tag is 16 bytes
    here, because ARIA's block is 128 bits - unlike the 64 bit ciphers
    next door, whose EAX tags are eight."""
    aead = allcrypt.Aead(KEYS[32], "aria-eax")
    assert aead.tag_size == 16
    sealed = aead.encrypt(bytes(12), b"payload", b"header")
    assert aead.decrypt(bytes(12), sealed, b"header") == b"payload"
    with pytest.raises(allcrypt.CryptoError):
        aead.decrypt(bytes(12), sealed, b"different header")
