"""XEdDSA: Signal's signatures with an X25519 key.

Two independent opinions are available here, and this file uses both.

  * **OpenSSL's Ed25519 verifier.** An XEdDSA signature is an Ed25519
    signature by the Edwards point the Montgomery key maps to, so once
    the point is rebuilt - `y = (u - 1) / (u + 1)`, with the sign bit the
    form says - python-cryptography can verify it. That checks the
    signer's arithmetic against code that shares none of it.
  * **libsignal-protocol-c**, through `vectors/xeddsa.vec`: its exact
    bytes for the same key, message and random input, and both of its
    verifiers' verdicts. `tests/test_xeddsa_vectors.rs` reads the whole
    file; the rows here confirm the Python surface reaches the same
    function.
"""

import os

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import allcrypt

P = 2**255 - 19
VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "xeddsa.vec")


def edwards_key(u_bytes, sign_bit):
    u = int.from_bytes(u_bytes, "little")
    y = (u - 1) * pow(u + 1, P - 2, P) % P
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= sign_bit
    return Ed25519PublicKey.from_public_bytes(bytes(encoded))


def openssl_verifies(form, public, message, signature):
    """Verify through OpenSSL, rebuilding the Edwards key as `form` says."""
    if form == "signal":
        sign_bit = signature[63] & 0x80
        signature = signature[:63] + bytes([signature[63] & 0x7F])
    else:
        sign_bit = 0
    try:
        edwards_key(public, sign_bit).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def records(section):
    rows, fields, inside = [], {}, False
    for line in open(VECTORS):
        line = line.strip()
        if line.startswith("["):
            inside = line == f"[{section}]"
            continue
        if not inside or line.startswith("#"):
            continue
        if not line:
            if fields:
                rows.append(fields)
            fields = {}
            continue
        key, value = line.split(" = ", 1)
        fields[key] = value
    if inside and fields:
        rows.append(fields)
    return rows


def test_the_forms_are_listed():
    assert allcrypt.xeddsa_forms() == ["signal", "xeddsa"]


@pytest.mark.parametrize("form", ["signal", "xeddsa"])
def test_openssl_verifies_our_signatures(form):
    signs = set()
    for length in range(0, 130, 3):
        private, public = allcrypt.x25519_generate()
        message = os.urandom(length)
        signature = allcrypt.xeddsa_sign(form, private, message)
        signs.add(signature[63] >> 7)
        assert allcrypt.xeddsa_verify(form, public, message, signature)
        assert openssl_verifies(form, public, message, signature), length
        assert not openssl_verifies(form, public, message + b"x", signature)
    # The Signal form puts the key's sign in S; over 44 keys both occur.
    assert signs == ({0, 1} if form == "signal" else {0})


def test_libsignals_bytes_through_the_python_surface():
    rows = records("sign")
    assert len(rows) == 40
    for row in rows[:6]:
        signature = allcrypt.xeddsa_sign(row["form"], bytes.fromhex(row["private"]),
                                         bytes.fromhex(row["message"]),
                                         bytes.fromhex(row["random"]))
        assert signature.hex() == row["signature"]


def test_libsignals_verdicts_through_the_python_surface():
    rows = records("verify")
    assert len(rows) == 77
    for row in rows[::7]:
        for form in ("signal", "xeddsa"):
            verdict = allcrypt.xeddsa_verify(form, bytes.fromhex(row["public"]),
                                             bytes.fromhex(row["message"]),
                                             bytes.fromhex(row["signature"]))
            assert verdict == (row[form] == "1"), (row["case"], form)


def test_a_given_random_input_reproduces_the_signature():
    private, _ = allcrypt.x25519_generate()
    z = bytes(range(64))
    one = allcrypt.xeddsa_sign("signal", private, b"m", z)
    assert one == allcrypt.xeddsa_sign("signal", private, b"m", z)
    assert one != allcrypt.xeddsa_sign("signal", private, b"m")


def test_lengths_and_names_are_errors_and_a_bad_signature_is_false():
    private, public = allcrypt.x25519_generate()
    signature = allcrypt.xeddsa_sign("signal", private, b"m")
    with pytest.raises(ValueError, match="not an XEdDSA form"):
        allcrypt.xeddsa_sign("vxeddsa", private, b"m")
    with pytest.raises(ValueError, match="32 bytes, not 31"):
        allcrypt.xeddsa_sign("signal", private[:31], b"m")
    with pytest.raises(ValueError, match="64 bytes, not 63"):
        allcrypt.xeddsa_sign("signal", private, b"m", bytes(63))
    with pytest.raises(ValueError, match="64 bytes, not 63"):
        allcrypt.xeddsa_verify("signal", public, b"m", signature[:63])
    assert allcrypt.xeddsa_verify("signal", public, b"n", signature) is False
