"""SM2 against the `openssl` binary, which implements it in 3.0 and later.

python-cryptography refuses the curve outright - "Curve 1.2.156.10197.1.301
is not supported" - so unlike every other public key algorithm here the
reference is driven through the command line rather than through a
library. That is the whole reason this file exists: the Rust tests
reproduce GB/T 32918.2 A.2's `Z_A` and `e` out of the vendored draft, and
nothing else in the repository can tell whether the *signature* and the
*ciphertext* are the ones a Chinese device would accept.

Both directions, for both operations. A signer and a verifier that share
a mistake agree perfectly with each other, and here there is more than
usually much to share: `Z_A` folds the identity and the whole curve into
the hash before the message is seen, the signing equation inverts
`(1 + d)` rather than a per-signature value, the KDF counter starts at
one, and the check value puts the plaintext *between* the two
coordinates. Every one of those is invisible to a round trip against
ourselves.

## The distinguishing identifier

`openssl pkeyutl` defaults to an **empty** identity; GB/T 32918.2's
default is `1234567812345678`. Measured rather than assumed - see
`test_the_openssl_default_identity_is_empty`, which is here so that the
trap stays documented rather than being something a future reader has to
rediscover. Every other test passes `distid` explicitly on the OpenSSL
side, so none of them depends on either default.
"""

import subprocess

import pytest

import allcrypt


CURVE = "sm2p256v1"
STANDARD_ID = b"1234567812345678"


def have_openssl_sm2():
    proc = subprocess.run(["openssl", "genpkey", "-algorithm", "SM2"],
                          capture_output=True)
    return proc.returncode == 0


pytestmark = pytest.mark.skipif(
    not have_openssl_sm2(),
    reason="this openssl has no SM2; 3.0 and later do")


# ------------------------------------------------------------------ helpers ---

def openssl_keypair():
    """A fresh SM2 key, as (PEM, private scalar, uncompressed public point).

    The DER is a SEC1 EC private key: SEQUENCE { INTEGER 1,
    OCTET STRING d, [0] curve OID, [1] BIT STRING public }.
    """
    pem = subprocess.run(["openssl", "genpkey", "-algorithm", "SM2"],
                         capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-outform", "DER"],
                         input=pem, capture_output=True, check=True).stdout
    # 30 77 02 01 01 04 20 <32 bytes>
    assert der[:7] == bytes.fromhex("30770201010420"), der[:7].hex()
    private = der[7:39]
    at = der.find(bytes.fromhex("03420004"))
    assert at > 0, "no uncompressed public point in the key"
    public = b"\x04" + der[at + 4:at + 68]
    return pem, private, public


def der_integer(value):
    body = value.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if body[0] >= 0x80:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def signature_to_der(raw):
    """Our fixed-width `r || s` to the SEQUENCE OpenSSL reads."""
    body = (der_integer(int.from_bytes(raw[:32], "big"))
            + der_integer(int.from_bytes(raw[32:], "big")))
    assert len(body) < 0x80
    return b"\x30" + bytes([len(body)]) + body


def signature_from_der(der):
    assert der[0] == 0x30
    at = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7f)
    out = b""
    while at < len(der):
        assert der[at] == 0x02
        length = der[at + 1]
        out += int.from_bytes(der[at + 2:at + 2 + length], "big").to_bytes(32, "big")
        at += 2 + length
    assert len(out) == 64
    return out


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def openssl_verify(key_path, message_path, signature_path, identity):
    proc = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-inkey", key_path, "-in", message_path,
         "-rawin", "-digest", "sm3", "-pkeyopt", "distid:" + identity.decode(),
         "-sigfile", signature_path],
        capture_output=True, text=True)
    return "Verified Successfully" in proc.stdout


def openssl_sign(key_path, message_path, out_path, identity):
    subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", key_path, "-in", message_path,
         "-rawin", "-digest", "sm3", "-pkeyopt", "distid:" + identity.decode(),
         "-out", out_path],
        capture_output=True, check=True)
    return open(out_path, "rb").read()


MESSAGES = [b"a", b"message digest", b"abc", bytes(64), bytes(range(200)),
            b"x" * 1000]


# -------------------------------------------------------------------- keys ---

def test_the_curve_is_listed():
    assert CURVE in allcrypt.curves_available


def test_our_public_key_matches_openssls():
    """`d*G` against OpenSSL, with OpenSSL choosing every scalar.

    OpenSSL will not derive a public key from a bare scalar for this
    curve, so it cannot be used as a multiplication oracle - but it
    generates keypairs, and checking `d*G` over many of them is the same
    thing with the scalars chosen for us.
    """
    for _ in range(20):
        _, private, public = openssl_keypair()
        key = allcrypt.EcKey.from_private(CURVE, private)
        assert key.public_bytes(False) == public


def test_the_key_size_is_the_field_size():
    _, private, _ = openssl_keypair()
    assert allcrypt.EcKey.from_private(CURVE, private).key_size == 256


# --------------------------------------------------------------- signature ---

@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: str(len(m)))
def test_openssl_verifies_what_we_sign(tmp_path, message):
    pem, private, _ = openssl_keypair()
    key = allcrypt.EcKey.from_private(CURVE, private)
    signature = key.sm2_sign(message)

    key_path = write(tmp_path, "k.pem", pem)
    message_path = write(tmp_path, "m.bin", message)
    signature_path = write(tmp_path, "s.der", signature_to_der(signature))
    assert openssl_verify(key_path, message_path, signature_path, STANDARD_ID)


@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: str(len(m)))
def test_we_verify_what_openssl_signs(tmp_path, message):
    pem, private, public = openssl_keypair()
    key_path = write(tmp_path, "k.pem", pem)
    message_path = write(tmp_path, "m.bin", message)
    der = openssl_sign(key_path, message_path, str(tmp_path / "s.der"), STANDARD_ID)

    raw = signature_from_der(der)
    assert allcrypt.EcPublicKey(CURVE, public).sm2_verify(message, raw)
    assert allcrypt.EcKey.from_private(CURVE, private).sm2_verify(message, raw)


def test_the_openssl_default_identity_is_empty(tmp_path):
    """The trap, pinned.

    A signature made by `openssl pkeyutl` with no `distid` verifies under
    an **empty** identity and fails under GB/T 32918.2's default. A
    library following the standard and a script using the command line
    therefore disagree, and the failure looks exactly like a wrong key.

    If a future OpenSSL changes this, this test fails and says so - which
    is the point of asserting a thing that is not what you want.
    """
    pem, _, public = openssl_keypair()
    key_path = write(tmp_path, "k.pem", pem)
    message_path = write(tmp_path, "m.bin", b"message digest")
    proc = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", key_path, "-in", message_path,
         "-rawin", "-digest", "sm3", "-out", str(tmp_path / "s.der")],
        capture_output=True, check=True)
    assert proc.returncode == 0
    raw = signature_from_der((tmp_path / "s.der").read_bytes())

    verifier = allcrypt.EcPublicKey(CURVE, public)
    assert verifier.sm2_verify(b"message digest", raw, b"")
    assert not verifier.sm2_verify(b"message digest", raw, STANDARD_ID)


def test_we_and_openssl_agree_about_a_non_default_identity(tmp_path):
    identity = b"ALICE123@YAHOO.COM"
    pem, private, public = openssl_keypair()
    key = allcrypt.EcKey.from_private(CURVE, private)
    message = b"message digest"

    signature = key.sm2_sign(message, identity)
    key_path = write(tmp_path, "k.pem", pem)
    message_path = write(tmp_path, "m.bin", message)
    signature_path = write(tmp_path, "s.der", signature_to_der(signature))
    assert openssl_verify(key_path, message_path, signature_path, identity)
    assert not openssl_verify(key_path, message_path, signature_path, STANDARD_ID)

    der = openssl_sign(key_path, message_path, str(tmp_path / "o.der"), identity)
    raw = signature_from_der(der)
    assert allcrypt.EcPublicKey(CURVE, public).sm2_verify(message, raw, identity)
    assert not allcrypt.EcPublicKey(CURVE, public).sm2_verify(message, raw)


def test_our_signature_is_deterministic_and_openssls_is_not(tmp_path):
    """Both are valid SM2. Only ours is reproducible.

    GB/T 32918.2 says `k` is random; this library derives it through RFC
    6979 instead, so the same inputs give the same signature. OpenSSL
    does what the standard says. A test asserting the two agree
    byte-for-byte would be asserting the wrong thing - the same shape as
    ML-DSA's hedged mode in docs/post-quantum.md.
    """
    pem, private, _ = openssl_keypair()
    key = allcrypt.EcKey.from_private(CURVE, private)
    assert key.sm2_sign(b"abc") == key.sm2_sign(b"abc")

    key_path = write(tmp_path, "k.pem", pem)
    message_path = write(tmp_path, "m.bin", b"abc")
    first = openssl_sign(key_path, message_path, str(tmp_path / "a.der"), STANDARD_ID)
    second = openssl_sign(key_path, message_path, str(tmp_path / "b.der"), STANDARD_ID)
    assert first != second

    # And both of OpenSSL's verify here, which is what actually matters.
    for der in (first, second):
        assert key.sm2_verify(b"abc", signature_from_der(der))


def test_every_signature_we_make_is_accepted_and_every_alteration_is_not(tmp_path):
    pem, private, _ = openssl_keypair()
    key = allcrypt.EcKey.from_private(CURVE, private)
    message = b"the message"
    signature = bytearray(key.sm2_sign(message))
    key_path = write(tmp_path, "k.pem", pem)
    message_path = write(tmp_path, "m.bin", message)

    for index in (0, 31, 32, 63):
        altered = bytearray(signature)
        altered[index] ^= 0x01
        path = write(tmp_path, f"s{index}.der", signature_to_der(bytes(altered)))
        assert not openssl_verify(key_path, message_path, path, STANDARD_ID)
        assert not key.sm2_verify(message, bytes(altered))


# -------------------------------------------------------------- encryption ---

@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: str(len(m)))
def test_openssl_decrypts_what_we_encrypt(tmp_path, message):
    pem, _, public = openssl_keypair()
    der = allcrypt.EcPublicKey(CURVE, public).sm2_encrypt_der(message)

    key_path = write(tmp_path, "k.pem", pem)
    cipher_path = write(tmp_path, "c.der", der)
    proc = subprocess.run(
        ["openssl", "pkeyutl", "-decrypt", "-inkey", key_path, "-in", cipher_path],
        capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode()[:200]
    assert proc.stdout == message


@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: str(len(m)))
def test_we_decrypt_what_openssl_encrypts(tmp_path, message):
    pem, private, _ = openssl_keypair()
    key_path = write(tmp_path, "k.pem", pem)
    message_path = write(tmp_path, "m.bin", message)
    cipher_path = str(tmp_path / "c.der")
    subprocess.run(
        ["openssl", "pkeyutl", "-encrypt", "-inkey", key_path, "-in", message_path,
         "-out", cipher_path],
        capture_output=True, check=True)

    key = allcrypt.EcKey.from_private(CURVE, private)
    ciphertext = open(cipher_path, "rb").read()
    try:
        plain = key.sm2_decrypt_der(ciphertext)
    except allcrypt.CryptoError as e:
        # OpenSSL does not check its KDF output for all zeros (GB/T
        # 32918.4 6.1 step A5), so for a one-byte message one ciphertext
        # in 256 carries the plaintext itself as C2. We refuse those, as
        # 7.1 requires; the refusal must be for that reason and no other,
        # which the C2 at the end of the DER shows.
        assert "all-zero key" in str(e)
        assert ciphertext.endswith(b"\x04" + bytes([len(message)]) + message)
    else:
        assert plain == message


def test_the_ciphertext_has_the_shape_the_standard_gives_it():
    _, _, public = openssl_keypair()
    message = b"sixteen byte msg"
    raw = allcrypt.EcPublicKey(CURVE, public).sm2_encrypt(message)
    # C1 (65) || C3 (32) || C2 (len)
    assert len(raw) == 65 + 32 + len(message)
    assert raw[0] == 0x04, "C1 is an uncompressed point"


def test_no_single_bit_of_a_ciphertext_survives_alteration():
    _, private, public = openssl_keypair()
    key = allcrypt.EcKey.from_private(CURVE, private)
    raw = allcrypt.EcPublicKey(CURVE, public).sm2_encrypt(b"sixteen byte msg")
    assert key.sm2_decrypt(raw) == b"sixteen byte msg"

    for index in range(len(raw)):
        for bit in (0x01, 0x80):
            altered = bytearray(raw)
            altered[index] ^= bit
            with pytest.raises(ValueError):
                key.sm2_decrypt(bytes(altered))


def test_openssl_refuses_a_ciphertext_we_altered(tmp_path):
    """The other half of the test above: our refusal could be our own
    idea. OpenSSL refusing the same bytes says the check value is the
    one the standard defines rather than one we invented."""
    pem, _, public = openssl_keypair()
    der = bytearray(allcrypt.EcPublicKey(CURVE, public).sm2_encrypt_der(b"hello there"))
    key_path = write(tmp_path, "k.pem", pem)
    # The last byte is inside C2, so this changes the plaintext and the
    # check value must catch it.
    der[-1] ^= 0x01
    cipher_path = write(tmp_path, "c.der", bytes(der))
    proc = subprocess.run(
        ["openssl", "pkeyutl", "-decrypt", "-inkey", key_path, "-in", cipher_path],
        capture_output=True)
    assert proc.returncode != 0


def test_a_ciphertext_for_another_key_is_refused():
    _, private_a, _ = openssl_keypair()
    _, _, public_b = openssl_keypair()
    raw = allcrypt.EcPublicKey(CURVE, public_b).sm2_encrypt(b"not for you")
    with pytest.raises(ValueError):
        allcrypt.EcKey.from_private(CURVE, private_a).sm2_decrypt(raw)


# ------------------------------------------------------- the curve is fixed ---

@pytest.mark.parametrize("curve", ["P-256", "secp256k1"])
def test_sm2_refuses_another_curve(curve):
    """The curve's `a`, `b` and generator go into `Z_A`, so SM2 over
    P-256 would be self-consistent and unverifiable by anyone. It is
    refused by name rather than quietly computed."""
    key = allcrypt.EcKey.generate(curve)
    with pytest.raises(ValueError, match="sm2p256v1"):
        key.sm2_sign(b"x")
    with pytest.raises(ValueError, match="sm2p256v1"):
        key.public_key().sm2_encrypt(b"x")
