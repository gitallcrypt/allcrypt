"""SSH keys and signatures, against python-cryptography's OpenSSH support.

`tests/test_ssh_vectors.rs` holds OpenSSH's own answers, recorded from
`ssh-keygen`; `scripts/check_ssh_witness.py` hands OpenSSH what this
library writes. What these add is a second, independent implementation
of the same formats in the gate itself: `cryptography` reads and writes
OpenSSH public keys and unencrypted `openssh-key-v1` private keys, and
verifies the raw signatures inside an SSH signature blob.
"""

import base64
import hashlib
import struct

import pytest

from cryptography.hazmat.primitives import hashes, serialization
import warnings

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import allcrypt

OPENSSH = serialization.Encoding.OpenSSH
PEM = serialization.Encoding.PEM
OPENSSH_PRIVATE = serialization.PrivateFormat.OpenSSH
NOTHING = serialization.NoEncryption()

THEIRS = [
    ("ed25519", lambda: ed25519.Ed25519PrivateKey.generate()),
    ("ecdsa256", lambda: ec.generate_private_key(ec.SECP256R1())),
    ("ecdsa384", lambda: ec.generate_private_key(ec.SECP384R1())),
    ("ecdsa521", lambda: ec.generate_private_key(ec.SECP521R1())),
    ("rsa2048", lambda: rsa.generate_private_key(65537, 2048)),
    ("dsa1024", lambda: dsa.generate_private_key(1024)),
]

OURS = [("ed25519", None), ("ecdsa", 256), ("ecdsa", 384), ("ecdsa", 521),
        ("rsa", 1024), ("dsa", None)]

# `cryptography` still reads and writes ssh-dss keys, and says on every
# call that it will stop; the warning is about its future, not ours.
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning",
                                        "ignore::UserWarning")


def strings(blob):
    """An SSH blob as its list of `string`s."""
    out = []
    while blob:
        (length,) = struct.unpack(">I", blob[:4])
        out.append(blob[4:4 + length])
        blob = blob[4 + length:]
    return out


@pytest.mark.parametrize("label,make", THEIRS, ids=[t[0] for t in THEIRS])
def test_their_keys_read_here(label, make):
    key = make()
    text = key.private_bytes(PEM, OPENSSH_PRIVATE, NOTHING).decode()
    ours = allcrypt.SshKey.from_openssh(text)
    their_line = key.public_key().public_bytes(OPENSSH, serialization.PublicFormat.OpenSSH)
    assert ours.public_key().to_line("") == their_line.decode()

    # And the fingerprint is SHA-256 of the blob, unpadded base64.
    blob = base64.b64decode(their_line.split()[1])
    expected = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert ours.public_key().fingerprint() == "SHA256:" + expected
    md5 = hashlib.md5(blob).hexdigest()
    assert ours.public_key().fingerprint("md5") == "MD5:" + ":".join(
        md5[i:i + 2] for i in range(0, 32, 2))


@pytest.mark.parametrize("kind,bits", OURS, ids=[f"{k}{b or ''}" for k, b in OURS])
def test_our_keys_read_there(kind, bits):
    key = allcrypt.SshKey.generate(kind, bits, comment="test@allcrypt")
    loaded = serialization.load_ssh_private_key(key.to_openssh().encode(), None)
    line = loaded.public_key().public_bytes(OPENSSH, serialization.PublicFormat.OpenSSH)
    assert key.public_key().to_line("") == line.decode()
    assert allcrypt.SshPublicKey.from_line(line.decode()) == key.public_key()


@pytest.mark.parametrize("kind,bits", OURS, ids=[f"{k}{b or ''}" for k, b in OURS])
def test_our_signatures_verify_there(kind, bits):
    key = allcrypt.SshKey.generate(kind, bits)
    theirs = serialization.load_ssh_private_key(key.to_openssh().encode(),
                                                None).public_key()
    data = b"session identifier and the rest of the request"
    algorithms = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"] if kind == "rsa" else [None]
    for algorithm in algorithms:
        name, raw = strings(key.sign(data, algorithm))
        if kind == "ed25519":
            assert name == b"ssh-ed25519"
            theirs.verify(raw, data)
        elif kind == "ecdsa":
            r, s = (int.from_bytes(x, "big") for x in strings(raw))
            digest = {256: hashes.SHA256(), 384: hashes.SHA384(),
                      521: hashes.SHA512()}[bits]
            theirs.verify(encode_dss_signature(r, s), data, ec.ECDSA(digest))
        elif kind == "dsa":
            assert name == b"ssh-dss" and len(raw) == 40
            r, s = int.from_bytes(raw[:20], "big"), int.from_bytes(raw[20:], "big")
            theirs.verify(encode_dss_signature(r, s), data, hashes.SHA1())
        else:
            digest = {b"rsa-sha2-512": hashes.SHA512(), b"rsa-sha2-256": hashes.SHA256(),
                      b"ssh-rsa": hashes.SHA1()}[name]
            assert name.decode() == algorithm
            theirs.verify(raw, data, padding.PKCS1v15(), digest)
        assert key.public_key().verify(data, key.sign(data, algorithm))
        assert not key.public_key().verify(data + b"!", key.sign(data, algorithm))


def test_their_ed25519_signature_verifies_here():
    key = ed25519.Ed25519PrivateKey.generate()
    ours = allcrypt.SshKey.from_openssh(
        key.private_bytes(PEM, OPENSSH_PRIVATE, NOTHING).decode()).public_key()
    data = b"signed elsewhere"
    raw = key.sign(data)
    blob = b"".join(struct.pack(">I", len(x)) + x for x in (b"ssh-ed25519", raw))
    assert ours.verify(data, blob)


def test_an_encrypted_key_round_trips_and_a_wrong_passphrase_raises():
    key = allcrypt.SshKey.generate("ed25519", comment="me")
    text = key.to_openssh(b"secret", cipher="chacha20-poly1305@openssh.com", rounds=2)
    assert "OPENSSH PRIVATE KEY" in text
    again = allcrypt.SshKey.from_openssh(text, b"secret")
    assert again.public_key() == key.public_key() and again.comment == "me"
    with pytest.raises(allcrypt.CryptoError, match="passphrase"):
        allcrypt.SshKey.from_openssh(text, b"guess")
    with pytest.raises(allcrypt.CryptoError, match="needs a passphrase"):
        allcrypt.SshKey.from_openssh(text)


def test_authorized_keys_options_and_sshsig():
    key = allcrypt.SshKey.generate("ecdsa", 384)
    line = 'from="10.0.0.0/8",no-pty ' + key.public_key().to_line("ops@example")
    read = allcrypt.SshPublicKey.from_line(line)
    assert read.options == 'from="10.0.0.0/8",no-pty'
    assert read.comment == "ops@example"
    assert read.algorithm == "ecdsa-sha2-nistp384" and read.bits == 384

    signature = key.sshsig(b"release.tar.gz contents", namespace="file")
    assert allcrypt.sshsig_verify(signature, b"release.tar.gz contents",
                                  "file") == key.public_key()
    with pytest.raises(allcrypt.CryptoError, match="namespace"):
        allcrypt.sshsig_verify(signature, b"release.tar.gz contents", "git")
