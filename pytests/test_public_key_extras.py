"""Public-key operations the library had and the bindings did not reach:
a verify-only DSA key and DSA over a digest, GOST's TLS 1.3 signature
encoding, VKO GOST R 34.10-2001, SM2's Z, digest and KDF, the EdDSA
public-key check, a Diffie-Hellman group with its subgroup order,
Miller-Rabin, and sntrup761.

Each is checked against something that is not this library where one
exists: python-cryptography for DSA and primes, hashlib's SM3 for SM2,
RFC 8032's decoding written out here for Ed25519, affine arithmetic
written here for VKO, and NIST's CTR_DRBG built on python-cryptography's
AES for sntrup761's known answers.
"""

import hashlib
import os
import re

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import allcrypt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def num(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


# ------------------------------------------------------------------- DSA ---

@pytest.fixture(scope="module")
def dsa_pair():
    theirs = dsa.generate_private_key(2048)
    n = theirs.private_numbers()
    pn = n.public_numbers.parameter_numbers
    ours = allcrypt.DsaKey.from_numbers(num(pn.p), num(pn.q), num(pn.g), num(n.x))
    return theirs, ours


def test_a_verify_only_dsa_key_checks_openssls_signatures(dsa_pair):
    theirs, ours = dsa_pair
    pn = theirs.private_numbers().public_numbers
    public = allcrypt.DsaPublicKey.from_numbers(
        num(pn.parameter_numbers.p), num(pn.parameter_numbers.q),
        num(pn.parameter_numbers.g), num(pn.y))
    assert public.public_bytes() == ours.public_bytes()
    assert public.parameters() == ours.parameters()
    signature = theirs.sign(b"a message", hashes.SHA256())
    assert public.verify(b"a message", signature, "sha256")
    assert not public.verify(b"another", signature, "sha256")
    assert ours.public_key().verify(b"a message", signature)


def test_dsa_over_a_digest_is_what_openssl_verifies_prehashed(dsa_pair):
    theirs, ours = dsa_pair
    digest = hashlib.sha256(b"computed elsewhere").digest()
    signature = ours.sign_digest(digest, "sha256")
    theirs.public_key().verify(signature, digest, utils.Prehashed(hashes.SHA256()))
    assert ours.sign_digest(digest, "sha256") == signature        # RFC 6979
    assert ours.sign(b"computed elsewhere", "sha256") == signature
    assert ours.verify_digest(digest, signature)
    assert ours.public_key().verify_digest(digest, signature)
    assert not ours.verify_digest(bytes(32), signature)


# --------------------------------------------------------------- GOST TLS ---

def test_the_tls13_gost_encoding_is_the_certificate_one_rearranged():
    """RFC 9367: str_l(r) || str_l(s), where a certificate's is s || r big
    endian. GOST signing here is deterministic, so the two encodings of
    one signature can be compared after rearranging by hand."""
    key = allcrypt.EcKey.generate("gost256-a")
    digest = hashlib.sha256(b"m").digest()
    certificate = key.sign_gost(digest, "streebog256")
    tls13 = key.sign_gost(digest, "streebog256", encoding="tls13")
    s, r = certificate[:32], certificate[32:]
    assert tls13 == r[::-1] + s[::-1]
    public = key.public_key()
    assert public.verify_gost(digest, tls13, encoding="tls13")
    assert not public.verify_gost(digest, tls13)
    assert key.verify_gost(digest, certificate)
    with pytest.raises(ValueError):
        key.sign_gost(digest, "streebog256", encoding="der")


# --------------------------------------------------------------- VKO 2001 ---

def test_vko_2001_is_rfc_4357s_equation():
    curve = allcrypt.curve_parameters("gost256-a")
    p, a, n = (int(curve[k], 16) for k in ("p", "a", "n"))
    G = (int(curve["gx"], 16), int(curve["gy"], 16))

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
            return None
        if P == Q:
            s = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
        else:
            s = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (s * s - P[0] - Q[0]) % p
        return x, (s * (P[0] - x) - P[1]) % p

    def mul(k, P):
        out = None
        for bit in bin(k)[2:]:
            out = add(out, out)
            if bit == "1":
                out = add(out, P)
        return out

    alice, bob = allcrypt.EcKey.generate("gost256-a"), allcrypt.EcKey.generate("gost256-a")
    ukm = bytes(range(1, 9))
    shared = alice.vko_2001(bob.public_bytes(), ukm)
    assert shared == bob.vko_2001(alice.public_bytes(), ukm)
    d = int.from_bytes(alice.private_bytes(), "big")
    peer = bob.public_bytes()
    Q = (int.from_bytes(peer[1:33], "big"), int.from_bytes(peer[33:], "big"))
    K = mul(int.from_bytes(ukm, "little") * d % n, Q)
    expected = allcrypt.new("gost94", K[0].to_bytes(32, "little") + K[1].to_bytes(32, "little"))
    assert shared == expected.digest()
    assert shared != alice.vko(bob.public_bytes(), ukm)        # the 2012 one


# -------------------------------------------------------------------- SM2 ---

def test_sm2_z_digest_and_kdf_are_the_standards():
    try:
        hashlib.new("sm3")
    except ValueError:
        pytest.skip("this hashlib has no SM3")
    sm3 = lambda data: hashlib.new("sm3", data).digest()
    curve = allcrypt.curve_parameters("sm2p256v1")
    key = allcrypt.EcKey.generate("sm2p256v1").public_key()
    public = key.public_bytes()
    for identity in (b"1234567812345678", b"ALICE123@YAHOO.COM", b""):
        z = sm3((8 * len(identity)).to_bytes(2, "big") + identity
                + b"".join(bytes.fromhex(curve[k]).rjust(32, b"\0")
                           for k in ("a", "b", "gx", "gy")) + public[1:])
        assert key.sm2_z(identity) == z
        assert key.sm2_digest(b"message", identity) == sm3(z + b"message")
    assert key.sm2_z() == key.sm2_z(b"1234567812345678")
    shared = b"shared value"
    stream = b"".join(sm3(shared + i.to_bytes(4, "big")) for i in range(1, 4))
    assert allcrypt.sm2_kdf(shared, 70) == stream[:70]
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.sm2_kdf(shared, 1 << 40)


# ------------------------------------------------------------------ EdDSA ---

def test_the_ed25519_public_key_check_is_rfc_8032s_decoding():
    p = 2**255 - 19
    d = -121665 * pow(121666, -1, p) % p

    def is_point(raw):
        y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
        sign = raw[31] >> 7
        if y >= p:
            return False
        u, v = (y * y - 1) % p, (d * y * y + 1) % p
        x = u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p) % p
        if (v * x * x - u) % p != 0:
            x = x * pow(2, (p - 1) // 4, p) % p
            if (v * x * x - u) % p != 0:
                return False
        return not (x == 0 and sign == 1)

    seen = {True: 0, False: 0}
    for i in range(200):
        raw = hashlib.sha256(b"candidate %d" % i).digest()
        verdict = allcrypt.eddsa_is_public_key("ed25519", raw)
        assert verdict == is_point(raw), raw.hex()
        seen[verdict] += 1
    assert seen[True] > 50 and seen[False] > 50
    real = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    assert allcrypt.eddsa_is_public_key("ed25519", real)
    assert not allcrypt.eddsa_is_public_key("ed25519", real[:-1])


# ------------------------------------------------------- DH with a subgroup ---

def test_a_group_with_its_subgroup_order_refuses_a_peer_outside_it():
    params = dsa.generate_parameters(1024).parameter_numbers()
    p, q, g = num(params.p), num(params.q), num(params.g)
    plain = allcrypt.DhGroup(p, g)
    strict = allcrypt.DhGroup(p, g, q)
    assert strict.q == q and plain.q is None
    outside = (2).to_bytes(len(p), "big")     # order not q for a DSA group
    assert pow(2, params.q, params.p) != 1
    plain.validate_peer(outside)
    with pytest.raises(allcrypt.CryptoError):
        strict.validate_peer(outside)
    _, inside = strict.generate_key_pair()
    strict.validate_peer(inside)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.DhGroup(p, g, num(params.q + 2))
    strict.check_size(1024)
    with pytest.raises(allcrypt.CryptoError):
        strict.check_size(2048)


# ----------------------------------------------------------- Miller-Rabin ---

def test_miller_rabin_agrees_with_openssls_primes():
    key = rsa.generate_private_key(65537, 1024).private_numbers()
    assert allcrypt.is_probable_prime(num(key.p))
    assert allcrypt.is_probable_prime(num(key.q), rounds=8)
    assert not allcrypt.is_probable_prime(num(key.p * key.q))
    for carmichael in (561, 41041, 825265):
        assert not allcrypt.is_probable_prime(num(carmichael))
    assert allcrypt.is_probable_prime(num(2**127 - 1))


# -------------------------------------------------------------- sntrup761 ---

class NistDrbg:
    """NIST's rng.c: AES-256 CTR_DRBG, no derivation function, the tail of
    every call discarded. On python-cryptography's AES."""

    def __init__(self, seed):
        self.key, self.v = bytes(32), bytes(16)
        self.update(seed)

    def block(self):
        self.v = ((int.from_bytes(self.v, "big") + 1) % (1 << 128)).to_bytes(16, "big")
        enc = Cipher(algorithms.AES(self.key), modes.ECB()).encryptor()
        return enc.update(self.v) + enc.finalize()

    def update(self, provided=None):
        temp = b"".join(self.block() for _ in range(3))
        if provided:
            temp = bytes(a ^ b for a, b in zip(temp, provided))
        self.key, self.v = temp[:32], temp[32:]

    def __call__(self, n):
        out = b"".join(self.block() for _ in range((n + 15) // 16))[:n]
        self.update()
        return out


def draft_records():
    text = open(os.path.join(ROOT, "rfcs", "draft-josefsson-ntruprime-streamlined-00.txt")).read()
    start = text.index("7.  Streamlined NTRU Prime: Test Vectors\n")
    body = text[start:start + text[start:].index("8.  Acknowledgements")]
    records, current = [], None
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("count ="):
            records.append({})
            current = None
            continue
        match = re.match(r"(seed|pk|sk|ct|ss)\s*=\s*\"?([0-9A-Fa-f]*)\"?", stripped)
        if match:
            current = match.group(1)
            records[-1][current] = match.group(2)
        elif stripped.startswith('"') and current:
            records[-1][current] += stripped.strip('"')
    assert len(records) == 2
    return [{k: bytes.fromhex(v) for k, v in r.items()} for r in records]


def test_sntrup761_reproduces_the_drafts_known_answers():
    for record in draft_records():
        drbg = NistDrbg(record["seed"])
        public, secret = allcrypt.sntrup761_keypair(randombytes=drbg)
        assert public == record["pk"]
        assert secret == record["sk"]
        shared, ciphertext = allcrypt.sntrup761_encapsulate(public, randombytes=drbg)
        assert ciphertext == record["ct"]
        assert shared == record["ss"]
        assert allcrypt.sntrup761_decapsulate(secret, ciphertext) == shared


def test_sntrup761_round_trips_and_rejects_implicitly():
    public, secret = allcrypt.sntrup761_keypair()
    assert (len(public), len(secret)) == (1158, 1763)
    shared, ciphertext = allcrypt.sntrup761_encapsulate(public)
    assert len(ciphertext) == 1039
    assert allcrypt.sntrup761_decapsulate(secret, ciphertext) == shared
    altered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    assert allcrypt.sntrup761_decapsulate(secret, altered) != shared
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.sntrup761_decapsulate(secret, ciphertext[:-1])
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.sntrup761_keypair(randombytes=lambda n: bytes(n - 1))
