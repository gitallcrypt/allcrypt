"""Type stubs for the allcrypt extension module.

Kept next to the built module so editors and mypy can see the API without
importing the compiled artifact.
"""

import enum
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

#: Anything holding bytes: `bytes`, `bytearray`, `memoryview`,
#: `array("B")`, a NumPy `uint8` array - any contiguous buffer of single
#: bytes. **Every byte-taking argument in this module accepts one**, so
#: working with mutable buffers needs no `bytes(...)` at the boundary.
#:
#: Typeshed calls this `ReadableBuffer` and `collections.abc.Buffer` is
#: the 3.12 spelling; written out here so the stub needs neither a
#: version check nor `typing_extensions`. **Return values are `bytes`**,
#: which is why this is not used everywhere `bytes` appears.
#:
#: Two things it does not cover, both refused at runtime with a message
#: saying so: a non-contiguous buffer (`memoryview(x)[::2]` - a
#: `BufferError`, as in `hashlib`), and a buffer of multi-byte items
#: (`array("I")` - a `TypeError`, where `hashlib` would hash the
#: machine's own byte order). `bytes(x)` and `x.tobytes()` are the two
#: remedies, and they put the choice where it belongs.
BytesLike = Union[bytes, bytearray, memoryview]

__version__: str

algorithms_available: List[str]

class Mode(str, enum.Enum):
    """The cipher modes, generated from ``api::MODES``.

    Members are ``str`` subclasses: ``Mode.CBC == "cbc"`` is true, so
    anywhere a mode name is taken, a member works.
    """
    ECB: "Mode"
    CBC: "Mode"
    CFB: "Mode"
    OFB: "Mode"
    CTR: "Mode"

class BlockCipher(str, enum.Enum):
    """The block ciphers, generated from ``api::BLOCK_CIPHERS``."""

class HashName(str, enum.Enum):
    """The hashes, generated from ``api::HASHES``.

    Named ``HashName`` rather than ``Hash`` because ``Hash`` is the hash
    object's own class.
    """

class StreamCipherName(str, enum.Enum):
    """The stream ciphers. ``StreamCipher`` is the object's class."""

class AeadName(str, enum.Enum):
    """The AEADs. ``Aead`` is the object's class."""

class CurveName(str, enum.Enum):
    """The named curves, generated from ``api::CURVES``."""
block_ciphers_available: List[str]
stream_ciphers_available: List[str]
modes_available: List[str]
aeads_available: List[str]
curves_available: List[str]
#: Every cipher suite in the registry, implemented or not - the catalogue
#: of what TLS has, rather than of what this library has.
tls_suites_available: List[str]

class CryptoError(ValueError):
    """Raised for any bad key, IV, mode, length or algorithm name."""

class Hash:
    """A hash in progress, shaped like a ``hashlib`` object."""

    def __init__(self, name: str, data: Optional[BytesLike] = None) -> None: ...
    def update(self, data: BytesLike) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> "Hash":
        """A fork of this hash's state; later updates do not affect it."""
    @property
    def digest_size(self) -> int: ...
    @property
    def block_size(self) -> int: ...
    @property
    def name(self) -> str: ...

def new(name: str, data: Optional[BytesLike] = None) -> Hash: ...
def md5(data: Optional[BytesLike] = None) -> Hash: ...
def sha0(data: Optional[BytesLike] = None) -> Hash: ...
def sha1(data: Optional[BytesLike] = None) -> Hash: ...
def sha224(data: Optional[BytesLike] = None) -> Hash: ...
def sha256(data: Optional[BytesLike] = None) -> Hash: ...
def sha384(data: Optional[BytesLike] = None) -> Hash: ...
def sha512(data: Optional[BytesLike] = None) -> Hash: ...
def sha512_224(data: Optional[BytesLike] = None) -> Hash: ...
def sha512_256(data: Optional[BytesLike] = None) -> Hash: ...

class Encryptor:
    """One encryption or decryption in progress."""

    def update(self, data: BytesLike) -> bytes:
        """Transform the next piece of input.

        For ``ecb`` and ``cbc`` the result may be shorter than the input,
        because whole blocks are buffered until they are complete.
        """
    def update_into(self, buf: bytearray) -> None:
        """Transform ``buf`` in place, with no copying.

        Only ``ctr``, ``ofb`` and ``cfb`` support this; ``ecb`` and ``cbc``
        raise :class:`CryptoError` because they work a block at a time.
        """
    def finalize(self) -> bytes:
        """End the stream, raising if a partial block was left dangling."""
    @property
    def block_size(self) -> int: ...
    @property
    def mode(self) -> str: ...
    @property
    def algorithm(self) -> str: ...

class AeadEncryptor:
    """One authenticated encryption or decryption in progress."""

    def update(self, data: BytesLike) -> bytes:
        """Transform the next piece of input.

        On a decryption, nothing this returns has been authenticated until
        :meth:`verify` has been called and has not raised.
        """
    def tag(self) -> bytes:
        """Finish an encryption and return the 16 byte tag."""
    def verify(self, tag: BytesLike) -> None:
        """Finish a decryption, raising :class:`CryptoError` if the tag does
        not match."""

class Aead:
    """An authenticated cipher, shaped like ``AESGCM`` in ``cryptography``.

    ``encrypt`` returns the ciphertext with the tag appended and ``decrypt``
    expects the same, which is the convention the Python ecosystem uses.

    **The nonce must never repeat under one key.** Two messages sharing one
    give away their XOR *and* the authentication key, after which anything
    can be forged under that key. Nothing here can check it; only the caller
    knows what was used before.
    """

    def __init__(self, key: BytesLike, name: str = "aes-gcm") -> None:
        """``name`` is one of ``aeads_available`` - ``"aes-gcm"``,
        ``"aes-ccm"``, ``"aes-ccm-8"``, ``"chacha20-poly1305"``, or an
        EAX or MGM over any of the block ciphers, or an OCB over any
        128 bit one (nonce up to 15 bytes, 16 byte tag).

        ChaCha20-Poly1305 takes a 256 bit key and a 96 bit nonce, and only
        those. AES-GCM takes 128, 192 or 256 bit keys and any non-empty
        nonce, though 96 bits is the size to use. AES-CCM takes the same
        keys and a nonce of 7 to 13 bytes - the nonce and the message
        length share fifteen bytes, so a longer nonce means a shorter
        maximum message. ``aes-ccm-8`` is CCM with an eight byte tag.

        **MGM's nonce is a whole block**, not twelve bytes: sixteen for
        ``kuznyechik-mgm`` and eight for ``magma-mgm``, and its top bit
        must be clear, because that bit separates the mode's two
        counter chains. It also refuses an empty message *and* empty
        associated data together - RFC 9058 section 6, where the tag
        stops depending on the nonce and one captured tag forges every
        such message.
        """
        # Raises CryptoError for a key length the cipher does not have, or
        # an AEAD that is not implemented - at construction, rather than at
        # the first encryption somewhere else entirely.

    def encrypt(self, nonce: BytesLike, data: BytesLike,
                associated_data: Optional[BytesLike] = None) -> bytes:
        """Encrypt and authenticate. Returns ciphertext followed by the tag."""
    def decrypt(self, nonce: BytesLike, data: BytesLike,
                associated_data: Optional[BytesLike] = None) -> bytes:
        """Verify and decrypt ``ciphertext || tag``.

        Raises :class:`CryptoError` on any failure and returns nothing at
        all. There is no partial result: unverified plaintext is not a
        result."""

    # CCM cannot stream: its MAC begins with the message's length, so
    # nothing can be processed before all of it has arrived. The two
    # constructors below raise for it rather than buffering behind an
    # ``update`` that would promise constant memory and not deliver it -
    # the same line ``cryptography`` draws for its ``AESCCM``.
    def encryptor(self, nonce: BytesLike,
                  associated_data: Optional[BytesLike] = None) -> AeadEncryptor: ...
    def decryptor(self, nonce: BytesLike,
                  associated_data: Optional[BytesLike] = None) -> AeadEncryptor: ...

    @property
    def name(self) -> str: ...
    @property
    def tag_size(self) -> int:
        """16 bytes, or 8 for ``aes-ccm-8`` - which exists for exactly
        that reason, so a constant here would misinform the one caller who
        needs to know."""

class Cipher:
    """A keyed block cipher.

    Holds no mode state, so one instance can spawn any number of independent
    encryptors and decryptors. ``param`` selects the S-box parameter set for
    ``gost`` and is ignored by the other ciphers.
    """

    def __init__(self, name: str, key: BytesLike, param: Optional[str] = None) -> None: ...
    def encryptor(self, mode: str, iv: Optional[BytesLike] = None) -> Encryptor: ...
    def decryptor(self, mode: str, iv: Optional[BytesLike] = None) -> Encryptor: ...
    def encrypt(self, mode: str, data: BytesLike, iv: Optional[BytesLike] = None) -> bytes: ...
    def decrypt(self, mode: str, data: BytesLike, iv: Optional[BytesLike] = None) -> bytes: ...
    @property
    def block_size(self) -> int: ...
    @property
    def name(self) -> str: ...

class StreamCipher:
    """A keyed stream cipher; its state carries across calls.

    ``update`` XORs the keystream onto the data, which encrypts and
    decrypts alike. ZipCrypto's keys absorb the plaintext, so it has no
    such keystream: ``update`` raises, and ``encrypt`` and ``decrypt``,
    which every stream cipher has, are the way to use it.
    """

    def __init__(self, name: str, key: BytesLike, nonce: Optional[BytesLike] = None) -> None: ...
    def update(self, data: BytesLike) -> bytes: ...
    def encrypt(self, data: BytesLike) -> bytes: ...
    def decrypt(self, data: BytesLike) -> bytes: ...
    @property
    def keystream(self) -> bool:
        """Whether ``update`` works: encrypting and decrypting are one operation."""
    @property
    def name(self) -> str: ...

class Hmac:
    """A keyed HMAC in progress, shaped like Python's own ``hmac`` objects."""

    def __init__(self, key: BytesLike, msg: Optional[BytesLike] = None,
                 digestmod: str = "sha256") -> None: ...
    def update(self, data: BytesLike) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    @property
    def digest_size(self) -> int: ...
    @property
    def name(self) -> str: ...

class EcKey:
    """An elliptic curve key pair on one of ``curves_available``."""

    @staticmethod
    def generate(curve: str) -> "EcKey":
        """A fresh key pair; the scalar comes from the OS random source."""

    @staticmethod
    def from_private(curve: str, private: BytesLike) -> "EcKey":
        """Import a private scalar, big endian. Refuses anything outside [1, n)."""

    def private_bytes(self) -> bytes: ...
    def public_bytes(self, compressed: bool = False) -> bytes:
        """SEC1 encoding: ``0x04 || X || Y``, or ``0x02``/``0x03 || X``."""

    def sm2_sign(self, message: BytesLike, id: Optional[BytesLike] = None) -> bytes:
        """SM2 signature, GB/T 32918.2. Takes the **message**, not a digest.

        ``id`` is the distinguishing identifier and defaults to the
        standard's ``b"1234567812345678"``. Pass ``b""`` for the empty
        identity ``openssl pkeyutl`` uses by default. sm2p256v1 only.
        """

    def sm2_verify(self, message: BytesLike, signature: BytesLike,
                   id: Optional[BytesLike] = None) -> bool: ...
    def sm2_decrypt(self, ciphertext: BytesLike) -> bytes:
        """Decrypt ``C1 || C3 || C2``."""

    def sm2_decrypt_der(self, der: BytesLike) -> bytes:
        """Decrypt the ``SEQUENCE {x1, y1, C3, C2}`` OpenSSL writes."""

    def exchange(self, peer_public: BytesLike) -> bytes:
        """ECDH. The peer point is validated before it is used."""

    def sign(self, digest: BytesLike, digestmod: str = "sha256") -> bytes:
        """ECDSA over an already computed digest, returning ``r || s``.

        Deterministic (RFC 6979): no random source is involved, and the same
        digest always gives the same bytes. ``digestmod`` must name the hash
        that produced ``digest``.
        """

    def verify(self, digest: BytesLike, signature: BytesLike) -> bool:
        """Verify with this key's own public half."""

    def public_key(self) -> "EcPublicKey": ...

    @property
    def curve(self) -> str: ...
    @property
    def key_size(self) -> int: ...

class EddsaKey:
    """An Ed25519 or Ed448 key pair."""

    @staticmethod
    def generate(name: str) -> "EddsaKey": ...
    @staticmethod
    def from_private(name: str, private: BytesLike) -> "EddsaKey":
        """Import a seed - 32 bytes for Ed25519, 57 for Ed448.

        A **seed**, not a scalar: the signing scalar is the hash of
        these bytes, clamped.
        """

    def private_bytes(self) -> bytes: ...
    def public_bytes(self) -> bytes: ...
    def sign(self, message: BytesLike, context: Optional[BytesLike] = None) -> bytes:
        """Sign a **message**, not a digest: EdDSA hashes internally."""

    def verify(self, message: BytesLike, signature: BytesLike,
               context: Optional[BytesLike] = None) -> bool: ...

    @property
    def curve(self) -> str: ...
    @property
    def key_size(self) -> int: ...

def tls_signature_schemes() -> List[str]:
    """The signature schemes the client offers, in preference order."""

class EcPublicKey:
    """A public point on a named curve: enough to verify, nothing more."""

    def __init__(self, curve: str, encoded: BytesLike) -> None:
        """Import a SEC1 point. Raises if it is not on the curve."""

    def public_bytes(self, compressed: bool = False) -> bytes: ...
    def verify(self, digest: BytesLike, signature: BytesLike) -> bool:
        """False for a wrong signature; raises for one that is malformed."""

    def sm2_verify(self, message: BytesLike, signature: BytesLike,
                   id: Optional[BytesLike] = None) -> bool:
        """Verify an SM2 signature over the message. sm2p256v1 only."""

    def sm2_encrypt(self, message: BytesLike) -> bytes:
        """Encrypt, returning ``C1 || C3 || C2``."""

    def sm2_encrypt_der(self, message: BytesLike) -> bytes:
        """Encrypt into the DER form OpenSSL reads."""

    @property
    def curve(self) -> str: ...
    @property
    def key_size(self) -> int: ...

class RsaKey:
    """An RSA private key, with its public half alongside."""

    @staticmethod
    def generate(bits: int = 2048) -> "RsaKey":
        """Generate a key. Slow and of unpredictable duration: it searches
        for primes. Refuses anything below 512 bits."""

    @staticmethod
    def from_primes(p: BytesLike, q: BytesLike, e: Optional[BytesLike] = None) -> "RsaKey":
        """Rebuild a key from its primes, big endian. ``e`` defaults to 65537.

        The CRT parameters are derived rather than taken, so they cannot
        disagree with the primes.
        """

    def public_key(self) -> "RsaPublicKey": ...
    def sign(self, digest: BytesLike, digestmod: str = "sha256") -> bytes:
        """PKCS#1 v1.5 over an already computed digest. Deterministic."""

    def decrypt(self, ciphertext: BytesLike) -> bytes:
        """PKCS#1 v1.5 decryption.

        Every failure raises the same message, on purpose. Do not catch this
        and report which check failed: that is Bleichenbacher's attack.
        """

    def decrypt_oaep(self, ciphertext: BytesLike, digestmod: str = "sha256",
                     mgf_digestmod: Optional[str] = None,
                     label: BytesLike = b"") -> bytes:
        """RSAES-OAEP decryption. ``mgf_digestmod`` defaults to ``digestmod``;
        the label must be the one encrypted under.

        Every failure of the ciphertext raises the same message: telling
        them apart is Manger's attack.
        """

    def sign_pss(self, digest: BytesLike, digestmod: str = "sha256",
                 salt_length: Optional[int] = None) -> bytes:
        """PSS over an already computed digest, with a random salt of
        ``salt_length`` bytes - the hash's length by default."""

    @property
    def numbers(self) -> dict:
        """n, e, d, p, q, dp, dq, qinv as big endian bytes."""
    @property
    def key_size(self) -> int:
        """Modulus size in bits."""
    @property
    def size(self) -> int:
        """Modulus size in bytes: the size of a ciphertext or signature."""

class RsaPublicKey:
    """An RSA public key: enough to encrypt and to verify."""

    def __init__(self, n: BytesLike, e: Optional[BytesLike] = None) -> None:
        """From a modulus and exponent, big endian. ``e`` defaults to 65537."""

    def encrypt(self, message: BytesLike) -> bytes:
        """PKCS#1 v1.5. Randomised, so the bytes differ every time."""

    def encrypt_oaep(self, message: BytesLike, digestmod: str = "sha256",
                     mgf_digestmod: Optional[str] = None,
                     label: BytesLike = b"") -> bytes:
        """RSAES-OAEP. ``digestmod`` hashes the label and sets the seed's
        length; ``mgf_digestmod``, which defaults to it, drives MGF1."""

    def verify_pss(self, digest: BytesLike, signature: BytesLike,
                   digestmod: str = "sha256",
                   salt_length: Optional[int] = None) -> bool:
        """False for a wrong signature. The salt length is required, not
        recovered from the signature: the hash's length by default."""

    def verify(self, digest: BytesLike, signature: BytesLike,
               digestmod: str = "sha256") -> bool:
        """False for a wrong signature; raises for a malformed one."""

    @property
    def n(self) -> bytes: ...
    @property
    def e(self) -> bytes: ...
    @property
    def key_size(self) -> int: ...
    @property
    def size(self) -> int: ...

class DhGroup:
    """A finite-field Diffie-Hellman group: a prime and a generator.

    Every value in and out is big-endian bytes padded to the width of the
    modulus, which is what OpenSSL produces. TLS 1.0-1.2 strip those zeros
    again for the premaster secret, which is why ``tls_premaster`` is a
    method of its own rather than the default.
    """

    def __init__(self, p: BytesLike, g: BytesLike) -> None:
        """From ``p`` and ``g``, big endian. Raises for an even modulus or a
        generator outside ``[2, p-2]``; size is a separate question."""

    @staticmethod
    def modp(bits: int) -> "DhGroup":
        """A built-in MODP group: 1024 (RFC 2409), or 1536, 2048, 3072,
        4096, 6144 or 8192 (RFC 3526)."""

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """A fresh ``(private, public)`` pair, both padded to ``p``."""

    def public_key(self, private: BytesLike) -> bytes:
        """``g**x mod p``."""

    def shared_secret(self, private: BytesLike, peer: BytesLike) -> bytes:
        """The shared secret, padded to the width of ``p``.

        Raises if the peer's value is 0, 1 or ``p-1`` - each of which makes
        the secret a constant, and each of which completes a key exchange
        in an implementation that does not check.
        """

    def tls_premaster(self, private: BytesLike, peer: BytesLike) -> bytes:
        """The shared secret with leading zeros stripped, as TLS 1.0-1.2
        use it (RFC 5246 section 8.1.2). TLS 1.3 keeps them."""

    def validate_peer(self, peer: BytesLike) -> None:
        """Raise if a peer public value is one of the degenerate ones."""

    def check_prime(self, rounds: int = 24) -> None:
        """Raise if ``p`` is composite. Several full-width modular
        exponentiations, so it is asked for rather than done for you - but
        a composite modulus makes the shared secret computable by whoever
        chose it while everything else looks right."""

    @property
    def bits(self) -> int: ...
    @property
    def p(self) -> bytes: ...
    @property
    def g(self) -> bytes: ...

class ElGamalKey:
    """An ElGamal key pair over a ``DhGroup``.

    OpenPGP algorithm 16 - the ``elg`` half of the ``dsa/elg`` keypairs
    GnuPG made by default for years. OpenSSL dropped ElGamal and
    ``cryptography`` never had it, so this is the only way to read those
    messages from Python.
    """

    @staticmethod
    def generate(group: "DhGroup") -> "ElGamalKey":
        """A fresh key in the given group."""

    @staticmethod
    def from_private(group: "DhGroup", private: BytesLike) -> "ElGamalKey":
        """A key from a private exponent, which is what a PGP secret key
        carries. The public value is recomputed rather than trusted."""

    def public_key(self) -> "ElGamalPublicKey": ...

    def decrypt(self, ciphertext: BytesLike) -> bytes:
        """OpenPGP's ElGamal decryption: PKCS#1 v1.5 inside the raw
        scheme.

        **Every failure raises the same message**, deliberately. Saying
        which check failed turns the key into a decryption oracle, which
        is Bleichenbacher's attack - and it is about the padding check
        rather than the trapdoor, so ElGamal is as exposed as RSA.
        """

    def sign(self, digest: BytesLike) -> bytes:
        """Sign a digest, returning ``r || s``.

        GnuPG withdrew ElGamal signing in 2003 after its sign+encrypt
        keys were broken by a short nonce. That was one implementation's
        choice rather than a flaw in the equation, and this is here
        because old signatures still need verifying.
        """

    @property
    def private_bytes(self) -> bytes: ...
    @property
    def public_bytes(self) -> bytes: ...
    @property
    def size(self) -> int:
        """One ciphertext component's width. A whole ciphertext is two."""

class ElGamalPublicKey:
    """The public half of an ElGamal key."""

    def __init__(self, group: "DhGroup", y: BytesLike) -> None:
        """Raises if ``y`` is 0, 1 or ``p-1`` - the same check a
        Diffie-Hellman peer value gets, for the same reason."""

    def encrypt(self, message: BytesLike) -> bytes:
        """OpenPGP's ElGamal encryption, returning ``c1 || c2``."""

    def verify(self, digest: BytesLike, signature: BytesLike) -> bool:
        """Verify ``r || s``. Range-checks both, which is not a
        formality: a verifier accepting ``r >= p`` can be handed a
        forged signature for a chosen message."""

    @property
    def y(self) -> bytes: ...
    @property
    def size(self) -> int: ...

class Certificate:
    """A parsed X.509 certificate."""

    def __init__(self, der: BytesLike) -> None:
        """Parse DER. Raises on anything malformed - including things a
        lenient parser would accept, such as a duplicate extension, a
        non-minimal length, or a name with an embedded NUL."""

    def to_dict(self) -> dict:
        """Every field, shaped like ``ssl.getpeercert()`` where they line up.

        Keys: version, serialNumber, notBefore, notAfter, subject, issuer,
        subjectAltName, commonName, issuerCommonName, signatureAlgorithm,
        publicKeyType, publicKeyBits, publicKeyParameterSet, isCA,
        pathLen, keyUsage, extendedKeyUsage, unrecognisedCritical.

        ``publicKeyParameterSet`` is not in ``ssl.getpeercert()`` and is
        ``None`` for everything but GOST. It is there because
        ``publicKeyType`` cannot express the distinction that decides
        whether a GOST key exchange is accepted: CryptoPro-A and
        CryptoPro-XchA are the same curve under two OIDs, so both read as
        ``gost256-a``, and naming the wrong one gets a ``decode_error``.
        """

    def matches_hostname(self, hostname: str) -> bool:
        """RFC 6125: a subjectAltName wins over the common name, a wildcard
        covers exactly one label and only the leftmost one."""

    @property
    def der(self) -> bytes: ...
    @property
    def tbs(self) -> bytes:
        """The TBSCertificate bytes: what the signature covers."""
    @property
    def subject(self) -> str: ...
    @property
    def issuer(self) -> str: ...
    @property
    def not_before(self) -> int: ...
    @property
    def not_after(self) -> int: ...
    @property
    def is_ca(self) -> bool: ...

def verify_chain(chain: Sequence[BytesLike], roots: Sequence[BytesLike], now: int,
                 hostname: Optional[str] = None, purpose: str = "server",
                 allow_sha1: bool = False, allow_md5: bool = False,
                 allow_expired: bool = False,
                 min_rsa_bits: int = 2048,
                 max_chain_length: int = 10,
                 crls: Sequence[BytesLike] = [],
                 ocsp: Sequence[BytesLike] = [],
                 ocsp_nonce: Optional[BytesLike] = None,
                 require_revocation: bool = False) -> None:
    """Verify a certificate chain, leaf first, against trusted roots.

    Returns None if every check passed and raises :class:`CryptoError` with
    the reason otherwise. ``now`` is seconds since the epoch and is required
    rather than read from a clock, so verification is reproducible.

    ``allow_sha1``, ``allow_md5``, ``allow_expired`` and ``min_rsa_bits``
    exist because talking to old servers is the point of this library. They
    are off by default.

    ``crls`` are DER certificate revocation lists and ``ocsp`` are DER
    OCSP responses, checked against every certificate in the chain and
    not only the leaf. OCSP is consulted first, because it answers
    about one certificate and is normally fresher; a CRL is the
    fallback. Responses need no labelling - each is matched to a
    certificate by its CertID. Nothing here fetches any of it; see
    :func:`crl_distribution_points` and :func:`ocsp_responders`.

    ``ocsp_nonce`` is the nonce sent in the request, if one was. A
    response that does not carry it back is not an answer to that
    request.
    ``require_revocation`` makes a status that could not be established a
    failure. It is off by default, which is soft fail; with it on and no
    CRLs supplied, every chain fails. A *revoked* certificate is refused
    either way.

    Name constraints on any CA in the chain are enforced always, with no
    flag to turn them off.
    """

def crl_distribution_points(der: BytesLike) -> List[str]:
    """Where a certificate says its CRL can be fetched, as URIs.

    Reported, never fetched: no socket is opened anywhere in this library.
    Get the bytes yourself and pass them to :func:`verify_chain` as
    ``crls``. A certificate with no such extension gives an empty list
    rather than raising - not having one is ordinary.
    """

def ocsp_responders(der: BytesLike) -> List[str]:
    """Where a certificate says its OCSP responder lives, as URLs.

    Reported, never fetched. Only the ``id-ad-ocsp`` entries of the
    authorityInfoAccess extension: the other access method in the same
    extension points at the issuer's *certificate*, and an OCSP request
    sent there reaches a file server.
    """

def ocsp_request(certificate: BytesLike, issuer: BytesLike, hash: str = "sha1",
                 nonce: Optional[BytesLike] = None) -> bytes:
    """An OCSP request for one certificate, as DER to POST.

    ``nonce`` is your own random bytes and must be handed back to
    :func:`ocsp_status` or to :func:`verify_chain`. **It is the only
    defence against a replayed response** - without one, a captured
    "good" stays valid until its nextUpdate, which is how a revoked
    certificate stays usable.
    """

def ocsp_status(certificate: BytesLike, issuer: BytesLike, response: BytesLike,
                now: int, nonce: Optional[BytesLike] = None) -> Tuple[str, str]:
    """What an OCSP response says, as ``(status, detail)``.

    The same three values :func:`crl_status` gives, because it is the
    same question. The responder answering ``unknown`` - meaning it
    cannot speak for this certificate, which is what a responder for a
    different CA says about yours - comes back as ``"unknown"``, not as
    ``"not_revoked"``.
    """

def crl_status(certificate: BytesLike, issuer: BytesLike, crls: Sequence[BytesLike],
               now: int) -> Tuple[str, str]:
    """What a CRL says about one certificate, as ``(status, detail)``.

    ``status`` is ``"revoked"``, ``"not_revoked"`` or ``"unknown"``.

    **Three values, not a boolean.** "Nothing could be established" is not
    "fine", and every way of getting a revocation check wrong turns the
    first into the second - no CRL supplied, a stale one, one signed by
    the wrong key, one covering the wrong part of the space. ``detail``
    says which.
    """

class TrustStore:
    """A set of trusted root certificates."""

    def __init__(self) -> None:
        """An empty store. Add roots before verifying anything with it."""

    @staticmethod
    def system() -> "TrustStore":
        """The platform's own store: the CA bundle files on unix, the ROOT
        certificate store on Windows.

        Raises if nothing usable was found, rather than returning an empty
        store - an empty store silently becomes "trust nothing" and looks
        like a network problem rather than a configuration one.
        """

    @staticmethod
    def from_file(path: str) -> "TrustStore":
        """A PEM file of concatenated certificates - a CA bundle."""

    @staticmethod
    def from_directory(path: str) -> "TrustStore":
        """A directory of PEM files, as ``/etc/ssl/certs`` is."""

    def add_pem(self, text: str) -> int:
        """Add every certificate in some PEM text; returns how many."""
    def add_der(self, der: BytesLike) -> None: ...
    def subjects(self) -> List[str]: ...
    def __len__(self) -> int: ...

    @property
    def roots(self) -> List[bytes]:
        """The roots as DER, for passing to :func:`verify_chain`."""
    @property
    def skipped(self) -> int:
        """Entries found but not parseable. Worth looking at: a store that
        dropped most of its roots looks like one that worked."""
    @property
    def skipped_reasons(self) -> List[str]:
        """Why those entries failed, up to the first sixteen. Each names the
        entry by size and digest - there is no subject to quote, since
        parsing it is what failed - and carries the parser's own complaint,
        which is what says whether the certificate is malformed or this
        library is too strict."""
    @property
    def source(self) -> str: ...

def encrypt_private_key(key: BytesLike, password: BytesLike, scheme: str = "aes-256-cbc", *,
                        prf: Optional[str] = None, iterations: Optional[int] = None,
                        salt: Optional[BytesLike] = None, iv: Optional[BytesLike] = None,
                        pem: bool = False) -> bytes:
    """Encrypt a PKCS#8 private key into an EncryptedPrivateKeyInfo (DER, or PEM)."""
def encryption_schemes() -> List[str]:
    """The scheme names ``encrypt_private_key`` takes."""
def private_key_encryption(data: BytesLike) -> Dict[str, Any]:
    """How an encrypted private key was encrypted: scheme, prf, iterations, salt, iv."""
def private_key(data: BytesLike,
                password: Optional[BytesLike] = None
                ) -> Union["EcKey", "RsaKey", "EddsaKey", "MlDsaKey", "DsaKey",
                           Tuple[str, bytes]]:
    """Read a private key from PEM text or DER bytes.

    Returns whichever kind the file holds, so the result goes straight
    to ``TlsServer`` without the caller having to know which it got. An
    X25519 or X448 key (RFC 8410), which has no key object here, comes
    back as ``("x25519", private)`` or ``("x448", private)``: the bytes
    ``x25519_exchange`` and ``x448_exchange`` take.

    PKCS#8 (``PRIVATE KEY``), SEC1 (``EC PRIVATE KEY``) and PKCS#1
    (``RSA PRIVATE KEY``) are all read, and **the bytes decide rather
    than the label**: ``openssl`` will put a SEC1 body under a
    ``PRIVATE KEY`` header if asked the wrong way, and a file that works
    everywhere else has to work here. A file holding a certificate and a
    key together - the usual deployment shape - is fine; the certificate
    is skipped.

    **Encrypted** keys are read too, given ``password``. PBES2 (RFC 8018
    A.4), the six PBES1 schemes (A.3) and the PKCS#12 PBEs (RFC 7292 B)
    are all understood, which between them covers everything
    ``openssl pkcs8 -topk8`` has ever written - including the schemes
    OpenSSL now hides behind ``-provider legacy`` and the two OIDs
    ``python-cryptography`` refuses outright.

    Without a password an encrypted key is refused *by name* rather than
    as "unsupported", because the remedy is a passphrase and not a
    different file. With the wrong password the PKCS#7 padding check
    refuses it - none of these schemes is authenticated, so that check is
    the only thing between a wrong password and a confident wrong answer.

    A password given for a key that is *not* encrypted is ignored, so a
    caller need not know which of its files used one.
    """


def pem_certificates(text: str) -> List[bytes]:
    """The certificates in some PEM text, as DER. Other block types are
    ignored; a malformed block raises."""

def tls_suite_names(selection: str = "modern") -> List[str]:
    """The suites a selection offers, in hello order.

    Takes the same strings ``TlsClient`` does: ``"modern"``,
    ``"legacy"``, ``"all"``, or a comma separated list of suite names.
    An unknown name raises rather than returning an empty list.
    """
    ...


def pem_wrap(der: BytesLike, label: str = "CERTIFICATE") -> str:
    """Wrap DER as a PEM block, 64 characters to a line."""

class TlsClient:
    """A TLS client connection, sans-I/O.

    This holds no socket. Feed it the bytes that arrived with
    ``push_incoming``, call ``process``, and send whatever ``take_outgoing``
    returns. Python owns the socket; this owns the protocol.
    """

    def __init__(self, hostname: str, roots: TrustStore, now: int,
                 ciphers: str = "modern", verify: bool = True,
                 min_version: str = "TLSv1.2", max_version: str = "TLSv1.2",
                 allow_sha1: bool = False, allow_md5: bool = False,
                 allow_expired: bool = False, verify_hostname: bool = True,
                 min_rsa_bits: int = 2048, min_dh_bits: int = 2048,
                 check_dh_prime: bool = False,
                 request_encrypt_then_mac: bool = True,
                 tickets: Sequence[BytesLike] = [],
                 client_certificate: Optional[Sequence[BytesLike]] = None,
                 client_key: Optional[Union["EcKey", "RsaKey", "MlDsaKey"]] = None,
                 early_data: BytesLike = b"",
                 alpn: List[str] = [],
                 request_stapled_ocsp: bool = True,
                 require_stapled_ocsp: bool = False) -> None:
        """Start a connection and produce the ClientHello.

        ``roots`` must hold the certificates to verify against; there is no
        default, because a client with no roots verifies nothing.
        ``verify=False`` skips verification - sometimes the only way to talk
        to something, and reported afterwards by ``certificate_verified``.

        ``ciphers`` is ``"modern"``, ``"legacy"``, or a comma separated list
        of suite names.

        Four ways to accept a certificate the default refuses, narrowest
        first - reach for the first that works, not the one that always
        works:

        1. Put the server's own certificate in ``roots``. Not a relaxation
           at all: it is authentication against a certificate you chose,
           and a man in the middle still fails.
        2. ``allow_expired=True`` - the dates, and nothing else.
        3. ``verify_hostname=False`` - the name, and nothing else. The
           chain is still verified. For connecting by IP address, or to a
           box whose certificate names something it no longer answers to.
        4. ``verify=False`` - nothing is checked at all. Reported
           afterwards by ``certificate_verified``, and the certificate is
           still there to look at through ``peer_certificates``.

        ``min_dh_bits`` is not about the certificate: a DHE server chooses
        the Diffie-Hellman group by itself, so it is the client's only say
        in the matter. 2048 by default; lower it to reach something old.
        ``check_dh_prime`` adds a primality test of the server's modulus,
        which costs more than the key exchange and catches the one attack
        nothing else would notice.

        ``tickets`` are session tickets from an earlier connection, as
        ``take_tickets`` handed them out. Offer each one once.

        ``client_certificate`` and ``client_key`` are the identity to
        send if the server asks for one - a chain
        leaf first as DER, and the matching ``EcKey`` or ``RsaKey``.
        They go together, and either alone is an error here rather than
        a handshake failure later. Without them a CertificateRequest is
        answered with an **empty** certificate rather than with silence,
        which is what RFC 8446 asks for: the server then decides whether
        that ends the connection.

        ``early_data`` is sent as TLS 1.3 0-RTT, before the handshake
        finishes. It goes only when the first ticket in ``tickets``
        permits it and is big enough, and only if the server then
        accepts - ask ``early_data_accepted`` afterwards, because when
        it is false those bytes did not arrive and **they are not
        resent for you**.

        Two things are true of them and of nothing else on the
        connection. They are **not forward secret**: they are encrypted
        under a key derived from a PSK that has been sitting in storage,
        so whoever later obtains it reads them. And they are
        **replayable**: they are sent before the server has said a word,
        so a captured copy of the flight is as valid the second time.
        Put in them only what may happen twice.

        ``alpn`` is the application protocols to offer (RFC 7301), in
        the client's order of preference. The *server* chooses, and may
        choose against that order; what this client enforces is that the
        answer is one of these and that it names exactly one, because
        either failure is an application speaking a protocol it never
        agreed to.

        ``request_stapled_ocsp`` asks the server for a cached OCSP
        response about its certificate (RFC 6066 §8). On by default; it
        costs one extension and the server either has one or does not.

        What the staple is allowed to decide is **asymmetric**. One that
        says *revoked* fails the handshake whatever else is set - that
        is an answer, signed by somebody the certificate's own issuer
        delegated to. One that settles nothing - absent, unreadable,
        about another certificate - costs nothing unless
        ``require_stapled_ocsp`` is on, which is off by default because
        most servers staple nothing.

        ``require_stapled_ocsp`` is **not** a CRL requirement: nothing
        here fetches a CRL, so requiring one would refuse every chain.
        """

    def push_incoming(self, data: BytesLike) -> None: ...
    def take_outgoing(self) -> bytes:
        """The bytes to send. Taken: a second call returns nothing."""
    def take_incoming(self) -> bytes:
        """Application data received so far."""
    def process(self) -> None:
        """Advance as far as the bytes allow. Raises with the reason on any
        protocol failure; the connection stays failed afterwards."""
    def write(self, data: BytesLike) -> None: ...
    def close(self) -> None:
        """Send close_notify."""

    def version(self) -> Optional[str]: ...
    def cipher(self) -> Optional[tuple]:
        """``(name, strength, key bits)`` once negotiated."""

    @property
    def state(self) -> str: ...
    @property
    def handshaking(self) -> bool: ...
    @property
    def established(self) -> bool: ...

    def take_tickets(self) -> List[bytes]:
        """Take the TLS 1.3 session tickets this connection was given.

        Hand them back as ``tickets=`` on a later connection to the same
        host and it resumes: no certificate, no signature, one round trip
        less.

        **These are key material.** Each one is enough to resume this
        connection. Taken rather than read, because a ticket is offered
        **once** - offering one twice lets a passive observer link the
        two connections, which is what the ticket's obfuscated age
        exists to prevent.

        Often empty right after the handshake: a TLS 1.3 server sends
        them under the application keys, so they arrive with or after
        the first data. Look again after a read.
        """

    @property
    def stapled_ocsp(self) -> Optional[bytes]:
        """The OCSP response the server stapled, as DER, or ``None``.

        ``None`` is the ordinary case and says nothing about the
        certificate: most servers staple nothing. A response saying
        *revoked* never reaches here - it fails the handshake."""

    def selected_alpn_protocol(self) -> Optional[str]:
        """The protocol the server chose, or ``None``.

        Named like ``ssl.SSLSocket.selected_alpn_protocol()``, which is
        the same question. A server cannot choose one this client did
        not offer - that is refused rather than reported."""

    @property
    def early_data_accepted(self) -> bool:
        """Whether the server took the ``early_data`` that was offered.

        False after offering is the ordinary rejection and not an
        error - but those bytes did not arrive, and they are **not
        resent for you**: whether sending them twice is acceptable is
        the decision that made them early data in the first place."""

    @property
    def resumed(self) -> bool:
        """Whether this handshake resumed a previous session.

        A resumed TLS 1.3 connection has **no certificate**: the
        pre-shared key authenticates the server, because only the peer
        that ran the original handshake could derive the same key. So an
        empty ``peer_certificates`` on one is normal rather than a
        failure, and this is what to ask first.
        """
    @property
    def peer_certificates(self) -> List[bytes]:
        """The chain the server sent, leaf first, as DER."""
    @property
    def certificate_verified(self) -> bool:
        """Whether the chain was actually verified."""
    @property
    def encrypt_then_mac(self) -> bool: ...
    @property
    def extended_master_secret(self) -> bool: ...
    @property
    def key_log_line(self) -> Optional[str]:
        """This session's line in the NSS key log format Wireshark reads:
        ``CLIENT_RANDOM <client random hex> <master secret hex>``, or
        ``None`` before the master secret exists.

        **Anyone holding this can decrypt the whole connection** from a
        capture taken at any time. Nothing writes it anywhere unless you
        do; see ``allcrypt_ssl.SSLContext.keylog_filename``."""

    @property
    def named_group(self) -> Optional[str]:
        """The group an ephemeral key exchange used, or ``None`` for static
        RSA, which has no group.

        An IANA curve name (``"secp256r1"``) for ECDHE, or the size of the
        finite field (``"dh2048"``) for DHE, which has no name to give
        before TLS 1.3 - the server sends the numbers themselves.

        Worth asking: a suite name says ECDHE or DHE but not in which
        group, and the group is the part that decides the strength."""
    @property
    def alert(self) -> Optional[str]: ...

class CertificateAuthority:
    """A certificate authority that issues leaf certificates on demand.

    The other half of a terminating proxy: read the host out of the
    client's SNI, issue a certificate for it on the spot, present it.

    **Installing this CA's certificate in a browser is a serious act.**
    Anything holding its key can then impersonate any site to that
    browser. Generate it on the machine that will use it, keep the key
    there, and remove the certificate from the store afterwards.

    EC on P-256 rather than RSA: an RSA key generation is a prime search
    taking unpredictable seconds, and a proxy issues a certificate while
    a browser waits on a half-open connection.
    """

    def __init__(self, common_name: str, not_before: str,
                 not_after: str, key_type: str = "P-256") -> None:
        """Generate a CA: a fresh key and a self-signed certificate.

        ``key_type`` is a curve name, ``"ed25519"``, or an ML-DSA
        parameter set (``"ML-DSA-44"``, ``"ML-DSA-65"``, ``"ML-DSA-87"``,
        RFC 9881). The leaves ``issue`` makes are of the same type; an
        ML-DSA leaf carries ``digitalSignature`` only, and its private key
        is the 32 byte seed ``MlDsaKey.from_seed`` takes.

        The dates are ``YYYYMMDDHHMMSSZ`` and are required rather than
        defaulted, because a proxy CA that outlives its usefulness is a
        key somebody forgot they installed.
        """

    @staticmethod
    def from_parts(private: BytesLike, certificate: BytesLike,
                   key_type: str = "P-256") -> "CertificateAuthority":
        """Rebuild a CA from a stored key and its certificate.

        A mismatched pair is **refused**: a CA signing with a key its
        certificate does not name issues chains that verify against
        nothing, with both halves looking correct on their own.
        """

    def issue(self, host: str, not_before: str,
              not_after: str) -> Tuple[bytes, bytes]:
        """Issue a leaf for ``host`` with a fresh key.

        Returns ``(certificate_der, private_key)`` - what ``TlsServer``
        and ``EcKey.from_private("P-256", ...)`` take.

        A fresh key every time rather than one reused across hosts: the
        cost is microseconds, and the alternative is a single key whose
        compromise is every site the proxy ever served.

        ``host`` may be a name or an IP address, and the two take
        different forms of subjectAltName. A verifier asked about an
        address looks only at ``iPAddress`` entries, so an address
        written as a ``dNSName`` matches nothing and says nothing about
        why.
        """

    @property
    def certificate(self) -> bytes:
        """The CA certificate as DER."""
    @property
    def certificate_pem(self) -> str:
        """The same, PEM wrapped - what a browser or OS store imports."""
    @property
    def private_bytes(self) -> bytes:
        """The private scalar, big endian.

        **Key material.** Anything holding this can impersonate any site
        to anyone who trusts this CA."""
    @property
    def common_name(self) -> str: ...
    @property
    def key_identifier(self) -> bytes:
        """The key identifier of this CA's key, which is what a leaf's
        authorityKeyIdentifier names."""

class ReplayGuard:
    """The strike register that refuses a repeated 0-RTT flight.

    **One of these is shared by every connection a server serves**, the
    way a ticket key is. A register built per connection has seen
    nothing, so it would refuse nothing - which is the shape this class
    exists to make impossible to write by accident.

    It bounds how *often* a replay works; it cannot make 0-RTT
    unreplayable. Early data carries nothing fresh from the server by
    construction (RFC 8446 8.2), so an attacker who reaches a machine
    that has not seen the flight, or who waits for the entry to age
    out, still gets it through. The guarantee to build on is that the
    application only puts things in early data that may happen twice.
    """

    def __init__(self, capacity: int = 4096) -> None:
        """A register remembering the last ``capacity`` flights.

        Size it for the 0-RTT connections expected within a ticket
        lifetime, not for comfort: too small means a replay outside the
        window succeeds, which is the thing it is for. Unbounded is not
        offered - that is memory an attacker chooses the size of.
        """

    def __len__(self) -> int: ...


class TlsServer:
    """A TLS 1.2 and 1.3 server connection, sans-I/O.

    The mirror of ``TlsClient``: no socket, bytes in and bytes out.

    It exists for terminating proxies. A browser cannot be made to speak
    to a box that only offers something old - Chromium links BoringSSL
    statically, so nothing can be interposed - so the way there is a
    local proxy that terminates TLS on the browser's side and speaks the
    old thing on the other. This is the termination half.
    """

    def __init__(self, certificate_chain: Sequence[BytesLike],
                 key: Union["EcKey", "RsaKey", "EddsaKey", "MlDsaKey"],
                 ciphers: str = "modern",
                 min_version: str = "TLSv1.2",
                 max_version: str = "TLSv1.3",
                 now: int = 0,
                 session_tickets: int = 0,
                 ticket_key: Optional[BytesLike] = None,
                 allow_encrypt_then_mac: bool = True,
                 allow_extended_master_secret: bool = True,
                 request_client_certificate: bool = False,
                 require_client_certificate: bool = False,
                 client_roots: Optional["TrustStore"] = None,
                 max_early_data: int = 0,
                 replay_guard: Optional["ReplayGuard"] = None,
                 alpn: List[str] = [],
                 require_alpn: bool = False,
                 ocsp_response: Optional[BytesLike] = None) -> None:
        """A server presenting ``certificate_chain`` (leaf first, DER).

        ``key`` is an ``EcKey`` or an ``RsaKey``. At TLS 1.2 it decides
        which suites are reachable: an EC key can only authenticate
        ``ECDHE_ECDSA``, an RSA key does ``ECDHE_RSA`` and RSA key
        transport. A suite the key cannot authenticate is never chosen,
        so a client offering both gets the one that works rather than a
        handshake that fails at the signature.

        At TLS 1.3 a suite names no key exchange and no authentication,
        so all three work with either kind of key; what authenticates is
        the signature scheme. RSA signs with PSS there, because RFC 8446
        forbids PKCS#1 v1.5 in a CertificateVerify.

        ``session_tickets`` is how many TLS 1.3 tickets to issue after a
        handshake, and it defaults to **zero**. Tickets need ``now`` to
        expire against, and a server that does not know the time cannot
        expire one; issuing tickets it will honour forever is worse than
        issuing none.

        ``ticket_key`` is forty bytes - eight of key name, thirty-two of
        key - and is what makes resumption work at all: without it each
        connection generates its own, sealing tickets nothing else can
        open. Share one across every connection, and configure the same
        one on every instance if tickets should survive a restart.

        ``ciphers`` takes the same strings ``TlsClient`` does, **in the
        server's own order of preference**: the first suite in it that
        the client also offered is the one chosen. A server that should
        honour the client's order passes a different list. There is no
        flag for it, because "whose order decides" is a property of the
        list and a boolean beside it would be a second place to look.

        ``max_version`` defaults to ``"TLSv1.3"`` and ``min_version`` to
        ``"TLSv1.2"``. The floor is where it is because a server is
        usually the side that gets to insist; lowering it to
        ``"TLSv1.0"`` is how you stop insisting, and it should be a
        decision rather than a default.

        ``request_client_certificate`` asks the client to authenticate,
        at TLS 1.2 or 1.3. On its own that is *optional* client
        authentication: a client with nothing suitable answers with an
        empty certificate and the handshake goes on, so
        ``peer_certificates`` is the only thing that says whether one
        arrived. ``require_client_certificate`` refuses an empty answer.

        ``client_roots`` is what a client's chain is verified against,
        and it is deliberately a separate store from the one a client
        would use on a server: the CAs allowed to issue identities for
        a service are almost never the public web PKI, and reusing the
        system store here would let anything holding a certificate from
        any public CA authenticate. Left ``None``, the chain is not
        judged at all - the signature is still checked, so the client
        does hold the key, and recognising it is left to the caller.
        Setting it needs ``now``, since every certificate is outside
        its validity window at zero.

        ``max_early_data`` is how much 0-RTT data a ticket from this
        server allows, in bytes. Zero - the default - offers none, and
        the default is off because early data is not like the rest of
        the connection: it is **not forward secret**, and it is
        **replayable**, because it is sent before the server has said a
        word. Turning it on is a statement about the application, not
        about the transport: the first thing a client sends has to be
        something that may happen twice.

        ``replay_guard`` is required with it - see ``ReplayGuard``. It
        bounds how often a replay works and cannot make one impossible.

        ``alpn`` is the application protocols this server speaks, **in
        its own order of preference** (RFC 7301): the first in this list
        that the client also offered is chosen. Empty - the default -
        answers nothing, which is the safe default for a proxy, because
        answering ``h2`` would promise a protocol the thing behind it
        may not speak. The list is what the application can do, not what
        this code can parse.

        With nothing in common the handshake goes on without the
        extension. ``require_alpn`` makes it a ``no_application_protocol``
        alert instead, for an application that has no other way to tell
        which protocol it is speaking. It is ignored when the client
        offered no ALPN at all: a client that did not ask has not
        disagreed with anybody.

        ``ocsp_response`` is a cached OCSP response to staple, as DER
        (RFC 6066 §8). It goes out only if the client asks for one.
        **Nothing here fetches it**: a server that went to the responder
        during a handshake would add the responder's latency and
        availability to every connection, which is the problem stapling
        exists to solve. It is not checked here either - a server
        judging a statement about its own certificate is checking its
        own homework, and the client has to judge it regardless.
        """

    def push_incoming(self, data: BytesLike) -> None: ...
    def take_outgoing(self) -> bytes:
        """The bytes to send. Taken: a second call returns nothing."""
    def take_incoming(self) -> bytes:
        """Application data received so far."""
    def process(self) -> None:
        """Advance as far as the bytes allow. Raises with the reason on
        any protocol failure; the connection stays failed afterwards."""
    def write(self, data: BytesLike) -> None: ...
    def close(self) -> None:
        """Send close_notify."""

    def version(self) -> Optional[str]: ...
    def cipher(self) -> Optional[tuple]:
        """``(name, strength, key bits)`` once negotiated."""

    @property
    def state(self) -> str: ...
    @property
    def handshaking(self) -> bool: ...
    @property
    def established(self) -> bool: ...

    @property
    def server_name(self) -> Optional[str]:
        """The host the client asked for in SNI, or ``None``.

        The field a proxy is here for: it is the only thing in a TLS
        handshake that says which host the client thinks it is reaching,
        and it arrives before anything has to be decided - so a proxy
        reads it, issues a certificate for that name, and only then
        answers. A client connecting by IP address sends none, and
        ``None`` is an answer rather than a failure."""

    @property
    def offered_alpn(self) -> List[str]:
        """Every protocol the client offered, chosen or not."""

    def selected_alpn_protocol(self) -> Optional[str]:
        """The protocol chosen from ``alpn``, or ``None``.

        ``None`` means this server offers none, or the client offered
        none, or nothing was in common and ``require_alpn`` was off -
        the three look the same on the wire, and ``offered_alpn`` is
        what tells them apart."""

    @property
    def peer_certificates(self) -> List[bytes]:
        """The client's chain as DER, leaf first, or empty.

        Empty says nothing on its own: we may not have asked, or the
        client may have had nothing suitable. A non-empty chain says the
        client holds the key for the certificate it sent - that is what
        its signature over the transcript proves - and says nothing
        about whether the chain was trusted, which is
        ``client_certificate_verified``."""

    def take_early_data(self) -> bytes:
        """Take the early data (0-RTT) this connection accepted.

        **Deliberately not part of** ``take_incoming``. These bytes are
        not forward secret and may be a replay of a flight that already
        happened; read out of the same buffer as everything else there
        would be no way to tell which bytes those were, and the whole
        question of whether 0-RTT is safe is a question about exactly
        these bytes."""

    @property
    def accepted_early_data(self) -> bool:
        """Whether this connection accepted early data."""

    @property
    def client_certificate_verified(self) -> bool:
        """Whether that chain was checked against ``client_roots``.

        False with a non-empty ``peer_certificates`` is the legitimate
        shape where no roots were configured and the caller recognises
        the key itself."""

    @property
    def encrypt_then_mac(self) -> bool:
        """Whether RFC 7366 was agreed - which needs the client to have
        asked and a CBC suite to have been chosen."""
    @property
    def extended_master_secret(self) -> bool:
        """Whether RFC 7627 was agreed."""

def x25519_generate() -> Tuple[bytes, bytes]:
    """A fresh X25519 key pair (RFC 7748), as ``(private, public)``.

    The private key is stored clamped, so the bytes and the public key
    cannot disagree about which scalar this is."""

def x25519_public_key(private: BytesLike) -> bytes:
    """The public key for an X25519 private key. Clamps first, so an
    unclamped 32 bytes gives the key OpenSSL would give for them too."""

def x25519_exchange(private: BytesLike, peer: BytesLike) -> bytes:
    """The X25519 shared secret.

    Raises if the result is all zero, which means the peer sent a
    low-order point and the secret is a constant anybody can compute. RFC
    7748 makes that check optional; an optional check against an active
    attacker is not a check.

    There is nothing else to validate: every 32 byte string is a valid u
    coordinate, which is a property of the curve rather than an
    omission."""

def x25519_raw(scalar: BytesLike, point: BytesLike) -> bytes:
    """The RFC 7748 primitive, without the degenerate-output refusal.
    Here because the specification's test vectors are stated in these
    terms, and a test that cannot reach the primitive cannot use them."""

def x448_generate() -> Tuple[bytes, bytes]:
    """A fresh X448 key pair (RFC 7748), as ``(private, public)``.

    **Every value here is 56 bytes, not 32.** A 32 byte key handed to one
    of these raises rather than being padded, and the error says which
    algorithm wanted 56 — an X25519 key passed to an X448 function is the
    likeliest mistake at this boundary.

    The private key is stored clamped, so the bytes and the public key
    cannot disagree about which scalar this is. The clamping is not
    X25519's: two low bits cleared rather than three, because Curve448's
    cofactor is 4, and bit 447 set rather than bit 254."""

def x448_public_key(private: BytesLike) -> bytes:
    """The public key for an X448 private key: ``scalar * 5``.

    Five, where X25519's base point is nine. Clamps first, so an
    unclamped 56 bytes gives the key OpenSSL would give for them too."""

def x448_exchange(private: BytesLike, peer: BytesLike) -> bytes:
    """The X448 shared secret.

    Raises if the result is all zero, which means the peer sent a
    low-order point and the secret is a constant anybody can compute. RFC
    7748 makes that check optional; an optional check against an active
    attacker is not a check.

    There is nothing else to validate: every 56 byte string is a valid u
    coordinate. Unlike X25519 there is no spare high bit to ignore — the
    field is 448 bits in exactly 56 bytes — so a coordinate at or above
    the prime is reduced rather than refused, which is what every other
    implementation does."""

def x448_raw(scalar: BytesLike, point: BytesLike) -> bytes:
    """The RFC 7748 primitive, without the degenerate-output refusal.
    Here because the specification's test vectors are stated in these
    terms, and a test that cannot reach the primitive cannot use them."""

def random_bytes(n: int) -> bytes:
    """``n`` cryptographically strong random bytes.

    The same operating-system source every key, nonce and salt in this
    library is drawn from, so a caller does not need a second library to
    get one."""

def random_source() -> str:
    """The name of the system random source, for a caller that wants to
    record which one was used."""

def hardware_aes() -> bool:
    """Whether AES runs on the processor's AES instructions: the module was
    built with the `aes-ni` feature and this CPU has AES-NI and PCLMULQDQ.
    False means the portable implementation."""

def key_wrap(kek: BytesLike, data: BytesLike, cipher: str = "aes") -> bytes:
    """Wrap key data under a key-encryption key (RFC 3394).

    There is no IV and no nonce: the same key data under the same KEK
    always gives the same bytes. That is deliberate, because a wrapped
    key is stored, copied and compared, and a random IV would make two
    copies of one key look like two keys.

    What replaces the randomness is integrity: six passes mix every 64
    bit half into every other, and unwrapping ends with a check against
    a known constant, so a wrapping cannot be altered undetectably.

    ``data`` must be at least two 64 bit blocks. Use
    :func:`key_wrap_with_padding` for any other length; this refuses
    rather than padding silently.

    ``cipher`` is any 128 bit block cipher. AES is what every standard
    names; the rest work because the construction is generic."""

def key_unwrap(kek: BytesLike, data: BytesLike, cipher: str = "aes") -> bytes:
    """Unwrap key data (RFC 3394).

    Raises if the integrity check fails - which is the only thing
    between the caller and a key an attacker chose."""

def cms_3des_key_wrap(kek: BytesLike, cek: BytesLike, iv: Optional[BytesLike] = None) -> bytes:
    """RFC 3217's Triple-DES key wrap: SHA-1 checksum, CBC, reverse, CBC.
    A 24-byte key gives 40 bytes; ``iv`` is random unless given."""
def cms_3des_key_unwrap(kek: BytesLike, wrapped: BytesLike) -> bytes: ...
def cms_rc2_key_wrap(kek: BytesLike, effective_bits: int, cek: BytesLike,
                     pad: Optional[BytesLike] = None, iv: Optional[BytesLike] = None) -> bytes:
    """RFC 3217's RC2 key wrap, the key-encryption key at ``effective_bits``."""
def cms_rc2_key_unwrap(kek: BytesLike, effective_bits: int, wrapped: BytesLike) -> bytes: ...
def pwri_key_wrap(cipher: str, kek: BytesLike, iv: BytesLike, cek: BytesLike,
                  padding: Optional[BytesLike] = None) -> bytes:
    """RFC 3211's password recipient wrap: length, check bytes and key,
    padded to two blocks or more, CBC-encrypted twice."""
def pwri_key_unwrap(cipher: str, kek: BytesLike, iv: BytesLike, wrapped: BytesLike) -> bytes: ...
def key_wrap_with_padding(kek: BytesLike, data: BytesLike, cipher: str = "aes") -> bytes:
    """Wrap key data of any length from one byte up (RFC 5649).

    A *different* algorithm from :func:`key_wrap`, not an option on it:
    the constant carries the real length, and eight bytes or fewer skips
    the six passes entirely."""

def key_unwrap_with_padding(kek: BytesLike, data: BytesLike, cipher: str = "aes") -> bytes:
    """Unwrap key data wrapped with RFC 5649.

    The length field and the zero padding are part of the
    authentication, so a mismatch in either raises rather than being
    trimmed."""

def xts_encrypt(key: BytesLike, sector: int, data: BytesLike, cipher: str = "aes") -> bytes:
    """Encrypt one XTS data unit (IEEE 1619, NIST SP 800-38E).

    The disk encryption mode: a sector is encrypted under its own
    number, so the same plaintext in two sectors gives different
    ciphertext, and the ciphertext is exactly as long as the plaintext.

    ``key`` is two cipher keys end to end - 32 bytes for AES-128-XTS and
    64 for AES-256-XTS - and **the two halves must differ**, because
    equal halves collapse the tweak into the data cipher.

    ``data`` must be at least one 16 byte block; a shorter final block
    steals from the one before it, and with nothing to steal from there
    is no data unit. Longer lengths need no padding.

    **This is not authenticated and cannot be.** There is no room for a
    tag. Anyone who can write to the storage can replace any block with
    bytes of their choosing, and decryption will return plaintext rather
    than an error."""

def xts_decrypt(key: BytesLike, sector: int, data: BytesLike, cipher: str = "aes") -> bytes:
    """Decrypt one XTS data unit.

    There is no authentication: this returns plaintext for any input of
    a legal length, including one an attacker wrote."""

def lrw_encrypt(key: BytesLike, index: int, data: BytesLike, cipher: str = "aes") -> bytes:
    """Encrypt whole 16 byte blocks with LRW (IEEE P1619's draft disk
    mode, which dm-crypt and TrueCrypt 4 used before XTS).

    ``key`` is the cipher key followed by the 16 byte tweak key;
    ``index`` is the first block's index - a block number, not a sector
    number. Not authenticated."""

def lrw_decrypt(key: BytesLike, index: int, data: BytesLike, cipher: str = "aes") -> bytes:
    """Decrypt with LRW. There is no authentication."""

def eddsa_curves() -> List[str]:
    """The EdDSA curves this build can sign with: ``ed25519`` and
    ``ed448``.

    ``ed25519ctx``, ``ed25519ph`` and ``ed448ph`` are *not* here and are
    not accepted as aliases. They are different schemes over the same
    curves, and treating one as the pure variant would produce signatures
    that verify here and nowhere else."""

def eddsa_generate(name: str) -> Tuple[bytes, bytes]:
    """A fresh EdDSA key pair, as ``(private, public)``.

    Unlike X25519's, the private key is *not* stored clamped: clamping
    happens to the hash of these bytes, so clamping them here would change
    which key it is."""

def eddsa_public_key(name: str, private: BytesLike) -> bytes:
    """The public key for an EdDSA private key."""

def eddsa_sign(name: str, private: BytesLike, message: BytesLike,
               context: Optional[BytesLike] = None) -> bytes:
    """Sign a message with EdDSA (RFC 8032).

    Deterministic: there is no randomness anywhere in the scheme, so the
    same key and message always give the same signature. That is the
    design, not a limitation - ECDSA's requirement for a fresh random
    nonce per signature is what leaks the key when one is reused.

    ``context`` is Ed448's domain separator, at most 255 bytes. Ed25519
    has no context in its pure form and raises if given one."""

def eddsa_verify(name: str, public: BytesLike, message: BytesLike, signature: BytesLike,
                 context: Optional[BytesLike] = None) -> bool:
    """Verify an EdDSA signature.

    ``False`` for a well-formed signature that is wrong; raises for
    something that is not a signature at all - the wrong length, or a
    public key that does not decode to a point.

    An ``S`` that is not reduced modulo the group order is refused, which
    RFC 8032 section 5.1.7 requires: accepting it would give every message
    a second valid signature."""

def xeddsa_forms() -> List[str]:
    """The XEdDSA forms: ``signal``, libsignal's, which carries the
    Edwards key's sign bit in the top bit of ``S``, and ``xeddsa``, the
    specification's, which forces it to zero."""

def xeddsa_sign(form: str, private: BytesLike, message: BytesLike,
                random: Optional[BytesLike] = None) -> bytes:
    """Sign with an X25519 private key: Signal's identity-key signature.

    The key is clamped first, so it signs as the point its X25519 public
    key names. ``random`` is the 64 bytes mixed into the nonce and is
    drawn from the system when omitted; pass it only to reproduce a
    signature, as a test against libsignal does."""

def xeddsa_verify(form: str, public: BytesLike, message: BytesLike,
                  signature: BytesLike) -> bool:
    """Verify an XEdDSA signature against an X25519 public key.

    ``False`` for a 64 byte signature that does not verify; raises only
    for an unknown form or the wrong lengths. Like libsignal, an ``S``
    is accepted below 2^253 rather than below the group order, so
    ``S + L`` verifies wherever ``S`` does."""

def umac(key: BytesLike, nonce: BytesLike, data: BytesLike, tag_len: int = 8) -> bytes:
    """UMAC (RFC 4418). ``key`` is 16 bytes (AES-128); ``nonce`` is 1 to 16
    bytes and must never repeat under one key; ``tag_len`` is 4, 8, 12 or
    16. SSH's ``umac-64@openssh.com`` is ``tag_len=8`` with the packet
    sequence number as an 8 byte big-endian nonce."""

def hkdf(ikm: BytesLike, length: int, salt: Optional[BytesLike] = None,
         info: Optional[BytesLike] = None, digestmod: str = "sha256") -> bytes:
    """HKDF (RFC 5869). ``salt=None`` uses the all-zero salt from the RFC."""

def pbkdf2_hmac(hash_name: str, password: BytesLike, salt: BytesLike, iterations: int,
                dklen: Optional[int] = None) -> bytes:
    """PBKDF2 (RFC 8018), argument for argument the same as
    ``hashlib.pbkdf2_hmac``, so it is a drop-in for it. ``dklen=None``
    means the hash's own output length.

    No minimum iteration count is imposed: a file written in 2009 with
    1000 iterations still has to be readable. Use
    ``pbkdf2_recommended_iterations`` when writing something new."""

def shake(name: str, data: BytesLike, length: int) -> bytes:
    """Squeeze any number of bytes out of a SHAKE.

    ``name`` is ``"shake_128"`` or ``"shake_256"``. Anything else is an
    error rather than a truncation: SHAKE is the only thing here with an
    answer to "give me a thousand bytes", and pretending otherwise would
    hand back a silently weaker key.

    A longer request extends a shorter one, which is what makes it an
    extendable output function rather than a family of hashes."""

def scrypt(password: BytesLike, *, salt: BytesLike, n: int, r: int, p: int,
           dklen: int = 64) -> bytes:
    """scrypt (RFC 7914), with the same argument names as
    ``hashlib.scrypt``. ``n`` is a power of two greater than one.

    Memory used is ``128 * n * r`` bytes and it is held for the whole
    computation - that is the point of it. Unlike ``hashlib.scrypt``
    there is no ``maxmem``: the limit here is what the machine can
    allocate, and a request past it is an error rather than a refusal at
    an arbitrary ceiling."""

def argon2(password: BytesLike, salt: BytesLike, *, variant: str = "argon2id",
           memory_kib: int = 65536, passes: int = 3, lanes: int = 4,
           secret: Optional[BytesLike] = None,
           associated_data: Optional[BytesLike] = None,
           dklen: int = 32) -> bytes:
    """Argon2 (RFC 9106). All three variants.

    ``variant`` is ``"argon2id"`` (the default, and what RFC 9106
    section 4 recommends), ``"argon2i"`` or ``"argon2d"``. The other two
    are not deprecated: Argon2d has the best trade-off resistance and is
    right where nothing can observe the machine's memory, and Argon2i is
    right where the access pattern must leak nothing.

    ``secret`` is the RFC's ``K``, sometimes called a pepper: held by the
    application rather than stored with the hash, so a stolen database
    alone does not allow guessing. ``associated_data`` is the RFC's
    ``X``.

    Only version ``0x13`` (Argon2 1.3) is produced and understood.
    Version ``0x10`` exists in files written before 2016 and computes
    the reference index differently; it is refused rather than answered
    wrongly."""

def pbkdf2_recommended_iterations(hash_name: str) -> int:
    """Iterations to use for *new* work, as of 2026 (OWASP's figures).
    Never consulted when reading, where the count comes from the file.
    An unknown name gets the most conservative answer."""

def tls12_prf(secret: BytesLike, label: BytesLike, seed: BytesLike, length: int,
              digestmod: str = "sha256") -> bytes:
    """The TLS 1.2 PRF (RFC 5246 section 5)."""

def tls10_prf(secret: BytesLike, label: BytesLike, seed: BytesLike, length: int) -> bytes:
    """The TLS 1.0/1.1 PRF (RFC 2246 section 5); hashes fixed by the spec."""

def pad_pkcs7(data: BytesLike, block_size: int) -> bytes: ...
def unpad_pkcs7(data: BytesLike, block_size: int) -> bytes: ...

def kbkdf_counter(prf: str, key: BytesLike, length: int, label: Optional[BytesLike] = None,
                  context: Optional[BytesLike] = None) -> bytes:
    """SP 800-108 counter mode. ``prf`` is ``"hmac-<hash>"`` or
    ``"cmac-<block cipher>"``; the fixed data is label, a zero byte,
    context and the length in bits, after a 32-bit counter."""
def kbkdf_feedback(prf: str, key: BytesLike, length: int, iv: Optional[BytesLike] = None,
                   label: Optional[BytesLike] = None,
                   context: Optional[BytesLike] = None) -> bytes:
    """SP 800-108 feedback mode with a counter, from ``iv``."""
def concat_kdf(z: BytesLike, length: int, other_info: Optional[BytesLike] = None,
               hash: str = "sha256") -> bytes:
    """SP 800-56C's one-step KDF: Hash(counter || Z || OtherInfo)."""
def x963_kdf(z: BytesLike, length: int, shared_info: Optional[BytesLike] = None,
             hash: str = "sha256") -> bytes:
    """ANSI X9.63's KDF: Hash(Z || counter || SharedInfo)."""
def kerberos_nfold(data: BytesLike, length: int) -> bytes:
    """RFC 3961's n-fold, to ``length`` bytes."""
def kerberos_derive_random(cipher: str, key: BytesLike, constant: BytesLike,
                           length: int) -> bytes:
    """RFC 3961's DR."""
def kerberos_des_string_to_key(password: BytesLike, salt: BytesLike) -> bytes:
    """RFC 3961's DES string-to-key (mit_des_string_to_key)."""
def kerberos_random_to_key(cipher: str, data: BytesLike) -> bytes:
    """RFC 3961's random-to-key for ``"des"`` (7 bytes) or ``"3des"`` (21)."""
def openpgp_s2k(hash_name: str, passphrase: BytesLike, salt: BytesLike, count: int,
                length: int) -> bytes:
    """OpenPGP's string-to-key: ``count`` octets of salt || passphrase repeated."""
def openpgp_s2k_count(coded: int) -> int:
    """The octet count an iterated S2K's coded count byte stands for."""
def sevenzip_aes_key(password: BytesLike, salt: BytesLike, cycles: int) -> bytes:
    """7-Zip's AES key from a UTF-16LE password; cycles 0x3f is the raw key."""
def keepass_aes_kdf(key: BytesLike, seed: BytesLike, rounds: int) -> bytes:
    """KeePass's AES-KDF: AES-256-ECB ``rounds`` times under ``seed``, then SHA-256."""
def luks_af_split(key: BytesLike, stripes: int = 4000, hash: str = "sha256") -> bytes:
    """LUKS's anti-forensic splitter, random stripes from the OS."""
def luks_af_merge(material: BytesLike, key_len: int, stripes: int = 4000,
                  hash: str = "sha256") -> bytes:
    """LUKS's AF merge: the key from its stripes."""
def bitlocker_encrypt_sector(method: str, key: BytesLike, byte_offset: int,
                             sector: BytesLike) -> bytes:
    """One BitLocker sector: aes-cbc-elephant-128/256, aes-cbc-128/256, aes-xts-128/256."""
def bitlocker_decrypt_sector(method: str, key: BytesLike, byte_offset: int,
                             sector: BytesLike) -> bytes:
    """The inverse of ``bitlocker_encrypt_sector``."""
def nt_hash(password: str) -> bytes:
    """The NT hash (NTOWFv1): MD4 of the password as UTF-16 little endian."""
def lm_hash(password: BytesLike) -> bytes:
    """The LM hash (LMOWFv1) of a password given as bytes in the OEM code
    page it was made under, at most 14 of them. ASCII letters are
    uppercased; other bytes are the caller's to uppercase, because which
    byte is the uppercase of which depends on the code page."""
def bitlocker_password_key(password: str, salt: BytesLike) -> bytes:
    """The AES key a BitLocker password protector's salt and password give."""
def bitlocker_recovery_password_key(recovery: str, salt: BytesLike) -> bytes:
    """The AES key a BitLocker recovery password protector's salt and password give."""
def michael(key: BytesLike, data: BytesLike) -> bytes:
    """Michael, TKIP's message integrity code. The key is 8 bytes."""
def wep_encrypt(key: BytesLike, iv: BytesLike, plaintext: BytesLike) -> bytes:
    """WEP's RC4 encapsulation under the 3-byte IV and the shared key."""
def wep_decrypt(key: BytesLike, iv: BytesLike, ciphertext: BytesLike) -> bytes:
    """The inverse of ``wep_encrypt``; a wrong key or damage fails the ICV."""
def tkip_rc4_key(tk: BytesLike, ta: BytesLike, tsc: int) -> bytes:
    """TKIP's per-packet RC4 key from the temporal key, address and sequence counter."""
def wpa_psk(passphrase: BytesLike, ssid: BytesLike) -> bytes:
    """The WPA/WPA2 pre-shared key from a passphrase and the SSID."""
def wpa_ptk(akm: str, pmk: BytesLike, aa: BytesLike, spa: BytesLike, anonce: BytesLike,
            snonce: BytesLike, bits: int) -> bytes:
    """The pairwise transient key (akm "sha1" or "sha256"; bits 512 TKIP, 384 CCMP)."""
def wpa_pmkid(pmk: BytesLike, aa: BytesLike, spa: BytesLike) -> bytes:
    """The PMKID that names a cached pairwise master key."""
def cmac(cipher: str, key: BytesLike, data: BytesLike) -> bytes:
    """CMAC (SP 800-38B, RFC 4493) over any block cipher here."""
def cbc_mac(cipher: str, key: BytesLike, data: BytesLike, iv: Optional[BytesLike] = None,
            zero_pad: bool = False) -> bytes:
    """CBC-MAC (ISO/IEC 9797-1 algorithm 1). Forgeable over messages of
    varying length; ``zero_pad`` is padding method 1, and without it the
    data must be whole blocks."""

def office_xor_verifier(password: BytesLike) -> int:
    """The 16-bit verifier of an XOR obfuscation password, 1 to 15 bytes.
    Also the hash Excel stores for a protected sheet."""
def office_xor_decrypt(password: BytesLike, data: BytesLike, index: int = 0) -> bytes:
    """The binary Office formats' XOR obfuscation, method 1: XOR with the
    password's 16-byte array, then rotate right by five. ``index`` is the
    array index the first byte meets."""
def office_xor_encrypt(password: BytesLike, data: BytesLike, index: int = 0) -> bytes:
    """The inverse of ``office_xor_decrypt``."""


# --------------------------------------------------------- the OID registry ---
#
# Absent from this stub until now, which is its own small lesson: the
# functions existed, were documented in docs/python.md and tested, and a
# caller's type checker knew nothing about them.

def register_oid(oid: str, *, hash: Optional[str] = None,
                 curve: Optional[str] = None,
                 gost_sbox: Optional[Sequence[Sequence[int]]] = None,
                 curve_parameters: Optional[Dict[str, Any]] = None) -> None:
    """Give an object identifier a meaning, for this process.

    Exactly one keyword, because an OID names one thing:

    * ``hash=`` and ``curve=`` move a **name**: they say this OID means a
      hash or a curve the library already implements.
    * ``gost_sbox=`` and ``curve_parameters=`` supply the **cryptography**
      itself, because a GOST cipher is its S-box and a short Weierstrass
      curve is its parameters - both are distributed as parameter sets
      rather than as code.

    ``curve_parameters`` takes ``name``, ``p``, ``a``, ``b``, ``gx``,
    ``gy``, ``n`` and ``cofactor``; all of them, since a caller who does
    not know the cofactor does not know the curve. Each number is an
    ``int`` or a hex ``str`` (``0x``, whitespace and ``:`` are ignored, so
    a value copied out of a specification works). The parameters are
    checked - p prime, the curve non-singular, G on it, n its prime order,
    the cofactor within Hasse's bound, and the curve not anomalous - and
    refused if they are not a curve, because a merely plausible one still
    computes and still produces signatures.

    A registration is consulted **after** the compiled-in tables, so it
    cannot change what a standard OID means. Registering one twice
    replaces the older meaning.
    """

def registered_oids() -> List[Tuple[str, str, str]]:
    """Every registration, as ``(oid, kind, meaning)``.

    ``kind`` is ``"hash"``, ``"curve"``, ``"gost-param-set"`` or
    ``"curve-parameters"``.
    """

def forget_oid(oid: str) -> bool:
    """Undo one registration. Returns whether there was one."""

def curve_parameters(name: str) -> Dict[str, str]:
    """A curve's domain parameters, in the shape ``register_oid`` takes.

    The counterpart of ``gost_sbox``: the usual way to register a parameter
    set is to read one out and change what differs.

    ``name``, ``p``, ``a``, ``b``, ``gx``, ``gy``, ``n`` and ``cofactor``.
    **Every number is hex, big-endian**, without ``0x`` and padded to an
    even number of digits, so each is a whole number of bytes and
    ``bytes.fromhex`` takes it. Strings rather than ints because an integer
    has no byte order until something serialises it, and this is the
    boundary where that is easiest to get wrong.
    """

def gost_sbox(name: str) -> Tuple[Tuple[int, ...], ...]:
    """The eight substitution rows of a GOST parameter set, built in or
    registered - so a new one can start from one that exists."""

class SlhDsaKey:
    """An SLH-DSA key pair (FIPS 205), the hash-based signature scheme.

    Signatures are large - 7,856 bytes at the smallest parameter set and
    49,856 at the largest - and signing is slow. In exchange the scheme
    rests on nothing but a hash function.

    FIPS 205's **external** interface, which is the one another
    implementation's default verifier accepts. The internal interface is
    reachable from Rust only.
    """

    @staticmethod
    def generate(parameter_set: str) -> "SlhDsaKey":
        """A fresh key pair, seeded from the OS random source.

        Around a second at the ``s`` parameter sets, because a key is the
        root of a Merkle tree over 512 one-time keys and every leaf has to
        be computed. The ``f`` sets are milliseconds.
        """

    @staticmethod
    def from_private(parameter_set: str, private: BytesLike) -> "SlhDsaKey":
        """Import ``SK.seed || SK.prf || PK.seed || PK.root``.

        Only the length is checked: every byte string of the right length
        is a well formed private key. ``recompute_public`` is how to ask
        whether the public root inside it matches its seeds.
        """

    parameter_set: str

    def private_bytes(self) -> bytes:
        """``SK.seed || SK.prf || PK.seed || PK.root``."""

    def public_bytes(self) -> bytes:
        """``PK.seed || PK.root``, which is the tail of the private key."""

    def public_key(self) -> "SlhDsaPublicKey": ...

    def recompute_public(self) -> bool:
        """Whether the public root matches the seeds. Costs a whole key
        generation, so it is a question rather than something importing
        does for you."""

    def sign(self, message: BytesLike, context: Optional[BytesLike] = None,
             prehash: Optional[str] = None) -> bytes:
        """Sign, drawing fresh randomness - FIPS 205's hedged mode.

        ``context`` is a domain separator of at most 255 bytes; a longer
        one raises rather than being truncated. ``prehash`` names one of
        ``slh_dsa_pre_hashes()`` and signs a digest of the message instead
        of the message. **Both are part of what gets signed**, so a
        verifier has to be given the same two.
        """

    def sign_deterministic(self, message: BytesLike,
                           context: Optional[BytesLike] = None,
                           prehash: Optional[str] = None) -> bytes:
        """Sign reproducibly: the same message always gives the same bytes.

        Standard and safe. ``sign`` is the default because a caller who has
        not thought about randomness is better served by real randomness
        than by a counter or a timestamp.
        """

    def verify(self, message: BytesLike, signature: BytesLike,
               context: Optional[BytesLike] = None,
               prehash: Optional[str] = None) -> bool:
        """False for a wrong signature; raises only for an input that could
        never be one."""

class SlhDsaPublicKey:
    """The verifying half of an SLH-DSA key: ``PK.seed || PK.root``."""

    @staticmethod
    def from_public(parameter_set: str, public: BytesLike) -> "SlhDsaPublicKey": ...

    parameter_set: str

    def public_bytes(self) -> bytes: ...
    def verify(self, message: BytesLike, signature: BytesLike,
               context: Optional[BytesLike] = None,
               prehash: Optional[str] = None) -> bool: ...

def slh_dsa_parameter_sets() -> List[str]:
    """The twelve parameter sets, as FIPS 205 names them.

    ``s`` is small-signature and slow-signing, ``f`` the other way round -
    but for *key generation* the ``f`` sets are the cheap ones, because a
    key costs one tree and ``f`` trees are short.
    """

def slh_dsa_pre_hashes() -> List[str]:
    """The twelve approved pre-hash names, e.g. ``SHA2-512/224``."""

class MlKemKey:
    """An ML-KEM decapsulation key (FIPS 203): the half that recovers
    shared secrets.

    The decapsulation key **contains** the encapsulation key, so
    ``public_bytes()`` is a slice of ``private_bytes()``.
    """

    @staticmethod
    def generate(parameter_set: str) -> "MlKemKey":
        """A fresh key pair, seeded from the OS random source."""

    @staticmethod
    def from_seed(parameter_set: str, seed: BytesLike) -> "MlKemKey":
        """Rebuild a key pair from its 64 byte seed ``d || z``. The seed
        is as secret as the key, and much shorter."""

    @staticmethod
    def from_private(parameter_set: str, private: BytesLike) -> "MlKemKey":
        """Import ``dk_pke || ek || H(ek) || z``. Raises if the ``H(ek)``
        it carries does not match the ``ek`` it carries."""

    parameter_set: str

    def private_bytes(self) -> bytes:
        """``dk_pke || ek || H(ek) || z``."""

    def public_bytes(self) -> bytes:
        """``ek``, carried inside the decapsulation key."""

    def public_key(self) -> "MlKemPublicKey": ...

    def decapsulate(self, ciphertext: BytesLike) -> bytes:
        """The 32 byte shared secret.

        **Never raises for a ciphertext that was altered or made for
        another key** - that gives a different secret, and raising would
        be a decryption oracle. Raises only for a ciphertext of the wrong
        length.
        """

class MlKemPublicKey:
    """An ML-KEM encapsulation key: the half that makes shared secrets."""

    @staticmethod
    def from_public(parameter_set: str, public: BytesLike) -> "MlKemPublicKey":
        """Import ``ek``. Raises if a coefficient is encoded at or above
        q - FIPS 203's modulus check."""

    parameter_set: str

    def public_bytes(self) -> bytes: ...

    def encapsulate(self) -> Tuple[bytes, bytes]:
        """``(shared_secret, ciphertext)``: keep the first, send the
        second. Fresh randomness on every call."""

def ml_kem_parameter_sets() -> List[str]:
    """``ML-KEM-512``, ``ML-KEM-768`` and ``ML-KEM-1024``."""

class DsaKey:
    """A DSA key pair (FIPS 186-4), signing with RFC 6979 nonces.

    Numbers are big-endian bytes; signatures are DER ``Dss-Sig-Value``
    over the message hashed with ``hash``."""

    @staticmethod
    def generate(l: int = 2048, n: int = 256) -> "DsaKey":
        """A fresh ``l``/``n`` bit group and a key in it. Takes seconds."""

    @staticmethod
    def from_numbers(p: BytesLike, q: BytesLike, g: BytesLike, x: BytesLike) -> "DsaKey":
        """A key from its group and ``x``; the group's structure is checked."""

    def parameters(self) -> Tuple[bytes, bytes, bytes]:
        """``(p, q, g)``."""
    def private_bytes(self) -> bytes:
        """``x``. Key material."""
    def public_bytes(self) -> bytes:
        """``y``."""
    def sign(self, message: BytesLike, hash: str = "sha256") -> bytes: ...
    def verify(self, message: BytesLike, signature: BytesLike,
               hash: str = "sha256") -> bool: ...
    @property
    def key_size(self) -> int:
        """The bit length of ``p``."""

class MlDsaKey:
    """An ML-DSA key pair (FIPS 204), the lattice signature scheme, over
    the external interface.

    Signatures are 2,420 to 4,627 bytes - a fraction of SLH-DSA's - and
    signing and verifying take milliseconds.
    """

    @staticmethod
    def generate(parameter_set: str) -> "MlDsaKey":
        """A fresh key pair from a 32 byte seed drawn from the OS."""

    @staticmethod
    def from_seed(parameter_set: str, seed: BytesLike) -> "MlDsaKey":
        """Rebuild a key pair from its 32 byte seed. The seed is as secret
        as the key."""

    @staticmethod
    def from_private(parameter_set: str, private: BytesLike) -> "MlDsaKey":
        """Import an expanded private key. The public key is recomputed
        from it, and a key whose parts do not belong together raises."""

    parameter_set: str

    def seed(self) -> Optional[bytes]:
        """The 32 byte seed, or ``None`` for a key imported expanded."""

    def private_bytes(self) -> bytes: ...
    def public_bytes(self) -> bytes: ...
    def public_key(self) -> "MlDsaPublicKey": ...

    def sign(self, message: BytesLike, context: Optional[BytesLike] = None,
             prehash: Optional[str] = None) -> bytes:
        """Sign with fresh randomness - FIPS 204's hedged mode.

        ``context`` is at most 255 bytes; ``prehash`` names one of the
        twelve approved functions (the same names as
        ``slh_dsa_pre_hashes()``). Both are part of what gets signed.
        """

    def sign_deterministic(self, message: BytesLike,
                           context: Optional[BytesLike] = None,
                           prehash: Optional[str] = None) -> bytes:
        """Sign reproducibly: the same message always gives the same
        signature."""

    def verify(self, message: BytesLike, signature: BytesLike,
               context: Optional[BytesLike] = None,
               prehash: Optional[str] = None) -> bool: ...

class MlDsaPublicKey:
    """The verifying half of an ML-DSA key."""

    @staticmethod
    def from_public(parameter_set: str, public: BytesLike) -> "MlDsaPublicKey": ...

    parameter_set: str

    def public_bytes(self) -> bytes: ...

    def verify(self, message: BytesLike, signature: BytesLike,
               context: Optional[BytesLike] = None,
               prehash: Optional[str] = None) -> bool:
        """``False`` for a wrong signature, including a wrong length or a
        malformed hint; raises only for a context over 255 bytes or an
        unknown pre-hash name."""

def ml_dsa_parameter_sets() -> List[str]:
    """``ML-DSA-44``, ``ML-DSA-65`` and ``ML-DSA-87``."""

class SshKey:
    """An SSH private key: Ed25519, ECDSA (P-256/384/521) or RSA.

    Reads and writes OpenSSH's ``openssh-key-v1`` files, plain or
    encrypted, and signs as SSH does or as SSHSIG."""

    @staticmethod
    def generate(kind: str = "ed25519", bits: Optional[int] = None,
                 comment: str = "") -> "SshKey":
        """``"ed25519"``, ``"ecdsa"`` (``bits`` 256, 384, 521) or ``"rsa"``
        (``bits`` the modulus, default 3072), or a key type name."""
    @staticmethod
    def from_openssh(text: str, passphrase: Optional[BytesLike] = None) -> "SshKey":
        """Read an ``OPENSSH PRIVATE KEY`` file. Raises ``CryptoError`` for
        a wrong passphrase or a file whose two key halves disagree."""
    def to_openssh(self, passphrase: Optional[BytesLike] = None,
                   cipher: str = "aes256-ctr", rounds: int = 16) -> str:
        """The key as an ``openssh-key-v1`` file; encrypted when a
        passphrase is given."""
    comment: str
    def public_key(self) -> "SshPublicKey": ...
    def sign(self, data: BytesLike, algorithm: Optional[str] = None) -> bytes:
        """An SSH signature blob. For RSA, ``algorithm`` is
        ``"rsa-sha2-512"`` (default), ``"rsa-sha2-256"`` or ``"ssh-rsa"``."""
    def sshsig(self, message: BytesLike, namespace: str = "file",
               hash: str = "sha512") -> str:
        """``ssh-keygen -Y sign``: an armoured SSHSIG."""


class SshPublicKey:
    """An SSH public key, from a ``.pub`` / ``authorized_keys`` line or a blob."""

    @staticmethod
    def from_line(line: str) -> "SshPublicKey": ...
    @staticmethod
    def from_blob(blob: BytesLike) -> "SshPublicKey": ...
    @property
    def blob(self) -> bytes: ...
    @property
    def algorithm(self) -> str: ...
    @property
    def bits(self) -> int: ...
    @property
    def comment(self) -> str: ...
    @property
    def options(self) -> str:
        """The ``authorized_keys`` options field as written, or ``""``."""
    def fingerprint(self, hash: str = "sha256") -> str:
        """``SHA256:...`` or, with ``"md5"``, ``MD5:aa:bb:...``."""
    def to_line(self, comment: Optional[str] = None) -> str: ...
    def verify(self, data: BytesLike, signature: BytesLike) -> bool: ...


class SshClient:
    """An SSH client connection, sans-I/O. ``allcrypt_ssh.run`` drives it
    over a socket."""

    def __init__(self, user: str,
                 host_key: Union["SshPublicKey", str, None] = None,
                 keys: Sequence["SshKey"] = (), password: Optional[str] = None,
                 kex: Optional[List[str]] = None, ciphers: Optional[List[str]] = None,
                 macs: Optional[List[str]] = None,
                 host_key_algorithms: Optional[List[str]] = None) -> None:
        """``host_key`` is the key or fingerprint the server must present;
        ``None`` accepts any and leaves it in ``host_key`` to pin. The
        algorithm lists replace the defaults - naming a legacy algorithm
        is how to reach it."""
    def exec(self, command: str) -> None: ...
    def push_incoming(self, data: BytesLike) -> None: ...
    def process(self) -> None: ...
    def take_outgoing(self) -> bytes: ...
    def take_stdout(self) -> bytes: ...
    def take_stderr(self) -> bytes: ...
    def write(self, data: BytesLike) -> None: ...
    def send_eof(self) -> None: ...
    @property
    def exit_status(self) -> Optional[int]: ...
    @property
    def closed(self) -> bool: ...
    @property
    def authenticated(self) -> bool: ...
    @property
    def strict_kex(self) -> bool: ...
    @property
    def banner(self) -> str: ...
    @property
    def host_key(self) -> Optional["SshPublicKey"]: ...
    @property
    def server_version(self) -> str: ...
    def algorithms(self) -> Dict[str, Optional[str]]: ...


class SshServer:
    """An SSH server connection, sans-I/O. ``allcrypt_ssh.serve`` drives it
    over a socket; what a command does is the caller's."""

    def __init__(self, host_keys: Sequence["SshKey"],
                 authorized: Sequence[Tuple[str, Union["SshPublicKey", str]]] = (),
                 kex: Optional[List[str]] = None, ciphers: Optional[List[str]] = None,
                 macs: Optional[List[str]] = None,
                 host_key_algorithms: Optional[List[str]] = None,
                 banner: Optional[str] = None) -> None:
        """``authorized`` pairs a user with an ``SshPublicKey`` or a
        password. The algorithm lists replace the defaults."""
    def push_incoming(self, data: BytesLike) -> None: ...
    def process(self) -> None: ...
    def take_outgoing(self) -> bytes: ...
    def take_stdin(self) -> bytes: ...
    def write(self, data: BytesLike) -> None: ...
    def write_stderr(self, data: BytesLike) -> None: ...
    def finish(self, exit_status: int) -> None: ...
    def rekey(self) -> None: ...
    @property
    def request(self) -> Optional[Tuple[str, Optional[str]]]: ...
    @property
    def terminal(self) -> Optional[Tuple[str, int, int]]: ...
    @property
    def environment(self) -> List[Tuple[str, str]]: ...
    @property
    def stdin_closed(self) -> bool: ...
    @property
    def user(self) -> Optional[str]: ...
    @property
    def auth_method(self) -> Optional[str]: ...
    @property
    def closed(self) -> bool: ...
    @property
    def strict_kex(self) -> bool: ...
    @property
    def key_exchanges(self) -> int: ...
    @property
    def client_version(self) -> str: ...
    def algorithms(self) -> Dict[str, Optional[str]]: ...


def sshsig_verify(signature: str, message: BytesLike,
                  namespace: str = "file") -> SshPublicKey:
    """Verify an SSHSIG under ``namespace`` and return the key that made
    it. Trusting that key is the caller's decision."""

