"""Every byte-taking argument accepts any buffer, not only `bytes`.

Working with data means working with `bytearray` and `memoryview`, and
until this existed every call site had to write `bytes(buf)` - noise, and
a copy the caller could not see. `src/python.rs` has one `Bytes`
extractor and every byte parameter in the file uses it, so what is tested
here is that extractor and the claim that nothing escaped it.

Three separate claims, and they need three different kinds of test:

1. **Each spelling of the same bytes gives the same answer.** A table of
   calls across the whole surface, each run once per spelling. This is
   the part that would catch a parameter converted wrongly.

2. **A buffer that is not a byte string is refused rather than
   flattened.** `memoryview(b"abcdef")[::2]` is a view of every other
   byte; `PyBuffer_ToContiguous` will happily gather it into `b"ace"`,
   which is three bytes that appear nowhere in the caller's memory. The
   first version of the extractor did exactly that, and its comment
   claimed it did not - see `docs/pitfalls.md`.

3. **No byte parameter was left behind.** Claims 1 and 2 are properties
   of one function, so a parameter that still took `Vec<u8>` or `&[u8]`
   would pass both by never reaching it. That one is a scan of the
   source, because it is a claim about the source.

And one claim that cannot be tested from here, recorded so nobody looks
for the test: releasing the GIL while borrowing a `bytearray` is
undefined behaviour, and undefined behaviour has no assertion.
`test_a_bytearray_may_be_resized_while_it_is_being_hashed` is the
closest thing - it makes the race actually happen, so a borrowing
implementation crashes or returns nonsense rather than merely being
wrong in principle.
"""

import array
import hashlib
import pathlib
import re
import threading

import pytest

import allcrypt


ROOT = pathlib.Path(__file__).resolve().parent.parent


# --------------------------------------------------------------- spellings ---

def _mmap(data):
    """A buffer from outside the builtins, to show the rule is about the
    buffer protocol rather than about three blessed types."""
    import mmap
    m = mmap.mmap(-1, len(data)) if data else mmap.mmap(-1, 1)
    if data:
        m[:] = data
        return memoryview(m)
    return memoryview(m)[:0]


#: Ways of spelling the same bytes. `bytes` is the reference every other
#: form is compared against, so it is first and is not itself a case.
SPELLINGS = {
    "bytes": bytes,
    "bytearray": bytearray,
    "memoryview": lambda d: memoryview(bytes(d)),
    "memoryview_of_bytearray": lambda d: memoryview(bytearray(d)),
    "array_B": lambda d: array.array("B", d),
    "mmap": _mmap,
}
OTHER_SPELLINGS = [name for name in SPELLINGS if name != "bytes"]


# ------------------------------------------------------------- the surface ---
#
# Each entry is a callable taking the wrapper for this spelling and
# returning something comparable. Everything that varies between runs
# (a generated key, a random nonce) is fixed, so two runs of the same
# entry differ only in how the bytes were spelled.
#
# This is a sample of the surface rather than all 126 parameter
# positions: they share one extractor, so the hundredth adds nothing the
# tenth did not. What the sample is chosen for is *shape* - an optional
# argument, a list of buffers, a constructor, a streaming `update`, a
# keyword-only argument - because those are the places a conversion can
# go wrong in a way the extractor cannot.

KEY16 = bytes(range(16))
KEY32 = bytes(range(32))
IV16 = bytes(range(16, 32))
NONCE12 = bytes(range(12))
DATA = bytes(range(64))


def _ec_key():
    return allcrypt.EcKey.from_private("P-256", bytes([1] * 31 + [7]))


def _eddsa_key():
    return allcrypt.EddsaKey.from_private("ed25519", bytes(range(32)))


CALLS = {
    # hashes: a constructor with an optional argument, and a streaming
    # update, which are the two shapes every digest-like object has.
    "hash_constructor": lambda w: allcrypt.new("sha256", w(DATA)).digest(),
    "hash_named_constructor": lambda w: allcrypt.sha512(w(DATA)).digest(),
    "hash_update": lambda w: _fed(allcrypt.new("sha3-256"), w(DATA)),
    "shake": lambda w: allcrypt.shake("shake128", w(DATA), 47),

    # HMAC: key and message in one call, message optional.
    "hmac": lambda w: allcrypt.Hmac(w(KEY32), w(DATA), "sha256").digest(),
    "hmac_no_message": lambda w: _fed(
        allcrypt.Hmac(w(KEY32), digestmod="sha256"), w(DATA)),

    # block ciphers: key at construction, data and an optional IV per call.
    "cipher_ecb": lambda w: allcrypt.Cipher("aes", w(KEY16)).encrypt(
        "ecb", w(DATA)),
    "cipher_cbc": lambda w: allcrypt.Cipher("aes", w(KEY16)).encrypt(
        "cbc", w(DATA), iv=w(IV16)),
    "cipher_stream_update": lambda w: _stream(
        allcrypt.Cipher("aes", w(KEY16)).encryptor("ctr", iv=w(IV16)), w(DATA)),

    # AEADs: the optional associated data is the interesting one.
    "aead": lambda w: allcrypt.Aead(w(KEY32), "aes-gcm").encrypt(
        w(NONCE12), w(DATA)),
    "aead_with_ad": lambda w: allcrypt.Aead(w(KEY32), "aes-gcm").encrypt(
        w(NONCE12), w(DATA), w(b"header")),
    "aead_ccm8": lambda w: allcrypt.Aead(w(KEY16), "aes-ccm-8").encrypt(
        w(NONCE12), w(DATA)),

    # stream ciphers, including the one that takes no nonce.
    "stream_cipher": lambda w: allcrypt.StreamCipher(
        "chacha20", w(KEY32), w(NONCE12)).update(w(DATA)),
    "stream_cipher_no_nonce": lambda w: allcrypt.StreamCipher(
        "rc4", w(KEY16)).update(w(DATA)),
    "stream_cipher_encrypt": lambda w: allcrypt.StreamCipher(
        "zipcrypto", w(KEY16)).encrypt(w(DATA)),
    "stream_cipher_decrypt": lambda w: allcrypt.StreamCipher(
        "zipcrypto", w(KEY16)).decrypt(w(DATA)),

    # padding.
    "pad": lambda w: allcrypt.pad_pkcs7(w(DATA[:10]), 16),
    "unpad": lambda w: allcrypt.unpad_pkcs7(w(bytes(10) + bytes([6] * 6)), 16),

    # KDFs, including two with keyword-only arguments.
    "hkdf": lambda w: allcrypt.hkdf(w(KEY32), 42, salt=w(b"salt"),
                                    info=w(b"info")),
    "hkdf_no_salt": lambda w: allcrypt.hkdf(w(KEY32), 42),
    "pbkdf2": lambda w: allcrypt.pbkdf2_hmac("sha256", w(b"pw"), w(b"salt"),
                                             100, 32),
    "scrypt": lambda w: allcrypt.scrypt(w(b"pw"), salt=w(b"salt"), n=16, r=4,
                                        p=1, dklen=32),
    "argon2": lambda w: allcrypt.argon2(w(b"password"), w(bytes(16)),
                                        memory_kib=64, passes=1, lanes=1,
                                        dklen=32),
    # argon2's two keyword-only byte arguments, which are the only
    # `Option<Bytes>` reachable by keyword in the whole surface.
    "argon2_keyed": lambda w: allcrypt.argon2(
        w(b"password"), w(bytes(16)), memory_kib=64, passes=1, lanes=1,
        secret=w(b"pepper"), associated_data=w(b"ad"), dklen=32),
    "tls12_prf": lambda w: allcrypt.tls12_prf(w(KEY32), w(b"label"),
                                              w(b"seed"), 48),
    "tls10_prf": lambda w: allcrypt.tls10_prf(w(KEY32), w(b"label"),
                                              w(b"seed"), 48),

    # key wrapping and XTS, whose data lengths are constrained.
    "key_wrap": lambda w: allcrypt.key_wrap(w(KEY16), w(bytes(range(32)))),
    "key_wrap_padded": lambda w: allcrypt.key_wrap_with_padding(
        w(KEY16), w(b"seventeen bytes!!")),
    "xts": lambda w: allcrypt.xts_encrypt(w(KEY32), 7, w(DATA)),

    # elliptic curves: a private key from bytes, a signature over a
    # digest, an exchange, and the deterministic SM2 paths.
    "ec_from_private": lambda w: allcrypt.EcKey.from_private(
        "P-256", w(bytes([1] * 31 + [7]))).public_bytes(),
    "ec_verify": lambda w: _ec_key().verify(
        w(bytes(range(32))), w(_EC_SIGNATURE)),
    "ec_exchange": lambda w: _ec_key().exchange(w(_EC_PUBLIC)),
    "ec_public_key_from_bytes": lambda w: allcrypt.EcPublicKey(
        "P-256", w(_EC_PUBLIC)).public_bytes(),
    "sm2_verify": lambda w: _SM2_KEY.sm2_verify(
        w(b"message digest"), w(_SM2_SIGNATURE)),
    "sm2_verify_with_id": lambda w: _SM2_KEY.sm2_verify(
        w(b"message digest"), w(_SM2_SIGNATURE), w(b"1234567812345678")),

    # EdDSA: a deterministic signature, so the bytes are comparable.
    "eddsa_from_private": lambda w: allcrypt.EddsaKey.from_private(
        "ed25519", w(bytes(range(32)))).public_bytes(),
    "eddsa_sign": lambda w: _eddsa_key().sign(w(DATA)),
    "eddsa_verify": lambda w: _eddsa_key().verify(w(DATA), w(_ED_SIGNATURE)),
    "eddsa_sign_module": lambda w: allcrypt.eddsa_sign(
        "ed25519", w(bytes(range(32))), w(DATA)),

    # X25519, whose arguments are all fixed-width scalars and points.
    "x25519_public": lambda w: allcrypt.x25519_public_key(w(bytes(range(32)))),
    "x25519_exchange": lambda w: allcrypt.x25519_exchange(
        w(bytes(range(32))), w(_X25519_PEER)),
    "x25519_raw": lambda w: allcrypt.x25519_raw(w(bytes(range(32))),
                                                w(_X25519_PEER)),

    # RSA from primes, which is three separate byte arguments and the
    # only place `e` is optional.
    "rsa_from_primes": lambda w: allcrypt.RsaKey.from_primes(
        w(_RSA_P), w(_RSA_Q)).public_key().n,
    "rsa_from_primes_with_e": lambda w: allcrypt.RsaKey.from_primes(
        w(_RSA_P), w(_RSA_Q), w(b"\x01\x00\x01")).public_key().n,

    # X.509: the list-of-buffers shape, which is a different extractor
    # path (`Vec<Bytes>`) from every other entry here.
    "pem_wrap": lambda w: allcrypt.pem_wrap(w(_CERTIFICATE)),
    "crl_distribution_points": lambda w: allcrypt.crl_distribution_points(
        w(_CERTIFICATE)),
    "verify_chain_list": lambda w: _refusal(
        lambda: allcrypt.verify_chain([w(_CERTIFICATE)], [w(_CERTIFICATE)],
                                      now=0)),
    "private_key": lambda w: _refusal(
        lambda: allcrypt.private_key(w(b"not a key at all"), w(b"password"))),
}


def _fed(obj, data):
    obj.update(data)
    return obj.digest()


def _stream(encryptor, data):
    return encryptor.update(data) + encryptor.finalize()


def _refusal(call):
    """The result of a call expected to raise, as a comparable value.

    An error message is an answer too, and one that depends on the bytes
    - so a chain verification that fails identically for every spelling
    is as good evidence as one that succeeds, and it does not need a
    certificate that is valid today.
    """
    try:
        return ("ok", call())
    except Exception as exc:                                  # noqa: BLE001
        return (type(exc).__name__, str(exc))


# Fixtures the table above needs. Built once, from `bytes`, so that the
# table's own arguments are the only thing that varies.
_EC_SIGNATURE = allcrypt.EcKey.from_private(
    "P-256", bytes([1] * 31 + [7])).sign(bytes(range(32)))
_EC_PUBLIC = allcrypt.EcKey.from_private(
    "P-256", bytes([2] * 31 + [9])).public_bytes()
_SM2_KEY = allcrypt.EcKey.from_private("sm2p256v1", bytes([3] * 31 + [11]))
_SM2_SIGNATURE = _SM2_KEY.sm2_sign(b"message digest")
_ED_SIGNATURE = allcrypt.EddsaKey.from_private(
    "ed25519", bytes(range(32))).sign(DATA)
_X25519_PEER = allcrypt.x25519_public_key(bytes(range(32, 64)))
# Real primes, taken from a generated key rather than typed: `from_primes`
# inverts `e` mod `(p-1)(q-1)`, so invented values fail as "not coprime"
# and the test would be about the failure rather than about the bytes.
_RSA_NUMBERS = dict(allcrypt.RsaKey.generate(1024).numbers)
_RSA_P, _RSA_Q = _RSA_NUMBERS["p"], _RSA_NUMBERS["q"]

_CA = allcrypt.CertificateAuthority("Byte Input Test CA",
                                    "20200101000000Z", "20400101000000Z")
_CERTIFICATE = _CA.certificate


# --------------------------------------------- the same answer either way ---

@pytest.mark.parametrize("spelling", OTHER_SPELLINGS)
@pytest.mark.parametrize("call", sorted(CALLS), ids=sorted(CALLS))
def test_every_spelling_of_the_same_bytes_gives_the_same_answer(call, spelling):
    reference = CALLS[call](SPELLINGS["bytes"])
    assert CALLS[call](SPELLINGS[spelling]) == reference


def test_the_table_covers_the_surface():
    """A count, so that deleting entries to make a failure go away shows
    up as a failure of its own. The number is the sample, not the number
    of parameters - `test_no_byte_parameter_escaped_the_extractor` is
    what holds those."""
    assert len(CALLS) >= 40


@pytest.mark.parametrize("spelling", OTHER_SPELLINGS)
def test_a_wrapper_really_produces_that_type(spelling):
    """Without this, a wrapper that quietly returned `bytes` would make
    every case above pass while testing one spelling six times."""
    made = SPELLINGS[spelling](b"abcdef")
    assert not isinstance(made, bytes), spelling
    assert bytes(made) == b"abcdef"


# ------------------------------------------------- what must be refused ---

def test_a_strided_memoryview_is_refused_rather_than_flattened():
    """The bug this test was written for.

    `memoryview(b"abcdef")[::2]` is a view of `b"ace"` spread over six
    bytes. `PyBuffer_ToContiguous` gathers it, so an extractor that
    calls `to_vec` without checking contiguity hashes three bytes that
    are nowhere in the caller's memory - and reports nothing.
    """
    strided = memoryview(bytearray(b"abcdef"))[::2]
    assert not strided.c_contiguous

    # `BufferError`, and the same first clause `hashlib` uses, because a
    # caller who hits this searches for the message rather than reading
    # our source. `test_the_refusals_match_the_standard_library` holds
    # the two together.
    with pytest.raises(BufferError) as caught:
        allcrypt.new("sha256", strided)
    assert "not C-contiguous" in str(caught.value)

    # And specifically not the gathered answer, which is what a silent
    # flatten would have produced.
    assert allcrypt.new("sha256", b"ace").hexdigest() != _digest_or_none(strided)


def test_a_reversed_memoryview_is_refused():
    """Same shape, opposite stride - and the one where the gathered
    bytes are a permutation of the real ones, so a length check would
    not have noticed."""
    with pytest.raises(BufferError):
        allcrypt.new("sha256", memoryview(b"abcdef")[::-1])


def _digest_or_none(value):
    try:
        return allcrypt.new("sha256", value).hexdigest()
    except (BufferError, TypeError, ValueError):
        return None


def test_a_contiguous_multidimensional_buffer_is_accepted_as_its_memory():
    """The other side of the contiguity rule, asserted so that tightening
    it further is a deliberate change rather than a silent one.

    There is no gather here: the bytes are the buffer's memory in order,
    which is exactly what `bytes(x)` gives for it.
    """
    flat = b"abcdef"
    two_d = memoryview(flat).cast("B", (2, 3))
    assert two_d.c_contiguous
    assert bytes(two_d) == flat
    assert (allcrypt.new("sha256", two_d).hexdigest()
            == allcrypt.new("sha256", flat).hexdigest())


@pytest.mark.parametrize("value,note", [
    ("text", "a str is not bytes, and encoding it is the caller's choice"),
    (7, "an int is not a buffer"),
    ([1, 2, 3], "a list of ints was accepted before this existed"),
    (array.array("I", [1, 2, 3]), "four-byte items are not bytes"),
    (memoryview(b"abcd").cast("I"), "same, through a memoryview"),
])
def test_a_thing_that_is_not_bytes_is_a_type_error(value, note):
    """`TypeError`, not `ValueError`. The argument is of the wrong kind,
    which is what `hashlib` says for the same inputs - and `CryptoError`
    is a `ValueError`, so using one here would put a wrong type in the
    same basket as a wrong key length."""
    with pytest.raises(TypeError) as caught:
        allcrypt.new("sha256", value)
    assert str(caught.value), note


def test_none_is_refused_where_the_argument_is_not_optional():
    """`None` is two different things here and they must not be confused.

    Where the signature has a default it is the default - `data=None` on
    a hash constructor is how pyo3 spells "no data", and `hashlib`
    spells the same thing `string=b""`. That is a real difference from
    `hashlib`, which raises for an explicit `None`, and it is why `None`
    is not in `test_the_refusals_match_the_standard_library`. It is
    harmless where it applies, because no-data and empty-data are the
    same digest.

    Where the signature has no default, `None` is a `TypeError`, exactly
    as in `hashlib` - which is the case that matters, because a
    forgotten key must not arrive as a key of zero length.
    """
    assert (allcrypt.new("sha256", None).hexdigest()
            == allcrypt.new("sha256", b"").hexdigest())        # optional
    with pytest.raises(TypeError):
        allcrypt.Hmac(None, digestmod="sha256")                # required


def test_the_message_names_what_was_passed():
    """A message that says only "expected bytes" leaves the caller
    looking at the argument they thought was bytes. The type is in it."""
    with pytest.raises(TypeError) as caught:
        allcrypt.new("sha256", 7)
    assert "int" in str(caught.value)


def test_a_list_of_certificates_is_not_satisfied_by_one_certificate():
    """`Vec<Bytes>` over a `bytes` object would iterate it into ints, so
    passing a single certificate where a chain is wanted must raise
    rather than verify a chain of 700 one-byte certificates."""
    with pytest.raises(TypeError):
        allcrypt.verify_chain(_CERTIFICATE, [_CERTIFICATE], now=0)


def test_the_refusals_match_the_standard_library():
    """`hashlib` is the thing a caller is porting from, so the exception
    it raises for a given argument is the one they already handle.

    Written as a comparison rather than as a list of expected types, so
    that it is CPython's behaviour being asserted and not a transcription
    of it - and so a CPython that changed its mind would say so here.
    """
    for value in ["text", 7, [1, 2, 3],
                  memoryview(bytearray(b"abcdef"))[::2],
                  memoryview(b"abcdef")[::-1]]:
        theirs = _raised(lambda: hashlib.sha256(value))
        ours = _raised(lambda: allcrypt.new("sha256", value))
        assert ours is theirs, (value, ours, theirs)


def test_where_we_are_stricter_than_the_standard_library_and_why():
    """The one divergence, asserted so that it stays a decision.

    `hashlib` hashes the raw memory of an `array('I')`. We refuse it: a
    key or a nonce built that way depends on the byte order of the
    machine, and the code works until it is moved. `tobytes()` is the
    caller saying which bytes they meant, and it is not more typing than
    the `bytes()` they would have written before this existed.
    """
    ints = array.array("I", [1, 2, 3])
    assert hashlib.sha256(ints).digest()                     # accepted there
    with pytest.raises(TypeError):
        allcrypt.new("sha256", ints)                          # refused here

    # And the remedy named in the message does work.
    assert (allcrypt.new("sha256", ints.tobytes()).hexdigest()
            == hashlib.sha256(ints).hexdigest())


def _raised(call):
    try:
        call()
        return None
    except Exception as exc:                                  # noqa: BLE001
        return type(exc)


# --------------------------------------------------- nothing escaped it ---

#: `&[u8]` and `Vec<u8>` are fine away from the Python boundary. These
#: are the places they are expected, each one named so that a new one
#: has to be added here deliberately.
ALLOWED_SLICES = {
    "fn hex_lower(bytes: &[u8]) -> String {": "an internal helper",
    "    fn deref(&self) -> &[u8] {": "the `Bytes` deref itself",
    "/// `&[u8]`, which pyo3 extracts only from `bytes`. Working with data":
        "the `Bytes` doc comment, explaining why it is not this",
    "    fn as_ref(&self) -> &[u8] {": "the `AsRef` impl on `Bytes`",
}

#: Struct fields, which own their bytes and are not arguments.
ALLOWED_VEC_FIELDS = {
    "    key: Vec<u8>,",
    # **A substitution table is not a byte string.** `register_oid`'s
    # `gost_sbox=` takes eight rows of sixteen *nibbles*, and a caller
    # writing one out writes `[[9, 6, 3, ...], ...]` - a list of ints
    # is the natural form here and accepting it is the point, where
    # for an opaque byte parameter it is the bug. `Bytes` would refuse
    # the lists and the rows would have to be `bytes` objects, which
    # is the wrong shape for a table somebody is editing by hand.
    #
    # The strided-memoryview hazard `Bytes` exists for does not arise:
    # every row is checked to be a permutation of 0..16 before it is
    # stored, so a table read the wrong way round is refused rather
    # than silently becoming a different cipher.
    #
    # **The line moved when `curve_parameters=` was added** and
    # `gost_sbox` stopped being the last parameter, which
    # `test_the_allow_list_still_describes_the_file` caught. Worth saying
    # because that is the entry's whole purpose: an allow-list pinned to a
    # signature forces a look every time the signature changes, and the
    # look is where somebody decides whether the exemption still holds.
    # It does: the argument above is about nibbles, not about position.
    "                gost_sbox: Option<Vec<Vec<u8>>>,",
}


def _python_rs():
    return (ROOT / "src" / "python.rs").read_text(encoding="utf-8")


def test_no_byte_parameter_escaped_the_extractor():
    """The claim the other tests cannot make.

    Every test above goes through `Bytes`, so a parameter still typed
    `&[u8]` or `Vec<u8>` passes all of them by never being reached -
    and a `Vec<u8>` parameter accepts a list of ints and silently
    flattens a strided memoryview, which is the whole bug again in a
    place nobody looked.
    """
    offenders = []
    for line in _python_rs().split("\n"):
        if "&[u8]" in line and line not in ALLOWED_SLICES:
            offenders.append(line.strip())
        elif re.search(r":\s*(Option<)?Vec<(Vec<)?u8>", line) \
                and line not in ALLOWED_VEC_FIELDS:
            offenders.append(line.strip())
    assert not offenders, (
        "these look like byte parameters that do not use `Bytes`:\n  "
        + "\n  ".join(offenders))


def test_the_allow_list_still_describes_the_file():
    """An allow-list entry that no longer matches anything is a hole: the
    line it was excusing may have been renamed rather than fixed, and the
    scan above would say nothing either way."""
    source = _python_rs()
    for line in list(ALLOWED_SLICES) + list(ALLOWED_VEC_FIELDS):
        assert line in source, f"stale allow-list entry: {line!r}"


def test_the_extractor_is_used_widely_enough_to_be_the_rule():
    """A scan that passes because the file has three byte parameters
    would be no evidence at all. This is what says the file really is
    built on `Bytes`."""
    source = _python_rs()
    uses = len(re.findall(r":\s*(?:Option<)?(?:Vec<)?Bytes", source))
    assert uses > 100, uses


# ----------------------------------------------- the copy, under a race ---

def test_a_bytearray_may_be_resized_while_it_is_being_hashed():
    """The soundness property, made to actually happen.

    Every bulk function releases the GIL. A borrow into a `bytearray`
    held across that is undefined behaviour - another thread resizes it
    and the buffer moves - which is why `PyByteArray::as_bytes` is
    `unsafe` in pyo3 and why `Bytes` copies a mutable source.

    There is no assertion that catches undefined behaviour. What this
    does instead is run the race: one thread hashes a large `bytearray`
    while another repeatedly shrinks and regrows it, which reallocates.
    The copy is made under the GIL, so every digest must be of one of
    the two states the buffer is ever in. A borrowing implementation
    reads freed memory and produces a third answer, or crashes.
    """
    full = bytes(range(256)) * 4096          # 1 MiB, enough to be slow
    half = full[:len(full) // 2]
    buf = bytearray(full)
    expected = {allcrypt.new("sha256", full).hexdigest(),
                allcrypt.new("sha256", half).hexdigest()}

    seen, stop = [], threading.Event()

    def resize():
        tail = full[len(full) // 2:]
        while not stop.is_set():
            del buf[len(full) // 2:]
            buf.extend(tail)

    resizer = threading.Thread(target=resize, daemon=True)
    resizer.start()
    try:
        for _ in range(200):
            seen.append(allcrypt.new("sha256", buf).hexdigest())
    finally:
        stop.set()
        resizer.join(timeout=5)

    unexpected = [digest for digest in seen if digest not in expected]
    assert not unexpected, (
        f"{len(unexpected)} of {len(seen)} digests were of neither state "
        "the buffer is ever in, so the bytes were read after they moved")


def test_the_race_test_would_notice_a_third_state():
    """The test above is only evidence if its `expected` set is small.
    If the resizing thread produced many distinct contents, "the digest
    was one of the expected ones" would be a weak claim - so the two
    states are asserted to be the only two."""
    full = bytes(range(256)) * 16
    half = full[:len(full) // 2]
    assert half != full
    assert (allcrypt.new("sha256", half).hexdigest()
            != allcrypt.new("sha256", full).hexdigest())


def test_mutating_a_bytearray_after_the_call_does_not_change_the_result():
    """The ordinary, visible half of the same property."""
    buf = bytearray(b"abcdef")
    digest = allcrypt.new("sha256", buf)
    buf[0] = ord("z")
    assert digest.hexdigest() == allcrypt.new("sha256", b"abcdef").hexdigest()
