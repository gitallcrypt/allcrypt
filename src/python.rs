/*
Python bindings.

This file is pure translation: Python types in, `api` calls, Python types
out. It deliberately contains no cryptographic logic, so everything it
exposes is already covered by the Rust test suite via `tests/test_api.rs`.

Built with cargo; the crate is a `cdylib`, so no other tool is needed:

    python3 scripts/build_python.py             # release, into python/
    python3 scripts/build_python.py --install   # and into site-packages

That script is `cargo build --features python` plus a rename - Python
imports by file name and cargo's is not the one it looks for
(`liballcrypt.so`, or `allcrypt.dll` on Windows where it must be `.pyd`).

maturin does the same thing and builds wheels besides, which is what
`pyproject.toml` is for. It is not needed to import the module locally,
and one fewer tool to install is one fewer reason for somebody to not run
the tests.

Written against pyo3 0.23 (built and tested against 0.23.5). If you move to
a newer pyo3 the only things likely to need a touch are the `Bound`
constructors (`PyBytes::new`) and `get_type`, both of which have been renamed
before.

The bulk operations release the GIL, so hashing and bulk encryption scale
across threads. `update_into` is the deliberate exception - see the comment
on it.
*/

use pyo3::create_exception;
use pyo3::exceptions::{PyBufferError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::buffer::PyBuffer;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyByteArray, PyBytes, PyDict, PyList, PyString, PyTuple};

use crate::api::{self, AnyBlockCipher, AnyHash, AnyStreamCipher, CipherStream, Mode};
use crate::block_ciphers::BlockCipher;
use crate::hash_functions::HashFunction;
use crate::block_ciphers::gost as allcrypt_gost;
use crate::mac::Hmac as RsHmac;
use crate::registry;
use crate::Mac;

create_exception!(allcrypt, CryptoError, PyValueError,
                  "Raised for any bad key, IV, mode, length or algorithm name.");

fn err(e: String) -> PyErr {
    CryptoError::new_err(e)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ------------------------------------------------------------ byte inputs ---

/// Any Python object holding bytes: `bytes`, `bytearray`, `memoryview`,
/// `array('B')`, a NumPy `uint8` array - anything with the buffer
/// protocol.
///
/// **Every byte-taking parameter in this file uses this**, rather than
/// `&[u8]`, which pyo3 extracts only from `bytes`. Working with data
/// means working with mutable buffers, and making a caller write
/// `bytes(buffer)` at each call is both noise and a copy they cannot
/// see.
///
/// ## `bytes` is borrowed and everything else is copied, and that is
/// not an optimisation - it is the only sound arrangement
///
/// Almost every function here calls `py.allow_threads`, which releases
/// the GIL for the duration of the work. **A borrow into a `bytearray`
/// held across that is undefined behaviour**: another Python thread can
/// resize it, and the buffer moves out from under the Rust slice. That
/// is why `PyByteArray::as_bytes` is an `unsafe` function in pyo3.
///
/// So a mutable source is copied before the GIL is released, and an
/// immutable `bytes` is borrowed. `PyBackedBytes` already draws exactly
/// that line - `Py<PyBytes>` plus a pointer for one, `Arc<[u8]>` for
/// the other - which is why it is used rather than something written
/// here.
///
/// **The `PyBackedBytes` branch is an optimisation and nothing rests on
/// it.** A `bytearray` reaching the buffer path below is copied there
/// too, so deleting the branch entirely leaves every answer identical
/// and only makes `bytes` slower. A breakage sweep therefore cannot see
/// it - removing it passed all 255 tests in
/// `pytests/test_byte_inputs.py` - and that is the right result rather
/// than a hole: what must be tested is that nothing mutable is
/// *borrowed*, and that holds on both paths.
///
/// The copy is not a new cost: a caller who wrote `bytes(buffer)` paid
/// it too, and paid an allocation in Python on top.
///
/// `Encryptor::update_into` is the other half of the same argument seen
/// from the other side: it takes a `&Bound<PyByteArray>` and writes into
/// it, and so it must *not* release the GIL. Borrowing a `bytearray` and
/// releasing the GIL are the two things that cannot both happen, and
/// every function here does exactly one of them.
///
/// ## What this does not do
///
/// It does not give a caller a way to avoid the copy for a mutable
/// buffer. There is no safe way to offer one: any API that borrowed a
/// `bytearray` across `allow_threads` would be unsound however it was
/// spelled. `update_into` avoids the copy by keeping the GIL instead,
/// which is the trade actually available.
pub enum Bytes {
    /// From `bytes` (borrowed) or `bytearray` (copied by pyo3).
    Backed(PyBackedBytes),
    /// From the buffer protocol, always copied.
    Copied(Vec<u8>),
}

impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Backed(backed) => backed,
            Bytes::Copied(owned) => owned,
        }
    }
}

/// So a `Vec<Bytes>` - a certificate chain, a list of CRLs - can be
/// handed to `api` functions taking `&[impl AsRef<[u8]>]` without being
/// rebuilt as a `Vec<Vec<u8>>` first.
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Bytes {
    /// For a `#[pyo3(signature = ..)]` default. It is not `Default`,
    /// because a byte *input* that defaulted to nothing would let a
    /// missing argument look like an empty one at every call site rather
    /// than only where the signature says so.
    pub fn empty() -> Self {
        Bytes::Copied(Vec::new())
    }
}

/// The copy for the places that genuinely need one: an `api` config
/// struct that *owns* its bytes, because it outlives the call that built
/// it. Everything else takes a slice and needs none, so reaching for
/// this is a decision rather than a default - see `verify_chain`, which
/// copies its CRLs and does not copy its chain.
fn owned(list: Vec<Bytes>) -> Vec<Vec<u8>> {
    list.iter().map(|item| item.to_vec()).collect()
}

impl FromPyObject<'_> for Bytes {
    fn extract_bound(object: &Bound<'_, PyAny>) -> PyResult<Self> {
        // `bytes` and `bytearray` first: the common cases, and the only
        // one that avoids a copy is in here.
        if let Ok(backed) = object.extract::<PyBackedBytes>() {
            return Ok(Bytes::Backed(backed));
        }
        // Then anything else exposing bytes. `PyBuffer::<u8>::get`
        // settles the element type - it refuses a buffer whose items are
        // not single bytes - but it says nothing about the layout, and
        // **`to_vec` gathers**: `PyBuffer_ToContiguous` walks the strides
        // and writes the elements out packed, so a strided memoryview
        // would arrive as a shorter byte string that is nowhere in the
        // caller's memory. That is not a conversion this extractor may
        // make silently. `memoryview(buf)[::2]` is a view of every other
        // byte, and a caller who means those bytes writes `bytes(view)`,
        // where the gather is visible and is their decision.
        //
        // So contiguity is checked here, and only then is the copy made.
        // A *contiguous* buffer of more than one dimension is accepted
        // and read in memory order, which is exactly what `bytes(x)`
        // gives for it - there is no gather, so nothing is being decided
        // on the caller's behalf.
        if let Ok(buffer) = PyBuffer::<u8>::get(object) {
            if !buffer.is_c_contiguous() {
                // `BufferError`, and wording close to CPython's, because
                // that is what `hashlib.sha256(view[::2])` raises and
                // what a caller who hits this will search for.
                return Err(PyBufferError::new_err(format!(
                    "{}: underlying buffer is not C-contiguous. Pass \
                     bytes(x) if you mean the bytes it selects - the copy \
                     and the reordering are then yours rather than ours.",
                    object.get_type().name()?)));
            }
            if let Ok(copied) = buffer.to_vec(object.py()) {
                return Ok(Bytes::Copied(copied));
            }
        }
        // A buffer of multi-byte items lands here, and this is a
        // **deliberate difference from `hashlib`**, which accepts
        // `array('I')` and hashes the machine's bytes for it. A hash of
        // arbitrary memory can afford that; a key, a nonce or a scalar
        // cannot, because the value would then depend on the byte order
        // of the machine it ran on and the mistake shows up only when
        // somebody moves the code. `x.tobytes()` says which bytes were
        // meant.
        //
        // `TypeError` rather than `ValueError`: the argument is of the
        // wrong kind, not of the wrong value, and that is the exception
        // `hashlib` raises for it. `CryptoError` stays a `ValueError`
        // and is for bad key lengths and unknown algorithm names.
        Err(PyTypeError::new_err(format!(
            "expected bytes, bytearray, memoryview or another contiguous \
             buffer of single bytes, not {}",
            object.get_type().name()?)))
    }
}

// ----------------------------------------------------------------- hashes ---

/// A hash in progress. Shaped like `hashlib`: `update`, `digest`,
/// `hexdigest`, `copy`, `digest_size`, `block_size`, `name`.
#[pyclass(module = "allcrypt")]
pub struct Hash {
    inner: AnyHash,
}

impl Hash {
    fn build(py: Python<'_>, name: &str, data: Option<Bytes>) -> PyResult<Self> {
        let mut inner = AnyHash::new(name).map_err(err)?;
        if let Some(d) = data {
            // Same GIL release as `update`: the constructors take the whole
            // message, so this is where the bulk of the work usually happens.
            py.allow_threads(|| inner.update(&d));
        }
        Ok(Hash { inner })
    }
}

#[pymethods]
impl Hash {
    #[new]
    #[pyo3(signature = (name, data = None))]
    fn py_new(py: Python<'_>, name: &str, data: Option<Bytes>) -> PyResult<Self> {
        Hash::build(py, name, data)
    }

    fn update(&mut self, py: Python<'_>, data: Bytes) {
        // Release the GIL for the hashing itself. `data` is either an
        // immutable `bytes` kept alive by this `Bytes` or a copy this
        // `Bytes` owns, so nothing it points at can move or change while
        // we are not holding the GIL - see the `Bytes` doc comment,
        // which is where that guarantee is made for every function here.
        py.allow_threads(|| self.inner.update(&data));
    }

    fn digest<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.digest())
    }

    fn hexdigest(&mut self) -> String {
        hex_lower(&self.inner.digest())
    }

    /// A fork of this hash's state, as `hashlib` objects provide.
    fn copy(&self) -> Hash {
        Hash { inner: self.inner.clone() }
    }

    #[getter]
    fn digest_size(&self) -> usize {
        self.inner.digest_len()
    }

    #[getter]
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.name().to_lowercase()
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.Hash '{}'>", self.inner.name().to_lowercase())
    }
}


/// `allcrypt.new("sha256", b"data")`, mirroring `hashlib.new`.
#[pyfunction]
#[pyo3(name = "new", signature = (name, data = None))]
fn hash_new(py: Python<'_>, name: &str, data: Option<Bytes>) -> PyResult<Hash> {
    Hash::build(py, name, data)
}

macro_rules! hash_constructor {
    ($fn_name:ident, $algo:literal) => {
        #[pyfunction]
        #[pyo3(signature = (data = None))]
        fn $fn_name(py: Python<'_>, data: Option<Bytes>) -> PyResult<Hash> {
            Hash::build(py, $algo, data)
        }
    };
}

hash_constructor!(md5, "md5");
hash_constructor!(sha0, "sha0");
hash_constructor!(sha1, "sha1");
hash_constructor!(sha224, "sha224");
hash_constructor!(sha256, "sha256");
hash_constructor!(sha384, "sha384");
hash_constructor!(sha512, "sha512");
hash_constructor!(sha512_224, "sha512_224");
hash_constructor!(sha512_256, "sha512_256");

// --------------------------------------------------------- cipher streams ---

/// One encryption or decryption in progress, shaped like the encryptor and
/// decryptor objects in `cryptography`.
#[pyclass(module = "allcrypt")]
pub struct Encryptor {
    inner: CipherStream,
}

#[pymethods]
impl Encryptor {
    /// Transform the next piece of input. For ECB and CBC the result may be
    /// shorter than the input, because whole blocks are buffered.
    fn update<'py>(&mut self, py: Python<'py>, data: Bytes) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.update(&data)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Transform a `bytearray` in place, with no copying. Only CTR, OFB and
    /// CFB can do this; ECB and CBC raise, because they need whole blocks.
    fn update_into(&mut self, buf: &Bound<'_, PyByteArray>) -> PyResult<()> {
        // SAFETY: the GIL is held for the whole call and nothing here calls
        // back into Python, so the bytearray cannot be resized or freed while
        // the slice is alive. This is also why this method, unlike the others,
        // must NOT release the GIL: another thread could resize the bytearray
        // out from under the slice.
        let slice = unsafe { buf.as_bytes_mut() };
        self.inner.update_into(slice).map_err(err)
    }

    /// End the stream. Raises if a partial block was left dangling.
    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let out = self.inner.finish().map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[getter]
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    #[getter]
    fn mode(&self) -> &'static str {
        self.inner.mode().name()
    }

    #[getter]
    fn algorithm(&self) -> &'static str {
        self.inner.cipher_name()
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.Encryptor {} {}>", self.inner.cipher_name(), self.inner.mode().name())
    }
}

// ------------------------------------------------------------------ AEAD ---

/// One authenticated encryption in progress.
#[pyclass(module = "allcrypt")]
pub struct AeadEncryptor {
    inner: api::AeadStream,
}

#[pymethods]
impl AeadEncryptor {
    fn update<'py>(&mut self, py: Python<'py>, data: Bytes)
                   -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| -> Result<Vec<u8>, String> {
            let mut out = Vec::with_capacity(data.len());
            self.inner.update(&data, &mut out)?;
            Ok(out)
        }).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Finish an encryption and return the 16 byte tag.
    fn tag<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let tag = self.inner.tag().map_err(err)?;
        Ok(PyBytes::new(py, &tag))
    }

    /// Finish a decryption by checking the tag. Until this returns, nothing
    /// `update` produced has been authenticated.
    fn verify(&mut self, py: Python<'_>, tag: Bytes) -> PyResult<()> {
        py.allow_threads(|| self.inner.verify(&tag)).map_err(err)
    }

    fn __repr__(&self) -> String {
        "<allcrypt.AeadEncryptor aes-gcm>".to_string()
    }
}

/// CCM cannot stream: its MAC starts with the message's length, so nothing
/// can be processed before all of it has arrived. Rather than offer an
/// `update` that silently buffers - an interface promising constant memory
/// and not delivering it - the streaming constructors refuse.
///
/// `cryptography` draws the same line: its `AESCCM` has `encrypt` and
/// `decrypt` and no streaming pair at all.
fn refuse_if_it_cannot_stream(stream: &api::AeadStream) -> PyResult<()> {
    if stream.buffers_everything() {
        return Err(err("CCM cannot be streamed: its authentication starts \
                        with the message's length, so nothing can be \
                        processed until all of it is here. Use encrypt() or \
                        decrypt(), which take the whole message.".to_string()));
    }
    Ok(())
}

/// An authenticated cipher, shaped like `AESGCM` in `cryptography`.
///
/// `encrypt` returns the ciphertext with the tag appended, and `decrypt`
/// expects the same - the convention the Python ecosystem uses, so code
/// written against `cryptography` moves across unchanged.
#[pyclass(module = "allcrypt")]
pub struct Aead {
    name: String,
    key: Vec<u8>,
}

#[pymethods]
impl Aead {
    #[new]
    #[pyo3(signature = (key, name = "aes-gcm"))]
    fn py_new(key: Bytes, name: &str) -> PyResult<Self> {
        // Build one and throw it away, so a bad key or an unknown name is
        // an error here rather than at the first encryption.
        // The key is checked by building a stream; `aead_tag_len` knows
        // which placeholder nonce each AEAD takes.
        api::aead_tag_len(name, &key).map_err(err)?;
        Ok(Aead { name: name.to_ascii_lowercase(), key: key.to_vec() })
    }

    /// Encrypt and authenticate. Returns ciphertext || tag.
    ///
    /// The nonce must never repeat under one key. Two messages sharing one
    /// give away their XOR and the authentication key.
    #[pyo3(signature = (nonce, data, associated_data = None))]
    fn encrypt<'py>(&self, py: Python<'py>, nonce: Bytes, data: Bytes,
                    associated_data: Option<Bytes>) -> PyResult<Bound<'py, PyBytes>> {
        let aad = associated_data.as_deref().unwrap_or(&[]);
        let out = py.allow_threads(|| -> Result<Vec<u8>, String> {
            let (mut ciphertext, tag) =
                api::aead_encrypt(&self.name, &self.key, &nonce, aad, &data)?;
            ciphertext.extend_from_slice(&tag);
            Ok(ciphertext)
        }).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Verify and decrypt. `data` is ciphertext || tag.
    ///
    /// Raises on any failure and returns nothing at all - there is no
    /// partial result, because unverified plaintext is not a result.
    #[pyo3(signature = (nonce, data, associated_data = None))]
    fn decrypt<'py>(&self, py: Python<'py>, nonce: Bytes, data: Bytes,
                    associated_data: Option<Bytes>) -> PyResult<Bound<'py, PyBytes>> {
        let aad = associated_data.as_deref().unwrap_or(&[]);
        // **Asked, not assumed.** This split was hard-coded at sixteen
        // bytes, which was true of GCM and ChaCha20-Poly1305 and false
        // for `aes-ccm-8` - whose whole reason for existing is the
        // shorter tag - and for EAX over any 64 bit block cipher. The
        // symptom was not a length error but "the tag does not match",
        // which tells a caller their data was altered when the library
        // had simply cut it in the wrong place.
        let tag_len = api::aead_tag_len(&self.name, &self.key).map_err(err)?;
        if data.len() < tag_len {
            return Err(err(format!(
                "Too short to hold a {} byte tag: {} bytes.", tag_len, data.len())));
        }
        let (ciphertext, tag) = data.split_at(data.len() - tag_len);
        let out = py.allow_threads(|| {
            api::aead_decrypt(&self.name, &self.key, &nonce, aad, ciphertext, tag)
        }).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// A streaming encryption, for data too large to hold twice.
    #[pyo3(signature = (nonce, associated_data = None))]
    fn encryptor(&self, nonce: Bytes, associated_data: Option<Bytes>)
                 -> PyResult<AeadEncryptor> {
        let inner = api::AeadStream::new(&self.name, &self.key, &nonce,
                                         associated_data.as_deref().unwrap_or(&[]), false)
            .map_err(err)?;
        refuse_if_it_cannot_stream(&inner)?;
        Ok(AeadEncryptor { inner })
    }

    /// A streaming decryption. Nothing it returns is trustworthy until
    /// `verify` has been called and has not raised.
    #[pyo3(signature = (nonce, associated_data = None))]
    fn decryptor(&self, nonce: Bytes, associated_data: Option<Bytes>)
                 -> PyResult<AeadEncryptor> {
        let inner = api::AeadStream::new(&self.name, &self.key, &nonce,
                                         associated_data.as_deref().unwrap_or(&[]), true)
            .map_err(err)?;
        refuse_if_it_cannot_stream(&inner)?;
        Ok(AeadEncryptor { inner })
    }

    #[getter]
    fn name(&self) -> String { self.name.clone() }

    /// The tag this AEAD produces, in bytes.
    ///
    /// 16 for most, 8 for the CCM_8 variant - which exists for exactly
    /// that reason - and 8 for EAX over a 64 bit block cipher, whose
    /// tag is one block.
    ///
    /// This used to be `if name ends with "-8" { 8 } else { 16 }` - a
    /// second copy of a fact the API already knew, written from the
    /// catalogue as it stood. It was right until EAX arrived over a 64
    /// bit block cipher. Asked of the API now, so there is one place
    /// that decides and `decrypt` splits where this says.
    #[getter]
    fn tag_size(&self) -> PyResult<usize> {
        api::aead_tag_len(&self.name, &self.key).map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.Aead {} {} bit key>", self.name, self.key.len() * 8)
    }
}

/// A keyed block cipher. Spawns encryptors and decryptors; holds no mode
/// state itself, so one `Cipher` can drive as many streams as you like.
#[pyclass(module = "allcrypt")]
pub struct Cipher {
    name: String,
    key: Vec<u8>,
    param: Option<String>,
    block_size: usize,
}

impl Cipher {
    fn stream(&self, mode: &str, iv: Option<Bytes>, decrypting: bool) -> PyResult<Encryptor> {
        let cipher = AnyBlockCipher::new(&self.name, &self.key, self.param.as_deref())
            .map_err(err)?;
        let mode = Mode::from_name(mode).map_err(err)?;
        let inner = CipherStream::new(cipher, mode, iv.as_deref().unwrap_or(&[]), decrypting)
            .map_err(err)?;
        Ok(Encryptor { inner })
    }
}

#[pymethods]
impl Cipher {
    /// `param` selects the S-box parameter set for GOST and is ignored by the
    /// other ciphers.
    #[new]
    #[pyo3(signature = (name, key, param = None))]
    fn py_new(name: &str, key: Bytes, param: Option<String>) -> PyResult<Self> {
        let probe = AnyBlockCipher::new(name, &key, param.as_deref()).map_err(err)?;
        Ok(Cipher {
            name: name.to_ascii_lowercase(),
            key: key.to_vec(),
            param,
            block_size: probe.blocksize(),
        })
    }

    #[pyo3(signature = (mode, iv = None))]
    fn encryptor(&self, mode: &str, iv: Option<Bytes>) -> PyResult<Encryptor> {
        self.stream(mode, iv, false)
    }

    #[pyo3(signature = (mode, iv = None))]
    fn decryptor(&self, mode: &str, iv: Option<Bytes>) -> PyResult<Encryptor> {
        self.stream(mode, iv, true)
    }

    /// One-shot convenience: encrypt everything and finalize.
    #[pyo3(signature = (mode, data, iv = None))]
    fn encrypt<'py>(&self, py: Python<'py>, mode: &str, data: Bytes,
                    iv: Option<Bytes>) -> PyResult<Bound<'py, PyBytes>> {
        let mut s = self.stream(mode, iv, false)?;
        let out = py.allow_threads(|| -> Result<Vec<u8>, String> {
            let mut out = s.inner.update(&data)?;
            out.extend_from_slice(&s.inner.finish()?);
            Ok(out)
        }).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[pyo3(signature = (mode, data, iv = None))]
    fn decrypt<'py>(&self, py: Python<'py>, mode: &str, data: Bytes,
                    iv: Option<Bytes>) -> PyResult<Bound<'py, PyBytes>> {
        let mut s = self.stream(mode, iv, true)?;
        let out = py.allow_threads(|| -> Result<Vec<u8>, String> {
            let mut out = s.inner.update(&data)?;
            out.extend_from_slice(&s.inner.finish()?);
            Ok(out)
        }).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[getter]
    fn block_size(&self) -> usize {
        self.block_size
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.Cipher '{}' block_size={}>", self.name, self.block_size)
    }
}

// --------------------------------------------------------- stream ciphers ---

/// A keyed stream cipher. Keystream position carries across `update` calls.
#[pyclass(module = "allcrypt", name = "StreamCipher")]
pub struct PyStreamCipher {
    inner: AnyStreamCipher,
    name: String,
}

#[pymethods]
impl PyStreamCipher {
    /// RC4 and ZipCrypto take no nonce; the ChaCha variants take 8 or 12
    /// bytes. ZipCrypto's key is the password.
    #[new]
    #[pyo3(signature = (name, key, nonce = None))]
    fn py_new(name: &str, key: Bytes, nonce: Option<Bytes>) -> PyResult<Self> {
        let inner = AnyStreamCipher::new(name, &key, nonce.as_deref().unwrap_or(&[])).map_err(err)?;
        Ok(PyStreamCipher { inner, name: name.to_ascii_lowercase() })
    }

    /// The keystream XORed onto the data, which encrypts and decrypts
    /// alike. Refused for ZipCrypto, whose two directions differ.
    fn update<'py>(&mut self, py: Python<'py>, data: Bytes) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.update(&data)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    fn encrypt<'py>(&mut self, py: Python<'py>, data: Bytes) -> Bound<'py, PyBytes> {
        let out = py.allow_threads(|| self.inner.encrypt(&data));
        PyBytes::new(py, &out)
    }

    fn decrypt<'py>(&mut self, py: Python<'py>, data: Bytes) -> Bound<'py, PyBytes> {
        let out = py.allow_threads(|| self.inner.decrypt(&data));
        PyBytes::new(py, &out)
    }

    /// Whether encrypting and decrypting are one operation (`update`).
    #[getter]
    fn keystream(&self) -> bool {
        self.inner.is_keystream()
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.StreamCipher '{}'>", self.name)
    }
}

// ---------------------------------------------------------------- padding ---

#[pyfunction]
fn pad_pkcs7<'py>(py: Python<'py>, data: Bytes, block_size: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::pad_pkcs7(&data, block_size).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn unpad_pkcs7<'py>(py: Python<'py>, data: Bytes, block_size: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::unpad_pkcs7(&data, block_size).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

// ---------------------------------------------------------- CBC-MAC, CMAC ---

/// CMAC (SP 800-38B) over any block cipher here: the whole message at once.
#[pyfunction]
fn cmac<'py>(py: Python<'py>, cipher: &str, key: Bytes, data: Bytes)
             -> PyResult<Bound<'py, PyBytes>> {
    let out = crate::mac::cmac::cmac(cipher, &key, &data).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// CBC-MAC. `iv` defaults to zeros; `zero_pad` pads to whole blocks with
/// zeros first, and without it the data must be whole blocks.
#[pyfunction]
#[pyo3(signature = (cipher, key, data, iv = None, zero_pad = false))]
fn cbc_mac<'py>(py: Python<'py>, cipher: &str, key: Bytes, data: Bytes, iv: Option<Bytes>,
                zero_pad: bool) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::cbc_mac(cipher, &key, &data, iv.as_deref(), zero_pad).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

// ------------------------------------------------- Office XOR obfuscation ---

/// The 16-bit verifier of an XOR obfuscation password (1 to 15 bytes).
#[pyfunction]
fn office_xor_verifier(password: Bytes) -> PyResult<u16> {
    api::office_xor_verifier(&password).map_err(err)
}

/// Office XOR obfuscation, method 1. `index` is the array index the
/// first byte meets; Excel's records start just past their own end.
#[pyfunction]
#[pyo3(signature = (password, data, index = 0))]
fn office_xor_decrypt<'py>(py: Python<'py>, password: Bytes, data: Bytes, index: usize)
                           -> PyResult<Bound<'py, PyBytes>> {
    let out = api::office_xor_decrypt(&password, &data, index).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
#[pyo3(signature = (password, data, index = 0))]
fn office_xor_encrypt<'py>(py: Python<'py>, password: Bytes, data: Bytes, index: usize)
                           -> PyResult<Bound<'py, PyBytes>> {
    let out = api::office_xor_encrypt(&password, &data, index).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

// ------------------------------------------------------------------ HMAC ---

/// A keyed HMAC in progress. Shaped like Python's own `hmac` objects.
#[pyclass(module = "allcrypt")]
pub struct Hmac {
    inner: RsHmac<AnyHash>,
    name: String,
}

#[pymethods]
impl Hmac {
    /// Mirrors `hmac.new(key, msg=None, digestmod=...)`.
    #[new]
    #[pyo3(signature = (key, msg = None, digestmod = "sha256"))]
    fn py_new(py: Python<'_>, key: Bytes, msg: Option<Bytes>, digestmod: &str) -> PyResult<Self> {
        let mut inner = api::new_hmac(digestmod, &key).map_err(err)?;
        if let Some(m) = msg {
            py.allow_threads(|| inner.update(&m));
        }
        Ok(Hmac { inner, name: format!("hmac-{}", digestmod.to_ascii_lowercase()) })
    }

    fn update(&mut self, py: Python<'_>, data: Bytes) {
        py.allow_threads(|| self.inner.update(&data));
    }

    fn digest<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.digest())
    }

    fn hexdigest(&mut self) -> String {
        hex_lower(&self.inner.digest())
    }

    #[getter]
    fn digest_size(&self) -> usize {
        self.inner.digest_len()
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.Hmac '{}'>", self.name)
    }
}

/// UMAC (RFC 4418), one shot. `key` is 16 bytes, `nonce` 1 to 16 and
/// never repeated under one key, `tag_len` 4, 8, 12 or 16.
#[pyfunction]
#[pyo3(signature = (key, nonce, data, tag_len = 8))]
fn umac<'py>(py: Python<'py>, key: Bytes, nonce: Bytes, data: Bytes, tag_len: usize)
             -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::umac(&key, &nonce, &data, tag_len)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

// ------------------------------------------------------------------- KDFs ---

/// HKDF (RFC 5869). `salt=None` uses the all-zero salt the RFC specifies.
#[pyfunction]
#[pyo3(signature = (ikm, length, salt = None, info = None, digestmod = "sha256"))]
fn hkdf<'py>(py: Python<'py>, ikm: Bytes, length: usize, salt: Option<Bytes>,
             info: Option<Bytes>, digestmod: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::hkdf(digestmod, salt.as_deref().unwrap_or(&[]), &ikm, info.as_deref().unwrap_or(&[]), length)
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// SP 800-108 counter mode; `prf` is "hmac-<hash>" or "cmac-<cipher>".
#[pyfunction]
#[pyo3(signature = (prf, key, length, label = None, context = None))]
fn kbkdf_counter<'py>(py: Python<'py>, prf: &str, key: Bytes, length: usize,
                      label: Option<Bytes>, context: Option<Bytes>)
                      -> PyResult<Bound<'py, PyBytes>> {
    let out = api::kbkdf_counter(prf, &key, label.as_deref().unwrap_or(&[]),
                                 context.as_deref().unwrap_or(&[]), length).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// SP 800-108 feedback mode with a counter, from `iv`.
#[pyfunction]
#[pyo3(signature = (prf, key, length, iv = None, label = None, context = None))]
fn kbkdf_feedback<'py>(py: Python<'py>, prf: &str, key: Bytes, length: usize,
                       iv: Option<Bytes>, label: Option<Bytes>, context: Option<Bytes>)
                       -> PyResult<Bound<'py, PyBytes>> {
    let out = api::kbkdf_feedback(prf, &key, iv.as_deref().unwrap_or(&[]),
                                  label.as_deref().unwrap_or(&[]),
                                  context.as_deref().unwrap_or(&[]), length).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// SP 800-56C's one-step KDF over a hash (the Concat KDF).
#[pyfunction]
#[pyo3(signature = (z, length, other_info = None, hash = "sha256"))]
fn concat_kdf<'py>(py: Python<'py>, z: Bytes, length: usize, other_info: Option<Bytes>,
                   hash: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::concat_kdf(hash, &z, other_info.as_deref().unwrap_or(&[]), length)
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// ANSI X9.63's KDF.
#[pyfunction]
#[pyo3(signature = (z, length, shared_info = None, hash = "sha256"))]
fn x963_kdf<'py>(py: Python<'py>, z: Bytes, length: usize, shared_info: Option<Bytes>,
                 hash: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::x963_kdf(hash, &z, shared_info.as_deref().unwrap_or(&[]), length)
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// RFC 3961's n-fold.
#[pyfunction]
fn kerberos_nfold<'py>(py: Python<'py>, data: Bytes, length: usize) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &api::kerberos_nfold(&data, length))
}

/// RFC 3961's DR under a block cipher.
#[pyfunction]
fn kerberos_derive_random<'py>(py: Python<'py>, cipher: &str, key: Bytes, constant: Bytes,
                               length: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::kerberos_derive_random(cipher, &key, &constant, length).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// RFC 3961's DES string-to-key.
#[pyfunction]
fn kerberos_des_string_to_key<'py>(py: Python<'py>, password: Bytes, salt: Bytes)
                                   -> PyResult<Bound<'py, PyBytes>> {
    let out = api::kerberos_des_string_to_key(&password, &salt).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// RFC 3961's random-to-key for "des" or "3des".
#[pyfunction]
fn kerberos_random_to_key<'py>(py: Python<'py>, cipher: &str, data: Bytes)
                               -> PyResult<Bound<'py, PyBytes>> {
    let out = api::kerberos_random_to_key(cipher, &data).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// OpenPGP's string-to-key (RFC 9580 3.7.1): `count` octets of
/// `salt || passphrase` repeated, `length` bytes out. `count` is the
/// decoded count (`openpgp_s2k_count`); zero with an empty salt is the
/// simple S2K.
#[pyfunction]
fn openpgp_s2k<'py>(py: Python<'py>, hash_name: &str, passphrase: Bytes, salt: Bytes,
                    count: usize, length: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::openpgp_s2k(hash_name, &passphrase, &salt, count, length).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The octet count an iterated S2K's coded count byte stands for.
#[pyfunction]
fn openpgp_s2k_count(coded: u8) -> usize {
    api::openpgp_s2k_count(coded)
}

/// 7-Zip's AES key: `password` as UTF-16LE bytes, 2^cycles rounds of
/// SHA-256, or the raw key for cycles 0x3f.
#[pyfunction]
fn sevenzip_aes_key<'py>(py: Python<'py>, password: Bytes, salt: Bytes, cycles: u8)
                         -> PyResult<Bound<'py, PyBytes>> {
    let out = api::sevenzip_aes_key(&password, &salt, cycles).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// KeePass's AES-KDF.
#[pyfunction]
fn keepass_aes_kdf<'py>(py: Python<'py>, key: Bytes, seed: Bytes, rounds: u64)
                        -> PyResult<Bound<'py, PyBytes>> {
    let out = api::keepass_aes_kdf(&key, &seed, rounds).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// LUKS's AF splitter, the random stripes from the operating system.
#[pyfunction]
#[pyo3(signature = (key, stripes = 4000, hash = "sha256"))]
fn luks_af_split<'py>(py: Python<'py>, key: Bytes, stripes: usize, hash: &str)
                      -> PyResult<Bound<'py, PyBytes>> {
    let out = api::luks_af_split(&key, stripes, hash).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// LUKS's AF merge.
#[pyfunction]
#[pyo3(signature = (material, key_len, stripes = 4000, hash = "sha256"))]
fn luks_af_merge<'py>(py: Python<'py>, material: Bytes, key_len: usize, stripes: usize,
                      hash: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::luks_af_merge(&material, key_len, stripes, hash).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Michael, TKIP's message integrity code. The key is 8 bytes.
#[pyfunction]
fn michael<'py>(py: Python<'py>, key: Bytes, data: Bytes) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &api::michael(&key, &data).map_err(err)?))
}

/// WEP's RC4 encapsulation: the 3-byte IV, the shared key, the data.
#[pyfunction]
fn wep_encrypt<'py>(py: Python<'py>, key: Bytes, iv: Bytes, plaintext: Bytes)
                    -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &api::wep_encrypt(&key, &iv, &plaintext).map_err(err)?))
}

/// The inverse of `wep_encrypt`; a wrong key or damage fails the ICV.
#[pyfunction]
fn wep_decrypt<'py>(py: Python<'py>, key: Bytes, iv: Bytes, ciphertext: Bytes)
                    -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &api::wep_decrypt(&key, &iv, &ciphertext).map_err(err)?))
}

/// TKIP's per-packet RC4 key: the 16-byte temporal key, the 6-byte
/// transmitter address, the 48-bit sequence counter.
#[pyfunction]
fn tkip_rc4_key<'py>(py: Python<'py>, tk: Bytes, ta: Bytes, tsc: u64)
                     -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &api::tkip_rc4_key(&tk, &ta, tsc).map_err(err)?))
}

/// The WPA/WPA2 pre-shared key from a passphrase and the SSID.
#[pyfunction]
fn wpa_psk<'py>(py: Python<'py>, passphrase: Bytes, ssid: Bytes)
                -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &api::wpa_psk(&passphrase, &ssid).map_err(err)?))
}

/// The pairwise transient key: `bits` 512 for TKIP, 384 for CCMP, under
/// the "sha1" (WPA, WPA2) or "sha256" (802.11w, WPA3) key hierarchy.
#[pyfunction]
#[pyo3(signature = (akm, pmk, aa, spa, anonce, snonce, bits))]
#[allow(clippy::too_many_arguments)]
fn wpa_ptk<'py>(py: Python<'py>, akm: &str, pmk: Bytes, aa: Bytes, spa: Bytes, anonce: Bytes,
                snonce: Bytes, bits: usize) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &api::wpa_ptk(akm, &pmk, &aa, &spa, &anonce, &snonce, bits)
        .map_err(err)?))
}

/// The PMKID that names a cached pairwise master key.
#[pyfunction]
fn wpa_pmkid<'py>(py: Python<'py>, pmk: Bytes, aa: Bytes, spa: Bytes)
                  -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &api::wpa_pmkid(&pmk, &aa, &spa).map_err(err)?))
}

/// Encrypt one BitLocker sector at its byte offset on the volume.
#[pyfunction]
fn bitlocker_encrypt_sector<'py>(py: Python<'py>, method: &str, key: Bytes, byte_offset: u64,
                                 sector: Bytes) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::bitlocker_encrypt_sector(method, &key, byte_offset, &sector).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Decrypt one BitLocker sector at its byte offset on the volume.
#[pyfunction]
fn bitlocker_decrypt_sector<'py>(py: Python<'py>, method: &str, key: Bytes, byte_offset: u64,
                                 sector: Bytes) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::bitlocker_decrypt_sector(method, &key, byte_offset, &sector).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The NT hash of a password: MD4 of it as UTF-16 little endian.
#[pyfunction]
fn nt_hash<'py>(py: Python<'py>, password: &str) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &api::nt_hash(password))
}

/// The LM hash of a password given as bytes in its OEM code page.
#[pyfunction]
fn lm_hash<'py>(py: Python<'py>, password: Bytes) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::lm_hash(&password).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The key a BitLocker password protector's salt and password give.
#[pyfunction]
fn bitlocker_password_key<'py>(py: Python<'py>, password: &str, salt: Bytes)
                               -> PyResult<Bound<'py, PyBytes>> {
    let out = api::bitlocker_password_key(password, &salt).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The key a BitLocker recovery password protector's salt and recovery
/// password give.
#[pyfunction]
fn bitlocker_recovery_password_key<'py>(py: Python<'py>, recovery: &str, salt: Bytes)
                                        -> PyResult<Bound<'py, PyBytes>> {
    let out = api::bitlocker_recovery_password_key(recovery, &salt).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// PBKDF2 (RFC 8018), with hashlib's argument order and names so that
/// `allcrypt.pbkdf2_hmac` is a drop-in for `hashlib.pbkdf2_hmac`.
///
/// `dklen=None` means the hash's own output length, as hashlib does.
#[pyfunction]
#[pyo3(signature = (hash_name, password, salt, iterations, dklen = None))]
fn pbkdf2_hmac<'py>(py: Python<'py>, hash_name: &str, password: Bytes, salt: Bytes,
                    iterations: u32, dklen: Option<usize>)
                    -> PyResult<Bound<'py, PyBytes>> {
    let length = match dklen {
        Some(length) => length,
        // hashlib's default. Resolved here rather than in `api` so the
        // Rust side keeps an explicit length and no hidden default.
        None => api::AnyHash::new(hash_name).map_err(err)?.digest_len(),
    };
    let out = api::pbkdf2(hash_name, &password, &salt, iterations, length).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Iterations to use for new work, as of 2026.
#[pyfunction]
fn pbkdf2_recommended_iterations(hash_name: &str) -> u32 {
    api::pbkdf2_recommended_iterations(hash_name)
}

/// Squeeze any number of bytes out of a SHAKE.
///
/// `hashlib`'s `shake_128(...).digest(length)` in function form. Only
/// the SHAKEs are extendable; asking a fixed-length hash for more than
/// its digest is an error rather than a silent truncation.
#[pyfunction]
#[pyo3(signature = (name, data, length))]
fn shake<'py>(py: Python<'py>, name: &str, data: Bytes, length: usize)
              -> PyResult<Bound<'py, PyBytes>> {
    let out = api::shake(name, &data, length).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// scrypt (RFC 7914), with hashlib's argument names and order.
#[pyfunction]
#[pyo3(signature = (password, *, salt, n, r, p, dklen = 64))]
fn scrypt<'py>(py: Python<'py>, password: Bytes, salt: Bytes, n: u64, r: u32,
               p: u32, dklen: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::scrypt(&password, &salt, n, r, p, dklen).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Argon2 (RFC 9106), all three variants.
///
/// `variant` defaults to "argon2id", which is what RFC 9106 section 4
/// recommends. The other two are not deprecated: Argon2d is the right
/// choice where nothing can observe the machine's memory, and Argon2i
/// where the access pattern must leak nothing.
#[pyfunction]
#[pyo3(signature = (password, salt, *, variant = "argon2id", memory_kib = 65536,
                    passes = 3, lanes = 4, secret = None, associated_data = None,
                    dklen = 32))]
#[allow(clippy::too_many_arguments)]
fn argon2<'py>(py: Python<'py>, password: Bytes, salt: Bytes, variant: &str,
               memory_kib: u32, passes: u32, lanes: u32, secret: Option<Bytes>,
               associated_data: Option<Bytes>, dklen: usize)
               -> PyResult<Bound<'py, PyBytes>> {
    let out = api::argon2(variant, &password, &salt, memory_kib, passes, lanes,
                          secret.as_deref().unwrap_or(&[]), associated_data.as_deref().unwrap_or(&[]),
                          dklen).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The TLS 1.2 PRF (RFC 5246 section 5).
#[pyfunction]
#[pyo3(signature = (secret, label, seed, length, digestmod = "sha256"))]
fn tls12_prf<'py>(py: Python<'py>, secret: Bytes, label: Bytes, seed: Bytes,
                  length: usize, digestmod: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::tls12_prf(digestmod, &secret, &label, &seed, length).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The TLS 1.0/1.1 PRF (RFC 2246 section 5). The hashes are fixed by the spec.
#[pyfunction]
fn tls10_prf<'py>(py: Python<'py>, secret: Bytes, label: Bytes, seed: Bytes,
                  length: usize) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &api::tls10_prf(&secret, &label, &seed, length))
}

// --------------------------------------------------------- elliptic curves ---

/// An elliptic curve key pair.
///
/// Translation only: the scalar arithmetic, the point validation and the
/// SEC1 encoding all live in `api::EcKey`, which `tests/test_api.rs` and
/// `tools/src/bin/diff_ec.rs` check against OpenSSL.
#[pyclass(name = "EcKey", module = "allcrypt")]
pub struct PyEcKey {
    inner: api::EcKey,
}

#[pymethods]
impl PyEcKey {
    /// A fresh key pair. The private scalar comes from the OS random source.
    #[staticmethod]
    fn generate(py: Python<'_>, curve: &str) -> PyResult<PyEcKey> {
        let inner = py.allow_threads(|| api::EcKey::generate(curve)).map_err(err)?;
        Ok(PyEcKey { inner })
    }

    /// Import a private scalar, big endian. Rejects anything outside `[1, n)`.
    #[staticmethod]
    fn from_private(py: Python<'_>, curve: &str, private: Bytes) -> PyResult<PyEcKey> {
        let inner = py.allow_threads(|| api::EcKey::from_private(curve, &private))
            .map_err(err)?;
        Ok(PyEcKey { inner })
    }

    /// The private scalar, big endian, padded to the group order's width
    /// (RFC 5915). That is the field's width on every built-in curve.
    fn private_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let out = self.inner.private_bytes().map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// The public point in SEC1 encoding: 0x04 || X || Y, or 0x02/0x03 || X
    /// when `compressed`.
    #[pyo3(signature = (compressed = false))]
    fn public_bytes<'py>(&self, py: Python<'py>, compressed: bool)
                        -> PyResult<Bound<'py, PyBytes>> {
        let out = self.inner.public_bytes(compressed).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// ECDH with a peer's SEC1 encoded public point, returning the shared
    /// X coordinate. The peer point is validated before any arithmetic
    /// touches it, so a hostile point on a weaker curve is rejected rather
    /// than leaking the private scalar.
    fn exchange<'py>(&self, py: Python<'py>, peer_public: Bytes)
                     -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.exchange(&peer_public)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[getter]
    fn curve(&self) -> &'static str {
        self.inner.curve_name()
    }

    #[getter]
    fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    /// Sign an already computed digest with ECDSA, returning `r || s`.
    ///
    /// `digestmod` must name the hash that produced `digest`: RFC 6979
    /// derives the nonce through an HMAC over that same hash. The signature
    /// is deterministic, so signing the same digest twice gives the same
    /// bytes and no random source is involved.
    #[pyo3(signature = (digest, digestmod = "sha256"))]
    fn sign<'py>(&self, py: Python<'py>, digest: Bytes, digestmod: &str)
                 -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sign(&digest, digestmod)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// VKO, the GOST key agreement (RFC 7836). Not ECDH with a hash on
    /// the end - the nonce goes into the scalar and both coordinates go
    /// into the digest, little endian.
    ///
    /// `cofactor` picks between RFC 7836's `m/q` term
    /// (`"as-specified"`, the default, and what OpenSSL's GOST engine
    /// computes) and the term left out (`"without-cofactor"`, which
    /// matches nothing known). The two agree on every curve whose
    /// cofactor is one, which is all but `gost256-tc26-a` and
    /// `gost512-c`.
    #[pyo3(signature = (peer_public, ukm, digest_bits = 256,
                        cofactor = "as-specified"))]
    fn vko<'py>(&self, py: Python<'py>, peer_public: Bytes, ukm: Bytes,
                digest_bits: usize, cofactor: &str)
                -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(
            || self.inner.vko_using(&peer_public, &ukm, digest_bits, cofactor))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Sign under GOST R 34.10-2012 instead of ECDSA. A different
    /// equation over the same curve, and a different encoding: `s || r`.
    #[pyo3(signature = (digest, digestmod = "streebog256"))]
    fn sign_gost<'py>(&self, py: Python<'py>, digest: Bytes, digestmod: &str)
                      -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sign_gost(&digest, digestmod))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Verify with this key's own public half, for the round trip.
    fn verify(&self, py: Python<'_>, digest: Bytes, signature: Bytes) -> PyResult<bool> {
        let public = self.inner.public_key();
        py.allow_threads(|| public.verify(&digest, &signature)).map_err(err)
    }

    /// Sign under SM2, GB/T 32918.2. **Takes the message, not a
    /// digest**: SM2's `e` is `SM3(Z_A || M)` and `Z_A` binds the
    /// identity and the curve, so no digest exists to pass in.
    ///
    /// `id` defaults to GB/T 32918.2's `1234567812345678`. Pass `b""`
    /// for a genuinely empty identity, which is what
    /// `openssl pkeyutl` uses when no `distid` is given.
    #[pyo3(signature = (message, id = None))]
    fn sm2_sign<'py>(&self, py: Python<'py>, message: Bytes, id: Option<Bytes>)
                     -> PyResult<Bound<'py, PyBytes>> {
        let id = id.as_deref().unwrap_or(api::sm2::DEFAULT_ID).to_vec();
        let out = py.allow_threads(|| self.inner.sm2_sign_with_id(&id, &message))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[pyo3(signature = (message, signature, id = None))]
    fn sm2_verify(&self, py: Python<'_>, message: Bytes, signature: Bytes,
                  id: Option<Bytes>) -> PyResult<bool> {
        let id = id.as_deref().unwrap_or(api::sm2::DEFAULT_ID).to_vec();
        py.allow_threads(|| self.inner.sm2_verify_with_id(&id, &message, &signature))
            .map_err(err)
    }

    /// Decrypt `C1 || C3 || C2`.
    fn sm2_decrypt<'py>(&self, py: Python<'py>, ciphertext: Bytes)
                        -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sm2_decrypt(&ciphertext)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Decrypt the DER form OpenSSL exchanges.
    fn sm2_decrypt_der<'py>(&self, py: Python<'py>, der: Bytes)
                            -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sm2_decrypt_der(&der)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    fn verify_gost(&self, py: Python<'_>, digest: Bytes, signature: Bytes)
                   -> PyResult<bool> {
        let public = self.inner.public_key();
        py.allow_threads(|| public.verify_gost(&digest, &signature)).map_err(err)
    }

    /// The public half on its own, which is what a verifier needs.
    fn public_key(&self) -> PyEcPublicKey {
        PyEcPublicKey { inner: self.inner.public_key() }
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.EcKey {}>", self.inner.curve_name())
    }
}

/// An EdDSA key pair: Ed25519 or Ed448.
#[pyclass(name = "EddsaKey", module = "allcrypt")]
pub struct PyEddsaKey {
    inner: api::EddsaKey,
}

#[pymethods]
impl PyEddsaKey {
    #[staticmethod]
    fn generate(name: &str) -> PyResult<PyEddsaKey> {
        Ok(PyEddsaKey { inner: api::EddsaKey::generate(name).map_err(err)? })
    }

    #[staticmethod]
    fn from_private(name: &str, private: Bytes) -> PyResult<PyEddsaKey> {
        Ok(PyEddsaKey { inner: api::EddsaKey::from_private(name, &private).map_err(err)? })
    }

    fn private_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.private_bytes())
    }

    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_bytes())
    }

    /// Sign a **message**, not a digest: EdDSA hashes internally and
    /// there is no digest a caller could compute in advance.
    #[pyo3(signature = (message, context = None))]
    fn sign<'py>(&self, py: Python<'py>, message: Bytes, context: Option<Bytes>)
                 -> PyResult<Bound<'py, PyBytes>> {
        let context = context.as_deref().unwrap_or(&[]).to_vec();
        let out = py.allow_threads(|| self.inner.sign(&message, &context)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[pyo3(signature = (message, signature, context = None))]
    fn verify(&self, py: Python<'_>, message: Bytes, signature: Bytes,
              context: Option<Bytes>) -> PyResult<bool> {
        let context = context.as_deref().unwrap_or(&[]).to_vec();
        py.allow_threads(|| self.inner.verify(&message, &signature, &context)).map_err(err)
    }

    #[getter]
    fn curve(&self) -> &'static str {
        self.inner.curve_name()
    }

    #[getter]
    fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.EddsaKey {}>", self.inner.curve_name())
    }
}

/// A DSA key pair (FIPS 186-4), signing with RFC 6979 nonces.
///
/// Numbers are big-endian bytes; signatures are DER `Dss-Sig-Value`,
/// over the message hashed with ``hash``.
#[pyclass(name = "DsaKey", module = "allcrypt")]
pub struct PyDsaKey {
    inner: api::DsaKey,
}

#[pymethods]
impl PyDsaKey {
    /// A fresh group of ``l`` and ``n`` bits and a key in it. Takes
    /// seconds: the group needs a prime search.
    #[staticmethod]
    #[pyo3(signature = (l = 2048, n = 256))]
    fn generate(py: Python<'_>, l: usize, n: usize) -> PyResult<PyDsaKey> {
        let inner = py.allow_threads(|| api::DsaKey::generate(l, n)).map_err(err)?;
        Ok(PyDsaKey { inner })
    }

    #[staticmethod]
    fn from_numbers(p: Bytes, q: Bytes, g: Bytes, x: Bytes) -> PyResult<PyDsaKey> {
        Ok(PyDsaKey { inner: api::DsaKey::from_numbers(&p, &q, &g, &x).map_err(err)? })
    }

    /// ``(p, q, g)``, big endian.
    fn parameters<'py>(&self, py: Python<'py>)
                       -> (Bound<'py, PyBytes>, Bound<'py, PyBytes>, Bound<'py, PyBytes>) {
        let (p, q, g) = self.inner.parameters();
        (PyBytes::new(py, &p), PyBytes::new(py, &q), PyBytes::new(py, &g))
    }

    /// ``x``, big endian. Key material.
    fn private_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.private_bytes())
    }

    /// ``y``, big endian.
    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_key().public_bytes())
    }

    #[pyo3(signature = (message, hash = "sha256"))]
    fn sign<'py>(&self, py: Python<'py>, message: Bytes, hash: &str)
                 -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sign(hash, &message)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[pyo3(signature = (message, signature, hash = "sha256"))]
    fn verify(&self, py: Python<'_>, message: Bytes, signature: Bytes, hash: &str)
              -> PyResult<bool> {
        py.allow_threads(|| self.inner.verify(hash, &message, &signature)).map_err(err)
    }

    /// The bit length of ``p``.
    #[getter]
    fn key_size(&self) -> usize {
        self.inner.inner().public.parameters.p.bit_len()
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.DsaKey {} bits>", self.key_size())
    }
}

/// A public point on a named curve: enough to verify, and nothing more.
#[pyclass(name = "EcPublicKey", module = "allcrypt")]
pub struct PyEcPublicKey {
    inner: api::EcPublicKey,
}

#[pymethods]
impl PyEcPublicKey {
    /// Import a SEC1 encoded point. The point is validated here, so a point
    /// that is not on the curve raises rather than becoming a key.
    #[new]
    fn py_new(curve: &str, encoded: Bytes) -> PyResult<PyEcPublicKey> {
        Ok(PyEcPublicKey { inner: api::EcPublicKey::from_bytes(curve, &encoded).map_err(err)? })
    }

    #[pyo3(signature = (compressed = false))]
    fn public_bytes<'py>(&self, py: Python<'py>, compressed: bool)
                         -> PyResult<Bound<'py, PyBytes>> {
        let out = self.inner.to_bytes(compressed).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Verify an `r || s` signature over a digest.
    ///
    /// Returns False for a signature that is well formed and wrong, and
    /// raises for one that is not a signature at all — the wrong length,
    /// say. Both mean "do not trust this", but they are different bugs.
    fn verify(&self, py: Python<'_>, digest: Bytes, signature: Bytes) -> PyResult<bool> {
        py.allow_threads(|| self.inner.verify(&digest, &signature)).map_err(err)
    }

    /// The same for a GOST R 34.10-2012 signature, which is `s || r` and
    /// a different equation over the same curve.
    fn verify_gost(&self, py: Python<'_>, digest: Bytes, signature: Bytes)
                   -> PyResult<bool> {
        py.allow_threads(|| self.inner.verify_gost(&digest, &signature)).map_err(err)
    }

    /// Verify an SM2 signature. `id` defaults to GB/T 32918.2's
    /// `1234567812345678`; pass `b""` for OpenSSL's command line default.
    #[pyo3(signature = (message, signature, id = None))]
    fn sm2_verify(&self, py: Python<'_>, message: Bytes, signature: Bytes,
                  id: Option<Bytes>) -> PyResult<bool> {
        let id = id.as_deref().unwrap_or(api::sm2::DEFAULT_ID).to_vec();
        py.allow_threads(|| self.inner.sm2_verify_with_id(&id, &message, &signature))
            .map_err(err)
    }

    /// Encrypt to this key, returning `C1 || C3 || C2`.
    fn sm2_encrypt<'py>(&self, py: Python<'py>, message: Bytes)
                        -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sm2_encrypt(&message)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Encrypt in the DER form OpenSSL exchanges.
    fn sm2_encrypt_der<'py>(&self, py: Python<'py>, message: Bytes)
                            -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sm2_encrypt_der(&message)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[getter]
    fn curve(&self) -> &'static str {
        self.inner.curve_name()
    }

    #[getter]
    fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.EcPublicKey {}>", self.inner.curve_name())
    }
}

// -------------------------------------------------------------------- RSA ---

/// An RSA private key.
#[pyclass(name = "RsaKey", module = "allcrypt")]
pub struct PyRsaKey {
    inner: api::RsaKey,
}

#[pymethods]
impl PyRsaKey {
    /// Generate a key of `bits` modulus bits. Slow and of unpredictable
    /// duration — it searches for primes — so the GIL is released and a
    /// caller with a deadline should do this in advance.
    #[staticmethod]
    #[pyo3(signature = (bits = 2048))]
    fn generate(py: Python<'_>, bits: usize) -> PyResult<PyRsaKey> {
        let inner = py.allow_threads(|| api::RsaKey::generate(bits)).map_err(err)?;
        Ok(PyRsaKey { inner })
    }

    /// Rebuild a key from its primes, big endian. The CRT parameters are
    /// derived here rather than taken, so they cannot disagree.
    #[staticmethod]
    #[pyo3(signature = (p, q, e = None))]
    fn from_primes(py: Python<'_>, p: Bytes, q: Bytes, e: Option<Bytes>) -> PyResult<PyRsaKey> {
        let e = e.map(|e| e.to_vec()).unwrap_or_else(|| vec![0x01, 0x00, 0x01]);
        let inner = py.allow_threads(|| api::RsaKey::from_primes(&p, &q, &e)).map_err(err)?;
        Ok(PyRsaKey { inner })
    }

    fn public_key(&self) -> PyRsaPublicKey {
        PyRsaPublicKey { inner: self.inner.public_key() }
    }

    /// Sign a digest with PSS and a random salt. Two signatures over the
    /// same digest differ, which is the point.
    #[pyo3(signature = (digest, digestmod = "sha256", salt_length = None))]
    fn sign_pss<'py>(&self, py: Python<'py>, digest: Bytes, digestmod: &str,
                     salt_length: Option<usize>) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sign_pss(digestmod, &digest,
                                                          salt_length))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Sign an already computed digest with PKCS#1 v1.5. Deterministic:
    /// there is no randomness in this padding, so the same digest always
    /// gives the same signature.
    #[pyo3(signature = (digest, digestmod = "sha256"))]
    fn sign<'py>(&self, py: Python<'py>, digest: Bytes, digestmod: &str)
                 -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sign(digestmod, &digest)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// PKCS#1 v1.5 decryption.
    ///
    /// Every failure raises the same message on purpose. Reporting which
    /// check failed is Bleichenbacher's attack, and a caller that catches
    /// this and reports the difference has rebuilt the oracle.
    fn decrypt<'py>(&self, py: Python<'py>, ciphertext: Bytes)
                    -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.decrypt(&ciphertext)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// RSAES-OAEP decryption. `mgf_digestmod` defaults to `digestmod`;
    /// the label must be the one the message was encrypted under. Every
    /// failure of the ciphertext raises the same message, as for
    /// `decrypt`: telling them apart is Manger's attack.
    #[pyo3(signature = (ciphertext, digestmod = "sha256", mgf_digestmod = None,
                        label = Bytes::empty()))]
    fn decrypt_oaep<'py>(&self, py: Python<'py>, ciphertext: Bytes, digestmod: &str,
                         mgf_digestmod: Option<&str>, label: Bytes)
                         -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.decrypt_oaep(digestmod, mgf_digestmod,
                                                              &label, &ciphertext))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// The key's components as a dict of big endian bytes: n, e, d, p, q,
    /// dp, dq, qinv. Until there is an ASN.1 encoder, this is how a key
    /// leaves the library.
    #[getter]
    fn numbers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (name, value) in self.inner.numbers() {
            dict.set_item(name, PyBytes::new(py, &value))?;
        }
        Ok(dict)
    }

    #[getter]
    fn key_size(&self) -> usize { self.inner.bits() }

    #[getter]
    fn size(&self) -> usize { self.inner.size() }

    fn __repr__(&self) -> String {
        format!("<allcrypt.RsaKey {} bits>", self.inner.bits())
    }
}

/// The TLS master secret for a named version.
///
/// Here because SSLv3's derivation is not TLS's and nothing on a modern
/// machine can check it - OpenSSL removed SSLv3 - so the only reference is
/// the specification, and a reference needs something to compare against.
#[pyfunction]
fn tls_master_secret<'py>(py: Python<'py>, version: &str, premaster: Bytes,
                          client_random: Bytes, server_random: Bytes)
                          -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::tls_master_secret(
        version, &premaster, &client_random, &server_random)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// SSLv3's record MAC (RFC 6101 section 5.2.3.1).
///
/// Not HMAC, and the record's version is not part of the input - which is
/// the detail a port of the TLS construction would miss, in a way both
/// ends of a handshake would agree on.
#[pyfunction]
fn ssl3_record_mac<'py>(py: Python<'py>, hash_name: &str, mac_key: Bytes,
                        sequence: u64, content_type: u8, fragment: Bytes)
                        -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::ssl3_record_mac(
        hash_name, &mac_key, sequence, content_type, &fragment)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

// ------------------------------------------------- the OID registry ---

/// Give an object identifier a meaning, for this process.
///
/// Exactly one of the three keywords, because an OID names one thing:
///
/// ```python
/// allcrypt.register_oid("1.2.643.2.2.9", hash="gost94")
/// allcrypt.register_oid("1.2.643.2.2.35.1", curve="gost256-a")
/// allcrypt.register_oid("1.3.6.1.4.1.42.1.1", gost_sbox=[[...], ...])
/// ```
///
/// A registered OID can then be used wherever that kind of name is
/// taken: as a hash name for `Hash(...)`, as a parameter set for a
/// GOST cipher, or as the parameter set in a certificate this library
/// would otherwise have refused.
///
/// **It cannot change what a built-in OID means.** The compiled-in
/// tables are consulted first, so a registration reaches only the gap
/// - the OIDs this library does not know. Registering one twice
/// replaces the older meaning.
#[pyfunction]
#[pyo3(signature = (oid, *, hash=None, curve=None, gost_sbox=None,
                    curve_parameters=None))]
fn register_oid(oid: &str, hash: Option<&str>, curve: Option<&str>,
                gost_sbox: Option<Vec<Vec<u8>>>,
                curve_parameters: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
    let given = hash.is_some() as u8 + curve.is_some() as u8
              + gost_sbox.is_some() as u8 + curve_parameters.is_some() as u8;
    if given != 1 {
        return Err(PyValueError::new_err(
            "register_oid takes exactly one of hash=, curve=, gost_sbox= or \
             curve_parameters=; an OID names one thing."));
    }
    let meaning = if let Some(name) = hash {
        registry::Meaning::hash(name)
    } else if let Some(name) = curve {
        registry::Meaning::curve(name)
    } else if let Some(fields) = curve_parameters {
        registry::Meaning::curve_parameters(read_curve_parameters(fields)?)
    } else {
        registry::Meaning::gost_param_set(gost_sbox.expect("checked above"))
    };
    registry::register(oid, meaning).map_err(err)
}

/// One field of `curve_parameters=`, as a `BigUint`.
///
/// **Accepts an `int` or a hex `str`**, because both are what a caller
/// actually has. A specification prints these in hex, often in
/// whitespace-separated groups, and copying that in is the likeliest way
/// to get them right; a caller computing them has Python ints. Refusing
/// either would mean the caller converting, which is one more place for a
/// digit to go missing.
///
/// A negative int is refused rather than wrapped: every value here is a
/// field element or an order, and `-3` for `a` means the caller meant
/// `p - 3` and this cannot know their `p` yet.
fn curve_field(fields: &Bound<'_, PyDict>, name: &str)
               -> PyResult<crate::bignum::BigUint> {
    let value = fields.get_item(name)?.ok_or_else(|| PyValueError::new_err(
        format!("curve_parameters is missing {:?}. All of name, p, a, b, gx, \
                 gy, n and cofactor are required: a caller who does not know \
                 the cofactor does not know the curve, and guessing 1 turns \
                 every cofactor check into a check of the guess.", name)))?;

    let hex = if let Ok(text) = value.extract::<String>() {
        let cleaned: String = text.chars()
            .filter(|c| !c.is_whitespace() && *c != ':' && *c != '_')
            .collect();
        let cleaned = cleaned.strip_prefix("0x")
            .or_else(|| cleaned.strip_prefix("0X"))
            .unwrap_or(&cleaned).to_string();
        if cleaned.is_empty() || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PyValueError::new_err(format!(
                "curve_parameters[{:?}] is a string, so it is read as hex, \
                 and {:?} is not hex.", name, text)));
        }
        cleaned
    } else {
        // `format(value, "x")` rather than `str`: `str` of an int is
        // decimal, and reading a decimal string as hex is the sort of
        // mistake that produces a number of the right length.
        let negative = value.lt(0i64).unwrap_or(false);
        if negative {
            return Err(PyValueError::new_err(format!(
                "curve_parameters[{:?}] is negative. These are field \
                 elements and orders; write `a` as p-3 rather than -3.",
                name)));
        }
        value.call_method1("__format__", ("x",))
            .map_err(|_| PyValueError::new_err(format!(
                "curve_parameters[{:?}] must be an int or a hex string.",
                name)))?
            .extract::<String>()?
    };

    let padded = if hex.len() % 2 == 1 { format!("0{}", hex) } else { hex };
    crate::bignum::BigUint::from_hex(&padded).map_err(err)
}

fn read_curve_parameters(fields: &Bound<'_, PyDict>)
                         -> PyResult<crate::ec::curves::CurveParameters> {
    // Every key is checked against the set below, so a misspelling is an
    // error rather than a silently missing field with a default. `cofator`
    // for `cofactor` would otherwise read as "not given".
    const KNOWN: &[&str] = &["name", "p", "a", "b", "gx", "gy", "n",
                             "cofactor"];
    for key in fields.keys() {
        let key: String = key.extract()?;
        if !KNOWN.contains(&key.as_str()) {
            return Err(PyValueError::new_err(format!(
                "curve_parameters has an unknown key {:?}. It takes {}.",
                key, KNOWN.join(", "))));
        }
    }
    let name: String = fields.get_item("name")?
        .ok_or_else(|| PyValueError::new_err(
            "curve_parameters is missing \"name\": the curve needs one to be \
             looked up by."))?
        .extract()?;

    Ok(crate::ec::curves::CurveParameters {
        name,
        p: curve_field(fields, "p")?,
        a: curve_field(fields, "a")?,
        b: curve_field(fields, "b")?,
        gx: curve_field(fields, "gx")?,
        gy: curve_field(fields, "gy")?,
        n: curve_field(fields, "n")?,
        h: curve_field(fields, "cofactor")?,
    })
}

/// Every registered OID, as `(oid, kind, meaning)` triples.
///
/// `kind` is `"hash"`, `"curve"` or `"gost-param-set"`, and `meaning`
/// is the name it resolves to - or, for a parameter set, its shape.
#[pyfunction]
fn registered_oids() -> Vec<(String, String, String)> {
    registry::registered().into_iter()
        .map(|(oid, meaning)| (oid, meaning.kind().to_string(),
                               meaning.describe()))
        .collect()
}

/// Undo one registration. Returns whether there was one.
#[pyfunction]
fn forget_oid(oid: &str) -> bool {
    registry::forget(oid)
}

/// The substitution rows of a GOST parameter set, built in or
/// registered.
///
/// Here so a caller can read a table before copying it: the usual way
/// to make a new parameter set is to start from one that exists.
#[pyfunction]
fn gost_sbox(name: &str) -> PyResult<Vec<Vec<u8>>> {
    allcrypt_gost::GostCrypto::sbox_named(name).map_err(err)
}

/// A curve's domain parameters, in the shape `register_oid` takes.
///
/// The counterpart of `gost_sbox`, and there for the same reason: the
/// usual way to register a parameter set is to read one out and change
/// what differs. Without this, a caller wanting to supply a curve had to
/// find the numbers elsewhere, and a curve *this library already has* was
/// the one thing they could not copy.
///
/// **Every number is hex, big-endian**, without a `0x` prefix, with no
/// leading zeros beyond a pad to an even number of digits - so each value
/// is a whole number of bytes and `bytes.fromhex` takes it directly. It returns
/// strings rather than ints so that the byte order is unambiguous at the
/// boundary: an int has no byte order until something serialises it, and
/// this is the point where a caller is most likely to get one wrong.
///
/// ```python
/// parameters = allcrypt.curve_parameters("P-256")
/// parameters["name"] = "p-256-by-another-name"
/// allcrypt.register_oid("1.3.6.1.4.1.99999.9.1",
///                       curve_parameters=parameters)
/// ```
#[pyfunction]
fn curve_parameters<'py>(py: Python<'py>, name: &str)
                         -> PyResult<Bound<'py, PyDict>> {
    let curve = crate::ec::curves::by_name(name).map_err(err)?;
    let x = curve.g.x().ok_or_else(|| PyValueError::new_err(
        "the base point is the identity"))?;
    let y = curve.g.y().ok_or_else(|| PyValueError::new_err(
        "the base point is the identity"))?;

    // Padded to an even number of digits, so every value is a whole
    // number of bytes and `bytes.fromhex` accepts it. `to_hex` drops
    // leading zeros, which for a cofactor of one gives `"1"` - a string
    // that reads as hex fine and is not a byte.
    let even = |value: &crate::bignum::BigUint| {
        let hex = value.to_hex();
        if hex.len() % 2 == 1 { format!("0{}", hex) } else { hex }
    };

    let dict = PyDict::new(py);
    dict.set_item("name", curve.name)?;
    dict.set_item("p", even(&curve.p))?;
    dict.set_item("a", even(&curve.a))?;
    dict.set_item("b", even(&curve.b))?;
    dict.set_item("gx", even(x))?;
    dict.set_item("gy", even(y))?;
    dict.set_item("n", even(&curve.n))?;
    dict.set_item("cofactor", even(&curve.h))?;
    Ok(dict)
}

/// X25519 key agreement (RFC 7748). Returns `(private, public)`.
#[pyfunction]
fn x25519_generate(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (private, public) = py.allow_threads(api::x25519_generate).map_err(err)?;
    Ok((PyBytes::new(py, &private).into(), PyBytes::new(py, &public).into()))
}

/// The public key for an X25519 private key.
#[pyfunction]
fn x25519_public_key<'py>(py: Python<'py>, private: Bytes) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::x25519_public_key(&private)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The X25519 shared secret. Raises if the result is all zero, which means
/// the peer sent a low-order point and the secret is a known constant.
#[pyfunction]
fn x25519_exchange<'py>(py: Python<'py>, private: Bytes, peer: Bytes)
                        -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::x25519_exchange(&private, &peer)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The raw RFC 7748 primitive, without the degenerate-output check. For
/// the specification's own test vectors, which are stated in these terms.
#[pyfunction]
fn x25519_raw<'py>(py: Python<'py>, scalar: Bytes, point: Bytes)
                   -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::x25519_raw(&scalar, &point)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// X448 (RFC 7748), the key agreement on Curve448.
///
/// Shaped exactly like the four `x25519_*` functions, with one thing to
/// know: **every value is 56 bytes, not 32**, and a 32 byte key handed
/// to one of these raises rather than being padded. The error says which
/// algorithm wanted 56.
#[pyfunction]
fn x448_generate(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (private, public) = py.allow_threads(api::x448_generate).map_err(err)?;
    Ok((PyBytes::new(py, &private).unbind(), PyBytes::new(py, &public).unbind()))
}

/// The public key for a private one: `scalar * 5`.
#[pyfunction]
fn x448_public_key<'py>(py: Python<'py>, private: Bytes) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::x448_public_key(&private)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The shared secret, refusing the all-zero result.
#[pyfunction]
fn x448_exchange<'py>(py: Python<'py>, private: Bytes, peer: Bytes)
                      -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::x448_exchange(&private, &peer)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The raw primitive, which does not refuse a degenerate result. RFC
/// 7748's vectors are stated in terms of it.
#[pyfunction]
fn x448_raw<'py>(py: Python<'py>, scalar: Bytes, point: Bytes)
                 -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::x448_raw(&scalar, &point)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Wrap key data under a key-encryption key (RFC 3394).
///
/// `cipher` is any 128 bit block cipher; AES is what every standard
/// names. The key data must be at least two 64 bit blocks; use
/// `key_wrap_with_padding` for anything else.
#[pyfunction]
#[pyo3(signature = (kek, data, cipher = "aes"))]
fn key_wrap<'py>(py: Python<'py>, kek: Bytes, data: Bytes, cipher: &str)
                 -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::key_wrap(cipher, &kek, &data)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Unwrap key data (RFC 3394). Raises if the integrity check fails,
/// which is the only thing standing between the caller and a key an
/// attacker chose.
#[pyfunction]
#[pyo3(signature = (kek, data, cipher = "aes"))]
fn key_unwrap<'py>(py: Python<'py>, kek: Bytes, data: Bytes, cipher: &str)
                   -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::key_unwrap(cipher, &kek, &data)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Wrap key data of any length (RFC 5649).
#[pyfunction]
#[pyo3(signature = (kek, data, cipher = "aes"))]
fn key_wrap_with_padding<'py>(py: Python<'py>, kek: Bytes, data: Bytes, cipher: &str)
                              -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::key_wrap_with_padding(cipher, &kek, &data))
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Unwrap key data wrapped with RFC 5649. The length field and the
/// padding are part of the authentication, so a mismatch in either
/// raises rather than being trimmed.
#[pyfunction]
#[pyo3(signature = (kek, data, cipher = "aes"))]
fn key_unwrap_with_padding<'py>(py: Python<'py>, kek: Bytes, data: Bytes, cipher: &str)
                                -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::key_unwrap_with_padding(cipher, &kek, &data))
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// RFC 3217's Triple-DES key wrap: a 24-byte key under a Triple-DES
/// key-encryption key. `iv` is random unless given.
#[pyfunction]
#[pyo3(signature = (kek, cek, iv = None))]
fn cms_3des_key_wrap<'py>(py: Python<'py>, kek: Bytes, cek: Bytes, iv: Option<Bytes>)
                          -> PyResult<Bound<'py, PyBytes>> {
    let out = api::cms_3des_key_wrap(&kek, &cek, iv.as_deref()).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn cms_3des_key_unwrap<'py>(py: Python<'py>, kek: Bytes, wrapped: Bytes)
                            -> PyResult<Bound<'py, PyBytes>> {
    let out = api::cms_3des_key_unwrap(&kek, &wrapped).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// RFC 3217's RC2 key wrap. `effective_bits` is the key-encryption
/// key's effective length; padding and `iv` are random unless given.
#[pyfunction]
#[pyo3(signature = (kek, effective_bits, cek, pad = None, iv = None))]
fn cms_rc2_key_wrap<'py>(py: Python<'py>, kek: Bytes, effective_bits: usize, cek: Bytes,
                         pad: Option<Bytes>, iv: Option<Bytes>)
                         -> PyResult<Bound<'py, PyBytes>> {
    let out = api::cms_rc2_key_wrap(&kek, effective_bits, &cek, pad.as_deref(), iv.as_deref())
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn cms_rc2_key_unwrap<'py>(py: Python<'py>, kek: Bytes, effective_bits: usize, wrapped: Bytes)
                           -> PyResult<Bound<'py, PyBytes>> {
    let out = api::cms_rc2_key_unwrap(&kek, effective_bits, &wrapped).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// RFC 3211's password recipient key wrap over `cipher`. The padding is
/// random unless given.
#[pyfunction]
#[pyo3(signature = (cipher, kek, iv, cek, padding = None))]
fn pwri_key_wrap<'py>(py: Python<'py>, cipher: &str, kek: Bytes, iv: Bytes, cek: Bytes,
                      padding: Option<Bytes>) -> PyResult<Bound<'py, PyBytes>> {
    let out = api::pwri_key_wrap(cipher, &kek, &iv, &cek, padding.as_deref()).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn pwri_key_unwrap<'py>(py: Python<'py>, cipher: &str, kek: Bytes, iv: Bytes, wrapped: Bytes)
                        -> PyResult<Bound<'py, PyBytes>> {
    let out = api::pwri_key_unwrap(cipher, &kek, &iv, &wrapped).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Encrypt one XTS data unit (IEEE 1619, NIST SP 800-38E).
///
/// `key` is two cipher keys end to end - 32 bytes for AES-128-XTS, 64
/// for AES-256-XTS - and the two halves must differ. The ciphertext is
/// exactly as long as the plaintext, and **is not authenticated**.
#[pyfunction]
#[pyo3(signature = (key, sector, data, cipher = "aes"))]
fn xts_encrypt<'py>(py: Python<'py>, key: Bytes, sector: u128, data: Bytes,
                    cipher: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::xts_encrypt(cipher, &key, sector, &data))
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Decrypt one XTS data unit. There is no authentication: this returns
/// plaintext for any input of a legal length, including one an attacker
/// wrote.
#[pyfunction]
#[pyo3(signature = (key, sector, data, cipher = "aes"))]
fn xts_decrypt<'py>(py: Python<'py>, key: Bytes, sector: u128, data: Bytes,
                    cipher: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::xts_decrypt(cipher, &key, sector, &data))
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Encrypt whole 16 byte blocks with LRW, the disk mode before XTS.
///
/// `key` is the cipher key followed by the 16 byte tweak key; `index` is
/// the first block's index (a block number, not a sector number).
#[pyfunction]
#[pyo3(signature = (key, index, data, cipher = "aes"))]
fn lrw_encrypt<'py>(py: Python<'py>, key: Bytes, index: u128, data: Bytes,
                    cipher: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::lrw_encrypt(cipher, &key, index, &data))
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Decrypt with LRW. There is no authentication.
#[pyfunction]
#[pyo3(signature = (key, index, data, cipher = "aes"))]
fn lrw_decrypt<'py>(py: Python<'py>, key: Bytes, index: u128, data: Bytes,
                    cipher: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::lrw_decrypt(cipher, &key, index, &data))
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// `n` cryptographically strong random bytes from the operating
/// system's source - the same one every key and nonce in this library
/// is drawn from.
#[pyfunction]
fn random_bytes(py: Python<'_>, n: usize) -> PyResult<Bound<'_, PyBytes>> {
    let out = py.allow_threads(|| api::random_bytes(n)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// The name of the system random source these bytes come from.
#[pyfunction]
fn random_source() -> &'static str {
    api::random_source()
}

/// Whether AES runs on the processor's AES instructions in this build.
#[pyfunction]
fn hardware_aes() -> bool {
    api::hardware_aes()
}

/// The EdDSA curves this build can sign with.
#[pyfunction]
fn eddsa_curves() -> Vec<&'static str> {
    api::eddsa_curves()
}

/// A fresh EdDSA key pair, as `(private, public)`. `name` is `ed25519`
/// or `ed448`.
#[pyfunction]
fn eddsa_generate(py: Python<'_>, name: &str) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (private, public) =
        py.allow_threads(|| api::eddsa_generate(name)).map_err(err)?;
    Ok((PyBytes::new(py, &private).into(), PyBytes::new(py, &public).into()))
}

/// The public key for an EdDSA private key.
#[pyfunction]
fn eddsa_public_key<'py>(py: Python<'py>, name: &str, private: Bytes)
                         -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| api::eddsa_public_key(name, &private)).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Sign a message with EdDSA. Deterministic: no randomness anywhere, so
/// the same key and message always give the same signature.
///
/// `context` is Ed448's domain separator and must be empty for Ed25519.
#[pyfunction]
#[pyo3(signature = (name, private, message, context = None))]
fn eddsa_sign<'py>(py: Python<'py>, name: &str, private: Bytes, message: Bytes,
                   context: Option<Bytes>) -> PyResult<Bound<'py, PyBytes>> {
    let context = context.as_deref().unwrap_or(&[]);
    let out = py.allow_threads(|| api::eddsa_sign(name, &private, &message, context))
        .map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Verify an EdDSA signature. `False` for a well-formed signature that is
/// wrong; raises for something that is not a signature at all.
#[pyfunction]
#[pyo3(signature = (name, public, message, signature, context = None))]
fn eddsa_verify(py: Python<'_>, name: &str, public: Bytes, message: Bytes,
                signature: Bytes, context: Option<Bytes>) -> PyResult<bool> {
    let context = context.as_deref().unwrap_or(&[]);
    py.allow_threads(|| api::eddsa_verify(name, &public, &message, &signature, context))
        .map_err(err)
}

/// The XEdDSA forms: `signal` (libsignal's) and `xeddsa` (the
/// specification's).
#[pyfunction]
fn xeddsa_forms() -> Vec<&'static str> {
    api::xeddsa_forms()
}

/// Sign with an X25519 private key. `random` is the 64 bytes mixed into
/// the nonce, drawn from the system when omitted.
#[pyfunction]
#[pyo3(signature = (form, private, message, random = None))]
fn xeddsa_sign<'py>(py: Python<'py>, form: &str, private: Bytes, message: Bytes,
                    random: Option<Bytes>) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| {
        api::xeddsa_sign(form, &private, &message, random.as_deref())
    }).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

/// Verify an XEdDSA signature against an X25519 public key.
#[pyfunction]
fn xeddsa_verify(py: Python<'_>, form: &str, public: Bytes, message: Bytes,
                 signature: Bytes) -> PyResult<bool> {
    py.allow_threads(|| api::xeddsa_verify(form, &public, &message, &signature))
        .map_err(err)
}

/// A finite-field Diffie-Hellman group.
///
/// Every value in and out is big-endian bytes, padded to the width of the
/// modulus - which is what makes this directly comparable with another
/// implementation, and is why the TLS premaster (which strips those zeros
/// again) is a separate method rather than the default.
#[pyclass(name = "DhGroup", module = "allcrypt")]
pub struct PyDhGroup {
    inner: api::DhGroup,
}

#[pymethods]
impl PyDhGroup {
    /// From `p` and `g` as big-endian bytes.
    #[new]
    fn py_new(p: Bytes, g: Bytes) -> PyResult<PyDhGroup> {
        Ok(PyDhGroup { inner: api::DhGroup::new(&p, &g).map_err(err)? })
    }

    /// One of the built-in MODP groups: 1024 (RFC 2409), or 1536, 2048,
    /// 3072, 4096, 6144 or 8192 (RFC 3526).
    #[staticmethod]
    fn modp(bits: usize) -> PyResult<PyDhGroup> {
        Ok(PyDhGroup { inner: api::DhGroup::modp(bits).map_err(err)? })
    }

    #[getter]
    fn bits(&self) -> usize {
        self.inner.bits()
    }

    #[getter]
    fn p<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.p())
    }

    #[getter]
    fn g<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.g())
    }

    /// A fresh `(private, public)` pair.
    fn generate_key_pair<'py>(&self, py: Python<'py>)
                              -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let (private, public) = py.allow_threads(|| self.inner.generate_key_pair())
            .map_err(err)?;
        Ok((PyBytes::new(py, &private), PyBytes::new(py, &public)))
    }

    /// `g^x mod p`.
    fn public_key<'py>(&self, py: Python<'py>, private: Bytes)
                       -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.public_key(&private)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// The shared secret, padded to the width of `p`.
    fn shared_secret<'py>(&self, py: Python<'py>, private: Bytes, peer: Bytes)
                          -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.shared_secret(&private, &peer))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// The shared secret as TLS 1.0-1.2 use it, with leading zero bytes
    /// removed (RFC 5246 section 8.1.2). TLS 1.3 keeps them.
    fn tls_premaster<'py>(&self, py: Python<'py>, private: Bytes, peer: Bytes)
                          -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.tls_premaster(&private, &peer))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Raise if a peer public value is one of the degenerate ones.
    fn validate_peer(&self, peer: Bytes) -> PyResult<()> {
        self.inner.validate_peer(&peer).map_err(err)
    }

    /// Raise if `p` is composite. Costs several full-width modular
    /// exponentiations, so it is asked for rather than done for you.
    #[pyo3(signature = (rounds = 24))]
    fn check_prime(&self, py: Python<'_>, rounds: usize) -> PyResult<()> {
        py.allow_threads(|| self.inner.check_prime(rounds)).map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("<DhGroup {} bits>", self.inner.bits())
    }
}

/// An ElGamal key pair over a `DhGroup`.
///
/// OpenPGP algorithm 16 - the `elg` half of the `dsa/elg` keypairs
/// GnuPG made by default for years. OpenSSL dropped ElGamal and
/// `cryptography` never had it, so this is the only way to read those
/// messages from Python.
#[pyclass(name = "ElGamalKey", module = "allcrypt")]
pub struct PyElGamalKey {
    inner: api::ElGamalKey,
}

/// The public half of an ElGamal key.
#[pyclass(name = "ElGamalPublicKey", module = "allcrypt")]
pub struct PyElGamalPublicKey {
    inner: api::ElGamalPublicKey,
}

#[pymethods]
impl PyElGamalKey {
    /// A fresh key in the given group.
    #[staticmethod]
    fn generate(py: Python<'_>, group: &PyDhGroup) -> PyResult<PyElGamalKey> {
        let inner = py.allow_threads(|| api::ElGamalKey::generate(&group.inner))
            .map_err(err)?;
        Ok(PyElGamalKey { inner })
    }

    /// A key from a private exponent, which is what a PGP secret key
    /// carries. The public value is recomputed rather than trusted.
    #[staticmethod]
    fn from_private(py: Python<'_>, group: &PyDhGroup, private: Bytes)
                    -> PyResult<PyElGamalKey> {
        let inner = py.allow_threads(
            || api::ElGamalKey::from_private(&group.inner, &private))
            .map_err(err)?;
        Ok(PyElGamalKey { inner })
    }

    #[getter]
    fn private_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.inner.private_bytes().map_err(err)?))
    }

    #[getter]
    fn public_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.inner.public_bytes().map_err(err)?))
    }

    fn public_key(&self) -> PyElGamalPublicKey {
        PyElGamalPublicKey { inner: self.inner.public_key() }
    }

    /// The width of one ciphertext component; a whole ciphertext is two
    /// of these.
    #[getter]
    fn size(&self) -> usize {
        self.inner.size()
    }

    /// OpenPGP's ElGamal decryption: PKCS#1 v1.5 inside the raw scheme.
    ///
    /// **Every failure raises the same message**, deliberately: saying
    /// which check failed turns this into a decryption oracle.
    fn decrypt<'py>(&self, py: Python<'py>, ciphertext: Bytes)
                    -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.decrypt(&ciphertext))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Sign a digest, returning `r || s`. GnuPG withdrew ElGamal
    /// signing; see `docs/pitfalls.md` before using it for anything new.
    fn sign<'py>(&self, py: Python<'py>, digest: Bytes)
                 -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.sign(&digest)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    fn __repr__(&self) -> String {
        format!("<ElGamalKey {} bytes>", self.inner.size())
    }
}

#[pymethods]
impl PyElGamalPublicKey {
    #[new]
    fn py_new(group: &PyDhGroup, y: Bytes) -> PyResult<PyElGamalPublicKey> {
        Ok(PyElGamalPublicKey {
            inner: api::ElGamalPublicKey::new(&group.inner, &y).map_err(err)?,
        })
    }

    #[getter]
    fn size(&self) -> usize {
        self.inner.size()
    }

    #[getter]
    fn y<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.inner.y().map_err(err)?))
    }

    /// OpenPGP's ElGamal encryption, returning `c1 || c2`.
    fn encrypt<'py>(&self, py: Python<'py>, message: Bytes)
                    -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.encrypt(&message))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    fn verify(&self, py: Python<'_>, digest: Bytes, signature: Bytes)
              -> PyResult<bool> {
        py.allow_threads(|| self.inner.verify(&digest, &signature))
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("<ElGamalPublicKey {} bytes>", self.inner.size())
    }
}

/// An RSA public key: enough to encrypt and to verify.
#[pyclass(name = "RsaPublicKey", module = "allcrypt")]
pub struct PyRsaPublicKey {
    inner: api::RsaPublicKey,
}

#[pymethods]
impl PyRsaPublicKey {
    /// From a modulus and exponent, big endian.
    #[new]
    #[pyo3(signature = (n, e = None))]
    fn py_new(n: Bytes, e: Option<Bytes>) -> PyResult<PyRsaPublicKey> {
        let e = e.map(|e| e.to_vec()).unwrap_or_else(|| vec![0x01, 0x00, 0x01]);
        Ok(PyRsaPublicKey { inner: api::RsaPublicKey::new(&n, &e).map_err(err)? })
    }

    /// PKCS#1 v1.5 encryption. Randomised, so the same message gives
    /// different bytes each time.
    fn encrypt<'py>(&self, py: Python<'py>, message: Bytes) -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.encrypt(&message)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// RSAES-OAEP encryption. `digestmod` hashes the label and
    /// `mgf_digestmod`, which defaults to it, drives MGF1. Randomised.
    #[pyo3(signature = (message, digestmod = "sha256", mgf_digestmod = None,
                        label = Bytes::empty()))]
    fn encrypt_oaep<'py>(&self, py: Python<'py>, message: Bytes, digestmod: &str,
                         mgf_digestmod: Option<&str>, label: Bytes)
                         -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.encrypt_oaep(digestmod, mgf_digestmod,
                                                              &label, &message))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Verify a PKCS#1 v1.5 signature over a digest. False for a signature
    /// that is well formed and wrong; raises for one that is malformed.
    #[pyo3(signature = (digest, signature, digestmod = "sha256"))]
    fn verify(&self, py: Python<'_>, digest: Bytes, signature: Bytes, digestmod: &str)
              -> PyResult<bool> {
        py.allow_threads(|| self.inner.verify(digestmod, &digest, &signature)).map_err(err)
    }

    /// Verify a PSS signature. `salt_length` defaults to the hash's own
    /// length, which is what TLS 1.3 requires and what "PSS with the
    /// obvious parameters" means everywhere else.
    ///
    /// The length is required rather than recovered from the block: a
    /// verifier that accepts any length accepts a salt of zero, which
    /// makes PSS deterministic.
    #[pyo3(signature = (digest, signature, digestmod = "sha256", salt_length = None))]
    fn verify_pss(&self, py: Python<'_>, digest: Bytes, signature: Bytes,
                  digestmod: &str, salt_length: Option<usize>) -> PyResult<bool> {
        py.allow_threads(|| self.inner.verify_pss(digestmod, &digest, &signature,
                                                  salt_length)).map_err(err)
    }

    #[getter]
    fn n<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.modulus())
    }

    #[getter]
    fn e<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.exponent())
    }

    #[getter]
    fn key_size(&self) -> usize { self.inner.bits() }

    #[getter]
    fn size(&self) -> usize { self.inner.size() }

    fn __repr__(&self) -> String {
        format!("<allcrypt.RsaPublicKey {} bits>", self.inner.bits())
    }
}

// ---------------------------------------------------------------- SLH-DSA ---

/// An SLH-DSA key pair (FIPS 205), over the external interface.
///
/// Translation only: every byte of the scheme is in `pq::slh_dsa` and
/// `api::SlhDsaKey`, checked against NIST's 264 ACVP vectors by
/// `tests/test_slh_dsa.rs`.
#[pyclass(name = "SlhDsaKey", module = "allcrypt")]
pub struct PySlhDsaKey {
    inner: api::SlhDsaKey,
}

#[pymethods]
impl PySlhDsaKey {
    /// A fresh key pair, seeded from the OS random source.
    ///
    /// **Slow at the `s` parameter sets** - around a second, because a key
    /// is the root of a Merkle tree over 512 one-time keys and every leaf
    /// has to be computed. The GIL is released throughout.
    #[staticmethod]
    fn generate(py: Python<'_>, parameter_set: &str) -> PyResult<PySlhDsaKey> {
        let inner = py.allow_threads(|| api::SlhDsaKey::generate(parameter_set))
            .map_err(err)?;
        Ok(PySlhDsaKey { inner })
    }

    /// Import a private key: `SK.seed || SK.prf || PK.seed || PK.root`.
    ///
    /// Only the length is checked. Every byte string of the right length
    /// is a well formed SLH-DSA private key, so whether the public root
    /// inside it matches the seeds is a separate question - and an
    /// expensive one. `recompute_public()` asks it.
    #[staticmethod]
    fn from_private(py: Python<'_>, parameter_set: &str, private: Bytes)
                    -> PyResult<PySlhDsaKey> {
        let inner = py.allow_threads(
            || api::SlhDsaKey::from_private(parameter_set, &private))
            .map_err(err)?;
        Ok(PySlhDsaKey { inner })
    }

    #[getter]
    fn parameter_set(&self) -> &'static str { self.inner.parameter_set() }

    /// `SK.seed || SK.prf || PK.seed || PK.root`.
    fn private_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.private_bytes())
    }

    /// `PK.seed || PK.root`, which is the tail of the private key.
    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.public_bytes())
    }

    fn public_key(&self) -> PySlhDsaPublicKey {
        PySlhDsaPublicKey { inner: self.inner.public_key() }
    }

    /// Whether the public root inside this private key matches its seeds.
    ///
    /// Costs a whole key generation, so it is a question rather than
    /// something importing does for you. Pointless on a key this library
    /// generated; worth asking once on a key read from elsewhere.
    fn recompute_public(&self, py: Python<'_>) -> PyResult<bool> {
        py.allow_threads(|| self.inner.recompute_public()).map_err(err)
    }

    /// Sign, drawing fresh randomness - FIPS 205's hedged mode, and the
    /// one to use.
    ///
    /// `context` is a domain separator of at most 255 bytes; empty is
    /// normal. `prehash` names one of `slh_dsa_pre_hashes()`, or is left
    /// out for the pure form. A verifier has to be given the same two,
    /// because both are part of what gets signed.
    #[pyo3(signature = (message, context = None, prehash = None))]
    fn sign<'py>(&self, py: Python<'py>, message: Bytes,
                 context: Option<Bytes>, prehash: Option<&str>)
                 -> PyResult<Bound<'py, PyBytes>> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        let out = py.allow_threads(
            || self.inner.sign(&message, &context, prehash)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Sign deterministically: the same message always gives the same
    /// signature.
    ///
    /// Standard and safe - `opt_rand` is `PK.seed`, which is public - and
    /// useful when a signature has to be reproducible. `sign` is the
    /// default because a caller who has not thought about randomness is
    /// better served by real randomness than by a counter.
    #[pyo3(signature = (message, context = None, prehash = None))]
    fn sign_deterministic<'py>(&self, py: Python<'py>, message: Bytes,
                               context: Option<Bytes>, prehash: Option<&str>)
                               -> PyResult<Bound<'py, PyBytes>> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        let out = py.allow_threads(
            || self.inner.sign_deterministic(&message, &context, prehash))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Verify against this key's own public half.
    #[pyo3(signature = (message, signature, context = None, prehash = None))]
    fn verify(&self, py: Python<'_>, message: Bytes, signature: Bytes,
              context: Option<Bytes>, prehash: Option<&str>) -> PyResult<bool> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        py.allow_threads(
            || self.inner.verify(&message, &context, prehash, &signature))
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.SlhDsaKey {}>", self.inner.parameter_set())
    }
}

/// The verifying half of an SLH-DSA key: `PK.seed || PK.root`.
#[pyclass(name = "SlhDsaPublicKey", module = "allcrypt")]
pub struct PySlhDsaPublicKey {
    inner: api::SlhDsaPublicKey,
}

#[pymethods]
impl PySlhDsaPublicKey {
    #[staticmethod]
    fn from_public(py: Python<'_>, parameter_set: &str, public: Bytes)
                   -> PyResult<PySlhDsaPublicKey> {
        let inner = py.allow_threads(
            || api::SlhDsaPublicKey::from_public(parameter_set, &public))
            .map_err(err)?;
        Ok(PySlhDsaPublicKey { inner })
    }

    #[getter]
    fn parameter_set(&self) -> &'static str { self.inner.parameter_set() }

    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.public_bytes())
    }

    /// `False` for a signature that is well formed and wrong; raises only
    /// for an input that could never be one - a context over 255 bytes, or
    /// a pre-hash name that is not one of the twelve.
    #[pyo3(signature = (message, signature, context = None, prehash = None))]
    fn verify(&self, py: Python<'_>, message: Bytes, signature: Bytes,
              context: Option<Bytes>, prehash: Option<&str>) -> PyResult<bool> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        py.allow_threads(
            || self.inner.verify(&message, &context, prehash, &signature))
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.SlhDsaPublicKey {}>", self.inner.parameter_set())
    }
}

/// The twelve SLH-DSA parameter sets, as FIPS 205 names them.
#[pyfunction]
fn slh_dsa_parameter_sets() -> Vec<&'static str> {
    api::slh_dsa_parameter_sets()
}

/// The twelve approved pre-hash function names.
#[pyfunction]
fn slh_dsa_pre_hashes() -> Vec<&'static str> {
    api::slh_dsa_pre_hashes()
}

// ----------------------------------------------------------------- ML-KEM ---

/// An ML-KEM decapsulation key (FIPS 203): the half that recovers shared
/// secrets.
///
/// Translation only: every byte of the scheme is in `pq::ml_kem` and
/// `api::MlKemKey`, checked against NIST's 195 ACVP vectors by
/// `tests/test_ml_kem.rs`.
#[pyclass(name = "MlKemKey", module = "allcrypt")]
pub struct PyMlKemKey {
    inner: api::MlKemKey,
}

#[pymethods]
impl PyMlKemKey {
    /// A fresh key pair, seeded from the OS random source.
    #[staticmethod]
    fn generate(py: Python<'_>, parameter_set: &str) -> PyResult<PyMlKemKey> {
        let inner = py.allow_threads(|| api::MlKemKey::generate(parameter_set))
            .map_err(err)?;
        Ok(PyMlKemKey { inner })
    }

    /// Rebuild a key pair from its 64 byte seed `d || z`. The seed is as
    /// secret as the key.
    #[staticmethod]
    fn from_seed(py: Python<'_>, parameter_set: &str, seed: Bytes)
                 -> PyResult<PyMlKemKey> {
        let inner = py.allow_threads(
            || api::MlKemKey::from_seed(parameter_set, &seed)).map_err(err)?;
        Ok(PyMlKemKey { inner })
    }

    /// Import an expanded decapsulation key. Raises if it fails FIPS 203's
    /// hash check - the `H(ek)` it carries must match the `ek` it carries.
    #[staticmethod]
    fn from_private(py: Python<'_>, parameter_set: &str, private: Bytes)
                    -> PyResult<PyMlKemKey> {
        let inner = py.allow_threads(
            || api::MlKemKey::from_private(parameter_set, &private))
            .map_err(err)?;
        Ok(PyMlKemKey { inner })
    }

    #[getter]
    fn parameter_set(&self) -> &'static str { self.inner.parameter_set() }

    /// `dk_pke || ek || H(ek) || z`.
    fn private_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.private_bytes())
    }

    /// `ek`, which is carried inside the decapsulation key.
    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.public_bytes())
    }

    fn public_key(&self) -> PyMlKemPublicKey {
        PyMlKemPublicKey { inner: self.inner.public_key() }
    }

    /// The 32 byte shared secret for `ciphertext`.
    ///
    /// **Never raises for a ciphertext that was altered or made for
    /// another key**: that gives a different secret, and the two sides
    /// disagree. Raising would be a decryption oracle. Raises only for a
    /// ciphertext of the wrong length.
    fn decapsulate<'py>(&self, py: Python<'py>, ciphertext: Bytes)
                        -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(|| self.inner.decapsulate(&ciphertext))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.MlKemKey {}>", self.inner.parameter_set())
    }
}

/// An ML-KEM encapsulation key: the half that makes shared secrets.
#[pyclass(name = "MlKemPublicKey", module = "allcrypt")]
pub struct PyMlKemPublicKey {
    inner: api::MlKemPublicKey,
}

#[pymethods]
impl PyMlKemPublicKey {
    /// Import an encapsulation key. Raises if it fails FIPS 203's modulus
    /// check - a coefficient encoded at or above q.
    #[staticmethod]
    fn from_public(py: Python<'_>, parameter_set: &str, public: Bytes)
                   -> PyResult<PyMlKemPublicKey> {
        let inner = py.allow_threads(
            || api::MlKemPublicKey::from_public(parameter_set, &public))
            .map_err(err)?;
        Ok(PyMlKemPublicKey { inner })
    }

    #[getter]
    fn parameter_set(&self) -> &'static str { self.inner.parameter_set() }

    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.public_bytes())
    }

    /// `(shared_secret, ciphertext)`: keep the first, send the second.
    fn encapsulate<'py>(&self, py: Python<'py>)
                        -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let (shared, ciphertext) = py.allow_threads(|| self.inner.encapsulate())
            .map_err(err)?;
        Ok((PyBytes::new(py, &shared), PyBytes::new(py, &ciphertext)))
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.MlKemPublicKey {}>", self.inner.parameter_set())
    }
}

/// The three ML-KEM parameter sets, as FIPS 203 names them.
#[pyfunction]
fn ml_kem_parameter_sets() -> Vec<&'static str> {
    api::ml_kem_parameter_sets()
}

// ----------------------------------------------------------------- ML-DSA ---

/// An ML-DSA key pair (FIPS 204), over the external interface.
///
/// Translation only: every byte of the scheme is in `pq::ml_dsa` and
/// `api::MlDsaKey`, checked against NIST's ACVP vectors by
/// `tests/test_ml_dsa.rs`.
#[pyclass(name = "MlDsaKey", module = "allcrypt")]
pub struct PyMlDsaKey {
    /// Shared, so that a `TlsServer` built from this key holds the same
    /// one rather than a copy of a few kilobytes of secret.
    inner: std::sync::Arc<api::MlDsaKey>,
}

#[pymethods]
impl PyMlDsaKey {
    /// A fresh key pair from a 32 byte seed drawn from the OS.
    #[staticmethod]
    fn generate(py: Python<'_>, parameter_set: &str) -> PyResult<PyMlDsaKey> {
        let inner = py.allow_threads(|| api::MlDsaKey::generate(parameter_set))
            .map_err(err)?;
        Ok(PyMlDsaKey { inner: std::sync::Arc::new(inner) })
    }

    /// Rebuild a key pair from its 32 byte seed. The seed is as secret as
    /// the key.
    #[staticmethod]
    fn from_seed(py: Python<'_>, parameter_set: &str, seed: Bytes)
                 -> PyResult<PyMlDsaKey> {
        let inner = py.allow_threads(
            || api::MlDsaKey::from_seed(parameter_set, &seed)).map_err(err)?;
        Ok(PyMlDsaKey { inner: std::sync::Arc::new(inner) })
    }

    /// Import an expanded private key. The public key is recomputed from
    /// it, and a key whose parts do not belong together raises.
    #[staticmethod]
    fn from_private(py: Python<'_>, parameter_set: &str, private: Bytes)
                    -> PyResult<PyMlDsaKey> {
        let inner = py.allow_threads(
            || api::MlDsaKey::from_private(parameter_set, &private))
            .map_err(err)?;
        Ok(PyMlDsaKey { inner: std::sync::Arc::new(inner) })
    }

    #[getter]
    fn parameter_set(&self) -> &'static str { self.inner.parameter_set() }

    /// The 32 byte seed, or `None` for a key imported in expanded form.
    fn seed<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.seed().map(|seed| PyBytes::new(py, seed))
    }

    fn private_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.private_bytes())
    }

    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.public_bytes())
    }

    fn public_key(&self) -> PyMlDsaPublicKey {
        PyMlDsaPublicKey { inner: self.inner.public_key() }
    }

    /// Sign with fresh randomness - FIPS 204's hedged mode, and the one to
    /// use. `context` is at most 255 bytes; `prehash` names one of the
    /// twelve approved functions or is left out for the pure form.
    #[pyo3(signature = (message, context = None, prehash = None))]
    fn sign<'py>(&self, py: Python<'py>, message: Bytes,
                 context: Option<Bytes>, prehash: Option<&str>)
                 -> PyResult<Bound<'py, PyBytes>> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        let out = py.allow_threads(
            || self.inner.sign(&message, &context, prehash)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// Sign deterministically: the same message always gives the same
    /// signature.
    #[pyo3(signature = (message, context = None, prehash = None))]
    fn sign_deterministic<'py>(&self, py: Python<'py>, message: Bytes,
                               context: Option<Bytes>, prehash: Option<&str>)
                               -> PyResult<Bound<'py, PyBytes>> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        let out = py.allow_threads(
            || self.inner.sign_deterministic(&message, &context, prehash))
            .map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[pyo3(signature = (message, signature, context = None, prehash = None))]
    fn verify(&self, py: Python<'_>, message: Bytes, signature: Bytes,
              context: Option<Bytes>, prehash: Option<&str>) -> PyResult<bool> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        py.allow_threads(
            || self.inner.verify(&message, &context, prehash, &signature))
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.MlDsaKey {}>", self.inner.parameter_set())
    }
}

/// The verifying half of an ML-DSA key.
#[pyclass(name = "MlDsaPublicKey", module = "allcrypt")]
pub struct PyMlDsaPublicKey {
    inner: api::MlDsaPublicKey,
}

#[pymethods]
impl PyMlDsaPublicKey {
    #[staticmethod]
    fn from_public(py: Python<'_>, parameter_set: &str, public: Bytes)
                   -> PyResult<PyMlDsaPublicKey> {
        let inner = py.allow_threads(
            || api::MlDsaPublicKey::from_public(parameter_set, &public))
            .map_err(err)?;
        Ok(PyMlDsaPublicKey { inner })
    }

    #[getter]
    fn parameter_set(&self) -> &'static str { self.inner.parameter_set() }

    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.public_bytes())
    }

    /// `False` for a wrong signature - including a wrong length or a
    /// malformed hint; raises only for a context over 255 bytes or an
    /// unknown pre-hash name.
    #[pyo3(signature = (message, signature, context = None, prehash = None))]
    fn verify(&self, py: Python<'_>, message: Bytes, signature: Bytes,
              context: Option<Bytes>, prehash: Option<&str>) -> PyResult<bool> {
        let context = context.map(|c| c.to_vec()).unwrap_or_default();
        py.allow_threads(
            || self.inner.verify(&message, &context, prehash, &signature))
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.MlDsaPublicKey {}>", self.inner.parameter_set())
    }
}

/// The three ML-DSA parameter sets, as FIPS 204 names them.
#[pyfunction]
fn ml_dsa_parameter_sets() -> Vec<&'static str> {
    api::ml_dsa_parameter_sets()
}

// -------------------------------------------------------------------- SSH ---

/// An SSH private key: Ed25519, ECDSA on P-256/384/521, or RSA.
///
/// Reads and writes OpenSSH's own `openssh-key-v1` files, plain or
/// encrypted (bcrypt_pbkdf and any of OpenSSH's ciphers), and signs in
/// SSH's signature format or as SSHSIG (`ssh-keygen -Y sign`). Checked
/// both ways against OpenSSH 10.0's `ssh-keygen`.
#[pyclass(name = "SshKey", module = "allcrypt")]
pub struct PySshKey {
    inner: crate::ssh::private_key::PrivateKey,
    comment: String,
}

#[pymethods]
impl PySshKey {
    /// A fresh key. `kind` is `"ed25519"`, `"ecdsa"` or `"rsa"` as
    /// `ssh-keygen -t` has them, or a key type name. `bits` picks the
    /// curve (256, 384, 521) or the RSA modulus (default 3072).
    #[staticmethod]
    #[pyo3(signature = (kind = "ed25519", bits = None, comment = ""))]
    fn generate(py: Python<'_>, kind: &str, bits: Option<usize>, comment: &str)
                -> PyResult<PySshKey> {
        let inner = py.allow_threads(
            || crate::ssh::private_key::PrivateKey::generate(kind, bits)).map_err(err)?;
        Ok(PySshKey { inner, comment: comment.to_string() })
    }

    /// Read an `-----BEGIN OPENSSH PRIVATE KEY-----` file. The
    /// passphrase is needed only if it is encrypted. A wrong one raises.
    #[staticmethod]
    #[pyo3(signature = (text, passphrase = None))]
    fn from_openssh(py: Python<'_>, text: &str, passphrase: Option<Bytes>)
                    -> PyResult<PySshKey> {
        let (inner, comment) = py.allow_threads(
            || crate::ssh::private_key::read(text, passphrase.as_deref()))
            .map_err(err)?;
        Ok(PySshKey { inner, comment })
    }

    /// The key as an `openssh-key-v1` file. With a passphrase it is
    /// encrypted under `cipher` with `rounds` of bcrypt_pbkdf, which are
    /// `ssh-keygen`'s defaults.
    #[pyo3(signature = (passphrase = None, cipher = "aes256-ctr", rounds = 16))]
    fn to_openssh(&self, py: Python<'_>, passphrase: Option<Bytes>, cipher: &str,
                  rounds: u32) -> PyResult<String> {
        py.allow_threads(|| {
            let encryption = passphrase.as_deref().map(|passphrase| {
                crate::ssh::private_key::Encryption { cipher, passphrase, rounds }
            });
            crate::ssh::private_key::write(&self.inner, &self.comment, encryption.as_ref())
        }).map_err(err)
    }

    #[getter]
    fn comment(&self) -> &str { &self.comment }

    #[setter]
    fn set_comment(&mut self, comment: String) { self.comment = comment; }

    fn public_key(&self) -> PySshPublicKey {
        PySshPublicKey { inner: self.inner.public(), comment: self.comment.clone(),
                         options: String::new() }
    }

    /// An SSH signature blob over `data`. `algorithm` matters only for
    /// RSA: `"rsa-sha2-512"` (the default), `"rsa-sha2-256"`, or
    /// `"ssh-rsa"` for SHA-1, which old servers need.
    #[pyo3(signature = (data, algorithm = None))]
    fn sign<'py>(&self, py: Python<'py>, data: Bytes, algorithm: Option<&str>)
                 -> PyResult<Bound<'py, PyBytes>> {
        let out = py.allow_threads(
            || crate::ssh::signature::sign(&self.inner, &data, algorithm)).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    /// `ssh-keygen -Y sign -n <namespace>`: an armoured SSHSIG.
    #[pyo3(signature = (message, namespace = "file", hash = "sha512"))]
    fn sshsig(&self, py: Python<'_>, message: Bytes, namespace: &str, hash: &str)
              -> PyResult<String> {
        py.allow_threads(
            || crate::ssh::signature::sshsig_sign(&self.inner, namespace, &message, hash))
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        let public = self.inner.public();
        format!("<allcrypt.SshKey {} {}>", public.algorithm(), public.fingerprint_sha256())
    }
}

/// An SSH public key, as a `.pub` / `authorized_keys` line or a blob.
#[pyclass(name = "SshPublicKey", module = "allcrypt")]
pub struct PySshPublicKey {
    inner: crate::ssh::keys::PublicKey,
    comment: String,
    options: String,
}

#[pymethods]
impl PySshPublicKey {
    /// One line of a `.pub` or `authorized_keys` file, options and all.
    #[staticmethod]
    fn from_line(line: &str) -> PyResult<PySshPublicKey> {
        let read = crate::ssh::keys::parse_line(line).map_err(err)?;
        Ok(PySshPublicKey { inner: read.key, comment: read.comment.to_string(),
                            options: read.options.to_string() })
    }

    /// The binary blob, as SSH sends it.
    #[staticmethod]
    fn from_blob(blob: Bytes) -> PyResult<PySshPublicKey> {
        let inner = crate::ssh::keys::PublicKey::from_blob(&blob).map_err(err)?;
        Ok(PySshPublicKey { inner, comment: String::new(), options: String::new() })
    }

    #[getter]
    fn blob<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_blob())
    }

    /// The key type: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, ...
    #[getter]
    fn algorithm(&self) -> &'static str { self.inner.algorithm() }

    #[getter]
    fn bits(&self) -> usize { self.inner.bits() }

    #[getter]
    fn comment(&self) -> &str { &self.comment }

    /// The `authorized_keys` options field, as written, or empty.
    #[getter]
    fn options(&self) -> &str { &self.options }

    /// `SHA256:...` as `ssh-keygen -l` prints it, or with
    /// `hash="md5"`, the colon-separated form older clients print.
    #[pyo3(signature = (hash = "sha256"))]
    fn fingerprint(&self, hash: &str) -> PyResult<String> {
        match hash {
            "sha256" => Ok(self.inner.fingerprint_sha256()),
            "md5" => Ok(self.inner.fingerprint_md5()),
            other => Err(err(format!("SSH fingerprints are sha256 or md5, not {other:?}."))),
        }
    }

    /// The `type base64 comment` line; `comment` defaults to the one read.
    #[pyo3(signature = (comment = None))]
    fn to_line(&self, comment: Option<&str>) -> String {
        self.inner.to_openssh(comment.unwrap_or(&self.comment))
    }

    /// Verify a signature blob. `False` for one that does not verify;
    /// raises for one that cannot be read or names an algorithm this key
    /// does not sign with.
    fn verify(&self, py: Python<'_>, data: Bytes, signature: Bytes) -> PyResult<bool> {
        py.allow_threads(|| crate::ssh::signature::verify(&self.inner, &data, &signature))
            .map(|verified| verified.is_some()).map_err(err)
    }

    fn __eq__(&self, other: &PySshPublicKey) -> bool { self.inner == other.inner }

    fn __repr__(&self) -> String {
        format!("<allcrypt.SshPublicKey {} {}>", self.inner.algorithm(),
                self.inner.fingerprint_sha256())
    }
}

/// An SSH client connection, sans-I/O: bytes in, bytes out.
///
/// The caller owns the socket. Everything `ssh::client` does: key
/// exchange (post-quantum by default), the host key checked against what
/// the caller expects, public key or password authentication, and one
/// command on a session channel. `allcrypt_ssh.run` drives it over a
/// socket.
#[pyclass(name = "SshClient", module = "allcrypt")]
pub struct PySshClient {
    inner: crate::ssh::client::Client,
}

fn leak_names(names: Option<Vec<String>>) -> Option<Vec<&'static str>> {
    // The algorithm tables hold `&'static str`, and every name accepted
    // is one of their entries - so look the entry up rather than leak.
    names.map(|names| names.into_iter().map(|name| static_name(&name)).collect())
}

fn static_name(name: &str) -> &'static str {
    use crate::ssh::{cipher, kex, mac};
    kex::METHODS.iter().map(|m| m.name)
        .chain(cipher::CIPHERS.iter().map(|c| c.name))
        .chain(mac::MACS.iter().map(|m| m.name))
        .chain(["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"])
        .find(|known| *known == name)
        // An unknown name stays unknown: negotiation will refuse it with
        // the server's list beside ours, which is the better message.
        .unwrap_or("unknown")
}

#[pymethods]
impl PySshClient {
    /// `host_key` is what the server must present: an `SshPublicKey`, a
    /// fingerprint string (`SHA256:...` or `MD5:...`), or `None` to accept
    /// any key and read it afterwards from `host_key` - for a first
    /// connection, after which the caller should pin it.
    ///
    /// `keys` are `SshKey`s tried in order, then `password` if given.
    /// The algorithm lists replace the defaults; legacy algorithms
    /// (`diffie-hellman-group1-sha1`, `3des-cbc`, `hmac-md5`, `ssh-rsa`
    /// host keys) are reached by naming them here.
    #[new]
    #[pyo3(signature = (user, host_key = None, keys = vec![], password = None,
                        kex = None, ciphers = None, macs = None,
                        host_key_algorithms = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(user: &str, host_key: Option<&Bound<'_, PyAny>>,
           keys: Vec<PyRef<'_, PySshKey>>, password: Option<String>,
           kex: Option<Vec<String>>, ciphers: Option<Vec<String>>,
           macs: Option<Vec<String>>, host_key_algorithms: Option<Vec<String>>)
           -> PyResult<PySshClient> {
        use crate::ssh::client::{Auth, Client, ClientConfig, HostKeyCheck};
        let check = match host_key {
            None => HostKeyCheck::AcceptAny,
            Some(value) => {
                if let Ok(key) = value.extract::<PyRef<'_, PySshPublicKey>>() {
                    HostKeyCheck::Key(key.inner.clone())
                } else if let Ok(fingerprint) = value.extract::<String>() {
                    HostKeyCheck::Fingerprint(fingerprint)
                } else {
                    return Err(PyTypeError::new_err(
                        "host_key is an SshPublicKey, a fingerprint string, or None."));
                }
            }
        };
        let mut config = ClientConfig::new(user, check);
        for key in keys {
            config.auth.push(Auth::PublicKey(key.inner.clone()));
        }
        if let Some(password) = password {
            config.auth.push(Auth::Password(password));
        }
        if let Some(list) = leak_names(kex) { config.kex = list; }
        if let Some(list) = leak_names(ciphers) { config.ciphers = list; }
        if let Some(list) = leak_names(macs) { config.macs = list; }
        if let Some(list) = leak_names(host_key_algorithms) { config.host_key_algorithms = list; }
        Ok(PySshClient { inner: Client::new(config).map_err(err)? })
    }

    /// The command to run once authenticated. Call before the first
    /// `process`.
    fn exec(&mut self, command: &str) {
        self.inner.exec(command);
    }

    fn push_incoming(&mut self, data: Bytes) {
        self.inner.push_incoming(&data);
    }

    /// Handle what has arrived. Raises `CryptoError` on anything the
    /// connection cannot survive, the host key not matching included.
    fn process(&mut self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.inner.process()).map_err(err)
    }

    fn take_outgoing<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_outgoing())
    }

    fn take_stdout<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_stdout())
    }

    fn take_stderr<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_stderr())
    }

    /// Data for the command's standard input.
    fn write(&mut self, data: Bytes) -> PyResult<()> {
        self.inner.write(&data).map_err(err)
    }

    fn send_eof(&mut self) -> PyResult<()> {
        self.inner.send_eof().map_err(err)
    }

    #[getter]
    fn exit_status(&self) -> Option<u32> { self.inner.exit_status() }

    #[getter]
    fn closed(&self) -> bool { self.inner.closed() }

    #[getter]
    fn authenticated(&self) -> bool { self.inner.authenticated() }

    #[getter]
    fn strict_kex(&self) -> bool { self.inner.strict_kex() }

    #[getter]
    fn banner(&self) -> &str { self.inner.banner() }

    /// The server's host key, once the key exchange has seen it.
    #[getter]
    fn host_key(&self) -> Option<PySshPublicKey> {
        self.inner.host_key().map(|key| PySshPublicKey {
            inner: key.clone(), comment: String::new(), options: String::new() })
    }

    #[getter]
    fn server_version(&self) -> String {
        String::from_utf8_lossy(self.inner.server_version()).into_owned()
    }

    /// What was negotiated, as a dict.
    fn algorithms<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let a = self.inner.algorithms();
        let out = PyDict::new(py);
        out.set_item("kex", &a.kex)?;
        out.set_item("host_key", &a.host_key)?;
        out.set_item("cipher_client_to_server", &a.cipher_c2s)?;
        out.set_item("cipher_server_to_client", &a.cipher_s2c)?;
        out.set_item("mac_client_to_server", a.mac_c2s.as_deref())?;
        out.set_item("mac_server_to_client", a.mac_s2c.as_deref())?;
        Ok(out)
    }
}

/// An SSH server connection, sans-I/O: bytes in, bytes out.
///
/// The caller owns the socket and decides what a command does. Everything
/// `ssh::server` does: key exchange (post-quantum by default) signed with
/// the host keys, public key and password authentication, and one session
/// channel whose request, terminal and standard input the caller reads
/// and whose output and exit status it writes. `allcrypt_ssh.serve`
/// drives it over a socket.
#[pyclass(name = "SshServer", module = "allcrypt")]
pub struct PySshServer {
    inner: crate::ssh::server::Server,
}

#[pymethods]
impl PySshServer {
    /// `host_keys` are `SshKey`s; each serves the algorithms it can sign
    /// under. `authorized` is a list of `(user, credential)` pairs, the
    /// credential an `SshPublicKey` or a password string. The algorithm
    /// lists replace the defaults, as for `SshClient`.
    #[new]
    #[pyo3(signature = (host_keys, authorized = vec![], kex = None, ciphers = None,
                        macs = None, host_key_algorithms = None, banner = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(host_keys: Vec<PyRef<'_, PySshKey>>,
           authorized: Vec<(String, Bound<'_, PyAny>)>,
           kex: Option<Vec<String>>, ciphers: Option<Vec<String>>,
           macs: Option<Vec<String>>, host_key_algorithms: Option<Vec<String>>,
           banner: Option<String>) -> PyResult<PySshServer> {
        use crate::ssh::server::{Server, ServerConfig};
        let mut config = ServerConfig::new(host_keys.iter().map(|k| k.inner.clone()).collect());
        for (user, credential) in authorized {
            if let Ok(key) = credential.extract::<PyRef<'_, PySshPublicKey>>() {
                config.authorize_key(&user, key.inner.clone());
            } else if let Ok(password) = credential.extract::<String>() {
                config.authorize_password(&user, &password);
            } else {
                return Err(PyTypeError::new_err(
                    "each authorized entry is (user, SshPublicKey) or (user, password)."));
            }
        }
        if let Some(list) = leak_names(kex) { config.kex = list; }
        if let Some(list) = leak_names(ciphers) { config.ciphers = list; }
        if let Some(list) = leak_names(macs) { config.macs = list; }
        if let Some(list) = leak_names(host_key_algorithms) { config.host_key_algorithms = list; }
        config.banner = banner;
        Ok(PySshServer { inner: Server::new(config).map_err(err)? })
    }

    fn push_incoming(&mut self, data: Bytes) {
        self.inner.push_incoming(&data);
    }

    /// Handle what has arrived. Raises `CryptoError` on anything the
    /// connection cannot survive; the DISCONNECT saying why is then in
    /// `take_outgoing`.
    fn process(&mut self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.inner.process()).map_err(err)
    }

    fn take_outgoing<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_outgoing())
    }

    /// Standard input received so far; taking it lets the client send
    /// more.
    fn take_stdin<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.inner.take_stdin().map_err(err)?))
    }

    /// Standard output for the client.
    fn write(&mut self, data: Bytes) -> PyResult<()> {
        self.inner.write(&data).map_err(err)
    }

    fn write_stderr(&mut self, data: Bytes) -> PyResult<()> {
        self.inner.write_stderr(&data).map_err(err)
    }

    /// End the session with this exit status, once what was written has
    /// gone.
    fn finish(&mut self, exit_status: u32) -> PyResult<()> {
        self.inner.finish(exit_status).map_err(err)
    }

    /// Start a key re-exchange.
    fn rekey(&mut self) -> PyResult<()> {
        self.inner.rekey().map_err(err)
    }

    /// `("exec", command)`, `("shell", None)`, or `None` before the
    /// client has asked.
    #[getter]
    fn request(&self) -> Option<(&'static str, Option<String>)> {
        use crate::ssh::server::SessionRequest;
        self.inner.request().map(|request| match request {
            SessionRequest::Exec(command) => ("exec", Some(command.clone())),
            SessionRequest::Shell => ("shell", None),
        })
    }

    /// `(term, columns, rows)` if the client asked for a terminal.
    #[getter]
    fn terminal(&self) -> Option<(String, u32, u32)> {
        self.inner.terminal().map(|t| (t.term.clone(), t.columns, t.rows))
    }

    /// The `env` requests, as `(name, value)` pairs.
    #[getter]
    fn environment(&self) -> Vec<(String, String)> {
        self.inner.environment().to_vec()
    }

    #[getter]
    fn stdin_closed(&self) -> bool { self.inner.stdin_closed() }

    #[getter]
    fn user(&self) -> Option<&str> { self.inner.user() }

    /// `"password"`, or `"publickey "` and the signature algorithm.
    #[getter]
    fn auth_method(&self) -> Option<&str> { self.inner.auth_method() }

    #[getter]
    fn closed(&self) -> bool { self.inner.closed() }

    #[getter]
    fn strict_kex(&self) -> bool { self.inner.strict_kex() }

    #[getter]
    fn key_exchanges(&self) -> u32 { self.inner.key_exchanges() }

    #[getter]
    fn client_version(&self) -> String {
        String::from_utf8_lossy(self.inner.client_version()).into_owned()
    }

    /// What was negotiated, as a dict with `SshClient.algorithms`' keys.
    fn algorithms<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let a = self.inner.algorithms();
        let out = PyDict::new(py);
        out.set_item("kex", &a.kex)?;
        out.set_item("host_key", &a.host_key)?;
        out.set_item("cipher_client_to_server", &a.cipher_c2s)?;
        out.set_item("cipher_server_to_client", &a.cipher_s2c)?;
        out.set_item("mac_client_to_server", a.mac_c2s.as_deref())?;
        out.set_item("mac_server_to_client", a.mac_s2c.as_deref())?;
        Ok(out)
    }
}

/// `ssh-keygen -Y check-novalidate`: verify an SSHSIG over `message`
/// under `namespace`, and return the key that made it. Whether that key
/// is one to trust is the caller's decision - which is what an
/// allowed-signers file is for.
#[pyfunction]
#[pyo3(signature = (signature, message, namespace = "file"))]
fn sshsig_verify(py: Python<'_>, signature: &str, message: Bytes, namespace: &str)
                 -> PyResult<PySshPublicKey> {
    let inner = py.allow_threads(
        || crate::ssh::signature::sshsig_verify(signature, namespace, &message))
        .map_err(err)?;
    Ok(PySshPublicKey { inner, comment: String::new(), options: String::new() })
}

// ------------------------------------------------------------------ X.509 ---

/// A parsed X.509 certificate.
#[pyclass(name = "Certificate", module = "allcrypt")]
pub struct PyCertificate {
    inner: api::Certificate,
}

#[pymethods]
impl PyCertificate {
    /// Parse DER. Raises if the certificate is malformed - which includes
    /// things a lenient parser would let through, such as a duplicate
    /// extension or a name with an embedded NUL.
    #[new]
    fn py_new(der: Bytes) -> PyResult<PyCertificate> {
        Ok(PyCertificate { inner: api::Certificate::parse(&der).map_err(err)? })
    }

    /// Everything, as a dict shaped like Python's `ssl.getpeercert()` where
    /// the fields line up, with the rest added.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let info = self.inner.info().map_err(err)?;
        let dict = PyDict::new(py);

        // `subject` and `issuer` in ssl.getpeercert() are a tuple of
        // one-element tuples of (name, value) pairs. Keeping that shape
        // means existing code that reads a peer certificate keeps working.
        let as_nested = |pairs: &[(String, String)]| -> Vec<Vec<(String, String)>> {
            pairs.iter().map(|pair| vec![pair.clone()]).collect()
        };

        dict.set_item("version", info.version)?;
        dict.set_item("serialNumber", info.serial.to_uppercase())?;
        dict.set_item("notBefore", info.not_before)?;
        dict.set_item("notAfter", info.not_after)?;
        dict.set_item("subject", as_nested(&info.subject))?;
        dict.set_item("issuer", as_nested(&info.issuer))?;
        dict.set_item("subjectAltName", info.subject_alt_names.clone())?;
        dict.set_item("commonName", info.subject_common_name.clone())?;
        dict.set_item("issuerCommonName", info.issuer_common_name.clone())?;
        dict.set_item("signatureAlgorithm", info.signature_algorithm.clone())?;
        dict.set_item("publicKeyType", info.public_key_type.clone())?;
        dict.set_item("publicKeyBits", info.public_key_bits)?;
        // Not in `ssl.getpeercert()`, because OpenSSL's GOST support is
        // an engine and CPython never grew a field for this. It is here
        // because `publicKeyType` cannot express it: see
        // `api::CertificateInfo::public_key_parameter_set`.
        dict.set_item("publicKeyParameterSet",
                      info.public_key_parameter_set.clone())?;
        dict.set_item("isCA", info.is_ca)?;
        dict.set_item("pathLen", info.path_len)?;
        dict.set_item("keyUsage", info.key_usage.clone())?;
        dict.set_item("extendedKeyUsage", info.extended_key_usage.clone())?;
        dict.set_item("unrecognisedCritical", info.unrecognised_critical.clone())?;
        Ok(dict)
    }

    /// Does this certificate cover `hostname`? RFC 6125: a subjectAltName
    /// wins over the common name, a wildcard covers exactly one label and
    /// only the leftmost one.
    fn matches_hostname(&self, hostname: &str) -> PyResult<bool> {
        self.inner.matches_hostname(hostname).map_err(err)
    }

    /// The certificate as it arrived.
    #[getter]
    fn der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.der())
    }

    /// The TBSCertificate bytes: what the signature covers.
    #[getter]
    fn tbs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.inner.tbs().map_err(err)?))
    }

    #[getter]
    fn subject(&self) -> PyResult<String> {
        self.inner.subject_string().map_err(err)
    }

    #[getter]
    fn issuer(&self) -> PyResult<String> {
        self.inner.issuer_string().map_err(err)
    }

    #[getter]
    fn not_before(&self) -> PyResult<i64> {
        Ok(self.inner.info().map_err(err)?.not_before)
    }

    #[getter]
    fn not_after(&self) -> PyResult<i64> {
        Ok(self.inner.info().map_err(err)?.not_after)
    }

    #[getter]
    fn is_ca(&self) -> PyResult<bool> {
        Ok(self.inner.info().map_err(err)?.is_ca)
    }

    fn __repr__(&self) -> String {
        match self.inner.subject_string() {
            Ok(subject) => format!("<allcrypt.Certificate {}>", subject),
            Err(_) => "<allcrypt.Certificate ?>".to_string(),
        }
    }
}

/// Verify a certificate chain against a set of trusted roots.
///
/// `chain` is leaf first, as a TLS peer sends it; `roots` is what you
/// already trust. Raises with the reason on any failure, rather than
/// returning False - a verification that fails silently is how this goes
/// wrong.
#[pyfunction]
#[pyo3(signature = (chain, roots, now, hostname = None, purpose = "server",
                    allow_sha1 = false, allow_md5 = false, allow_expired = false,
                    min_rsa_bits = 2048, max_chain_length = 10,
                    crls = vec![], ocsp = vec![], ocsp_nonce = None,
                    require_revocation = false))]
#[allow(clippy::too_many_arguments)]
fn verify_chain(py: Python<'_>, chain: Vec<Bytes>, roots: Vec<Bytes>, now: i64,
                hostname: Option<String>, purpose: &str, allow_sha1: bool,
                allow_md5: bool, allow_expired: bool, min_rsa_bits: usize,
                max_chain_length: usize, crls: Vec<Bytes>,
                ocsp: Vec<Bytes>, ocsp_nonce: Option<Bytes>,
                require_revocation: bool) -> PyResult<()> {
    // `VerifyOptions` owns its CRLs and OCSP responses, so these three
    // are copied where `chain` and `roots` are not. They are optional,
    // usually empty, and small; owning them is what lets the options be
    // built once and reused across chains.
    let options = api::VerifyOptions {
        now, allow_sha1, allow_md5, allow_expired, min_rsa_bits, max_chain_length,
        purpose: purpose.to_string(), hostname,
        crls: crls.iter().map(|c| c.to_vec()).collect(),
        ocsp: ocsp.iter().map(|o| o.to_vec()).collect(),
        ocsp_nonce: ocsp_nonce.map(|n| n.to_vec()),
        require_revocation,
    };
    py.allow_threads(|| api::verify_chain(&chain, &roots, &options)).map_err(err)
}

/// Where a certificate says its OCSP responder lives, as a list of URLs.
///
/// Reported, never fetched. Only the `id-ad-ocsp` entries: the other
/// access method in the same extension points at the issuer's
/// *certificate*, and an OCSP request sent there reaches a file server.
#[pyfunction]
fn ocsp_responders(der: Bytes) -> PyResult<Vec<String>> {
    api::ocsp_responders(&der).map_err(err)
}

/// An OCSP request for one certificate, as DER to POST.
///
/// `nonce` is your own random bytes and must be handed back to
/// `ocsp_status`. It is the only defence against a replayed response.
#[pyfunction]
#[pyo3(signature = (certificate, issuer, hash = "sha1", nonce = None))]
fn ocsp_request<'py>(py: Python<'py>, certificate: Bytes, issuer: Bytes,
                     hash: &str, nonce: Option<Bytes>)
                     -> PyResult<Bound<'py, PyBytes>> {
    let der = py.allow_threads(
        || api::ocsp_request(&certificate, &issuer, hash, nonce.as_deref()))
        .map_err(err)?;
    Ok(PyBytes::new(py, &der))
}

/// What an OCSP response says about one certificate, as
/// `(status, detail)`.
///
/// `status` is `"revoked"`, `"not_revoked"` or `"unknown"` - the same
/// three values `crl_status` gives, because it is the same question.
#[pyfunction]
#[pyo3(signature = (certificate, issuer, response, now, nonce = None))]
fn ocsp_status(py: Python<'_>, certificate: Bytes, issuer: Bytes,
               response: Bytes, now: i64, nonce: Option<Bytes>)
               -> PyResult<(String, String)> {
    py.allow_threads(|| api::ocsp_status(&certificate, &issuer, &response,
                                         nonce.as_deref(), now))
        .map_err(err)
}

/// Where a certificate says its CRL can be fetched, as a list of URIs.
///
/// Reported, never fetched: nothing in this library opens a socket. Get
/// the bytes yourself and pass them back as `verify_chain(crls=[...])`.
#[pyfunction]
fn crl_distribution_points(der: Bytes) -> PyResult<Vec<String>> {
    api::crl_distribution_points(&der).map_err(err)
}

/// What a CRL says about one certificate, as `(status, detail)`.
///
/// `status` is `"revoked"`, `"not_revoked"` or `"unknown"`. **Three
/// values, not a boolean**: "nothing could be established" is not
/// "fine", and every way of getting a CRL check wrong fails in that
/// direction. `detail` says which way.
#[pyfunction]
fn crl_status(py: Python<'_>, certificate: Bytes, issuer: Bytes,
              crls: Vec<Bytes>, now: i64) -> PyResult<(String, String)> {
    py.allow_threads(|| api::crl_status(&certificate, &issuer, &crls, now))
        .map_err(err)
}

// ------------------------------------------------------------ trust store ---

/// A set of trusted root certificates.
#[pyclass(name = "TrustStore", module = "allcrypt")]
pub struct PyTrustStore {
    inner: api::TrustStore,
}

impl PyTrustStore {
    pub fn store(&self) -> &api::TrustStore {
        &self.inner
    }
}

#[pymethods]
impl PyTrustStore {
    /// An empty store. Roots must be added before it will verify anything.
    #[new]
    fn py_new() -> PyTrustStore {
        PyTrustStore { inner: api::TrustStore::new() }
    }

    /// The platform's own trust store: the CA bundle files on unix, the
    /// ROOT certificate store on Windows.
    ///
    /// Raises if nothing usable was found, rather than returning an empty
    /// store - an empty store silently becomes "trust nothing" and looks
    /// like a network problem rather than a configuration one.
    #[staticmethod]
    fn system(py: Python<'_>) -> PyResult<PyTrustStore> {
        let inner = py.allow_threads(api::TrustStore::system).map_err(err)?;
        Ok(PyTrustStore { inner })
    }

    /// A PEM file of concatenated certificates - a CA bundle.
    #[staticmethod]
    fn from_file(py: Python<'_>, path: &str) -> PyResult<PyTrustStore> {
        let inner = py.allow_threads(|| api::TrustStore::from_pem_file(path))
            .map_err(err)?;
        Ok(PyTrustStore { inner })
    }

    /// A directory of PEM files, as `/etc/ssl/certs` is on most systems.
    #[staticmethod]
    fn from_directory(py: Python<'_>, path: &str) -> PyResult<PyTrustStore> {
        let inner = py.allow_threads(|| api::TrustStore::from_directory(path))
            .map_err(err)?;
        Ok(PyTrustStore { inner })
    }

    /// Add every certificate in some PEM text, returning how many were added.
    fn add_pem(&mut self, text: &str) -> PyResult<usize> {
        self.inner.add_pem(text).map_err(err)
    }

    /// Add one DER certificate.
    fn add_der(&mut self, der: Bytes) -> PyResult<()> {
        self.inner.add_der(&der).map_err(err)
    }

    /// The roots, as DER, for passing to `verify_chain`.
    #[getter]
    fn roots<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.inner.roots().iter().map(|der| PyBytes::new(py, der)).collect()
    }

    /// The subject of every root, for showing a human what is trusted.
    fn subjects(&self) -> Vec<String> {
        self.inner.subjects()
    }

    /// How many entries were found but could not be parsed. A store that
    /// quietly dropped most of its roots looks exactly like one that
    /// worked, so this is worth looking at.
    #[getter]
    fn skipped(&self) -> usize {
        self.inner.skipped()
    }

    /// Why they could not be parsed, up to the first few. The count on
    /// its own does not say whether the certificate is malformed or this
    /// library is too strict, and those have opposite remedies.
    #[getter]
    fn skipped_reasons(&self) -> Vec<String> {
        self.inner.skipped_reasons().to_vec()
    }

    #[getter]
    fn source(&self) -> String {
        self.inner.source().to_string()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.TrustStore {} roots from {}>",
                self.inner.len(), self.inner.source())
    }
}

/// Encrypt a PKCS#8 private key (DER, or PEM labelled `PRIVATE KEY`)
/// into an `EncryptedPrivateKeyInfo`: DER, or PEM labelled `ENCRYPTED
/// PRIVATE KEY` with `pem=True`. `scheme` is a PBES2 cipher or a
/// `pbe-...` scheme (`encryption_schemes()`); the salt, IV and count
/// default as `api::encrypt_private_key` says.
#[pyfunction]
#[pyo3(signature = (key, password, scheme = "aes-256-cbc", *, prf = None, iterations = None,
                    salt = None, iv = None, pem = false))]
#[allow(clippy::too_many_arguments)]
fn encrypt_private_key(py: Python<'_>, key: Bytes, password: Bytes, scheme: &str,
                       prf: Option<&str>, iterations: Option<u32>, salt: Option<Bytes>,
                       iv: Option<Bytes>, pem: bool) -> PyResult<PyObject> {
    let der = api::encrypt_private_key(&key, &password, scheme, prf, iterations,
                                       salt.as_deref(), iv.as_deref()).map_err(err)?;
    if pem {
        let text = crate::pem::wrap("ENCRYPTED PRIVATE KEY", &der);
        return Ok(PyBytes::new(py, text.as_bytes()).into_any().unbind());
    }
    Ok(PyBytes::new(py, &der).into_any().unbind())
}

/// The scheme names `encrypt_private_key` takes.
#[pyfunction]
fn encryption_schemes() -> Vec<&'static str> {
    crate::x509::encrypted_key::scheme_names()
}

/// How an encrypted private key was encrypted, without the password: a
/// dict of `scheme`, `prf` (PBES2 only, else None), `iterations`, `salt`
/// and `iv` (empty unless PBES2).
#[pyfunction]
fn private_key_encryption<'py>(py: Python<'py>, data: Bytes) -> PyResult<Bound<'py, PyDict>> {
    let p = api::private_key_encryption(&data).map_err(err)?;
    let dict = PyDict::new(py);
    dict.set_item("scheme", p.scheme)?;
    dict.set_item("prf", p.prf)?;
    dict.set_item("iterations", p.iterations)?;
    dict.set_item("salt", PyBytes::new(py, &p.salt))?;
    dict.set_item("iv", PyBytes::new(py, &p.iv))?;
    Ok(dict)
}

/// Read a private key from PEM text or DER bytes.
///
/// Returns an `EcKey`, `RsaKey`, `EddsaKey` or `MlDsaKey` - whichever the
/// file holds - so the caller passes the result straight to `TlsServer`
/// without having to know which it got.
///
/// PKCS#8 (`PRIVATE KEY`), SEC1 (`EC PRIVATE KEY`) and PKCS#1 (`RSA
/// PRIVATE KEY`) are all read, and **the bytes decide rather than the
/// label**: `openssl` will put a SEC1 body under a `PRIVATE KEY` header
/// if asked the wrong way, and a file that works everywhere else has to
/// work here.
///
/// A file holding a certificate and a key together - the usual
/// deployment shape - is fine; the certificate is skipped.
///
/// **Encrypted** keys are read too, given `password`. PBES2, the six
/// PBES1 schemes and the PKCS#12 PBEs are all understood - which between
/// them cover every `openssl pkcs8 -topk8` has ever written. Without a
/// password an encrypted key is refused by name rather than as
/// "unsupported", because the remedy is a passphrase and not a different
/// file; with the wrong one the padding check refuses it.
///
/// A password given for a key that is not encrypted is ignored, so a
/// caller need not know which of its files used one.
#[pyfunction]
#[pyo3(signature = (data, password = None))]
fn private_key(py: Python<'_>, data: Bytes, password: Option<Bytes>)
               -> PyResult<PyObject> {
    match api::parse_private_key_with_password(&data, password.as_deref())
        .map_err(err)? {
        api::PrivateKeyParts::Ec { curve, private } => {
            let inner = api::EcKey::from_private(&curve, &private).map_err(err)?;
            Ok(PyEcKey { inner }.into_pyobject(py)?.into_any().unbind())
        }
        api::PrivateKeyParts::Rsa { p, q, e } => {
            let inner = api::RsaKey::from_primes(&p, &q, &e).map_err(err)?;
            Ok(PyRsaKey { inner }.into_pyobject(py)?.into_any().unbind())
        }
        api::PrivateKeyParts::Eddsa { curve, private } => {
            let inner = api::EddsaKey::from_private(&curve, &private).map_err(err)?;
            Ok(PyEddsaKey { inner }.into_pyobject(py)?.into_any().unbind())
        }
        // No key object for these: the X25519 and X448 functions take the
        // bytes, so that is what comes back, with the curve's name.
        api::PrivateKeyParts::Xdh { curve, private } =>
            Ok((curve, PyBytes::new(py, &private)).into_pyobject(py)?.into_any().unbind()),
        // The seed when there is one, so that `seed()` answers on the
        // key that comes back.
        api::PrivateKeyParts::Dsa { p, q, g, x } => {
            let inner = api::DsaKey::from_numbers(&p, &q, &g, &x).map_err(err)?;
            Ok(PyDsaKey { inner }.into_pyobject(py)?.into_any().unbind())
        }
        api::PrivateKeyParts::MlDsa { parameter_set, seed, expanded } => {
            let inner = py.allow_threads(|| match &seed {
                Some(seed) => api::MlDsaKey::from_seed(&parameter_set, seed),
                None => api::MlDsaKey::from_private(&parameter_set, &expanded),
            }).map_err(err)?;
            Ok(PyMlDsaKey { inner: std::sync::Arc::new(inner) }.into_pyobject(py)?.into_any().unbind())
        }
    }
}


// ------------------------------------------------------- name enumerations ---

/// A member name for an algorithm name: uppercase, and anything that is
/// not a letter or digit becomes an underscore.
///
/// `aes-gcm` becomes `AES_GCM`, `sha512_224` stays `SHA512_224`,
/// `P-256` becomes `P_256`.
fn member_name(value: &str) -> String {
    let mut out: String = value.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Build a `str`-subclass enum from a list of algorithm names and add it
/// to the module.
///
/// **Generated rather than written out.** The names come from the same
/// Rust constants the `*_available` lists come from, so an enum cannot
/// drift from the catalogue: adding a mode in `api::MODES` adds the
/// member, and there is no second place to forget.
///
/// The members *are* strings - `Mode.CBC == "cbc"` is true and
/// `isinstance(Mode.CBC, str)` is true - so every existing call that
/// passes a plain string keeps working, and the enum is an aid to
/// autocomplete rather than a new type to convert at the boundary.
///
/// `__str__` is put back to `str`'s. Without that, `f"{Mode.CBC}"` is
/// `"Mode.CBC"`, because `Enum` overrides it - which would make the
/// enum members unusable in any message or path built by formatting.
/// Python 3.11's `StrEnum` does this for us; this has to work on 3.10.
fn add_name_enum(module: &Bound<'_, PyModule>, name: &str, values: &[&str])
                 -> PyResult<()> {
    let py = module.py();
    let members: Vec<Bound<'_, PyTuple>> = values.iter()
        .map(|value| PyTuple::new(py, [member_name(value), value.to_string()]))
        .collect::<PyResult<_>>()?;
    let members = PyList::new(py, members)?;

    let kwargs = PyDict::new(py);
    kwargs.set_item("type", py.get_type::<PyString>())?;
    kwargs.set_item("module", "allcrypt")?;

    let created = py.import("enum")?.getattr("Enum")?
        .call((name, members), Some(&kwargs))?;
    created.setattr("__str__", py.get_type::<PyString>().getattr("__str__")?)?;
    module.add(name, created)
}

/// Extract the certificates from PEM text, as a list of DER.
#[pyfunction]
fn pem_certificates<'py>(py: Python<'py>, text: &str)
                         -> PyResult<Vec<Bound<'py, PyBytes>>> {
    Ok(api::pem_certificates(text).map_err(err)?
        .iter().map(|der| PyBytes::new(py, der)).collect())
}

/// Wrap DER as a PEM block.
#[pyfunction]
#[pyo3(signature = (der, label = "CERTIFICATE"))]
fn pem_wrap(der: Bytes, label: &str) -> String {
    api::pem_wrap(label, &der)
}

// -------------------------------------------------------------------- TLS ---

/// The suites a selection offers, in hello order.
///
/// `selection` takes the same strings `TlsClient` does - "modern",
/// "legacy", "all", or a comma separated list of suite names - so the
/// answer is what a client built with that string would actually send.
/// Asking for a name that does not exist is an error rather than an
/// empty list, because an empty list reads as "this selection offers
/// nothing" and a typo reads as neither.
#[pyfunction]
#[pyo3(signature = (selection = "modern"))]
fn tls_suite_names(selection: &str) -> PyResult<Vec<String>> {
    api::tls_suite_names(selection).map_err(err)
}

/// The signature schemes this client offers, in preference order.
///
/// A scheme this library can verify but does not offer is unreachable:
/// a server holding only such a certificate answers `handshake_failure`,
/// which reads as a cipher suite problem. So the offered list is worth
/// being able to look at from outside.
#[pyfunction]
fn tls_signature_schemes() -> Vec<String> {
    api::tls_signature_schemes()
}

/// An `EcKey`, `RsaKey`, `EddsaKey` or `MlDsaKey` as the private half of
/// a client identity.
///
/// The same two classes a server takes, read the same way, so a caller
/// does not have to know which end it is configuring.
fn client_key_material(key: &Bound<'_, PyAny>)
                       -> PyResult<api::ClientKeyMaterial> {
    if let Ok(ec) = key.downcast::<PyEcKey>() {
        let ec = ec.borrow();
        return Ok(api::ClientKeyMaterial::Ec {
            curve: ec.inner.curve_name().to_string(),
            private: ec.inner.private_bytes().map_err(err)?,
        });
    }
    if let Ok(rsa) = key.downcast::<PyRsaKey>() {
        let rsa = rsa.borrow();
        let numbers = rsa.inner.numbers();
        let part = |want: &str| -> Vec<u8> {
            numbers.iter().find(|(name, _)| *name == want)
                .map(|(_, bytes)| bytes.clone()).unwrap_or_default()
        };
        return Ok(api::ClientKeyMaterial::Rsa {
            p: part("p"), q: part("q"), e: part("e"),
        });
    }
    if let Ok(ml_dsa) = key.downcast::<PyMlDsaKey>() {
        return Ok(api::ClientKeyMaterial::MlDsa(ml_dsa.borrow().inner.clone()));
    }
    if let Ok(eddsa) = key.downcast::<PyEddsaKey>() {
        let eddsa = eddsa.borrow();
        return Ok(api::ClientKeyMaterial::Eddsa {
            name: eddsa.inner.curve_name().to_string(),
            seed: eddsa.inner.private_bytes(),
        });
    }
    Err(PyValueError::new_err(
        "client_key must be an allcrypt.EcKey, an allcrypt.RsaKey, an \
         allcrypt.EddsaKey or an allcrypt.MlDsaKey."))
}

/// The strike register that refuses a repeated 0-RTT flight.
///
/// **One of these is shared by every connection a server serves**, the
/// way a ticket key is. A register built per connection has seen
/// nothing, so it would refuse nothing - which is the shape this class
/// exists to make impossible to write by accident.
///
/// It bounds how *often* a replay works; it cannot make 0-RTT
/// unreplayable, because early data carries nothing fresh from the
/// server by construction (RFC 8446 8.2). An attacker who reaches a
/// machine that has not seen the flight, or who waits for the entry to
/// age out of the register, still gets it through. The guarantee to
/// build on is that the application only puts things in early data that
/// may happen twice.
#[pyclass(name = "ReplayGuard", module = "allcrypt")]
pub struct PyReplayGuard {
    inner: std::sync::Arc<std::sync::Mutex<
        crate::tls::tickets::ReplayGuard>>,
}

#[pymethods]
impl PyReplayGuard {
    /// A register remembering the last `capacity` accepted flights.
    ///
    /// Size it for the 0-RTT connections expected within a ticket
    /// lifetime, not for comfort: too small means a replay outside the
    /// window succeeds, which is the thing it is for. Unbounded is not
    /// offered - that is memory an attacker chooses the size of.
    #[new]
    #[pyo3(signature = (capacity = 4096))]
    fn py_new(capacity: usize) -> PyReplayGuard {
        PyReplayGuard {
            inner: std::sync::Arc::new(std::sync::Mutex::new(
                crate::tls::tickets::ReplayGuard::with_capacity(capacity))),
        }
    }

    /// How many flights it is currently remembering.
    fn __len__(&self) -> usize {
        self.inner.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.ReplayGuard remembering {} flights>", self.__len__())
    }
}

/// A TLS client connection.
///
/// Sans-I/O: this holds no socket. Feed it the bytes that arrived with
/// `push_incoming`, call `process`, and send whatever `take_outgoing`
/// returns. Python owns the socket; this owns the protocol.
#[pyclass(name = "TlsClient", module = "allcrypt")]
pub struct PyTlsClient {
    inner: api::TlsClient,
}

#[pymethods]
impl PyTlsClient {
    /// Start a connection to `hostname` and produce the ClientHello.
    ///
    /// `roots` must hold the certificates to verify against; there is no
    /// default, because a client with no roots verifies nothing and that
    /// has to be a decision rather than an oversight. Pass `verify=False`
    /// to skip verification, which is sometimes the only way to talk to
    /// something and is reported afterwards by `certificate_verified`.
    #[new]
    #[pyo3(signature = (hostname, roots, now, ciphers = "modern", verify = true,
                        min_version = "TLSv1.2", max_version = "TLSv1.3",
                        allow_sha1 = false, allow_md5 = false,
                        allow_expired = false, verify_hostname = true,
                        min_rsa_bits = 2048, min_dh_bits = 2048,
                        check_dh_prime = false,
                        request_encrypt_then_mac = true,
                        tickets = vec![], client_certificate = None,
                        client_key = None, early_data = Bytes::empty(),
                        alpn = vec![], request_stapled_ocsp = true,
                        require_stapled_ocsp = false))]
    #[allow(clippy::too_many_arguments)]
    fn py_new(hostname: &str, roots: &PyTrustStore, now: i64, ciphers: &str,
              verify: bool, min_version: &str, max_version: &str,
              allow_sha1: bool, allow_md5: bool, allow_expired: bool,
              verify_hostname: bool, min_rsa_bits: usize, min_dh_bits: usize,
              check_dh_prime: bool, request_encrypt_then_mac: bool,
              tickets: Vec<Bytes>,
              client_certificate: Option<Vec<Bytes>>,
              client_key: Option<&Bound<'_, PyAny>>,
              early_data: Bytes, alpn: Vec<String>,
              request_stapled_ocsp: bool, require_stapled_ocsp: bool)
              -> PyResult<PyTlsClient> {
        // Two arguments rather than one pair, because that is how a
        // caller has them - and either one alone is a mistake worth
        // naming: a chain with no key cannot sign, and a key with no
        // chain has nothing to send.
        let identity = match (client_certificate, client_key) {
            (Some(chain), Some(key)) =>
                Some(api::ClientIdentity { chain: owned(chain),
                                           key: client_key_material(key)? }),
            (None, None) => None,
            _ => return Err(PyValueError::new_err(
                "client_certificate and client_key go together.")),
        };
        let options = api::TlsOptions {
            now,
            ciphers: ciphers.to_string(),
            verify,
            min_version: min_version.to_string(),
            max_version: max_version.to_string(),
            allow_sha1,
            allow_md5,
            allow_expired,
            verify_hostname,
            min_rsa_bits,
            min_dh_bits,
            check_dh_prime,
            request_encrypt_then_mac,
            tickets: owned(tickets),
            client_certificate: identity,
            early_data: early_data.to_vec(),
            alpn,
            request_stapled_ocsp,
            require_stapled_ocsp,
        };
        Ok(PyTlsClient {
            inner: api::TlsClient::new(hostname, roots.store(), &options).map_err(err)?,
        })
    }

    /// Channel binding material: `"tls-unique"` (RFC 5929, TLS 1.2 and
    /// below) or `"tls-exporter"` (RFC 9266, TLS 1.3).
    ///
    /// `None` when the negotiated version does not define that binding,
    /// or the handshake has not got there yet. Never a substitute.
    fn channel_binding<'py>(&self, py: Python<'py>, kind: &str)
                            -> PyResult<Option<Bound<'py, PyBytes>>> {
        Ok(self.inner.channel_binding(kind).map_err(err)?
            .map(|bytes| PyBytes::new(py, &bytes)))
    }

    fn push_incoming(&mut self, data: Bytes) {
        self.inner.push_incoming(&data);
    }

    /// The bytes to send, and they are taken - calling twice gives nothing
    /// the second time.
    fn take_outgoing<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_outgoing())
    }

    /// Application data received so far.
    fn take_incoming<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_incoming())
    }

    /// Advance as far as the bytes allow. Raises with the reason on any
    /// protocol failure, and the connection stays failed afterwards.
    fn process(&mut self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.inner.process()).map_err(err)
    }

    fn write(&mut self, data: Bytes) -> PyResult<()> {
        self.inner.write(&data).map_err(err)
    }

    fn close(&mut self) -> PyResult<()> {
        self.inner.close().map_err(err)
    }

    #[getter]
    fn state(&self) -> String { self.inner.state() }

    #[getter]
    fn handshaking(&self) -> bool { self.inner.is_handshaking() }

    #[getter]
    fn established(&self) -> bool { self.inner.is_established() }

    /// Take the session tickets this connection was given, as bytes to
    /// store and hand back as `tickets=` on a later connection.
    ///
    /// **These are key material.** Each is enough to resume this
    /// connection. Taken rather than read, because a ticket is offered
    /// once: offering one twice lets a passive observer link the two
    /// connections.
    ///
    /// Often empty right after the handshake - a TLS 1.3 server sends
    /// them under the application keys, so they arrive with or after
    /// the first data. Look again after a read.
    fn take_tickets<'py>(&mut self, py: Python<'py>)
                         -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let tickets = self.inner.take_tickets().map_err(err)?;
        Ok(tickets.iter().map(|t| PyBytes::new(py, t)).collect())
    }

    /// Whether this handshake resumed a previous session.
    ///
    /// A resumed TLS 1.3 connection has no certificate: the pre-shared
    /// key authenticates the server, so an empty `peer_certificates`
    /// on one is normal.
    #[getter]
    fn resumed(&self) -> bool { self.inner.resumed() }

    /// Whether the server accepted the `early_data` that was offered.
    ///
    /// False after offering is the ordinary rejection and not an error -
    /// but those bytes did not arrive, and they are **not resent for
    /// you**: whether sending them twice is acceptable is the decision
    /// that made them early data in the first place.
    #[getter]
    fn early_data_accepted(&self) -> bool { self.inner.early_data_accepted() }

    /// The application protocol the server chose, or `None`.
    ///
    /// Named like `ssl.SSLSocket.selected_alpn_protocol()`, which is
    /// the same question. `None` means the server chose none, and a
    /// server cannot choose one this client did not offer - that is
    /// refused rather than reported.
    fn selected_alpn_protocol(&self) -> Option<String> {
        self.inner.negotiated_alpn()
    }

    /// The OCSP response the server stapled, as DER, or `None`.
    ///
    /// Named like `ssl.SSLSocket.ocsp_response`... which does not
    /// exist: the standard library has `SSLContext` flags for stapling
    /// on some platforms and no way at all to read what arrived. This
    /// hands over the bytes, because a caller who asked for a staple
    /// usually wants to look at it.
    ///
    /// `None` is the ordinary case and says nothing about the
    /// certificate: most servers staple nothing. A response saying
    /// **revoked** never reaches here - it fails the handshake.
    #[getter]
    fn stapled_ocsp<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.stapled_ocsp().map(|der| PyBytes::new(py, &der))
    }

    /// The negotiated version, once there is one.
    fn version(&self) -> Option<String> { self.inner.version() }

    /// `(name, strength, key bits)`, shaped like `ssl.SSLSocket.cipher()`
    /// but with the strength label this library keeps.
    fn cipher(&self) -> Option<(String, String, usize)> { self.inner.cipher() }

    /// The chain the server sent, leaf first, as DER.
    #[getter]
    fn peer_certificates<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.inner.peer_certificates().iter()
            .map(|der| PyBytes::new(py, der)).collect()
    }

    /// Whether the chain was actually verified - so a caller does not have
    /// to remember what it configured.
    #[getter]
    fn certificate_verified(&self) -> bool { self.inner.certificate_verified() }

    #[getter]
    fn encrypt_then_mac(&self) -> bool { self.inner.uses_encrypt_then_mac() }

    /// The curve an ephemeral key exchange used, by its IANA name, or
    /// `None` for static RSA, which has no group.
    #[getter]
    fn named_group(&self) -> Option<String> { self.inner.named_group() }

    /// This session's line in the NSS key log format that Wireshark reads:
    /// ``CLIENT_RANDOM <client random hex> <master secret hex>``.
    ///
    /// ``None`` until the master secret exists. **Anyone holding this can
    /// decrypt the whole connection from a capture**, so it is a debugging
    /// tool; nothing writes it anywhere unless you do.
    #[getter]
    fn key_log_line(&self) -> Option<String> { self.inner.key_log_line() }

    #[getter]
    fn extended_master_secret(&self) -> bool {
        self.inner.uses_extended_master_secret()
    }

    /// The last alert sent or received, if any.
    #[getter]
    fn alert(&self) -> Option<String> { self.inner.alert() }

    fn __repr__(&self) -> String {
        format!("<allcrypt.TlsClient {}{}>", self.inner.state(),
                match self.inner.version() {
                    Some(version) => format!(" {}", version),
                    None => String::new(),
                })
    }
}


#[pyclass(name = "CertificateAuthority", module = "allcrypt")]
pub struct PyCertificateAuthority {
    inner: api::CertificateAuthority,
}

#[pymethods]
impl PyCertificateAuthority {
    /// Generate a CA: a fresh P-256 key and a self-signed certificate.
    ///
    /// **Installing `certificate_pem` in a browser is a serious act.**
    /// Anything holding this CA's key can then impersonate any site to
    /// that browser. Generate it on the machine that will use it, keep
    /// the key there, and remove the certificate from the store when
    /// you are done with it.
    ///
    /// `not_before` and `not_after` are ``YYYYMMDDHHMMSSZ`` and are
    /// required rather than defaulted: a proxy CA that outlives its
    /// usefulness is a key somebody forgot they installed.
    /// `key_type` is a curve name, ``"ed25519"`` or an ML-DSA parameter
    /// set (``"ML-DSA-65"``). P-256 is the
    /// default because a proxy issues a certificate while a browser
    /// waits, and it is the fastest generation here; the leaves this
    /// CA issues are of the same type as the CA itself.
    #[new]
    #[pyo3(signature = (common_name, not_before, not_after, key_type = "P-256"))]
    fn py_new(py: Python<'_>, common_name: &str, not_before: &str,
              not_after: &str, key_type: &str) -> PyResult<PyCertificateAuthority> {
        let inner = py.allow_threads(|| api::CertificateAuthority::generate_with(
            key_type, common_name, not_before, not_after)).map_err(err)?;
        Ok(PyCertificateAuthority { inner })
    }

    /// Which kind of key this CA signs with.
    #[getter]
    fn key_type(&self) -> &'static str { self.inner.key_type() }

    /// Rebuild a CA from a stored key and its certificate.
    ///
    /// The certificate is not derived from the key, and a mismatched
    /// pair is refused: a CA signing with a key its certificate does
    /// not name issues chains that verify against nothing, with both
    /// halves looking correct on their own.
    #[staticmethod]
    #[pyo3(signature = (private, certificate, key_type = "P-256"))]
    fn from_parts(private: Bytes, certificate: Bytes, key_type: &str)
                  -> PyResult<PyCertificateAuthority> {
        let inner = api::CertificateAuthority::from_parts_with(
            key_type, &private, certificate.to_vec()).map_err(err)?;
        Ok(PyCertificateAuthority { inner })
    }

    /// The CA certificate as DER.
    #[getter]
    fn certificate<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.certificate())
    }

    /// The same, PEM wrapped - what a browser or an OS store imports.
    #[getter]
    fn certificate_pem(&self) -> String { self.inner.certificate_pem() }

    /// The private scalar, big endian.
    ///
    /// **Key material.** Anything holding this can impersonate any site
    /// to anyone who trusts this CA.
    #[getter]
    fn private_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.inner.private_bytes().map_err(err)?))
    }

    #[getter]
    fn common_name(&self) -> &str { self.inner.common_name() }

    /// Issue a leaf for `host` with a fresh key.
    ///
    /// Returns ``(certificate_der, private_key)``, which is what
    /// ``TlsServer`` and ``EcKey.from_private("P-256", ...)`` take.
    ///
    /// `host` may be a name or an IP address, and they go into
    /// different kinds of subjectAltName: a verifier asked about an
    /// address looks only at the address entries, so an address written
    /// as a name matches nothing and says nothing about why.
    #[pyo3(signature = (host, not_before, not_after))]
    fn issue<'py>(&self, py: Python<'py>, host: &str, not_before: &str,
                  not_after: &str)
                  -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let (der, key) = self.inner.issue(host, not_before, not_after)
            .map_err(err)?;
        Ok((PyBytes::new(py, &der), PyBytes::new(py, &key)))
    }

    /// The key identifier of this CA's key, which is what a leaf's
    /// authorityKeyIdentifier names.
    #[getter]
    fn key_identifier<'py>(&self, py: Python<'py>)
                           -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.inner.key_identifier().map_err(err)?))
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.CertificateAuthority {:?}>", self.inner.common_name())
    }
}

#[pyclass(name = "TlsServer", module = "allcrypt")]
pub struct PyTlsServer {
    inner: api::TlsServer,
}

#[pymethods]
impl PyTlsServer {
    /// A server holding `certificate_chain` (leaf first, DER) and `key`.
    ///
    /// `key` is an `EcKey` or an `RsaKey`. It is the key object rather
    /// than its bytes because the two kinds need different numbers -
    /// a scalar and a curve for one, two primes and an exponent for the
    /// other - and a single `key=bytes` argument would have to guess
    /// which it had been given.
    ///
    /// `ciphers` is **in the server's own order of preference**: the
    /// first suite here that the client also offered is the one chosen.
    ///
    /// The ceiling is TLS 1.3. The floor is 1.2 because a server is
    /// usually the side that gets to insist; `min_version="TLSv1.0"`
    /// is how you stop insisting, and it is a decision rather than a
    /// default.
    #[new]
    #[pyo3(signature = (certificate_chain, key, ciphers = "modern",
                        min_version = "TLSv1.2", max_version = "TLSv1.3",
                        now = 0, session_tickets = 0, ticket_key = None,
                        allow_encrypt_then_mac = true,
                        allow_extended_master_secret = true,
                        request_client_certificate = false,
                        require_client_certificate = false,
                        client_roots = None,
                        max_early_data = 0, replay_guard = None,
                        alpn = vec![], require_alpn = false,
                        ocsp_response = None))]
    #[allow(clippy::too_many_arguments)]
    fn py_new(certificate_chain: Vec<Bytes>, key: &Bound<'_, PyAny>,
              ciphers: &str, min_version: &str, max_version: &str,
              now: i64, session_tickets: u8, ticket_key: Option<Bytes>,
              allow_encrypt_then_mac: bool,
              allow_extended_master_secret: bool,
              request_client_certificate: bool,
              require_client_certificate: bool,
              client_roots: Option<&PyTrustStore>,
              max_early_data: u32, replay_guard: Option<&PyReplayGuard>,
              alpn: Vec<String>, require_alpn: bool,
              ocsp_response: Option<Bytes>)
              -> PyResult<PyTlsServer> {
        // The chain is copied once, here, because every
        // `TlsServer::with_*_key` owns it: a server outlives the call
        // that built it and the Python objects these bytes came from
        // may not.
        let certificate_chain = owned(certificate_chain);
        // Requiring without asking is not a stricter setting, it is a
        // contradiction: nothing asks the client, so nothing arrives,
        // and every handshake would fail at a check for a message that
        // was never requested. Refused here rather than silently
        // treated as one or the other.
        if (require_client_certificate || client_roots.is_some())
            && !request_client_certificate {
            return Err(PyValueError::new_err(
                "require_client_certificate and client_roots need \
                 request_client_certificate."));
        }
        // **Early data without a register is refused here**, where Rust's
        // own `ServerConfig` merely documents it. The difference is that
        // a struct literal shows the field and a keyword argument that
        // was never typed shows nothing - so the Python caller has to
        // say which of the two they meant.
        if max_early_data > 0 && replay_guard.is_none() {
            return Err(PyValueError::new_err(
                "max_early_data needs a replay_guard. Pass \
                 allcrypt.ReplayGuard(), shared by every connection this \
                 server makes - a fresh one per connection has seen \
                 nothing and refuses nothing. There is deliberately no \
                 default: 0-RTT data can be replayed, and how much that \
                 matters is a question about the application."));
        }
        let options = api::TlsServerOptions {
            ciphers: ciphers.to_string(),
            min_version: min_version.to_string(),
            max_version: max_version.to_string(),
            now,
            session_tickets,
            ticket_key: ticket_key.map(|k| k.to_vec()).unwrap_or_default(),
            allow_encrypt_then_mac,
            allow_extended_master_secret,
            request_client_certificate,
            require_client_certificate,
            client_roots: client_roots.map(|store| store.store().clone()),
            max_early_data,
            replay_guard: replay_guard.map(|guard| guard.inner.clone()),
            alpn,
            require_alpn,
            ocsp_response: ocsp_response.map(|r| r.to_vec()).unwrap_or_default(),
        };
        if let Ok(ec) = key.downcast::<PyEcKey>() {
            let ec = ec.borrow();
            let private = ec.inner.private_bytes().map_err(err)?;
            let inner = api::TlsServer::with_ec_key(
                certificate_chain, ec.inner.curve_name(), &private, &options)
                .map_err(err)?;
            return Ok(PyTlsServer { inner });
        }
        if let Ok(rsa) = key.downcast::<PyRsaKey>() {
            let rsa = rsa.borrow();
            let numbers = rsa.inner.numbers();
            let part = |want: &str| -> Vec<u8> {
                numbers.iter().find(|(name, _)| *name == want)
                    .map(|(_, bytes)| bytes.clone()).unwrap_or_default()
            };
            let inner = api::TlsServer::with_rsa_key(
                certificate_chain, &part("p"), &part("q"), &part("e"),
                &options).map_err(err)?;
            return Ok(PyTlsServer { inner });
        }
        if let Ok(eddsa) = key.downcast::<PyEddsaKey>() {
            let eddsa = eddsa.borrow();
            let inner = api::TlsServer::with_eddsa_key(
                certificate_chain, eddsa.inner.curve_name(),
                &eddsa.inner.private_bytes(), &options).map_err(err)?;
            return Ok(PyTlsServer { inner });
        }
        if let Ok(ml_dsa) = key.downcast::<PyMlDsaKey>() {
            let inner = api::TlsServer::with_ml_dsa_key(
                certificate_chain, ml_dsa.borrow().inner.clone(), &options).map_err(err)?;
            return Ok(PyTlsServer { inner });
        }
        Err(PyValueError::new_err(
            "key must be an allcrypt.EcKey, allcrypt.RsaKey, allcrypt.EddsaKey or \
             allcrypt.MlDsaKey."))
    }

    fn push_incoming(&mut self, data: Bytes) {
        self.inner.push_incoming(&data);
    }

    /// The bytes to send, and they are taken - calling twice gives
    /// nothing the second time.
    fn take_outgoing<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_outgoing())
    }

    /// Application data received so far.
    fn take_incoming<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_incoming())
    }

    fn process(&mut self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.inner.process()).map_err(err)
    }

    fn write(&mut self, data: Bytes) -> PyResult<()> {
        self.inner.write(&data).map_err(err)
    }

    fn close(&mut self) -> PyResult<()> {
        self.inner.close().map_err(err)
    }

    #[getter]
    fn state(&self) -> String { self.inner.state() }

    #[getter]
    fn handshaking(&self) -> bool { self.inner.is_handshaking() }

    #[getter]
    fn established(&self) -> bool { self.inner.is_established() }

    fn version(&self) -> Option<String> { self.inner.version() }

    /// `(name, strength, key bits)`, shaped like the client's.
    fn cipher(&self) -> Option<(String, String, usize)> { self.inner.cipher() }

    /// The host the client asked for in SNI, or `None` if it sent none.
    ///
    /// This is the field a terminating proxy exists to read: it is the
    /// only thing in a handshake that says which host the client thinks
    /// it is reaching, and it arrives before anything has to be decided.
    #[getter]
    fn server_name(&self) -> Option<String> { self.inner.server_name() }

    /// Every ALPN protocol the client offered, chosen or not.
    #[getter]
    fn offered_alpn(&self) -> Vec<String> { self.inner.offered_alpn() }

    /// The protocol chosen from `alpn`, or `None`.
    ///
    /// Named like `ssl.SSLSocket.selected_alpn_protocol()`. `None`
    /// means this server offers none, or the client offered none, or
    /// nothing was in common and `require_alpn` was off - the three are
    /// the same on the wire, and `offered_alpn` tells them apart.
    fn selected_alpn_protocol(&self) -> Option<String> {
        self.inner.negotiated_alpn()
    }

    /// The client's certificate chain as DER, leaf first, or empty.
    ///
    /// Empty says nothing on its own - we may not have asked, or the
    /// client may have had nothing suitable - and a non-empty chain
    /// says the client holds the key, not that the chain was trusted.
    /// `client_certificate_verified` is that separate question.
    #[getter]
    fn peer_certificates<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.inner.peer_certificates().iter()
            .map(|der| PyBytes::new(py, der)).collect()
    }

    /// Whether the client's chain was checked against `client_roots`.
    #[getter]
    fn client_certificate_verified(&self) -> bool {
        self.inner.client_certificate_verified()
    }

    /// Take the early data (0-RTT) this connection accepted.
    ///
    /// **Deliberately not part of `take_incoming`.** These bytes are not
    /// forward secret and they may be a replay of a flight that already
    /// happened; a caller reading them out of the same buffer as
    /// everything else has no way to tell which bytes those were, and
    /// the whole question of whether 0-RTT is safe is a question about
    /// exactly these bytes.
    fn take_early_data<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.take_early_data())
    }

    /// Whether this connection accepted early data.
    #[getter]
    fn accepted_early_data(&self) -> bool { self.inner.accepted_early_data() }

    #[getter]
    fn encrypt_then_mac(&self) -> bool { self.inner.uses_encrypt_then_mac() }

    #[getter]
    fn extended_master_secret(&self) -> bool {
        self.inner.uses_extended_master_secret()
    }

    fn __repr__(&self) -> String {
        format!("<allcrypt.TlsServer {}{}>", self.inner.state(),
                match self.inner.version() {
                    Some(version) => format!(" {}", version),
                    None => String::new(),
                })
    }
}

// ----------------------------------------------------------------- module ---


#[pymodule]
fn allcrypt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Hash>()?;
    m.add_class::<Cipher>()?;
    m.add_class::<Encryptor>()?;
    m.add_class::<Aead>()?;
    m.add_class::<AeadEncryptor>()?;
    m.add_class::<PyStreamCipher>()?;
    m.add_class::<Hmac>()?;
    m.add_class::<PyEcKey>()?;
    m.add_class::<PyEddsaKey>()?;
    m.add_class::<PyDsaKey>()?;
    m.add_class::<PyEcPublicKey>()?;
    m.add_class::<PyRsaKey>()?;
    m.add_class::<PyRsaPublicKey>()?;
    m.add_class::<PyDhGroup>()?;
    m.add_class::<PyElGamalKey>()?;
    m.add_class::<PyElGamalPublicKey>()?;
    m.add_class::<PyCertificate>()?;
    m.add_class::<PyTrustStore>()?;
    m.add_class::<PyReplayGuard>()?;
    m.add_function(wrap_pyfunction!(private_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(encryption_schemes, m)?)?;
    m.add_function(wrap_pyfunction!(private_key_encryption, m)?)?;
    m.add_class::<PyTlsClient>()?;
    m.add_class::<PyTlsServer>()?;
    m.add_class::<PyCertificateAuthority>()?;

    m.add("CryptoError", m.py().get_type::<CryptoError>())?;

    m.add_function(wrap_pyfunction!(hash_new, m)?)?;
    m.add_function(wrap_pyfunction!(md5, m)?)?;
    m.add_function(wrap_pyfunction!(sha0, m)?)?;
    m.add_function(wrap_pyfunction!(sha1, m)?)?;
    m.add_function(wrap_pyfunction!(sha224, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(sha384, m)?)?;
    m.add_function(wrap_pyfunction!(sha512, m)?)?;
    m.add_function(wrap_pyfunction!(sha512_224, m)?)?;
    m.add_function(wrap_pyfunction!(sha512_256, m)?)?;
    m.add_function(wrap_pyfunction!(pad_pkcs7, m)?)?;
    m.add_function(wrap_pyfunction!(unpad_pkcs7, m)?)?;
    m.add_function(wrap_pyfunction!(cmac, m)?)?;
    m.add_function(wrap_pyfunction!(kbkdf_counter, m)?)?;
    m.add_function(wrap_pyfunction!(kbkdf_feedback, m)?)?;
    m.add_function(wrap_pyfunction!(concat_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(x963_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(kerberos_nfold, m)?)?;
    m.add_function(wrap_pyfunction!(kerberos_derive_random, m)?)?;
    m.add_function(wrap_pyfunction!(kerberos_des_string_to_key, m)?)?;
    m.add_function(wrap_pyfunction!(kerberos_random_to_key, m)?)?;
    m.add_function(wrap_pyfunction!(openpgp_s2k, m)?)?;
    m.add_function(wrap_pyfunction!(openpgp_s2k_count, m)?)?;
    m.add_function(wrap_pyfunction!(sevenzip_aes_key, m)?)?;
    m.add_function(wrap_pyfunction!(keepass_aes_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(luks_af_split, m)?)?;
    m.add_function(wrap_pyfunction!(luks_af_merge, m)?)?;
    m.add_function(wrap_pyfunction!(bitlocker_encrypt_sector, m)?)?;
    m.add_function(wrap_pyfunction!(bitlocker_decrypt_sector, m)?)?;
    m.add_function(wrap_pyfunction!(bitlocker_password_key, m)?)?;
    m.add_function(wrap_pyfunction!(nt_hash, m)?)?;
    m.add_function(wrap_pyfunction!(lm_hash, m)?)?;
    m.add_function(wrap_pyfunction!(bitlocker_recovery_password_key, m)?)?;
    m.add_function(wrap_pyfunction!(michael, m)?)?;
    m.add_function(wrap_pyfunction!(wep_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(wep_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(tkip_rc4_key, m)?)?;
    m.add_function(wrap_pyfunction!(wpa_psk, m)?)?;
    m.add_function(wrap_pyfunction!(wpa_ptk, m)?)?;
    m.add_function(wrap_pyfunction!(wpa_pmkid, m)?)?;
    m.add_function(wrap_pyfunction!(cbc_mac, m)?)?;
    m.add_function(wrap_pyfunction!(office_xor_verifier, m)?)?;
    m.add_function(wrap_pyfunction!(office_xor_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(office_xor_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf, m)?)?;
    m.add_function(wrap_pyfunction!(umac, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_hmac, m)?)?;
    m.add_function(wrap_pyfunction!(shake, m)?)?;
    m.add_function(wrap_pyfunction!(scrypt, m)?)?;
    m.add_function(wrap_pyfunction!(argon2, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_recommended_iterations, m)?)?;
    m.add_function(wrap_pyfunction!(tls_master_secret, m)?)?;
    m.add_function(wrap_pyfunction!(ssl3_record_mac, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_exchange, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_raw, m)?)?;
    m.add_function(wrap_pyfunction!(x448_generate, m)?)?;
    m.add_function(wrap_pyfunction!(x448_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(x448_exchange, m)?)?;
    m.add_function(wrap_pyfunction!(x448_raw, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(random_source, m)?)?;
    m.add_function(wrap_pyfunction!(hardware_aes, m)?)?;
    m.add_function(wrap_pyfunction!(key_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(key_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(key_wrap_with_padding, m)?)?;
    m.add_function(wrap_pyfunction!(cms_3des_key_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(cms_3des_key_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(cms_rc2_key_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(cms_rc2_key_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(pwri_key_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(pwri_key_unwrap, m)?)?;
    m.add_function(wrap_pyfunction!(key_unwrap_with_padding, m)?)?;
    m.add_function(wrap_pyfunction!(xts_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(xts_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(lrw_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(lrw_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(eddsa_curves, m)?)?;
    m.add_function(wrap_pyfunction!(eddsa_generate, m)?)?;
    m.add_function(wrap_pyfunction!(eddsa_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(eddsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(eddsa_verify, m)?)?;
    m.add_function(wrap_pyfunction!(xeddsa_forms, m)?)?;
    m.add_function(wrap_pyfunction!(xeddsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(xeddsa_verify, m)?)?;
    m.add_function(wrap_pyfunction!(tls12_prf, m)?)?;
    m.add_function(wrap_pyfunction!(tls10_prf, m)?)?;
    m.add_function(wrap_pyfunction!(verify_chain, m)?)?;
    m.add_function(wrap_pyfunction!(crl_distribution_points, m)?)?;
    m.add_function(wrap_pyfunction!(crl_status, m)?)?;
    m.add_function(wrap_pyfunction!(ocsp_responders, m)?)?;
    m.add_function(wrap_pyfunction!(ocsp_request, m)?)?;
    m.add_function(wrap_pyfunction!(ocsp_status, m)?)?;
    m.add_function(wrap_pyfunction!(pem_certificates, m)?)?;
    m.add_function(wrap_pyfunction!(pem_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(register_oid, m)?)?;
    m.add_function(wrap_pyfunction!(registered_oids, m)?)?;
    m.add_function(wrap_pyfunction!(curve_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(forget_oid, m)?)?;
    m.add_function(wrap_pyfunction!(gost_sbox, m)?)?;

    // The catalogue, so Python can discover what is available rather than
    // guessing. These come straight from the Rust constants, and
    // tests/test_api.rs asserts every name in them actually constructs.
    m.add("algorithms_available", api::HASHES.to_vec())?;
    m.add("block_ciphers_available", api::BLOCK_CIPHERS.to_vec())?;
    m.add("stream_ciphers_available", api::STREAM_CIPHERS.to_vec())?;
    m.add("modes_available", api::MODES.to_vec())?;
    m.add("aeads_available", api::AEADS.to_vec())?;
    m.add("curves_available", api::CURVES.to_vec())?;
    m.add("tls_suites_available", api::tls_suites_known())?;
    m.add_function(wrap_pyfunction!(tls_suite_names, m)?)?;
    m.add_function(wrap_pyfunction!(tls_signature_schemes, m)?)?;
    m.add_class::<PySlhDsaKey>()?;
    m.add_class::<PySlhDsaPublicKey>()?;
    m.add_function(wrap_pyfunction!(slh_dsa_parameter_sets, m)?)?;
    m.add_function(wrap_pyfunction!(slh_dsa_pre_hashes, m)?)?;
    m.add_class::<PyMlKemKey>()?;
    m.add_class::<PyMlKemPublicKey>()?;
    m.add_function(wrap_pyfunction!(ml_kem_parameter_sets, m)?)?;
    m.add_class::<PyMlDsaKey>()?;
    m.add_class::<PyMlDsaPublicKey>()?;
    m.add_function(wrap_pyfunction!(ml_dsa_parameter_sets, m)?)?;
    m.add_class::<PySshKey>()?;
    m.add_class::<PySshPublicKey>()?;
    m.add_class::<PySshClient>()?;
    m.add_class::<PySshServer>()?;
    m.add_function(wrap_pyfunction!(sshsig_verify, m)?)?;
    // The same catalogues as enumerations, generated from the same
    // constants. Where the obvious name is already a class - `Hash`,
    // `StreamCipher`, `Aead` are all types here - the enum takes a
    // `Name` suffix rather than shadowing it.
    add_name_enum(m, "Mode", api::MODES)?;
    add_name_enum(m, "HashName", api::HASHES)?;
    add_name_enum(m, "BlockCipher", api::BLOCK_CIPHERS)?;
    add_name_enum(m, "StreamCipherName", api::STREAM_CIPHERS)?;
    add_name_enum(m, "AeadName", api::AEADS)?;
    add_name_enum(m, "CurveName", api::CURVES)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
