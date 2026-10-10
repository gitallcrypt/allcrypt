//! The C interface: `extern "C"` functions over `api`, declared in
//! `include/allcrypt.h`. Built with the `c-api` feature; `docs/c.md` has
//! the build and link lines.
//!
//! Translation only, like `python.rs`: each function checks its pointers,
//! converts its arguments, calls `api`, and converts the answer back.
//! Nothing here is cryptography. `scripts/check_c_api.py` compares every
//! function below with its prototype in the header, parameter by
//! parameter, and runs a C program against the built library.
//!
//! The conventions, which the header repeats for the C reader:
//!
//! - A function that can fail returns `int`: `ALLCRYPT_OK` (0), or
//!   `ALLCRYPT_ERROR` with a message for `allcrypt_last_error`. The
//!   verifiers also return `ALLCRYPT_INVALID` for a well-formed signature
//!   that does not verify. **Only 0 is success**, so a verifier's result
//!   cannot be read as a boolean the wrong way round.
//! - Bytes in are a pointer and a length; the pointer may be NULL when
//!   the length is 0. Names are NUL-terminated UTF-8.
//! - Output whose length the caller chooses (a KDF, random bytes) goes
//!   into the caller's memory. Output whose length the library decides
//!   goes into an `allcrypt_buffer`, which `allcrypt_buffer_free` zeroes
//!   and releases. A buffer is overwritten, not appended to.
//! - Objects are opaque pointers made by `_new`, `_generate`,
//!   `_from_*` or `_load`, and released by their `_free`, which accepts
//!   NULL. An object may be used from one thread at a time.
//! - A panic is caught at the boundary and becomes `ALLCRYPT_ERROR`.
//!   Unwinding out of an `extern "C"` function aborts the process, and the
//!   process is somebody else's program.

// The opaque types carry their C names, so that the header and this file
// spell every parameter's type the same way and the check script can
// compare them as text.
#![allow(non_camel_case_types)]
// Every function here takes raw pointers from C and dereferences them,
// and the contract is the same for all of them: pointers point at what
// the header says, for as long as the call lasts, and objects came from
// this library and have not been freed. The header states it once, and
// sixty copies of it in `# Safety` sections would bury the documentation
// that differs between functions.
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::api;
use crate::hash_functions::HashFunction;
use crate::Mac;

pub const ALLCRYPT_OK: c_int = 0;
pub const ALLCRYPT_ERROR: c_int = -1;
pub const ALLCRYPT_INVALID: c_int = -2;

pub type allcrypt_hash_state = api::AnyHash;
pub type allcrypt_hmac_state = crate::mac::hmac::Hmac<api::AnyHash>;
pub type allcrypt_cipher = api::CipherStream;
pub type allcrypt_stream = api::AnyStreamCipher;
pub type allcrypt_ec_key = api::EcKey;
pub type allcrypt_eddsa_key = api::EddsaKey;
pub type allcrypt_rsa_key = api::RsaKey;
pub type allcrypt_rsa_public_key = api::RsaPublicKey;

/// Bytes whose length the library decided. `data` is NULL when `len` is 0.
#[repr(C)]
pub struct allcrypt_buffer {
    pub data: *mut u8,
    pub len: usize,
}

// ------------------------------------------------------------ plumbing ---

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_error(message: &str) {
    // A message is ours and never holds a NUL; if one ever did, the C
    // reader would see it cut short, so it is spelled out instead.
    let text = CString::new(message.replace('\0', "\\0")).unwrap_or_default();
    LAST_ERROR.with(|last| *last.borrow_mut() = text);
}

/// Run `body`, turning an error or a panic into a status and a message.
fn guard(body: impl FnOnce() -> Result<c_int, String>) -> c_int {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(status)) => status,
        Ok(Err(message)) => {
            set_error(&message);
            ALLCRYPT_ERROR
        }
        Err(_) => {
            set_error("allcrypt panicked, which is a bug in allcrypt.");
            ALLCRYPT_ERROR
        }
    }
}

unsafe fn bytes<'a>(data: *const u8, len: usize, what: &str) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(format!("{what} is NULL with a length of {len}."));
    }
    Ok(std::slice::from_raw_parts(data, len))
}

unsafe fn bytes_mut<'a>(data: *mut u8, len: usize, what: &str) -> Result<&'a mut [u8], String> {
    if len == 0 {
        return Ok(&mut []);
    }
    if data.is_null() {
        return Err(format!("{what} is NULL with a length of {len}."));
    }
    Ok(std::slice::from_raw_parts_mut(data, len))
}

/// A NULL pointer is `None`, and any other - even with a length of 0 - is
/// a value: no password and an empty password are different requests.
unsafe fn optional_bytes<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(data, len))
    }
}

unsafe fn text<'a>(name: *const c_char, what: &str) -> Result<&'a str, String> {
    if name.is_null() {
        return Err(format!("{what} is NULL."));
    }
    CStr::from_ptr(name).to_str().map_err(|_| format!("{what} is not UTF-8."))
}

unsafe fn optional_text<'a>(name: *const c_char, what: &str) -> Result<Option<&'a str>, String> {
    if name.is_null() {
        Ok(None)
    } else {
        text(name, what).map(Some)
    }
}

unsafe fn object<'a, T>(handle: *const T, what: &str) -> Result<&'a T, String> {
    handle.as_ref().ok_or_else(|| format!("The {what} is NULL."))
}

unsafe fn object_mut<'a, T>(handle: *mut T, what: &str) -> Result<&'a mut T, String> {
    handle.as_mut().ok_or_else(|| format!("The {what} is NULL."))
}

/// Checked before any work, so that a NULL output does not first cost an
/// RSA key generation.
unsafe fn slot<'a, T>(out: *mut *mut T) -> Result<&'a mut *mut T, String> {
    out.as_mut().ok_or_else(|| "The pointer to receive the object is NULL.".to_string())
}

fn give_object<T>(slot: &mut *mut T, value: T) -> c_int {
    *slot = Box::into_raw(Box::new(value));
    ALLCRYPT_OK
}

unsafe fn free_object<T>(handle: *mut T) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

unsafe fn buffer<'a>(out: *mut allcrypt_buffer, what: &str) -> Result<&'a mut allcrypt_buffer, String> {
    out.as_mut().ok_or_else(|| format!("The buffer for the {what} is NULL."))
}

fn give(out: &mut allcrypt_buffer, bytes: Vec<u8>) -> c_int {
    if bytes.is_empty() {
        out.data = ptr::null_mut();
        out.len = 0;
    } else {
        let boxed = bytes.into_boxed_slice();
        out.len = boxed.len();
        out.data = Box::into_raw(boxed) as *mut u8;
    }
    ALLCRYPT_OK
}

fn fill(out: &mut [u8], bytes: &[u8]) -> Result<c_int, String> {
    if bytes.len() != out.len() {
        return Err(format!("{} bytes were produced for {} requested.", bytes.len(), out.len()));
    }
    out.copy_from_slice(bytes);
    Ok(ALLCRYPT_OK)
}

fn verdict(valid: bool) -> c_int {
    if valid { ALLCRYPT_OK } else { ALLCRYPT_INVALID }
}

// ------------------------------------------------------------- general ---

/// The library's version, NUL-terminated; never freed.
#[no_mangle]
pub extern "C" fn allcrypt_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// The message for the last error on this thread. Valid until the next
/// failing call on this thread; never freed by the caller.
#[no_mangle]
pub extern "C" fn allcrypt_last_error() -> *const c_char {
    LAST_ERROR.with(|last| last.borrow().as_ptr())
}

/// Zero and release a buffer's bytes, and set it empty. NULL, and an
/// already empty buffer, are fine.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_buffer_free(buffer: *mut allcrypt_buffer) {
    let Some(buffer) = buffer.as_mut() else { return };
    if !buffer.data.is_null() {
        let bytes = ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
        for byte in (*bytes).iter_mut() {
            ptr::write_volatile(byte, 0);
        }
        drop(Box::from_raw(bytes));
    }
    buffer.data = ptr::null_mut();
    buffer.len = 0;
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_random(out: *mut u8, out_len: usize) -> c_int {
    guard(|| {
        let out = bytes_mut(out, out_len, "out")?;
        fill(out, &api::random_bytes(out.len())?)
    })
}

/// The names one family accepts, comma separated, or NULL for a kind
/// that is not one of the seven. Built once per kind and kept.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_names(kind: *const c_char) -> *const c_char {
    use std::sync::OnceLock;
    static LISTS: [OnceLock<CString>; 7] = [const { OnceLock::new() }; 7];
    let Ok(kind) = text(kind, "The kind") else { return ptr::null() };
    let (index, names): (usize, fn() -> Vec<&'static str>) = match kind {
        "hashes" => (0, || api::HASHES.to_vec()),
        "block_ciphers" => (1, || api::BLOCK_CIPHERS.to_vec()),
        "modes" => (2, || api::MODES.to_vec()),
        "stream_ciphers" => (3, || api::STREAM_CIPHERS.to_vec()),
        "aeads" => (4, || api::AEADS.to_vec()),
        "curves" => (5, || api::CURVES.to_vec()),
        "eddsa" => (6, api::eddsa_curves),
        _ => return ptr::null(),
    };
    LISTS[index].get_or_init(|| CString::new(names().join(",")).unwrap_or_default()).as_ptr()
}

// -------------------------------------------------------------- hashes ---

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hash(name: *const c_char, data: *const u8, data_len: usize,
                                       digest: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let digest = buffer(digest, "digest")?;
        let mut hash = api::AnyHash::new(text(name, "The hash name")?)?;
        hash.update(bytes(data, data_len, "data")?);
        Ok(give(digest, hash.digest()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hash_new(name: *const c_char, out: *mut *mut allcrypt_hash_state)
                                           -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::AnyHash::new(text(name, "The hash name")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hash_update(hash: *mut allcrypt_hash_state, data: *const u8,
                                              data_len: usize) -> c_int {
    guard(|| {
        object_mut(hash, "hash")?.update(bytes(data, data_len, "data")?);
        Ok(ALLCRYPT_OK)
    })
}

/// The digest of everything so far. The hash can go on being updated.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_hash_digest(hash: *mut allcrypt_hash_state,
                                              digest: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let digest = buffer(digest, "digest")?;
        Ok(give(digest, object_mut(hash, "hash")?.digest()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hash_free(hash: *mut allcrypt_hash_state) {
    free_object(hash)
}

/// SHAKE128 or SHAKE256, `out_len` bytes of it.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_shake(name: *const c_char, data: *const u8, data_len: usize,
                                        out: *mut u8, out_len: usize) -> c_int {
    guard(|| {
        let out = bytes_mut(out, out_len, "out")?;
        let answer = api::shake(text(name, "The SHAKE name")?, bytes(data, data_len, "data")?,
                                out.len())?;
        fill(out, &answer)
    })
}

// ---------------------------------------------------------------- HMAC ---

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hmac(hash_name: *const c_char, key: *const u8, key_len: usize,
                                       data: *const u8, data_len: usize,
                                       mac: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let mac = buffer(mac, "MAC")?;
        Ok(give(mac, api::hmac(text(hash_name, "The hash name")?, bytes(key, key_len, "key")?,
                               bytes(data, data_len, "data")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hmac_new(hash_name: *const c_char, key: *const u8,
                                           key_len: usize, out: *mut *mut allcrypt_hmac_state)
                                           -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::new_hmac(text(hash_name, "The hash name")?,
                                          bytes(key, key_len, "key")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hmac_update(hmac: *mut allcrypt_hmac_state, data: *const u8,
                                              data_len: usize) -> c_int {
    guard(|| {
        object_mut(hmac, "HMAC")?.update(bytes(data, data_len, "data")?);
        Ok(ALLCRYPT_OK)
    })
}

/// The MAC of everything so far. The HMAC can go on being updated.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_hmac_digest(hmac: *mut allcrypt_hmac_state,
                                              mac: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let mac = buffer(mac, "MAC")?;
        Ok(give(mac, object_mut(hmac, "HMAC")?.digest()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_hmac_free(hmac: *mut allcrypt_hmac_state) {
    free_object(hmac)
}

// ---------------------------------------------------------------- KDFs ---

#[no_mangle]
pub unsafe extern "C" fn allcrypt_pbkdf2(hash_name: *const c_char, password: *const u8,
                                         password_len: usize, salt: *const u8, salt_len: usize,
                                         iterations: u32, out: *mut u8, out_len: usize) -> c_int {
    guard(|| {
        let out = bytes_mut(out, out_len, "out")?;
        let key = api::pbkdf2(text(hash_name, "The hash name")?,
                              bytes(password, password_len, "password")?,
                              bytes(salt, salt_len, "salt")?, iterations, out.len())?;
        fill(out, &key)
    })
}

/// HKDF (RFC 5869). An empty salt is the all-zero salt the RFC specifies.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_hkdf(hash_name: *const c_char, salt: *const u8,
                                       salt_len: usize, ikm: *const u8, ikm_len: usize,
                                       info: *const u8, info_len: usize, out: *mut u8,
                                       out_len: usize) -> c_int {
    guard(|| {
        let out = bytes_mut(out, out_len, "out")?;
        let key = api::hkdf(text(hash_name, "The hash name")?, bytes(salt, salt_len, "salt")?,
                            bytes(ikm, ikm_len, "ikm")?, bytes(info, info_len, "info")?,
                            out.len())?;
        fill(out, &key)
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_scrypt(password: *const u8, password_len: usize,
                                         salt: *const u8, salt_len: usize, n: u64, r: u32,
                                         p: u32, out: *mut u8, out_len: usize) -> c_int {
    guard(|| {
        let out = bytes_mut(out, out_len, "out")?;
        let key = api::scrypt(bytes(password, password_len, "password")?,
                              bytes(salt, salt_len, "salt")?, n, r, p, out.len())?;
        fill(out, &key)
    })
}

/// `variant` is `argon2d`, `argon2i` or `argon2id`.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_argon2(variant: *const c_char, password: *const u8,
                                         password_len: usize, salt: *const u8, salt_len: usize,
                                         memory_kib: u32, passes: u32, lanes: u32,
                                         secret: *const u8, secret_len: usize,
                                         associated_data: *const u8,
                                         associated_data_len: usize, out: *mut u8,
                                         out_len: usize) -> c_int {
    guard(|| {
        let out = bytes_mut(out, out_len, "out")?;
        let key = api::argon2(text(variant, "The Argon2 variant")?,
                              bytes(password, password_len, "password")?,
                              bytes(salt, salt_len, "salt")?, memory_kib, passes, lanes,
                              bytes(secret, secret_len, "secret")?,
                              bytes(associated_data, associated_data_len, "associated_data")?,
                              out.len())?;
        fill(out, &key)
    })
}

// ------------------------------------------------------- block ciphers ---

/// A block cipher in a mode, one direction. `param` is the cipher's
/// optional parameter (RC2's effective key bits, say) or NULL; `decrypt`
/// is 0 to encrypt and anything else to decrypt.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_cipher_new(cipher: *const c_char, key: *const u8,
                                             key_len: usize, param: *const c_char,
                                             mode: *const c_char, iv: *const u8, iv_len: usize,
                                             decrypt: c_int, out: *mut *mut allcrypt_cipher)
                                             -> c_int {
    guard(|| {
        let out = slot(out)?;
        let block = api::AnyBlockCipher::new(text(cipher, "The cipher name")?,
                                             bytes(key, key_len, "key")?,
                                             optional_text(param, "The cipher parameter")?)?;
        let mode = api::Mode::from_name(text(mode, "The mode name")?)?;
        Ok(give_object(out, api::CipherStream::new(block, mode, bytes(iv, iv_len, "iv")?,
                                                   decrypt != 0)?))
    })
}

/// Whatever output is ready; the block modes may hold back a partial
/// block until more input or `allcrypt_cipher_finish`.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_cipher_update(cipher: *mut allcrypt_cipher, data: *const u8,
                                                data_len: usize, out: *mut allcrypt_buffer)
                                                -> c_int {
    guard(|| {
        let out = buffer(out, "output")?;
        Ok(give(out, object_mut(cipher, "cipher")?.update(bytes(data, data_len, "data")?)?))
    })
}

/// The rest of the output. ECB and CBC add no padding: the input must be
/// whole blocks (`allcrypt_pad_pkcs7` first, to pad).
#[no_mangle]
pub unsafe extern "C" fn allcrypt_cipher_finish(cipher: *mut allcrypt_cipher,
                                                out: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let out = buffer(out, "output")?;
        Ok(give(out, object_mut(cipher, "cipher")?.finish()?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_cipher_free(cipher: *mut allcrypt_cipher) {
    free_object(cipher)
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_pad_pkcs7(data: *const u8, data_len: usize, block_size: usize,
                                            out: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let out = buffer(out, "output")?;
        Ok(give(out, api::pad_pkcs7(bytes(data, data_len, "data")?, block_size)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_unpad_pkcs7(data: *const u8, data_len: usize,
                                              block_size: usize, out: *mut allcrypt_buffer)
                                              -> c_int {
    guard(|| {
        let out = buffer(out, "output")?;
        Ok(give(out, api::unpad_pkcs7(bytes(data, data_len, "data")?, block_size)?))
    })
}

// ---------------------------------------------------------------- AEAD ---

#[no_mangle]
pub unsafe extern "C" fn allcrypt_aead_encrypt(name: *const c_char, key: *const u8,
                                               key_len: usize, nonce: *const u8,
                                               nonce_len: usize, aad: *const u8, aad_len: usize,
                                               plaintext: *const u8, plaintext_len: usize,
                                               ciphertext: *mut allcrypt_buffer,
                                               tag: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let ciphertext = buffer(ciphertext, "ciphertext")?;
        let tag = buffer(tag, "tag")?;
        let (sealed, mac) = api::aead_encrypt(text(name, "The AEAD name")?,
                                              bytes(key, key_len, "key")?,
                                              bytes(nonce, nonce_len, "nonce")?,
                                              bytes(aad, aad_len, "aad")?,
                                              bytes(plaintext, plaintext_len, "plaintext")?)?;
        give(ciphertext, sealed);
        Ok(give(tag, mac))
    })
}

/// The plaintext, or an error and no plaintext at all.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_aead_decrypt(name: *const c_char, key: *const u8,
                                               key_len: usize, nonce: *const u8,
                                               nonce_len: usize, aad: *const u8, aad_len: usize,
                                               ciphertext: *const u8, ciphertext_len: usize,
                                               tag: *const u8, tag_len: usize,
                                               plaintext: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let plaintext = buffer(plaintext, "plaintext")?;
        Ok(give(plaintext, api::aead_decrypt(text(name, "The AEAD name")?,
                                             bytes(key, key_len, "key")?,
                                             bytes(nonce, nonce_len, "nonce")?,
                                             bytes(aad, aad_len, "aad")?,
                                             bytes(ciphertext, ciphertext_len, "ciphertext")?,
                                             bytes(tag, tag_len, "tag")?)?))
    })
}

// ------------------------------------------------------ stream ciphers ---

#[no_mangle]
pub unsafe extern "C" fn allcrypt_stream_new(name: *const c_char, key: *const u8,
                                             key_len: usize, nonce: *const u8, nonce_len: usize,
                                             out: *mut *mut allcrypt_stream) -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::AnyStreamCipher::new(text(name, "The cipher name")?,
                                                      bytes(key, key_len, "key")?,
                                                      bytes(nonce, nonce_len, "nonce")?)?))
    })
}

/// XOR the keystream over `data` in place; encryption and decryption are
/// the same call.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_stream_apply(stream: *mut allcrypt_stream, data: *mut u8,
                                               data_len: usize) -> c_int {
    guard(|| {
        object_mut(stream, "stream cipher")?.apply(bytes_mut(data, data_len, "data")?)?;
        Ok(ALLCRYPT_OK)
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_stream_free(stream: *mut allcrypt_stream) {
    free_object(stream)
}

// -------------------------------------------------------------- X25519 ---

unsafe fn array32<'a>(data: *const u8, what: &str) -> Result<&'a [u8], String> {
    bytes(data, 32, what)
}

unsafe fn array32_mut<'a>(data: *mut u8, what: &str) -> Result<&'a mut [u8], String> {
    bytes_mut(data, 32, what)
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_x25519_generate(private_key: *mut u8, public_key: *mut u8)
                                                  -> c_int {
    guard(|| {
        let private_out = array32_mut(private_key, "private_key")?;
        let public_out = array32_mut(public_key, "public_key")?;
        let (private, public) = api::x25519_generate()?;
        fill(private_out, &private)?;
        fill(public_out, &public)
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_x25519_public_key(private_key: *const u8, public_key: *mut u8)
                                                    -> c_int {
    guard(|| {
        let out = array32_mut(public_key, "public_key")?;
        fill(out, &api::x25519_public_key(array32(private_key, "private_key")?)?)
    })
}

/// Refuses the all-zero result, which a low-order peer point produces.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_x25519_exchange(private_key: *const u8, peer: *const u8,
                                                  shared: *mut u8) -> c_int {
    guard(|| {
        let out = array32_mut(shared, "shared")?;
        fill(out, &api::x25519_exchange(array32(private_key, "private_key")?,
                                        array32(peer, "peer")?)?)
    })
}

// ------------------------------------------------- private key files ---

unsafe fn load(data: *const u8, data_len: usize, password: *const u8, password_len: usize)
               -> Result<api::PrivateKeyParts, String> {
    api::parse_private_key_with_password(bytes(data, data_len, "data")?,
                                         optional_bytes(password, password_len))
}

fn kind(parts: &api::PrivateKeyParts) -> &'static str {
    match parts {
        api::PrivateKeyParts::Ec { .. } => "an EC key",
        api::PrivateKeyParts::Rsa { .. } => "an RSA key",
        api::PrivateKeyParts::Eddsa { .. } => "an EdDSA key",
        api::PrivateKeyParts::Xdh { .. } => "an X25519 or X448 key",
        api::PrivateKeyParts::MlDsa { .. } => "an ML-DSA key",
        api::PrivateKeyParts::Dsa { .. } => "a DSA key",
    }
}

// ------------------------------------------------------------------ EC ---

#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_generate(curve: *const c_char,
                                              out: *mut *mut allcrypt_ec_key) -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::EcKey::generate(text(curve, "The curve name")?)?))
    })
}

/// The private scalar, big endian.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_from_private(curve: *const c_char, private_key: *const u8,
                                                  private_key_len: usize,
                                                  out: *mut *mut allcrypt_ec_key) -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::EcKey::from_private(
            text(curve, "The curve name")?, bytes(private_key, private_key_len, "private_key")?)?))
    })
}

/// A PKCS#8, SEC1 or PEM file. `password` NULL means the file is not
/// encrypted.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_load(data: *const u8, data_len: usize,
                                          password: *const u8, password_len: usize,
                                          out: *mut *mut allcrypt_ec_key) -> c_int {
    guard(|| {
        let out = slot(out)?;
        match load(data, data_len, password, password_len)? {
            api::PrivateKeyParts::Ec { curve, private } =>
                Ok(give_object(out, api::EcKey::from_private(&curve, &private)?)),
            other => Err(format!("The file holds {}, not an EC key.", kind(&other))),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_private_bytes(key: *const allcrypt_ec_key,
                                                   out: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let out = buffer(out, "private key")?;
        Ok(give(out, object(key, "EC key")?.private_bytes()?))
    })
}

/// SEC1: `04 || x || y`, or `02`/`03 || x` when `compressed` is not 0.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_public_bytes(key: *const allcrypt_ec_key, compressed: c_int,
                                                  out: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let out = buffer(out, "public key")?;
        Ok(give(out, object(key, "EC key")?.public_bytes(compressed != 0)?))
    })
}

/// ECDSA over a digest, deterministic (RFC 6979). `hash_name` names the
/// hash that made the digest. The signature is `r || s`, fixed width.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_sign(key: *const allcrypt_ec_key, hash_name: *const c_char,
                                          digest: *const u8, digest_len: usize,
                                          signature: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let signature = buffer(signature, "signature")?;
        Ok(give(signature, object(key, "EC key")?.sign(bytes(digest, digest_len, "digest")?,
                                                       text(hash_name, "The hash name")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_exchange(key: *const allcrypt_ec_key, peer: *const u8,
                                              peer_len: usize, shared: *mut allcrypt_buffer)
                                              -> c_int {
    guard(|| {
        let shared = buffer(shared, "shared secret")?;
        Ok(give(shared, object(key, "EC key")?.exchange(bytes(peer, peer_len, "peer")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_key_free(key: *mut allcrypt_ec_key) {
    free_object(key)
}

/// `ALLCRYPT_OK` for a valid signature, `ALLCRYPT_INVALID` for a
/// well-formed one that is not, `ALLCRYPT_ERROR` for anything malformed.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_ec_verify(curve: *const c_char, public_key: *const u8,
                                            public_key_len: usize, digest: *const u8,
                                            digest_len: usize, signature: *const u8,
                                            signature_len: usize) -> c_int {
    guard(|| {
        let key = api::EcPublicKey::from_bytes(text(curve, "The curve name")?,
                                               bytes(public_key, public_key_len, "public_key")?)?;
        Ok(verdict(key.verify(bytes(digest, digest_len, "digest")?,
                              bytes(signature, signature_len, "signature")?)?))
    })
}

// --------------------------------------------------------------- EdDSA ---

/// `ed25519` or `ed448`.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_generate(name: *const c_char,
                                                 out: *mut *mut allcrypt_eddsa_key) -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::EddsaKey::generate(text(name, "The EdDSA name")?)?))
    })
}

/// The private key as RFC 8032 defines it: the seed, not a scalar.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_from_private(name: *const c_char,
                                                     private_key: *const u8,
                                                     private_key_len: usize,
                                                     out: *mut *mut allcrypt_eddsa_key)
                                                     -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::EddsaKey::from_private(
            text(name, "The EdDSA name")?, bytes(private_key, private_key_len, "private_key")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_load(data: *const u8, data_len: usize,
                                             password: *const u8, password_len: usize,
                                             out: *mut *mut allcrypt_eddsa_key) -> c_int {
    guard(|| {
        let out = slot(out)?;
        match load(data, data_len, password, password_len)? {
            api::PrivateKeyParts::Eddsa { curve, private } =>
                Ok(give_object(out, api::EddsaKey::from_private(&curve, &private)?)),
            other => Err(format!("The file holds {}, not an EdDSA key.", kind(&other))),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_private_bytes(key: *const allcrypt_eddsa_key,
                                                      out: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let out = buffer(out, "private key")?;
        Ok(give(out, object(key, "EdDSA key")?.private_bytes()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_public_bytes(key: *const allcrypt_eddsa_key,
                                                     out: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let out = buffer(out, "public key")?;
        Ok(give(out, object(key, "EdDSA key")?.public_bytes()))
    })
}

/// Signs the message itself, not a digest. `context` is Ed448's context
/// string, empty for none; Ed25519 has none and refuses one.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_sign(key: *const allcrypt_eddsa_key,
                                             message: *const u8, message_len: usize,
                                             context: *const u8, context_len: usize,
                                             signature: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let signature = buffer(signature, "signature")?;
        Ok(give(signature, object(key, "EdDSA key")?.sign(
            bytes(message, message_len, "message")?, bytes(context, context_len, "context")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_key_free(key: *mut allcrypt_eddsa_key) {
    free_object(key)
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_eddsa_verify(name: *const c_char, public_key: *const u8,
                                               public_key_len: usize, message: *const u8,
                                               message_len: usize, signature: *const u8,
                                               signature_len: usize, context: *const u8,
                                               context_len: usize) -> c_int {
    guard(|| {
        Ok(verdict(api::eddsa_verify(text(name, "The EdDSA name")?,
                                     bytes(public_key, public_key_len, "public_key")?,
                                     bytes(message, message_len, "message")?,
                                     bytes(signature, signature_len, "signature")?,
                                     bytes(context, context_len, "context")?)?))
    })
}

// ----------------------------------------------------------------- RSA ---

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_generate(bits: usize, out: *mut *mut allcrypt_rsa_key)
                                               -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::RsaKey::generate(bits)?))
    })
}

/// The two primes and the public exponent, big endian.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_from_primes(p: *const u8, p_len: usize, q: *const u8,
                                                  q_len: usize, e: *const u8, e_len: usize,
                                                  out: *mut *mut allcrypt_rsa_key) -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::RsaKey::from_primes(bytes(p, p_len, "p")?,
                                                     bytes(q, q_len, "q")?,
                                                     bytes(e, e_len, "e")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_load(data: *const u8, data_len: usize,
                                           password: *const u8, password_len: usize,
                                           out: *mut *mut allcrypt_rsa_key) -> c_int {
    guard(|| {
        let out = slot(out)?;
        match load(data, data_len, password, password_len)? {
            api::PrivateKeyParts::Rsa { p, q, e } =>
                Ok(give_object(out, api::RsaKey::from_primes(&p, &q, &e)?)),
            other => Err(format!("The file holds {}, not an RSA key.", kind(&other))),
        }
    })
}

/// The modulus and the public exponent, big endian.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_public_numbers(key: *const allcrypt_rsa_key,
                                                     n: *mut allcrypt_buffer,
                                                     e: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let n = buffer(n, "modulus")?;
        let e = buffer(e, "exponent")?;
        let public = object(key, "RSA key")?.public_key();
        give(n, public.modulus());
        Ok(give(e, public.exponent()))
    })
}

/// PKCS#1 v1.5 over a digest made by `hash_name`.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_sign(key: *const allcrypt_rsa_key,
                                           hash_name: *const c_char, digest: *const u8,
                                           digest_len: usize, signature: *mut allcrypt_buffer)
                                           -> c_int {
    guard(|| {
        let signature = buffer(signature, "signature")?;
        Ok(give(signature, object(key, "RSA key")?.sign(text(hash_name, "The hash name")?,
                                                        bytes(digest, digest_len, "digest")?)?))
    })
}

/// PSS with MGF1 over the same hash and a salt as long as the digest.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_sign_pss(key: *const allcrypt_rsa_key,
                                               hash_name: *const c_char, digest: *const u8,
                                               digest_len: usize,
                                               signature: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let signature = buffer(signature, "signature")?;
        Ok(give(signature, object(key, "RSA key")?.sign_pss(
            text(hash_name, "The hash name")?, bytes(digest, digest_len, "digest")?, None)?))
    })
}

/// PKCS#1 v1.5 decryption. Every failure is the same error.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_decrypt(key: *const allcrypt_rsa_key,
                                              ciphertext: *const u8, ciphertext_len: usize,
                                              plaintext: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let plaintext = buffer(plaintext, "plaintext")?;
        Ok(give(plaintext, object(key, "RSA key")?.decrypt(
            bytes(ciphertext, ciphertext_len, "ciphertext")?)?))
    })
}

/// No padding: `c^d mod n`, written at the key's size with leading zeros.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_decrypt_raw(key: *const allcrypt_rsa_key,
                                                  ciphertext: *const u8, ciphertext_len: usize,
                                                  plaintext: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let plaintext = buffer(plaintext, "plaintext")?;
        Ok(give(plaintext, object(key, "RSA key")?.decrypt_raw(
            bytes(ciphertext, ciphertext_len, "ciphertext")?)?))
    })
}

/// OAEP with MGF1 over the same hash.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_decrypt_oaep(key: *const allcrypt_rsa_key,
                                                   hash_name: *const c_char, label: *const u8,
                                                   label_len: usize, ciphertext: *const u8,
                                                   ciphertext_len: usize,
                                                   plaintext: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let plaintext = buffer(plaintext, "plaintext")?;
        Ok(give(plaintext, object(key, "RSA key")?.decrypt_oaep(
            text(hash_name, "The hash name")?, None, bytes(label, label_len, "label")?,
            bytes(ciphertext, ciphertext_len, "ciphertext")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_key_free(key: *mut allcrypt_rsa_key) {
    free_object(key)
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_public_new(n: *const u8, n_len: usize, e: *const u8,
                                                 e_len: usize,
                                                 out: *mut *mut allcrypt_rsa_public_key)
                                                 -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, api::RsaPublicKey::new(bytes(n, n_len, "n")?,
                                                   bytes(e, e_len, "e")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_public_from_key(key: *const allcrypt_rsa_key,
                                                      out: *mut *mut allcrypt_rsa_public_key)
                                                      -> c_int {
    guard(|| {
        let out = slot(out)?;
        Ok(give_object(out, object(key, "RSA key")?.public_key()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_verify(key: *const allcrypt_rsa_public_key,
                                             hash_name: *const c_char, digest: *const u8,
                                             digest_len: usize, signature: *const u8,
                                             signature_len: usize) -> c_int {
    guard(|| {
        Ok(verdict(object(key, "RSA public key")?.verify(
            text(hash_name, "The hash name")?, bytes(digest, digest_len, "digest")?,
            bytes(signature, signature_len, "signature")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_verify_pss(key: *const allcrypt_rsa_public_key,
                                                 hash_name: *const c_char, digest: *const u8,
                                                 digest_len: usize, signature: *const u8,
                                                 signature_len: usize) -> c_int {
    guard(|| {
        Ok(verdict(object(key, "RSA public key")?.verify_pss(
            text(hash_name, "The hash name")?, bytes(digest, digest_len, "digest")?,
            bytes(signature, signature_len, "signature")?, None)?))
    })
}

/// PKCS#1 v1.5 encryption, randomised.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_encrypt(key: *const allcrypt_rsa_public_key,
                                              message: *const u8, message_len: usize,
                                              ciphertext: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let ciphertext = buffer(ciphertext, "ciphertext")?;
        Ok(give(ciphertext, object(key, "RSA public key")?.encrypt(
            bytes(message, message_len, "message")?)?))
    })
}

/// No padding: `m^e mod n`, the message a big-endian integer below the
/// modulus. Deterministic.
#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_encrypt_raw(key: *const allcrypt_rsa_public_key,
                                                  message: *const u8, message_len: usize,
                                                  ciphertext: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let ciphertext = buffer(ciphertext, "ciphertext")?;
        Ok(give(ciphertext, object(key, "RSA public key")?.encrypt_raw(
            bytes(message, message_len, "message")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_encrypt_oaep(key: *const allcrypt_rsa_public_key,
                                                   hash_name: *const c_char, label: *const u8,
                                                   label_len: usize, message: *const u8,
                                                   message_len: usize,
                                                   ciphertext: *mut allcrypt_buffer) -> c_int {
    guard(|| {
        let ciphertext = buffer(ciphertext, "ciphertext")?;
        Ok(give(ciphertext, object(key, "RSA public key")?.encrypt_oaep(
            text(hash_name, "The hash name")?, None, bytes(label, label_len, "label")?,
            bytes(message, message_len, "message")?)?))
    })
}

#[no_mangle]
pub unsafe extern "C" fn allcrypt_rsa_public_key_free(key: *mut allcrypt_rsa_public_key) {
    free_object(key)
}
