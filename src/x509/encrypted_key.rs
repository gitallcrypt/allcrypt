/*
Encrypted private keys: PKCS#8 `EncryptedPrivateKeyInfo`, RFC 5958 section 3.

    EncryptedPrivateKeyInfo ::= SEQUENCE {
      encryptionAlgorithm  AlgorithmIdentifier,
      encryptedData        OCTET STRING }

Decrypting gives the plain `PrivateKeyInfo` DER, which goes straight into
`private_key::from_der`. Nothing here parses a key; it removes a layer.

## Why three key derivations

Because the files on disk were written across twenty-five years, and the
scheme is named by an OID in the file rather than chosen by the reader.

  * **PBES2** (RFC 8018 A.4) is what `openssl pkcs8 -topk8` writes today:
    PBKDF2 for the key, then a named cipher in CBC. Anything written
    since about 2005 is this.
  * **PBES1** (RFC 8018 A.3) is PBKDF1 and a 64 bit cipher, in six
    combinations of MD2/MD5/SHA-1 with DES or RC2. PBKDF1 cannot produce
    more than 20 bytes, which is why none of these has an AES variant.
  * **The PKCS#12 PBE** (RFC 7292 B) is a third construction again, and
    it is the one to be careful about calling obsolete: it is what
    `openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES` writes, it is what every
    `.p12` file uses, and it is the *only* `-v1` scheme this machine's
    OpenSSL will still produce without the legacy provider.

## What that says about the reference

Measured on the development machine, September 2026: OpenSSL 3.0.13 will
write PBES2 and the PKCS#12 PBE from its default provider, and the six
PBES1 schemes only with `-provider legacy`. `python-cryptography` 46
reads PBES2, the PKCS#12 schemes and `pbeWithMD5AndDES-CBC`, and refuses
`pbeWithSHA1AndDES-CBC` and `pbeWithMD5AndRC2-CBC` outright - "Unknown
key encryption algorithm", for OIDs that are in the standard it claims to
implement.

That is the whole argument for this file. The keys did not become
unreadable; the readers did. The tests therefore pin the fixtures rather
than regenerating them, because the command that generates them is
already failing on some of these and will eventually fail on the rest.
*/

use crate::asn1::{tag, Oid, Reader, Tag};
use crate::block_ciphers::{BlockCipher, CbcState};
use crate::hash_functions::{md5::MD5, sha1::SHA1, sha2};
use crate::kdf::password::{pbkdf1, pbkdf2, pkcs12_kdf, Pkcs12Purpose};
use crate::x509::oids;

/// The largest iteration count a key file may ask for: 2^24, ten times
/// `pbkdf2_recommended_iterations` for SHA-1 and far above anything
/// OpenSSL or the JDK write. The count is a `u32` in every scheme here,
/// and a crafted file with 4 billion iterations stalls the reader for
/// hours; files are user-chosen, so this is a bound rather than a
/// defence, and it costs nothing.
pub const MAX_ITERATIONS: u32 = 1 << 24;

/// The iteration count from a parameter block, bounded.
fn read_iterations(reader: &mut Reader<'_>) -> Result<u32, String> {
    let iterations = reader.read_u32()?;
    if iterations > MAX_ITERATIONS {
        return Err(format!("The file asks for {} iterations; nothing above {} is \
                            run.", iterations, MAX_ITERATIONS));
    }
    Ok(iterations)
}

/// What a scheme needs from its key derivation, once the OID is known.
#[derive(Clone, Copy)]
struct Recipe {
    /// Bytes of key the cipher wants.
    key_len: usize,
    /// Bytes of IV the cipher wants; zero for a stream cipher.
    iv_len: usize,
    cipher: CipherKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CipherKind {
    Aes,
    TripleDes,
    Des,
    /// RC2, whose *effective* key length is a separate number from the
    /// key length and is carried in the parameters.
    Rc2 { effective_bits: u32 },
    Rc4,
}

/// Decrypt an `EncryptedPrivateKeyInfo`, returning the `PrivateKeyInfo`
/// DER inside it.
///
/// `password` is taken as bytes rather than as text because that is what
/// PBES1 and PBES2 hash - the encoding question only arises for the
/// PKCS#12 schemes, which need a BMPString, and that conversion happens
/// below where it applies.
pub fn decrypt(der: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let mut outer = Reader::new(der);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    let mut algorithm = sequence.read_sequence()?;
    let scheme = algorithm.read_oid()?;
    let parameters = algorithm.remaining();
    let ciphertext = sequence.read_octet_string()?;
    sequence.finish()?;

    let scheme_bytes = scheme.as_bytes();
    if scheme_bytes == oids::PBES2 {
        return pbes2(parameters, ciphertext, password);
    }
    if let Some((hash, kind)) = pbes1_scheme(scheme_bytes) {
        return pbes1(parameters, ciphertext, password, hash, kind);
    }
    if let Some(recipe) = pkcs12_scheme(scheme_bytes) {
        return pkcs12_pbe(parameters, ciphertext, password, recipe);
    }
    if scheme_bytes == oids::JKS_KEY_PROTECTOR {
        return jks_unprotect(ciphertext, password);
    }
    if scheme_bytes == oids::JCE_KEY_PROTECTOR {
        let mut reader = Reader::new(parameters);
        let mut params = reader.read_sequence()?;
        reader.finish()?;
        let salt = params.read_octet_string()?;
        let iterations = read_iterations(&mut params)?;
        params.finish()?;
        return jdk_pbe_md5_3des_decrypt(password, salt, iterations, ciphertext);
    }
    Err(format!("Unsupported key encryption scheme {}. This library knows \
                 PBES2, the six PBES1 schemes, the PKCS#12 PBEs and Java's two \
                 key protectors.",
                dotted(&scheme)))
}

/// Is this DER an `EncryptedPrivateKeyInfo` rather than a plain one?
///
/// **Structural, and deliberately not a check that the scheme is one we
/// support.** The shape is unambiguous: this is a SEQUENCE whose first
/// element is a SEQUENCE beginning with an OID and whose second is an
/// OCTET STRING, while all three plain encodings begin with an INTEGER
/// version. Nothing can be both.
///
/// The first version of this matched the OID against the schemes below,
/// which looked equivalent and was not. A key encrypted with a scheme
/// this library does not know - a future one, or `id-scrypt` from
/// RFC 7914 - then failed the recognition, fell through to the three
/// plain parsers, and came back as "not PKCS#8; not SEC1 EC; not PKCS#1
/// RSA". Three wrong answers about the wrong question, when the right
/// one was "this is encrypted, with a scheme I do not have". Recognising
/// the *shape* and refusing at the *scheme* puts each error where it
/// belongs.
pub fn looks_encrypted(der: &[u8]) -> bool {
    let mut outer = Reader::new(der);
    let Ok(mut sequence) = outer.read_sequence() else { return false };
    if outer.finish().is_err() {
        return false;
    }
    let Ok(mut algorithm) = sequence.read_sequence() else { return false };
    if algorithm.read_oid().is_err() {
        return false;
    }
    sequence.read_octet_string().is_ok()
}

// -------------------------------------------------------------- PBES2 ---

/// PBES2, RFC 8018 A.4.
///
/// ```text
/// PBES2-params ::= SEQUENCE {
///   keyDerivationFunc  AlgorithmIdentifier,   -- id-PBKDF2
///   encryptionScheme   AlgorithmIdentifier }
/// ```
fn pbes2(parameters: &[u8], ciphertext: &[u8], password: &[u8])
         -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(parameters);
    let mut params = reader.read_sequence()?;
    reader.finish()?;

    let mut kdf = params.read_sequence()?;
    let kdf_oid = kdf.read_oid()?;
    if kdf_oid.as_bytes() != oids::PBKDF2 {
        return Err(format!("PBES2 with key derivation {}, which is not PBKDF2. \
                            No other is defined.", dotted(&kdf_oid)));
    }
    let kdf_parameters = kdf.remaining();

    let mut encryption = params.read_sequence()?;
    let cipher_oid = encryption.read_oid()?;
    let cipher_parameters = encryption.remaining();
    params.finish()?;

    let recipe = pbes2_cipher(cipher_oid.as_bytes())
        .ok_or_else(|| format!("PBES2 with cipher {}, which this library does \
                                not know.", dotted(&cipher_oid)))?;
    let (recipe, iv) = pbes2_cipher_parameters(recipe, cipher_parameters)?;

    let key = pbkdf2_from_parameters(kdf_parameters, password, recipe.key_len)?;
    decipher(&recipe, &key, &iv, ciphertext)
}

/// ```text
/// PBKDF2-params ::= SEQUENCE {
///   salt            OCTET STRING,          -- the `specified` CHOICE
///   iterationCount  INTEGER,
///   keyLength       INTEGER OPTIONAL,
///   prf             AlgorithmIdentifier DEFAULT hmacWithSHA1 }
/// ```
fn pbkdf2_from_parameters(parameters: &[u8], password: &[u8], want_key_len: usize)
                          -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(parameters);
    let mut params = reader.read_sequence()?;
    reader.finish()?;

    // The `otherSource` CHOICE is an AlgorithmIdentifier and has never
    // been used by anything; refusing it by name beats a confusing
    // "expected OCTET STRING".
    let salt = params.read_octet_string().map_err(|reason| {
        format!("PBKDF2 salt: {} (the `otherSource` form is not supported; \
                 nothing is known to write it)", reason)
    })?;
    let iterations = read_iterations(&mut params)?;

    // keyLength is optional and, when present, is advisory: the cipher
    // decides how much key it needs. Read to keep the parse in step,
    // and checked rather than trusted, because a file whose stated
    // length disagrees with its own cipher is malformed and silently
    // preferring either answer hides that.
    let mut stated_key_len = None;
    if params.peek_tag() == Some(Tag::universal(tag::INTEGER)) {
        stated_key_len = Some(params.read_u32()? as usize);
    }
    if let Some(stated) = stated_key_len {
        if stated != want_key_len {
            return Err(format!("PBKDF2 says the key is {} bytes but the cipher \
                                takes {}.", stated, want_key_len));
        }
    }

    // DEFAULT hmacWithSHA1 means absent, and absent is the common case
    // in older files. Defaulting to SHA-256 here - which looks more
    // modern and more sensible - would fail to open every one of them.
    let hash_name = if params.is_empty() {
        "sha1"
    } else {
        let mut prf = params.read_sequence()?;
        let prf_oid = prf.read_oid()?;
        hmac_prf(prf_oid.as_bytes())
            .ok_or_else(|| format!("PBKDF2 with PRF {}, which this library does \
                                    not know.", dotted(&prf_oid)))?
    };
    params.finish()?;

    derive_pbkdf2(hash_name, password, salt, iterations, want_key_len)
}

fn derive_pbkdf2(hash_name: &str, password: &[u8], salt: &[u8], iterations: u32,
                 length: usize) -> Result<Vec<u8>, String> {
    match hash_name {
        "sha1" => pbkdf2(SHA1::new(&[]), password, salt, iterations, length),
        "sha224" => pbkdf2(sha2::SHA224::new(&[]), password, salt, iterations, length),
        "sha256" => pbkdf2(sha2::SHA256::new(&[]), password, salt, iterations, length),
        "sha384" => pbkdf2(sha2::SHA384::new(&[]), password, salt, iterations, length),
        "sha512" => pbkdf2(sha2::SHA512::new(&[], 512), password, salt, iterations, length),
        "sha512_224" => pbkdf2(sha2::SHA512::new(&[], 224), password, salt, iterations, length),
        "sha512_256" => pbkdf2(sha2::SHA512::new(&[], 256), password, salt, iterations, length),
        other => Err(format!("No PBKDF2 PRF for {}.", other)),
    }
}

fn hmac_prf(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        o if o == oids::HMAC_WITH_SHA1 => "sha1",
        o if o == oids::HMAC_WITH_SHA224 => "sha224",
        o if o == oids::HMAC_WITH_SHA256 => "sha256",
        o if o == oids::HMAC_WITH_SHA384 => "sha384",
        o if o == oids::HMAC_WITH_SHA512 => "sha512",
        o if o == oids::HMAC_WITH_SHA512_224 => "sha512_224",
        o if o == oids::HMAC_WITH_SHA512_256 => "sha512_256",
        _ => return None,
    })
}

fn pbes2_cipher(oid: &[u8]) -> Option<Recipe> {
    Some(match oid {
        o if o == oids::AES128_CBC =>
            Recipe { key_len: 16, iv_len: 16, cipher: CipherKind::Aes },
        o if o == oids::AES192_CBC =>
            Recipe { key_len: 24, iv_len: 16, cipher: CipherKind::Aes },
        o if o == oids::AES256_CBC =>
            Recipe { key_len: 32, iv_len: 16, cipher: CipherKind::Aes },
        o if o == oids::DES_EDE3_CBC =>
            Recipe { key_len: 24, iv_len: 8, cipher: CipherKind::TripleDes },
        o if o == oids::DES_CBC =>
            Recipe { key_len: 8, iv_len: 8, cipher: CipherKind::Des },
        o if o == oids::RC2_CBC =>
            // A placeholder: `pbes2_cipher_parameters` replaces both
            // numbers from the RC2-CBC-Parameter, where an absent
            // version means 32 effective bits (RFC 8018 B.2.3), not 128.
            Recipe { key_len: 16, iv_len: 8,
                     cipher: CipherKind::Rc2 { effective_bits: 128 } },
        _ => return None,
    })
}

/// Pull the IV out of a PBES2 encryption scheme's parameters, and for
/// RC2 the key length too.
///
/// ```text
/// RC2-CBC-Parameter ::= SEQUENCE {
///   rc2ParameterVersion  INTEGER OPTIONAL,
///   iv                   OCTET STRING (SIZE(8)) }
/// ```
/// Everything else carries a bare `OCTET STRING` IV.
fn pbes2_cipher_parameters(recipe: Recipe, parameters: &[u8])
                           -> Result<(Recipe, Vec<u8>), String> {
    let mut reader = Reader::new(parameters);
    if let CipherKind::Rc2 { .. } = recipe.cipher {
        let mut sequence = reader.read_sequence()?;
        reader.finish()?;
        let mut version = None;
        if sequence.peek_tag() == Some(Tag::universal(tag::INTEGER)) {
            version = Some(sequence.read_u32()?);
        }
        let iv = sequence.read_octet_string()?.to_vec();
        sequence.finish()?;
        let effective_bits = match version {
            None => 32,
            Some(version) => rc2_version_to_bits(version)?,
        };
        let key_len = effective_bits.div_ceil(8) as usize;
        return Ok((Recipe { key_len, iv_len: 8,
                            cipher: CipherKind::Rc2 { effective_bits } }, iv));
    }
    let iv = reader.read_octet_string()?.to_vec();
    reader.finish()?;
    if iv.len() != recipe.iv_len {
        return Err(format!("The IV is {} bytes, but this cipher takes {}.",
                           iv.len(), recipe.iv_len));
    }
    Ok((recipe, iv))
}

/// RC2's parameter version, RFC 8018 B.2.3.
///
/// A small table below 256 and the value itself above it, which is one
/// of the least guessable encodings in any of these standards - the
/// table is not a formula and the three entries are the three that
/// matter (40, 64 and 128 bit effective keys).
fn rc2_version_to_bits(version: u32) -> Result<u32, String> {
    Ok(match version {
        160 => 40,
        120 => 64,
        58 => 128,
        // RC2's key is at most 128 bytes (RFC 2268), so an effective
        // length past 1024 bits names a key the cipher cannot hold -
        // and the value sizes the derived key, so an unbounded one is
        // a derivation of up to half a gigabyte.
        other if other > 1024 => return Err(format!(
            "RC2 parameters name {} effective key bits; the cipher's key is \
             at most 1024.", other)),
        other if other >= 256 => other,
        // Anything else below 256 is not in the table. Treated as the
        // value itself rather than refused, because a file that used an
        // unlisted version is still a file somebody needs to open, and
        // the worst case is a wrong key rather than a wrong answer -
        // the padding check below catches it.
        other => other,
    })
}

// -------------------------------------------------------------- PBES1 ---

/// The six PBES1 schemes, RFC 8018 A.3.
///
/// Returned as the hash for PBKDF1 and the cipher it feeds.
fn pbes1_scheme(oid: &[u8]) -> Option<(&'static str, CipherKind)> {
    Some(match oid {
        o if o == oids::PBE_MD2_DES => ("md2", CipherKind::Des),
        o if o == oids::PBE_MD2_RC2 => ("md2", CipherKind::Rc2 { effective_bits: 64 }),
        o if o == oids::PBE_MD5_DES => ("md5", CipherKind::Des),
        o if o == oids::PBE_MD5_RC2 => ("md5", CipherKind::Rc2 { effective_bits: 64 }),
        o if o == oids::PBE_SHA1_DES => ("sha1", CipherKind::Des),
        o if o == oids::PBE_SHA1_RC2 => ("sha1", CipherKind::Rc2 { effective_bits: 64 }),
        _ => return None,
    })
}

/// ```text
/// PBEParameter ::= SEQUENCE {
///   salt            OCTET STRING (SIZE(8)),
///   iterationCount  INTEGER }
/// ```
///
/// PBKDF1 gives 16 bytes and both ciphers take 8 of key and 8 of IV, so
/// the split is exactly the whole output - that is the arithmetic that
/// fixed PBES1 at 64 bit ciphers forever.
fn pbes1(parameters: &[u8], ciphertext: &[u8], password: &[u8],
         hash_name: &'static str, cipher: CipherKind) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(parameters);
    let mut params = reader.read_sequence()?;
    reader.finish()?;
    let salt = params.read_octet_string()?;
    let iterations = read_iterations(&mut params)?;
    params.finish()?;

    if salt.len() != 8 {
        return Err(format!("PBES1 salt is {} bytes; the standard fixes it at 8.",
                           salt.len()));
    }

    let derived = match hash_name {
        "md5" => pbkdf1(MD5::new(&[]), password, salt, iterations, 16)?,
        "sha1" => pbkdf1(SHA1::new(&[]), password, salt, iterations, 16)?,
        "md2" => pbkdf1(crate::hash_functions::md2::Md2::new(&[]), password, salt,
                        iterations, 16)?,
        other => return Err(format!("No PBKDF1 hash for {}.", other)),
    };

    let recipe = match cipher {
        CipherKind::Des => Recipe { key_len: 8, iv_len: 8, cipher },
        CipherKind::Rc2 { .. } =>
            Recipe { key_len: 8, iv_len: 8,
                     cipher: CipherKind::Rc2 { effective_bits: 64 } },
        other => return Err(format!("PBES1 cannot use {:?}.", other)),
    };
    decipher(&recipe, &derived[..8], &derived[8..16], ciphertext)
}

// ---------------------------------------------------------- PKCS#12 PBE ---

/// The PKCS#12 password schemes, RFC 7292 Appendix C.
///
/// `PBE-SHA1-3DES` is the one that matters: it is what
/// `openssl pkcs8 -topk8 -v1` writes by default and what the inside of
/// every `.p12` looks like.
fn pkcs12_scheme(oid: &[u8]) -> Option<Recipe> {
    Some(match oid {
        o if o == oids::PBE_SHA1_3DES =>
            Recipe { key_len: 24, iv_len: 8, cipher: CipherKind::TripleDes },
        o if o == oids::PBE_SHA1_2DES =>
            // Two-key 3DES: the KDF gives K1 K2, which `TripleDes` takes
            // as K1 K2 K1.
            Recipe { key_len: 16, iv_len: 8, cipher: CipherKind::TripleDes },
        o if o == oids::PBE_SHA1_RC2_128 =>
            Recipe { key_len: 16, iv_len: 8,
                     cipher: CipherKind::Rc2 { effective_bits: 128 } },
        o if o == oids::PBE_SHA1_RC2_40 =>
            Recipe { key_len: 5, iv_len: 8,
                     cipher: CipherKind::Rc2 { effective_bits: 40 } },
        o if o == oids::PBE_SHA1_128_RC4 =>
            Recipe { key_len: 16, iv_len: 0, cipher: CipherKind::Rc4 },
        o if o == oids::PBE_SHA1_RC4_40 =>
            Recipe { key_len: 5, iv_len: 0, cipher: CipherKind::Rc4 },
        _ => return None,
    })
}

fn pkcs12_pbe(parameters: &[u8], ciphertext: &[u8], password: &[u8], recipe: Recipe)
              -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(parameters);
    let mut params = reader.read_sequence()?;
    reader.finish()?;
    let salt = params.read_octet_string()?;
    let iterations = read_iterations(&mut params)?;
    params.finish()?;

    // The password arrives here as bytes but PKCS#12 hashes a BMPString,
    // so it has to be interpreted as text first. Non-UTF-8 is refused
    // rather than passed through: there is no defined answer, and
    // guessing produces a wrong key and an unhelpful padding error.
    let text = core::str::from_utf8(password).map_err(|_| {
        "A PKCS#12 scheme needs the password as text (it hashes a BMPString), \
         and this one is not valid UTF-8.".to_string()
    })?;

    // The empty password is genuinely ambiguous - an empty BMPString
    // is two NUL bytes, and some writers hash no bytes at all instead -
    // so both are tried. `openssl pkcs8 -passout pass:` hashes the two
    // NULs (`encrypt` reproduces its file that way). This is not
    // laziness: a file written by either has to open.
    let candidates: Vec<Vec<u8>> = if text.is_empty() {
        vec![Vec::new(), vec![0, 0]]
    } else {
        vec![crate::kdf::password::pkcs12_bmp_password(text)]
    };

    let mut last = String::new();
    for bmp in candidates {
        let key = pkcs12_kdf(SHA1::new(&[]), &bmp, salt, Pkcs12Purpose::Key,
                             iterations, recipe.key_len)?;
        let iv = if recipe.iv_len == 0 {
            Vec::new()
        } else {
            pkcs12_kdf(SHA1::new(&[]), &bmp, salt, Pkcs12Purpose::Iv,
                       iterations, recipe.iv_len)?
        };
        match decipher(&recipe, &key, &iv, ciphertext) {
            Ok(plain) => return Ok(plain),
            Err(reason) => last = reason,
        }
    }
    Err(last)
}

// ------------------------------------------------------------- the cipher ---

/// CBC-decrypt (or RC4-decrypt) and strip the padding.
///
/// **The padding check is the only thing standing between a wrong
/// password and a confident wrong answer.** None of these schemes carries
/// an authentication tag, so a wrong key decrypts to random bytes and the
/// only signal that anything is wrong is that those bytes do not end in
/// valid PKCS#7 padding. That catches a wrong password about 255 times
/// out of 256; the parse that follows catches almost all of the rest.
fn decipher(recipe: &Recipe, key: &[u8], iv: &[u8], ciphertext: &[u8])
            -> Result<Vec<u8>, String> {
    if ciphertext.is_empty() {
        return Err("The encrypted key is empty.".to_string());
    }

    let plain = match recipe.cipher {
        CipherKind::Rc4 => {
            use crate::stream_ciphers::StreamCipher;
            let mut rc4 = crate::stream_ciphers::rc4::RC4::new(key)?;
            let mut out = Vec::new();
            rc4.crypt(ciphertext, &mut out);
            // A stream cipher has no padding to strip, and nothing to
            // check. Returned as is; the DER parse is the only guard.
            return Ok(out);
        }
        CipherKind::Aes => cbc_decrypt(
            crate::block_ciphers::aes::AesCrypto::new(key)?, iv, ciphertext)?,
        CipherKind::TripleDes => cbc_decrypt(
            crate::block_ciphers::des::TripleDes::new(key)?, iv, ciphertext)?,
        CipherKind::Des => cbc_decrypt(
            crate::block_ciphers::des::Des::new(key)?, iv, ciphertext)?,
        CipherKind::Rc2 { effective_bits } => cbc_decrypt(
            crate::block_ciphers::rc2::RC2::with_effective_bits(
                key, effective_bits as usize)?, iv, ciphertext)?,
    };

    crate::api::unpad_pkcs7(&plain, recipe_block_size(recipe)).map_err(|_| {
        "The decrypted key is not validly padded, which almost always means \
         the password is wrong.".to_string()
    })
}

fn recipe_block_size(recipe: &Recipe) -> usize {
    match recipe.cipher {
        CipherKind::Aes => 16,
        CipherKind::TripleDes | CipherKind::Des | CipherKind::Rc2 { .. } => 8,
        CipherKind::Rc4 => 1,
    }
}

fn cbc_decrypt<C: BlockCipher>(mut cipher: C, iv: &[u8], ciphertext: &[u8])
                               -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    if iv.len() != block {
        return Err(format!("The IV is {} bytes and the cipher's block is {}.",
                           iv.len(), block));
    }
    if !ciphertext.len().is_multiple_of(block) {
        return Err(format!("The ciphertext is {} bytes, not a whole number of \
                            {} byte blocks.", ciphertext.len(), block));
    }
    let mut state = CbcState::new(&mut cipher, iv, true)?;
    let mut out = Vec::with_capacity(ciphertext.len());
    state.update(&mut cipher, ciphertext, &mut out)?;
    Ok(out)
}

// ------------------------------------------------------------ encrypting ---

/// How a scheme is spelled: the family, the OID, and what the key
/// derivation has to produce.
#[derive(Clone, Copy)]
enum Family {
    /// PBKDF2 and a cipher named by its own OID inside PBES2.
    Pbes2,
    /// PBKDF1 over the named hash.
    Pbes1(&'static str),
    Pkcs12,
}

struct Named {
    name: &'static str,
    family: Family,
    oid: &'static [u8],
    recipe: Recipe,
}

const fn recipe(key_len: usize, iv_len: usize, cipher: CipherKind) -> Recipe {
    Recipe { key_len, iv_len, cipher }
}

/// Every scheme `encrypt` writes and `parameters` names. The PBES2 rows
/// are named for the cipher, as `openssl pkcs8 -v2` takes them; the
/// others as `-v1` does, in lower case.
const SCHEMES: &[Named] = &[
    Named { name: "aes-128-cbc", family: Family::Pbes2, oid: oids::AES128_CBC,
            recipe: recipe(16, 16, CipherKind::Aes) },
    Named { name: "aes-192-cbc", family: Family::Pbes2, oid: oids::AES192_CBC,
            recipe: recipe(24, 16, CipherKind::Aes) },
    Named { name: "aes-256-cbc", family: Family::Pbes2, oid: oids::AES256_CBC,
            recipe: recipe(32, 16, CipherKind::Aes) },
    Named { name: "des-ede3-cbc", family: Family::Pbes2, oid: oids::DES_EDE3_CBC,
            recipe: recipe(24, 8, CipherKind::TripleDes) },
    Named { name: "des-cbc", family: Family::Pbes2, oid: oids::DES_CBC,
            recipe: recipe(8, 8, CipherKind::Des) },
    Named { name: "rc2-cbc", family: Family::Pbes2, oid: oids::RC2_CBC,
            recipe: recipe(16, 8, CipherKind::Rc2 { effective_bits: 128 }) },
    Named { name: "rc2-64-cbc", family: Family::Pbes2, oid: oids::RC2_CBC,
            recipe: recipe(8, 8, CipherKind::Rc2 { effective_bits: 64 }) },
    Named { name: "rc2-40-cbc", family: Family::Pbes2, oid: oids::RC2_CBC,
            recipe: recipe(5, 8, CipherKind::Rc2 { effective_bits: 40 }) },
    Named { name: "pbe-md2-des", family: Family::Pbes1("md2"), oid: oids::PBE_MD2_DES,
            recipe: recipe(8, 8, CipherKind::Des) },
    Named { name: "pbe-md2-rc2-64", family: Family::Pbes1("md2"), oid: oids::PBE_MD2_RC2,
            recipe: recipe(8, 8, CipherKind::Rc2 { effective_bits: 64 }) },
    Named { name: "pbe-md5-des", family: Family::Pbes1("md5"), oid: oids::PBE_MD5_DES,
            recipe: recipe(8, 8, CipherKind::Des) },
    Named { name: "pbe-md5-rc2-64", family: Family::Pbes1("md5"), oid: oids::PBE_MD5_RC2,
            recipe: recipe(8, 8, CipherKind::Rc2 { effective_bits: 64 }) },
    Named { name: "pbe-sha1-des", family: Family::Pbes1("sha1"), oid: oids::PBE_SHA1_DES,
            recipe: recipe(8, 8, CipherKind::Des) },
    Named { name: "pbe-sha1-rc2-64", family: Family::Pbes1("sha1"), oid: oids::PBE_SHA1_RC2,
            recipe: recipe(8, 8, CipherKind::Rc2 { effective_bits: 64 }) },
    Named { name: "pbe-sha1-3des", family: Family::Pkcs12, oid: oids::PBE_SHA1_3DES,
            recipe: recipe(24, 8, CipherKind::TripleDes) },
    Named { name: "pbe-sha1-2des", family: Family::Pkcs12, oid: oids::PBE_SHA1_2DES,
            recipe: recipe(16, 8, CipherKind::TripleDes) },
    Named { name: "pbe-sha1-rc2-128", family: Family::Pkcs12, oid: oids::PBE_SHA1_RC2_128,
            recipe: recipe(16, 8, CipherKind::Rc2 { effective_bits: 128 }) },
    Named { name: "pbe-sha1-rc2-40", family: Family::Pkcs12, oid: oids::PBE_SHA1_RC2_40,
            recipe: recipe(5, 8, CipherKind::Rc2 { effective_bits: 40 }) },
    Named { name: "pbe-sha1-rc4-128", family: Family::Pkcs12, oid: oids::PBE_SHA1_128_RC4,
            recipe: recipe(16, 0, CipherKind::Rc4) },
    Named { name: "pbe-sha1-rc4-40", family: Family::Pkcs12, oid: oids::PBE_SHA1_RC4_40,
            recipe: recipe(5, 0, CipherKind::Rc4) },
];

/// The names `encrypt` takes, in the order above.
pub fn scheme_names() -> Vec<&'static str> {
    SCHEMES.iter().map(|n| n.name).collect()
}

/// The PBKDF2 PRF's OID for a hash name.
fn prf_oid(hash: &str) -> Option<&'static [u8]> {
    Some(match hash {
        "sha1" => oids::HMAC_WITH_SHA1,
        "sha224" => oids::HMAC_WITH_SHA224,
        "sha256" => oids::HMAC_WITH_SHA256,
        "sha384" => oids::HMAC_WITH_SHA384,
        "sha512" => oids::HMAC_WITH_SHA512,
        "sha512_224" => oids::HMAC_WITH_SHA512_224,
        "sha512_256" => oids::HMAC_WITH_SHA512_256,
        _ => return None,
    })
}

/// RC2's parameter version for an effective key length, the inverse of
/// `rc2_version_to_bits` for the three lengths in RFC 8018's table.
fn rc2_bits_to_version(bits: u32) -> u32 {
    match bits {
        40 => 160,
        64 => 120,
        128 => 58,
        other => other,
    }
}

/// Encrypt a `PrivateKeyInfo` into an `EncryptedPrivateKeyInfo`.
///
/// `scheme` is one of `scheme_names()`: a cipher name for PBES2
/// (`aes-256-cbc`, `des-ede3-cbc`, `rc2-40-cbc`, ...) or a `pbe-...`
/// name for PBES1 and the PKCS#12 PBEs. `prf` is PBES2's PBKDF2 hash,
/// and must be `None` for the others, whose hash is part of the scheme.
/// `iv` is the cipher's IV for PBES2 and empty for the others, which
/// derive it.
///
/// What is written is what OpenSSL writes for the same inputs, byte for
/// byte: the PRF left out when it is SHA-1 (its DEFAULT), PBKDF2's
/// `keyLength` written only for RC2, whose key length is variable. The
/// tests re-encrypt OpenSSL's own files and compare.
///
/// PBES1 fixes the salt at eight bytes; the others take any salt.
pub fn encrypt(plain: &[u8], password: &[u8], scheme: &str, prf: Option<&str>,
               iterations: u32, salt: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let named = SCHEMES.iter().find(|n| n.name == scheme).ok_or_else(|| {
        format!("Unknown key encryption scheme {scheme:?}; these are known: {}.",
                scheme_names().join(", "))
    })?;
    if iterations == 0 {
        return Err("A key encryption scheme needs at least one iteration.".to_string());
    }
    let recipe = named.recipe;
    let mut w = crate::asn1::Writer::new();
    let (key, iv) = match named.family {
        Family::Pbes2 => {
            let hash = prf.unwrap_or("sha256");
            let prf_oid = prf_oid(hash).ok_or_else(|| format!("No PBKDF2 PRF for {hash}."))?;
            if iv.len() != recipe.iv_len {
                return Err(format!("{scheme} takes a {}-byte IV, not {}.", recipe.iv_len,
                                   iv.len()));
            }
            w.write_sequence(|w| {
                w.write_oid(oids::PBES2);
                w.write_sequence(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(oids::PBKDF2);
                        w.write_sequence(|w| {
                            w.write_octet_string(salt);
                            w.write_u32(iterations);
                            if let CipherKind::Rc2 { .. } = recipe.cipher {
                                w.write_u32(recipe.key_len as u32);
                            }
                            if hash != "sha1" {
                                w.write_sequence(|w| {
                                    w.write_oid(prf_oid);
                                    w.write_null();
                                });
                            }
                        });
                    });
                    w.write_sequence(|w| {
                        w.write_oid(named.oid);
                        if let CipherKind::Rc2 { effective_bits } = recipe.cipher {
                            w.write_sequence(|w| {
                                w.write_u32(rc2_bits_to_version(effective_bits));
                                w.write_octet_string(iv);
                            });
                        } else {
                            w.write_octet_string(iv);
                        }
                    });
                });
            });
            (derive_pbkdf2(hash, password, salt, iterations, recipe.key_len)?, iv.to_vec())
        }
        Family::Pbes1(hash) => {
            refuse_prf_and_iv(scheme, prf, iv)?;
            if salt.len() != 8 {
                return Err(format!("PBES1's salt is 8 bytes, not {}.", salt.len()));
            }
            let derived = match hash {
                "md2" => pbkdf1(crate::hash_functions::md2::Md2::new(&[]), password, salt,
                                iterations, 16)?,
                "md5" => pbkdf1(MD5::new(&[]), password, salt, iterations, 16)?,
                _ => pbkdf1(SHA1::new(&[]), password, salt, iterations, 16)?,
            };
            write_salt_and_count(&mut w, named.oid, salt, iterations);
            (derived[..8].to_vec(), derived[8..16].to_vec())
        }
        Family::Pkcs12 => {
            refuse_prf_and_iv(scheme, prf, iv)?;
            let text = core::str::from_utf8(password).map_err(|_| {
                "A PKCS#12 scheme needs the password as text (it hashes a BMPString), \
                 and this one is not valid UTF-8.".to_string()
            })?;
            // The empty password is written as an empty BMPString's
            // two NULs, which is what `openssl pkcs8 -passout pass:`
            // hashes - the fixture written that way is reproduced byte
            // for byte. Reading tries no bytes as well.
            let bmp = crate::kdf::password::pkcs12_bmp_password(text);
            let key = pkcs12_kdf(SHA1::new(&[]), &bmp, salt, Pkcs12Purpose::Key, iterations,
                                 recipe.key_len)?;
            let iv = if recipe.iv_len == 0 {
                Vec::new()
            } else {
                pkcs12_kdf(SHA1::new(&[]), &bmp, salt, Pkcs12Purpose::Iv, iterations,
                           recipe.iv_len)?
            };
            write_salt_and_count(&mut w, named.oid, salt, iterations);
            (key, iv)
        }
    };
    let algorithm = w.finish();
    let ciphertext = encipher(&recipe, &key, &iv, plain)?;
    let mut out = crate::asn1::Writer::new();
    out.write_sequence(|w| {
        w.write_raw(&algorithm);
        w.write_octet_string(&ciphertext);
    });
    Ok(out.finish())
}

fn refuse_prf_and_iv(scheme: &str, prf: Option<&str>, iv: &[u8]) -> Result<(), String> {
    if prf.is_some() {
        return Err(format!("{scheme} has its hash in its name; a PRF is for PBES2 only."));
    }
    if !iv.is_empty() {
        return Err(format!("{scheme} derives its IV from the password; none is given."));
    }
    Ok(())
}

/// PBEParameter: the scheme's OID, then SEQUENCE { salt, iterations }.
fn write_salt_and_count(w: &mut crate::asn1::Writer, oid: &[u8], salt: &[u8], iterations: u32) {
    w.write_sequence(|w| {
        w.write_oid(oid);
        w.write_sequence(|w| {
            w.write_octet_string(salt);
            w.write_u32(iterations);
        });
    });
}

/// PKCS#7-pad and CBC-encrypt, or RC4-encrypt.
fn encipher(recipe: &Recipe, key: &[u8], iv: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    use crate::block_ciphers::{aes::AesCrypto, des::Des, des::TripleDes, rc2::RC2};
    if let CipherKind::Rc4 = recipe.cipher {
        use crate::stream_ciphers::StreamCipher;
        let mut out = Vec::with_capacity(plain.len());
        crate::stream_ciphers::rc4::RC4::new(key)?.crypt(plain, &mut out);
        return Ok(out);
    }
    let padded = crate::api::pad_pkcs7(plain, recipe_block_size(recipe))?;
    let mut out = Vec::with_capacity(padded.len());
    match recipe.cipher {
        CipherKind::Aes => AesCrypto::new(key)?.cbc_encrypt(&padded, &mut out,
                                                                      iv)?,
        CipherKind::TripleDes => TripleDes::new(key)?.cbc_encrypt(&padded, &mut out,
                                                                            iv)?,
        CipherKind::Des => Des::new(key)?.cbc_encrypt(&padded, &mut out, iv)?,
        CipherKind::Rc2 { effective_bits } =>
            RC2::with_effective_bits(key, effective_bits as usize)?
                .cbc_encrypt(&padded, &mut out, iv)?,
        CipherKind::Rc4 => unreachable!("handled above"),
    }
    Ok(out)
}

/// How an `EncryptedPrivateKeyInfo` was encrypted: the scheme by the name
/// `encrypt` takes, PBES2's PRF, and the salt, count and (for PBES2) IV.
/// Handing these back to `encrypt` with the decrypted key reproduces the
/// file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub scheme: &'static str,
    pub prf: Option<&'static str>,
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
}

/// Read an `EncryptedPrivateKeyInfo`'s scheme and parameters, without
/// the password.
pub fn parameters(der: &[u8]) -> Result<Parameters, String> {
    let mut outer = Reader::new(der);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;
    let mut algorithm = sequence.read_sequence()?;
    let scheme = algorithm.read_oid()?;
    let mut reader = Reader::new(algorithm.remaining());
    let mut params = reader.read_sequence()?;
    reader.finish()?;
    if scheme.as_bytes() != oids::PBES2 {
        let named = SCHEMES.iter()
            .find(|n| !matches!(n.family, Family::Pbes2) && n.oid == scheme.as_bytes())
            .ok_or_else(|| format!("No scheme here is {}.", dotted(&scheme)))?;
        let salt = params.read_octet_string()?.to_vec();
        let iterations = params.read_u32()?;
        params.finish()?;
        return Ok(Parameters { scheme: named.name, prf: None, iterations, salt,
                               iv: Vec::new() });
    }
    let mut kdf = params.read_sequence()?;
    if kdf.read_oid()?.as_bytes() != oids::PBKDF2 {
        return Err("PBES2 with a key derivation other than PBKDF2.".to_string());
    }
    let mut kdf_params = kdf.read_sequence()?;
    let salt = kdf_params.read_octet_string()?.to_vec();
    let iterations = kdf_params.read_u32()?;
    if kdf_params.peek_tag() == Some(Tag::universal(tag::INTEGER)) {
        kdf_params.read_u32()?;
    }
    let prf = if kdf_params.is_empty() {
        "sha1"
    } else {
        let mut prf = kdf_params.read_sequence()?;
        let oid = prf.read_oid()?;
        hmac_prf(oid.as_bytes()).ok_or_else(|| format!("PBKDF2 PRF {}.", dotted(&oid)))?
    };
    let mut encryption = params.read_sequence()?;
    let cipher = encryption.read_oid()?;
    let recipe = pbes2_cipher(cipher.as_bytes())
        .ok_or_else(|| format!("PBES2 cipher {}.", dotted(&cipher)))?;
    let (recipe, iv) = pbes2_cipher_parameters(recipe, encryption.remaining())?;
    let named = SCHEMES.iter()
        .find(|n| matches!(n.family, Family::Pbes2) && n.oid == cipher.as_bytes()
              && n.recipe.cipher == recipe.cipher)
        .ok_or_else(|| format!("PBES2 cipher {} with {:?}.", dotted(&cipher), recipe.cipher))?;
    Ok(Parameters { scheme: named.name, prf: Some(prf), iterations, salt, iv })
}

// ------------------------------------------------ Java's key protectors --

/// The password as the JDK hashes it for JKS: UTF-16 big endian, no
/// terminator.
fn utf16be(password: &[u8]) -> Result<Vec<u8>, String> {
    let text = core::str::from_utf8(password).map_err(|_| {
        "A JKS key password is text (it is hashed as UTF-16), and this one is \
         not valid UTF-8.".to_string()
    })?;
    Ok(text.encode_utf16().flat_map(u16::to_be_bytes).collect())
}

fn sha1_of(parts: &[&[u8]]) -> Vec<u8> {
    use crate::hash_functions::HashFunction;
    let mut h = SHA1::new(&[]);
    for part in parts {
        h.update(part);
    }
    h.digest()
}

/// JKS's key protector (`sun.security.provider.KeyProtector`, OID
/// 1.3.6.1.4.1.42.2.17.1.1): a 20-byte salt, then the key XORed with a
/// keystream of SHA-1 digests - each the hash of the password and the
/// previous digest, the salt first - then SHA-1 of the password and the
/// plaintext as a check. Sun's own, and no stronger than it sounds: a
/// password guess costs two hashes. `salt` is 20 bytes.
pub fn jks_protect(plain: &[u8], password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    if salt.len() != 20 {
        return Err(format!("A JKS key protector salt is 20 bytes, not {}.", salt.len()));
    }
    let p = utf16be(password)?;
    let mut out = salt.to_vec();
    let mut digest = salt.to_vec();
    for chunk in plain.chunks(20) {
        digest = sha1_of(&[&p, &digest]);
        out.extend(chunk.iter().zip(&digest).map(|(c, k)| c ^ k));
    }
    out.extend(sha1_of(&[&p, plain]));
    Ok(out)
}

/// The inverse of `jks_protect`, refusing a wrong password by its check.
pub fn jks_unprotect(protected: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    if protected.len() < 40 {
        return Err("A JKS protected key shorter than its salt and check.".to_string());
    }
    let p = utf16be(password)?;
    let (salt, rest) = protected.split_at(20);
    let (body, check) = rest.split_at(rest.len() - 20);
    let mut plain = Vec::with_capacity(body.len());
    let mut digest = salt.to_vec();
    for chunk in body.chunks(20) {
        digest = sha1_of(&[&p, &digest]);
        plain.extend(chunk.iter().zip(&digest).map(|(c, k)| c ^ k));
    }
    if crate::bignum::ct::bytes_differ(&sha1_of(&[&p, &plain]), check) {
        return Err("Wrong key password: the JKS key check does not match.".to_string());
    }
    Ok(plain)
}

/// The JDK's password for `PBEWithMD5AndTripleDES`: printable ASCII,
/// as `PBEKey` insists.
fn jdk_ascii(password: &[u8]) -> Result<&[u8], String> {
    if !password.iter().all(|&c| (b' '..=b'~').contains(&c)) {
        return Err("A PBEWithMD5AndTripleDES password is printable ASCII.".to_string());
    }
    Ok(password)
}

/// `PBEWithMD5AndTripleDES` (JCEKS's key protector, OID
/// 1.3.6.1.4.1.42.2.19.1): the key and IV of
/// `kdf::password::jdk_pbe_md5_3des_key`, and 3DES in CBC with PKCS#5
/// padding.
pub fn jdk_pbe_md5_3des_encrypt(password: &[u8], salt: &[u8], iterations: u32, plain: &[u8])
                                -> Result<Vec<u8>, String> {
    let (key, iv) = crate::kdf::password::jdk_pbe_md5_3des_key(
        jdk_ascii(password)?, salt, iterations)?;
    let mut cipher = crate::block_ciphers::des::TripleDes::new(&key)?;
    let mut state = CbcState::new(&mut cipher, &iv, false)?;
    let mut out = Vec::with_capacity(plain.len() + 8);
    state.update(&mut cipher, &crate::api::pad_pkcs7(plain, 8)?, &mut out)?;
    Ok(out)
}

pub fn jdk_pbe_md5_3des_decrypt(password: &[u8], salt: &[u8], iterations: u32,
                                ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let (key, iv) = crate::kdf::password::jdk_pbe_md5_3des_key(
        jdk_ascii(password)?, salt, iterations)?;
    let recipe = Recipe { key_len: 24, iv_len: 8, cipher: CipherKind::TripleDes };
    decipher(&recipe, &key, &iv, ciphertext)
}

/// An OID as its dotted form when the library knows it, and as hex when
/// it does not - so an error about an unsupported scheme names something
/// the reader can search for.
fn dotted(oid: &Oid) -> String {
    match oids::name_of(oid.as_bytes()) {
        Some(dotted) => dotted.to_string(),
        None => format!("(unknown OID, DER {})", crate::to_hex(oid.as_bytes())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The optional `keyLength` is recognised by its whole tag, not by
    /// its tag number.
    ///
    /// What was wrong: three copies of the same peek matched
    /// `Tag { number: 2, .. }`, so any tag numbered 2 - a context
    /// `[2]`, say - was taken for the INTEGER and handed to `read_u32`,
    /// which then failed with a message about the integer rather than
    /// about the field that was actually there. Every other peek in the
    /// crate compares the full tag. The existing tests read real files,
    /// whose optional field is either absent or a proper INTEGER.
    #[test]
    fn test_pbkdf2_key_length_is_matched_by_its_whole_tag() {
        use crate::asn1::Writer;
        let build = |key_length: Option<&[u8]>, odd_tag: bool| {
            let mut writer = Writer::new();
            writer.write_sequence(|w| {
                w.write_octet_string(b"salt");
                w.write_u32(2);
                if let Some(bytes) = key_length {
                    w.write_tlv(Tag::universal(tag::INTEGER), bytes);
                }
                if odd_tag {
                    w.write_tlv(Tag::context(2, false), &[16]);
                }
            });
            writer.finish()
        };

        // A proper keyLength that agrees with the cipher is read, and
        // the derived key is PBKDF2's own.
        let key = pbkdf2_from_parameters(&build(Some(&[16]), false), b"pw", 16).unwrap();
        let expected = pbkdf2(SHA1::new(&[]), b"pw", b"salt", 2, 16).unwrap();
        assert_eq!(key, expected);

        // A context [2] where keyLength would be is not keyLength: the
        // failure is the PRF's AlgorithmIdentifier being absent, not an
        // INTEGER being malformed.
        let error = pbkdf2_from_parameters(&build(None, true), b"pw", 16).unwrap_err();
        assert!(!error.contains("universal 2,"), "{}", error);
        assert!(error.contains("found context 2"), "{}", error);
    }

    /// An iteration count or an RC2 key length that would stall the
    /// reader is refused before any work is done.
    ///
    /// What was wrong: every scheme's iteration count was a bare `u32`
    /// handed to the KDF, and `rc2_version_to_bits` returned any value
    /// of 256 or more as the effective key length, which sizes the
    /// derived key - so a crafted file could ask for four billion
    /// iterations or a half-gigabyte RC2 key. Files are user-chosen,
    /// so this is a bound rather than a defence; the existing tests
    /// read files OpenSSL and the JDK wrote, whose counts are small.
    #[test]
    fn test_iteration_counts_and_rc2_key_lengths_are_bounded() {
        use crate::asn1::Writer;
        let pbkdf2_params = |iterations: u32| {
            let mut writer = Writer::new();
            writer.write_sequence(|w| {
                w.write_octet_string(b"salt");
                w.write_u32(iterations);
            });
            writer.finish()
        };
        let error = pbkdf2_from_parameters(&pbkdf2_params(MAX_ITERATIONS + 1),
                                           b"pw", 16).unwrap_err();
        assert!(error.contains("iterations"), "{}", error);
        // The bound itself is run (with a tiny count below it here, so
        // that the test stays fast): the refusal is for the count, not
        // for the shape of the parameters.
        pbkdf2_from_parameters(&pbkdf2_params(2), b"pw", 16).unwrap();

        assert_eq!(rc2_version_to_bits(58).unwrap(), 128);
        assert_eq!(rc2_version_to_bits(1024).unwrap(), 1024);
        let error = rc2_version_to_bits(1025).unwrap_err();
        assert!(error.contains("at most 1024"), "{}", error);
    }

    /// The JKS protector round-trips at every length either side of its
    /// 20-byte blocks, and refuses the wrong password by its check.
    /// keytool's own files are read by `examples/products/keystore`'s
    /// tests and by `scripts/check_keystore.py`.
    #[test]
    fn test_the_jks_protector_round_trips() {
        let salt: Vec<u8> = (100..120).collect();
        for length in [1, 19, 20, 21, 40, 1217] {
            let plain: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let sealed = jks_protect(&plain, "pässword".as_bytes(), &salt).unwrap();
            assert_eq!(sealed.len(), 20 + length + 20);
            assert_eq!(&sealed[..20], &salt[..]);
            assert_eq!(jks_unprotect(&sealed, "pässword".as_bytes()).unwrap(), plain);
            assert!(jks_unprotect(&sealed, b"password").is_err());
        }
        assert!(jks_protect(b"x", b"pw", &salt[..19]).is_err());
    }

    /// The password is hashed as UTF-16 big endian: "pw" is the bytes
    /// 00 70 00 77, and the first keystream block is SHA-1 of those and
    /// the salt.
    #[test]
    fn test_the_jks_password_is_utf16_big_endian() {
        let salt = [7u8; 20];
        let sealed = jks_protect(&[0u8; 20], b"pw", &salt).unwrap();
        assert_eq!(sealed[20..40], sha1_of(&[&[0, 0x70, 0, 0x77], &salt])[..]);
    }

    #[test]
    fn test_the_jdk_pbe_round_trips_and_wants_ascii() {
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        for length in [0usize, 1, 7, 8, 9, 100] {
            let plain: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let sealed = jdk_pbe_md5_3des_encrypt(b"pw", &salt, 10, &plain).unwrap();
            assert_eq!(sealed.len(), (length / 8 + 1) * 8);
            assert_eq!(jdk_pbe_md5_3des_decrypt(b"pw", &salt, 10, &sealed).unwrap(), plain);
        }
        assert!(jdk_pbe_md5_3des_encrypt("pä".as_bytes(), &salt, 1, b"x").is_err());
    }
}
