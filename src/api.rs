/*
A dynamic, owning facade over the library.

Everything here is chosen so a foreign runtime can hold it: concrete enums
rather than trait objects, owned state rather than borrows, names looked up
from strings, and errors as `String`. The Python bindings in `python.rs` are
a thin translation layer over this module and contain no cryptographic logic
of their own, which is what keeps them small enough to review.

It is perfectly usable from Rust too, when the algorithm is only known at run
time. Code that knows its algorithm statically should keep using the concrete
types and the borrowing mode wrappers, which avoid the dispatch entirely.
*/

use crate::block_ciphers::aes::AesCrypto;
use crate::block_ciphers::blowfish::Blowfish;
use crate::block_ciphers::des::{Des, TripleDes};
use crate::block_ciphers::gost::GostCrypto;
use crate::block_ciphers::rc2::RC2;
use crate::block_ciphers::{BlockCipher, CbcState, CfbState, CtrState, CtsState, CtsVariant,
                           GcmState, OfbState, PcbcState};
use crate::hash_functions::{md5::MD5, sha1::SHA1, sha2, HashFunction};
use crate::stream_ciphers::chacha20poly1305::ChaCha20Poly1305;
use crate::stream_ciphers::{chacha::Chacha, rc4::RC4, StreamCipher};

// ------------------------------------------------------------- catalogue ---

pub const BLOCK_CIPHERS: &[&str] =
    &["aes", "aria", "blowfish", "blowfish-le", "camellia", "cast5", "des", "3des", "gost",
      "idea", "kuznyechik", "magma", "rc2", "rc5", "seed", "serpent",
      "sm4", "tea", "twofish", "xtea"];
pub const STREAM_CIPHERS: &[&str] =
    &["chacha20", "chacha12", "chacha8", "xchacha20", "rc4", "salsa20", "salsa12", "salsa8",
      "xsalsa20", "zipcrypto"];
pub const MODES: &[&str] = &["ecb", "cbc", "pcbc", "cfb", "ofb", "ctr", "ctr-le",
                              "cbc-cs1", "cbc-cs2", "cbc-cs3"];
/// Authenticated modes, which are not in `MODES` because they do not
/// share its interface: they take a nonce and additional data, and
/// decryption can fail.
pub const AEADS: &[&str] = &["aes-gcm", "aes-ccm", "aes-ccm-8",
                             "chacha20-poly1305", "xchacha20-poly1305",
                             // EAX over any block cipher here. Named per
                             // cipher rather than as one "eax" taking a
                             // cipher argument, because the catalogue is
                             // what a caller picks from and "eax" alone
                             // does not say what it will be built on.
                             "aes-eax", "twofish-eax", "serpent-eax",
                             "camellia-eax", "sm4-eax", "des-eax",
                             "3des-eax", "blowfish-eax",
                             // TEA and XTEA are 64 bit blocks like DES,
                             // so CMAC uses Rb = 0x1b for them and EAX
                             // works unchanged. The tag is still 16
                             // bytes - EAX's tag length is the CMAC's,
                             // which is the cipher's block, so **these
                             // two produce 8 byte tags**. See
                             // `aead_tag_len`.
                             "tea-eax", "xtea-eax", "rc5-eax", "aria-eax",
                             // MGM (RFC 9058), named the same way. The
                             // first two are the ones the standard is
                             // written for and the ones RFC 9367's TLS
                             // 1.3 suites use; the rest come free,
                             // because MGM is a mode and every cipher
                             // here has a 64 or 128 bit block.
                             "kuznyechik-mgm", "magma-mgm", "aes-mgm",
                             "twofish-mgm", "serpent-mgm", "camellia-mgm",
                             "sm4-mgm", "aria-mgm", "des-mgm", "3des-mgm",
                             "blowfish-mgm", "tea-mgm", "xtea-mgm",
                             "rc5-mgm",
                             // OCB (RFC 7253), which is defined for 128
                             // bit blocks only. OpenPGP's AEAD packets
                             // default to it.
                             "aes-ocb", "camellia-ocb", "twofish-ocb",
                             "serpent-ocb", "aria-ocb", "sm4-ocb",
                             "seed-ocb", "kuznyechik-ocb",
                             // AES-CBC and HMAC-SHA-2 as one AEAD (RFC
                             // 7518 5.2): JWE's A128CBC-HS256 and its two
                             // siblings. The nonce is the 16-byte IV.
                             "aes-128-cbc-hmac-sha256", "aes-192-cbc-hmac-sha384",
                             "aes-256-cbc-hmac-sha512"];
pub const HASHES: &[&str] = &[
    // MD2 and MD4 are here for what still uses them rather than for
    // what they protect: `md2WithRSAEncryption` on old root
    // certificates, and MD4 inside the NT hash, CHAP and MS-CHAPv2.
    "md2", "md4",
    "md5", "sha0", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha512_224", "sha512_256", "streebog256", "streebog512",
    // GOST R 34.11-94, Streebog's predecessor and what the 0x0081 TLS
    // suite hashes with. The name without a suffix is the CryptoPro
    // parameter set, which is the one every certificate carries; the
    // standard's own test parameter set is a separate name because it
    // is a different hash of the same message.
    "gost94", "gost94_test",
    "blake2b", "blake2s", "ripemd128", "ripemd160", "ripemd256", "ripemd320",
    "sm3", "whirlpool", "whirlpool_0", "whirlpool_t", "has160",
    "md6_128", "md6_224", "md6_256", "md6_384", "md6_512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "shake_128", "shake_256",
    "keccak_224", "keccak_256", "keccak_384", "keccak_512",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Ecb, Cbc, Pcbc, Cfb, Ofb, Ctr,
    /// CTR with the whole block as a little-endian counter (WinZip AES).
    CtrLe,
    /// CBC with ciphertext stealing, NIST's three variants.
    CbcCs1, CbcCs2, CbcCs3,
}

impl Mode {
    pub fn from_name(name: &str) -> Result<Mode, String> {
        match name.to_ascii_lowercase().as_str() {
            "ecb" => Ok(Mode::Ecb),
            "cbc" => Ok(Mode::Cbc),
            "pcbc" => Ok(Mode::Pcbc),
            "cfb" => Ok(Mode::Cfb),
            "ofb" => Ok(Mode::Ofb),
            "ctr" => Ok(Mode::Ctr),
            "ctr-le" => Ok(Mode::CtrLe),
            "cbc-cs1" => Ok(Mode::CbcCs1),
            "cbc-cs2" => Ok(Mode::CbcCs2),
            "cbc-cs3" => Ok(Mode::CbcCs3),
            other => Err(format!("Unknown mode {:?}. Known modes: {}.", other, MODES.join(", "))),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Mode::Ecb => "ecb", Mode::Cbc => "cbc", Mode::Pcbc => "pcbc",
            Mode::Cfb => "cfb", Mode::Ofb => "ofb", Mode::Ctr => "ctr",
            Mode::CtrLe => "ctr-le", Mode::CbcCs1 => "cbc-cs1", Mode::CbcCs2 => "cbc-cs2",
            Mode::CbcCs3 => "cbc-cs3",
        }
    }
    /// The ciphertext stealing variant, for the three modes that are one.
    pub fn cts_variant(self) -> Option<CtsVariant> {
        match self {
            Mode::CbcCs1 => Some(CtsVariant::Cs1),
            Mode::CbcCs2 => Some(CtsVariant::Cs2),
            Mode::CbcCs3 => Some(CtsVariant::Cs3),
            _ => None,
        }
    }
    /// ECB takes no IV; every other mode requires one.
    pub fn needs_iv(self) -> bool { self != Mode::Ecb }
    /// Whether the mode works byte at a time (so it can transform in place
    /// and accept any input length).
    pub fn is_stream_like(self) -> bool {
        matches!(self, Mode::Cfb | Mode::Ofb | Mode::Ctr | Mode::CtrLe)
    }
}

// ---------------------------------------------------------- block ciphers ---

/// Every block cipher the library knows, as one concrete type.
///
/// ## Why the round keys are not boxed
///
/// `clippy::large_enum_variant` wants the large variants behind a `Box`,
/// and the answer is no. The largest are a few hundred bytes of round
/// keys - `Serpent` 528 (33 four-word subkeys), `Kuznyechik` 480,
/// `TripleDes` 384 - against 32 for `Magma`, so the enum is 544 bytes.
///
/// One of these exists **per stream**, never per block and never in an
/// array: `CipherStream`, `Cmac`, `CtrAcpkm` and the record layer each
/// hold exactly one, and the record layer holds two per connection. So a
/// few hundred bytes are paid twice per TLS connection, and against them
/// a box costs an allocation on every construction and a pointer chase
/// on every call to `block_encrypt` - which is once per eight or sixteen
/// bytes for the very cipher being boxed.
///
/// The 4 KB tables *are* boxed, for the same reasoning read the other
/// way: GOST's substitution table made `Protection` 8592 bytes, and no
/// AES connection should carry a GOST table. Blowfish's S-boxes are boxed
/// for the same reason, and Twofish's key-dependent tables and AES's
/// schedule are built boxed. Hundreds of bytes are not 4 KB, and the line
/// is drawn between them deliberately rather than by following the lint.
#[allow(clippy::large_enum_variant)]
pub enum AnyBlockCipher {
    Aes(AesCrypto),
    Blowfish(Blowfish),
    /// Blowfish with its block read as little-endian words: TrueCrypt's.
    BlowfishLe(crate::block_ciphers::blowfish::BlowfishLe),
    Gost(GostCrypto),
    Des(Des),
    TripleDes(TripleDes),
    Rc2(RC2),
    /// GOST R 34.12-2015. Two ciphers, one standard: a 128 bit one and a
    /// 64 bit one. Magma is GOST 28147-89 with a fixed S-box read big
    /// endian, which is why both are here and neither replaces `Gost`.
    Kuznyechik(crate::block_ciphers::kuznyechik::Kuznyechik),
    Magma(crate::block_ciphers::magma::Magma),
    Idea(crate::block_ciphers::idea::Idea),
    Sm4(crate::block_ciphers::sm4::Sm4),
    Seed(crate::block_ciphers::seed::Seed),
    /// Twofish and Serpent, two AES finalists. Neither is in OpenSSL,
    /// so both are checked against Botan's vendored vector files.
    Twofish(crate::block_ciphers::twofish::Twofish),
    Serpent(crate::block_ciphers::serpent::Serpent),
    Camellia(crate::block_ciphers::camellia::Camellia),
    Cast5(crate::block_ciphers::cast5::Cast5),
    /// TEA and XTEA. Two ciphers rather than one with a fix: TEA has
    /// equivalent keys that make its effective length 126 bits, and
    /// XTEA changes the key schedule to remove them.
    Tea(crate::block_ciphers::tea::Tea),
    Xtea(crate::block_ciphers::tea::Xtea),
    /// RC5-32/r/b: a 64 bit block, a round count and a key of 1..=255
    /// bytes. Only the 32 bit word size is implemented; see the module.
    Rc5(crate::block_ciphers::rc5::Rc5),
    /// ARIA, RFC 5794 - the Korean national block cipher, and the one
    /// RFC 6209's TLS suites use. AES's block and key sizes, AES's
    /// S-box as one of its four, and neither AES's diffusion nor AES's
    /// key schedule.
    Aria(crate::block_ciphers::aria::Aria),
}

impl AnyBlockCipher {
    /// `param` is the one cipher-specific setting this facade carries:
    /// the S-box parameter set for GOST, and the **effective key length
    /// in bits** for RC2, where it is not a length check but part of the
    /// key schedule. TLS's `RC2_CBC_40` is `("rc2", <16 bytes>, "40")`,
    /// which is a different cipher from the same 16 bytes unweakened.
    /// Ignored by everything else.
    pub fn new(name: &str, key: &[u8], param: Option<&str>) -> Result<Self, String> {
        match name.to_ascii_lowercase().as_str() {
            "aes" => Ok(AnyBlockCipher::Aes(AesCrypto::new(key.to_vec())?)),
            "aria" => Ok(AnyBlockCipher::Aria(
                crate::block_ciphers::aria::Aria::new(key)?)),
            "blowfish" => {
                // Blowfish::new does not validate, and an empty key divides by
                // zero in the key schedule.
                if key.is_empty() || key.len() > 56 {
                    return Err(format!("Wrong key length {}. Blowfish takes 1..=56 bytes.", key.len()));
                }
                Ok(AnyBlockCipher::Blowfish(Blowfish::new(key.to_vec())))
            }
            // "blowfish_le" is cryptsetup's spelling.
            "blowfish-le" | "blowfish_le" => {
                if key.is_empty() || key.len() > 56 {
                    return Err(format!("Wrong key length {}. Blowfish takes 1..=56 bytes.",
                                       key.len()));
                }
                Ok(AnyBlockCipher::BlowfishLe(
                    crate::block_ciphers::blowfish::BlowfishLe::new(key.to_vec())))
            }
            // **`param` names the S-box, and the S-box is the cipher.**
            // The string here used to be "Default", which matched no
            // parameter set and was silently turned into CryptoPro-A
            // by a fallback inside `GostCrypto::new`. That fallback is
            // gone - an unknown name is an error now - so the default
            // is named, once, where it can be read.
            "gost" => Ok(AnyBlockCipher::Gost(
                GostCrypto::new(key.to_vec(),
                                param.unwrap_or(GostCrypto::DEFAULT_PARAM_SET)
                                     .to_string())?)),
            "idea" => Ok(AnyBlockCipher::Idea(
                crate::block_ciphers::idea::Idea::new(key.to_vec())?)),
            "sm4" => Ok(AnyBlockCipher::Sm4(
                crate::block_ciphers::sm4::Sm4::new(key.to_vec())?)),
            "seed" => Ok(AnyBlockCipher::Seed(
                crate::block_ciphers::seed::Seed::new(key.to_vec())?)),
            "twofish" => Ok(AnyBlockCipher::Twofish(
                crate::block_ciphers::twofish::Twofish::new(key.to_vec())?)),
            "serpent" => Ok(AnyBlockCipher::Serpent(
                crate::block_ciphers::serpent::Serpent::new(key.to_vec())?)),
            "camellia" => Ok(AnyBlockCipher::Camellia(
                crate::block_ciphers::camellia::Camellia::new(key.to_vec())?)),
            "cast5" | "cast128" => Ok(AnyBlockCipher::Cast5(
                crate::block_ciphers::cast5::Cast5::new(key)?)),
            // TEA and XTEA take their round count as the parameter,
            // the way RC2 takes its effective key length - published
            // vectors sweep it from 1 to 64 and firmware in the wild
            // ships reduced-round builds. Absent means the published
            // 32, which is what a caller means by "TEA".
            // RC5's parameter is its round count, like TEA's. Absent
            // means RFC 2040's nominal twelve, which is what "RC5"
            // means without qualification.
            "rc5" => {
                let rounds = match param {
                    None => crate::block_ciphers::rc5::DEFAULT_ROUNDS,
                    Some(text) => text.parse::<usize>().map_err(|_| format!(
                        "RC5's parameter is its round count, as a number; \
                         {:?} is not one.", text))?,
                };
                Ok(AnyBlockCipher::Rc5(
                    crate::block_ciphers::rc5::Rc5::with_rounds(key, rounds)?))
            }
            "tea" | "xtea" => {
                let rounds = match param {
                    None => crate::block_ciphers::tea::DEFAULT_ROUNDS,
                    Some(text) => text.parse::<usize>().map_err(|_| format!(
                        "TEA's parameter is its round count, as a number; \
                         {:?} is not one.", text))?,
                };
                if name.eq_ignore_ascii_case("tea") {
                    Ok(AnyBlockCipher::Tea(
                        crate::block_ciphers::tea::Tea::with_rounds(key, rounds)?))
                } else {
                    Ok(AnyBlockCipher::Xtea(
                        crate::block_ciphers::tea::Xtea::with_rounds(key, rounds)?))
                }
            }
            "rc2" => {
                let bits = match param {
                    None => key.len() * 8,
                    Some(text) => text.parse::<usize>().map_err(|_| format!(
                        "RC2's parameter is its effective key length in bits, \
                         as a number; {:?} is not one.", text))?,
                };
                Ok(AnyBlockCipher::Rc2(RC2::with_effective_bits(key, bits)?))
            }
            // GOST R 34.12-2015's two. "grasshopper" is what the
            // gost-engine calls Kuznyechik and what a caller coming from
            // OpenSSL will have typed.
            "kuznyechik" | "kuznechik" | "grasshopper" => Ok(AnyBlockCipher::Kuznyechik(
                crate::block_ciphers::kuznyechik::Kuznyechik::new(key)?)),
            "magma" => Ok(AnyBlockCipher::Magma(
                crate::block_ciphers::magma::Magma::new(key)?)),
            "des" => Ok(AnyBlockCipher::Des(Des::new(key.to_vec())?)),
            // "3des" is what OpenSSL and everyone else calls it; "des-ede3"
            // is the formal name and both reach the same place.
            "3des" | "des3" | "des-ede" | "des-ede3" | "tripledes" =>
                Ok(AnyBlockCipher::TripleDes(TripleDes::new(key.to_vec())?)),
            other => Err(format!("Unknown block cipher {:?}. Known: {}.",
                                 other, BLOCK_CIPHERS.join(", "))),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AnyBlockCipher::Aes(_) => "aes",
            AnyBlockCipher::Blowfish(_) => "blowfish",
            AnyBlockCipher::BlowfishLe(_) => "blowfish-le",
            AnyBlockCipher::Gost(_) => "gost",
            AnyBlockCipher::Des(_) => "des",
            AnyBlockCipher::TripleDes(_) => "3des",
            AnyBlockCipher::Rc2(_) => "rc2",
            AnyBlockCipher::Kuznyechik(_) => "kuznyechik",
            AnyBlockCipher::Magma(_) => "magma",
            AnyBlockCipher::Idea(_) => "idea",
            AnyBlockCipher::Sm4(_) => "sm4",
            AnyBlockCipher::Seed(_) => "seed",
            AnyBlockCipher::Twofish(_) => "twofish",
            AnyBlockCipher::Serpent(_) => "serpent",
            AnyBlockCipher::Camellia(_) => "camellia",
            AnyBlockCipher::Cast5(_) => "cast5",
            AnyBlockCipher::Tea(_) => "tea",
            AnyBlockCipher::Xtea(_) => "xtea",
            AnyBlockCipher::Rc5(_) => "rc5",
            AnyBlockCipher::Aria(_) => "aria",
        }
    }
}

macro_rules! dispatch {
    ($self:ident, $inner:ident => $body:expr) => {
        match $self {
            AnyBlockCipher::Aes($inner) => $body,
            AnyBlockCipher::Blowfish($inner) => $body,
            AnyBlockCipher::BlowfishLe($inner) => $body,
            AnyBlockCipher::Gost($inner) => $body,
            AnyBlockCipher::Des($inner) => $body,
            AnyBlockCipher::TripleDes($inner) => $body,
            AnyBlockCipher::Rc2($inner) => $body,
            AnyBlockCipher::Kuznyechik($inner) => $body,
            AnyBlockCipher::Magma($inner) => $body,
            AnyBlockCipher::Idea($inner) => $body,
            AnyBlockCipher::Sm4($inner) => $body,
            AnyBlockCipher::Seed($inner) => $body,
            AnyBlockCipher::Twofish($inner) => $body,
            AnyBlockCipher::Serpent($inner) => $body,
            AnyBlockCipher::Camellia($inner) => $body,
            AnyBlockCipher::Cast5($inner) => $body,
            AnyBlockCipher::Tea($inner) => $body,
            AnyBlockCipher::Xtea($inner) => $body,
            AnyBlockCipher::Rc5($inner) => $body,
            AnyBlockCipher::Aria($inner) => $body,
        }
    };
}

impl BlockCipher for AnyBlockCipher {
    fn blocksize(&self) -> usize {
        dispatch!(self, c => c.blocksize())
    }
    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        dispatch!(self, c => c.block_encrypt(input, result))
    }
    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        dispatch!(self, c => c.block_decrypt(input, result))
    }
    // Forwarded so AES's multi-block path is reached through this wrapper.
    fn encrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
        dispatch!(self, c => c.encrypt_blocks(blocks))
    }
    fn decrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
        dispatch!(self, c => c.decrypt_blocks(blocks))
    }
    // And the one-block path, which CBC calls per block.
    fn encrypt_block_in_place(&mut self, block: &mut [u8], scratch: &mut Vec<u8>)
                              -> Result<(), String> {
        dispatch!(self, c => c.encrypt_block_in_place(block, scratch))
    }
    fn decrypt_block_in_place(&mut self, block: &mut [u8], scratch: &mut Vec<u8>)
                              -> Result<(), String> {
        dispatch!(self, c => c.decrypt_block_in_place(block, scratch))
    }
    // The counter hooks must be forwarded too, or GOST would silently fall
    // back to the generic counter through this wrapper.
    fn ctr_init(&mut self, iv: &[u8], counter: &mut Vec<u8>) -> Result<(), String> {
        dispatch!(self, c => c.ctr_init(iv, counter))
    }
    fn ctr_next(&self, counter: &mut [u8]) {
        dispatch!(self, c => c.ctr_next(counter))
    }
    fn ctr_fill(&self, counter: &mut [u8], out: &mut [u8]) {
        dispatch!(self, c => c.ctr_fill(counter, out))
    }
    fn ctr_xor(&mut self, counter: &mut [u8], data: &mut [u8], counter32: bool)
               -> Result<bool, String> {
        dispatch!(self, c => c.ctr_xor(counter, data, counter32))
    }
    fn xts_blocks(&mut self, tweak: &mut [u8; 16], data: &mut [u8], encrypt: bool)
                  -> Result<bool, String> {
        dispatch!(self, c => c.xts_blocks(tweak, data, encrypt))
    }
}

// ------------------------------------------------------------- the stream ---

enum Driver {
    /// ECB has no chaining state, only a partial input block to carry.
    Ecb { decrypting: bool, partial: Vec<u8> },
    Cbc(CbcState),
    Pcbc(PcbcState),
    Cfb(CfbState),
    Ofb(OfbState),
    Ctr(CtrState),
    Cts(CtsState),
}

// -------------------------------------------------------------- the AEAD ---

/// An authenticated encryption in progress.
///
/// Separate from `CipherStream` rather than a sixth `Mode`, because the
/// shape of the operation is different and pretending otherwise would hide
/// the differences that matter: it takes a nonce and additional data,
/// encryption produces a tag, and decryption can fail. A mode that can fail
/// cannot share an interface with four that cannot without one of them
/// having to lie.
///
/// **The nonce must never repeat under one key.** Two messages that share
/// one give away their XOR and the authentication key, after which anything
/// can be forged under that key. Nothing here can check it, because only
/// the caller knows what was used before.
pub struct AeadStream {
    inner: AeadInner,
    decrypting: bool,
}

/// The two constructions have nothing in common underneath - one drives a
/// block cipher in counter mode with GHASH, the other a stream cipher with
/// Poly1305 - so this is an enum rather than a trait object. Concrete
/// types are what let the Python bindings own one.
enum AeadInner {
    Gcm { cipher: AnyBlockCipher, state: GcmState },
    ChaChaPoly(ChaCha20Poly1305),
    /// CCM cannot stream: its MAC starts with the message's length, so
    /// nothing can be processed until all of it has arrived. The
    /// buffering is here, at the facade, rather than inside the mode -
    /// where it would be an interface promising constant memory and not
    /// delivering it. See `src/block_ciphers/ccm.rs`.
    Ccm {
        cipher: AnyBlockCipher,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        buffered: Vec<u8>,
        tag_len: usize,
    },
    /// EAX. **Buffers, though it does not have to.**
    ///
    /// The mode itself is online in both passes - that is its whole
    /// advantage over CCM - but `Eax` here is written as a one-shot
    /// because the streaming form needs a `Cmac` and a `CtrState` kept
    /// side by side with the ciphertext fed to the first as it leaves
    /// the second, and `buffers_everything()` already exists to say so
    /// honestly. Said out loud rather than left as an implied
    /// limitation of the mode.
    Eax {
        eax: crate::block_ciphers::eax::Eax,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        buffered: Vec<u8>,
    },
    /// MGM (RFC 9058). **Buffers, and unlike EAX it has to.**
    ///
    /// The mode is online in both passes by construction - that is one
    /// of its stated design goals - but the tag's last multiplicand is
    /// `len(A) || len(C)`, so nothing can be finished until the length
    /// is known. That only affects the tag, not the ciphertext, so a
    /// streaming form is possible; it is not written yet, and
    /// `buffers_everything()` says so rather than the interface
    /// implying constant memory it does not deliver.
    Mgm {
        mgm: crate::block_ciphers::mgm::Mgm,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        buffered: Vec<u8>,
    },
    /// OCB (RFC 7253). **Buffers, though it does not have to**, as EAX
    /// does: the mode is online and its tag needs no length, but it is
    /// written as a one-shot here.
    Ocb {
        ocb: crate::block_ciphers::ocb::Ocb,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        buffered: Vec<u8>,
    },
    /// AES-CBC with HMAC-SHA-2 (RFC 7518 5.2). **Buffers**: encryption
    /// could stream, but decryption must not release a byte before the
    /// tag over all of the ciphertext has checked, or the padding check
    /// becomes an oracle.
    CbcHmac {
        aead: crate::block_ciphers::cbc_hmac::CbcHmac,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        buffered: Vec<u8>,
    },
}

impl AeadStream {
    /// `name` is the AEAD, not the block cipher: `"aes-gcm"` or
    /// `"chacha20-poly1305"`.
    pub fn new(name: &str, key: &[u8], nonce: &[u8], aad: &[u8],
               decrypting: bool) -> Result<Self, String> {
        let inner = match name.to_ascii_lowercase().as_str() {
            "aes-gcm" | "gcm" => {
                let mut cipher = AnyBlockCipher::new("aes", key, None)?;
                let state = if decrypting {
                    GcmState::decryptor(&mut cipher, nonce, aad)?
                } else {
                    GcmState::encryptor(&mut cipher, nonce, aad)?
                };
                AeadInner::Gcm { cipher, state }
            }
            "aes-ccm" | "ccm" | "aes-ccm-8" | "ccm-8" => {
                let cipher = AnyBlockCipher::new("aes", key, None)?;
                AeadInner::Ccm {
                    cipher,
                    nonce: nonce.to_vec(),
                    aad: aad.to_vec(),
                    buffered: Vec::new(),
                    tag_len: if name.ends_with("-8") { 8 } else { 16 },
                }
            }
            "chacha20-poly1305" | "chacha20poly1305" => {
                AeadInner::ChaChaPoly(if decrypting {
                    ChaCha20Poly1305::decryptor(key, nonce, aad)?
                } else {
                    ChaCha20Poly1305::encryptor(key, nonce, aad)?
                })
            }
            "xchacha20-poly1305" | "xchacha20poly1305" => {
                AeadInner::ChaChaPoly(if decrypting {
                    ChaCha20Poly1305::x_decryptor(key, nonce, aad)?
                } else {
                    ChaCha20Poly1305::x_encryptor(key, nonce, aad)?
                })
            }
            other if other.ends_with("-eax") => {
                let cipher = &other[..other.len() - 4];
                AeadInner::Eax {
                    eax: crate::block_ciphers::eax::Eax::new(cipher, key)?,
                    nonce: nonce.to_vec(),
                    aad: aad.to_vec(),
                    buffered: Vec::new(),
                }
            }
            other if other.ends_with("-mgm") => {
                let cipher = &other[..other.len() - 4];
                AeadInner::Mgm {
                    mgm: crate::block_ciphers::mgm::Mgm::new(cipher, key)?,
                    nonce: nonce.to_vec(),
                    aad: aad.to_vec(),
                    buffered: Vec::new(),
                }
            }
            other if other.ends_with("-ocb") => {
                let cipher = &other[..other.len() - 4];
                AeadInner::Ocb {
                    ocb: crate::block_ciphers::ocb::Ocb::new(cipher, key)?,
                    nonce: nonce.to_vec(),
                    aad: aad.to_vec(),
                    buffered: Vec::new(),
                }
            }
            "aes-128-cbc-hmac-sha256" | "aes-192-cbc-hmac-sha384" | "aes-256-cbc-hmac-sha512" => {
                use crate::block_ciphers::cbc_hmac::{CbcHmac, Variant};
                let variant = match &name.to_ascii_lowercase()[..7] {
                    "aes-128" => Variant::Aes128HmacSha256,
                    "aes-192" => Variant::Aes192HmacSha384,
                    _ => Variant::Aes256HmacSha512,
                };
                if nonce.len() != 16 {
                    return Err(format!("{name}'s nonce is its 16-byte IV, not {} bytes.",
                                       nonce.len()));
                }
                AeadInner::CbcHmac {
                    aead: CbcHmac::new(variant, key)?,
                    nonce: nonce.to_vec(),
                    aad: aad.to_vec(),
                    buffered: Vec::new(),
                }
            }
            other => return Err(format!(
                "Unknown AEAD {:?}. Known: {}.", other, AEADS.join(", "))),
        };
        Ok(AeadStream { inner, decrypting })
    }

    /// Feed input. For GCM and ChaCha20-Poly1305 this produces output as
    /// it goes; for CCM it produces nothing until `tag` or `verify`,
    /// because the mode cannot start before it knows the length.
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        match &mut self.inner {
            AeadInner::Gcm { cipher, state } => state.update(cipher, input, out),
            AeadInner::ChaChaPoly(state) => state.update(input, out),
            AeadInner::Ccm { buffered, .. } | AeadInner::Eax { buffered, .. }
            | AeadInner::Mgm { buffered, .. } | AeadInner::Ocb { buffered, .. }
            | AeadInner::CbcHmac { buffered, .. } => {
                buffered.extend_from_slice(input);
                Ok(())
            }
        }
    }

    /// The tag this AEAD produces, in bytes.
    ///
    /// **Asked rather than assumed.** The Python one-shot `decrypt`
    /// split `ciphertext || tag` at sixteen bytes from the end, which
    /// was true of everything here until it was not: `aes-ccm-8` has an
    /// eight byte tag, and so does EAX over any 64 bit block cipher.
    /// The failure was not a length error - it was
    /// *"the tag does not match"*, which tells a caller their data was
    /// altered when in fact the library split it in the wrong place.
    pub fn tag_len(&self) -> usize {
        match &self.inner {
            AeadInner::Gcm { .. } | AeadInner::ChaChaPoly(_) => 16,
            AeadInner::Ccm { tag_len, .. } => *tag_len,
            AeadInner::Eax { eax, .. } => eax.tag_len(),
            AeadInner::Mgm { mgm, .. } => mgm.tag_len(),
            AeadInner::Ocb { ocb, .. } => ocb.tag_len(),
            AeadInner::CbcHmac { aead, .. } => aead.tag_len(),
        }
    }

    /// Whether this AEAD holds everything back until the end. True only
    /// for CCM, and asked rather than assumed: a caller that streams a
    /// large message needs to know which of the two shapes it has.
    pub fn buffers_everything(&self) -> bool {
        matches!(self.inner, AeadInner::Ccm { .. } | AeadInner::Eax { .. }
                             | AeadInner::Mgm { .. } | AeadInner::Ocb { .. }
                             | AeadInner::CbcHmac { .. })
    }

    /// Finish a CCM encryption: the ciphertext, which `update` could not
    /// produce, and the tag.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<Vec<u8>, String> {
        match &mut self.inner {
            AeadInner::Ccm { cipher, nonce, aad, buffered, tag_len } => {
                if self.decrypting {
                    return Err("This is a decryption; call open() with the \
                                tag.".to_string());
                }
                let (ciphertext, tag) = crate::block_ciphers::ccm::encrypt(
                    cipher, nonce, aad, buffered, *tag_len)?;
                out.extend_from_slice(&ciphertext);
                Ok(tag)
            }
            AeadInner::Eax { eax, nonce, aad, buffered } => {
                if self.decrypting {
                    return Err("This is a decryption; call open() with the \
                                tag.".to_string());
                }
                let (ciphertext, tag) = eax.encrypt(nonce, aad, buffered)?;
                out.extend_from_slice(&ciphertext);
                Ok(tag)
            }
            AeadInner::Mgm { mgm, nonce, aad, buffered } => {
                if self.decrypting {
                    return Err("This is a decryption; call open() with the \
                                tag.".to_string());
                }
                let (ciphertext, tag) = mgm.encrypt(nonce, aad, buffered)?;
                out.extend_from_slice(&ciphertext);
                Ok(tag)
            }
            AeadInner::Ocb { ocb, nonce, aad, buffered } => {
                if self.decrypting {
                    return Err("This is a decryption; call open() with the \
                                tag.".to_string());
                }
                let (ciphertext, tag) = ocb.encrypt(nonce, aad, buffered)?;
                out.extend_from_slice(&ciphertext);
                Ok(tag)
            }
            AeadInner::CbcHmac { aead, nonce, aad, buffered } => {
                if self.decrypting {
                    return Err("This is a decryption; call open() with the \
                                tag.".to_string());
                }
                let (ciphertext, tag) = aead.encrypt(nonce, aad, buffered)?;
                out.extend_from_slice(&ciphertext);
                Ok(tag)
            }
            _ => self.tag(),
        }
    }

    /// Finish a CCM decryption: verify, then hand back the plaintext.
    /// Nothing comes out unless the tag checks, which is the whole point.
    pub fn open(&mut self, tag: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        match &mut self.inner {
            AeadInner::Ccm { cipher, nonce, aad, buffered, .. } => {
                if !self.decrypting {
                    return Err("This is an encryption; call finish().".to_string());
                }
                let plaintext = crate::block_ciphers::ccm::decrypt(
                    cipher, nonce, aad, buffered, tag)?;
                out.extend_from_slice(&plaintext);
                Ok(())
            }
            AeadInner::Eax { eax, nonce, aad, buffered } => {
                if !self.decrypting {
                    return Err("This is an encryption; call finish().".to_string());
                }
                let plaintext = eax.decrypt(nonce, aad, buffered, tag)?;
                out.extend_from_slice(&plaintext);
                Ok(())
            }
            AeadInner::Mgm { mgm, nonce, aad, buffered } => {
                if !self.decrypting {
                    return Err("This is an encryption; call finish().".to_string());
                }
                let plaintext = mgm.decrypt(nonce, aad, buffered, tag)?;
                out.extend_from_slice(&plaintext);
                Ok(())
            }
            AeadInner::Ocb { ocb, nonce, aad, buffered } => {
                if !self.decrypting {
                    return Err("This is an encryption; call finish().".to_string());
                }
                let plaintext = ocb.decrypt(nonce, aad, buffered, tag)?;
                out.extend_from_slice(&plaintext);
                Ok(())
            }
            AeadInner::CbcHmac { aead, nonce, aad, buffered } => {
                if !self.decrypting {
                    return Err("This is an encryption; call finish().".to_string());
                }
                let plaintext = aead.decrypt(nonce, aad, buffered, tag)?;
                out.extend_from_slice(&plaintext);
                Ok(())
            }
            _ => self.verify(tag),
        }
    }

    /// Finish an encryption and return the tag.
    pub fn tag(&mut self) -> Result<Vec<u8>, String> {
        if self.decrypting {
            return Err("This is a decryption; call verify with the tag.".to_string());
        }
        match &mut self.inner {
            AeadInner::Gcm { cipher, state } => Ok(state.tag(cipher)?.to_vec()),
            AeadInner::ChaChaPoly(state) => Ok(state.tag()?.to_vec()),
            // CCM's ciphertext and tag appear together, so asking for the
            // tag alone would silently drop the ciphertext.
            AeadInner::Ccm { .. } => Err(
                "CCM produces its ciphertext and tag together; call finish() \
                 with a buffer for both.".to_string()),
            AeadInner::Eax { .. } => Err(
                "This EAX is one-shot here; call finish() with a buffer for \
                 the ciphertext.".to_string()),
            AeadInner::Mgm { .. } => Err(
                "MGM's tag covers the ciphertext's length, so it is one-shot \
                 here; call finish() with a buffer for the ciphertext."
                    .to_string()),
            AeadInner::Ocb { .. } => Err(
                "This OCB is one-shot here; call finish() with a buffer for \
                 the ciphertext.".to_string()),
            AeadInner::CbcHmac { .. } => Err(
                "CBC-HMAC is one-shot here; call finish() with a buffer for \
                 the ciphertext.".to_string()),
        }
    }

    /// Finish a decryption. Until this returns `Ok`, nothing `update`
    /// produced is trustworthy.
    pub fn verify(&mut self, tag: &[u8]) -> Result<(), String> {
        if !self.decrypting {
            return Err("This is an encryption; call tag().".to_string());
        }
        match &mut self.inner {
            AeadInner::Gcm { cipher, state } => state.verify(cipher, tag),
            AeadInner::ChaChaPoly(state) => state.verify(tag),
            AeadInner::Ccm { .. } => Err(
                "CCM releases its plaintext only once the tag checks; call \
                 open() with a buffer for it.".to_string()),
            AeadInner::Eax { .. } => Err(
                "EAX releases its plaintext only once the tag checks; call \
                 open() with a buffer for it.".to_string()),
            AeadInner::Mgm { .. } => Err(
                "MGM releases its plaintext only once the tag checks; call \
                 open() with a buffer for it.".to_string()),
            AeadInner::Ocb { .. } => Err(
                "OCB releases its plaintext only once the tag checks; call \
                 open() with a buffer for it.".to_string()),
            AeadInner::CbcHmac { .. } => Err(
                "CBC-HMAC releases its plaintext only once the tag checks; call \
                 open() with a buffer for it.".to_string()),
        }
    }
}

/// The tag length of a named AEAD, for a caller that has to split
/// `ciphertext || tag` before it can open anything.
pub fn aead_tag_len(name: &str, key: &[u8]) -> Result<usize, String> {
    // The nonce and aad are irrelevant to the tag length, but a stream
    // has to be built to ask - so they are placeholders, and a key that
    // the cipher refuses fails here rather than later.
    let nonce = [0u8; 24];
    let lower = name.to_ascii_lowercase();
    let length = if lower.starts_with("xchacha") { 24 }
                 else if lower.contains("-cbc-hmac-") { 16 }
                 else { 12 };
    Ok(AeadStream::new(name, key, &nonce[..length], &[], false)?.tag_len())
}

/// Seal in one call: ciphertext and tag.
pub fn aead_encrypt(name: &str, key: &[u8], nonce: &[u8], aad: &[u8],
                    plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut stream = AeadStream::new(name, key, nonce, aad, false)?;
    let mut out = Vec::with_capacity(plaintext.len());
    stream.update(plaintext, &mut out)?;
    let tag = stream.finish(&mut out)?;
    Ok((out, tag))
}

/// Open in one call. Returns the plaintext, or an error and nothing else -
/// never both. A caller that gets bytes back alongside a failure will
/// eventually use them.
pub fn aead_decrypt(name: &str, key: &[u8], nonce: &[u8], aad: &[u8],
                    ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = AeadStream::new(name, key, nonce, aad, true)?;
    let mut out = Vec::with_capacity(ciphertext.len());
    stream.update(ciphertext, &mut out)?;
    stream.open(tag, &mut out)?;
    Ok(out)
}

/// One encryption or decryption in progress: a cipher plus the state of the
/// mode driving it. Feed it with `update` as many times as you like, then
/// `finish`.
pub struct CipherStream {
    cipher: AnyBlockCipher,
    driver: Driver,
    mode: Mode,
    finished: bool,
}

impl CipherStream {
    pub fn new(mut cipher: AnyBlockCipher, mode: Mode, iv: &[u8],
               decrypting: bool) -> Result<Self, String> {
        if !mode.needs_iv() && !iv.is_empty() {
            return Err(format!("{} mode takes no IV.", mode.name().to_uppercase()));
        }
        if mode.needs_iv() && iv.is_empty() {
            return Err(format!("{} mode requires an IV.", mode.name().to_uppercase()));
        }
        let driver = match mode {
            Mode::Ecb => Driver::Ecb { decrypting, partial: Vec::with_capacity(cipher.blocksize()) },
            Mode::Cbc => Driver::Cbc(CbcState::new(&mut cipher, iv, decrypting)?),
            Mode::Pcbc => Driver::Pcbc(PcbcState::new(&mut cipher, iv, decrypting)?),
            Mode::Cfb => Driver::Cfb(CfbState::new(&mut cipher, iv, decrypting)?),
            Mode::Ofb => Driver::Ofb(OfbState::new(&mut cipher, iv)?),
            Mode::Ctr => Driver::Ctr(CtrState::new(&mut cipher, iv)?),
            Mode::CtrLe => Driver::Ctr(CtrState::new_little_endian(&mut cipher, iv)?),
            Mode::CbcCs1 | Mode::CbcCs2 | Mode::CbcCs3 => Driver::Cts(CtsState::new(
                &mut cipher, iv, mode.cts_variant().expect("a CTS mode"), decrypting)?),
        };
        Ok(CipherStream { cipher, driver, mode, finished: false })
    }

    pub fn block_size(&self) -> usize { self.cipher.blocksize() }
    pub fn mode(&self) -> Mode { self.mode }
    pub fn cipher_name(&self) -> &'static str { self.cipher.name() }

    /// Transform the next piece of input, returning whatever output is ready.
    /// For the block-at-a-time modes this may be shorter than the input.
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if self.finished {
            return Err("This stream has already been finalized.".to_string());
        }
        let mut out = Vec::with_capacity(input.len());
        match &mut self.driver {
            Driver::Ecb { decrypting, partial } => {
                let bs = self.cipher.blocksize();
                let mut rest = input;
                if !partial.is_empty() {
                    let take = core::cmp::min(bs - partial.len(), rest.len());
                    partial.extend_from_slice(&rest[..take]);
                    rest = &rest[take..];
                    if partial.len() < bs {
                        return Ok(out);
                    }
                    if *decrypting {
                        self.cipher.block_decrypt(partial, &mut out);
                    } else {
                        self.cipher.block_encrypt(partial, &mut out);
                    }
                    partial.clear();
                }
                let full = rest.len() / bs;
                let from = out.len();
                out.extend_from_slice(&rest[..full * bs]);
                if *decrypting {
                    self.cipher.decrypt_blocks(&mut out[from..])?;
                } else {
                    self.cipher.encrypt_blocks(&mut out[from..])?;
                }
                partial.extend_from_slice(&rest[full*bs..]);
            }
            Driver::Cbc(s) => s.update(&mut self.cipher, input, &mut out)?,
            Driver::Pcbc(s) => s.update(&mut self.cipher, input, &mut out)?,
            Driver::Cfb(s) => s.update(&mut self.cipher, input, &mut out)?,
            Driver::Ofb(s) => s.update(&mut self.cipher, input, &mut out)?,
            Driver::Ctr(s) => s.update(&mut self.cipher, input, &mut out)?,
            Driver::Cts(s) => s.update(&mut self.cipher, input, &mut out)?,
        }
        Ok(out)
    }

    /// Transform `buf` in place. Only the byte-granular modes can do this;
    /// ECB and CBC need whole blocks and buffer across calls.
    pub fn update_into(&mut self, buf: &mut [u8]) -> Result<(), String> {
        if self.finished {
            return Err("This stream has already been finalized.".to_string());
        }
        match &mut self.driver {
            Driver::Cfb(s) => s.apply(&mut self.cipher, buf),
            Driver::Ofb(s) => s.apply(&mut self.cipher, buf),
            Driver::Ctr(s) => s.apply(&mut self.cipher, buf),
            _ => Err(format!("{} mode cannot transform in place; use update().",
                             self.mode.name().to_uppercase())),
        }
    }

    /// End the stream. Returns any trailing output - the last two blocks
    /// for ciphertext stealing, nothing for the other modes - and errors
    /// if a partial block was left dangling.
    pub fn finish(&mut self) -> Result<Vec<u8>, String> {
        if self.finished {
            return Err("This stream has already been finalized.".to_string());
        }
        self.finished = true;
        match &mut self.driver {
            Driver::Ecb { partial, .. } if !partial.is_empty() =>
                Err("Input length not a multiple of block size, (padding is needed).".to_string()),
            Driver::Cbc(s) => s.finish().map(|_| Vec::new()),
            Driver::Pcbc(s) => s.finish().map(|_| Vec::new()),
            Driver::Cts(s) => {
                let mut out = Vec::new();
                s.finish(&mut self.cipher, &mut out)?;
                Ok(out)
            }
            _ => Ok(Vec::new()),
        }
    }
}

// --------------------------------------------------------- stream ciphers ---

pub enum AnyStreamCipher {
    Chacha(Chacha),
    Rc4(RC4),
    Salsa20(crate::stream_ciphers::salsa20::Salsa20),
    /// PKWARE's traditional ZIP encryption. Its keys absorb the
    /// plaintext, so it has a direction: `encrypt` and `decrypt` work and
    /// `update` refuses.
    ZipCrypto(crate::stream_ciphers::zipcrypto::ZipCrypto),
}

impl AnyStreamCipher {
    pub fn new(name: &str, key: &[u8], nonce: &[u8]) -> Result<Self, String> {
        let lower = name.to_ascii_lowercase();
        let rounds = match lower.as_str() {
            "chacha20" | "chacha" => Some(20usize),
            "chacha12" => Some(12),
            "chacha8" => Some(8),
            _ => None,
        };
        if let Some(r) = rounds {
            return Ok(AnyStreamCipher::Chacha(Chacha::new(key.to_vec(), nonce.to_vec(), r)?));
        }
        if lower == "xchacha20" {
            return Ok(AnyStreamCipher::Chacha(
                crate::stream_ciphers::chacha::xchacha20(key, nonce)?));
        }
        if lower == "xsalsa20" {
            return Ok(AnyStreamCipher::Salsa20(
                crate::stream_ciphers::salsa20::xsalsa20(key, nonce)?));
        }
        // Salsa20's reduced-round variants are real ciphers from the
        // eSTREAM portfolio, not a test knob, so they get names.
        let salsa_rounds = match lower.as_str() {
            "salsa20" | "salsa" => Some(20usize),
            "salsa12" => Some(12),
            "salsa8" => Some(8),
            _ => None,
        };
        if let Some(r) = salsa_rounds {
            return Ok(AnyStreamCipher::Salsa20(
                crate::stream_ciphers::salsa20::Salsa20::with_rounds(
                    key.to_vec(), nonce.to_vec(), r)?));
        }
        match lower.as_str() {
            "rc4" => {
                if !nonce.is_empty() {
                    return Err("RC4 takes no nonce.".to_string());
                }
                Ok(AnyStreamCipher::Rc4(RC4::new(key.to_vec())?))
            }
            // The key is the password, of any length, the empty one
            // included.
            "zipcrypto" => {
                if !nonce.is_empty() {
                    return Err("ZipCrypto takes no nonce.".to_string());
                }
                Ok(AnyStreamCipher::ZipCrypto(
                    crate::stream_ciphers::zipcrypto::ZipCrypto::new(key)))
            }
            other => Err(format!("Unknown stream cipher {:?}. Known: {}.",
                                 other, STREAM_CIPHERS.join(", "))),
        }
    }

    /// Whether encrypting and decrypting are the same operation: true
    /// for a keystream XORed onto the data, false for ZipCrypto.
    pub fn is_keystream(&self) -> bool {
        !matches!(self, AnyStreamCipher::ZipCrypto(_))
    }

    /// XOR the keystream onto `input`, which encrypts and decrypts alike.
    /// Refused for a cipher without a keystream independent of the data,
    /// rather than guessing a direction.
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(input.len());
        match self {
            AnyStreamCipher::Chacha(c) => c.crypt(input, &mut out),
            AnyStreamCipher::Rc4(c) => c.crypt(input, &mut out),
            AnyStreamCipher::Salsa20(c) => c.crypt(input, &mut out),
            AnyStreamCipher::ZipCrypto(_) => {
                return Err("ZipCrypto's keys absorb the plaintext, so encrypting and \
                            decrypting differ: use encrypt or decrypt."
                    .to_string())
            }
        }
        Ok(out)
    }

    pub fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        match self {
            AnyStreamCipher::Chacha(c) => c.crypt(input, &mut out),
            AnyStreamCipher::Rc4(c) => c.crypt(input, &mut out),
            AnyStreamCipher::Salsa20(c) => c.crypt(input, &mut out),
            AnyStreamCipher::ZipCrypto(c) => c.encrypt(input, &mut out),
        }
        out
    }

    pub fn decrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        match self {
            AnyStreamCipher::Chacha(c) => c.crypt(input, &mut out),
            AnyStreamCipher::Rc4(c) => c.crypt(input, &mut out),
            AnyStreamCipher::Salsa20(c) => c.crypt(input, &mut out),
            AnyStreamCipher::ZipCrypto(c) => c.decrypt(input, &mut out),
        }
        out
    }

    /// Transform `buf` in place, continuing the keystream.
    ///
    /// The same operation as `update` with no allocation, which matters in
    /// the record layer where this runs once per record. The underlying
    /// `crypt` appends, so the keystream is taken against the buffer's own
    /// bytes and XORed back over them - which is why the temporary is the
    /// same length and not the whole message.
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        if buf.is_empty() {
            return Ok(());
        }
        let transformed = self.update(buf)?;
        if transformed.len() != buf.len() {
            return Err(format!(
                "Stream cipher produced {} bytes for {} of input.",
                transformed.len(), buf.len()));
        }
        buf.copy_from_slice(&transformed);
        Ok(())
    }
}

// ------------------------------------------------------------- CBC-MAC ---

/// CBC-MAC (ISO/IEC 9797-1 MAC algorithm 1) over any block cipher here.
/// `iv` defaults to zeros. With `zero_pad`, the message is padded with
/// zero bytes to whole blocks first (padding method 1); without it, it
/// must already be whole blocks. Safe only for messages of one fixed
/// length - see `mac::cbc_mac`; CMAC is the fixed construction.
pub fn cbc_mac(cipher_name: &str, key: &[u8], data: &[u8], iv: Option<&[u8]>,
               zero_pad: bool) -> Result<Vec<u8>, String> {
    let mut cipher = AnyBlockCipher::new(cipher_name, key, None)?;
    let zeros = vec![0u8; cipher.blocksize()];
    let iv = iv.unwrap_or(&zeros);
    if zero_pad {
        crate::mac::cbc_mac::cbc_mac_zero_padded(&mut cipher, iv, data)
    } else {
        crate::mac::cbc_mac::cbc_mac(&mut cipher, iv, data)
    }
}

// ------------------------------------------------------ Office XOR obfuscation ---

/// The 16-bit verifier of a password for the binary Office formats' XOR
/// obfuscation, which is also Excel's sheet-protection hash.
pub fn office_xor_verifier(password: &[u8]) -> Result<u16, String> {
    crate::stream_ciphers::office_xor::password_verifier(password)
}

/// Office XOR obfuscation (method 1): `index` is the array index the
/// first byte meets.
pub fn office_xor_decrypt(password: &[u8], data: &[u8], index: usize)
                          -> Result<Vec<u8>, String> {
    let mut out = data.to_vec();
    crate::stream_ciphers::office_xor::OfficeXor::new(password)?.decrypt(&mut out, index);
    Ok(out)
}

pub fn office_xor_encrypt(password: &[u8], data: &[u8], index: usize)
                          -> Result<Vec<u8>, String> {
    let mut out = data.to_vec();
    crate::stream_ciphers::office_xor::OfficeXor::new(password)?.encrypt(&mut out, index);
    Ok(out)
}

// --------------------------------------------------------- IEEE 802.11 ---

/// Michael, TKIP's message integrity code (`mac::michael`). The key is
/// 8 bytes.
pub fn michael(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let key: [u8; 8] = key.try_into()
        .map_err(|_| format!("Michael's key is 8 bytes, not {}.", key.len()))?;
    Ok(crate::mac::michael::michael(&key, data).to_vec())
}

/// WEP's RC4 encapsulation of `plaintext` under the IV and shared key
/// (`stream_ciphers::wep`).
pub fn wep_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let iv: [u8; 3] = iv.try_into()
        .map_err(|_| format!("A WEP IV is 3 bytes, not {}.", iv.len()))?;
    Ok(crate::stream_ciphers::wep::encrypt(key, &iv, plaintext))
}

/// The inverse of `wep_encrypt`, refusing a wrong key or a damaged frame
/// by the ICV.
pub fn wep_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let iv: [u8; 3] = iv.try_into()
        .map_err(|_| format!("A WEP IV is 3 bytes, not {}.", iv.len()))?;
    crate::stream_ciphers::wep::decrypt(key, &iv, ciphertext)
}

/// TKIP's per-packet RC4 key from the temporal key, the transmitter
/// address and the 48-bit sequence counter (`stream_ciphers::tkip`).
pub fn tkip_rc4_key(tk: &[u8], ta: &[u8], tsc: u64) -> Result<Vec<u8>, String> {
    let tk: [u8; 16] = tk.try_into()
        .map_err(|_| format!("A TKIP temporal key is 16 bytes, not {}.", tk.len()))?;
    let ta: [u8; 6] = ta.try_into()
        .map_err(|_| format!("A transmitter address is 6 bytes, not {}.", ta.len()))?;
    Ok(crate::stream_ciphers::tkip::rc4_key(&tk, &ta, tsc).to_vec())
}

/// The WPA/WPA2 pre-shared key from a passphrase and the SSID
/// (`kdf::ieee80211`).
pub fn wpa_psk(passphrase: &[u8], ssid: &[u8]) -> Result<Vec<u8>, String> {
    Ok(crate::kdf::ieee80211::psk(passphrase, ssid)?.to_vec())
}

/// The pairwise transient key: `bits` is 512 for TKIP and 384 for CCMP,
/// over a SHA-1 (`akm` "sha1", WPA and WPA2) or SHA-256 (`akm`
/// "sha256", 802.11w and WPA3) key hierarchy.
pub fn wpa_ptk(akm: &str, pmk: &[u8], aa: &[u8], spa: &[u8], anonce: &[u8], snonce: &[u8],
               bits: usize) -> Result<Vec<u8>, String> {
    let mac = |m: &[u8], what: &str| -> Result<[u8; 6], String> {
        m.try_into().map_err(|_| format!("A {what} is 6 bytes, not {}.", m.len()))
    };
    let nonce = |n: &[u8], what: &str| -> Result<[u8; 32], String> {
        n.try_into().map_err(|_| format!("A {what} is 32 bytes, not {}.", n.len()))
    };
    let (aa, spa) = (mac(aa, "BSSID")?, mac(spa, "station address")?);
    let (anonce, snonce) = (nonce(anonce, "nonce")?, nonce(snonce, "nonce")?);
    Ok(match akm {
        "sha1" => crate::kdf::ieee80211::ptk_sha1(pmk, &aa, &spa, &anonce, &snonce, bits),
        "sha256" => crate::kdf::ieee80211::ptk_sha256(pmk, &aa, &spa, &anonce, &snonce, bits),
        other => return Err(format!("A WPA AKM is \"sha1\" or \"sha256\", not {other:?}.")),
    })
}

/// The PMKID, which names a cached pairwise master key.
pub fn wpa_pmkid(pmk: &[u8], aa: &[u8], spa: &[u8]) -> Result<Vec<u8>, String> {
    let aa: [u8; 6] = aa.try_into().map_err(|_| "A BSSID is 6 bytes.".to_string())?;
    let spa: [u8; 6] = spa.try_into()
        .map_err(|_| "A station address is 6 bytes.".to_string())?;
    Ok(crate::kdf::ieee80211::pmkid(pmk, &aa, &spa).to_vec())
}

// ----------------------------------------------------------------- hashes ---

/// Every hash the library knows, as one concrete `Clone`able type, so that
/// `copy()` (which callers coming from hashlib expect) is just a clone.
#[derive(Clone)]
pub enum AnyHash {
    Md5(MD5),
    Sha1(SHA1),
    Sha224(sha2::SHA224),
    Sha256(sha2::SHA256),
    Sha384(sha2::SHA384),
    Sha512(sha2::SHA512),
    /// GOST R 34.11-2012, in both its sizes. One variant because the two
    /// differ only in their IV and in which half of the state comes out,
    /// and `Streebog` already carries that.
    Streebog(crate::hash_functions::streebog::Streebog),
    /// BLAKE2b and BLAKE2s. One variant each rather than one per output
    /// length, because the length lives inside the instance - it is a
    /// field of the parameter block, not a truncation.
    Blake2b(crate::hash_functions::blake2::Blake2b),
    Blake2s(crate::hash_functions::blake2::Blake2s),
    Ripemd160(crate::hash_functions::ripemd160::Ripemd160),
    /// RIPEMD-128, -256 and -320: RIPEMD-160's relatives, one type with
    /// the variant inside.
    Ripemd(crate::hash_functions::ripemd::Ripemd),
    /// HAS-160, the Korean standard hash KCDSA signs with.
    Has160(crate::hash_functions::has160::Has160),
    /// MD6, any whole-byte digest size up to 512 bits.
    Md6(crate::hash_functions::md6::Md6),
    /// SM3, GB/T 32905-2016. The hash SM2 is defined against and the
    /// one RFC 8998's TLS 1.3 suites use.
    Sm3(crate::hash_functions::sm3::Sm3),
    /// MD2, RFC 1319. Byte-oriented throughout and unlike everything
    /// else here - a 16-byte block, a checksum appended to the message,
    /// and no length field at all.
    Md2(crate::hash_functions::md2::Md2),
    /// GOST R 34.11-94, the hash Streebog replaced. Its S-box is a
    /// parameter, so the instance carries which one it was built with.
    Gost94(crate::hash_functions::gost94::Gost94),
    /// MD4, RFC 1320. The root of the MD5/RIPEMD/SHA family, and the
    /// hash inside NTLM.
    Md4(crate::hash_functions::md4::Md4),
    /// Whirlpool, ISO/IEC 10118-3. A 512 bit digest with a 512 bit
    /// block, which is the one hash here whose digest is as wide as its
    /// block.
    Whirlpool(crate::hash_functions::whirlpool::Whirlpool),
    /// SHA-3, SHAKE and pre-standard Keccak. One variant,
    /// because the three differ only in a rate and one byte of
    /// padding - which is exactly the point being made.
    Keccak(crate::hash_functions::keccak::Keccak),
}

impl AnyHash {
    pub fn new(name: &str) -> Result<Self, String> {
        // **The built-in names first, then the registry.** An OID a
        // caller has given a meaning to can be used as a hash name
        // here - which is how a certificate naming a digest by an OID
        // this library does not carry becomes readable without a
        // rebuild - and a registration can never shadow a name that
        // is compiled in. See `src/registry.rs`.
        if let Some(algorithm) = crate::registry::hash_for(name) {
            if !HASHES.contains(&name) {
                return AnyHash::new(&algorithm);
            }
        }
        match name.to_ascii_lowercase().replace('-', "_").as_str() {
            "md2" => Ok(AnyHash::Md2(
                crate::hash_functions::md2::Md2::new(&[]))),
            "md4" => Ok(AnyHash::Md4(
                crate::hash_functions::md4::Md4::new(&[]))),
            "md5" => Ok(AnyHash::Md5(MD5::new(&[]))),
            "sha1" => Ok(AnyHash::Sha1(SHA1::new(&[]))),
            "sha0" => {
                let mut h = SHA1::new(&[]);
                h.set_to_sha0();
                Ok(AnyHash::Sha1(h))
            }
            "sha224" => Ok(AnyHash::Sha224(sha2::SHA224::new(&[]))),
            "sha256" => Ok(AnyHash::Sha256(sha2::SHA256::new(&[]))),
            "sha384" => Ok(AnyHash::Sha384(sha2::SHA384::new(&[]))),
            "sha512" => Ok(AnyHash::Sha512(sha2::SHA512::new(&[], 512))),
            "sha512_224" => Ok(AnyHash::Sha512(sha2::SHA512::new(&[], 224))),
            "sha512_256" => Ok(AnyHash::Sha512(sha2::SHA512::new(&[], 256))),
            // "streebog" alone means the 256 bit one, which is what
            // RFC 9189's suites use and what a caller almost always
            // means. The full name is accepted for both sizes.
            "streebog" | "streebog256" | "gostr341112_256" | "gost34.11_256" =>
                Ok(AnyHash::Streebog(
                    crate::hash_functions::streebog::Streebog::new_256(&[]))),
            "gost94" | "gostr341194" | "gost34.11_94" =>
                Ok(AnyHash::Gost94(
                    crate::hash_functions::gost94::Gost94::new(&[]))),
            "gost94_test" | "gostr341194_test" =>
                Ok(AnyHash::Gost94(
                    crate::hash_functions::gost94::Gost94::with_param_set(
                        &[], crate::hash_functions::gost94::TEST_PARAM_SET)?)),
            "streebog512" | "gostr341112_512" | "gost34.11_512" =>
                Ok(AnyHash::Streebog(
                    crate::hash_functions::streebog::Streebog::new(&[]))),
            // BLAKE2 takes an output length, so `blake2b` means its
            // full 64 bytes and `blake2b_256` means 256 bits - the
            // shape hashlib's `digest_size` argument covers. The
            // length is part of the function rather than a truncation,
            // which is why it is in the name at all.
            // SHA-3 and its neighbours. `shake_128` and `shake_256`
            // default to the output length that matches their security
            // level; `squeeze` on the concrete type gives any length.
            "sha3_224" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::sha3(28)?)),
            "sha3_256" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::sha3(32)?)),
            "sha3_384" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::sha3(48)?)),
            "sha3_512" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::sha3(64)?)),
            "shake_128" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::shake(128, 16)?)),
            "shake_256" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::shake(256, 32)?)),
            // **Not SHA-3.** The pre-standard padding, which is what
            // Ethereum means by `keccak256`.
            "keccak_224" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::keccak(28)?)),
            "keccak_256" | "keccak" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::keccak(32)?)),
            "keccak_384" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::keccak(48)?)),
            "keccak_512" => Ok(AnyHash::Keccak(
                crate::hash_functions::keccak::Keccak::keccak(64)?)),
            "ripemd160" | "ripemd_160" | "rmd160" => Ok(AnyHash::Ripemd160(
                crate::hash_functions::ripemd160::Ripemd160::new(&[]))),
            other if other.starts_with("md6_") => {
                let bits: usize = other[4..].parse().map_err(|_| {
                    format!("{:?} does not name a bit length.", other)
                })?;
                Ok(AnyHash::Md6(crate::hash_functions::md6::Md6::new(bits)?))
            }
            "has160" | "has_160" => Ok(AnyHash::Has160(
                crate::hash_functions::has160::Has160::new(&[]))),
            "ripemd128" | "ripemd_128" | "rmd128" => Ok(AnyHash::Ripemd(
                crate::hash_functions::ripemd::Ripemd::ripemd128(&[]))),
            "ripemd256" | "ripemd_256" | "rmd256" => Ok(AnyHash::Ripemd(
                crate::hash_functions::ripemd::Ripemd::ripemd256(&[]))),
            "ripemd320" | "ripemd_320" | "rmd320" => Ok(AnyHash::Ripemd(
                crate::hash_functions::ripemd::Ripemd::ripemd320(&[]))),
            "whirlpool" => Ok(AnyHash::Whirlpool(
                crate::hash_functions::whirlpool::Whirlpool::new(&[]))),
            // The two earlier versions. Whirlpool-T is also called
            // Whirlpool-1, being the first revision.
            "whirlpool_0" | "whirlpool0" => Ok(AnyHash::Whirlpool(
                crate::hash_functions::whirlpool::Whirlpool::of_version(
                    crate::hash_functions::whirlpool::Version::Zero, &[]))),
            "whirlpool_t" | "whirlpoolt" | "whirlpool_1" | "whirlpool1" => Ok(AnyHash::Whirlpool(
                crate::hash_functions::whirlpool::Whirlpool::of_version(
                    crate::hash_functions::whirlpool::Version::Tweaked, &[]))),
            "sm3" => Ok(AnyHash::Sm3(
                crate::hash_functions::sm3::Sm3::new(&[]))),
            "blake2b" => Ok(AnyHash::Blake2b(
                crate::hash_functions::blake2::Blake2b::new(&[]))),
            "blake2s" => Ok(AnyHash::Blake2s(
                crate::hash_functions::blake2::Blake2s::new(&[]))),
            other if other.starts_with("blake2b_") || other.starts_with("blake2s_") => {
                let bits: usize = other[8..].parse().map_err(|_| {
                    format!("{:?} does not name a bit length.", other)
                })?;
                if !bits.is_multiple_of(8) {
                    return Err(format!("A BLAKE2 output is a whole number of \
                                        bytes; {} bits is not.", bits));
                }
                if other.starts_with("blake2b_") {
                    Ok(AnyHash::Blake2b(
                        crate::hash_functions::blake2::Blake2b::with_length(bits / 8)?))
                } else {
                    Ok(AnyHash::Blake2s(
                        crate::hash_functions::blake2::Blake2s::with_length(bits / 8)?))
                }
            }
            other => Err(format!("Unknown hash {:?}. Known: {}.", other, HASHES.join(", "))),
        }
    }

}

macro_rules! dispatch_hash {
    ($self:ident, $inner:ident => $body:expr) => {
        match $self {
            AnyHash::Md5($inner) => $body,
            AnyHash::Sha1($inner) => $body,
            AnyHash::Sha224($inner) => $body,
            AnyHash::Sha256($inner) => $body,
            AnyHash::Sha384($inner) => $body,
            AnyHash::Sha512($inner) => $body,
            AnyHash::Streebog($inner) => $body,
            AnyHash::Blake2b($inner) => $body,
            AnyHash::Blake2s($inner) => $body,
            AnyHash::Ripemd160($inner) => $body,
            AnyHash::Ripemd($inner) => $body,
            AnyHash::Has160($inner) => $body,
            AnyHash::Md6($inner) => $body,
            AnyHash::Sm3($inner) => $body,
            AnyHash::Md2($inner) => $body,
            AnyHash::Md4($inner) => $body,
            AnyHash::Gost94($inner) => $body,
            AnyHash::Whirlpool($inner) => $body,
            AnyHash::Keccak($inner) => $body,
        }
    };
}

impl HashFunction for AnyHash {
    fn name(&self) -> String { dispatch_hash!(self, h => h.name()) }
    fn digest_len(&self) -> usize { dispatch_hash!(self, h => h.digest_len()) }
    fn block_size(&self) -> usize { dispatch_hash!(self, h => h.block_size()) }
    fn update(&mut self, input: &[u8]) { dispatch_hash!(self, h => h.update(input)) }
    fn digest(&mut self) -> Vec<u8> { dispatch_hash!(self, h => h.digest()) }
}

// ---------------------------------------------------------------- padding ---

/// PKCS#7 padding as a value-returning function, for callers that cannot use
/// the in-place `BlockCipher::pad_pkcs7`.
pub fn pad_pkcs7(data: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    if block_size == 0 || block_size > 255 {
        return Err(format!("Block size must be 1..=255, got {}.", block_size));
    }
    let pad_len = block_size - (data.len() % block_size);
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    Ok(out)
}

/// Inverse of [`pad_pkcs7`], rejecting anything not validly padded.
pub fn unpad_pkcs7(data: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    if block_size == 0 || block_size > 255 {
        return Err(format!("Block size must be 1..=255, got {}.", block_size));
    }
    if data.is_empty() || !data.len().is_multiple_of(block_size) {
        return Err("Input length is not a non-zero multiple of the block size.".to_string());
    }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > block_size {
        return Err("Invalid PKCS#7 padding.".to_string());
    }
    let mut bad = 0u8;
    for b in &data[data.len()-pad_len..] {
        bad |= b ^ (pad_len as u8);
    }
    if bad != 0 {
        return Err("Invalid PKCS#7 padding.".to_string());
    }
    Ok(data[..data.len()-pad_len].to_vec())
}

// ------------------------------------------------------------ MAC and KDF ---

use crate::kdf;
use crate::mac::Hmac;

/// A keyed HMAC over any hash this library knows, by name.
pub fn new_hmac(hash_name: &str, key: &[u8]) -> Result<Hmac<AnyHash>, String> {
    Ok(Hmac::new(AnyHash::new(hash_name)?, key))
}

/// One shot HMAC.
pub fn hmac(hash_name: &str, key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    Ok(Hmac::mac(AnyHash::new(hash_name)?, key, message))
}

/// One shot UMAC (RFC 4418): a 16 byte AES key, a nonce of 1 to 16
/// bytes that must never repeat under one key, and a tag of 4, 8, 12 or
/// 16 bytes.
pub fn umac(key: &[u8], nonce: &[u8], message: &[u8], tag_len: usize)
            -> Result<Vec<u8>, String> {
    crate::mac::umac::Umac::new(key, tag_len)?.tag(message, nonce)
}

/// HKDF (RFC 5869), extract then expand. An empty `salt` means the all-zero
/// salt the RFC specifies.
pub fn hkdf(hash_name: &str, salt: &[u8], ikm: &[u8], info: &[u8],
            length: usize) -> Result<Vec<u8>, String> {
    kdf::hkdf(AnyHash::new(hash_name)?, salt, ikm, info, length)
}

/// SP 800-108 counter mode. `prf` is `"hmac-<hash>"` or
/// `"cmac-<block cipher>"`; the fixed data is `label || 0x00 || context
/// || [L]_32`, as RFC 8009 uses it.
pub fn kbkdf_counter(prf: &str, key: &[u8], label: &[u8], context: &[u8], length: usize)
                     -> Result<Vec<u8>, String> {
    kdf::nist::kbkdf_counter(kdf::nist::Prf::named(prf)?, key, label, context, length)
}

/// SP 800-108 feedback mode with a counter, from `iv` (RFC 6803 uses a
/// block of zeros).
pub fn kbkdf_feedback(prf: &str, key: &[u8], iv: &[u8], label: &[u8], context: &[u8],
                      length: usize) -> Result<Vec<u8>, String> {
    kdf::nist::kbkdf_feedback(kdf::nist::Prf::named(prf)?, key, iv, label, context, length)
}

/// SP 800-56C's one-step KDF over a hash (the Concat KDF).
pub fn concat_kdf(hash_name: &str, z: &[u8], other_info: &[u8], length: usize)
                  -> Result<Vec<u8>, String> {
    kdf::nist::concat_kdf(hash_name, z, other_info, length)
}

/// ANSI X9.63's KDF.
pub fn x963_kdf(hash_name: &str, z: &[u8], shared_info: &[u8], length: usize)
                -> Result<Vec<u8>, String> {
    kdf::nist::x963_kdf(hash_name, z, shared_info, length)
}

/// RFC 3961's n-fold.
pub fn kerberos_nfold(data: &[u8], length: usize) -> Vec<u8> {
    kdf::kerberos::nfold(data, length)
}

/// RFC 3961's DR under the named block cipher.
pub fn kerberos_derive_random(cipher: &str, key: &[u8], constant: &[u8], length: usize)
                              -> Result<Vec<u8>, String> {
    kdf::kerberos::derive_random(&mut AnyBlockCipher::new(cipher, key, None)?, constant, length)
}

/// RFC 3961's DES string-to-key (`mit_des_string_to_key`).
pub fn kerberos_des_string_to_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    kdf::kerberos::des_string_to_key(password, salt)
}

/// RFC 3961's random-to-key for `"des"` (7 bytes) or `"3des"` (21).
pub fn kerberos_random_to_key(cipher: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    match cipher {
        "des" => kdf::kerberos::des_random_to_key(data),
        "3des" => kdf::kerberos::des3_random_to_key(data),
        other => Err(format!("RFC 3961's random-to-key is for des and 3des, not {other}; \
                              the AES and Camellia types take the bytes as they are.")),
    }
}

/// OpenPGP's string-to-key (RFC 9580 3.7.1) over a named hash: `count`
/// octets of `salt || passphrase` repeated (one copy if `count` is
/// shorter), `key_len` bytes out. Simple S2K is an empty salt and a count
/// of zero. See `kdf::password::openpgp_s2k`.
pub fn openpgp_s2k(hash: &str, passphrase: &[u8], salt: &[u8], count: usize, key_len: usize)
                   -> Result<Vec<u8>, String> {
    Ok(kdf::password::openpgp_s2k(AnyHash::new(hash)?, passphrase, salt, count, key_len))
}

/// The octet count an OpenPGP iterated S2K's coded count byte stands for.
pub fn openpgp_s2k_count(coded: u8) -> usize {
    kdf::password::openpgp_s2k_count(coded)
}

/// 7-Zip's AES key from a UTF-16LE password, a salt and the cycle count
/// (2^cycles rounds of SHA-256; 0x3f for the raw key).
pub fn sevenzip_aes_key(password: &[u8], salt: &[u8], cycles: u8) -> Result<Vec<u8>, String> {
    Ok(kdf::password::sevenzip_aes_key(password, salt, cycles)?.to_vec())
}

/// KeePass's AES-KDF: `rounds` of AES-256-ECB under `seed`, then SHA-256.
pub fn keepass_aes_kdf(key: &[u8], seed: &[u8], rounds: u64) -> Result<Vec<u8>, String> {
    Ok(kdf::password::keepass_aes_kdf(key, seed, rounds)?.to_vec())
}

/// LUKS's AF splitter: `key` spread over `stripes` stripes, all but the
/// last from the operating system's random source.
pub fn luks_af_split(key: &[u8], stripes: usize, hash: &str) -> Result<Vec<u8>, String> {
    let mut fill = |buf: &mut [u8]| -> Result<(), String> {
        buf.copy_from_slice(&random_bytes(buf.len())?);
        Ok(())
    };
    kdf::luks_af::af_split(key, stripes, hash, &mut fill)
}

/// LUKS's AF merge: the key from its stripes.
pub fn luks_af_merge(material: &[u8], key_len: usize, stripes: usize, hash: &str)
                     -> Result<Vec<u8>, String> {
    kdf::luks_af::af_merge(material, key_len, stripes, hash)
}

/// Encrypt one BitLocker sector. `method` is `aes-cbc-elephant-128`,
/// `aes-cbc-256`, `aes-xts-128` and so on; `key` is the volume key as
/// dm-crypt takes it (for Elephant, the CBC key then the tweak key);
/// `byte_offset` is the sector's offset on the volume, and the sector
/// size is the data's length.
pub fn bitlocker_encrypt_sector(method: &str, key: &[u8], byte_offset: u64, sector: &[u8])
                                -> Result<Vec<u8>, String> {
    use crate::block_ciphers::bitlocker::{Method, SectorCipher};
    let mut out = sector.to_vec();
    SectorCipher::new(Method::from_name(method)?, key)?.encrypt_sector(byte_offset, &mut out)?;
    Ok(out)
}

/// Decrypt one BitLocker sector; see `bitlocker_encrypt_sector`.
pub fn bitlocker_decrypt_sector(method: &str, key: &[u8], byte_offset: u64, sector: &[u8])
                                -> Result<Vec<u8>, String> {
    use crate::block_ciphers::bitlocker::{Method, SectorCipher};
    let mut out = sector.to_vec();
    SectorCipher::new(Method::from_name(method)?, key)?.decrypt_sector(byte_offset, &mut out)?;
    Ok(out)
}

/// The NT hash of a password (MS-NLMP NTOWFv1): MD4 of the password as
/// UTF-16 little endian. It is what NTLM and Kerberos's RC4-HMAC use as
/// the user's key.
pub fn nt_hash(password: &str) -> Vec<u8> {
    kdf::windows::nt_hash(password).to_vec()
}

/// The LM hash of a password (MS-NLMP LMOWFv1), given as bytes in the
/// OEM code page it was made under. ASCII letters are uppercased here;
/// other bytes are used as they are, since their uppercase depends on
/// the code page. More than 14 bytes is an error: Windows stores no LM
/// hash for such a password.
pub fn lm_hash(password: &[u8]) -> Result<Vec<u8>, String> {
    kdf::windows::lm_hash(password).map(|hash| hash.to_vec())
}

/// The key that opens a BitLocker password protector's copy of the
/// volume master key: SHA-256 twice over the UTF-16LE password, then
/// 2^20 rounds of stretching with the protector's 16-byte salt.
pub fn bitlocker_password_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let salt: [u8; 16] = salt.try_into()
        .map_err(|_| format!("A BitLocker salt is 16 bytes, not {}.", salt.len()))?;
    Ok(kdf::password::bitlocker_stretch(&kdf::password::bitlocker_password_hash(password),
                                        &salt).to_vec())
}

/// The same for a recovery password: its 16-byte key, SHA-256, then the
/// stretching.
pub fn bitlocker_recovery_password_key(recovery: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let salt: [u8; 16] = salt.try_into()
        .map_err(|_| format!("A BitLocker salt is 16 bytes, not {}.", salt.len()))?;
    let key = kdf::password::bitlocker_recovery_key(recovery)?;
    let mut h = AnyHash::new("sha256")?;
    h.update(&key);
    let initial: [u8; 32] = h.digest().try_into().unwrap();
    Ok(kdf::password::bitlocker_stretch(&initial, &salt).to_vec())
}

/// A Unix `crypt(3)` password hash. `setting` chooses the method by its
/// prefix - a bare two-character salt for traditional DES, `_` for BSDi,
/// `$1$` for MD5-crypt, `$2b$` and kin for bcrypt, `$5$`/`$6$` for the
/// SHA-crypts, `$3$` for the NT hash, `$sha1$`, `$md5` for Sun's - and
/// also carries the salt and any cost. Returns the full hash string,
/// which begins with the setting. These are old by design; `crate::kdf::
/// unix_crypt` says what each is and when it was current.
///
/// # Errors
/// A setting whose prefix names no known method, or is malformed for the
/// method it names.
pub fn unix_crypt(password: &[u8], setting: &str) -> Result<String, String> {
    kdf::unix_crypt::crypt(password, setting)
}

/// Whether `password` produces the stored `crypt(3)` hash, compared in
/// constant time. `false` for a hash this cannot parse, so a parse
/// failure cannot be mistaken for a match.
pub fn unix_crypt_verify(password: &[u8], stored: &str) -> bool {
    kdf::unix_crypt::verify(password, stored)
}

/// PBKDF2 (RFC 8018 section 5.2).
///
/// No minimum iteration count is imposed: a file written in 2009 with
/// `c=1000` still has to be readable. See `kdf::password` for the
/// argument, and `pbkdf2_recommended_iterations` for what to use when
/// writing something new.
pub fn pbkdf2(hash_name: &str, password: &[u8], salt: &[u8], iterations: u32,
              length: usize) -> Result<Vec<u8>, String> {
    kdf::password::pbkdf2(AnyHash::new(hash_name)?, password, salt, iterations, length)
}

/// What to use for new work, as of 2026. Never consulted when reading,
/// where the count comes from the file.
pub fn pbkdf2_recommended_iterations(hash_name: &str) -> u32 {
    kdf::password::pbkdf2_recommended_iterations(hash_name)
}

/// Squeeze `length` bytes out of a SHAKE.
///
/// Refused for anything that is not extendable, rather than truncating
/// or repeating: SHAKE is the only thing here that has an answer for
/// "give me a thousand bytes", and pretending otherwise would hand back
/// a silently weaker key.
pub fn shake(name: &str, data: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let lower = name.to_ascii_lowercase().replace('-', "_");
    let security = match lower.as_str() {
        "shake_128" | "shake128" => 128,
        "shake_256" | "shake256" => 256,
        other => return Err(format!(
            "{:?} is not an extendable output function. Only shake_128 and \
             shake_256 can produce an arbitrary length.", other)),
    };
    let mut sponge = crate::hash_functions::keccak::Keccak::shake(security, length)?;
    use crate::hash_functions::HashFunction;
    sponge.update(data);
    Ok(sponge.squeeze(length))
}

/// scrypt (RFC 7914). `n` is a power of two greater than one.
pub fn scrypt(password: &[u8], salt: &[u8], n: u64, r: u32, p: u32,
              length: usize) -> Result<Vec<u8>, String> {
    kdf::scrypt::scrypt(password, salt, n, r, p, length)
}

/// Argon2 (RFC 9106). `variant` is "argon2d", "argon2i" or "argon2id".
///
/// Named by string here rather than by enum because this is the layer
/// the Python bindings cross, and a string is what a caller coming from
/// `argon2-cffi` or `cryptography` already has.
#[allow(clippy::too_many_arguments)]
pub fn argon2(variant: &str, password: &[u8], salt: &[u8], memory_kib: u32,
              passes: u32, lanes: u32, secret: &[u8], associated_data: &[u8],
              length: usize) -> Result<Vec<u8>, String> {
    let variant = match variant.to_ascii_lowercase().as_str() {
        "argon2d" | "d" => kdf::argon2::Variant::D,
        "argon2i" | "i" => kdf::argon2::Variant::I,
        "argon2id" | "id" => kdf::argon2::Variant::Id,
        other => return Err(format!(
            "Unknown Argon2 variant {:?}. Known: argon2d, argon2i, argon2id.",
            other)),
    };
    kdf::argon2::Argon2 {
        variant, memory_kib, passes, lanes,
        secret: secret.to_vec(),
        associated_data: associated_data.to_vec(),
    }.derive(password, salt, length)
}

/// The TLS 1.2 PRF (RFC 5246 section 5).
pub fn tls12_prf(hash_name: &str, secret: &[u8], label: &[u8], seed: &[u8],
                 length: usize) -> Result<Vec<u8>, String> {
    Ok(kdf::tls12_prf(AnyHash::new(hash_name)?, secret, label, seed, length))
}

/// The TLS 1.0/1.1 PRF (RFC 2246 section 5). The hash is fixed by the spec.
pub fn tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    kdf::tls10_prf(secret, label, seed, length)
}

// --------------------------------------------------------- elliptic curves ---

use crate::bignum::BigUint;
use crate::ec::vko::Cofactor;
use crate::ec::{curves, Curve, Point, Signature};

pub use crate::ec::curves::NAMES as CURVES;

/// An EC key pair, held as the private scalar plus its public point.
pub struct EcKey {
    curve: Curve,
    private: BigUint,
    public: Point,
}

impl EcKey {
    /// A fresh key pair from the OS random source.
    pub fn generate(curve_name: &str) -> Result<EcKey, String> {
        let curve = curves::by_name(curve_name)?;
        let (private, public) = curve.generate_key_pair()?;
        Ok(EcKey { curve, private, public })
    }

    /// Import a private scalar, big endian. Rejects anything outside
    /// `[1, n)`, which is where a scalar has to live.
    pub fn from_private(curve_name: &str, private: &[u8]) -> Result<EcKey, String> {
        let curve = curves::by_name(curve_name)?;
        let d = BigUint::from_bytes_be(private);
        if d.is_zero() || d >= curve.n {
            return Err("Private scalar is not in [1, n).".to_string());
        }
        let public = curve.scalar_mul_ct(&curve.g, &d);
        Ok(EcKey { curve, private: d, public })
    }

    pub fn curve_name(&self) -> &'static str {
        self.curve.name
    }

    /// The size of the field in bits, which is what everyone calls the key
    /// size for an EC key: 256 for P-256.
    pub fn key_size(&self) -> usize {
        self.curve.p.bit_len()
    }

    pub fn private_bytes(&self) -> Result<Vec<u8>, String> {
        self.private.to_bytes_be_padded(self.curve.scalar_bytes())
    }

    /// SEC1 point encoding of the public key.
    pub fn public_bytes(&self, compressed: bool) -> Result<Vec<u8>, String> {
        self.curve.encode_point(&self.public, compressed)
    }

    /// ECDH against a peer's encoded point. The point is validated before
    /// any arithmetic touches it, and the scalar multiplication uses the
    /// constant-time ladder.
    pub fn exchange(&self, peer_public: &[u8]) -> Result<Vec<u8>, String> {
        let peer = self.curve.decode_point(peer_public)?;
        self.curve.ecdh(&self.private, &peer)
    }

    /// VKO, the GOST key agreement (RFC 7836 section 4.3).
    ///
    /// Not ECDH with a hash on the end: the nonce is mixed into the
    /// scalar, and the output is Streebog over *both* coordinates
    /// written little endian. `ukm` is the user keying material, a value
    /// both sides know, and it must not be zero.
    ///
    /// `digest_bits` is 256 or 512 and follows the key size rather than
    /// the curve's.
    pub fn vko(&self, peer_public: &[u8], ukm: &[u8], digest_bits: usize)
               -> Result<Vec<u8>, String> {
        let peer = self.curve.decode_point(peer_public)?;
        self.curve.vko(&self.private, &peer, ukm, digest_bits)
    }

    /// The same, naming which reading of the cofactor to use:
    /// `"as-specified"` for RFC 7836's `m/q` term, which is also what
    /// OpenSSL's GOST engine computes, or `"without-cofactor"` for the
    /// term left out.
    ///
    /// **Use `"as-specified"`.** Only two curves have a cofactor that
    /// is not one - `gost256-tc26-a` and `gost512-c` - and on every
    /// other one the two readings are the same number. On those two
    /// they are different points, and the `vko-*` rows of
    /// `vectors/gost_engine.vec` show that the engine is the document's
    /// reading on both. `"without-cofactor"` matches nothing known and
    /// exists so a test can show the distinction is real.
    pub fn vko_using(&self, peer_public: &[u8], ukm: &[u8],
                     digest_bits: usize, cofactor: &str)
                     -> Result<Vec<u8>, String> {
        let peer = self.curve.decode_point(peer_public)?;
        self.curve.vko_using(&self.private, &peer, ukm, digest_bits,
                             Cofactor::by_name(cofactor)?)
    }

    /// Sign an already computed digest with ECDSA, returning fixed-width
    /// `r || s`. `hash_name` must name the algorithm that produced the
    /// digest: RFC 6979 derives the nonce with an HMAC over that same hash,
    /// so a mismatch produces a signature nobody else will reproduce.
    ///
    /// The signature is deterministic. The same key and digest always give
    /// the same bytes, and no randomness is involved.
    pub fn sign(&self, digest: &[u8], hash_name: &str) -> Result<Vec<u8>, String> {
        let hash = AnyHash::new(hash_name)?;
        let signature = self.curve.sign(&self.private, digest, hash)?;
        signature.to_bytes(&self.curve)
    }

    /// Sign under SM2, GB/T 32918.2.
    ///
    /// **Takes the message, not a digest.** SM2's `e` is
    /// `SM3(Z_A || M)` where `Z_A` binds the identity and the curve, so
    /// there is no digest a caller could have computed in advance - an
    /// API taking one cannot express SM2 at all.
    ///
    /// `id` is the distinguishing identifier. An empty slice means
    /// GB/T 32918.2's default, `1234567812345678`, because that is what
    /// a Chinese implementation uses; to sign under a genuinely empty
    /// identity - which is what `openssl pkeyutl` does by default -
    /// pass `Some(&[])` through `sm2_sign_with_id`.
    ///
    /// Deterministic, by the same RFC 6979 construction the rest of
    /// this file uses. SM2 does not standardise that; the failure mode
    /// of a repeated nonce is identical to ECDSA's, so it is used
    /// anyway.
    pub fn sm2_sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.sm2_sign_with_id(sm2::DEFAULT_ID, message)
    }

    /// Sign under SM2 with an explicit identity, which may be empty.
    pub fn sm2_sign_with_id(&self, id: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        self.require_sm2()?;
        let signature = sm2::sign(&self.curve, &self.private, id, message)?;
        signature.to_bytes(&self.curve)
    }

    /// Verify an SM2 signature with our own public key.
    pub fn sm2_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        self.sm2_verify_with_id(sm2::DEFAULT_ID, message, signature)
    }

    pub fn sm2_verify_with_id(&self, id: &[u8], message: &[u8], signature: &[u8])
                              -> Result<bool, String> {
        self.require_sm2()?;
        let signature = Signature::from_bytes(&self.curve, signature)?;
        sm2::verify(&self.curve, &self.public, id, message, &signature)
    }

    /// Decrypt an SM2 ciphertext in the `C1 || C3 || C2` form.
    pub fn sm2_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        self.require_sm2()?;
        sm2::decrypt(&self.curve, &self.private, ciphertext)
    }

    /// Decrypt an SM2 ciphertext in the DER form OpenSSL exchanges.
    pub fn sm2_decrypt_der(&self, der: &[u8]) -> Result<Vec<u8>, String> {
        self.require_sm2()?;
        let raw = sm2::ciphertext_from_der(&self.curve, der)?;
        sm2::decrypt(&self.curve, &self.private, &raw)
    }

    /// SM2 is defined over one curve. Refusing another is not pedantry:
    /// the curve's own `a`, `b` and generator go into `Z_A`, so a
    /// signature made over P-256 would be a perfectly self-consistent
    /// thing that no SM2 verifier can check.
    fn require_sm2(&self) -> Result<(), String> {
        if self.curve.name != "sm2p256v1" {
            return Err(format!(
                "SM2 is defined over sm2p256v1; this key is on {}. The curve \
                 is hashed into Z_A, so a signature over another curve is not \
                 an SM2 signature.",
                self.curve.name
            ));
        }
        Ok(())
    }

    /// Sign under GOST R 34.10-2012 rather than ECDSA.
    ///
    /// A different equation over the same curve, with three conventions
    /// of its own - the digest is read little endian, the signing
    /// equation has no inversion in it, and the encoding is `s || r`
    /// rather than `r || s`. See `src/ec/gost3410.rs`.
    ///
    /// Also deterministic, by the same RFC 6979 construction. GOST does
    /// not standardise that and the failure mode of a repeated nonce is
    /// identical to ECDSA's, so it is used anyway.
    pub fn sign_gost(&self, digest: &[u8], hash_name: &str) -> Result<Vec<u8>, String> {
        let hash = AnyHash::new(hash_name)?;
        let signature = self.curve.gost_sign(&self.private, digest, hash)?;
        self.curve.gost_signature_bytes(&signature)
    }

    /// The public half on its own, which is what a verifier needs.
    pub fn public_key(&self) -> EcPublicKey {
        EcPublicKey { curve: self.curve.clone(), point: self.public.clone() }
    }
}

/// A public point on a named curve: enough to verify a signature or to be a
/// peer in a key exchange, and nothing more.
pub struct EcPublicKey {
    curve: Curve,
    point: Point,
}

impl EcPublicKey {
    /// Import a SEC1 encoded point. Validated on the way in — a point that
    /// is not on the curve is refused here rather than at the first
    /// arithmetic that touches it.
    pub fn from_bytes(curve_name: &str, encoded: &[u8]) -> Result<EcPublicKey, String> {
        let curve = curves::by_name(curve_name)?;
        let point = curve.decode_point(encoded)?;
        Ok(EcPublicKey { curve, point })
    }

    pub fn to_bytes(&self, compressed: bool) -> Result<Vec<u8>, String> {
        self.curve.encode_point(&self.point, compressed)
    }

    pub fn curve_name(&self) -> &'static str {
        self.curve.name
    }

    pub fn key_size(&self) -> usize {
        self.curve.p.bit_len()
    }

    /// Verify a fixed-width `r || s` signature over a digest.
    ///
    /// Returns `false` for a signature that is well formed and wrong, and an
    /// error only for one that is not a signature at all — the wrong length,
    /// say. A caller that treats both the same is fine; one that treats an
    /// error as "valid" is not, which is why this does not return a bare
    /// bool.
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, String> {
        let signature = Signature::from_bytes(&self.curve, signature)?;
        self.curve.verify(&self.point, digest, &signature)
    }

    /// Verify a GOST R 34.10-2012 signature, which is `s || r` and a
    /// different equation from ECDSA's over the same curve.
    pub fn verify_gost(&self, digest: &[u8], signature: &[u8])
                       -> Result<bool, String> {
        let signature = self.curve.gost_signature_from_bytes(signature)?;
        self.curve.gost_verify(&self.point, digest, &signature)
    }

    /// Verify an SM2 signature under GB/T 32918.2's default identity.
    pub fn sm2_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        self.sm2_verify_with_id(sm2::DEFAULT_ID, message, signature)
    }

    /// Verify with an explicit identity. An empty `id` is a real empty
    /// identity, which is what `openssl pkeyutl` signs under by default.
    pub fn sm2_verify_with_id(&self, id: &[u8], message: &[u8], signature: &[u8])
                              -> Result<bool, String> {
        self.require_sm2()?;
        let signature = Signature::from_bytes(&self.curve, signature)?;
        sm2::verify(&self.curve, &self.point, id, message, &signature)
    }

    /// Encrypt to this key, returning `C1 || C3 || C2`.
    pub fn sm2_encrypt(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.require_sm2()?;
        sm2::encrypt(&self.curve, &self.point, message)
    }

    /// Encrypt to this key in the DER form OpenSSL exchanges.
    pub fn sm2_encrypt_der(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.require_sm2()?;
        let raw = sm2::encrypt(&self.curve, &self.point, message)?;
        sm2::ciphertext_to_der(&self.curve, &raw)
    }

    fn require_sm2(&self) -> Result<(), String> {
        if self.curve.name != "sm2p256v1" {
            return Err(format!(
                "SM2 is defined over sm2p256v1; this key is on {}.",
                self.curve.name
            ));
        }
        Ok(())
    }
}

/// An EdDSA key pair, held as the seed plus its derived public key.
///
/// Separate from `EcKey` rather than a curve under it, because almost
/// nothing is shared: the private value is a **seed** and not a scalar,
/// the public key is a compressed Edwards point and not a SEC1 one,
/// signing takes the message rather than a digest, and there is no
/// key agreement on this curve at all - X25519 is a different function
/// on a different model of the same curve.
pub struct EddsaKey {
    variant: eddsa::Variant,
    name: &'static str,
    seed: Vec<u8>,
    public: Vec<u8>,
}

impl EddsaKey {
    pub fn generate(name: &str) -> Result<EddsaKey, String> {
        let (seed, public) = eddsa_generate(name)?;
        Ok(EddsaKey { variant: eddsa_variant(name)?, name: eddsa_name(name)?, seed, public })
    }

    /// Import a seed. The length is the whole check available: every
    /// byte string of the right length is a valid EdDSA key, which is
    /// one of the things the scheme was designed for.
    pub fn from_private(name: &str, seed: &[u8]) -> Result<EddsaKey, String> {
        let variant = eddsa_variant(name)?;
        if seed.len() != variant.key_len() {
            return Err(format!("An {} private key is {} bytes; got {}.",
                               name, variant.key_len(), seed.len()));
        }
        let public = eddsa_public_key(name, seed)?;
        Ok(EddsaKey { variant, name: eddsa_name(name)?, seed: seed.to_vec(), public })
    }

    pub fn curve_name(&self) -> &'static str {
        self.name
    }

    pub fn private_bytes(&self) -> Vec<u8> {
        self.seed.clone()
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Sign a message. **Not a digest** - see `eddsa_sign`.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
        eddsa_sign(self.name, &self.seed, message, context)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8], context: &[u8])
                  -> Result<bool, String> {
        eddsa_verify(self.name, &self.public, message, signature, context)
    }

    pub fn key_size(&self) -> usize {
        self.variant.key_len() * 8
    }
}

/// The canonical spelling, so `EddsaKey` can hold a `&'static str`
/// rather than the caller's copy.
fn eddsa_name(name: &str) -> Result<&'static str, String> {
    match eddsa_variant(name)? {
        eddsa::Variant::Ed25519 => Ok("ed25519"),
        eddsa::Variant::Ed448 => Ok("ed448"),
    }
}

// -------------------------------------------------------------------- RSA ---

use crate::publickey_ciphers::rsa;

/// An RSA private key, with its public half alongside.
pub struct RsaKey {
    inner: rsa::RsaPrivateKey,
}

/// An RSA public key: enough to encrypt and to verify.
pub struct RsaPublicKey {
    inner: rsa::RsaPublicKey,
}

/// Big endian bytes, trimmed of leading zeros — which is how every RSA
/// serialisation format carries these numbers.
fn number_bytes(value: &BigUint) -> Vec<u8> {
    value.to_bytes_be()
}

impl RsaKey {
    /// Generate a key. `bits` is the modulus size; 2048 is the sensible
    /// minimum and anything smaller is for talking to something old.
    ///
    /// This is slow — it searches for two primes — and the time is
    /// unpredictable, so a caller with a deadline should do it in advance.
    pub fn generate(bits: usize) -> Result<RsaKey, String> {
        Ok(RsaKey { inner: rsa::RsaPrivateKey::generate(bits)? })
    }

    /// Rebuild a key from its two primes. The CRT parameters are derived
    /// rather than taken, so there is nothing to be inconsistent.
    pub fn from_primes(p: &[u8], q: &[u8], e: &[u8]) -> Result<RsaKey, String> {
        Ok(RsaKey {
            inner: rsa::RsaPrivateKey::from_primes(
                BigUint::from_bytes_be(p),
                BigUint::from_bytes_be(q),
                BigUint::from_bytes_be(e))?,
        })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey { inner: self.inner.public_key() }
    }

    /// Modulus size in bytes: the size of every ciphertext and signature.
    pub fn size(&self) -> usize { self.inner.size() }
    pub fn bits(&self) -> usize { self.inner.bits() }

    /// Sign an already computed digest with PKCS#1 v1.5. `hash_name` picks
    /// the DigestInfo prefix and must name the hash that made the digest.
    pub fn sign(&self, hash_name: &str, digest: &[u8]) -> Result<Vec<u8>, String> {
        rsa::sign_pkcs1v15(&self.inner, hash_name, digest)
    }

    /// Sign a digest with PSS and a random salt. `salt_len` defaults to
    /// the hash's own length, which is what TLS 1.3 requires.
    ///
    /// Two signatures over the same digest differ, which is the point: a
    /// PSS that produced the same bytes twice would not be using its salt.
    pub fn sign_pss(&self, hash_name: &str, digest: &[u8],
                    salt_len: Option<usize>) -> Result<Vec<u8>, String> {
        let salt_len = match salt_len {
            Some(n) => n,
            None => rsa::pss_salt_len(hash_name)?,
        };
        rsa::sign_pss(&self.inner, hash_name, digest, salt_len)
    }

    /// PKCS#1 v1.5 decryption. Every failure returns the same error, on
    /// purpose — see the note on `rsa::decrypt_pkcs1v15`.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        rsa::decrypt_pkcs1v15(&self.inner, ciphertext)
    }

    /// RSAES-OAEP decryption. `mgf_hash` defaults to `hash_name`; the
    /// label defaults to empty, and must be the one encrypted under.
    /// Every failure of the ciphertext returns the same error, on purpose
    /// — see the note on `rsa::decrypt_oaep`.
    pub fn decrypt_oaep(&self, hash_name: &str, mgf_hash: Option<&str>, label: &[u8],
                        ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        rsa::decrypt_oaep(&self.inner, hash_name, mgf_hash.unwrap_or(hash_name), label,
                          ciphertext)
    }

    /// The key's components, big endian: n, e, d, p, q, dp, dq, qinv. Until
    /// there is an ASN.1 encoder, this is how a key leaves the library.
    pub fn numbers(&self) -> Vec<(&'static str, Vec<u8>)> {
        let (p, q) = self.inner.primes();
        let (dp, dq, qinv) = self.inner.crt_parameters();
        vec![
            ("n", number_bytes(&self.inner.public.n)),
            ("e", number_bytes(&self.inner.public.e)),
            ("d", number_bytes(self.inner.private_exponent())),
            ("p", number_bytes(p)),
            ("q", number_bytes(q)),
            ("dp", number_bytes(dp)),
            ("dq", number_bytes(dq)),
            ("qinv", number_bytes(qinv)),
        ]
    }
}

impl RsaPublicKey {
    /// From a modulus and exponent, big endian.
    pub fn new(n: &[u8], e: &[u8]) -> Result<RsaPublicKey, String> {
        Ok(RsaPublicKey {
            inner: rsa::RsaPublicKey::new(BigUint::from_bytes_be(n),
                                          BigUint::from_bytes_be(e))?,
        })
    }

    pub fn size(&self) -> usize { self.inner.size() }
    pub fn bits(&self) -> usize { self.inner.bits() }

    pub fn modulus(&self) -> Vec<u8> { number_bytes(&self.inner.n) }
    pub fn exponent(&self) -> Vec<u8> { number_bytes(&self.inner.e) }

    /// PKCS#1 v1.5 encryption. Randomised, so the same message encrypts to
    /// different bytes every time — which is the point.
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        rsa::encrypt_pkcs1v15(&self.inner, message)
    }

    /// RSAES-OAEP encryption (RFC 8017 section 7.1). `hash_name` hashes
    /// the label and `mgf_hash`, which defaults to it, drives MGF1.
    /// Randomised, like `encrypt`.
    pub fn encrypt_oaep(&self, hash_name: &str, mgf_hash: Option<&str>, label: &[u8],
                        message: &[u8]) -> Result<Vec<u8>, String> {
        rsa::encrypt_oaep(&self.inner, hash_name, mgf_hash.unwrap_or(hash_name), label,
                          message)
    }

    /// Verify a PKCS#1 v1.5 signature over a digest. `false` for a signature
    /// that is well formed and wrong, an error for one that is not a
    /// signature at all.
    pub fn verify(&self, hash_name: &str, digest: &[u8], signature: &[u8])
                  -> Result<bool, String> {
        rsa::verify_pkcs1v15(&self.inner, hash_name, digest, signature)
    }

    /// Verify a PSS signature. `salt_len` defaults to the hash's own
    /// length, which is what TLS 1.3 requires and what every library's
    /// "PSS with the obvious parameters" means.
    ///
    /// The length is required rather than recovered from the block: a
    /// verifier that accepts any length accepts a salt of zero, which
    /// makes PSS deterministic and discards the property it exists for.
    pub fn verify_pss(&self, hash_name: &str, digest: &[u8], signature: &[u8],
                      salt_len: Option<usize>) -> Result<bool, String> {
        let salt_len = match salt_len {
            Some(n) => n,
            None => rsa::pss_salt_len(hash_name)?,
        };
        rsa::verify_pss(&self.inner, hash_name, digest, signature, salt_len)
    }
}

// -------------------------------------------------------- TLS key schedule ---

/// The master secret, for a named version.
///
/// Exposed because SSLv3's derivation is not TLS's and nothing on a modern
/// machine can check it: OpenSSL removed SSLv3, so the only reference is
/// the specification, and a reference written from the specification needs
/// something to compare against. See `scripts/diff_check.py`.
pub fn tls_master_secret(version: &str, premaster: &[u8], client_random: &[u8],
                         server_random: &[u8]) -> Result<Vec<u8>, String> {
    let version = parse_version(version)?;
    if client_random.len() != 32 || server_random.len() != 32 {
        return Err(format!(
            "A TLS random is 32 bytes; these are {} and {}.",
            client_random.len(), server_random.len()));
    }
    let mut client = [0u8; 32];
    let mut server = [0u8; 32];
    client.copy_from_slice(client_random);
    server.copy_from_slice(server_random);
    // The PRF hash only matters from TLS 1.2 on; SHA-256 is what every
    // suite this library implements uses there.
    crate::tls::keys::master_secret(
        version, crate::tls::suites::MacAlgorithm::Sha256,
        premaster, &client, &server)
}

/// SSLv3's record MAC (RFC 6101 section 5.2.3.1).
///
/// Not HMAC, and - the part a port of the TLS construction would miss -
/// the record's version is not in the input. Exposed for the same reason
/// as above: it is the only way to check it from outside.
pub fn ssl3_record_mac(hash_name: &str, mac_key: &[u8], sequence: u64,
                       content_type: u8, fragment: &[u8]) -> Result<Vec<u8>, String> {
    // `from_byte` maps anything unknown to `Unknown(n)` and keeps the
    // byte, which is right: a MAC is over the bytes that were sent, and
    // refusing a content type here would refuse to reproduce a real
    // record that used one.
    let content_type = crate::tls::ContentType::from_byte(content_type);
    crate::tls::record::ssl3_mac(hash_name, mac_key,
                                 crate::tls::record::SequenceNumber::at(sequence),
                                 content_type, fragment)
}

// ------------------------------------------------------------------ X25519 ---

pub use crate::ec::x25519;

/// X25519, by bytes. A free function rather than a key type, because that
/// is what RFC 7748 defines and what every caller wants: 32 bytes in, 32
/// bytes out, no encoding to agree on.
pub fn x25519_generate() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (private, public) = x25519::generate_key_pair()?;
    Ok((private.to_vec(), public.to_vec()))
}

fn thirty_two(label: &str, bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!("An X25519 {} is 32 bytes, not {}.", label, bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub fn x25519_public_key(private: &[u8]) -> Result<Vec<u8>, String> {
    Ok(x25519::public_key(&thirty_two("private key", private)?)?.to_vec())
}

/// The shared secret. Refuses the all-zero result, which means the peer
/// sent a low-order point and every session would share a known key.
pub fn x25519_exchange(private: &[u8], peer: &[u8]) -> Result<Vec<u8>, String> {
    Ok(x25519::exchange(&thirty_two("private key", private)?,
                        &thirty_two("public key", peer)?)?.to_vec())
}

/// The raw primitive, with no refusal of degenerate outputs. Here because
/// the RFC 7748 test vectors are stated in terms of it, and a test that
/// cannot reach the primitive cannot use them.
pub fn x25519_raw(scalar: &[u8], point: &[u8]) -> Result<Vec<u8>, String> {
    Ok(x25519::x25519(&thirty_two("scalar", scalar)?,
                      &thirty_two("u coordinate", point)?)?.to_vec())
}

// -------------------------------------------------------------------- X448 ---

pub use crate::ec::x448;

/// X448, by bytes, shaped exactly like the X25519 four above - **and
/// with its own length check**.
///
/// `fifty_six` rather than a shared helper taking a width: the error
/// message names the algorithm, and an X25519 key handed to an X448
/// function is the single most likely mistake a caller makes here. A
/// message saying "a key is 56 bytes, not 32" without saying which
/// algorithm wanted 56 leaves them looking at the wrong call.
pub fn x448_generate() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (private, public) = x448::generate_key_pair()?;
    Ok((private.to_vec(), public.to_vec()))
}

fn fifty_six(label: &str, bytes: &[u8]) -> Result<[u8; x448::KEY_LEN], String> {
    if bytes.len() != x448::KEY_LEN {
        return Err(format!("An X448 {} is {} bytes, not {}. (X25519's is 32, \
                            if that is what this is.)",
                           label, x448::KEY_LEN, bytes.len()));
    }
    let mut out = [0u8; x448::KEY_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub fn x448_public_key(private: &[u8]) -> Result<Vec<u8>, String> {
    Ok(x448::public_key(&fifty_six("private key", private)?)?.to_vec())
}

/// The shared secret. Refuses the all-zero result, which means the peer
/// sent a low-order point and every session would share a known key.
pub fn x448_exchange(private: &[u8], peer: &[u8]) -> Result<Vec<u8>, String> {
    Ok(x448::exchange(&fifty_six("private key", private)?,
                      &fifty_six("public key", peer)?)?.to_vec())
}

/// The raw primitive, with no refusal of degenerate outputs. Here
/// because RFC 7748's test vectors are stated in terms of it, and a test
/// that cannot reach the primitive cannot use them.
pub fn x448_raw(scalar: &[u8], point: &[u8]) -> Result<Vec<u8>, String> {
    Ok(x448::x448(&fifty_six("scalar", scalar)?,
                  &fifty_six("u coordinate", point)?)?.to_vec())
}

// ------------------------------------------------- key wrap and XTS ---

pub use crate::block_ciphers::{keywrap, lrw, xts};

/// A 128 bit block cipher by name, for the two modes that have no 64 bit
/// form.
///
/// The error names the block size rather than saying "unknown", because
/// the cipher is usually known and simply the wrong shape - `des` and
/// `magma` are both in `block_ciphers_available` and neither can do
/// either of these modes.
fn wide_block(name: &str, key: &[u8]) -> Result<AnyBlockCipher, String> {
    let cipher = AnyBlockCipher::new(name, key, None)?;
    if cipher.blocksize() != 16 {
        return Err(format!(
            "{} has a {} byte block; this mode is defined for 128 bit blocks \
             only, and there is no narrower variant of it.",
            cipher.name(), cipher.blocksize()));
    }
    Ok(cipher)
}

/// Wrap key data under a key-encryption key, RFC 3394.
///
/// `cipher` is any 128 bit block cipher. AES is what every standard
/// names; the others work because the construction is generic, and
/// nothing else anywhere implements them.
///
/// # Errors
/// A cipher that is unknown or not 128 bits, a bad key length, or key
/// data that is not at least two whole 64 bit blocks - use
/// [`key_wrap_with_padding`] for those.
pub fn key_wrap(cipher: &str, kek: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    keywrap::wrap(&mut wide_block(cipher, kek)?, data)
}

/// Unwrap key data, RFC 3394.
///
/// # Errors
/// Anything that is not a valid wrapping under this key. The integrity
/// check is what replaces a separate MAC, and it is the only thing
/// standing between a caller and a key an attacker chose.
pub fn key_unwrap(cipher: &str, kek: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    keywrap::unwrap(&mut wide_block(cipher, kek)?, data)
}

/// Wrap key data of any length, RFC 5649.
///
/// # Errors
/// As [`key_wrap`], except that any length from one byte up is
/// accepted.
pub fn key_wrap_with_padding(cipher: &str, kek: &[u8], data: &[u8])
                             -> Result<Vec<u8>, String> {
    keywrap::wrap_with_padding(&mut wide_block(cipher, kek)?, data)
}

/// Unwrap key data wrapped with RFC 5649.
///
/// # Errors
/// Anything that is not a valid padded wrapping under this key,
/// including a length field or padding that does not match - both are
/// part of the authentication.
pub fn key_unwrap_with_padding(cipher: &str, kek: &[u8], data: &[u8])
                               -> Result<Vec<u8>, String> {
    keywrap::unwrap_with_padding(&mut wide_block(cipher, kek)?, data)
}

/// `given`, or `n` fresh random bytes when it is `None`.
fn or_random(given: Option<&[u8]>, n: usize) -> Result<Vec<u8>, String> {
    match given {
        Some(bytes) => Ok(bytes.to_vec()),
        None => random_bytes(n),
    }
}

/// RFC 3217's Triple-DES key wrap. `iv` is drawn at random when absent.
pub fn cms_3des_key_wrap(kek: &[u8], cek: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>, String> {
    crate::block_ciphers::cms_wrap::wrap_3des(kek, cek, &or_random(iv, 8)?)
}

pub fn cms_3des_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    crate::block_ciphers::cms_wrap::unwrap_3des(kek, wrapped)
}

/// RFC 3217's RC2 key wrap, the key-encryption key at `effective_bits`.
/// The padding and `iv` are drawn at random when absent.
pub fn cms_rc2_key_wrap(kek: &[u8], effective_bits: usize, cek: &[u8], pad: Option<&[u8]>,
                        iv: Option<&[u8]>) -> Result<Vec<u8>, String> {
    crate::block_ciphers::cms_wrap::wrap_rc2(kek, effective_bits, cek, &or_random(pad, 7)?,
                                             &or_random(iv, 8)?)
}

pub fn cms_rc2_key_unwrap(kek: &[u8], effective_bits: usize, wrapped: &[u8])
                          -> Result<Vec<u8>, String> {
    crate::block_ciphers::cms_wrap::unwrap_rc2(kek, effective_bits, wrapped)
}

/// RFC 3211's password recipient key wrap over `cipher`, keyed by the
/// key-encryption key (which PBKDF2 makes from the password). The
/// padding is drawn at random when absent.
pub fn pwri_key_wrap(cipher: &str, kek: &[u8], iv: &[u8], cek: &[u8], padding: Option<&[u8]>)
                     -> Result<Vec<u8>, String> {
    let mut c = AnyBlockCipher::new(cipher, kek, None)?;
    let padding = or_random(padding, 2 * c.blocksize())?;
    crate::block_ciphers::cms_wrap::pwri_wrap(&mut c, iv, cek, &padding)
}

pub fn pwri_key_unwrap(cipher: &str, kek: &[u8], iv: &[u8], wrapped: &[u8])
                       -> Result<Vec<u8>, String> {
    crate::block_ciphers::cms_wrap::pwri_unwrap(&mut AnyBlockCipher::new(cipher, kek, None)?,
                                                iv, wrapped)
}

/// Split an XTS key into its two halves, refusing the ones that are not
/// keys.
///
/// **Equal halves are refused.** They collapse the tweak cipher into the
/// data cipher, which is a configuration mistake rather than a legacy
/// format - OpenSSL refuses such a key too, and there is nothing already
/// written with one to stay readable for. That is the one place this
/// library is strict about reading as well as writing, and the reason is
/// that no such disk exists.
/// Whether two key halves differ, as an OR of XORs over every byte: `==`
/// on slices stops at the first difference, so its time says how long a
/// prefix the two secret halves share. The answer itself is public - an
/// equal pair is refused - and the branch on it is the caller's. Never
/// inlined, so `scripts/ct_check.py` can name it.
#[inline(never)]
fn halves_differ(first: &[u8], second: &[u8]) -> bool {
    first.iter().zip(second).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0
}

fn xts_halves(key: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if key.len() < 2 || !key.len().is_multiple_of(2) {
        return Err(format!(
            "An XTS key is two cipher keys end to end, so an even number of \
             bytes; this is {}.", key.len()));
    }
    let half = key.len() / 2;
    let (first, second) = key.split_at(half);
    if !halves_differ(first, second) {
        return Err("The two halves of this XTS key are identical, which \
                    collapses the tweak into the data cipher. XTS needs two \
                    different keys.".to_string());
    }
    Ok((first, second))
}

/// Encrypt one XTS data unit.
///
/// `key` is the two cipher keys end to end, so 32 bytes for
/// AES-128-XTS and 64 for AES-256-XTS. `sector` is the data unit
/// number. The output is exactly as long as the input.
///
/// # Errors
/// A cipher that is unknown or not 128 bits, a key whose halves are
/// equal or which is not two valid keys, an input shorter than one
/// block, or an input longer than [`xts::MAX_BLOCKS`] blocks.
pub fn xts_encrypt(cipher: &str, key: &[u8], sector: u128, data: &[u8])
                   -> Result<Vec<u8>, String> {
    let (first, second) = xts_halves(key)?;
    let mut data_cipher = wide_block(cipher, first)?;
    let mut tweak_cipher = wide_block(cipher, second)?;
    xts::encrypt(&mut data_cipher, &mut tweak_cipher, &xts::sector_tweak(sector), data)
}

/// Decrypt one XTS data unit.
///
/// # Errors
/// As [`xts_encrypt`], except that a data unit longer than
/// [`xts::MAX_BLOCKS`] blocks is accepted - see that constant. **There
/// is no authentication**: this returns plaintext for any input of a
/// legal length, including one an attacker wrote.
pub fn xts_decrypt(cipher: &str, key: &[u8], sector: u128, data: &[u8])
                   -> Result<Vec<u8>, String> {
    let (first, second) = xts_halves(key)?;
    let mut data_cipher = wide_block(cipher, first)?;
    let mut tweak_cipher = wide_block(cipher, second)?;
    xts::decrypt(&mut data_cipher, &mut tweak_cipher, &xts::sector_tweak(sector), data)
}

/// The data cipher's key and LRW's 16 byte tweak key, split.
fn lrw_parts(cipher: &str, key: &[u8]) -> Result<(AnyBlockCipher, [u8; 16]), String> {
    let split = key.len().checked_sub(16).filter(|&n| n > 0).ok_or_else(|| format!(
        "An LRW key is a cipher key followed by the 16 byte tweak key; {} bytes is too \
         short to be both.", key.len()))?;
    let (data_key, tweak_key) = key.split_at(split);
    Ok((wide_block(cipher, data_key)?, tweak_key.try_into().map_err(|_| "length".to_string())?))
}

/// Encrypt whole 16 byte blocks with LRW (IEEE P1619's draft mode, as
/// dm-crypt and TrueCrypt 4 used it). `key` is the cipher's key followed
/// by the 16 byte tweak key; `index` is the first block's index.
///
/// # Errors
/// A cipher that is unknown or not 128 bits, a key too short to hold a
/// tweak key, or an input that is not whole blocks.
pub fn lrw_encrypt(cipher: &str, key: &[u8], index: u128, data: &[u8])
                   -> Result<Vec<u8>, String> {
    let (mut data_cipher, tweak_key) = lrw_parts(cipher, key)?;
    lrw::encrypt(&mut data_cipher, &tweak_key, &index.to_be_bytes(), data)
}

/// Decrypt with LRW. Not authenticated, as XTS is not.
pub fn lrw_decrypt(cipher: &str, key: &[u8], index: u128, data: &[u8])
                   -> Result<Vec<u8>, String> {
    let (mut data_cipher, tweak_key) = lrw_parts(cipher, key)?;
    lrw::decrypt(&mut data_cipher, &tweak_key, &index.to_be_bytes(), data)
}

/// Whether AES runs on the processor's AES instructions in this build:
/// the `aes-ni` feature is compiled in and the CPU has AES-NI and
/// PCLMULQDQ. False means the portable implementation - bitsliced and
/// constant time for the multi-block modes, table-driven for the
/// one-block ones (see `docs/building.md`, "Building for speed").
pub fn hardware_aes() -> bool {
    crate::block_ciphers::aes::hardware_aes()
}

// ------------------------------------------------------------- randomness ---

pub use crate::random;

/// `n` cryptographically strong random bytes, from the operating
/// system's own source.
///
/// Exposed because a caller of this library should not have to reach
/// for a second one to get a nonce or a salt, and because the Python
/// shim's `RAND_bytes` has to come from somewhere it can name.
///
/// # Errors
/// The system random source being unreadable, which on every platform
/// here means something is badly wrong rather than that a retry would
/// help.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
    random::bytes(n)
}

/// Which source the bytes above come from, for a caller that wants to
/// record it.
pub fn random_source() -> &'static str {
    random::source()
}

// --------------------------------------------------------- Dual_EC_DRBG ---

pub use crate::prng::dual_ec;

/// Dual_EC_DRBG (SP 800-90A, withdrawn 2015) output, the whole of a
/// generator's life in one call: instantiate on `entropy`, `nonce` and
/// `personalization`, then `requests.len()` generate calls, each for its
/// own byte count and additional input. It uses the standard's `Q`, so it
/// is a demonstration of the design and its history (see `crate::prng::
/// dual_ec`), not something to generate keys with.
///
/// `curve` is `"P-256"`, `"P-384"` or `"P-521"`; `hash` is `"SHA-1"` or a
/// SHA-2 name. For prediction resistance, reseed between requests, which
/// this one-shot does not expose - the streaming type in `dual_ec` does.
///
/// # Errors
/// An unknown curve or hash, a hash too weak for the curve, or too little
/// entropy.
pub fn dual_ec_drbg(curve: &str, hash: &str, entropy: &[u8], nonce: &[u8],
                    personalization: &[u8], requests: &[(usize, &[u8])])
                    -> Result<Vec<Vec<u8>>, String> {
    let params = dual_ec::Parameters::standard(dual_ec::DualEcCurve::from_name(curve)?);
    let hash = dual_ec::DrbgHash::from_name(hash)?;
    let mut drbg = dual_ec::DualEcDrbg::new(params, hash, entropy, nonce, personalization)?;
    requests.iter().map(|(n, adin)| drbg.generate(*n, adin)).collect()
}

// ------------------------------------------------------------------ EdDSA ---

pub use crate::ec::eddsa;
pub use crate::ec::sm2;

/// The curve, by the name everything else calls it.
///
/// # Errors
/// Any name that is not `ed25519` or `ed448`. **`ed25519ctx`,
/// `ed25519ph` and `ed448ph` are errors rather than aliases**: they are
/// different schemes over the same curves, and quietly treating one as
/// the pure variant would produce signatures that verify here and
/// nowhere else.
pub fn eddsa_variant(name: &str) -> Result<eddsa::Variant, String> {
    match name.to_ascii_lowercase().as_str() {
        "ed25519" => Ok(eddsa::Variant::Ed25519),
        "ed448" => Ok(eddsa::Variant::Ed448),
        "ed25519ctx" | "ed25519ph" | "ed448ph" => Err(format!(
            "{} is a different scheme from the pure variant and is not \
             implemented. Use ed25519 or ed448.",
            name
        )),
        other => Err(format!("{} is not an EdDSA curve. Try ed25519 or ed448.", other)),
    }
}

/// The curves this build can sign with.
pub fn eddsa_curves() -> Vec<&'static str> {
    vec!["ed25519", "ed448"]
}

/// A fresh key pair, as `(private, public)`.
///
/// # Errors
/// An unknown curve name, or the system random source failing.
pub fn eddsa_generate(name: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    eddsa::generate_key_pair(eddsa_variant(name)?)
}

/// The public key for a private key.
///
/// # Errors
/// An unknown curve name, or a private key of the wrong length.
pub fn eddsa_public_key(name: &str, private: &[u8]) -> Result<Vec<u8>, String> {
    eddsa::public_key(eddsa_variant(name)?, private)
}

/// Sign a message. Deterministic: the same key and message always give
/// the same signature.
///
/// `context` is Ed448's domain separator and must be empty for Ed25519.
///
/// # Errors
/// An unknown curve name, a private key of the wrong length, or a
/// context where none is allowed.
pub fn eddsa_sign(name: &str, private: &[u8], message: &[u8], context: &[u8])
                  -> Result<Vec<u8>, String> {
    eddsa::sign(eddsa_variant(name)?, private, message, context)
}

/// Verify a signature.
///
/// `false` for a well-formed signature that is wrong, and an error only
/// for something that is not a signature at all - the wrong length, or a
/// public key that is not a point. Same split as [`EcPublicKey::verify`]
/// and [`RsaPublicKey::verify`], so a caller that ignores the `Result`
/// still cannot mistake a bad signature for a good one.
///
/// # Errors
/// An unknown curve name, a key or signature of the wrong length, or a
/// public key that does not decode to a point.
pub fn eddsa_verify(name: &str, public: &[u8], message: &[u8], signature: &[u8],
                    context: &[u8]) -> Result<bool, String> {
    let variant = eddsa_variant(name)?;
    if public.len() != variant.key_len() {
        return Err(format!("An {} public key is {} bytes; this one is {}.",
                           variant.name(), variant.key_len(), public.len()));
    }
    if signature.len() != variant.signature_len() {
        return Err(format!("An {} signature is {} bytes; this one is {}.",
                           variant.name(), variant.signature_len(), signature.len()));
    }
    if !eddsa::is_public_key(variant, public) {
        return Err("The public key does not decode to a point.".to_string());
    }
    if variant == eddsa::Variant::Ed25519 && !context.is_empty() {
        return Err("Ed25519 has no context string. Ed25519ctx is a separate \
                    scheme and is not implemented here.".to_string());
    }
    if context.len() > 255 {
        return Err(format!("An Ed448 context is at most 255 bytes; this one is {}.",
                           context.len()));
    }
    Ok(eddsa::verify(variant, public, message, signature, context).is_ok())
}

// ---------------------------------------------------------------- XEdDSA ---

pub use crate::ec::xeddsa;

/// The XEdDSA forms: `signal`, libsignal's, which carries the Edwards
/// sign bit in the top bit of `S`, and `xeddsa`, the specification's,
/// which forces it to zero. See `ec::xeddsa`.
pub fn xeddsa_forms() -> Vec<&'static str> {
    vec![xeddsa::Form::Signal.name(), xeddsa::Form::Specification.name()]
}

/// Sign with an X25519 private key.
///
/// `random` is the 64 bytes `Z` mixed into the nonce, drawn from the
/// system source when `None`. Passing it makes the signature
/// reproducible, which is what a test against another implementation
/// needs and what a real signer should not do.
///
/// # Errors
/// An unknown form, a key that is not 32 bytes, `random` that is not
/// 64, or the system random source failing.
pub fn xeddsa_sign(form: &str, private: &[u8], message: &[u8], random: Option<&[u8]>)
                   -> Result<Vec<u8>, String> {
    let form = xeddsa::Form::by_name(form)?;
    let private = thirty_two("private key", private)?;
    let mut z = [0u8; 64];
    match random {
        Some(bytes) if bytes.len() == 64 => z.copy_from_slice(bytes),
        Some(bytes) => return Err(format!(
            "XEdDSA's random input is 64 bytes, not {}.", bytes.len())),
        None => random::fill(&mut z)?,
    }
    Ok(xeddsa::sign(form, &private, message, &z).to_vec())
}

/// Verify an XEdDSA signature against an X25519 public key.
///
/// `false` for a 64 byte signature that does not verify under this
/// form, whatever the reason; an error only for an unknown form or the
/// wrong lengths. Same split as [`eddsa_verify`].
///
/// # Errors
/// An unknown form, a key that is not 32 bytes or a signature that is
/// not 64.
pub fn xeddsa_verify(form: &str, public: &[u8], message: &[u8], signature: &[u8])
                     -> Result<bool, String> {
    let form = xeddsa::Form::by_name(form)?;
    let public = thirty_two("public key", public)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| format!(
        "An XEdDSA signature is 64 bytes, not {}.", signature.len()))?;
    Ok(xeddsa::verify(form, &public, message, &signature).is_ok())
}

// ------------------------------------------------------------------- NaCl ---

pub use crate::nacl;

/// The box constructions by name: `xsalsa20poly1305`, NaCl's, and
/// `xchacha20poly1305`, libsodium's, each with or without the box's
/// `curve25519` prefix. See `crate::nacl` for how the second differs
/// from the AEAD `xchacha20-poly1305`.
pub const BOX_CONSTRUCTIONS: &[&str] = nacl::CONSTRUCTIONS;

fn construction(name: &str) -> Result<nacl::Construction, String> {
    nacl::Construction::from_name(name)
}

/// A secretbox: the 16 byte tag followed by the ciphertext.
///
/// **The nonce must never repeat under one key.** At 24 bytes it can be
/// drawn at random per message.
pub fn secretbox_encrypt(key: &[u8], nonce: &[u8], message: &[u8], construction_name: &str)
                         -> Result<Vec<u8>, String> {
    nacl::secretbox_encrypt(construction(construction_name)?, key, nonce, message)
}

/// Open a secretbox. An error, and no plaintext, unless it authenticates.
pub fn secretbox_decrypt(key: &[u8], nonce: &[u8], boxed: &[u8], construction_name: &str)
                         -> Result<Vec<u8>, String> {
    nacl::secretbox_decrypt(construction(construction_name)?, key, nonce, boxed)
}

/// A secretbox as `(ciphertext, tag)`.
pub fn secretbox_encrypt_detached(key: &[u8], nonce: &[u8], message: &[u8],
                                  construction_name: &str)
                                  -> Result<(Vec<u8>, Vec<u8>), String> {
    let (ciphertext, tag) = nacl::secretbox_encrypt_detached(
        construction(construction_name)?, key, nonce, message)?;
    Ok((ciphertext, tag.to_vec()))
}

pub fn secretbox_decrypt_detached(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8],
                                  construction_name: &str) -> Result<Vec<u8>, String> {
    nacl::secretbox_decrypt_detached(construction(construction_name)?, key, nonce,
                                     ciphertext, tag)
}

/// The key a box between two key pairs is sealed under; a secretbox
/// under it is a box (NaCl's `crypto_box_beforenm` and `_afternm`).
/// Refuses a low-order peer key.
pub fn box_beforenm(peer_public: &[u8], private: &[u8], construction_name: &str)
                    -> Result<Vec<u8>, String> {
    Ok(nacl::box_beforenm(construction(construction_name)?, peer_public, private)?.to_vec())
}

/// A box from `private` to `peer_public`: the tag followed by the
/// ciphertext, as libsodium's `crypto_box_easy`.
pub fn box_encrypt(peer_public: &[u8], private: &[u8], nonce: &[u8], message: &[u8],
                   construction_name: &str) -> Result<Vec<u8>, String> {
    nacl::box_encrypt(construction(construction_name)?, peer_public, private, nonce, message)
}

/// Open a box from `peer_public` to `private`.
pub fn box_decrypt(peer_public: &[u8], private: &[u8], nonce: &[u8], boxed: &[u8],
                   construction_name: &str) -> Result<Vec<u8>, String> {
    nacl::box_decrypt(construction(construction_name)?, peer_public, private, nonce, boxed)
}

/// A fresh box key pair, `(private, public)` - an X25519 key pair.
pub fn box_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    x25519_generate()
}

/// A box key pair from a 32 byte seed, as libsodium's
/// `crypto_box_seed_keypair`.
pub fn box_seed_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (private, public) = nacl::box_seed_keypair(seed)?;
    Ok((private.to_vec(), public.to_vec()))
}

/// An anonymous box to `recipient_public` (libsodium's `crypto_box_seal`):
/// a fresh ephemeral key per message, `SEAL_BYTES` of overhead. Anybody
/// can make one, so it says nothing about the sender.
pub fn box_seal(recipient_public: &[u8], message: &[u8], construction_name: &str)
                -> Result<Vec<u8>, String> {
    nacl::box_seal(construction(construction_name)?, recipient_public, message)
}

pub fn box_seal_open(recipient_public: &[u8], recipient_private: &[u8], sealed: &[u8],
                     construction_name: &str) -> Result<Vec<u8>, String> {
    nacl::box_seal_open(construction(construction_name)?, recipient_public,
                        recipient_private, sealed)
}

/// A key-exchange key pair from a 32 byte seed, as libsodium's
/// `crypto_kx_seed_keypair` - a different key pair from
/// `box_seed_keypair`'s for the same seed.
pub fn kx_seed_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (private, public) = nacl::kx_seed_keypair(seed)?;
    Ok((private.to_vec(), public.to_vec()))
}

/// The client's `(receive, transmit)` session keys.
pub fn kx_client_session_keys(client_public: &[u8], client_private: &[u8],
                              server_public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (rx, tx) = nacl::kx_client_session_keys(client_public, client_private, server_public)?;
    Ok((rx.to_vec(), tx.to_vec()))
}

/// The server's `(receive, transmit)` session keys.
pub fn kx_server_session_keys(server_public: &[u8], server_private: &[u8],
                              client_public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (rx, tx) = nacl::kx_server_session_keys(server_public, server_private, client_public)?;
    Ok((rx.to_vec(), tx.to_vec()))
}

/// NaCl's `crypto_auth`: HMAC-SHA-512 truncated to 32 bytes.
pub fn nacl_auth(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    Ok(nacl::auth(key, message)?.to_vec())
}

/// Whether a `crypto_auth` tag is right, compared in constant time. An
/// error only for a key of the wrong length.
pub fn nacl_auth_verify(key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool, String> {
    nacl::auth(key, &[])?;
    Ok(nacl::auth_verify(key, message, tag).is_ok())
}

/// NaCl's `crypto_sign`: the Ed25519 signature followed by the message.
/// `private` is the 32 byte seed or libsodium's 64 byte secret key.
pub fn nacl_sign(private: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    nacl::sign(private, message)
}

/// NaCl's `crypto_sign_open`: the message, or an error.
pub fn nacl_sign_open(public: &[u8], signed: &[u8]) -> Result<Vec<u8>, String> {
    nacl::sign_open(public, signed)
}

/// The X25519 public key for an Ed25519 one (libsodium's
/// `crypto_sign_ed25519_pk_to_curve25519`). Refuses small-order points
/// and points outside the prime-order subgroup.
pub fn ed25519_public_to_x25519(public: &[u8]) -> Result<Vec<u8>, String> {
    Ok(eddsa::ed25519_public_to_x25519(public)?.to_vec())
}

/// The X25519 private key for an Ed25519 seed, clamped
/// (libsodium's `crypto_sign_ed25519_sk_to_curve25519`).
pub fn ed25519_private_to_x25519(private: &[u8]) -> Result<Vec<u8>, String> {
    Ok(eddsa::ed25519_private_to_x25519(private)?.to_vec())
}

/// HSalsa20 (`crypto_core_hsalsa20`): XSalsa20's subkey derivation.
pub fn hsalsa20(key: &[u8], input: &[u8]) -> Result<Vec<u8>, String> {
    let key: &[u8; 32] = key.try_into()
        .map_err(|_| format!("An HSalsa20 key is 32 bytes, not {}.", key.len()))?;
    let input: &[u8; 16] = input.try_into()
        .map_err(|_| format!("HSalsa20's input is 16 bytes, not {}.", input.len()))?;
    Ok(crate::stream_ciphers::salsa20::hsalsa20(key, input).to_vec())
}

// ---------------------------------------------- Diffie-Hellman (finite field) ---

use crate::publickey_ciphers::dh;
use crate::publickey_ciphers::elgamal;

/// A finite-field Diffie-Hellman group, addressed by bytes rather than by
/// `BigUint`, because that is what crosses a language boundary.
///
/// Exposed for its own sake as well as for TLS: a differential test against
/// another implementation needs to reach the arithmetic directly, and the
/// key exchange inside a handshake is not reachable from outside it.
pub struct DhGroup {
    pub(crate) inner: dh::DhGroup,
}

impl DhGroup {
    /// `p` and `g` as big-endian bytes.
    pub fn new(p: &[u8], g: &[u8]) -> Result<DhGroup, String> {
        Ok(DhGroup { inner: dh::DhGroup::from_bytes(p, g)? })
    }

    /// One of the built-in MODP groups: 1024 (RFC 2409 group 2), or 1536,
    /// 2048, 3072, 4096, 6144 or 8192 (RFC 3526).
    pub fn modp(bits: usize) -> Result<DhGroup, String> {
        let group = match bits {
            1024 => dh::MODP_1024,
            1536 => dh::MODP_1536,
            2048 => dh::MODP_2048,
            3072 => dh::MODP_3072,
            4096 => dh::MODP_4096,
            6144 => dh::MODP_6144,
            8192 => dh::MODP_8192,
            other => return Err(format!(
                "No built-in MODP group of {} bits; there are 1024, 1536, \
                 2048, 3072, 4096, 6144 and 8192. Pass p and g directly for \
                 anything else.", other)),
        };
        Ok(DhGroup { inner: dh::modp_group(group)? })
    }

    pub fn bits(&self) -> usize {
        self.inner.bits()
    }

    pub fn p(&self) -> Vec<u8> {
        self.inner.p().to_bytes_be()
    }

    pub fn g(&self) -> Vec<u8> {
        self.inner.g().to_bytes_be()
    }

    /// A fresh `(private, public)` pair, both big-endian and padded to the
    /// modulus width.
    pub fn generate_key_pair(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (private, public) = self.inner.generate_key_pair()?;
        Ok((self.inner.encode(&private)?, self.inner.encode(&public)?))
    }

    /// `g^x mod p` for a private exponent given as bytes.
    pub fn public_key(&self, private: &[u8]) -> Result<Vec<u8>, String> {
        let public = self.inner.public_key(&BigUint::from_bytes_be(private))?;
        self.inner.encode(&public)
    }

    /// The shared secret, padded to the modulus width.
    pub fn shared_secret(&self, private: &[u8], peer: &[u8]) -> Result<Vec<u8>, String> {
        self.inner.shared_secret(&BigUint::from_bytes_be(private),
                                 &BigUint::from_bytes_be(peer))
    }

    /// The shared secret as TLS 1.0-1.2 use it: leading zero bytes removed
    /// (RFC 5246 section 8.1.2). TLS 1.3 and RFC 7919 keep them, so this is
    /// a named function rather than a default.
    pub fn tls_premaster(&self, private: &[u8], peer: &[u8]) -> Result<Vec<u8>, String> {
        let shared = self.shared_secret(private, peer)?;
        Ok(dh::strip_leading_zeros(&shared).to_vec())
    }

    pub fn validate_peer(&self, peer: &[u8]) -> Result<(), String> {
        self.inner.validate_peer(&BigUint::from_bytes_be(peer))
    }

    /// Whether `p` is probably prime. Several full-width exponentiations,
    /// so it is a question you ask rather than something done for you.
    pub fn check_prime(&self, rounds: usize) -> Result<(), String> {
        self.inner.check_prime(rounds)
    }
}

// ------------------------------------------------------------- ElGamal ---

/// An ElGamal key pair, over the same groups `DhGroup` holds.
///
/// OpenPGP algorithm 16 - the `elg` half of the `dsa/elg` keypairs GnuPG
/// made by default for years. OpenSSL dropped ElGamal and
/// `python-cryptography` never had it, so this is the only way to read
/// those messages from either language.
pub struct ElGamalKey {
    inner: elgamal::ElGamalPrivateKey,
}

/// The public half, for encrypting to somebody else and verifying their
/// signatures.
pub struct ElGamalPublicKey {
    inner: elgamal::ElGamalPublicKey,
}

impl ElGamalKey {
    /// A fresh key in the given group.
    pub fn generate(group: &DhGroup) -> Result<ElGamalKey, String> {
        Ok(ElGamalKey {
            inner: elgamal::ElGamalPrivateKey::generate(group.inner.clone())?,
        })
    }

    /// A key from a private exponent, which is what a PGP secret key
    /// carries. `y` is recomputed rather than trusted.
    pub fn from_private(group: &DhGroup, private: &[u8])
                        -> Result<ElGamalKey, String> {
        Ok(ElGamalKey {
            inner: elgamal::ElGamalPrivateKey::from_private(
                group.inner.clone(), BigUint::from_bytes_be(private))?,
        })
    }

    pub fn private_bytes(&self) -> Result<Vec<u8>, String> {
        self.inner.private_bytes()
    }

    pub fn public_bytes(&self) -> Result<Vec<u8>, String> {
        self.inner.public().y().to_bytes_be_padded(self.inner.public().size())
    }

    pub fn public_key(&self) -> ElGamalPublicKey {
        ElGamalPublicKey { inner: self.inner.public().clone() }
    }

    /// The width of one ciphertext component. A whole ciphertext is two
    /// of these.
    pub fn size(&self) -> usize {
        self.inner.public().size()
    }

    /// OpenPGP's ElGamal decryption: PKCS#1 v1.5 inside the raw scheme.
    ///
    /// **Every failure returns the same message**, deliberately - see
    /// the note on `elgamal::decrypt_pkcs1v15`.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        elgamal::decrypt_pkcs1v15(&self.inner, ciphertext)
    }

    /// Sign a digest, returning `r || s`, each padded to the modulus
    /// width. Read `elgamal`'s module comment first: GnuPG withdrew
    /// ElGamal signing, for a reason that was about its choice of nonce.
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, String> {
        let (r, s) = self.inner.sign(digest)?;
        let size = self.size();
        let mut out = r.to_bytes_be_padded(size)?;
        out.extend_from_slice(&s.to_bytes_be_padded(size)?);
        Ok(out)
    }
}

impl ElGamalPublicKey {
    /// A public key from a group and `y`.
    pub fn new(group: &DhGroup, y: &[u8]) -> Result<ElGamalPublicKey, String> {
        Ok(ElGamalPublicKey {
            inner: elgamal::ElGamalPublicKey::new(
                group.inner.clone(), BigUint::from_bytes_be(y))?,
        })
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub fn y(&self) -> Result<Vec<u8>, String> {
        self.inner.y().to_bytes_be_padded(self.inner.size())
    }

    /// OpenPGP's ElGamal encryption, returning `c1 || c2`.
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        elgamal::encrypt_pkcs1v15(&self.inner, message)
    }

    /// Verify a signature given as `r || s`.
    pub fn verify(&self, digest: &[u8], signature: &[u8])
                  -> Result<bool, String> {
        let size = self.size();
        if signature.len() != 2 * size {
            return Ok(false);
        }
        self.inner.verify(digest,
                          &BigUint::from_bytes_be(&signature[..size]),
                          &BigUint::from_bytes_be(&signature[size..]))
    }
}

// ------------------------------------------------------------------ X.509 ---

use crate::x509;

/// A parsed certificate that owns its bytes.
///
/// The `x509::Certificate` type borrows the DER it was parsed from, which is
/// right for Rust and impossible for a Python object that outlives the
/// buffer it came from. This owns the DER and re-parses on access. Parsing
/// is microseconds and certificates are small, so the cost is not worth an
/// unsafe self-referential struct.
pub struct Certificate {
    der: Vec<u8>,
}

/// One field of a certificate, flattened for a foreign runtime.
pub struct CertificateInfo {
    pub version: u32,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub subject: Vec<(String, String)>,
    pub issuer: Vec<(String, String)>,
    pub subject_common_name: Option<String>,
    pub issuer_common_name: Option<String>,
    pub signature_algorithm: String,
    pub public_key_type: String,
    pub public_key_bits: usize,
    /// The key's parameter-set OID, where the algorithm has one that the
    /// type name does not already determine. `None` for RSA, EC and
    /// EdDSA; set for GOST.
    ///
    /// **The curve name is not enough for GOST, and that cost a
    /// handshake.** `1.2.643.2.2.35.1` (CryptoPro-A) and
    /// `1.2.643.2.2.36.0` (CryptoPro-XchA) are the *same* domain
    /// parameters under two OIDs, so both come out of `public_key_type`
    /// as `gost256-a` - and a peer that spelled its key XchA rejects a
    /// ClientKeyExchange whose ephemeral key says A, with a fatal
    /// `decode_error` and nothing to read. Two of CryptoPro's three
    /// public test endpoints are on XchA. Reporting only the curve made
    /// that invisible from Python: the field that decides whether a
    /// GOST key exchange is accepted was not reported at all.
    ///
    /// EC is left `None` on purpose: a named curve there maps one to one
    /// onto its OID, so the name carries everything the OID does.
    pub public_key_parameter_set: Option<String>,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    /// `("DNS", "example.test")`, `("IP Address", "192.0.2.1")` and so on,
    /// which is the shape Python's `ssl.getpeercert()` uses.
    pub subject_alt_names: Vec<(String, String)>,
    pub key_usage: Vec<&'static str>,
    pub extended_key_usage: Vec<String>,
    pub unrecognised_critical: Vec<String>,
}

impl Certificate {
    pub fn parse(der: &[u8]) -> Result<Certificate, String> {
        // Parse once here so a bad certificate fails at construction rather
        // than at the first field access.
        x509::Certificate::parse(der)?;
        Ok(Certificate { der: der.to_vec() })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    fn borrowed(&self) -> Result<x509::Certificate<'_>, String> {
        x509::Certificate::parse(&self.der)
    }

    pub fn info(&self) -> Result<CertificateInfo, String> {
        let certificate = self.borrowed()?;

        let name_pairs = |name: &x509::Name<'_>| -> Vec<(String, String)> {
            name.attributes.iter()
                .map(|a| (a.label(),
                          a.text().unwrap_or_else(|_| "<unprintable>".to_string())))
                .collect()
        };

        let subject_alt_names = certificate.extensions.subject_alt_names.iter()
            .filter_map(|entry| match entry {
                x509::GeneralName::Dns(text) => Some(("DNS".to_string(), text.to_string())),
                x509::GeneralName::Email(text) =>
                    Some(("email".to_string(), text.to_string())),
                x509::GeneralName::Uri(text) => Some(("URI".to_string(), text.to_string())),
                x509::GeneralName::IpAddress(bytes) =>
                    Some(("IP Address".to_string(), format_ip(bytes))),
                _ => None,
            })
            .collect();

        let mut key_usage = Vec::new();
        if let Some(usage) = certificate.extensions.key_usage {
            for (flag, name) in [
                (usage.digital_signature, "digitalSignature"),
                (usage.non_repudiation, "nonRepudiation"),
                (usage.key_encipherment, "keyEncipherment"),
                (usage.data_encipherment, "dataEncipherment"),
                (usage.key_agreement, "keyAgreement"),
                (usage.key_cert_sign, "keyCertSign"),
                (usage.crl_sign, "cRLSign"),
                (usage.encipher_only, "encipherOnly"),
                (usage.decipher_only, "decipherOnly"),
            ] {
                if flag {
                    key_usage.push(name);
                }
            }
        }

        let (public_key_type, public_key_bits) = match &certificate.public_key {
            x509::PublicKey::Rsa { n, .. } => ("RSA".to_string(), n.bit_len()),
            x509::PublicKey::Ec { curve, .. } => (format!("EC {}", curve), 0),
            // The bit count is the curve's, which the name already
            // carries - reported as zero for the same reason as EC,
            // rather than inventing a number the caller would compare
            // against an RSA one.
            //
            // **Which generation, not just "GOST".** This said 2012 for
            // both, so a 2001 certificate was described as a 2012 one
            // through the Python surface - and which generation a box
            // has is exactly what decides whether 0x0081 or 0xC102 is
            // the suite to offer it. `main.rs` was already careful
            // here; this was not, which is what a second copy of a rule
            // costs.
            x509::PublicKey::Gost { curve, legacy: true, .. } =>
                (format!("GOST R 34.10-2001 {}", curve), 0),
            x509::PublicKey::Gost { curve, .. } =>
                (format!("GOST R 34.10-2012 {}", curve), 0),
            x509::PublicKey::Eddsa { curve, .. } => (format!("EdDSA {}", curve), 0),
            x509::PublicKey::MlDsa { parameter_set, .. } => (parameter_set.to_string(), 0),
            x509::PublicKey::Dsa { parameters, .. } => ("DSA".to_string(),
                parameters.as_ref().map_or(0, |(p, _, _)| p.bit_len())),
            x509::PublicKey::UnsupportedCurve { oid, family } =>
                (format!("{} (unsupported parameter set {})", family, oid), 0),
            x509::PublicKey::Unsupported { .. } => ("unsupported".to_string(), 0),
        };

        // Only where the type name does not already determine it - see
        // the field's own comment for why GOST is the case that matters.
        let public_key_parameter_set = match &certificate.public_key {
            x509::PublicKey::Gost { param_set, .. } => Some(param_set.to_string()),
            _ => None,
        };

        Ok(CertificateInfo {
            version: certificate.version,
            serial: certificate.serial_hex(),
            not_before: certificate.not_before,
            not_after: certificate.not_after,
            subject: name_pairs(&certificate.subject),
            issuer: name_pairs(&certificate.issuer),
            subject_common_name: certificate.subject.common_name(),
            issuer_common_name: certificate.issuer.common_name(),
            signature_algorithm: certificate.signature_algorithm.describe(),
            public_key_type,
            public_key_bits,
            public_key_parameter_set,
            is_ca: certificate.extensions.is_ca(),
            path_len: certificate.extensions.path_len(),
            subject_alt_names,
            key_usage,
            extended_key_usage: certificate.extensions.extended_key_usage
                .as_ref()
                .map(|list| list.iter().map(|o| o.to_string()).collect())
                .unwrap_or_default(),
            unrecognised_critical: certificate.extensions.unrecognised_critical
                .iter().map(|o| o.to_string()).collect(),
        })
    }

    pub fn subject_string(&self) -> Result<String, String> {
        Ok(self.borrowed()?.subject.to_string())
    }

    pub fn issuer_string(&self) -> Result<String, String> {
        Ok(self.borrowed()?.issuer.to_string())
    }

    /// Does this certificate cover `hostname`? RFC 6125 rules - see
    /// `x509::verify::matches_hostname`.
    pub fn matches_hostname(&self, hostname: &str) -> Result<bool, String> {
        Ok(x509::verify::matches_hostname(&self.borrowed()?, hostname))
    }

    /// The TBS bytes, which is what a signature covers.
    pub fn tbs(&self) -> Result<Vec<u8>, String> {
        Ok(self.borrowed()?.tbs.to_vec())
    }
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
        16 => bytes.chunks(2)
            .map(|pair| format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])))
            .collect::<Vec<_>>().join(":"),
        _ => bytes.iter().map(|b| format!("{:02x}", b)).collect(),
    }
}

/// What a chain must satisfy. Mirrors `x509::verify::Policy` in bytes and
/// strings, for a caller that does not have the Rust types.
pub struct VerifyOptions {
    pub now: i64,
    pub allow_sha1: bool,
    pub allow_md5: bool,
    /// Accept a certificate outside its validity window. Everything else
    /// is still checked.
    pub allow_expired: bool,
    pub min_rsa_bits: usize,
    pub max_chain_length: usize,
    /// "server", "client" or "any".
    pub purpose: String,
    /// If set, the leaf must also cover this name.
    pub hostname: Option<String>,
    /// DER certificate revocation lists to check the chain against.
    ///
    /// Supplied rather than fetched: nothing in this library opens a
    /// socket. `crl_distribution_points` says where a certificate
    /// claims its list lives.
    pub crls: Vec<Vec<u8>>,
    /// DER OCSP responses, stapled or fetched. Each is matched to a
    /// certificate by its CertID, so they need no labelling.
    pub ocsp: Vec<Vec<u8>>,
    /// The nonce sent in the OCSP request, if one was sent.
    pub ocsp_nonce: Option<Vec<u8>>,
    /// Refuse a chain whose revocation status could not be
    /// established. Off by default, which is soft fail - with no
    /// evidence supplied and this on, every chain fails.
    pub require_revocation: bool,
}

impl Default for VerifyOptions {
    fn default() -> VerifyOptions {
        VerifyOptions {
            now: 0,
            allow_sha1: false,
            allow_md5: false,
            allow_expired: false,
            min_rsa_bits: 2048,
            max_chain_length: 10,
            purpose: "server".to_string(),
            hostname: None,
            crls: Vec::new(),
            ocsp: Vec::new(),
            ocsp_nonce: None,
            require_revocation: false,
        }
    }
}

/// The DER of `data`'s first PEM block labelled `label`, or `data`
/// itself when it is not PEM.
fn der_of(data: &[u8], labels: &[&str]) -> Result<Vec<u8>, String> {
    if let Ok(text) = core::str::from_utf8(data) {
        if text.contains("-----BEGIN") {
            return crate::pem::parse(text)?.into_iter()
                .find(|b| labels.contains(&b.label.as_str()))
                .map(|b| b.contents)
                .ok_or_else(|| format!("No {} block in the PEM.", labels.join(" or ")));
        }
    }
    Ok(data.to_vec())
}

/// Encrypt a PKCS#8 `PrivateKeyInfo` (DER, or PEM labelled `PRIVATE
/// KEY`) into an `EncryptedPrivateKeyInfo`, DER.
///
/// `scheme` is a PBES2 cipher (`aes-256-cbc`, ...) or a `pbe-...`
/// scheme; `encrypted_key::scheme_names` lists them. `prf` is PBES2's
/// hash, SHA-256 when absent. Absent, `iterations` is
/// `pbkdf2_recommended_iterations` for PBES2 and OpenSSL's 2048 for the
/// older schemes, the salt is 16 random bytes for PBES2 and 8 for the
/// others (PBES1 requires 8), and PBES2's IV is random.
///
/// A SEC1 or PKCS#1 key is refused rather than wrapped: what is inside
/// an `EncryptedPrivateKeyInfo` is a `PrivateKeyInfo`.
pub fn encrypt_private_key(key: &[u8], password: &[u8], scheme: &str, prf: Option<&str>,
                           iterations: Option<u32>, salt: Option<&[u8]>, iv: Option<&[u8]>)
                           -> Result<Vec<u8>, String> {
    let der = der_of(key, &["PRIVATE KEY"])?;
    crate::x509::private_key::pkcs8(&der).map_err(|reason| {
        format!("Only a PKCS#8 PrivateKeyInfo is encrypted this way, and this is not one \
                 ({reason}).")
    })?;
    let pbes2 = !scheme.starts_with("pbe-");
    let iterations = iterations.unwrap_or_else(|| {
        if pbes2 { pbkdf2_recommended_iterations(prf.unwrap_or("sha256")) } else { 2048 }
    });
    let salt = match salt {
        Some(salt) => salt.to_vec(),
        None => random_bytes(if pbes2 { 16 } else { 8 })?,
    };
    let iv = match iv {
        Some(iv) => iv.to_vec(),
        None if pbes2 => {
            let block = if scheme.starts_with("aes") { 16 } else { 8 };
            random_bytes(block)?
        }
        None => Vec::new(),
    };
    let prf = if pbes2 { Some(prf.unwrap_or("sha256")) } else { prf };
    crate::x509::encrypted_key::encrypt(&der, password, scheme, prf, iterations, &salt, &iv)
}

/// How an `EncryptedPrivateKeyInfo` (DER, or PEM labelled `ENCRYPTED
/// PRIVATE KEY`) was encrypted, read without the password.
pub fn private_key_encryption(data: &[u8])
                              -> Result<crate::x509::encrypted_key::Parameters, String> {
    crate::x509::encrypted_key::parameters(&der_of(data, &["ENCRYPTED PRIVATE KEY"])?)
}

/// Read a private key from PEM text or DER bytes.
///
/// PEM or DER, PKCS#8 or SEC1 or PKCS#1, and the **bytes decide rather
/// than the label** - see `x509::private_key`.
pub fn parse_private_key(data: &[u8]) -> Result<PrivateKeyParts, String> {
    parse_private_key_with_password(data, None)
}

/// The same, with a passphrase for an encrypted key. `None` refuses an
/// encrypted key by name rather than failing to parse it.
pub fn parse_private_key_with_password(data: &[u8], password: Option<&[u8]>)
                                       -> Result<PrivateKeyParts, String> {
    match crate::x509::private_key::parse_with_password(data, password)? {
        crate::x509::private_key::PrivateKey::Ec { curve, private } =>
            Ok(PrivateKeyParts::Ec { curve: curve.to_string(), private }),
        crate::x509::private_key::PrivateKey::Rsa { p, q, e } =>
            Ok(PrivateKeyParts::Rsa {
                p: p.to_bytes_be(), q: q.to_bytes_be(), e: e.to_bytes_be(),
            }),
        crate::x509::private_key::PrivateKey::Eddsa { curve, private } =>
            Ok(PrivateKeyParts::Eddsa { curve: curve.to_string(), private }),
        crate::x509::private_key::PrivateKey::Xdh { curve, private } =>
            Ok(PrivateKeyParts::Xdh { curve: curve.to_string(), private }),
        crate::x509::private_key::PrivateKey::MlDsa { parameter_set, seed, expanded } =>
            Ok(PrivateKeyParts::MlDsa { parameter_set: parameter_set.to_string(), seed,
                                        expanded }),
        crate::x509::private_key::PrivateKey::Dsa { p, q, g, x } =>
            Ok(PrivateKeyParts::Dsa { p: p.to_bytes_be(), q: q.to_bytes_be(),
                                      g: g.to_bytes_be(), x: x.to_bytes_be() }),
    }
}

/// A private key as bytes, for crossing into Python.
pub enum PrivateKeyParts {
    /// The curve by name, and the scalar big endian, padded to the
    /// curve's width.
    Ec { curve: String, private: Vec<u8> },
    /// The two primes and the public exponent, big endian - what
    /// `RsaKey::from_primes` takes.
    Rsa { p: Vec<u8>, q: Vec<u8>, e: Vec<u8> },
    /// The variant by name, and the raw **seed** - not a scalar. See
    /// `x509::private_key::PrivateKey::Eddsa`.
    Eddsa { curve: String, private: Vec<u8> },
    /// `x25519` or `x448`, and the private bytes as RFC 7748 takes them:
    /// what `x25519_exchange` and `x448_exchange` want.
    Xdh { curve: String, private: Vec<u8> },
    /// FIPS 204's parameter set name, the seed if the file had one, and
    /// the expanded private key, already checked against each other.
    MlDsa { parameter_set: String, seed: Option<Vec<u8>>, expanded: Vec<u8> },
    /// A DSA group and `x`, big endian - what `DsaKey::from_numbers` takes.
    Dsa { p: Vec<u8>, q: Vec<u8>, g: Vec<u8>, x: Vec<u8> },
}

/// Verify a chain, leaf first, against a set of trusted roots.
///
/// Returns `Ok(())` only if every check passed. The error says which one
/// failed, because "certificate verify failed" with no reason is the single
/// most-cursed error message in the whole ecosystem.
///
/// The two lists are generic over anything that holds bytes so that a
/// caller holding `Vec<Vec<u8>>`, `&[&[u8]]` or - the reason it is
/// written this way - the Python bindings' borrowed byte objects can all
/// pass them straight in. A chain is a few kilobytes and copying it here
/// would be a copy made only to satisfy a signature.
pub fn verify_chain(chain: &[impl AsRef<[u8]>], roots: &[impl AsRef<[u8]>],
                    options: &VerifyOptions) -> Result<(), String> {
    let parsed: Vec<x509::Certificate<'_>> = chain.iter()
        .map(|der| x509::Certificate::parse(der.as_ref()))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("A certificate in the chain did not parse: {}", e))?;
    let parsed_roots: Vec<x509::Certificate<'_>> = roots.iter()
        .map(|der| x509::Certificate::parse(der.as_ref()))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("A trusted root did not parse: {}", e))?;

    let purpose = match options.purpose.to_ascii_lowercase().as_str() {
        "server" | "serverauth" => x509::verify::Purpose::ServerAuth,
        "client" | "clientauth" => x509::verify::Purpose::ClientAuth,
        "any" => x509::verify::Purpose::Any,
        other => return Err(format!("Unknown purpose {:?}. Use server, client or any.",
                                    other)),
    };

    let policy = x509::verify::Policy {
        now: options.now,
        allow_sha1: options.allow_sha1,
        allow_md5: options.allow_md5,
        allow_expired: options.allow_expired,
        min_rsa_bits: options.min_rsa_bits,
        max_chain_length: options.max_chain_length,
        require_revocation: options.require_revocation,
    };

    let crls: Vec<x509::crl::CertificateList<'_>> = options.crls.iter()
        .map(|der| x509::crl::CertificateList::parse(der))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("A CRL did not parse: {}", e))?;

    // The hostname is checked first: it is the cheapest check and the one
    // most likely to fail, and there is no point verifying signatures on a
    // chain for somebody else's name.
    if let Some(hostname) = &options.hostname {
        let leaf = parsed.first()
            .ok_or_else(|| "An empty chain verifies nothing.".to_string())?;
        if !x509::verify::matches_hostname(leaf, hostname) {
            return Err(format!("Certificate does not cover {:?}. It covers: {}.",
                               hostname, describe_names(leaf)));
        }
    }

    let responses: Vec<&[u8]> = options.ocsp.iter()
        .map(|der| der.as_slice()).collect();
    let revocation = x509::verify::Revocation {
        crls: &crls,
        ocsp: &responses,
        ocsp_nonce: options.ocsp_nonce.as_deref(),
    };
    x509::verify::verify_chain_with_revocation(&parsed, &parsed_roots, &policy,
                                               purpose, &revocation)
}

/// Where a certificate says its OCSP responder lives.
///
/// Reported, never fetched. Only the `id-ad-ocsp` entries of the
/// authorityInfoAccess extension: the other access method in it points
/// at the issuer's *certificate*, and sending an OCSP request there
/// would reach a file server.
pub fn ocsp_responders(der: &[u8]) -> Result<Vec<String>, String> {
    let certificate = x509::Certificate::parse(der)?;
    Ok(x509::ocsp::responder_urls(&certificate))
}

/// An OCSP request for one certificate, as DER to POST.
///
/// `nonce` is the caller's own random bytes and must be handed back to
/// `ocsp_status`. It is the only defence against a replayed response:
/// without one, a captured "good" stays valid until its nextUpdate.
pub fn ocsp_request(certificate_der: &[u8], issuer_der: &[u8], hash: &str,
                    nonce: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let certificate = x509::Certificate::parse(certificate_der)?;
    let issuer = x509::Certificate::parse(issuer_der)?;
    x509::ocsp::build_request(&certificate, &issuer, hash, nonce)
}

/// What an OCSP response says about one certificate.
///
/// Returns `("revoked", reason)`, `("not_revoked", "")` or
/// `("unknown", why)` - the same three values a CRL check gives,
/// because it is the same question.
pub fn ocsp_status(certificate_der: &[u8], issuer_der: &[u8],
                   response_der: &[u8], nonce: Option<&[u8]>, now: i64)
                   -> Result<(String, String), String> {
    let certificate = x509::Certificate::parse(certificate_der)?;
    let issuer = x509::Certificate::parse(issuer_der)?;
    let policy = x509::verify::Policy::at(now);
    Ok(match x509::ocsp::check(&certificate, &issuer, response_der, nonce,
                               &policy, now) {
        x509::crl::Status::Revoked { at, reason } => (
            "revoked".to_string(),
            match reason {
                Some(reason) => format!("{} at {}", reason.name(), at),
                None => format!("at {}", at),
            }),
        x509::crl::Status::NotRevoked =>
            ("not_revoked".to_string(), String::new()),
        x509::crl::Status::Unknown(why) => ("unknown".to_string(), why),
    })
}

/// Where a certificate says its CRL can be fetched.
///
/// Reported, never fetched. A caller with a socket can go and get it and
/// hand the bytes back through `VerifyOptions::crls`.
pub fn crl_distribution_points(der: &[u8]) -> Result<Vec<String>, String> {
    let certificate = x509::Certificate::parse(der)?;
    Ok(x509::crl::distribution_points(&certificate))
}

/// What a CRL says about one certificate, without verifying a chain.
///
/// Returns `("revoked", reason)`, `("not_revoked", "")` or
/// `("unknown", why)`. Three values rather than a boolean, because
/// "nothing could be established" is not "fine" and a boolean cannot
/// say so.
pub fn crl_status(certificate_der: &[u8], issuer_der: &[u8],
                  crl_ders: &[impl AsRef<[u8]>], now: i64)
                  -> Result<(String, String), String> {
    let certificate = x509::Certificate::parse(certificate_der)?;
    let issuer = x509::Certificate::parse(issuer_der)?;
    let crls: Vec<x509::crl::CertificateList<'_>> = crl_ders.iter()
        .map(|der| x509::crl::CertificateList::parse(der.as_ref()))
        .collect::<Result<_, _>>()?;
    let policy = x509::verify::Policy::at(now);
    Ok(match x509::crl::check(&certificate, &issuer, &crls, &policy, now) {
        x509::crl::Status::Revoked { at, reason } => (
            "revoked".to_string(),
            match reason {
                Some(reason) => format!("{} at {}", reason.name(), at),
                None => format!("at {}", at),
            }),
        x509::crl::Status::NotRevoked =>
            ("not_revoked".to_string(), String::new()),
        x509::crl::Status::Unknown(why) => ("unknown".to_string(), why),
    })
}

fn describe_names(certificate: &x509::Certificate<'_>) -> String {
    let names = certificate.extensions.dns_names();
    if !names.is_empty() {
        return names.join(", ");
    }
    match certificate.subject.common_name() {
        Some(name) => format!("{} (from the common name, with no SAN)", name),
        None => "nothing".to_string(),
    }
}

// ------------------------------------------------------------ trust store ---

pub use crate::trust::TrustStore;

/// The certificates PEM text holds, as DER.
pub fn pem_certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
    crate::pem::certificates(text)
}

/// Wrap DER as a PEM block.
pub fn pem_wrap(label: &str, der: &[u8]) -> String {
    crate::pem::wrap(label, der)
}

// -------------------------------------------------------------------- TLS ---

use crate::tls::client as tls_client;

/// Options for a TLS client connection, as strings and bytes.
pub struct TlsOptions {
    pub now: i64,
    /// "modern", "legacy", or a comma separated list of suite names.
    pub ciphers: String,
    pub verify: bool,
    pub min_version: String,
    pub max_version: String,
    pub allow_sha1: bool,
    pub allow_md5: bool,
    /// Accept a certificate outside its validity window. The chain, the
    /// signatures and the name are all still checked.
    pub allow_expired: bool,
    /// Check that the certificate covers the hostname. On by default, and
    /// separate from `verify` - "a certificate I trust, for a name I am
    /// not checking" is a much narrower request than "check nothing".
    pub verify_hostname: bool,
    pub min_rsa_bits: usize,
    /// The smallest finite-field Diffie-Hellman group to accept, in bits.
    /// A DHE server picks the group on its own, so this is the client's
    /// only say in it. Logjam is the reason the default is 2048.
    pub min_dh_bits: usize,
    /// Test the server's Diffie-Hellman modulus for primality. Off by
    /// default because it costs more than the key exchange itself; on, it
    /// is what catches a deliberately composite modulus.
    pub check_dh_prime: bool,
    /// TLS 1.3 session tickets to offer, as the opaque blobs
    /// `TlsClient::tickets` hands out.
    ///
    /// **These are key material.** Each one is enough to resume the
    /// connection it came from. Offer each one once: reusing a ticket
    /// lets a passive observer link the two connections, which is what
    /// its obfuscated age exists to prevent.
    pub tickets: Vec<Vec<u8>>,
    /// Offer encrypt-then-MAC (RFC 7366). On by default; it is the proper
    /// fix for the CBC padding oracle rather than a mitigation of it.
    ///
    /// Turning it off is a real need, not just a test hook: some old
    /// equipment mishandles the extension, and a caller that has to reach
    /// one of those has to be able to stop offering it. It also makes the
    /// MAC-then-encrypt path reachable from a test without needing the
    /// peer's cooperation, which matters because that is the path Lucky 13
    /// applies to and the one the legacy suites all use.
    pub request_encrypt_then_mac: bool,
    /// The certificate and key to send if the server asks for one
    /// at TLS 1.2 or 1.3.
    ///
    /// `None` - the default - means a CertificateRequest is answered
    /// with an *empty* Certificate rather than with silence, which is
    /// what RFC 8446 4.4.2.1 asks for: the server then decides whether
    /// that ends the connection.
    pub client_certificate: Option<ClientIdentity>,
    /// Bytes to send as TLS 1.3 early data (0-RTT). See
    /// `tls::client::ClientConfig::early_data` - they are not forward
    /// secret, they are replayable, and they are not resent for you.
    pub early_data: Vec<u8>,
    /// Application protocols to offer (RFC 7301), in preference order.
    /// Empty sends no extension.
    pub alpn: Vec<String>,
    /// Ask the server to staple an OCSP response (RFC 6066 §8). On by
    /// default. A stapled response that says **revoked** fails the
    /// handshake; one that settles nothing fails only when the policy
    /// requires revocation to be checked.
    pub request_stapled_ocsp: bool,
    /// Refuse a connection whose revocation status a staple did not
    /// settle - none sent, one that does not parse, one about another
    /// certificate. Off by default, because most servers staple nothing.
    ///
    /// **Not the same as requiring a CRL**, which nothing here fetches
    /// and which would therefore refuse every chain.
    pub require_stapled_ocsp: bool,
}

/// A client certificate and the key that goes with it, in the shape the
/// bindings can carry: bytes, and a named curve.
///
/// Separate from `tls::client::ClientIdentity`, which holds parsed keys,
/// because everything that crosses into Python is bytes - and because a
/// key that will not parse should be an error where it was supplied,
/// not at the handshake.
pub struct ClientIdentity {
    /// Leaf first, DER.
    pub chain: Vec<Vec<u8>>,
    pub key: ClientKeyMaterial,
}

/// The private half of a client identity.
pub enum ClientKeyMaterial {
    /// The scalar big endian, and the curve by name. Named rather than
    /// inferred from the certificate for the same reason the server's
    /// is: a key that does not match its certificate should be an error
    /// here, not a signature nobody can verify.
    Ec { curve: String, private: Vec<u8> },
    /// The two primes and the public exponent, big endian - what
    /// `RsaKey::numbers` hands out under "p", "q" and "e".
    Rsa { p: Vec<u8>, q: Vec<u8>, e: Vec<u8> },
    /// An ML-DSA key, for TLS 1.3 only. Shared rather than copied.
    MlDsa(std::sync::Arc<MlDsaKey>),
    /// An Ed25519 or Ed448 key by curve name, and its RFC 8032 seed.
    Eddsa { name: String, seed: Vec<u8> },
}

impl ClientIdentity {
    fn build(&self) -> Result<tls_client::ClientIdentity, String> {
        let key = match &self.key {
            ClientKeyMaterial::Ec { curve, private } => {
                let handle = crate::ec::curves::by_name(curve)?;
                let scalar = BigUint::from_bytes_be(private);
                if scalar.is_zero() || scalar >= handle.n {
                    return Err("Private scalar is not in [1, n).".to_string());
                }
                tls_client::ClientKey::Ec { curve: handle.name, private: scalar }
            }
            ClientKeyMaterial::Rsa { p, q, e } => {
                tls_client::ClientKey::Rsa(Box::new(
                    rsa::RsaPrivateKey::from_primes(BigUint::from_bytes_be(p),
                                                    BigUint::from_bytes_be(q),
                                                    BigUint::from_bytes_be(e))?))
            }
            ClientKeyMaterial::MlDsa(key) => tls_client::ClientKey::MlDsa(key.clone()),
            ClientKeyMaterial::Eddsa { name, seed } => {
                let variant = eddsa_variant(name)?;
                if seed.len() != variant.key_len() {
                    return Err(format!("An {} private key is {} bytes; got {}.",
                                       name, variant.key_len(), seed.len()));
                }
                tls_client::ClientKey::Eddsa { name: eddsa_name(name)?, seed: seed.clone() }
            }
        };
        if self.chain.is_empty() {
            return Err("A client identity needs a certificate.".to_string());
        }
        Ok(tls_client::ClientIdentity { chain: self.chain.clone(), key })
    }
}

impl Default for TlsOptions {
    fn default() -> TlsOptions {
        TlsOptions {
            now: 0,
            ciphers: "modern".to_string(),
            verify: true,
            min_version: "TLSv1.2".to_string(),
            max_version: "TLSv1.3".to_string(),
            allow_sha1: false,
            allow_md5: false,
            allow_expired: false,
            verify_hostname: true,
            min_rsa_bits: 2048,
            min_dh_bits: 2048,
            check_dh_prime: false,
            request_encrypt_then_mac: true,
            client_certificate: None,
            early_data: Vec::new(),
            alpn: Vec::new(),
            request_stapled_ocsp: true,
            require_stapled_ocsp: false,
            tickets: Vec::new(),
        }
    }
}

fn parse_version(name: &str) -> Result<crate::tls::Version, String> {
    match name.to_ascii_uppercase().replace(['_', ' ', '.'], "").as_str() {
        "SSLV3" | "SSL3" => Ok(crate::tls::Version::SSL30),
        "TLSV1" | "TLSV10" | "TLS1" => Ok(crate::tls::Version::TLS10),
        "TLSV11" => Ok(crate::tls::Version::TLS11),
        "TLSV12" => Ok(crate::tls::Version::TLS12),
        "TLSV13" => Ok(crate::tls::Version::TLS13),
        other => Err(format!("Unknown TLS version {:?}.", other)),
    }
}

/// A TLS client connection, sans-I/O: bytes in, bytes out, no socket.
/// The suites a selection offers, in the order they go into a hello.
///
/// Exposed because a caller cannot otherwise find out what asking for
/// `"modern"` or `"legacy"` actually got them, and "what did we offer"
/// is the first question when a handshake fails with no suite in
/// common. It is also what `scripts/check_live.py` uses to report the
/// suites nothing in its matrix can reach - a list that must be derived
/// rather than typed, or it goes stale the moment a suite is added.
/// The TLS signature schemes this client offers, in preference order.
pub fn tls_signature_schemes() -> Vec<String> {
    crate::tls::handshake13::scheme::OFFERED.iter()
        .map(|s| crate::tls::handshake13::scheme::name(*s))
        .collect()
}

pub fn tls_suite_names(selection: &str) -> Result<Vec<String>, String> {
    Ok(tls_selection(selection)?.names())
}

/// Every suite name in the registry, implemented or not.
///
/// Wider than any selection on purpose: the registry is the catalogue of
/// what TLS has, not of what we have, and telling the two apart is what
/// `tls_suite_names` above is for. Reaches Python as the list
/// `tls_suites_available`, beside `curves_available` and the rest.
pub fn tls_suites_known() -> Vec<String> {
    crate::tls::suites::ALL.iter().map(|s| s.name.to_string()).collect()
}

fn tls_selection(name: &str) -> Result<crate::tls::suites::Selection, String> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "modern" | "default" => crate::tls::suites::Selection::modern(),
        "legacy" => crate::tls::suites::Selection::legacy(),
        // "all" used to be an alias for "legacy", which meant a caller
        // asking for everything silently got a set with the NULL and
        // anonymous suites removed and no indication of it. It now
        // means what it says: every implemented suite, insecure ones
        // included. That is a wider thing to ask for and it is only
        // reachable by asking for it.
        "all" | "everything" => crate::tls::suites::Selection::all(),
        list => {
            let names: Vec<&str> = list.split(',').map(|n| n.trim()).collect();
            crate::tls::suites::Selection::named(&names)?
        }
    })
}

pub struct TlsClient {
    inner: tls_client::ClientConnection,
}

impl TlsClient {
    pub fn new(hostname: &str, roots: &TrustStore, options: &TlsOptions)
               -> Result<TlsClient, String> {
        let mut config = tls_client::ClientConfig::new(roots.clone(), options.now);

        // One function, so `tls_suite_names` above reports exactly what
        // a client with the same string would offer. Two copies of this
        // match would drift, and the drift would be invisible: the
        // report would be right about a selection nobody used.
        config.suites = tls_selection(&options.ciphers)?;
        config.verify_certificate = options.verify;
        config.min_version = parse_version(&options.min_version)?;
        config.max_version = parse_version(&options.max_version)?;
        config.policy.allow_sha1 = options.allow_sha1;
        config.policy.allow_md5 = options.allow_md5;
        config.policy.min_rsa_bits = options.min_rsa_bits;
        config.policy.allow_expired = options.allow_expired;
        config.verify_hostname = options.verify_hostname;
        config.min_dh_bits = options.min_dh_bits;
        config.check_dh_prime = options.check_dh_prime;
        config.request_encrypt_then_mac = options.request_encrypt_then_mac;
        config.client_certificate = match &options.client_certificate {
            Some(identity) => Some(identity.build()?),
            None => None,
        };
        config.early_data = options.early_data.clone();
        config.alpn = options.alpn.clone();
        config.request_stapled_ocsp = options.request_stapled_ocsp;
        config.require_stapled_ocsp = options.require_stapled_ocsp;

        // A stored ticket that will not decode is an error rather than
        // a silent omission: it means the caller's storage is wrong,
        // and quietly not resuming would look like a server that
        // declined.
        config.tickets = options.tickets.iter()
            .map(|bytes| crate::tls::resumption::Ticket::decode(bytes))
            .collect::<Result<_, _>>()?;

        Ok(TlsClient { inner: tls_client::ClientConnection::new(config, hostname)? })
    }

    /// Channel binding material, RFC 5929 (`tls-unique`) and RFC 9266
    /// (`tls-exporter`).
    ///
    /// What a SASL mechanism mixes into its exchange so an
    /// authentication cannot be relayed onto another TLS connection.
    /// `None` when the negotiated version does not define the binding
    /// asked for, or when the handshake has not produced it yet - never
    /// a plausible substitute, because a binding that authenticates the
    /// wrong connection fails silently by construction.
    ///
    /// # Errors
    /// A binding type this library does not implement.
    pub fn channel_binding(&self, kind: &str) -> Result<Option<Vec<u8>>, String> {
        self.inner.channel_binding(kind)
    }

    /// Take the session tickets this connection was given, as opaque
    /// blobs to store and hand back in `TlsOptions::tickets`.
    ///
    /// Taken rather than read, because a ticket is offered **once** -
    /// reading them without removing them invites offering the same one
    /// twice, which is exactly the linkability their obfuscated age
    /// exists to prevent.
    ///
    /// Often empty right after the handshake: a TLS 1.3 server sends
    /// tickets under the application keys, so they arrive with or after
    /// the first data. Look again after a read.
    pub fn take_tickets(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.inner.take_tickets().iter().map(|ticket| ticket.encode()).collect()
    }

    /// Whether this handshake resumed a previous session.
    ///
    /// A resumed TLS 1.3 connection has **no certificate** - the PSK
    /// authenticates the server - so an empty `peer_certificates` on
    /// one is normal rather than a failure.
    pub fn resumed(&self) -> bool {
        self.inner.resumed()
    }

    /// Whether the server accepted the early data that was offered.
    ///
    /// False after offering is the ordinary rejection and not an error -
    /// but those bytes did not arrive, and they are **not resent for
    /// you**. See `tls::client::ClientConfig::early_data`.
    pub fn early_data_accepted(&self) -> bool {
        self.inner.early_data_accepted()
    }

    /// The application protocol the server chose, or `None`.
    pub fn negotiated_alpn(&self) -> Option<String> {
        self.inner.negotiated_alpn().map(str::to_string)
    }

    /// The OCSP response the server stapled, as DER, or `None`.
    pub fn stapled_ocsp(&self) -> Option<Vec<u8>> {
        self.inner.stapled_ocsp().map(<[u8]>::to_vec)
    }

    pub fn push_incoming(&mut self, bytes: &[u8]) {
        self.inner.push_incoming(bytes);
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        self.inner.take_outgoing()
    }

    pub fn take_incoming(&mut self) -> Vec<u8> {
        self.inner.take_incoming()
    }

    pub fn process(&mut self) -> Result<(), String> {
        self.inner.process().map_err(|e| e.describe())
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.inner.write(data).map_err(|e| e.describe())
    }

    pub fn close(&mut self) -> Result<(), String> {
        self.inner.close().map_err(|e| e.describe())
    }

    pub fn is_handshaking(&self) -> bool { self.inner.is_handshaking() }
    pub fn is_established(&self) -> bool { self.inner.is_established() }
    pub fn state(&self) -> String { format!("{:?}", self.inner.state()) }

    pub fn version(&self) -> Option<String> {
        self.inner.negotiated_version().map(|v| v.name())
    }

    pub fn cipher(&self) -> Option<(String, String, usize)> {
        self.inner.negotiated_suite().map(|suite| (
            suite.name.to_string(),
            suite.strength.name().to_string(),
            suite.cipher.key_len() * 8,
        ))
    }

    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.inner.peer_certificates()
    }

    pub fn certificate_verified(&self) -> bool { self.inner.certificate_verified() }
    pub fn uses_encrypt_then_mac(&self) -> bool { self.inner.uses_encrypt_then_mac() }
    pub fn named_group(&self) -> Option<String> { self.inner.named_group() }

    /// This session's NSS key log line, for Wireshark. See the note on
    /// `tls::client::ClientConnection::key_log_line` - it hands out the
    /// session keys, and nothing writes it anywhere unless asked.
    pub fn key_log_line(&self) -> Option<String> { self.inner.key_log_line() }
    pub fn uses_extended_master_secret(&self) -> bool {
        self.inner.uses_extended_master_secret()
    }

    pub fn alert(&self) -> Option<String> {
        self.inner.alert().map(|a| a.name())
    }
}

use crate::tls::server as tls_server;
use crate::tls::tickets as tls_tickets;

/// Options for a TLS **server** connection.
///
/// Deliberately not `TlsOptions` with a flag. A client's options are
/// almost all about judging the peer - roots, hostname, expiry, minimum
/// key sizes - and a server here judges nothing, because it asks for no
/// client certificate. Sharing the struct would mean a server config
/// full of fields that do nothing, and the first one somebody set
/// expecting it to take effect would be a security bug.
pub struct TlsServerOptions {
    /// "modern", "legacy", "all", or a comma separated list of suite
    /// names - the same vocabulary as the client's `ciphers`, and the
    /// same function reads it.
    ///
    /// **In the server's own order of preference.** The first suite
    /// here that the client also offered is the one chosen.
    pub ciphers: String,
    pub min_version: String,
    pub max_version: String,
    /// The key session tickets are sealed under, as
    /// `TicketKey::byte_length()` bytes. Empty means "generate one for this
    /// connection", which cannot be resumed against - see
    /// `ServerConfig::ticket_key`.
    pub ticket_key: Vec<u8>,
    /// The current time, seconds since the epoch. Only session tickets
    /// need it - see `ServerConfig::now`.
    pub now: i64,
    /// How many TLS 1.3 session tickets to send. Zero is off, and is the
    /// default because a ticket needs a clock to expire against.
    pub session_tickets: u8,
    /// Agree to encrypt-then-MAC when the client asks (RFC 7366).
    pub allow_encrypt_then_mac: bool,
    /// Agree to the extended master secret when the client asks.
    pub allow_extended_master_secret: bool,

    /// Ask the client for a certificate, at TLS 1.2 or 1.3.
    ///
    /// On its own this is *optional* client authentication: a client
    /// with no suitable certificate answers with an empty one and the
    /// handshake goes on. `peer_certificates` is then empty, and a
    /// caller that treats "asked" as "got" is the bug this split
    /// exists to make visible.
    pub request_client_certificate: bool,
    /// Refuse the connection when the client's answer is empty.
    ///
    /// Only meaningful with `request_client_certificate`.
    pub require_client_certificate: bool,
    /// The roots a client's chain is verified against.
    ///
    /// **Not the server's own chain's roots**, and deliberately a
    /// separate field: the set of CAs allowed to issue client identities
    /// for this service is almost never the public web PKI, and reusing
    /// the system store here would let anything with a certificate from
    /// any public CA authenticate.
    ///
    /// `None` means the chain is not verified at all - the certificate
    /// is taken, the signature over the transcript is still checked (so
    /// the client does hold the key), and judging the chain is left to
    /// the caller. That is a real deployment shape, where the
    /// application looks the key up in its own list.
    pub client_roots: Option<TrustStore>,
    /// How much early data (0-RTT) a ticket allows, in bytes. Zero - the
    /// default - offers none. See `tls::server::ServerConfig::
    /// max_early_data`: it is not forward secret and it is replayable.
    pub max_early_data: u32,
    /// The strike register that refuses a 0-RTT flight already seen.
    ///
    /// **Shared between connections or it is nothing**: a register built
    /// per connection has seen nothing. `None` with `max_early_data` set
    /// accepts early data with no replay check at all, which is right
    /// behind a front end that already de-duplicates and wrong
    /// everywhere else.
    pub replay_guard: Option<std::sync::Arc<std::sync::Mutex<
        tls_tickets::ReplayGuard>>>,
    /// A cached OCSP response to staple, as DER. Nothing here fetches
    /// one; see `tls::server::ServerConfig::ocsp_response`.
    pub ocsp_response: Vec<u8>,
    /// Application protocols this server speaks, **in its own order of
    /// preference**. Empty negotiates nothing.
    pub alpn: Vec<String>,
    /// Fail with `no_application_protocol` when the client offered ALPN
    /// and nothing is in common. Off by default, and ignored when
    /// `alpn` is empty.
    pub require_alpn: bool,
}

impl Default for TlsServerOptions {
    fn default() -> TlsServerOptions {
        TlsServerOptions {
            ciphers: "modern".to_string(),
            min_version: "TLSv1.2".to_string(),
            max_version: "TLSv1.3".to_string(),
            ticket_key: Vec::new(),
            now: 0,
            session_tickets: 0,
            allow_encrypt_then_mac: true,
            allow_extended_master_secret: true,
            request_client_certificate: false,
            require_client_certificate: false,
            client_roots: None,
            max_early_data: 0,
            replay_guard: None,
            ocsp_response: Vec::new(),
            alpn: Vec::new(),
            require_alpn: false,
        }
    }
}

/// A TLS server connection, sans-I/O: bytes in, bytes out, no socket.
pub struct TlsServer {
    inner: tls_server::ServerConnection,
}

impl TlsServer {
    /// A server holding an EC key, for the ECDHE_ECDSA suites.
    ///
    /// `private` is the scalar, big endian - what `EcKey::private_bytes`
    /// hands out. The curve is named rather than inferred from the
    /// certificate: inferring it would mean a mismatch between the key
    /// and the certificate became a signature nobody can verify, which
    /// is a handshake failure with no explanation in it.
    pub fn with_ec_key(certificate_chain: Vec<Vec<u8>>, curve: &str,
                       private: &[u8], options: &TlsServerOptions)
                       -> Result<TlsServer, String> {
        let handle = crate::ec::curves::by_name(curve)?;
        let scalar = BigUint::from_bytes_be(private);
        if scalar.is_zero() || scalar >= handle.n {
            return Err("Private scalar is not in [1, n).".to_string());
        }
        TlsServer::build(certificate_chain,
                         tls_server::ServerKey::Ec { curve: handle.name,
                                                     private: scalar },
                         options)
    }

    /// A server holding an EdDSA key. **TLS 1.3 only.**
    ///
    /// RFC 8422 defines no 1.2 suite whose server authentication is
    /// EdDSA, so `ServerKey::authenticates` refuses every 1.2 exchange
    /// for this key and a 1.2 client gets `handshake_failure` rather
    /// than a suite whose ServerKeyExchange nothing can sign.
    ///
    /// `private` is the **seed**, 32 bytes for Ed25519 - what
    /// `CertificateAuthority::issue` hands back for an ed25519 CA.
    pub fn with_eddsa_key(certificate_chain: Vec<Vec<u8>>, name: &str,
                          private: &[u8], options: &TlsServerOptions)
                          -> Result<TlsServer, String> {
        let variant = eddsa_variant(name)?;
        if private.len() != variant.key_len() {
            return Err(format!("An {} private key is {} bytes; got {}.",
                               name, variant.key_len(), private.len()));
        }
        TlsServer::build(certificate_chain,
                         tls_server::ServerKey::Eddsa {
                             name: eddsa_name(name)?,
                             seed: private.to_vec() },
                         options)
    }

    /// A server holding an ML-DSA key. **TLS 1.3 only**:
    /// draft-ietf-tls-mldsa forbids its schemes at 1.2, so a 1.2 client
    /// gets `handshake_failure`. The certificate must carry the same
    /// parameter set (RFC 9881); the scheme follows from the key.
    pub fn with_ml_dsa_key(certificate_chain: Vec<Vec<u8>>,
                           key: std::sync::Arc<MlDsaKey>, options: &TlsServerOptions)
                           -> Result<TlsServer, String> {
        TlsServer::build(certificate_chain, tls_server::ServerKey::MlDsa(key), options)
    }

    /// A server holding an RSA key, for the ECDHE_RSA and RSA suites.
    ///
    /// The two primes and the public exponent, big endian - what
    /// `RsaKey::numbers` hands out under "p", "q" and "e". The CRT
    /// parameters are derived rather than taken, so there is nothing
    /// here that can disagree with itself.
    pub fn with_rsa_key(certificate_chain: Vec<Vec<u8>>, p: &[u8], q: &[u8],
                        e: &[u8], options: &TlsServerOptions)
                        -> Result<TlsServer, String> {
        let key = rsa::RsaPrivateKey::from_primes(BigUint::from_bytes_be(p),
                                                  BigUint::from_bytes_be(q),
                                                  BigUint::from_bytes_be(e))?;
        TlsServer::build(certificate_chain, tls_server::ServerKey::Rsa(Box::new(key)),
                         options)
    }

    fn build(certificate_chain: Vec<Vec<u8>>, key: tls_server::ServerKey,
             options: &TlsServerOptions) -> Result<TlsServer, String> {
        let mut config = tls_server::ServerConfig::new(certificate_chain, key);
        config.suites = tls_selection(&options.ciphers)?;
        config.min_version = parse_version(&options.min_version)?;
        config.max_version = parse_version(&options.max_version)?;
        if !options.ticket_key.is_empty() {
            config.ticket_key = Some(std::sync::Arc::new(
                tls_tickets::TicketKey::from_bytes(&options.ticket_key)?));
        }
        config.now = options.now;
        config.session_tickets = options.session_tickets;
        config.allow_encrypt_then_mac = options.allow_encrypt_then_mac;
        config.allow_extended_master_secret =
            options.allow_extended_master_secret;
        config.request_client_certificate = options.request_client_certificate;
        config.require_client_certificate = options.require_client_certificate;
        config.client_roots = options.client_roots.clone();
        // The clock the client's chain is judged against is the server's
        // own, which is the only one it has. A caller who did not set
        // `now` gets zero, and every certificate is then not yet valid -
        // so requiring a chain without a clock is refused here rather
        // than at the handshake, where it would read as the client's
        // fault.
        if options.client_roots.is_some() && options.now == 0 {
            return Err("Verifying a client's chain needs `now`.".to_string());
        }
        config.client_policy = x509::verify::Policy::at(options.now);
        config.alpn = options.alpn.clone();
        config.require_alpn = options.require_alpn;
        if !options.ocsp_response.is_empty() {
            config.ocsp_response = Some(options.ocsp_response.clone());
        }
        config.max_early_data = options.max_early_data;
        if options.max_early_data > 0 {
            if options.now == 0 {
                return Err("Early data needs `now`: it is only reachable \
                            through a session ticket.".to_string());
            }
            config.replay_guard = options.replay_guard.clone();
        }
        Ok(TlsServer {
            inner: tls_server::ServerConnection::new(config)
                .map_err(|e| e.describe())?,
        })
    }

    pub fn push_incoming(&mut self, bytes: &[u8]) { self.inner.push_incoming(bytes); }
    pub fn take_outgoing(&mut self) -> Vec<u8> { self.inner.take_outgoing() }
    pub fn take_incoming(&mut self) -> Vec<u8> { self.inner.take_incoming() }

    pub fn process(&mut self) -> Result<(), String> {
        self.inner.process().map_err(|e| e.describe())
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.inner.write(data).map_err(|e| e.describe())
    }

    pub fn close(&mut self) -> Result<(), String> {
        self.inner.close().map_err(|e| e.describe())
    }

    pub fn is_handshaking(&self) -> bool { self.inner.is_handshaking() }
    pub fn is_established(&self) -> bool { self.inner.is_established() }
    pub fn state(&self) -> String { self.inner.state().to_string() }

    pub fn version(&self) -> Option<String> {
        self.inner.version().map(|v| v.name())
    }

    pub fn cipher(&self) -> Option<(String, String, usize)> {
        self.inner.negotiated_suite().map(|suite| (
            suite.name.to_string(),
            suite.strength.name().to_string(),
            suite.cipher.key_len() * 8,
        ))
    }

    /// The host the client asked for in SNI, if it sent one.
    ///
    /// This is the field a terminating proxy is here for: it is the only
    /// thing in a TLS handshake that says which host the client thinks
    /// it is reaching, and it arrives before anything has to be decided.
    pub fn server_name(&self) -> Option<String> {
        self.inner.server_name().map(|name| name.to_string())
    }

    /// The client's certificate chain, leaf first, or empty. See
    /// `tls::server::ServerConnection::peer_certificates`.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.inner.peer_certificates()
    }

    /// Whether that chain was checked against `client_roots`.
    pub fn client_certificate_verified(&self) -> bool {
        self.inner.client_certificate_verified()
    }

    /// Take the early data (0-RTT) this connection accepted. Deliberately
    /// not part of `take_incoming`; see
    /// `tls::server::ServerConnection::take_early_data`.
    pub fn take_early_data(&mut self) -> Vec<u8> {
        self.inner.take_early_data()
    }

    pub fn accepted_early_data(&self) -> bool {
        self.inner.accepted_early_data()
    }

    /// The application protocol chosen from `alpn`, or `None`.
    pub fn negotiated_alpn(&self) -> Option<String> {
        self.inner.negotiated_alpn().map(str::to_string)
    }

    /// The ALPN protocols the client offered. Nothing is negotiated;
    /// a caller that cares reads this and decides.
    pub fn offered_alpn(&self) -> Vec<String> {
        self.inner.offered_alpn().to_vec()
    }

    pub fn uses_encrypt_then_mac(&self) -> bool {
        self.inner.uses_encrypt_then_mac()
    }

    pub fn uses_extended_master_secret(&self) -> bool {
        self.inner.uses_extended_master_secret()
    }
}

// ---------------------------------------------------- a certificate authority ---

use crate::x509::builder::{key_usage, CertificateBuilder,
                           SanEntry, SigningKey, SubjectKey};

/// A certificate authority that issues leaf certificates on demand.
///
/// **This is what a terminating proxy is built on.** The proxy reads the
/// host out of the client's SNI, issues a certificate for that host on
/// the spot, and presents it - so the browser is talking to something
/// it trusts while the proxy talks to the old box behind it however it
/// has to.
///
/// Which means the whole thing rests on the browser trusting this CA's
/// certificate, and that is a decision somebody makes deliberately,
/// once, by installing it. There is no way to make it less serious than
/// it is: **anything holding this key can impersonate any site to
/// anyone who installed it.** `certificate_pem` is for installing; the
/// private key should not leave the machine that generates it.
///
/// EC on P-256 rather than RSA. An RSA key generation is a prime search
/// taking unpredictable seconds, and a proxy issues a certificate while
/// a browser waits on a half-open connection.
pub struct CertificateAuthority {
    key: CaKey,
    certificate: Vec<u8>,
    common_name: String,
}

/// What a CA signs with.
///
/// P-256 is the default and the proxy's, for the reason above: an RSA
/// key generation is a prime search taking unpredictable seconds and a
/// browser is waiting. Ed25519 is here because RFC 8410 certificates
/// are now ordinary, and because a signature scheme with no way to
/// issue a certificate is unreachable - that was the thing blocking
/// `ed25519` as a TLS signature scheme.
pub enum CaKey {
    Ec { curve: crate::ec::Curve, private: BigUint },
    /// The **seed**, not a scalar. See `EddsaKey`.
    Eddsa { name: &'static str, seed: Vec<u8> },
    /// ML-DSA (RFC 9881). Always made from a seed, which is what
    /// `private_bytes` hands out.
    MlDsa(MlDsaKey),
}

impl CaKey {
    fn signing(&self) -> SigningKey<'_> {
        match self {
            CaKey::Ec { curve, private } => SigningKey::Ec { curve, private },
            CaKey::Eddsa { name, seed } => SigningKey::Eddsa { name, seed },
            CaKey::MlDsa(key) => SigningKey::MlDsa(key),
        }
    }

    /// The name this key answers to, which is also what `issue` gives
    /// the leaf it makes.
    pub fn type_name(&self) -> &'static str {
        match self {
            CaKey::Ec { curve, .. } => curve.name,
            CaKey::Eddsa { name, .. } => name,
            CaKey::MlDsa(key) => key.parameter_set(),
        }
    }

    /// The private key as the bytes `from_parts_with` takes back: the
    /// scalar, padded; the EdDSA seed; the ML-DSA seed.
    fn private_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            CaKey::Ec { curve, private } => private.to_bytes_be_padded(curve.scalar_bytes()),
            CaKey::Eddsa { seed, .. } => Ok(seed.clone()),
            CaKey::MlDsa(key) => key.seed().map(<[u8]>::to_vec)
                .ok_or_else(|| "This ML-DSA key has no seed.".to_string()),
        }
    }
}

impl CertificateAuthority {
    /// Generate a fresh CA: a new key, and a self-signed certificate
    /// for it.
    ///
    /// The validity window is given rather than defaulted, because a
    /// proxy CA that outlives its usefulness is a key somebody forgot
    /// they installed. Both are `YYYYMMDDHHMMSSZ`.
    pub fn generate(common_name: &str, not_before: &str, not_after: &str)
                    -> Result<CertificateAuthority, String> {
        CertificateAuthority::generate_with("P-256", common_name, not_before, not_after)
    }

    /// The same, choosing the key type: a curve name, `ed25519`, or an
    /// ML-DSA parameter set (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`).
    ///
    /// The leaves `issue` makes are of the **same** type, because a CA
    /// whose leaves are a different algorithm from itself is a
    /// combination nothing needs and two code paths to keep right.
    pub fn generate_with(key_type: &str, common_name: &str,
                         not_before: &str, not_after: &str)
                         -> Result<CertificateAuthority, String> {
        let key = ca_key(key_type)?;
        // The encoded public half has to outlive the builder, which
        // borrows it - hence the binding rather than a helper returning
        // a `SubjectKey`.
        let public = ca_public(&key)?;
        let subject = ca_subject(&key, &public);

        let mut builder = CertificateBuilder::new(common_name, subject);
        builder.serial = serial()?;
        builder.not_before = not_before;
        builder.not_after = not_after;
        // pathLen 0: this CA signs leaves and nothing else. A proxy has
        // no use for an intermediate, and a CA that could make one is a
        // CA whose key can delegate.
        builder.is_ca = Some((true, Some(0)));
        builder.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
        builder.key_identifiers = true;
        let certificate = builder.sign(&key.signing())?;

        Ok(CertificateAuthority { key, certificate,
                                  common_name: common_name.to_string() })
    }

    /// Rebuild a CA from a key and the certificate it goes with.
    ///
    /// The certificate is not derived from the key: a CA that reissued
    /// itself a different certificate would start signing leaves whose
    /// issuer name no browser has trusted, and the failure would be a
    /// chain that verifies against nothing with both halves looking
    /// correct on their own.
    pub fn from_parts(private: &[u8], certificate: Vec<u8>)
                      -> Result<CertificateAuthority, String> {
        CertificateAuthority::from_parts_with("P-256", private, certificate)
    }

    /// The same, saying which kind of key the bytes are.
    pub fn from_parts_with(key_type: &str, private: &[u8], certificate: Vec<u8>)
                           -> Result<CertificateAuthority, String> {
        let key = match key_type.to_ascii_lowercase().as_str() {
            "ed25519" | "ed448" => {
                let name = eddsa_name(key_type)?;
                CaKey::Eddsa { name, seed: private.to_vec() }
            }
            lower if lower.starts_with("ml-dsa") =>
                CaKey::MlDsa(MlDsaKey::from_seed(&lower.to_ascii_uppercase(), private)?),
            other => {
                let curve = curves::by_name(other)?;
                let scalar = BigUint::from_bytes_be(private);
                if scalar.is_zero() || scalar >= curve.n {
                    return Err("Private scalar is not in [1, n).".to_string());
                }
                CaKey::Ec { curve, private: scalar }
            }
        };

        let parsed = crate::x509::Certificate::parse(&certificate)?;
        let common_name = parsed.subject.common_name()
            .ok_or("The CA certificate has no common name.")?.to_string();

        // The certificate must actually be this key's. A CA signing
        // with a key its certificate does not name issues chains that
        // verify against nothing, with both halves looking correct on
        // their own.
        let public = ca_public(&key)?;
        let matches = match (&parsed.public_key, &key) {
            (crate::x509::PublicKey::Ec { point, .. }, CaKey::Ec { .. }) =>
                *point == public,
            (crate::x509::PublicKey::Eddsa { key: bits, curve }, CaKey::Eddsa { name, .. }) =>
                *bits == public && curve == name,
            (crate::x509::PublicKey::MlDsa { key: bits, parameter_set }, CaKey::MlDsa(key)) =>
                *bits == public && *parameter_set == key.parameter_set(),
            _ => false,
        };
        if !matches {
            return Err("This certificate does not hold this key; a CA \
                        signing with a key its certificate does not name \
                        issues chains that verify against nothing."
                       .to_string());
        }

        Ok(CertificateAuthority { key, certificate, common_name })
    }

    /// The CA certificate as DER - what goes into a browser's store.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The same, PEM wrapped, which is what most things want to import.
    pub fn certificate_pem(&self) -> String {
        crate::pem::wrap("CERTIFICATE", &self.certificate)
    }

    /// The private scalar, big endian.
    ///
    /// **Key material.** Anything holding this can impersonate any site
    /// to anyone who trusts this CA.
    pub fn private_bytes(&self) -> Result<Vec<u8>, String> {
        self.key.private_bytes()
    }

    /// Which kind of key this CA signs with, and what its leaves carry.
    pub fn key_type(&self) -> &'static str {
        self.key.type_name()
    }

    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// Issue a leaf for `host`, with a fresh key.
    ///
    /// Returns the certificate as DER and the new key's private scalar,
    /// which is what `TlsServer::with_ec_key` takes.
    ///
    /// A fresh key every time rather than one reused across hosts: the
    /// cost is one P-256 generation, which is microseconds, and the
    /// alternative is a single key whose compromise is every site the
    /// proxy ever served.
    ///
    /// `host` may be a name or an IP address, and the two go into
    /// different kinds of subjectAltName - **a certificate with an IP
    /// address in a dNSName matches nothing**, because a verifier asked
    /// about an address looks only at iPAddress entries.
    pub fn issue(&self, host: &str, not_before: &str, not_after: &str)
                 -> Result<(Vec<u8>, Vec<u8>), String> {
        let leaf = ca_key(self.key.type_name())?;
        let public = ca_public(&leaf)?;
        let subject = ca_subject(&leaf, &public);

        let mut builder = CertificateBuilder::new(host, subject);
        builder.serial = serial()?;
        builder.issuer = vec![(crate::x509::oids::COMMON_NAME,
                               self.common_name.clone())];
        builder.not_before = not_before;
        builder.not_after = not_after;
        // RFC 9881 section 5: an ML-DSA key "MUST NOT" carry
        // keyEncipherment - it cannot encrypt anything.
        builder.key_usage = Some(match leaf {
            CaKey::MlDsa(_) => key_usage::DIGITAL_SIGNATURE,
            _ => key_usage::DIGITAL_SIGNATURE | key_usage::KEY_ENCIPHERMENT,
        });
        builder.extended_key_usage = vec![crate::x509::oids::EKU_SERVER_AUTH];
        builder.sans = vec![san_for(host)];
        builder.key_identifiers = true;

        let der = builder.sign(&self.key.signing())?;
        Ok((der, leaf.private_bytes()?))
    }

    /// The key identifier of this CA's key, which is what a leaf's
    /// authorityKeyIdentifier names.
    pub fn key_identifier(&self) -> Result<Vec<u8>, String> {
        self.key.signing().key_identifier()
    }
}

/// A fresh CA-or-leaf key of the named type.
fn ca_key(key_type: &str) -> Result<CaKey, String> {
    match key_type.to_ascii_lowercase().as_str() {
        "ed25519" | "ed448" => {
            let name = eddsa_name(key_type)?;
            let (seed, _) = eddsa_generate(name)?;
            Ok(CaKey::Eddsa { name, seed })
        }
        lower if lower.starts_with("ml-dsa") =>
            Ok(CaKey::MlDsa(MlDsaKey::generate(&lower.to_ascii_uppercase())?)),
        other => {
            let curve = curves::by_name(other)?;
            let (private, _) = curve.generate_key_pair()?;
            Ok(CaKey::Ec { curve, private })
        }
    }
}

/// The encoded public half: a SEC1 point, or the raw EdDSA key.
fn ca_public(key: &CaKey) -> Result<Vec<u8>, String> {
    match key {
        CaKey::Ec { curve, private } =>
            curve.encode_point(&curve.scalar_mul_ct(&curve.g, private), false),
        CaKey::Eddsa { name, seed } => eddsa_public_key(name, seed),
        CaKey::MlDsa(key) => Ok(key.public_bytes().to_vec()),
    }
}

/// A `SubjectKey` borrowing the bytes `ca_public` produced.
fn ca_subject<'a>(key: &'a CaKey, public: &'a [u8]) -> SubjectKey<'a> {
    match key {
        CaKey::Ec { curve, .. } => SubjectKey::Ec { curve, point: public },
        CaKey::Eddsa { name, .. } => SubjectKey::Eddsa { name, key: public },
        CaKey::MlDsa(key) => SubjectKey::MlDsa { parameter_set: key.parameter_set(),
                                                 key: public },
    }
}

/// A subjectAltName for a host, choosing the form by what the host is.
///
/// An IP address goes in an `iPAddress` and a name in a `dNSName`, and
/// they are not interchangeable: a verifier asked about `192.0.2.1`
/// looks only at the address entries, so an address written as a name
/// produces a certificate that matches nothing and says nothing about
/// why.
fn san_for(host: &str) -> SanEntry {
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return SanEntry::Ip(v4.octets().to_vec());
    }
    // An address in a URL is bracketed; a SAN holds the address itself.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(v6) = bare.parse::<std::net::Ipv6Addr>() {
        return SanEntry::Ip(v6.octets().to_vec());
    }
    SanEntry::Dns(host.to_string())
}

/// A serial number: 16 random bytes with the top bit clear.
///
/// Random rather than counted, because a counter is state a proxy would
/// have to keep across restarts and a repeated serial from one issuer
/// is what a browser caches and then refuses. The top bit is cleared
/// because a DER INTEGER with it set is negative, which RFC 5280
/// forbids and our own parser refuses.
fn serial() -> Result<Vec<u8>, String> {
    let mut bytes = crate::random::bytes(16)?;
    bytes[0] &= 0x7f;
    // An all-zero first byte is legal but wasteful; a leading zero in a
    // DER INTEGER is only allowed to clear the sign bit.
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    Ok(bytes)
}

// ------------------------------------------------------------- SLH-DSA ---

use crate::pq::slh_dsa;

/// An SLH-DSA key pair, over FIPS 205's **external** interface.
///
/// The external interface on purpose: `slh_dsa::sign_internal` is the
/// layer underneath and signs a different byte string, so a signature
/// made with it is not one another implementation's default verifier
/// accepts. A facade exists to be the obvious thing to reach for, and the
/// obvious thing should be the interoperable one. A protocol that
/// specifies the internal interface can call the `pq::slh_dsa` module
/// directly.
///
/// Holds the private key, so it is the signing half. [`SlhDsaPublicKey`]
/// is the other.
pub struct SlhDsaKey {
    parameters: &'static slh_dsa::Parameters,
    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`.
    private: Vec<u8>,
}

/// The verifying half of an SLH-DSA key: `PK.seed ‖ PK.root`.
pub struct SlhDsaPublicKey {
    parameters: &'static slh_dsa::Parameters,
    public: Vec<u8>,
}

/// Turn a pre-hash name into the thing itself, treating "no pre-hash" as
/// a name-shaped absence.
///
/// `None` means the pure form. Anything else has to be one of the twelve,
/// and an unknown name is refused rather than falling back to pure - a
/// caller who misspells `"SHA2-256"` wants an error, not a signature over
/// the whole message under a different domain separator.
fn slh_pre_hash(name: Option<&str>) -> Result<Option<slh_dsa::PreHash>, String> {
    match name {
        None => Ok(None),
        Some(name) => Ok(Some(slh_dsa::PreHash::by_name(name)?)),
    }
}

impl SlhDsaKey {
    /// A fresh key pair from the OS random source.
    ///
    /// Three `n` byte seeds, drawn here rather than taken as arguments -
    /// which is the whole difference between this and
    /// `slh_dsa::key_gen_internal`, and the reason that one exists: it is
    /// testable against vectors that state the seeds, and this one is
    /// what a caller should use.
    ///
    /// **Slow at the `s` parameter sets**, on the order of a second, because
    /// a key is the root of a tree over `2^h'` one-time keys and every leaf
    /// has to be computed. `docs/post-quantum.md` has the measurements.
    pub fn generate(parameter_set: &str) -> Result<SlhDsaKey, String> {
        let parameters = slh_dsa::parameters(parameter_set)?;
        let n = parameters.n;
        let seed = crate::random::bytes(3 * n)?;
        let (private, _public) = slh_dsa::key_gen_internal(
            parameters, &seed[..n], &seed[n..2 * n], &seed[2 * n..])?;
        Ok(SlhDsaKey { parameters, private })
    }

    /// Import a private key: the `4n` bytes FIPS 205 defines.
    ///
    /// There is nothing to validate beyond the length. Unlike an EC
    /// scalar, every byte string of the right length is a well formed
    /// SLH-DSA private key - the public root inside it either matches the
    /// seeds or it does not, and checking that would cost a full key
    /// generation. [`SlhDsaKey::recompute_public`] is how to ask.
    pub fn from_private(parameter_set: &str, private: &[u8])
            -> Result<SlhDsaKey, String> {
        let parameters = slh_dsa::parameters(parameter_set)?;
        if private.len() != parameters.secret_key_len() {
            return Err(format!(
                "{}: a private key is {} bytes, not {}.", parameters.name,
                parameters.secret_key_len(), private.len()));
        }
        Ok(SlhDsaKey { parameters, private: private.to_vec() })
    }

    pub fn parameter_set(&self) -> &'static str { self.parameters.name }

    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`.
    pub fn private_bytes(&self) -> &[u8] { &self.private }

    /// `PK.seed ‖ PK.root`, which is the **tail of the private key**
    /// rather than something derived.
    pub fn public_bytes(&self) -> &[u8] {
        &self.private[2 * self.parameters.n..]
    }

    pub fn public_key(&self) -> SlhDsaPublicKey {
        SlhDsaPublicKey {
            parameters: self.parameters,
            public: self.public_bytes().to_vec(),
        }
    }

    /// Regenerate the public root from the seeds and compare it with the
    /// one the private key carries.
    ///
    /// The only way to know an imported private key is self-consistent,
    /// and it costs a whole key generation - seconds at the `s` parameter
    /// sets - which is why importing does not do it. Worth calling once
    /// after reading a key from somewhere you do not control; pointless on
    /// a key this library generated.
    pub fn recompute_public(&self) -> Result<bool, String> {
        let n = self.parameters.n;
        let (private, _) = slh_dsa::key_gen_internal(
            self.parameters, &self.private[..n], &self.private[n..2 * n],
            &self.private[2 * n..3 * n])?;
        Ok(private == self.private)
    }

    /// Sign, drawing fresh randomness: FIPS 205's **hedged** mode.
    ///
    /// The default because it is the one the standard recommends, and
    /// because the failure mode of the alternative is worse: a
    /// deterministic signature reveals nothing extra, but a *badly*
    /// randomised one - a counter, a timestamp, the same value twice - is
    /// worse than deterministic. Making the random path the default means
    /// the caller who does not think about it gets the safe one.
    ///
    /// `context` is a domain separator, at most 255 bytes, and empty is
    /// normal. `pre_hash` names one of the twelve approved hash functions,
    /// or `None` for the pure form. Both are part of what gets signed, so
    /// a verifier must be given the same two.
    pub fn sign(&self, message: &[u8], context: &[u8], pre_hash: Option<&str>)
            -> Result<Vec<u8>, String> {
        let opt_rand = crate::random::bytes(self.parameters.n)?;
        slh_dsa::sign(self.parameters, &self.private, message, context,
                      slh_pre_hash(pre_hash)?, &opt_rand)
    }

    /// Sign deterministically: the same message always gives the same
    /// signature.
    ///
    /// Standard, and useful when a signature has to be reproducible - a
    /// test vector, a signed artefact compared byte for byte across
    /// builds. `opt_rand` is `PK.seed`, which is public, so this reveals
    /// nothing that the signature does not.
    pub fn sign_deterministic(&self, message: &[u8], context: &[u8],
                              pre_hash: Option<&str>)
            -> Result<Vec<u8>, String> {
        let n = self.parameters.n;
        // `PK.seed` is the third quarter of the private key. Copied out
        // because `sign` borrows the whole private key at the same time.
        let pk_seed = self.private[2 * n..3 * n].to_vec();
        slh_dsa::sign(self.parameters, &self.private, message, context,
                      slh_pre_hash(pre_hash)?, &pk_seed)
    }

    /// Verify against this key's own public half.
    pub fn verify(&self, message: &[u8], context: &[u8],
                  pre_hash: Option<&str>, signature: &[u8])
            -> Result<bool, String> {
        self.public_key().verify(message, context, pre_hash, signature)
    }
}

impl SlhDsaPublicKey {
    /// Import a public key: the `2n` bytes FIPS 205 defines.
    pub fn from_public(parameter_set: &str, public: &[u8])
            -> Result<SlhDsaPublicKey, String> {
        let parameters = slh_dsa::parameters(parameter_set)?;
        if public.len() != parameters.public_key_len() {
            return Err(format!(
                "{}: a public key is {} bytes, not {}.", parameters.name,
                parameters.public_key_len(), public.len()));
        }
        Ok(SlhDsaPublicKey { parameters, public: public.to_vec() })
    }

    pub fn parameter_set(&self) -> &'static str { self.parameters.name }

    pub fn public_bytes(&self) -> &[u8] { &self.public }

    /// `false` for a signature that is well formed and wrong, `Err` only
    /// for an input that could never be one - a context over 255 bytes,
    /// or an unknown pre-hash name.
    pub fn verify(&self, message: &[u8], context: &[u8],
                  pre_hash: Option<&str>, signature: &[u8])
            -> Result<bool, String> {
        slh_dsa::verify(self.parameters, &self.public, message, context,
                        slh_pre_hash(pre_hash)?, signature)
    }
}

/// Every SLH-DSA parameter set, for a caller offering a choice.
pub fn slh_dsa_parameter_sets() -> Vec<&'static str> {
    slh_dsa::PARAMETER_SETS.iter().map(|set| set.name).collect()
}

/// Every approved pre-hash function name.
pub fn slh_dsa_pre_hashes() -> Vec<&'static str> {
    slh_dsa::PRE_HASHES.iter().map(|which| which.name()).collect()
}

// -------------------------------------------------------------- ML-KEM ---

use crate::pq::ml_kem;

/// An ML-KEM decapsulation key (FIPS 203): the half that recovers shared
/// secrets. [`MlKemPublicKey`] is the encapsulation key, the half that
/// makes them.
///
/// Holds the whole `dk`, which **contains** `ek` - so the public half is a
/// slice of this one rather than something recomputed, the same
/// arrangement as SLH-DSA.
pub struct MlKemKey {
    parameters: &'static ml_kem::Parameters,
    /// `dk_pke ‖ ek ‖ H(ek) ‖ z`, FIPS 203's decapsulation key.
    private: Vec<u8>,
}

/// An ML-KEM encapsulation key: `ByteEncode_12(t_hat) ‖ rho`.
pub struct MlKemPublicKey {
    parameters: &'static ml_kem::Parameters,
    public: Vec<u8>,
}

impl MlKemKey {
    /// A fresh key pair from the OS random source.
    ///
    /// Draws FIPS 203's two seeds `d` and `z`, which is the whole
    /// difference between this and `ml_kem::key_gen_internal`: that one is
    /// testable against vectors that state the seeds, and this one is what
    /// a caller should use.
    pub fn generate(parameter_set: &str) -> Result<MlKemKey, String> {
        let seed = crate::random::bytes(64)?;
        MlKemKey::from_seed(parameter_set, &seed)
    }

    /// Rebuild a key pair from the 64 byte seed `d ‖ z`.
    ///
    /// FIPS 203 allows storing the seed in place of the expanded `dk`
    /// and re-expanding it with `KeyGen_internal`, and it is 64 bytes
    /// against up to 3,168. The seed is
    /// **as secret as the key** - it is the key, in the form key
    /// generation consumes.
    pub fn from_seed(parameter_set: &str, seed: &[u8])
            -> Result<MlKemKey, String> {
        let parameters = ml_kem::parameters(parameter_set)?;
        if seed.len() != 64 {
            return Err(format!(
                "{}: a seed is d || z, 64 bytes, and this is {}.",
                parameters.name, seed.len()));
        }
        let (_ek, private) = ml_kem::key_gen_internal(
            parameters, &seed[..32], &seed[32..])?;
        Ok(MlKemKey { parameters, private })
    }

    /// Import an expanded decapsulation key.
    ///
    /// **Checked on import** with FIPS 203's hash check - the `H(ek)` the
    /// key carries must match the `ek` it carries - because decapsulation
    /// would refuse the key anyway, and an error at import says where the
    /// problem came from. What the check cannot establish is that
    /// `dk_pke` belongs to `ek`: nothing short of the seed can, and a
    /// mismatched pair decapsulates every ciphertext to the
    /// implicit-rejection secret.
    pub fn from_private(parameter_set: &str, private: &[u8])
            -> Result<MlKemKey, String> {
        let parameters = ml_kem::parameters(parameter_set)?;
        if private.len() != parameters.decapsulation_key_len() {
            return Err(format!(
                "{}: a decapsulation key is {} bytes and should be {}.",
                parameters.name, private.len(),
                parameters.decapsulation_key_len()));
        }
        if !ml_kem::hash_check(parameters, private)? {
            return Err(format!(
                "{}: the decapsulation key fails FIPS 203's hash check - the \
                 H(ek) it carries does not match the ek it carries, so it \
                 has been altered or assembled wrongly.", parameters.name));
        }
        Ok(MlKemKey { parameters, private: private.to_vec() })
    }

    pub fn parameter_set(&self) -> &'static str { self.parameters.name }

    /// `dk`: `dk_pke ‖ ek ‖ H(ek) ‖ z`.
    pub fn private_bytes(&self) -> &[u8] { &self.private }

    /// `ek`, which is the **middle of the decapsulation key** rather than
    /// something derived.
    pub fn public_bytes(&self) -> &[u8] {
        let k = self.parameters.k;
        &self.private[384 * k..768 * k + 32]
    }

    pub fn public_key(&self) -> MlKemPublicKey {
        MlKemPublicKey {
            parameters: self.parameters,
            public: self.public_bytes().to_vec(),
        }
    }

    /// Recover the 32 byte shared secret from a ciphertext.
    ///
    /// **A ciphertext that was altered, or made for another key, is not an
    /// error.** It decapsulates to a different secret - pseudorandom,
    /// derived from the ciphertext and a seed only this key holds - and
    /// the two sides simply disagree. Reporting the mismatch would be a
    /// decryption oracle. `Err` is for a ciphertext of the wrong length
    /// only, which is a public fact.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        ml_kem::decapsulate_internal(self.parameters, &self.private,
                                     ciphertext)
    }
}

impl MlKemPublicKey {
    /// Import an encapsulation key.
    ///
    /// **Checked on import** with FIPS 203's modulus check, which refuses
    /// a coefficient encoded at or above `q`. Without it two different
    /// byte strings would be the same key.
    pub fn from_public(parameter_set: &str, public: &[u8])
            -> Result<MlKemPublicKey, String> {
        let parameters = ml_kem::parameters(parameter_set)?;
        if public.len() != parameters.encapsulation_key_len() {
            return Err(format!(
                "{}: an encapsulation key is {} bytes and should be {}.",
                parameters.name, public.len(),
                parameters.encapsulation_key_len()));
        }
        if !ml_kem::modulus_check(parameters, public)? {
            return Err(format!(
                "{}: the encapsulation key fails FIPS 203's modulus check - \
                 a coefficient is encoded at or above q.", parameters.name));
        }
        Ok(MlKemPublicKey { parameters, public: public.to_vec() })
    }

    pub fn parameter_set(&self) -> &'static str { self.parameters.name }

    pub fn public_bytes(&self) -> &[u8] { &self.public }

    /// Make a fresh shared secret for the holder of the matching
    /// decapsulation key: `(shared_secret, ciphertext)`, in FIPS 203's
    /// order.
    ///
    /// The secret is 32 bytes and stays here; the ciphertext is what gets
    /// sent. Draws its 32 byte `m` from the OS random source - a repeated
    /// `m` gives a repeated secret, which is why it is not an argument
    /// here. `ml_kem::encapsulate_internal` takes it, for testing.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let m = crate::random::bytes(32)?;
        ml_kem::encapsulate_internal(self.parameters, &self.public, &m)
    }
}

/// The three ML-KEM parameter sets, as FIPS 203 names them.
pub fn ml_kem_parameter_sets() -> Vec<&'static str> {
    ml_kem::PARAMETER_SETS.iter().map(|set| set.name).collect()
}

// ----------------------------------------------------------------- DSA ---

use crate::publickey_ciphers::dsa;

/// A DSA key pair (FIPS 186-4), signing with RFC 6979 nonces.
///
/// Numbers cross this boundary as big-endian bytes, as `RsaKey`'s do.
/// Signatures are DER `Dss-Sig-Value` - what a certificate and a TLS
/// ServerKeyExchange carry - and are over a message hashed with the named
/// hash, truncated to `q`'s length as FIPS 186-4 says.
#[derive(Clone)]
pub struct DsaKey {
    inner: dsa::DsaPrivateKey,
}

/// The verifying half of a DSA key.
#[derive(Clone)]
pub struct DsaPublicKey {
    inner: dsa::DsaPublicKey,
}

impl DsaKey {
    /// A fresh group of `l` and `n` bits and a key in it. FIPS 186-4's
    /// sizes are (1024, 160), (2048, 224), (2048, 256) and (3072, 256);
    /// a group search takes seconds.
    pub fn generate(l: usize, n: usize) -> Result<DsaKey, String> {
        let parameters = dsa::DsaParameters::generate(l, n)?;
        Ok(DsaKey { inner: dsa::DsaPrivateKey::generate(parameters)? })
    }

    /// A key from its group and `x`, all big endian. The group is checked
    /// for structure; `y` is computed.
    pub fn from_numbers(p: &[u8], q: &[u8], g: &[u8], x: &[u8]) -> Result<DsaKey, String> {
        let parameters = dsa::DsaParameters::new(BigUint::from_bytes_be(p),
                                                 BigUint::from_bytes_be(q),
                                                 BigUint::from_bytes_be(g))?;
        Ok(DsaKey { inner: dsa::DsaPrivateKey::from_x(parameters, BigUint::from_bytes_be(x))? })
    }

    pub fn inner(&self) -> &dsa::DsaPrivateKey {
        &self.inner
    }

    /// `(p, q, g)`, big endian.
    pub fn parameters(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let dsa::DsaParameters { p, q, g } = &self.inner.public.parameters;
        (p.to_bytes_be(), q.to_bytes_be(), g.to_bytes_be())
    }

    /// `x`, big endian. **Key material.**
    pub fn private_bytes(&self) -> Vec<u8> {
        self.inner.x().to_bytes_be()
    }

    pub fn public_key(&self) -> DsaPublicKey {
        DsaPublicKey { inner: self.inner.public.clone() }
    }

    /// Sign `message` hashed with `hash`; the signature is DER.
    pub fn sign(&self, hash: &str, message: &[u8]) -> Result<Vec<u8>, String> {
        let mut hasher = AnyHash::new(hash)?;
        hasher.update(message);
        let (r, s) = self.inner.sign(&hasher.digest(), AnyHash::new(hash)?)?;
        Ok(crate::x509::verify::encode_ecdsa_der(&Signature { r, s }))
    }

    pub fn verify(&self, hash: &str, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        self.public_key().verify(hash, message, signature)
    }
}

impl DsaPublicKey {
    /// A public key from its group and `y`, big endian, checked: `y` must
    /// be in the subgroup of order `q`.
    pub fn from_numbers(p: &[u8], q: &[u8], g: &[u8], y: &[u8]) -> Result<DsaPublicKey, String> {
        let parameters = dsa::DsaParameters::new(BigUint::from_bytes_be(p),
                                                 BigUint::from_bytes_be(q),
                                                 BigUint::from_bytes_be(g))?;
        Ok(DsaPublicKey { inner: dsa::DsaPublicKey::new(parameters, BigUint::from_bytes_be(y))? })
    }

    /// `y`, big endian.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.inner.y.to_bytes_be()
    }

    /// `false` for a signature that does not verify or does not parse.
    pub fn verify(&self, hash: &str, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        let mut hasher = AnyHash::new(hash)?;
        hasher.update(message);
        let Ok(decoded) = crate::x509::verify::decode_ecdsa_der(signature) else {
            return Ok(false);
        };
        self.inner.verify(&hasher.digest(), &decoded.r, &decoded.s)
    }
}

// -------------------------------------------------------------- ML-DSA ---

use crate::pq::ml_dsa;

/// An ML-DSA key pair (FIPS 204), over the **external** interface.
///
/// The external interface for the same reason as [`SlhDsaKey`]: it is the
/// one another implementation's default verifier accepts. The internal
/// interface and the external-`mu` variant are in `pq::ml_dsa`.
///
/// Holds the 32 byte seed as well as the expanded private key when it
/// was made from one, because the seed is the compact and portable form -
/// FIPS 204 allows storing it instead of the key.
pub struct MlDsaKey {
    parameters: &'static ml_dsa::Parameters,
    seed: Option<Vec<u8>>,
    private: Vec<u8>,
    public: Vec<u8>,
}

/// The verifying half of an ML-DSA key.
pub struct MlDsaPublicKey {
    parameters: &'static ml_dsa::Parameters,
    public: Vec<u8>,
}

/// A pre-hash name to the thing itself; `None` is the pure form, and an
/// unknown name is an error rather than a fall back to pure.
fn ml_dsa_pre_hash(name: Option<&str>)
        -> Result<Option<ml_dsa::PreHash>, String> {
    match name {
        None => Ok(None),
        Some(name) => Ok(Some(ml_dsa::PreHash::by_name(name)?)),
    }
}

impl MlDsaKey {
    /// A fresh key pair from a 32 byte seed drawn from the OS.
    pub fn generate(parameter_set: &str) -> Result<MlDsaKey, String> {
        let seed = crate::random::bytes(32)?;
        MlDsaKey::from_seed(parameter_set, &seed)
    }

    /// Rebuild a key pair from its 32 byte seed `xi`. The seed is as secret
    /// as the key.
    pub fn from_seed(parameter_set: &str, seed: &[u8])
            -> Result<MlDsaKey, String> {
        let parameters = ml_dsa::parameters(parameter_set)?;
        if seed.len() != 32 {
            return Err(format!("{}: a seed is 32 bytes, and this is {}.",
                               parameters.name, seed.len()));
        }
        let (public, private) = ml_dsa::key_gen_internal(parameters, seed)?;
        Ok(MlDsaKey { parameters, seed: Some(seed.to_vec()), private, public })
    }

    /// Import an expanded private key.
    ///
    /// An ML-DSA private key does not contain its public key - `t1` is not
    /// stored, only `tr = H(pk)` - but it contains everything `t1` is made
    /// from, so the public key is **recomputed** here: `t = A*s1 + s2`,
    /// split by `Power2Round`. That doubles as a consistency check, and a
    /// thorough one: the recomputed `t0` must be the one the key carries
    /// and `H(pk)` must be its `tr`, so a key whose parts do not belong
    /// together is refused rather than signing as one key while claiming
    /// another.
    pub fn from_private(parameter_set: &str, private: &[u8])
            -> Result<MlDsaKey, String> {
        let parameters = ml_dsa::parameters(parameter_set)?;
        let public = ml_dsa::public_from_private(parameters, private)?;
        Ok(MlDsaKey { parameters, seed: None, private: private.to_vec(),
                      public })
    }

    pub fn parameter_set(&self) -> &'static str { self.parameters.name }

    /// The 32 byte seed, if the key was made from one.
    pub fn seed(&self) -> Option<&[u8]> { self.seed.as_deref() }

    pub fn private_bytes(&self) -> &[u8] { &self.private }

    pub fn public_bytes(&self) -> &[u8] { &self.public }

    pub fn public_key(&self) -> MlDsaPublicKey {
        MlDsaPublicKey { parameters: self.parameters,
                         public: self.public.to_vec() }
    }

    /// Sign with fresh randomness: FIPS 204's **hedged** mode, the default
    /// the standard recommends.
    ///
    /// `context` is a domain separator of at most 255 bytes, normally
    /// empty; `pre_hash` names one of the twelve approved functions or is
    /// `None` for the pure form. A verifier must be given the same two.
    pub fn sign(&self, message: &[u8], context: &[u8], pre_hash: Option<&str>)
            -> Result<Vec<u8>, String> {
        let rnd = crate::random::bytes(32)?;
        ml_dsa::sign(self.parameters, &self.private, message, context,
                     ml_dsa_pre_hash(pre_hash)?, &rnd)
    }

    /// Sign deterministically: `rnd` is 32 zero bytes, so the same message
    /// always gives the same signature.
    pub fn sign_deterministic(&self, message: &[u8], context: &[u8],
                              pre_hash: Option<&str>)
            -> Result<Vec<u8>, String> {
        ml_dsa::sign(self.parameters, &self.private, message, context,
                     ml_dsa_pre_hash(pre_hash)?, &[0u8; 32])
    }

    pub fn verify(&self, message: &[u8], context: &[u8],
                  pre_hash: Option<&str>, signature: &[u8])
            -> Result<bool, String> {
        ml_dsa::verify(self.parameters, &self.public, message, context,
                       ml_dsa_pre_hash(pre_hash)?, signature)
    }
}

impl MlDsaPublicKey {
    pub fn from_public(parameter_set: &str, public: &[u8])
            -> Result<MlDsaPublicKey, String> {
        let parameters = ml_dsa::parameters(parameter_set)?;
        if public.len() != parameters.public_key_len() {
            return Err(format!(
                "{}: a public key is {} bytes and should be {}.",
                parameters.name, public.len(), parameters.public_key_len()));
        }
        Ok(MlDsaPublicKey { parameters, public: public.to_vec() })
    }

    pub fn parameter_set(&self) -> &'static str { self.parameters.name }

    pub fn public_bytes(&self) -> &[u8] { &self.public }

    /// `false` for a signature that is wrong - including one of the wrong
    /// length or with a malformed hint - and `Err` only for an input that
    /// could never be one: a context over 255 bytes or an unknown pre-hash.
    pub fn verify(&self, message: &[u8], context: &[u8],
                  pre_hash: Option<&str>, signature: &[u8])
            -> Result<bool, String> {
        ml_dsa::verify(self.parameters, &self.public, message, context,
                       ml_dsa_pre_hash(pre_hash)?, signature)
    }
}

/// The three ML-DSA parameter sets.
pub fn ml_dsa_parameter_sets() -> Vec<&'static str> {
    ml_dsa::PARAMETER_SETS.iter().map(|set| set.name).collect()
}
