/*
The cipher suite registry.

This is the part of the library the whole thing exists for. Every other TLS
implementation has spent twenty years deleting rows from this table; this
one keeps them, because the servers that only speak them are not ours to
upgrade and "cannot connect" is not an answer.

Keeping them is not the same as offering them. The table records what each
suite *is* - its key exchange, cipher, MAC and PRF - and a `Strength` that
says how it is regarded now. `Selection` decides which are offered, and its
default offers none of the broken ones. Turning one on is a named,
per-connection decision, so that using RC4 is something somebody chose
rather than something that happened.

The strength labels are not opinions:

  * `Modern` - no known practical attack.
  * `Weak` - attacks exist that need unusual conditions or a lot of
    traffic. CBC with SHA-1, whose padding oracle is largely removed by
    encrypt-then-MAC, which this client negotiates by default.
  * `Broken` - practical attacks. RC4, export grade, single DES, MD5 MACs,
    and 3DES.

    3DES sat in `Weak` until a real server pointed out what that meant:
    `Selection::modern` takes everything at `Weak` or better, so the
    *default* offered 3DES - while the policy is that legacy suites are
    off by default and enabled by name, and 3DES is among them. The
    implementation and the policy disagreed, and the policy was right.

    Moving the label rather than carving out an exception in the selection
    is the honest fix, because the label is what became wrong. Sweet32 is
    not a theoretical bound: it recovered a session cookie from real HTTPS,
    and the conditions it needs - a long-lived connection carrying a
    repeated secret - are what HTTPS *is*. NIST disallowed 3DES in TLS and
    every major implementation has removed it. "Practical attack" fits.

    It stays implemented and fully reachable, through `Selection::legacy`
    or by name. That is the entire point of the project; what changed is
    that reaching for it is now a decision somebody made.
  * `Insecure` - provides no confidentiality or no authentication at all.
    The NULL ciphers and the anonymous key exchanges. These are diagnostic
    tools, not ciphersuites; `Selection::all` is the only set that
    includes them and it has to be asked for by name.

    The NULL ciphers are implemented. The anonymous key exchanges are
    **not**: DH_anon and ECDH_anon send a ServerKeyExchange with no
    signature, and that path has not been written - so they stay in the
    table, marked, and no selection offers them.

What a suite lists here is what it *needs*, not what we have. A suite whose
cipher or MAC is not implemented yet is still in the table, marked, and
`Selection` will not offer it - so the table doubles as the list of what is
left to build.
*/

use crate::tls::Version;

// ----------------------------------------------------------------- pieces ---

/// How the two sides agree on a premaster secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyExchange {
    /// The client encrypts the premaster under the server's RSA key. No
    /// forward secrecy: anyone who later obtains the server key can decrypt
    /// every recorded session.
    Rsa,
    /// Ephemeral Diffie-Hellman, signed. Forward secret.
    DheRsa,
    DheDss,
    EcdheRsa,
    EcdheEcdsa,
    /// Static DH, where the server's certificate carries the DH key.
    DhRsa,
    DhDss,
    EcdhRsa,
    EcdhEcdsa,
    /// Unauthenticated. There is no certificate, so there is nobody to be.
    /// A man in the middle is not an attack on these, it is the expected
    /// case.
    AnonDh,
    AnonEcdh,
    /// Pre-shared key.
    Psk,
    /// GOST, RFC 9189.
    GostVko,
    /// VKO GOST R 34.10-2001, draft-chudov-cryptopro-cptls. The same
    /// shape as `GostVko` - an ephemeral key agreed against the
    /// server's certificate key, wrapping a secret the client chose -
    /// with a different hash, a different VKO and a different S-box
    /// under all of it. A variant of its own because every one of
    /// those is silent when confused with the 2012 one: the wrong
    /// choice derives a key of the right length and fails at a MAC
    /// check four messages later.
    GostVko2001,
}

impl KeyExchange {
    pub fn is_forward_secret(self) -> bool {
        matches!(self, KeyExchange::DheRsa | KeyExchange::DheDss
                     | KeyExchange::EcdheRsa | KeyExchange::EcdheEcdsa
                     | KeyExchange::AnonDh | KeyExchange::AnonEcdh)
    }

    pub fn is_authenticated(self) -> bool {
        !matches!(self, KeyExchange::AnonDh | KeyExchange::AnonEcdh)
    }

    /// Whether the ServerKeyExchange carries `ServerDHParams` - a prime, a
    /// generator and a public value - rather than a curve and a point.
    ///
    /// The two messages have the same signature tail and completely
    /// different bodies, so this is what the parser has to branch on. The
    /// anonymous variant is included because its message has the same
    /// shape; what it lacks is the signature, not the parameters.
    pub fn is_finite_field_dh(self) -> bool {
        matches!(self, KeyExchange::DheRsa | KeyExchange::DheDss
                     | KeyExchange::AnonDh)
    }

    pub fn name(self) -> &'static str {
        match self {
            KeyExchange::Rsa => "RSA",
            KeyExchange::DheRsa => "DHE_RSA",
            KeyExchange::DheDss => "DHE_DSS",
            KeyExchange::EcdheRsa => "ECDHE_RSA",
            KeyExchange::EcdheEcdsa => "ECDHE_ECDSA",
            KeyExchange::DhRsa => "DH_RSA",
            KeyExchange::DhDss => "DH_DSS",
            KeyExchange::EcdhRsa => "ECDH_RSA",
            KeyExchange::EcdhEcdsa => "ECDH_ECDSA",
            KeyExchange::AnonDh => "DH_anon",
            KeyExchange::AnonEcdh => "ECDH_anon",
            KeyExchange::Psk => "PSK",
            KeyExchange::GostVko => "GOSTR341112_256",
            KeyExchange::GostVko2001 => "GOSTR341001",
        }
    }
}

/// The bulk cipher, and how the record layer has to drive it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BulkCipher {
    /// No encryption at all. Records go out in the clear, authenticated
    /// only. For diagnostics.
    Null,
    Rc4_128,
    Rc4_40,
    Rc2Cbc40,
    Des40Cbc,
    DesCbc,
    TripleDesCbc,
    Aes128Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes256Gcm,
    Aes128Ccm,
    Aes256Ccm,
    /// The same, with an 8 byte tag (RFC 6655). A shorter tag is a real
    /// trade rather than a free saving: a blind forgery succeeds once in
    /// 2^64 attempts instead of once in 2^128.
    Aes128Ccm8,
    Aes256Ccm8,
    Camellia128Cbc,
    Camellia256Cbc,
    Seed128Cbc,
    Idea128Cbc,
    ChaCha20Poly1305,
    Gost28147Cnt,
    Kuznyechik,
    Magma,
    /// RFC 9367's four TLS 1.3 suites. **Four variants rather than two**,
    /// because the `_L` and `_S` forms of each cipher differ only in
    /// their TLSTREE re-keying schedule - and that schedule is part of
    /// the suite, not a setting. `_S` re-keys far more often: the Magma
    /// one changes its third-level key on *every record*.
    ///
    /// They are separate from `Kuznyechik` and `Magma` above, which are
    /// the TLS 1.2 CTR_OMAC suites over the same two block ciphers. The
    /// cipher is shared; nothing else is.
    KuznyechikMgmL,
    KuznyechikMgmS,
    MagmaMgmL,
    MagmaMgmS,
}

impl BulkCipher {
    /// The algorithm name this library uses, if it has one.
    pub fn algorithm(self) -> Option<&'static str> {
        match self {
            BulkCipher::Aes128Cbc | BulkCipher::Aes256Cbc
            | BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm
            | BulkCipher::Aes128Ccm | BulkCipher::Aes256Ccm
            | BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8 => Some("aes"),
            BulkCipher::Rc4_128 | BulkCipher::Rc4_40 => Some("rc4"),
            BulkCipher::Rc2Cbc40 => Some("rc2"),
            BulkCipher::TripleDesCbc => Some("3des"),
            BulkCipher::DesCbc | BulkCipher::Des40Cbc => Some("des"),
            BulkCipher::Gost28147Cnt => Some("gost"),
            BulkCipher::ChaCha20Poly1305 => Some("chacha20"),
            BulkCipher::Kuznyechik
            | BulkCipher::KuznyechikMgmL
            | BulkCipher::KuznyechikMgmS => Some("kuznyechik"),
            BulkCipher::Magma
            | BulkCipher::MagmaMgmL
            | BulkCipher::MagmaMgmS => Some("magma"),
            _ => None,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            BulkCipher::Null => 0,
            BulkCipher::Rc4_40 | BulkCipher::Rc2Cbc40 | BulkCipher::Des40Cbc => 5,
            BulkCipher::DesCbc => 8,
            BulkCipher::Rc4_128 | BulkCipher::Aes128Cbc | BulkCipher::Aes128Gcm
            | BulkCipher::Aes128Ccm | BulkCipher::Aes128Ccm8
            | BulkCipher::Camellia128Cbc
            | BulkCipher::Seed128Cbc | BulkCipher::Idea128Cbc => 16,
            BulkCipher::TripleDesCbc => 24,
            BulkCipher::Aes256Cbc | BulkCipher::Aes256Gcm | BulkCipher::Aes256Ccm
            | BulkCipher::Aes256Ccm8 | BulkCipher::Camellia256Cbc | BulkCipher::ChaCha20Poly1305
            | BulkCipher::Gost28147Cnt | BulkCipher::Kuznyechik
            | BulkCipher::KuznyechikMgmL | BulkCipher::KuznyechikMgmS
            | BulkCipher::MagmaMgmL | BulkCipher::MagmaMgmS
            // Magma's *block* is 8 bytes and its key is 32. It used to
            // sit with the 128 bit ciphers, which is the trap in the
            // name: GOST R 34.12-2015 gives both its ciphers a 256 bit
            // key and they differ only in block size.
            | BulkCipher::Magma => 32,
        }
    }

    /// Whether this cipher is one of the deliberately weakened export
    /// grades, whose key material goes through a second expansion.
    ///
    /// Export suites do not simply use a short key: the key block yields
    /// five bytes, and those five bytes are then *expanded* back up to the
    /// cipher's real key length by a further PRF pass (RFC 2246 §6.3.1).
    /// The result has 40 bits of entropy in a 16 byte key, which was the
    /// entire point - the paperwork said forty and the wire format did not
    /// change.
    pub fn is_exportable(self) -> bool {
        matches!(self, BulkCipher::Rc4_40 | BulkCipher::Rc2Cbc40
                     | BulkCipher::Des40Cbc)
    }

    /// The key length the cipher is actually keyed with, after the export
    /// expansion. Equal to `key_len` for everything that is not exportable.
    ///
    /// The three export ciphers do not agree on it, which is the sort of
    /// thing a single constant would get wrong: RC4_40 and RC2_CBC_40
    /// expand to 16 bytes, DES40_CBC to 8.
    pub fn expanded_key_len(self) -> usize {
        match self {
            BulkCipher::Rc4_40 | BulkCipher::Rc2Cbc40 => 16,
            BulkCipher::Des40Cbc => 8,
            other => other.key_len(),
        }
    }

    /// RC2's effective key length in bits, which is part of its key
    /// schedule rather than a length check. `None` for everything else.
    ///
    /// TLS's RC2_CBC_40 is a 16 byte expanded key with 40 effective bits.
    /// Keying RC2 with those 16 bytes unweakened is a different cipher
    /// that round-trips perfectly against itself.
    pub fn rc2_effective_bits(self) -> Option<usize> {
        match self {
            BulkCipher::Rc2Cbc40 => Some(40),
            _ => None,
        }
    }

    /// The record layer's block size, or zero for a stream cipher.
    pub fn block_size(self) -> usize {
        match self {
            BulkCipher::Null | BulkCipher::Rc4_128 | BulkCipher::Rc4_40
            | BulkCipher::ChaCha20Poly1305 | BulkCipher::Gost28147Cnt
            // MGM is a counter mode with a multilinear MAC over it, so
            // the *record layer* has no block even though Magma's is 8
            // and Kuznyechik's is 16. `block_size` is the record
            // layer's question; `mgm().block` is the cipher's.
            | BulkCipher::KuznyechikMgmL | BulkCipher::KuznyechikMgmS
            | BulkCipher::MagmaMgmL | BulkCipher::MagmaMgmS => 0,
            BulkCipher::Rc2Cbc40 | BulkCipher::Des40Cbc | BulkCipher::DesCbc
            | BulkCipher::TripleDesCbc | BulkCipher::Idea128Cbc
            | BulkCipher::Magma => 8,
            _ => 16,
        }
    }

    /// The CTR_OMAC parameters, for the two RFC 9189 suites that have
    /// them, and `None` for everything else.
    ///
    /// The whole parameter set travels together - cipher, block, ACPKM
    /// section, TLSTREE constants and SNMAX - because picking them
    /// individually is how a suite ends up with Magma's section size
    /// under Kuznyechik, each choice separately plausible.
    pub fn ctr_omac(self) -> Option<crate::tls::record_gost::CtrOmacSuite> {
        use crate::tls::record_gost::CtrOmacSuite;
        match self {
            BulkCipher::Kuznyechik => Some(CtrOmacSuite::KUZNYECHIK),
            BulkCipher::Magma => Some(CtrOmacSuite::MAGMA),
            _ => None,
        }
    }

    /// The Finished message's `verify_data` length, in bytes.
    ///
    /// **Twelve is the default and not the rule.** RFC 5246 section
    /// 7.4.9 says twelve "unless the cipher suite specifies a
    /// verify_data_length", and for years nothing here specified one -
    /// so it became a constant, `keys::VERIFY_DATA_LEN`.
    ///
    /// RFC 9189 section 4.2.6 specifies one: **32 for the CTR_OMAC
    /// suites**, 12 for CNT_IMIT. Getting it wrong is invisible from
    /// inside, because both ends of a handshake between two copies of
    /// the same implementation truncate to the same length and agree -
    /// which is exactly what `tests/test_gost_handshake.rs` was doing.
    /// A real peer says `bad digest length` and nothing else.
    ///
    /// It belongs to the *cipher*, not to the PRF, because that is
    /// where RFC 9189 puts it: the two CTR_OMAC suites differ from the
    /// CNT_IMIT one in this and share a PRF.
    pub fn verify_data_len(self) -> usize {
        match self {
            BulkCipher::Kuznyechik | BulkCipher::Magma => 32,
            _ => crate::tls::keys::VERIFY_DATA_LEN,
        }
    }

    pub fn is_aead(self) -> bool {
        matches!(self, BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm
                     | BulkCipher::Aes128Ccm | BulkCipher::Aes256Ccm
                     | BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8
                     | BulkCipher::ChaCha20Poly1305
                     | BulkCipher::KuznyechikMgmL | BulkCipher::KuznyechikMgmS
                     | BulkCipher::MagmaMgmL | BulkCipher::MagmaMgmS)
    }

    pub fn is_cbc(self) -> bool {
        self.block_size() > 0 && !self.is_aead()
    }

    /// The AEAD nonce's fixed half, derived once into the key block and
    /// reused for every record. Zero for anything that is not an AEAD.
    ///
    /// TLS 1.2 splits an AEAD nonce in two (RFC 5246 §6.2.3.3): a salt from
    /// the key block, and a per-record part. For GCM that is 4 + 8
    /// (RFC 5288); ChaCha20-Poly1305 later abandoned the split and derives
    /// the whole 12 bytes from the sequence number (RFC 7905), which is why
    /// this is a property of the cipher and not a constant.
    pub fn fixed_iv_len(self) -> usize {
        match self {
            BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm
            | BulkCipher::Aes128Ccm | BulkCipher::Aes256Ccm
            | BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8 => 4,
            BulkCipher::ChaCha20Poly1305 => 12,
            _ => 0,
        }
    }

    /// The per-record half of the nonce, sent in the clear ahead of the
    /// ciphertext. Zero for the AEADs that send nothing.
    pub fn explicit_iv_len(self) -> usize {
        match self {
            BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm
            | BulkCipher::Aes128Ccm | BulkCipher::Aes256Ccm
            | BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8 => 8,
            _ => 0,
        }
    }

    /// The authentication tag's length in bytes, which is not the same for
    /// every AEAD: the CCM_8 suites exist precisely to make it eight.
    /// Zero for anything that is not an AEAD, which has a MAC instead.
    pub fn tag_len(self) -> usize {
        match self {
            BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8 => 8,
            // **MGM's tag is its block** (RFC 9367 4.1.1 sets S = n), so
            // the Magma suites have an 8 byte tag and the Kuznyechik
            // ones 16. Not a truncation - a property of the cipher, and
            // the same shape as EAX over a 64 bit block.
            BulkCipher::MagmaMgmL | BulkCipher::MagmaMgmS => 8,
            BulkCipher::KuznyechikMgmL | BulkCipher::KuznyechikMgmS => 16,
            _ if self.is_aead() => 16,
            _ => 0,
        }
    }

    /// The **TLS 1.3** static IV's length, which is not twelve for
    /// everything.
    ///
    /// RFC 8446 section 7.3 expands `"iv"` to the AEAD's nonce length,
    /// and every AEAD that document names takes twelve bytes - so the
    /// twelve became a constant here. RFC 9367 section 4.1.1 sets
    /// `IVlen = n`, which is 16 for Kuznyechik and 8 for Magma.
    ///
    /// A wrong answer here is not a length error at the first record: it
    /// is a *different static IV*, since the expansion's output length
    /// is part of its input.
    pub fn iv_len_13(self) -> usize {
        match self {
            BulkCipher::MagmaMgmL | BulkCipher::MagmaMgmS => 8,
            BulkCipher::KuznyechikMgmL | BulkCipher::KuznyechikMgmS => 16,
            _ => crate::tls::keys13::NONCE_LEN,
        }
    }

    /// The MGM parameters of an RFC 9367 suite, and `None` for
    /// everything else.
    ///
    /// The whole set travels together for the reason `ctr_omac` gives
    /// just below: chosen individually, a suite ends up with the `_S`
    /// schedule under the `_L` cipher, each choice separately
    /// plausible and the pair wrong.
    pub fn mgm(self) -> Option<crate::tls::record_mgm::MgmSuite> {
        use crate::tls::record_mgm::MgmSuite;
        match self {
            BulkCipher::KuznyechikMgmL => Some(MgmSuite::KUZNYECHIK_L),
            BulkCipher::KuznyechikMgmS => Some(MgmSuite::KUZNYECHIK_S),
            BulkCipher::MagmaMgmL => Some(MgmSuite::MAGMA_L),
            BulkCipher::MagmaMgmS => Some(MgmSuite::MAGMA_S),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            BulkCipher::Null => "NULL",
            BulkCipher::Rc4_128 => "RC4_128",
            BulkCipher::Rc4_40 => "RC4_40",
            BulkCipher::Rc2Cbc40 => "RC2_CBC_40",
            BulkCipher::Des40Cbc => "DES40_CBC",
            BulkCipher::DesCbc => "DES_CBC",
            BulkCipher::TripleDesCbc => "3DES_EDE_CBC",
            BulkCipher::Aes128Cbc => "AES_128_CBC",
            BulkCipher::Aes256Cbc => "AES_256_CBC",
            BulkCipher::Aes128Gcm => "AES_128_GCM",
            BulkCipher::Aes256Gcm => "AES_256_GCM",
            BulkCipher::Aes128Ccm => "AES_128_CCM",
            BulkCipher::Aes256Ccm => "AES_256_CCM",
            BulkCipher::Aes128Ccm8 => "AES_128_CCM_8",
            BulkCipher::Aes256Ccm8 => "AES_256_CCM_8",
            BulkCipher::Camellia128Cbc => "CAMELLIA_128_CBC",
            BulkCipher::Camellia256Cbc => "CAMELLIA_256_CBC",
            BulkCipher::Seed128Cbc => "SEED_CBC",
            BulkCipher::Idea128Cbc => "IDEA_CBC",
            BulkCipher::ChaCha20Poly1305 => "CHACHA20_POLY1305",
            BulkCipher::Gost28147Cnt => "28147_CNT",
            BulkCipher::Kuznyechik => "KUZNYECHIK",
            BulkCipher::Magma => "MAGMA",
            BulkCipher::KuznyechikMgmL => "KUZNYECHIK_MGM_L",
            BulkCipher::KuznyechikMgmS => "KUZNYECHIK_MGM_S",
            BulkCipher::MagmaMgmL => "MAGMA_MGM_L",
            BulkCipher::MagmaMgmS => "MAGMA_MGM_S",
        }
    }
}

/// The record MAC.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MacAlgorithm {
    /// AEAD suites carry no separate MAC.
    Aead,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    /// OMAC over the suite's block cipher (RFC 9189 4.3.2), whose key is
    /// 32 bytes and whose tag is a whole block. Not a hash, so it has no
    /// `hash_name`.
    Gost,
    /// Streebog-256, which the GOST suites use as their **PRF** hash
    /// (RFC 9189 4.3.4). A separate variant from `Gost` because the two
    /// slots hold different algorithms in these suites: `mac` is OMAC
    /// and `prf` is HMAC-Streebog, and one enum spanning both would let
    /// the record layer ask a MAC for a hash name and get one.
    Streebog256,
    /// GOST R 34.11-94, which the 2001 suite uses as its PRF hash and
    /// its transcript hash. **Not** interchangeable with
    /// `Streebog256`: both are 256 bits and they are different
    /// functions.
    Gost94,
}

impl MacAlgorithm {
    /// The TLS 1.3 PRF hash this name denotes.
    ///
    /// The inverse of `hash_name` for the two hashes TLS 1.3 allows, so
    /// a ticket that remembers `"sha384"` can be turned back into the
    /// algorithm its key schedule needs. Only those two: TLS 1.3 has no
    /// other KDF hash, and a `MacAlgorithm` that is not one of them is
    /// not a 1.3 suite's PRF.
    pub fn for_tls13_hash(hash: &str) -> Result<MacAlgorithm, String> {
        match hash {
            "sha256" => Ok(MacAlgorithm::Sha256),
            "sha384" => Ok(MacAlgorithm::Sha384),
            // RFC 9367 section 4.2. The inverse of
            // `handshake13::tls13_hash_name`, and a test asserts the two
            // round trip - a resumed session whose ticket named a hash
            // this could not map would be refused for the wrong reason.
            "streebog256" => Ok(MacAlgorithm::Streebog256),
            other => Err(format!(
                "TLS 1.3's KDF hash is SHA-256, SHA-384 or Streebog-256; \
                 {:?} is none of them.", other)),
        }
    }

    pub fn hash_name(self) -> Option<&'static str> {
        match self {
            MacAlgorithm::Md5 => Some("md5"),
            MacAlgorithm::Sha1 => Some("sha1"),
            MacAlgorithm::Sha256 => Some("sha256"),
            MacAlgorithm::Sha384 => Some("sha384"),
            MacAlgorithm::Streebog256 => Some("streebog256"),
            MacAlgorithm::Gost94 => Some("gost94"),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            MacAlgorithm::Aead => "AEAD",
            MacAlgorithm::Md5 => "MD5",
            MacAlgorithm::Sha1 => "SHA",
            MacAlgorithm::Sha256 => "SHA256",
            MacAlgorithm::Sha384 => "SHA384",
            MacAlgorithm::Gost => "GOSTR3411",
            MacAlgorithm::Streebog256 => "STREEBOG256",
            MacAlgorithm::Gost94 => "GOSTR3411",
        }
    }
}

/// How a suite is regarded now. See the note at the top of this file.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Strength {
    /// No confidentiality or no authentication at all.
    Insecure,
    /// Practical attacks exist.
    Broken,
    /// Attacks exist that need unusual conditions or a lot of traffic.
    Weak,
    /// No known practical attack.
    Modern,
}

impl Strength {
    pub fn name(self) -> &'static str {
        match self {
            Strength::Insecure => "insecure",
            Strength::Broken => "broken",
            Strength::Weak => "weak",
            Strength::Modern => "modern",
        }
    }
}

/// One row of the registry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CipherSuite {
    pub code: u16,
    /// The IANA name, which is what everyone greps for.
    pub name: &'static str,
    /// The OpenSSL name, which is what people actually type.
    pub openssl_name: &'static str,
    pub key_exchange: KeyExchange,
    pub cipher: BulkCipher,
    pub mac: MacAlgorithm,
    /// The PRF hash for TLS 1.2. Before 1.2 the PRF is fixed by the
    /// version, not the suite.
    pub prf: MacAlgorithm,
    pub strength: Strength,
    /// The lowest version this suite may be used with.
    pub min_version: Version,
}

impl CipherSuite {
    /// Whether every piece this suite needs is implemented here.
    ///
    /// A suite whose cipher or MAC is missing stays in the table - the
    /// table is the catalogue of what TLS has, not of what we have - but it
    /// is never offered, and this is how the difference is known.
    pub fn is_implemented(&self) -> bool {
        // All three RFC 9189 suites are built. They share the shape of
        // the key exchange and nothing else: CTR_OMAC has per-record
        // keys from TLSTREE, and CNT_IMIT has one keystream and one
        // cumulative MAC for the whole connection.
        if self.key_exchange == KeyExchange::GostVko
            || self.key_exchange == KeyExchange::GostVko2001 {
            return true;
        }
        if self.key_exchange == KeyExchange::Psk {
            return false;
        }
        if self.mac == MacAlgorithm::Gost {
            return false;
        }
        // The key exchanges that are wired up: static RSA, both flavours
        // of ephemeral ECDH, and finite-field DHE with an RSA or a DSA
        // signature (the DSA one on the client side; this library's
        // server does not do finite-field DHE at all). The static
        // DH ones need a certificate carrying a DH key, which nothing has
        // issued this century; and the anonymous ones are excluded **here**
        // rather than by their strength, because they are not implemented -
        // DH_anon and ECDH_anon carry a ServerKeyExchange with no
        // signature at all and that path has not been written. This
        // comment used to claim the strength label did the excluding,
        // which would have been true only if the code existed.
        if !matches!(self.key_exchange,
                     KeyExchange::Rsa | KeyExchange::EcdheRsa
                   | KeyExchange::EcdheEcdsa | KeyExchange::DheRsa
                   | KeyExchange::DheDss) {
            return false;
        }
        match self.cipher {
            BulkCipher::Aes128Cbc | BulkCipher::Aes256Cbc => true,
            BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm => true,
            BulkCipher::Aes128Ccm | BulkCipher::Aes256Ccm => true,
            BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8 => true,
            BulkCipher::ChaCha20Poly1305 => true,
            // RFC 9367's four. They reach this arm because a TLS 1.3
            // suite names no key exchange and every 1.3 row carries the
            // same placeholder - which is the point: what makes these
            // GOST is the cipher and the hash, and both are built.
            BulkCipher::KuznyechikMgmL | BulkCipher::KuznyechikMgmS
            | BulkCipher::MagmaMgmL | BulkCipher::MagmaMgmS => true,
            BulkCipher::Rc4_128 | BulkCipher::Rc4_40 => true,
            BulkCipher::TripleDesCbc | BulkCipher::DesCbc => true,
            // The export grades. Deliberately weakened by 1990s US law,
            // and the reason FREAK and Logjam were possible in 2015.
            BulkCipher::Rc2Cbc40 | BulkCipher::Des40Cbc => true,
            BulkCipher::Null => true,
            _ => false,
        }
    }

    pub fn describe(&self) -> String {
        format!("0x{:04x} {} ({}, {})", self.code, self.name,
                self.strength.name(),
                if self.key_exchange.is_forward_secret() {
                    "forward secret"
                } else {
                    "not forward secret"
                })
    }
}

macro_rules! suites {
    ($($code:literal, $name:literal, $openssl:literal, $kx:ident, $cipher:ident,
       $mac:ident, $prf:ident, $strength:ident, $min:ident;)*) => {
        pub const ALL: &[CipherSuite] = &[$(CipherSuite {
            code: $code,
            name: $name,
            openssl_name: $openssl,
            key_exchange: KeyExchange::$kx,
            cipher: BulkCipher::$cipher,
            mac: MacAlgorithm::$mac,
            prf: MacAlgorithm::$prf,
            strength: Strength::$strength,
            min_version: Version::$min,
        },)*];
    };
}

suites! {
    // --- no encryption. Diagnostic only; these authenticate and nothing else.
    0x0000, "TLS_NULL_WITH_NULL_NULL",          "",              Rsa,  Null, Md5,  Sha256, Insecure, SSL30;
    0x0001, "TLS_RSA_WITH_NULL_MD5",            "NULL-MD5",      Rsa,  Null, Md5,  Sha256, Insecure, SSL30;
    0x0002, "TLS_RSA_WITH_NULL_SHA",            "NULL-SHA",      Rsa,  Null, Sha1, Sha256, Insecure, SSL30;
    0x003b, "TLS_RSA_WITH_NULL_SHA256",         "NULL-SHA256",   Rsa,  Null, Sha256, Sha256, Insecure, TLS12;

    // --- export grade. Deliberately weakened to 40 bits by 1990s US law,
    //     and the reason FREAK and Logjam were possible in 2015.
    0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5",   "EXP-RC4-MD5",   Rsa,  Rc4_40,   Md5,  Sha256, Broken, SSL30;
    0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "EXP-RC2-CBC-MD5", Rsa, Rc2Cbc40, Md5, Sha256, Broken, SSL30;
    0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-DES-CBC-SHA", Rsa, Des40Cbc, Sha1, Sha256, Broken, SSL30;
    0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-EDH-RSA-DES-CBC-SHA", DheRsa, Des40Cbc, Sha1, Sha256, Broken, SSL30;
    0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "EXP-EDH-DSS-DES-CBC-SHA", DheDss, Des40Cbc, Sha1, Sha256, Broken, SSL30;

    // --- RC4. Biases in the keystream recover plaintext; prohibited by
    //     RFC 7465 and still the only thing some old kit speaks.
    0x0004, "TLS_RSA_WITH_RC4_128_MD5",         "RC4-MD5",       Rsa,  Rc4_128, Md5,  Sha256, Broken, SSL30;
    0x0005, "TLS_RSA_WITH_RC4_128_SHA",         "RC4-SHA",       Rsa,  Rc4_128, Sha1, Sha256, Broken, SSL30;
    0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA",   "ECDHE-RSA-RC4-SHA", EcdheRsa, Rc4_128, Sha1, Sha256, Broken, TLS10;

    // --- single DES. 56 bits, brute forced in 1998 and cheaply since.
    0x0009, "TLS_RSA_WITH_DES_CBC_SHA",         "DES-CBC-SHA",   Rsa,  DesCbc, Sha1, Sha256, Broken, SSL30;
    0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA",     "EDH-RSA-DES-CBC-SHA", DheRsa, DesCbc, Sha1, Sha256, Broken, SSL30;
    0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA",     "EDH-DSS-DES-CBC-SHA", DheDss, DesCbc, Sha1, Sha256, Broken, SSL30;

    // --- 3DES. Sweet32: a 64 bit block leaks after ~32GB on one connection.
    0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA",    "DES-CBC3-SHA",  Rsa,  TripleDesCbc, Sha1, Sha256, Broken, SSL30;
    0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "EDH-RSA-DES-CBC3-SHA", DheRsa, TripleDesCbc, Sha1, Sha256, Broken, SSL30;
    0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "EDH-DSS-DES-CBC3-SHA", DheDss, TripleDesCbc, Sha1, Sha256, Broken, SSL30;
    0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA", EcdheRsa, TripleDesCbc, Sha1, Sha256, Broken, TLS10;

    // --- IDEA and SEED, regional and largely historical.
    0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA",        "IDEA-CBC-SHA",  Rsa,  Idea128Cbc, Sha1, Sha256, Weak, SSL30;
    0x0096, "TLS_RSA_WITH_SEED_CBC_SHA",        "SEED-SHA",      Rsa,  Seed128Cbc, Sha1, Sha256, Weak, SSL30;

    // --- anonymous. No certificate, so nobody to authenticate. A man in
    //     the middle is not an attack on these; it is the expected case.
    0x0018, "TLS_DH_anon_WITH_RC4_128_MD5",     "ADH-RC4-MD5",   AnonDh, Rc4_128, Md5, Sha256, Insecure, SSL30;
    0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "ADH-DES-CBC3-SHA", AnonDh, TripleDesCbc, Sha1, Sha256, Insecure, SSL30;
    0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", "ADH-AES128-SHA", AnonDh, Aes128Cbc, Sha1, Sha256, Insecure, SSL30;
    0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "AECDH-AES128-SHA", AnonEcdh, Aes128Cbc, Sha1, Sha256, Insecure, TLS10;

    // --- AES-CBC with SHA-1. What the TLS client was first written for,
    //     and what most old-but-not-ancient servers speak. Weak because of the CBC padding history,
    //     not because of AES.
    0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA",     "AES128-SHA",    Rsa,  Aes128Cbc, Sha1, Sha256, Weak, SSL30;
    0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA",     "AES256-SHA",    Rsa,  Aes256Cbc, Sha1, Sha256, Weak, SSL30;
    0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA", DheRsa, Aes128Cbc, Sha1, Sha256, Weak, SSL30;
    0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA", DheRsa, Aes256Cbc, Sha1, Sha256, Weak, SSL30;
    0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA", EcdheRsa, Aes128Cbc, Sha1, Sha256, Weak, TLS10;
    0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE-RSA-AES256-SHA", EcdheRsa, Aes256Cbc, Sha1, Sha256, Weak, TLS10;
    0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE-ECDSA-AES128-SHA", EcdheEcdsa, Aes128Cbc, Sha1, Sha256, Weak, TLS10;
    0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE-ECDSA-AES256-SHA", EcdheEcdsa, Aes256Cbc, Sha1, Sha256, Weak, TLS10;

    // --- AES-CBC with SHA-256. TLS 1.2 only.
    0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256",  "AES128-SHA256", Rsa,  Aes128Cbc, Sha256, Sha256, Weak, TLS12;
    0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256",  "AES256-SHA256", Rsa,  Aes256Cbc, Sha256, Sha256, Weak, TLS12;
    0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256", DheRsa, Aes128Cbc, Sha256, Sha256, Weak, TLS12;
    0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256", DheRsa, Aes256Cbc, Sha256, Sha256, Weak, TLS12;
    0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256", EcdheRsa, Aes128Cbc, Sha256, Sha256, Weak, TLS12;
    0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384", EcdheRsa, Aes256Cbc, Sha384, Sha384, Weak, TLS12;

    // --- AEAD. Not implemented yet; here so the table is the catalogue.
    0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256",  "AES128-GCM-SHA256", Rsa, Aes128Gcm, Aead, Sha256, Modern, TLS12;
    0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384",  "AES256-GCM-SHA384", Rsa, Aes256Gcm, Aead, Sha384, Modern, TLS12;
    0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", EcdheRsa, Aes128Gcm, Aead, Sha256, Modern, TLS12;
    0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384", EcdheRsa, Aes256Gcm, Aead, Sha384, Modern, TLS12;
    0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", EcdheEcdsa, Aes128Gcm, Aead, Sha256, Modern, TLS12;
    0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384", EcdheEcdsa, Aes256Gcm, Aead, Sha384, Modern, TLS12;
    0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-CHACHA20-POLY1305", EcdheRsa, ChaCha20Poly1305, Aead, Sha256, Modern, TLS12;
    0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", EcdheEcdsa, ChaCha20Poly1305, Aead, Sha256, Modern, TLS12;
    // Finite-field DHE with AEAD. After the elliptic curve rows on
    // purpose: the sort is stable within a strength, so registry order is
    // what makes a server that offers both get the curve - which is
    // faster, and whose group we can actually check by name.
    // --- AES-CCM (RFC 6655 and RFC 7251). Same AES, a different AEAD:
    //     CBC-MAC and CTR rather than GHASH, which is what hardware with
    //     no carryless multiply can do cheaply. The _8 rows have an eight
    //     byte tag, which is the whole reason they exist.
    0xc09c, "TLS_RSA_WITH_AES_128_CCM",        "AES128-CCM",    Rsa, Aes128Ccm, Aead, Sha256, Modern, TLS12;
    0xc09d, "TLS_RSA_WITH_AES_256_CCM",        "AES256-CCM",    Rsa, Aes256Ccm, Aead, Sha256, Modern, TLS12;
    0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8",      "AES128-CCM8",   Rsa, Aes128Ccm8, Aead, Sha256, Modern, TLS12;
    0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8",      "AES256-CCM8",   Rsa, Aes256Ccm8, Aead, Sha256, Modern, TLS12;
    0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM",    "DHE-RSA-AES128-CCM", DheRsa, Aes128Ccm, Aead, Sha256, Modern, TLS12;
    0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM",    "DHE-RSA-AES256-CCM", DheRsa, Aes256Ccm, Aead, Sha256, Modern, TLS12;
    0xc0a2, "TLS_DHE_RSA_WITH_AES_128_CCM_8",  "DHE-RSA-AES128-CCM8", DheRsa, Aes128Ccm8, Aead, Sha256, Modern, TLS12;
    0xc0a3, "TLS_DHE_RSA_WITH_AES_256_CCM_8",  "DHE-RSA-AES256-CCM8", DheRsa, Aes256Ccm8, Aead, Sha256, Modern, TLS12;
    0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "ECDHE-ECDSA-AES128-CCM", EcdheEcdsa, Aes128Ccm, Aead, Sha256, Modern, TLS12;
    0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", "ECDHE-ECDSA-AES256-CCM", EcdheEcdsa, Aes256Ccm, Aead, Sha256, Modern, TLS12;
    0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", "ECDHE-ECDSA-AES128-CCM8", EcdheEcdsa, Aes128Ccm8, Aead, Sha256, Modern, TLS12;
    0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", "ECDHE-ECDSA-AES256-CCM8", EcdheEcdsa, Aes256Ccm8, Aead, Sha256, Modern, TLS12;

    0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256", DheRsa, Aes128Gcm, Aead, Sha256, Modern, TLS12;
    0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384", DheRsa, Aes256Gcm, Aead, Sha384, Modern, TLS12;
    0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE-RSA-CHACHA20-POLY1305", DheRsa, ChaCha20Poly1305, Aead, Sha256, Modern, TLS12;

    // --- DHE with a DSA certificate. Every one is Weak at best, AEAD or
    //     not: the strength of the suite is the signature's, DSA was
    //     withdrawn for new signatures by FIPS 186-5, and the DSA keys in
    //     the field are overwhelmingly 1024 bit. The certificate's group
    //     size is held to `min_rsa_bits`, as an RSA modulus is.
    0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE-DSS-AES128-SHA", DheDss, Aes128Cbc, Sha1, Sha256, Weak, SSL30;
    0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE-DSS-AES256-SHA", DheDss, Aes256Cbc, Sha1, Sha256, Weak, SSL30;
    0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE-DSS-AES128-SHA256", DheDss, Aes128Cbc, Sha256, Sha256, Weak, TLS12;
    0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE-DSS-AES256-SHA256", DheDss, Aes256Cbc, Sha256, Sha256, Weak, TLS12;
    0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE-DSS-AES128-GCM-SHA256", DheDss, Aes128Gcm, Aead, Sha256, Weak, TLS12;
    0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE-DSS-AES256-GCM-SHA384", DheDss, Aes256Gcm, Aead, Sha384, Weak, TLS12;

    // --- TLS 1.3. The key exchange is not part of the suite any more.
    0x1301, "TLS_AES_128_GCM_SHA256",           "TLS_AES_128_GCM_SHA256", EcdheRsa, Aes128Gcm, Aead, Sha256, Modern, TLS13;
    0x1302, "TLS_AES_256_GCM_SHA384",           "TLS_AES_256_GCM_SHA384", EcdheRsa, Aes256Gcm, Aead, Sha384, Modern, TLS13;
    0x1303, "TLS_CHACHA20_POLY1305_SHA256",     "TLS_CHACHA20_POLY1305_SHA256", EcdheRsa, ChaCha20Poly1305, Aead, Sha256, Modern, TLS13;
    // RFC 8446 section B.4. These exist for constrained devices, and the
    // _8 one is the reason `BulkCipher::tag_len` is not a constant: its
    // tag is eight bytes, so a record layer that assumed sixteen would
    // read eight bytes of ciphertext as part of it.
    0x1304, "TLS_AES_128_CCM_SHA256",           "TLS_AES_128_CCM_SHA256", EcdheRsa, Aes128Ccm, Aead, Sha256, Modern, TLS13;
    0x1305, "TLS_AES_128_CCM_8_SHA256",         "TLS_AES_128_CCM_8_SHA256", EcdheRsa, Aes128Ccm8, Aead, Sha256, Weak, TLS13;

    // --- GOST, RFC 9189. The reason this library was started.
    0xc100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC", GostVko, Kuznyechik, Gost, Streebog256, Modern, TLS12;
    0xc101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "GOST2012-MAGMA-MAGMAOMAC", GostVko, Magma, Gost, Streebog256, Modern, TLS12;
    0xc102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", "IANA-GOST2012-GOST8912-GOST8912", GostVko, Gost28147Cnt, Gost, Streebog256, Modern, TLS12;
    // **The same suite, at the code point it had before IANA gave it
    // one.** RFC 9189 section 10 says so in as many words: "some old
    // implementations can still use the old value {0xFF, 0x85} instead
    // of the {0xC1, 0x02} value to indicate the
    // TLS_GOSTR341112_256_WITH_28147_CNT_IMIT cipher suite". 0xFF85 is
    // in the private-use range, which is where these lived before 2022,
    // and a box installed before then speaks only this one.
    //
    // It is a row of its own rather than an alias because a code point
    // is what goes on the wire: the client has to offer both numbers,
    // and a ServerHello naming either has to be recognised. Everything
    // else about it - the key exchange, the cipher, the MAC, the PRF -
    // is the row above, and `tests::test_the_two_cnt_imit_code_points_
    // agree` is what keeps them that way.
    0xff85, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT_LEGACY", "LEGACY-GOST2012-GOST8912-GOST8912", GostVko, Gost28147Cnt, Gost, Streebog256, Modern, TLS12;

    // --- GOST, the 2001 generation. draft-chudov-cryptopro-cptls-04
    //     (vendored in `rfcs/`), and
    //     never an RFC - but it is what a box installed before 2012
    //     speaks, and OpenSSL's GOST engine still has it as
    //     `GOST2001-GOST89-GOST89`.
    //
    //     The record layer is the same CNT_IMIT as 0xC102 above, on a
    //     different S-box; everything else is a decade older. GOST R
    //     34.11-94 is the hash - for the PRF, for the transcript, for
    //     the certificate's signature and inside the key exchange -
    //     and it has had published collisions since 2008, which is why
    //     this is `Weak` where its 2012 neighbours are `Modern`. It is
    //     here because the equipment is.
    0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT", "GOST2001-GOST89-GOST89", GostVko2001, Gost28147Cnt, Gost, Gost94, Weak, TLS10;

    // --- GOST at TLS 1.3, RFC 9367.
    //
    //     Like every 1.3 suite the key exchange here is a placeholder:
    //     the suite names an AEAD and a hash and nothing else. The hash
    //     is Streebog-256 (RFC 9367 section 4.2), which is what makes
    //     these four the only 1.3 suites in this table whose PRF is
    //     neither SHA-256 nor SHA-384.
    //
    //     `_L` and `_S` are the same cipher with different re-keying:
    //     the `_S` suites change the record key far more often and cap
    //     the connection at 2^42-1 or 2^39-1 records for it. That is
    //     the whole difference, it is invisible on the wire, and it is
    //     why they are four rows rather than two with a flag.
    0xc103, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L", "GOST2012-KUZNYECHIK-MGM-L", EcdheRsa, KuznyechikMgmL, Aead, Streebog256, Modern, TLS13;
    0xc104, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", "GOST2012-MAGMA-MGM-L", EcdheRsa, MagmaMgmL, Aead, Streebog256, Modern, TLS13;
    0xc105, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S", "GOST2012-KUZNYECHIK-MGM-S", EcdheRsa, KuznyechikMgmS, Aead, Streebog256, Modern, TLS13;
    0xc106, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", "GOST2012-MAGMA-MGM-S", EcdheRsa, MagmaMgmS, Aead, Streebog256, Modern, TLS13;
}

/// The signalling value that says "I am not falling back on purpose".
///
/// RFC 7507. A client retrying at a lower version includes it; a server
/// that supports something higher then refuses. Without it, an attacker who
/// can break connections can force a downgrade just by breaking them.
pub const FALLBACK_SCSV: u16 = 0x5600;

/// The signalling value that says "I support secure renegotiation".
///
/// RFC 5746, the other way of saying it besides the extension.
pub const RENEGOTIATION_SCSV: u16 = 0x00ff;

/// Look a suite up by its code.
pub fn by_code(code: u16) -> Option<&'static CipherSuite> {
    ALL.iter().find(|suite| suite.code == code)
}

/// Look a suite up by either of its names, case insensitively.
pub fn by_name(name: &str) -> Option<&'static CipherSuite> {
    if let Some(code) = alias(name) {
        return by_code(code);
    }
    ALL.iter().find(|suite| suite.name.eq_ignore_ascii_case(name)
                         || (!suite.openssl_name.is_empty()
                             && suite.openssl_name.eq_ignore_ascii_case(name)))
}

/// Spellings that are somebody's name for a suite but not its own.
///
/// OpenSSL renamed the CNT_IMIT suite when IANA assigned it a code
/// point: what it called `GOST2012-GOST8912-GOST8912` is now
/// `IANA-GOST2012-GOST8912-GOST8912`, with the old spelling given to
/// nothing. A configuration file written against the older OpenSSL
/// names the suite the old way, and that has to keep working - this is
/// a library for reaching things nobody will update, and a cipher list
/// somebody wrote in 2019 is one of them.
fn alias(name: &str) -> Option<u16> {
    const ALIASES: &[(&str, u16)] = &[
        ("GOST2012-GOST8912-GOST8912", 0xc102),
    ];
    ALIASES.iter()
        .find(|(spelling, _)| spelling.eq_ignore_ascii_case(name))
        .map(|(_, code)| *code)
}

/// A name for a code, even one we do not know.
pub fn describe_code(code: u16) -> String {
    match code {
        FALLBACK_SCSV => "TLS_FALLBACK_SCSV".to_string(),
        RENEGOTIATION_SCSV => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV".to_string(),
        other => match by_code(other) {
            Some(suite) => suite.name.to_string(),
            None => format!("unknown suite 0x{:04x}", other),
        },
    }
}

// -------------------------------------------------------------- selection ---

/// Which suites to offer.
///
/// The default offers only what is implemented and not broken. Everything
/// else has to be asked for, by name or by strength, so that connecting
/// with RC4 is a decision somebody made rather than something that
/// happened.
#[derive(Clone, Debug)]
pub struct Selection {
    codes: Vec<u16>,
}

impl Default for Selection {
    fn default() -> Selection {
        Selection::modern()
    }
}

impl Selection {
    /// Everything implemented that is not broken or insecure, strongest
    /// first.
    pub fn modern() -> Selection {
        let mut suites: Vec<&CipherSuite> = ALL.iter()
            .filter(|suite| suite.is_implemented()
                         && suite.strength >= Strength::Weak)
            .collect();
        suites.sort_by_key(|suite| (core::cmp::Reverse(suite.strength),
                                    core::cmp::Reverse(suite.cipher.key_len())));
        Selection { codes: suites.iter().map(|suite| suite.code).collect() }
    }

    /// Everything implemented, including the broken ones, strongest first.
    ///
    /// This is the "I have to talk to it anyway" selection. It still
    /// excludes `Insecure` - a suite with no encryption or no
    /// authentication is not something to fall into, only something to ask
    /// for by name.
    pub fn legacy() -> Selection {
        let mut suites: Vec<&CipherSuite> = ALL.iter()
            .filter(|suite| suite.is_implemented()
                         && suite.strength >= Strength::Broken)
            .collect();
        suites.sort_by_key(|suite| (core::cmp::Reverse(suite.strength),
                                    core::cmp::Reverse(suite.cipher.key_len())));
        Selection { codes: suites.iter().map(|suite| suite.code).collect() }
    }

    /// **Everything this library implements**, including the suites that
    /// provide no confidentiality and no authentication at all.
    ///
    /// The widest selection there is, and the only one that reaches the
    /// `Insecure` rows without naming them one at a time. It exists
    /// because "I have to talk to this box and I do not care what it
    /// offers" is a real position, and the alternative was a caller
    /// pasting a list of forty suite names and getting it wrong.
    ///
    /// It is not reachable by accident: `Selection::default()` is
    /// `modern`, `legacy` stops at `Broken`, and the only way here is to
    /// ask for this by name. What it buys over `legacy` is the NULL
    /// ciphers and the anonymous key exchanges - a connection with no
    /// encryption, or with nobody on the other end. If that is what the
    /// equipment speaks, this is how you reach it; if it is not, do not
    /// use this.
    pub fn all() -> Selection {
        let mut suites: Vec<&CipherSuite> = ALL.iter()
            .filter(|suite| suite.is_implemented())
            .collect();
        suites.sort_by_key(|suite| (core::cmp::Reverse(suite.strength),
                                    core::cmp::Reverse(suite.cipher.key_len())));
        Selection { codes: suites.iter().map(|suite| suite.code).collect() }
    }

    /// Exactly these, by name, in this order. Anything at all can be named,
    /// including the insecure ones - naming it is the point.
    pub fn named(names: &[&str]) -> Result<Selection, String> {
        let mut codes = Vec::new();
        for name in names {
            let suite = by_name(name).ok_or_else(|| format!(
                "Unknown cipher suite {:?}.", name))?;
            if !suite.is_implemented() {
                return Err(format!(
                    "{} is in the registry but not implemented yet ({} with {}).",
                    suite.name, suite.cipher.name(), suite.mac.name()));
            }
            codes.push(suite.code);
        }
        if codes.is_empty() {
            return Err("A selection needs at least one cipher suite.".to_string());
        }
        Ok(Selection { codes })
    }

    /// Exactly these codes, whatever they are. For talking to something
    /// that wants a suite we have not named.
    pub fn from_codes(codes: Vec<u16>) -> Result<Selection, String> {
        if codes.is_empty() {
            return Err("A selection needs at least one cipher suite.".to_string());
        }
        Ok(Selection { codes })
    }

    pub fn codes(&self) -> &[u16] {
        &self.codes
    }

    /// Whether any suite here is a GOST one.
    ///
    /// The ClientHello asks, because the GOST curves belong in
    /// `supported_groups` exactly when a suite that could use them is
    /// on offer.
    pub fn offers_gost(&self) -> bool {
        self.codes.iter().any(|code| by_code(*code).is_some_and(
            |suite| matches!(suite.key_exchange,
                             KeyExchange::GostVko | KeyExchange::GostVko2001)))
    }

    /// Whether any DHE_DSS suite is offered, which is when the hello
    /// carries the DSA signature schemes: a scheme offered with no suite
    /// that can use it is a row nothing checks.
    pub fn offers_dss(&self) -> bool {
        self.codes.iter().any(|code| by_code(*code)
            .is_some_and(|suite| suite.key_exchange == KeyExchange::DheDss))
    }

    /// Whether any of RFC 9367's TLS 1.3 GOST suites is offered.
    ///
    /// A different question from `offers_gost`, and the two are not
    /// nested: a TLS 1.3 suite names no key exchange at all, so its
    /// `key_exchange` is the placeholder every 1.3 row carries. What
    /// makes it GOST is the cipher.
    ///
    /// It decides whether the hello carries RFC 9367's seven signature
    /// schemes, which are a different set of codepoints from RFC 9189's
    /// five - a 1.3 GOST server will not use a 1.2 one.
    pub fn offers_gost_13(&self) -> bool {
        self.codes.iter().any(|code| by_code(*code)
            .is_some_and(|suite| suite.cipher.mgm().is_some()))
    }

    /// The codes to put in a ClientHello, with the renegotiation SCSV
    /// appended.
    ///
    /// The SCSV is not optional. Without either it or the extension, a
    /// server cannot tell a renegotiation from a fresh handshake, which is
    /// the 2009 attack.
    pub fn to_hello(&self) -> Vec<u16> {
        let mut codes = self.codes.clone();
        codes.push(RENEGOTIATION_SCSV);
        codes
    }

    /// Whether a server's choice was one we actually offered.
    ///
    /// A server that picks a suite the client did not offer is either
    /// broken or attacking; accepting it is how a downgrade happens
    /// silently.
    pub fn was_offered(&self, code: u16) -> bool {
        self.codes.contains(&code)
    }

    pub fn names(&self) -> Vec<String> {
        self.codes.iter().map(|code| describe_code(*code)).collect()
    }

    /// Only the suites usable at this version.
    pub fn for_version(&self, version: Version) -> Selection {
        Selection {
            codes: self.codes.iter().copied()
                .filter(|code| by_code(*code)
                        .map(|suite| version >= suite.min_version)
                        .unwrap_or(true))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// No two rows may share a code, and no two may share a name. A
    /// copy-paste slip in a table this size is otherwise invisible.
    #[test]
    fn test_the_registry_is_consistent() {
        let mut codes = HashSet::new();
        let mut names = HashSet::new();
        for suite in ALL {
            assert!(codes.insert(suite.code),
                    "duplicate code 0x{:04x} ({})", suite.code, suite.name);
            assert!(names.insert(suite.name),
                    "duplicate name {}", suite.name);
            assert!(suite.name.starts_with("TLS_"),
                    "{} does not look like an IANA name", suite.name);
        }
        assert!(ALL.len() > 40, "the registry has only {} suites", ALL.len());
    }

    /// The pieces each row claims must agree with each other.
    #[test]
    fn test_each_suite_is_internally_consistent() {
        for suite in ALL {
            if suite.cipher.is_aead() {
                assert_eq!(suite.mac, MacAlgorithm::Aead,
                           "{} is AEAD but names a MAC", suite.name);
            } else {
                assert_ne!(suite.mac, MacAlgorithm::Aead,
                           "{} is not AEAD but has no MAC", suite.name);
            }

            // An anonymous key exchange has no certificate, so it cannot be
            // anything but insecure.
            if !suite.key_exchange.is_authenticated() {
                assert_eq!(suite.strength, Strength::Insecure,
                           "{} is anonymous but not marked insecure", suite.name);
            }
            // Neither can a suite with no encryption.
            if suite.cipher == BulkCipher::Null {
                assert_eq!(suite.strength, Strength::Insecure,
                           "{} has no encryption but is not marked insecure",
                           suite.name);
            }
            // Export grade and RC4 are broken, not weak.
            if matches!(suite.cipher, BulkCipher::Rc4_40 | BulkCipher::Rc2Cbc40
                                    | BulkCipher::Des40Cbc | BulkCipher::DesCbc) {
                assert!(suite.strength <= Strength::Broken,
                        "{} is export or single-DES but marked {}",
                        suite.name, suite.strength.name());
            }

            assert!(suite.cipher.key_len() > 0 || suite.cipher == BulkCipher::Null);
        }
    }

    /// The codes must be the real ones. These are checked against RFC 5246
    /// appendix A.5, RFC 8446 appendix B.4, RFC 4492, RFC 7905 and RFC 9189.
    #[test]
    fn test_well_known_codes() {
        for (code, name) in [
            (0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
            (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
            (0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
            (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
            (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
            (0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            (0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            (0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            (0x1301, "TLS_AES_128_GCM_SHA256"),
            (0x1302, "TLS_AES_256_GCM_SHA384"),
            (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
        ] {
            let suite = by_code(code).unwrap_or_else(|| panic!(
                "0x{:04x} is not in the registry", code));
            assert_eq!(suite.name, name);
        }

        assert_eq!(describe_code(FALLBACK_SCSV), "TLS_FALLBACK_SCSV");
        assert_eq!(describe_code(RENEGOTIATION_SCSV),
                   "TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
        assert_eq!(describe_code(0xdead), "unknown suite 0xdead");
    }

    #[test]
    fn test_lookup_by_name() {
        assert_eq!(by_name("AES128-SHA").unwrap().code, 0x002f);
        assert_eq!(by_name("aes128-sha").unwrap().code, 0x002f);
        assert_eq!(by_name("TLS_RSA_WITH_AES_128_CBC_SHA").unwrap().code, 0x002f);
        assert!(by_name("NOT-A-SUITE").is_none());
        // The empty OpenSSL name must not match the empty string.
        assert!(by_name("").is_none());
    }

    /// The default selection must not contain anything broken. This is the
    /// test that would catch a strength label being edited without thought.
    /// The default must not offer anything the policy calls a legacy
    /// suite. A real server found this: `3des.badssl.com` serves nothing
    /// but 3DES, and the *default* context connected to it happily -
    /// because `modern()` takes everything at `Weak` or better and 3DES
    /// was labelled `Weak`.
    ///
    /// Written as a list of names rather than as `strength >= Weak`, so
    /// that it keeps meaning something if the selection's rule changes.
    #[test]
    fn test_the_default_offers_no_legacy_suite() {
        let offered: Vec<String> = Selection::modern().names();
        for forbidden in ["3DES", "RC4", "DES_CBC", "EXPORT", "NULL",
                          "anon", "IDEA", "SEED", "RC2"] {
            assert!(!offered.iter().any(|name| name.contains(forbidden)),
                    "the default offers a {} suite: {:?}", forbidden,
                    offered.iter().filter(|n| n.contains(forbidden))
                        .collect::<Vec<_>>());
        }

        // And each of those is still reachable, which is the point of the
        // project - refusing by default is not the same as removing.
        let legacy: Vec<String> = Selection::legacy().names();
        assert!(legacy.iter().any(|name| name.contains("3DES")),
                "3DES is not reachable through the legacy selection either");
        assert!(Selection::named(&["DES-CBC3-SHA"]).is_ok());
        assert!(Selection::named(&["RC4-SHA"]).is_ok());
    }

    /// `all` is the widest selection and the only one that reaches the
    /// insecure suites without naming them individually. The test is that
    /// it is strictly wider than `legacy`, which is strictly wider than
    /// `modern` - and that nothing reaches the insecure rows by accident.
    #[test]
    fn test_the_all_selection_is_the_widest_and_is_never_a_default() {
        let modern = Selection::modern().codes().len();
        let legacy = Selection::legacy().codes().len();
        let all = Selection::all().codes().len();
        assert!(modern < legacy, "legacy must be wider than modern");
        assert!(legacy < all, "all must be wider than legacy");

        // What `all` adds over `legacy` is the NULL ciphers. The
        // anonymous key exchanges are *not* in it, and that is not an
        // oversight of this selection: they are not implemented, because
        // DH_anon and ECDH_anon need a ServerKeyExchange with no
        // signature and nothing has been written for it. A selection
        // cannot offer a suite the client cannot complete.
        let names = Selection::all().names();
        assert!(names.iter().any(|n| n.contains("NULL")),
                "all does not reach the NULL suites");
        assert!(!names.iter().any(|n| n.contains("anon")),
                "all offers an anonymous suite, which is not implemented - \
                 offering one would mean a handshake we cannot finish");
        let legacy_names = Selection::legacy().names();
        assert!(!legacy_names.iter().any(|n| n.contains("NULL")),
                "legacy reaches a NULL suite, which it must not");

        // And nothing falls into it: the default is still modern.
        assert_eq!(Selection::default().codes(), Selection::modern().codes());
    }

    #[test]
    fn test_the_default_selection_is_not_broken() {
        let selection = Selection::modern();
        assert!(!selection.codes().is_empty(), "nothing is offered by default");

        for code in selection.codes() {
            let suite = by_code(*code).unwrap();
            assert!(suite.strength >= Strength::Weak,
                    "{} is offered by default", suite.describe());
            assert!(suite.is_implemented(),
                    "{} is offered but not implemented", suite.name);
            assert!(suite.key_exchange.is_authenticated(),
                    "{} is anonymous and offered by default", suite.name);
            assert_ne!(suite.cipher, BulkCipher::Null,
                       "{} has no encryption and is offered by default", suite.name);
        }
    }

    /// Legacy offers more, and still not the insecure ones - a suite with
    /// no encryption is something to ask for by name, not to fall into.
    #[test]
    fn test_the_legacy_selection_adds_broken_but_not_insecure() {
        let modern = Selection::modern();
        let legacy = Selection::legacy();
        assert!(legacy.codes().len() > modern.codes().len(),
                "legacy offers no more than modern");

        for code in legacy.codes() {
            let suite = by_code(*code).unwrap();
            assert!(suite.strength >= Strength::Broken,
                    "{} is in the legacy selection", suite.describe());
        }
        // RC4 is in legacy and not in modern, which is the whole point.
        assert!(legacy.was_offered(0x0005));
        assert!(!modern.was_offered(0x0005));
    }

    #[test]
    fn test_naming_suites_explicitly() {
        let selection = Selection::named(&["AES128-SHA", "RC4-SHA"]).unwrap();
        assert_eq!(selection.codes(), &[0x002f, 0x0005]);
        assert_eq!(selection.names(), vec!["TLS_RSA_WITH_AES_128_CBC_SHA",
                                           "TLS_RSA_WITH_RC4_128_SHA"]);

        assert!(Selection::named(&["NOT-A-SUITE"]).is_err());
        assert!(Selection::named(&[]).is_err());

        // A suite in the registry but not implemented says so clearly,
        // rather than silently producing an empty hello.
        //
        // Whichever one that is, found from the registry rather than named
        // here. Two earlier versions of this line named a specific suite -
        // first a GCM one, then ChaCha20-Poly1305 - and both went stale
        // within the week, because the whole point of the registry is that
        // its unimplemented rows keep becoming implemented ones.
        let unbuilt = ALL.iter().find(|suite| !suite.is_implemented()
                                           && !suite.openssl_name.is_empty())
            .expect("the registry should still hold something unimplemented; \
                     if it does not, this assertion is vacuous and should go");
        let error = Selection::named(&[unbuilt.openssl_name]).unwrap_err();
        assert!(error.contains("not implemented"),
                "naming {}: {}", unbuilt.openssl_name, error);
    }

    /// The renegotiation SCSV must be in every hello. Without it or the
    /// extension, a server cannot tell a renegotiation from a fresh
    /// handshake - the 2009 attack.
    #[test]
    fn test_the_hello_carries_the_renegotiation_scsv() {
        let hello = Selection::modern().to_hello();
        assert!(hello.contains(&RENEGOTIATION_SCSV));
        assert_eq!(hello.last(), Some(&RENEGOTIATION_SCSV),
                   "the SCSV belongs at the end");
    }

    /// A server that picks something the client did not offer is either
    /// broken or attacking.
    #[test]
    fn test_a_suite_we_did_not_offer_is_noticed() {
        let selection = Selection::named(&["AES128-SHA"]).unwrap();
        assert!(selection.was_offered(0x002f));
        assert!(!selection.was_offered(0x0005));
        assert!(!selection.was_offered(0x0000));
    }

    #[test]
    fn test_version_filtering() {
        let selection = Selection::from_codes(vec![0x002f, 0x003c, 0x1301]).unwrap();

        // SHA256 CBC suites are TLS 1.2 only; the 1.3 suite needs 1.3.
        let for_tls10 = selection.for_version(Version::TLS10);
        assert_eq!(for_tls10.codes(), &[0x002f]);

        let for_tls12 = selection.for_version(Version::TLS12);
        assert_eq!(for_tls12.codes(), &[0x002f, 0x003c]);

        let for_tls13 = selection.for_version(Version::TLS13);
        assert_eq!(for_tls13.codes().len(), 3);
    }

    /// Every suite we claim to implement must name algorithms this library
    /// actually has. This is the test that keeps `is_implemented` honest.
    #[test]
    fn test_implemented_suites_name_real_algorithms() {
        for suite in ALL.iter().filter(|s| s.is_implemented()) {
            if suite.cipher != BulkCipher::Null {
                let algorithm = suite.cipher.algorithm().unwrap_or_else(|| panic!(
                    "{} is implemented but its cipher has no algorithm name",
                    suite.name));
                assert!(crate::api::BLOCK_CIPHERS.contains(&algorithm)
                        || crate::api::STREAM_CIPHERS.contains(&algorithm),
                        "{} names {}, which this library does not have",
                        suite.name, algorithm);
            }
            // OMAC is not a hash, so it has no hash name and is checked
            // by its cipher instead - which `ctr_omac` above already
            // did. Everything else that is not an AEAD is an HMAC.
            if suite.mac == MacAlgorithm::Gost {
                assert!(suite.cipher.ctr_omac().is_some()
                        || suite.cipher == BulkCipher::Gost28147Cnt,
                        "{} uses a GOST MAC but names no GOST cipher",
                        suite.name);
            } else if suite.mac != MacAlgorithm::Aead {
                let hash = suite.mac.hash_name().unwrap_or_else(|| panic!(
                    "{} is implemented but its MAC has no hash name", suite.name));
                assert!(crate::api::HASHES.contains(&hash),
                        "{} names {}, which this library does not have",
                        suite.name, hash);
            }

            // The PRF is always a hash, whatever the MAC is.
            let prf = suite.prf.hash_name().unwrap_or_else(|| panic!(
                "{} is implemented but its PRF has no hash name", suite.name));
            assert!(crate::api::HASHES.contains(&prf),
                    "{} names {} as its PRF, which this library does not have",
                    suite.name, prf);
        }
    }

    /// Every suite's declared key and block lengths must be the ones the
    /// cipher itself accepts.
    ///
    /// This table used to say Magma took a 16 byte key. It takes 32:
    /// GOST R 34.12-2015 gives both its ciphers a 256 bit key and they
    /// differ only in block size, and Magma had been grouped with the
    /// 128 bit ciphers because its *block* is 8 bytes. Nothing noticed,
    /// because the suite was not implemented and so nothing ever built
    /// the cipher from the length this table claimed. The check is over
    /// the whole table rather than the implemented part for that exact
    /// reason - a wrong length that is only wrong while unused is still
    /// wrong, and becomes a handshake that fails on the first record
    /// the day the suite is turned on.
    #[test]
    fn test_the_declared_lengths_are_the_ciphers_own() {
        use crate::block_ciphers::BlockCipher;

        for suite in ALL.iter() {
            let Some(algorithm) = suite.cipher.algorithm() else { continue };
            if !crate::api::BLOCK_CIPHERS.contains(&algorithm) {
                continue;   // stream ciphers have no block size to compare
            }
            // Export suites weaken the key on purpose: their five bytes
            // go through the PRF again to reach the cipher's real
            // length, so the table's number is not a key length.
            if suite.cipher.is_exportable() {
                continue;
            }

            let key = vec![0u8; suite.cipher.key_len()];
            let cipher = crate::api::AnyBlockCipher::new(algorithm, &key, None)
                .unwrap_or_else(|e| panic!(
                    "{} says {} takes a {} byte key: {}",
                    suite.name, algorithm, suite.cipher.key_len(), e));

            // `block_size` is the *record layer's* block, which is not
            // always the cipher's: a counter mode turns a block cipher
            // into a stream one and the record layer then has no block
            // at all, which is why `Gost28147Cnt` says zero. The two
            // questions coincide only for CBC, so only CBC is compared.
            if suite.cipher.is_cbc() {
                assert_eq!(cipher.blocksize(), suite.cipher.block_size(),
                           "{} says {} has a {} byte block",
                           suite.name, algorithm, suite.cipher.block_size());
            }
        }
    }

    /// All three RFC 9189 suites are built, and they share almost
    /// nothing below the shape of the key exchange.
    ///
    /// CTR_OMAC derives per-record keys with TLSTREE; CNT_IMIT keeps
    /// one keystream and one cumulative MAC for the whole connection.
    /// So this checks that each names the pieces it needs, rather than
    /// that the three agree about anything.
    ///
    /// Four rows, three suites: CNT_IMIT is in the table twice, once
    /// at the code point IANA assigned it and once at the private-use
    /// one it had first. See the note on 0xFF85 in the table.
    #[test]
    fn test_the_three_gost_suites_are_built_and_differ() {
        let gost: Vec<&CipherSuite> = ALL.iter()
            .filter(|s| s.key_exchange == KeyExchange::GostVko).collect();
        assert_eq!(gost.len(), 4,
                   "RFC 9189 defines three suites, and one of them has two \
                    code points");

        for suite in &gost {
            assert!(suite.is_implemented(), "{}", suite.name);
            // All three use a GOST MAC in the MAC slot and Streebog in
            // the PRF slot. Confusing the two is what a single `Gost`
            // variant in both places would invite.
            assert_eq!(suite.mac, MacAlgorithm::Gost, "{}", suite.name);
            assert_eq!(suite.prf, MacAlgorithm::Streebog256, "{}", suite.name);
            // And each is offered, since each is built - a suite we can
            // finish and do not offer is a different kind of mistake
            // from one we offer and cannot.
            assert!(Selection::legacy().was_offered(suite.code), "{}", suite.name);
        }

        // Two take CTR_OMAC parameters and one does not, which is how
        // the record layer and the key exchange tell them apart.
        let ctr_omac: Vec<&str> = gost.iter()
            .filter(|s| s.cipher.ctr_omac().is_some()).map(|s| s.name).collect();
        assert_eq!(ctr_omac, vec!["TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
                                  "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"]);
        let cnt_imit: Vec<u16> = gost.iter()
            .filter(|s| s.cipher == BulkCipher::Gost28147Cnt)
            .map(|s| s.code).collect();
        assert_eq!(cnt_imit, vec![0xc102, 0xff85]);
    }

    /// The two CNT_IMIT code points are one suite.
    ///
    /// RFC 9189 section 10 says 0xFF85 *indicates* the suite that
    /// 0xC102 indicates - not something like it - so every field but
    /// the code and the names has to match. Written as a comparison
    /// rather than as two lists of expected values, because two lists
    /// drift apart one edit at a time and this cannot.
    #[test]
    fn test_the_two_cnt_imit_code_points_agree() {
        let iana = by_code(0xc102).expect("the IANA code point");
        let legacy = by_code(0xff85).expect("the private-use code point");
        assert_eq!(iana.key_exchange, legacy.key_exchange);
        assert_eq!(iana.cipher, legacy.cipher);
        assert_eq!(iana.mac, legacy.mac);
        assert_eq!(iana.prf, legacy.prf);
        assert_eq!(iana.strength, legacy.strength);
        assert_eq!(iana.min_version, legacy.min_version);
        assert_ne!(iana.name, legacy.name, "two rows need two names");

        // Both are offered, because which one a box understands is
        // exactly what is not known before the handshake.
        for code in [0xc102u16, 0xff85] {
            assert!(Selection::modern().was_offered(code),
                    "0x{:04x} is not offered", code);
        }

        // And the document says this, in section 10, rather than it
        // being folklore. The sentence is matched loosely enough to
        // survive rewrapping and tightly enough to be about this.
        const RFC9189: &str = include_str!("../../rfcs/rfc9189.txt");
        let flat = RFC9189.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("use the old value {0xFF, 0x85} instead of the \
                               {0xC1, 0x02} value to indicate the \
                               TLS_GOSTR341112_256_WITH_28147_CNT_IMIT cipher \
                               suite".split_whitespace().collect::<Vec<_>>()
                              .join(" ").as_str()),
                "RFC 9189 no longer says what this row is for");
    }

    /// OpenSSL's old spelling of the CNT_IMIT suite still finds it.
    #[test]
    fn test_the_superseded_openssl_name_still_resolves() {
        assert_eq!(by_name("GOST2012-GOST8912-GOST8912").map(|s| s.code),
                   Some(0xc102));
        assert_eq!(by_name("IANA-GOST2012-GOST8912-GOST8912").map(|s| s.code),
                   Some(0xc102));
        assert_eq!(by_name("LEGACY-GOST2012-GOST8912-GOST8912").map(|s| s.code),
                   Some(0xff85));
        // The alias table must not shadow a suite's own name.
        for suite in ALL {
            assert_eq!(by_name(suite.name).map(|s| s.code), Some(suite.code),
                       "{} does not resolve to itself", suite.name);
        }
    }
}
