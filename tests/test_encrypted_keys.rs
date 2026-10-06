/*!
Encrypted PKCS#8 private keys, against files a real OpenSSL wrote.

Every fixture in `tests/keys/` was produced by `openssl pkcs8 -topk8` on
the development machine, and each one decrypts to the plain key sitting
beside it. That is the whole shape of the test: not "our decryptor agrees
with our encryptor" but "somebody else's encryptor produced this, and we
get the original back". The encryptor is checked the same way round:
given each file's salt, count and IV, it has to write OpenSSL's file
again, byte for byte.

## Why the fixtures are pinned rather than regenerated

Because the command that made them is already failing.

Measured on this machine, OpenSSL 3.0.13, September 2026:

  * `-v2 aes-*-cbc`, `-v2 des-ede3-cbc` and `-v1 PBE-SHA1-3DES` work
    from the default provider.
  * `-v1 PBE-MD5-DES`, `-v1 PBE-SHA1-DES`, `-v1 PBE-MD5-RC2-64`,
    `-v1 PBE-SHA1-RC2-40`, `-v1 PBE-SHA1-RC4-128`, `-v2 des-cbc` and
    `-v2 rc2-cbc` need `-provider legacy` and produce a silently empty
    file without it.

`python-cryptography` 46 has gone further: it reads PBES2, the PKCS#12
schemes and `pbeWithMD5AndDES-CBC`, and refuses `pbeWithSHA1AndDES-CBC`
and `pbeWithMD5AndRC2-CBC` with "Unknown key encryption algorithm" - for
OIDs in the standard it implements.

A test that regenerated these would therefore start skipping rows, one
distribution upgrade at a time, and a skipped row looks exactly like a
passing one on the summary line. The files are checked in so that the
day OpenSSL drops the legacy provider entirely, this suite still proves
the keys can be read - which is the entire point of the library.
*/

use allcrypt::x509::private_key::{self, PrivateKey};

const PASSWORD: &[u8] = b"secret";

/// The fixtures, each with the scheme it exercises.
///
/// Named rather than globbed so that a file failing to be added is a
/// compile error here, not a quietly shorter run.
const RSA_FIXTURES: &[(&str, &str, &str)] = &[
    // PBES2 - RFC 8018 A.4, PBKDF2 and a named cipher in CBC.
    ("rsa_pbes2_aes128.pem", include_str!("keys/rsa_pbes2_aes128.pem"),
     "PBES2, AES-128-CBC"),
    ("rsa_pbes2_aes192.pem", include_str!("keys/rsa_pbes2_aes192.pem"),
     "PBES2, AES-192-CBC"),
    ("rsa_pbes2_aes256.pem", include_str!("keys/rsa_pbes2_aes256.pem"),
     "PBES2, AES-256-CBC"),
    ("rsa_pbes2_3des.pem", include_str!("keys/rsa_pbes2_3des.pem"),
     "PBES2, DES-EDE3-CBC"),
    ("rsa_pbes2_des.pem", include_str!("keys/rsa_pbes2_des.pem"),
     "PBES2, single DES - legacy provider only"),
    ("rsa_pbes2_rc2.pem", include_str!("keys/rsa_pbes2_rc2.pem"),
     "PBES2, RC2-CBC with its own parameter version - legacy provider only"),

    // The PBKDF2 PRF, which is absent in older files and means SHA-1.
    ("rsa_pbes2_aes256_prf_sha1.pem",
     include_str!("keys/rsa_pbes2_aes256_prf_sha1.pem"), "PBES2, PRF SHA-1"),
    ("rsa_pbes2_aes256_prf_sha256.pem",
     include_str!("keys/rsa_pbes2_aes256_prf_sha256.pem"), "PBES2, PRF SHA-256"),
    ("rsa_pbes2_aes256_prf_sha512.pem",
     include_str!("keys/rsa_pbes2_aes256_prf_sha512.pem"), "PBES2, PRF SHA-512"),

    // PBES1 - RFC 8018 A.3, PBKDF1 and a 64 bit cipher.
    ("rsa_pbes1_md5_des.pem", include_str!("keys/rsa_pbes1_md5_des.pem"),
     "PBES1, pbeWithMD5AndDES-CBC"),
    ("rsa_pbes1_md5_rc2.pem", include_str!("keys/rsa_pbes1_md5_rc2.pem"),
     "PBES1, pbeWithMD5AndRC2-CBC - python-cryptography refuses this OID"),
    ("rsa_pbes1_sha1_des.pem", include_str!("keys/rsa_pbes1_sha1_des.pem"),
     "PBES1, pbeWithSHA1AndDES-CBC - python-cryptography refuses this OID"),

    // The PKCS#12 PBEs - RFC 7292 B, a third key derivation entirely.
    ("rsa_pkcs12_sha1_3des.pem", include_str!("keys/rsa_pkcs12_sha1_3des.pem"),
     "PKCS#12, SHA-1 and 3DES - what `-v1` still writes by default"),
    ("rsa_pkcs12_sha1_rc2_40.pem", include_str!("keys/rsa_pkcs12_sha1_rc2_40.pem"),
     "PKCS#12, SHA-1 and 40 bit RC2"),
    ("rsa_pkcs12_sha1_rc4_128.pem", include_str!("keys/rsa_pkcs12_sha1_rc4_128.pem"),
     "PKCS#12, SHA-1 and RC4 - a stream cipher, so no padding to check"),
];

const EC_FIXTURES: &[(&str, &str, &str)] = &[
    ("ec_pbes2_aes256.pem", include_str!("keys/ec_pbes2_aes256.pem"),
     "PBES2, AES-256-CBC, P-256 key"),
    ("ec_pkcs12_sha1_3des.pem", include_str!("keys/ec_pkcs12_sha1_3des.pem"),
     "PKCS#12, SHA-1 and 3DES, P-256 key"),
];

fn rsa_plain() -> PrivateKey {
    private_key::from_pem(include_str!("keys/rsa_plain.pem"))
        .expect("the unencrypted RSA fixture does not parse")
}

fn ec_plain() -> PrivateKey {
    private_key::from_pem(include_str!("keys/ec_plain.pem"))
        .expect("the unencrypted EC fixture does not parse")
}

/// Two keys are the same key.
///
/// Compared on the private material rather than on a formatted string,
/// so that a decryption producing a *structurally valid but different*
/// key fails here rather than passing.
fn same_key(left: &PrivateKey, right: &PrivateKey) -> bool {
    match (left, right) {
        (PrivateKey::Rsa { p: p1, q: q1, e: e1 },
         PrivateKey::Rsa { p: p2, q: q2, e: e2 }) => p1 == p2 && q1 == q2 && e1 == e2,
        (PrivateKey::Ec { curve: c1, private: k1 },
         PrivateKey::Ec { curve: c2, private: k2 }) => c1 == c2 && k1 == k2,
        _ => false,
    }
}

#[test]
fn test_every_rsa_scheme_gives_back_the_original_key() {
    let want = rsa_plain();
    for (name, pem, scheme) in RSA_FIXTURES {
        let got = private_key::from_pem_with_password(pem, Some(PASSWORD))
            .unwrap_or_else(|reason| panic!("{} ({}): {}", name, scheme, reason));
        assert!(same_key(&got, &want),
                "{} ({}) decrypted to a different key", name, scheme);
    }
}

#[test]
fn test_every_ec_scheme_gives_back_the_original_key() {
    let want = ec_plain();
    for (name, pem, scheme) in EC_FIXTURES {
        let got = private_key::from_pem_with_password(pem, Some(PASSWORD))
            .unwrap_or_else(|reason| panic!("{} ({}): {}", name, scheme, reason));
        assert!(same_key(&got, &want),
                "{} ({}) decrypted to a different key", name, scheme);
    }
}

/// **The check the rest of the file is worthless without.**
///
/// None of these schemes is authenticated, so a wrong password decrypts
/// to random bytes rather than failing. If that were accepted, every
/// test above would pass against an implementation that ignored the
/// password entirely. The padding check is what makes a wrong password
/// an error, and this is what proves the padding check is there.
#[test]
fn test_a_wrong_password_is_refused_for_every_scheme() {
    for (name, pem, scheme) in RSA_FIXTURES.iter().chain(EC_FIXTURES) {
        let result = private_key::from_pem_with_password(pem, Some(b"wrong"));
        assert!(result.is_err(),
                "{} ({}) accepted the wrong password and returned a key", name, scheme);
    }
}

/// A password that differs by one byte, and one that is a prefix.
///
/// The wrong password above is a different length as well as different
/// content; these two rule out an implementation that only compares
/// lengths, or that truncates.
#[test]
fn test_a_nearly_right_password_is_refused() {
    let pem = include_str!("keys/rsa_pbes2_aes256.pem");
    for wrong in [&b"secrew"[..], &b"secre"[..], &b"secrett"[..], &b"Secret"[..],
                  &b"secret "[..], &b" secret"[..]] {
        assert!(private_key::from_pem_with_password(pem, Some(wrong)).is_err(),
                "{:?} was accepted in place of the password", wrong);
    }
}

/// An encrypted key with no password names the remedy.
#[test]
fn test_an_encrypted_key_without_a_password_says_so() {
    let pem = include_str!("keys/rsa_pbes2_aes256.pem");
    let reason = private_key::from_pem(pem).expect_err("parsed without a password");
    assert!(reason.contains("encrypted"),
            "the error should name encryption as the problem, not the parse: {}", reason);
    assert!(reason.contains("passphrase") || reason.contains("password"),
            "the error should name the remedy: {}", reason);
}

/// A password given for a key that is not encrypted is ignored.
///
/// A caller that always has a passphrase to hand should not have to know
/// which of its files used one.
#[test]
fn test_a_password_on_an_unencrypted_key_is_ignored() {
    let got = private_key::from_pem_with_password(
        include_str!("keys/rsa_plain.pem"), Some(b"not needed")).unwrap();
    assert!(same_key(&got, &rsa_plain()));
}

/// The empty password, which PBES2 and PKCS#12 disagree about.
///
/// PBES2 hashes the password bytes, so empty is zero bytes and there is
/// nothing to decide. PKCS#12 hashes a BMPString, where empty could be
/// zero bytes or the two NUL bytes of an empty string. OpenSSL's API
/// given a NULL password hashes the first; the `openssl` command, which
/// wrote this fixture, and other implementations hash the second
/// (`test_reencrypting_openssls_files_reproduces_them` shows which). Both
/// are tried.
#[test]
fn test_the_empty_password_works_in_both_families() {
    let want = rsa_plain();
    for (name, pem) in [
        ("PBES2", include_str!("keys/rsa_pbes2_aes256_empty_password.pem")),
        ("PKCS#12", include_str!("keys/rsa_pkcs12_sha1_3des_empty_password.pem")),
    ] {
        let got = private_key::from_pem_with_password(pem, Some(b""))
            .unwrap_or_else(|reason| panic!("{} with an empty password: {}", name, reason));
        assert!(same_key(&got, &want), "{} empty password gave a different key", name);
    }
}

/// A non-ASCII password, which is where the BMPString encoding bites.
///
/// PBES2 hashes the UTF-8 bytes; PKCS#12 hashes UTF-16 big endian. An
/// implementation that used one encoding for both opens the ASCII files
/// and none of these, which is a failure that only appears once somebody
/// outside the ASCII range tries to use it.
#[test]
fn test_a_non_ascii_password_works_in_both_families() {
    let want = rsa_plain();
    let password = "pässwörd ünïcode".as_bytes();
    for (name, pem) in [
        ("PBES2", include_str!("keys/rsa_pbes2_aes256_unicode_password.pem")),
        ("PKCS#12", include_str!("keys/rsa_pkcs12_sha1_3des_unicode_password.pem")),
    ] {
        let got = private_key::from_pem_with_password(pem, Some(password))
            .unwrap_or_else(|reason| panic!("{} with a non-ASCII password: {}", name, reason));
        assert!(same_key(&got, &want), "{} gave a different key", name);
    }
}

/// DER as well as PEM, since a DER file has no label to go on.
#[test]
fn test_an_encrypted_key_is_recognised_as_der_without_a_label() {
    let blocks = allcrypt::pem::parse(
        include_str!("keys/rsa_pbes2_aes256.pem")).unwrap();
    let der = &blocks[0].contents;

    assert!(allcrypt::x509::encrypted_key::looks_encrypted(der),
            "the DER was not recognised as encrypted");
    let got = private_key::from_der_with_password(der, Some(PASSWORD)).unwrap();
    assert!(same_key(&got, &rsa_plain()));

    // And the negative: a plain key must not be mistaken for an
    // encrypted one, or every unencrypted file starts demanding a
    // password.
    let plain = allcrypt::pem::parse(include_str!("keys/rsa_plain.pem")).unwrap();
    assert!(!allcrypt::x509::encrypted_key::looks_encrypted(&plain[0].contents),
            "an unencrypted key was taken for an encrypted one");
}

/// Truncation at every offset is an error, never a panic.
///
/// The same property the other parsers are held to. An encrypted key has
/// more places to go wrong than a plain one - two nested
/// AlgorithmIdentifiers, an optional integer and an optional sequence -
/// and a panic here is reachable from a file somebody was sent.
#[test]
fn test_truncation_at_every_offset_is_an_error_not_a_panic() {
    let blocks = allcrypt::pem::parse(
        include_str!("keys/rsa_pbes2_aes256.pem")).unwrap();
    let der = &blocks[0].contents;
    for length in 0..der.len() {
        let _ = private_key::from_der_with_password(&der[..length], Some(PASSWORD));
        let _ = allcrypt::x509::encrypted_key::looks_encrypted(&der[..length]);
    }
}

/// Every single byte flipped in the algorithm identifier is an error,
/// never a panic.
///
/// Truncation only exercises short reads. This exercises wrong values:
/// an unknown OID, an iteration count of zero, a salt of the wrong
/// length, an IV that does not match the cipher.
#[test]
fn test_corruption_in_the_parameters_is_an_error_not_a_panic() {
    let blocks = allcrypt::pem::parse(
        include_str!("keys/rsa_pbes2_aes256.pem")).unwrap();
    let der = &blocks[0].contents;
    // The header is comfortably within the first 80 bytes for every
    // scheme here; the rest is ciphertext, where a flip only changes
    // the plaintext.
    for index in 0..core::cmp::min(80, der.len()) {
        for bit in 0..8 {
            let mut broken = der.clone();
            broken[index] ^= 1 << bit;
            let _ = private_key::from_der_with_password(&broken, Some(PASSWORD));
        }
    }
}

/// An unsupported scheme says which scheme, by its dotted OID.
///
/// "Unsupported" with no name sends the reader to the source; the OID
/// is searchable and tells them what wrote the file.
///
/// **This caught a real one.** `looks_encrypted` originally matched the
/// scheme OID against the supported list, so a key encrypted with
/// anything else was not recognised as encrypted at all: it fell
/// through to the three plain parsers and came back "not PKCS#8; not
/// SEC1 EC; not PKCS#1 RSA". Every other test here passed, because they
/// all use schemes that *are* supported. Recognition is structural now
/// and the refusal happens at the scheme, where it can name it.
#[test]
fn test_an_unknown_scheme_is_named_in_the_error() {
    let blocks = allcrypt::pem::parse(
        include_str!("keys/rsa_pbes2_aes256.pem")).unwrap();
    let der = &blocks[0].contents;

    // The PBES2 OID is 1.2.840.113549.1.5.13; its last byte is the 13.
    // Changing it to 99 makes an OID nothing defines.
    let position = der.windows(allcrypt::x509::oids::PBES2.len())
        .position(|window| window == allcrypt::x509::oids::PBES2)
        .expect("the PBES2 OID is not in the fixture");
    let mut broken = der.clone();
    let last = position + allcrypt::x509::oids::PBES2.len() - 1;
    broken[last] = 99;

    let reason = private_key::from_der_with_password(&broken, Some(PASSWORD))
        .expect_err("an undefined scheme OID was accepted");
    assert!(reason.contains("99") || reason.contains("scheme") || reason.contains("OID"),
            "the error does not identify the scheme: {}", reason);
}

/// Re-encrypting each of OpenSSL's files with its own salt, count and IV
/// writes the file again, byte for byte - every scheme, the empty and the
/// non-ASCII passwords included. This is what settles the encoding
/// choices a round trip cannot: the PRF left out for SHA-1, `keyLength`
/// present for RC2 only, RC2's parameter version, and which bytes the
/// empty PKCS#12 password hashes.
#[test]
fn test_reencrypting_openssls_files_reproduces_them() {
    use allcrypt::x509::encrypted_key::{decrypt, encrypt, parameters};
    let unicode = "pässwörd ünïcode".as_bytes();
    let extra: &[(&str, &str, &[u8])] = &[
        ("rsa_pbes2_aes256_empty_password.pem",
         include_str!("keys/rsa_pbes2_aes256_empty_password.pem"), b""),
        ("rsa_pkcs12_sha1_3des_empty_password.pem",
         include_str!("keys/rsa_pkcs12_sha1_3des_empty_password.pem"), b""),
        ("rsa_pbes2_aes256_unicode_password.pem",
         include_str!("keys/rsa_pbes2_aes256_unicode_password.pem"), unicode),
        ("rsa_pkcs12_sha1_3des_unicode_password.pem",
         include_str!("keys/rsa_pkcs12_sha1_3des_unicode_password.pem"), unicode),
    ];
    let fixtures = RSA_FIXTURES.iter().chain(EC_FIXTURES)
        .map(|(name, pem, _)| (*name, *pem, PASSWORD))
        .chain(extra.iter().map(|(name, pem, pw)| (*name, *pem, *pw)));
    let mut count = 0;
    for (name, pem, password) in fixtures {
        let der = allcrypt::pem::parse(pem).unwrap().remove(0).contents;
        let p = parameters(&der).unwrap_or_else(|e| panic!("{name}: {e}"));
        let plain = decrypt(&der, password).unwrap();
        let prf = if p.scheme.starts_with("pbe-") { None } else { p.prf };
        let again = encrypt(&plain, password, p.scheme, prf, p.iterations, &p.salt, &p.iv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(again == der, "{name} ({}) is not reproduced", p.scheme);
        count += 1;
    }
    assert_eq!(count, 21);
}

/// Every scheme round-trips, including the ones no fixture has - the
/// PKCS#12 two-key Triple DES and 128-bit RC2 and 40-bit RC4, PBES1 with
/// MD2, and PBES2 with 40- and 64-bit RC2 - at lengths either side of a
/// block, and a wrong password does not give the key back.
#[test]
fn test_every_scheme_round_trips() {
    use allcrypt::x509::encrypted_key::{decrypt, encrypt, parameters, scheme_names};
    for scheme in scheme_names() {
        let iv_len = match scheme {
            s if s.starts_with("pbe-") => 0,
            s if s.starts_with("aes") => 16,
            _ => 8,
        };
        let prf = if scheme.starts_with("pbe-") { None } else { Some("sha512") };
        // An empty RC4 ciphertext is refused on reading as no key at
        // all, so the stream cipher starts at one byte.
        let shortest = usize::from(scheme.contains("rc4"));
        for length in [0usize, 1, 15, 16, 17, 100].into_iter().filter(|&l| l >= shortest) {
            let plain: Vec<u8> = (0..length).map(|i| (i * 7) as u8).collect();
            let der = encrypt(&plain, "pä".as_bytes(), scheme, prf, 3, &[9; 8],
                              &vec![4; iv_len]).unwrap();
            assert_eq!(parameters(&der).unwrap().scheme, scheme);
            assert_eq!(decrypt(&der, "pä".as_bytes()).unwrap(), plain, "{scheme} {length}");
            if let Ok(wrong) = decrypt(&der, b"pa") {
                assert_ne!(wrong, plain, "{scheme} {length}");
            }
        }
    }
    assert_eq!(scheme_names().len(), 20);
}

#[test]
fn test_encrypt_refuses_what_it_cannot_write() {
    use allcrypt::x509::encrypted_key::encrypt;
    assert!(encrypt(b"k", b"pw", "aes-256-ctr", None, 1, &[0; 8], &[0; 16]).is_err());
    // Both of these would fail further down too - CBC refuses the IV and
    // PBKDF2 a count of zero - so the messages are pinned to show the
    // checks here are the ones refusing.
    let short_iv = encrypt(b"k", b"pw", "aes-256-cbc", None, 1, &[0; 8], &[0; 8]).unwrap_err();
    assert!(short_iv.contains("takes a 16-byte IV"), "{short_iv}");
    let zero = encrypt(b"k", b"pw", "pbe-sha1-3des", None, 0, &[0; 8], &[]).unwrap_err();
    assert!(zero.contains("key encryption scheme"), "{zero}");
    assert!(encrypt(b"k", b"pw", "aes-256-cbc", Some("md5"), 1, &[0; 8], &[0; 16]).is_err());
    assert!(encrypt(b"k", b"pw", "pbe-md5-des", None, 1, &[0; 7], &[]).is_err());
    assert!(encrypt(b"k", b"pw", "pbe-md5-des", Some("sha1"), 1, &[0; 8], &[]).is_err());
    assert!(encrypt(b"k", b"pw", "pbe-sha1-3des", None, 1, &[0; 8], &[0; 8]).is_err());
}
