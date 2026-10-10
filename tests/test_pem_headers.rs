/*!
PEM blocks with RFC 1421 encapsulated headers, and bundles with a block
that does not decode.

`TRADITIONAL_ENCRYPTED_KEY` is the output of

    openssl rsa -in tests/keys/rsa_plain.pem -aes128 \
        -passout pass:correct-horse -traditional

on OpenSSL 3.0.13: the "traditional" format, whose encryption is
announced by `Proc-Type` and `DEK-Info` header lines inside the block
rather than by a PKCS#8 wrapper. The parser used to append every line
between BEGIN and END to the base64 body, so this file failed with
"Character ':' is not base64", and a bundle that carried one such key
beside its certificates lost every certificate with it. Every fixture
in `tests/keys/` is PKCS#8 or a certificate, so no existing test held
a header line.
*/

use allcrypt::pem;
use allcrypt::trust::TrustStore;

const TRADITIONAL_ENCRYPTED_KEY: &str = "\
-----BEGIN RSA PRIVATE KEY-----\n\
Proc-Type: 4,ENCRYPTED\n\
DEK-Info: AES-128-CBC,A85E41DFF861CD72E5A1DE07C0675FB4\n\
\n\
iXTStVryf/c0dmMX+3BTdAyJqxdsZBY4xayzfLDn7aaeIJxnDbEoQBZ7DBi9j+jC\n\
Zqtj6ZIuhs65alQROL64GixcuYLiClyZWpRF/SOsFZmWtU5NYO7xp3Arc2jsX/DE\n\
FycfFxGVjq5Xb7O9/mYftG5PiigKFkYazmD7y2GgB77bEQpCL+NcEl8KonCvvAhb\n\
d/NwB6Vk2MzoQJRdXNYQDm9DhR4tCXnkDAPKCb8vl6wbb8vV3/XPJJmFYIxFmRiH\n\
h1k1wYmgaMaPeBNBGQ2kALaAnigoObQAilBgACxPaJ7zgvpfZw0BUpGoM7SwZvO/\n\
kROoxzWyyzURaNwZbASLo9HxDe+jdlKpK2yyaAoXJPZjFSDa8FZO6ngEF/fDRQ88\n\
38v6+VUJyfH/ggdPn8/Zk603OjyoutfrQVoZJX2w6QjaN2ax5AZeC9rycoPsVGPL\n\
PN2nyIUREzMEPk47rowklGBRiAoqEpPUQNJEHpRRUlWP6WG7glm6Am6h3gWpWr8P\n\
ThDTMShk0UumZGId6dohbybTZZBn1iNAhUSZF2dJE1jYiiZaF2OCOh0s4onNuuj+\n\
rNe0nfudEsOOpNmaGC9kYM9nFBsgFzDKTbiZ1PP2q9qYgxFurltCKNco8lNey+N8\n\
hfyhKvmfgx6xanp1IMhDwYAysczF3aCDaTC2PHg/xRVVjEIEjqLmW/lScDJjg1qU\n\
xUxIpvdmzEy+cwHb18cDA8vW4Auh7ToHszjjgNC81ipSAvewHnvSOPN0lFhThV/j\n\
62UN9HUjQMGr80c9QGJlZQ03jc+V8a3fcwd/0hZxfnYU1nXairOvGM7TADggb9vg\n\
mp1Nk4LK6cP0IwJnvBAfQuS6NnOZxetd6B3xb485lf+R9WNDPUBQUYsqdXAXACpU\n\
At/81jqMO0p8xArGu/kDs2XTRuA8q2LPBazi3KTJ4KDiIrEjbaG+KgYsreKKfhSA\n\
/F/o4GiPrjNCoSRtL+tbw5Fs9mhNflUQB96VfnhX/BME8DY4TW9+UzewKdKRPwCa\n\
RXCoCb9jt6fCA9DtjddqUt+uIM66QW9lM7wFe+8UFiucHNCwd2MzEzKJzBJ2rJoc\n\
Hkh4+FUQ8r8Kno4KpK4Lkz5zoSJYBCafI31h16gy/tZgg76g+wir9evaokNGw6dR\n\
YNlfT6E316xdcXEJDPvLVfyC5fKIoC2LxhvEZ73Y+Swg8ALyt33pStQ4C3iRLdmX\n\
Y3vcpxb0pfwFLAd/4mddqtd7Co3ETGuGSAhz3QQarZN1ScuXo3adW0yttb6ZFa83\n\
roxZNNSCzxuQBvzTsUeXDXvExjOHv2MfahLUbm4c8q/2wgJkAZvdaU4P8S3v34GK\n\
cveJbXGAnLCSoO8FC9OLWYvr2cuTbTqFy0E+Vwjh3M8sGrWgRYsM9Z0JNf55++oT\n\
wEkWaoOGezoSuEQWtcYe+r3IXHxyDSekgrgucpyudVqi2eW4MD+sMymvoye3L6jI\n\
LvMy4l6Ala+C6YQOjshcNQw/xjYctsNmUbspcFhMrWBKzapPB+4Rf2aKvXW0LJ7S\n\
gY+DC10BlN2s7VjNWRnO9KSouuiQq3VlF3ZLqIdQOvjdlBvgzGsvtPUnQ3d4adW/\n\
-----END RSA PRIVATE KEY-----\n\
";

#[test]
fn test_an_openssl_traditional_encrypted_key_parses() {
    let blocks = pem::parse(TRADITIONAL_ENCRYPTED_KEY).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].label, "RSA PRIVATE KEY");
    assert_eq!(blocks[0].header("Proc-Type"), Some("4,ENCRYPTED"));
    let dek = blocks[0].header("DEK-Info").unwrap();
    let (cipher, iv) = dek.split_once(',').unwrap();
    assert_eq!(cipher, "AES-128-CBC");
    assert_eq!(iv.len(), 32, "a 16 byte IV in hex");
    // The body is the ciphertext: a whole number of AES blocks, and
    // the 1192 byte PKCS#1 key padded to a block.
    assert!(blocks[0].contents.len().is_multiple_of(16) && blocks[0].contents.len() >= 1192,
            "{} bytes", blocks[0].contents.len());
}

/// A combined certificate-and-key file, HAProxy style, with the key in
/// the traditional encrypted form: a certificate source has to read the
/// certificates out of it.
#[test]
fn test_a_certificate_bundle_survives_a_block_it_cannot_decode() {
    let certificate = pem::wrap("CERTIFICATE", b"not a real certificate");
    let bundle = format!("{}{}", certificate, TRADITIONAL_ENCRYPTED_KEY);
    assert_eq!(pem::certificates(&bundle).unwrap(),
               vec![b"not a real certificate".to_vec()]);

    // The same bundle with a block whose body is not base64 at all.
    let broken = format!("{}-----BEGIN EC PARAMETERS-----\n****\n\
                          -----END EC PARAMETERS-----\n{}", certificate, certificate);
    assert_eq!(pem::certificates(&broken).unwrap().len(), 2);
    let (blocks, skipped) = pem::parse_lenient(&broken);
    assert_eq!(blocks.len(), 2);
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].label, "EC PARAMETERS");
    assert!(pem::parse(&broken).is_err(), "strict parse still refuses");

    // Through the trust store: the certificate here is not one, so it
    // is counted as skipped by `add_der`, but the call itself succeeds
    // where it used to fail on the key block.
    let mut store = TrustStore::new();
    assert_eq!(store.add_pem(&bundle).unwrap(), 0);
}
