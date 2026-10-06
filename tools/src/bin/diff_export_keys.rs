// The export suites' second key expansion, dumped for comparison against a
// reference written from RFC 2246 section 6.3.1 and RFC 6101 section 6.2.2.
//
// An export suite does not simply use a short key. The key block yields
// five bytes per direction, and those five bytes are run through the PRF
// *again* to produce a key of the cipher's real length. Forty bits of
// entropy, spread over sixteen bytes, so that the export paperwork said
// forty and the wire format did not have to change.
//
// Three things here are invisible to a round trip against ourselves,
// because both ends of a handshake would get them wrong together:
//
//   * the IVs do not come from the key block at all. They come from a
//     separate PRF pass whose secret is **empty**;
//   * the three export ciphers expand to different lengths - 16 bytes for
//     RC4_40 and RC2_CBC_40, 8 for DES40_CBC;
//   * SSLv3's version is a bare MD5 rather than a PRF, and swaps the two
//     randoms for the server direction.
//
// OpenSSL cannot check any of it: it removed the export suites in 1.1.0,
// and this build offers none. So the reference is the specification.
use allcrypt::tls::keys::key_block;
use allcrypt::tls::suites;
use allcrypt::tls::Version;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 97 + seed as u32 * 41 + 3) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    for index in 0..6u8 {
        let master = filler(48, index + 1);
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];
        client_random.copy_from_slice(&filler(32, index + 40));
        server_random.copy_from_slice(&filler(32, index + 50));

        for name in ["TLS_RSA_EXPORT_WITH_RC4_40_MD5",
                     "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
                     "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
                     "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"] {
            let suite = suites::by_name(name).unwrap();
            assert!(suite.cipher.is_exportable(), "{} is not exportable", name);

            for version in [Version::SSL30, Version::TLS10] {
                let block = key_block(version, suite, &master,
                                      &client_random, &server_random).unwrap();
                assert_eq!(block.client.key.len(), suite.cipher.expanded_key_len(),
                           "{} at {}: key not expanded", name, version.name());

                println!("export {} {} {} {} {} {} {} {} {} {}",
                         name, version.name(), hex(&master),
                         hex(&client_random), hex(&server_random),
                         hex(&block.client.mac_key), hex(&block.server.mac_key),
                         hex(&block.client.key), hex(&block.server.key),
                         hex(&block.client.iv));
                println!("exportiv {} {} {}", name, version.name(),
                         hex(&block.server.iv));
                cases += 1;

                // The two directions must differ in every field, or one of
                // the four PRF calls is being reused.
                assert_ne!(block.client.key, block.server.key,
                           "{}: both directions got the same key", name);
                if !block.client.iv.is_empty() {
                    assert_ne!(block.client.iv, block.server.iv,
                               "{}: both directions got the same IV", name);
                }
            }
        }
    }

    eprintln!("{} export key expansion cases", cases);
}
