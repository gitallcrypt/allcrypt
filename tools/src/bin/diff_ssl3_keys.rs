// SSLv3's key schedule and Finished, dumped for comparison against a
// reference written from RFC 6101.
//
// This corpus exists because **nothing on this machine can check it**.
// OpenSSL removed SSLv3 and is built without it here - `ssl.HAS_SSLv3` is
// False - so there is no second implementation to hand. The reference in
// scripts/diff_check.py is written from the specification's text in a
// different language, which is the strongest check available and weaker
// than the usual one; the commit that adds it says so.
//
// What is dumped, and why each is a place to go wrong:
//
//   * the master secret, whose expansion puts the secret in twice per
//     round and salts with a repeated letter - `A`, `BB`, `CCC` - rather
//     than a counter;
//   * the key block, which uses the same expansion with the two randoms
//     the *other* way round;
//   * Finished, 36 bytes rather than 12, built from the transcript's
//     running state with pad lengths that differ per hash: 48 for MD5 and
//     40 for SHA-1.
//
// Every one of those is a mistake both ends of a handshake could make
// together and never notice.
use allcrypt::tls::keys::{key_block, master_secret, Side, Transcript};
use allcrypt::tls::suites;
use allcrypt::tls::Version;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 73 + seed as u32 * 29 + 5) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    // Premaster lengths: 48 is the RSA one, and the others are what an
    // ephemeral key exchange produces - a shared secret whose length is
    // the group's, not a fixed 48.
    for (index, premaster_len) in [48usize, 32, 20, 128, 256].iter().enumerate() {
        let premaster = filler(*premaster_len, index as u8 + 1);
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];
        client_random.copy_from_slice(&filler(32, index as u8 + 10));
        server_random.copy_from_slice(&filler(32, index as u8 + 20));

        let master = master_secret(Version::SSL30, suites::MacAlgorithm::Sha256,
                                   &premaster, &client_random, &server_random)
            .unwrap();
        assert_eq!(master.len(), 48, "a master secret is 48 bytes in every version");

        println!("master {} {} {} {}", hex(&premaster), hex(&client_random),
                 hex(&server_random), hex(&master));
        cases += 1;

        // A key block for each suite shape SSLv3 has: the MAC length, the
        // key length and the IV length all come from the suite, and the
        // expansion has to produce exactly their sum.
        for name in ["TLS_RSA_WITH_AES_128_CBC_SHA",
                     "TLS_RSA_WITH_AES_256_CBC_SHA",
                     "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                     "TLS_RSA_WITH_DES_CBC_SHA",
                     "TLS_RSA_WITH_RC4_128_MD5",
                     "TLS_RSA_WITH_RC4_128_SHA",
                     "TLS_RSA_WITH_NULL_MD5"] {
            let suite = suites::by_name(name).unwrap();
            let block = key_block(Version::SSL30, suite, &master,
                                  &client_random, &server_random).unwrap();
            println!("keyblock {} {} {} {} {} {} {} {} {}",
                     name, hex(&master), hex(&client_random), hex(&server_random),
                     hex(&block.client.mac_key), hex(&block.server.mac_key),
                     hex(&block.client.key), hex(&block.server.key),
                     hex(&block.client.iv));
            // The server IV goes on its own line to keep the columns
            // countable; a nine column line is already at the limit of
            // what anybody will read.
            println!("keyblockiv {} {}", name, hex(&block.server.iv));
            cases += 1;
        }

        // Finished, over transcripts of several lengths. The transcript is
        // fed raw handshake bytes, so any bytes will do here - what is
        // being checked is the construction around them.
        for transcript_len in [0usize, 1, 64, 1000] {
            let messages = filler(transcript_len, index as u8 + 30);
            let mut transcript =
                Transcript::new(Version::SSL30, suites::MacAlgorithm::Sha256).unwrap();
            transcript.update(&messages);

            for side in [Side::Client, Side::Server] {
                let finished = transcript.ssl3_finished(&master, side).unwrap();
                assert_eq!(finished.len(), 36, "SSLv3's Finished is 36 bytes");
                println!("finished {} {} {} {}",
                         if side == Side::Client { "client" } else { "server" },
                         hex(&master), hex(&messages), hex(&finished));
                cases += 1;
            }

            // The two sides must differ, or the sender constant is not
            // reaching the hash - which no round trip would notice,
            // because each side checks the other's.
            assert_ne!(transcript.ssl3_finished(&master, Side::Client).unwrap(),
                       transcript.ssl3_finished(&master, Side::Server).unwrap(),
                       "client and server Finished are identical");
        }
    }

    eprintln!("{} SSLv3 key schedule cases", cases);
}
