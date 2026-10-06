// GCM output dumped for comparison against OpenSSL, via scripts/diff_check.py.
//
// The specification's own vectors are already in the unit tests, and they
// are not enough: there are six of them, the longest plaintext is 60 bytes,
// and between them they exercise three distinct additional-data lengths.
// None of that reaches the cases where an implementation usually breaks -
// a partial block at the end of the ciphertext, additional data whose
// length is a multiple of the block size versus one byte more, a plaintext
// that crosses the point where the counter's low byte carries.
//
// So: every length from 0 to 80, then a spread of larger ones, crossed with
// three key sizes, several additional-data lengths and three nonce lengths
// (the 96 bit case that skips GHASH for J0, and two that do not).
//
// Both the ciphertext and the tag go in the dump. A checker that compared
// only the ciphertext would pass with GHASH completely broken, since the
// keystream does not depend on it.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::BlockCipher;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Deterministic filler, so the dump is reproducible and the checker needs
/// to carry only the lengths.
fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 61 + seed as u32 * 37 + 11) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    let lengths: Vec<usize> = (0..=80)
        .chain([96, 127, 128, 129, 255, 256, 257, 511, 1000, 4096])
        .collect();

    for key_len in [16usize, 24, 32] {
        let key = filler(key_len, 1);

        for nonce_len in [12usize, 8, 16, 60] {
            let nonce = filler(nonce_len, 2);

            for aad_len in [0usize, 1, 15, 16, 17, 32, 61] {
                let aad = filler(aad_len, 3);

                for &len in &lengths {
                    // Keep the dump to a sensible size: the long plaintexts
                    // only need one nonce and one aad length, since what
                    // they are testing is the counter, not the padding.
                    if len > 80 && (nonce_len != 12 || aad_len != 16) {
                        continue;
                    }
                    let plaintext = filler(len, 4);

                    let mut cipher = AesCrypto::new(key.clone()).unwrap();
                    let mut ciphertext = Vec::new();
                    let mut tag = Vec::new();
                    cipher.gcm_encrypt(&plaintext, &mut ciphertext, &nonce,
                                       &mut tag, &aad).unwrap();

                    // And straight back, so the dump also records that our
                    // own decryption agrees with our own encryption. The
                    // checker still compares both against OpenSSL.
                    let mut cipher = AesCrypto::new(key.clone()).unwrap();
                    let mut recovered = Vec::new();
                    cipher.gcm_decrypt(&ciphertext, &mut recovered, &nonce,
                                       &tag, &aad).unwrap();
                    assert_eq!(recovered, plaintext, "round trip");

                    println!("gcm {} {} {} {} {} {}",
                             hex(&key), hex(&nonce), hex(&aad),
                             hex(&plaintext), hex(&ciphertext), hex(&tag));
                    cases += 1;
                }
            }
        }
    }

    eprintln!("[diff_gcm] {} GCM cases written", cases);
}
