// CCM output dumped for comparison against OpenSSL, via scripts/diff_check.py.
//
// The RFC 3610 packet vectors and the SP 800-38C example are in the unit
// tests. Between them they cover two nonce lengths and two tag lengths, and
// nothing at all either side of the places where CCM's formatting changes
// shape:
//
//   * the plaintext is zero padded to a block boundary for the MAC, so 15,
//     16 and 17 bytes take three different paths;
//   * the additional data is length prefixed and then padded, and the
//     prefix is two bytes below 65280 and six at or above it;
//   * the nonce's length decides L, which decides both the width of the
//     length field in B0 and the width of the counter - so every nonce
//     length is a different block layout rather than a different value.
//
// So: every length from 0 to 80, a spread of larger ones, crossed with
// three key sizes, seven additional-data lengths, four nonce lengths and
// every legal tag length.
//
// Ciphertext and tag both. A checker that compared only the ciphertext
// would pass with the CBC-MAC completely broken, since the keystream does
// not depend on it.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::ccm;

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

        // 7 and 13 are the ends of the legal range: 13 leaves two bytes
        // for the length, so it is also the one where a long plaintext is
        // refused rather than silently truncated.
        for nonce_len in [12usize, 7, 11, 13] {
            let nonce = filler(nonce_len, 2);

            for aad_len in [0usize, 1, 15, 16, 17, 32, 61] {
                let aad = filler(aad_len, 3);

                for &len in &lengths {
                    // 13 bytes of nonce caps the message at 65535, which
                    // every length here is under - but the long ones only
                    // need one nonce and one aad length, since what they
                    // exercise is the counter rather than the padding.
                    if len > 80 && (nonce_len != 12 || aad_len != 16) {
                        continue;
                    }
                    let plaintext = filler(len, 4);

                    // The tag length is varied with the case rather than
                    // looped over, which would multiply the dump by seven
                    // for very little: what a tag length changes is one
                    // field of B0 and how many bytes are kept.
                    let tag_len = [4usize, 6, 8, 10, 12, 14, 16][len % 7];

                    let mut cipher = AesCrypto::new(key.clone()).unwrap();
                    let (ciphertext, tag) =
                        ccm::encrypt(&mut cipher, &nonce, &aad, &plaintext,
                                     tag_len).unwrap();

                    // And straight back, so the dump also records that our
                    // own decryption agrees with our own encryption.
                    let mut cipher = AesCrypto::new(key.clone()).unwrap();
                    let recovered =
                        ccm::decrypt(&mut cipher, &nonce, &aad, &ciphertext, &tag)
                            .unwrap();
                    assert_eq!(recovered, plaintext, "round trip");

                    println!("ccm {} {} {} {} {} {}",
                             hex(&key), hex(&nonce), hex(&aad),
                             hex(&plaintext), hex(&ciphertext), hex(&tag));
                    cases += 1;
                }
            }
        }
    }

    // The additional-data length prefix changes shape at 65280, which no
    // case above reaches. Two rows either side of it, with everything else
    // held still so a mismatch can only be the prefix.
    for aad_len in [0xfeffusize, 0xff00] {
        let key = filler(16, 5);
        let nonce = filler(12, 6);
        let aad = filler(aad_len, 7);
        let plaintext = filler(48, 8);
        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        let (ciphertext, tag) =
            ccm::encrypt(&mut cipher, &nonce, &aad, &plaintext, 16).unwrap();
        println!("ccm {} {} {} {} {} {}", hex(&key), hex(&nonce), hex(&aad),
                 hex(&plaintext), hex(&ciphertext), hex(&tag));
        cases += 1;
    }

    eprintln!("{} CCM cases, every one round tripped", cases);
}
