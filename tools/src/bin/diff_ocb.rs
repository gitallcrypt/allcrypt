// OCB output dumped for comparison against OpenSSL, via scripts/diff_check.py.
//
// RFC 7253's appendix is in the unit tests: seventeen samples, the
// internal values of one, and the iterated vector for all nine AES
// parameter sets. What this adds is breadth where OCB changes shape:
//
//   * every message and associated-data length either side of the block
//     boundaries, where the partial block takes its own branch (`L_*`,
//     the `1 || 0...` padding, the keystream from `E(Offset_*)`);
//   * every value of the nonce's low six bits (`bottom`), which picks the
//     window into `Stretch` - the last nonce byte steps with the case;
//   * every nonce length OpenSSL takes, 12 to 15 bytes, since the length
//     moves the `1` bit above the nonce;
//   * enough blocks to reach `L_5`, where `ntz` stops being small.
//
// Ciphertext and tag both, and the tag is over the plaintext's checksum,
// so a broken checksum shows in the tag alone.

use allcrypt::block_ciphers::ocb::Ocb;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 61 + seed as u32 * 37 + 11) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;
    let lengths: Vec<usize> = (0..=80).chain([96, 127, 128, 129, 255, 256, 257, 511, 1000, 4096])
        .collect();
    for key_len in [16usize, 24, 32] {
        let key = filler(key_len, 1);
        let mut ocb = Ocb::new("aes", &key).unwrap();
        for nonce_len in [12usize, 13, 14, 15] {
            for aad_len in [0usize, 1, 15, 16, 17, 32, 61] {
                let aad = filler(aad_len, 3);
                for &len in &lengths {
                    if len > 80 && aad_len != 16 {
                        continue;
                    }
                    let mut nonce = filler(nonce_len, 2);
                    *nonce.last_mut().unwrap() = cases as u8;
                    let plaintext = filler(len, 4);
                    let (ciphertext, tag) = ocb.encrypt(&nonce, &aad, &plaintext).unwrap();
                    let back = ocb.decrypt(&nonce, &aad, &ciphertext, &tag).unwrap();
                    assert_eq!(back, plaintext, "round trip");
                    println!("ocb {} {} {} {} {} {}", hex(&key), hex(&nonce), hex(&aad),
                             hex(&plaintext), hex(&ciphertext), hex(&tag));
                    cases += 1;
                }
            }
        }
    }
    eprintln!("{} OCB cases, every one round tripped", cases);
}
