// ChaCha20-Poly1305 output dumped for comparison against OpenSSL, via
// scripts/diff_check.py.
//
// RFC 8439's two vectors are in the unit tests. This is what they do not
// cover: every plaintext length across the 16 byte Poly1305 block boundary
// and the 64 byte ChaCha block boundary, crossed with additional-data
// lengths either side of 16 - the two paddings are where this construction
// differs from every other one, and each is only wrong for the lengths
// that are not already aligned.
//
// Both the ciphertext and the tag are compared. The keystream does not
// depend on Poly1305, so a comparison of ciphertext alone would pass with
// the authentication completely broken.

use allcrypt::stream_ciphers::chacha20poly1305::seal;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 53 + seed as u32 * 29 + 7) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    // Every length to 80 covers both block boundaries with room either
    // side; the larger ones reach past a single ChaCha block and into the
    // counter's second and third steps.
    let lengths: Vec<usize> = (0..=80)
        .chain([127, 128, 129, 191, 192, 193, 255, 256, 1000, 4096])
        .collect();

    for key_seed in [1u8, 2] {
        let key = filler(32, key_seed);
        for nonce_seed in [3u8, 4] {
            let nonce = filler(12, nonce_seed);
            for aad_len in [0usize, 1, 15, 16, 17, 32, 63] {
                let aad = filler(aad_len, 5);
                for &len in &lengths {
                    if len > 80 && (key_seed != 1 || nonce_seed != 3 || aad_len != 16) {
                        continue;
                    }
                    let plaintext = filler(len, 6);
                    let (ciphertext, tag) =
                        seal(&key, &nonce, &aad, &plaintext).unwrap();

                    println!("chachapoly {} {} {} {} {} {}",
                             hex(&key), hex(&nonce), hex(&aad),
                             hex(&plaintext), hex(&ciphertext), hex(&tag));
                    cases += 1;
                }
            }
        }
    }

    eprintln!("[diff_chachapoly] {} cases written", cases);
}
