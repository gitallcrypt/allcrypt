// ACPKM internal re-keying and CTR-ACPKM, dumped for comparison against a
// reference written from RFC 8645. Verified by scripts/diff_check.py.
//
// Nothing on this machine implements either, so the reference is a second
// reading of the specification rather than somebody else's code - the
// same claim, and the same caveat, as the GOST primitives underneath.
// What it does catch is the two things that are easy to get wrong and
// impossible to notice:
//
//   * the counter continuing across a section boundary rather than
//     restarting with the key, which disagrees with everyone and with
//     nothing local;
//   * the key changing one block early or late, which shows up as a
//     ciphertext that is correct for one section and wrong afterwards.
//
// Section sizes deliberately include one that divides the message
// exactly, one that does not, and one longer than the whole message - the
// last being plain CTR, which is the case an implementation gets right by
// accident.
//
//   acpkm <cipher> <key>  <next key>
//   ctracpkm <cipher> <key> <nonce> <section> <plaintext>  <ciphertext>
use allcrypt::block_ciphers::acpkm::{acpkm_next, ctr_acpkm};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 181 + seed as u32 * 67 + 13) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    for (name, block) in [("kuznyechik", 16usize), ("magma", 8), ("aes", 16)] {
        let key_len = if name == "aes" { 16 } else { 32 };

        for seed in 0..4u8 {
            let mut key = filler(key_len, seed + 1);

            // Several steps, because a derivation that is right once and
            // wrong when chained is a real shape of mistake.
            for _ in 0..4 {
                let next = acpkm_next(name, &key).unwrap();
                println!("acpkm {} {} {}", name, hex(&key), hex(&next));
                cases += 1;
                key = next;
            }

            let key = filler(key_len, seed + 20);
            let nonce = filler(block / 2, seed + 50);
            let message = filler(block * 9 + 5, seed + 80);

            for sections in [1usize, 2, 3, 100] {
                let section = block * sections;
                for length in [0usize, 1, block - 1, block, block + 1,
                               section, section + 1, message.len()] {
                    if length > message.len() {
                        continue;
                    }
                    let plaintext = &message[..length];
                    let ciphertext = ctr_acpkm(name, &key, &nonce, section,
                                               plaintext).unwrap();
                    assert_eq!(ctr_acpkm(name, &key, &nonce, section,
                                         &ciphertext).unwrap(),
                               plaintext, "{} does not round trip", name);

                    println!("ctracpkm {} {} {} {} {} {}", name, hex(&key),
                             hex(&nonce), section, hex(plaintext), hex(&ciphertext));
                    cases += 1;
                }
            }
        }
    }

    eprintln!("[diff_acpkm] {} cases", cases);
}
