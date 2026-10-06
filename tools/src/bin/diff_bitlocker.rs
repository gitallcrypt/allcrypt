// Dumps BitLocker sector encryption - every method, both sector sizes,
// offsets small and large - so `scripts/diff_check.py bitlocker` can redo
// it with OpenSSL's AES and the diffusers written in dm-crypt's shape.
use allcrypt::block_ciphers::bitlocker::{Method, SectorCipher};
use allcrypt::to_hex;

fn data(n: usize) -> Vec<u8> { (0..n).map(|i| ((i * 167 + 13) & 0xff) as u8).collect() }
fn key(n: usize) -> Vec<u8> { (0..n).map(|i| ((i * 89 + 7) & 0xff) as u8).collect() }

fn main() {
    let names = ["aes-cbc-elephant-128", "aes-cbc-elephant-256", "aes-cbc-128", "aes-cbc-256",
                 "aes-xts-128", "aes-xts-256"];
    for name in names {
        let method = Method::from_name(name).unwrap();
        let mut cipher = SectorCipher::new(method, &key(method.key_len())).unwrap();
        for (sector, offsets) in [(512usize, &[0u64, 512, 8192, 1 << 32, (1 << 40) + 512][..]),
                                  (4096, &[0u64, 4096, 1 << 33][..])] {
            for &offset in offsets {
                for seed in [0usize, 3] {
                    let plain = data(sector + seed)[seed..].to_vec();
                    let mut sealed = plain.clone();
                    cipher.encrypt_sector(offset, &mut sealed).unwrap();
                    let mut back = sealed.clone();
                    cipher.decrypt_sector(offset, &mut back).unwrap();
                    assert_eq!(back, plain, "{name} {sector} {offset}");
                    println!("bl/{name}/{sector}/{offset}/{seed} {}",
                             to_hex(&sealed).to_lowercase());
                }
            }
        }
    }
}
