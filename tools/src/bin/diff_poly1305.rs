// Poly1305 on its own, dumped for comparison with OpenSSL's through
// python-cryptography. Verified by scripts/diff_check.py.
//
// ChaCha20-Poly1305's corpus already reaches Poly1305, but only with
// keys that came out of ChaCha and with the AEAD's padding around every
// message. This one chooses the keys: random ones, and the largest r the
// clamp allows with an s of all ones, against messages of all 0xff -
// together the values that push every limb and carry to its bound - as
// well as r = 0 and s = 0. Lengths sweep 0 to 80 byte by byte, so every
// short final block and every boundary is reached, plus a few long ones.
// Each tag is also computed in irregular pieces and must agree with the
// one-shot value before it is printed.
//
//   poly1305 <key> <message>  <tag>
use allcrypt::mac::poly1305::Poly1305;
use allcrypt::Mac;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(12345);
    (0..len).map(|_| { x ^= x << 13; x ^= x >> 17; x ^= x << 5; x as u8 }).collect()
}

fn main() {
    let mut keys = vec![vec![0xffu8; 32], [vec![0xffu8; 16], vec![0u8; 16]].concat(),
                        [vec![0u8; 16], vec![0xffu8; 16]].concat()];
    keys.extend((0..5).map(|seed| filler(32, seed)));
    let messages = [vec![0xffu8; 1024], filler(1024, 99), vec![0u8; 1024]];

    let mut lengths: Vec<usize> = (0..=80).collect();
    lengths.extend([127, 128, 129, 255, 256, 1000, 1024]);

    let mut cases = 0usize;
    for key in &keys {
        for message in &messages {
            for &length in &lengths {
                let message = &message[..length];
                let mut whole = Poly1305::new(key).unwrap();
                whole.update(message);
                let tag = whole.digest();
                let mut pieces = Poly1305::new(key).unwrap();
                let mut rest = message;
                let mut size = 1;
                while !rest.is_empty() {
                    let take = size.min(rest.len());
                    pieces.update(&rest[..take]);
                    rest = &rest[take..];
                    size = size % 37 + 7;
                }
                assert_eq!(pieces.digest(), tag, "streaming differs at length {length}");
                println!("poly1305 {} {} {}", hex(key), hex(message), hex(&tag));
                cases += 1;
            }
        }
    }
    eprintln!("[diff_poly1305] {} cases", cases);
}
