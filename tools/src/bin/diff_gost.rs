// Kuznyechik, Magma and Streebog, dumped for comparison against a
// reference written from the GOST standards. Verified by
// scripts/diff_check.py.
//
// **Nothing on this machine implements any of these.** OpenSSL here is
// built with no GOST engine - `openssl list -digest-algorithms` has no
// Streebog and `-cipher-algorithms` has no Magma or Kuznyechik - and
// python-cryptography has never offered them. So the second
// implementation is a second reading of the specification, in a different
// language by a different route. That catches a transcription error in
// the Rust and would not catch a misreading of the standard that both
// transcriptions shared. It is a weaker claim than "agrees with OpenSSL"
// and it is the strongest one available, exactly as for SSLv3.
//
// The constant tables are the part that cannot be checked that way, and
// they were not transcribed at all: Kuznyechik's `pi` is byte-identical
// between RustCrypto's crate and the `gostcrypto` Python package,
// Streebog's `A`, `PI` and `C` together reproduce the gost-engine
// project's precomputed table byte for byte, and Magma's S-box is the one
// already in `gost.rs` for the same parameter set. The unit tests then
// pin each algorithm to its standard's published vectors.
//
// What is dumped, and why each length matters:
//
//   block  <cipher> <key> <plaintext>  <ciphertext>
//   cbc    <cipher> <key> <iv> <plaintext>  <ciphertext>
//   ctr    <cipher> <key> <iv> <plaintext>  <ciphertext>
//   hash   <size> <message>  <digest>
//
// The hash lengths sweep every offset around the 64 byte block boundary,
// because Streebog's padding and its two finalisation blocks are where a
// Merkle-Damgard construction goes wrong - and a length that happens to
// be a whole number of blocks is the case an implementation skips.
use allcrypt::api::{AnyBlockCipher, AnyHash, CipherStream, Mode};
use allcrypt::hash_functions::HashFunction;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 149 + seed as u32 * 53 + 17) & 0xff) as u8).collect()
}

/// One whole-message transform through the streaming interface, which is
/// the only path `api` offers and therefore the one worth checking.
fn run(name: &str, key: &[u8], mode: Mode, iv: &[u8], input: &[u8],
       decrypting: bool) -> Vec<u8> {
    let cipher = AnyBlockCipher::new(name, key, None).unwrap();
    let mut stream = CipherStream::new(cipher, mode, iv, decrypting).unwrap();
    let mut out = stream.update(input).unwrap();
    out.extend_from_slice(&stream.finish().unwrap());
    out
}

fn main() {
    let mut cases = 0usize;

    for (name, block_size) in [("kuznyechik", 16usize), ("magma", 8)] {
        for seed in 0..6u8 {
            let key = filler(32, seed + 1);

            // --- single blocks ---
            for index in 0..4u8 {
                let plaintext = filler(block_size, seed * 8 + index + 40);
                let out = run(name, &key, Mode::Ecb, &[], &plaintext, false);

                // Never emit a block we cannot read back ourselves.
                assert_eq!(run(name, &key, Mode::Ecb, &[], &out, true), plaintext);

                println!("block {} {} {} {}", name, hex(&key), hex(&plaintext), hex(&out));
                cases += 1;
            }

            // --- the chaining modes, over several whole-block lengths ---
            //
            // CTR matters most: RFC 9189's suites use it, and a counter
            // that increments the wrong end of the block produces a
            // keystream that is perfectly random and agrees with nobody.
            let iv = filler(block_size, seed + 90);
            for blocks in [1usize, 2, 3, 8] {
                let plaintext = filler(block_size * blocks, seed + blocks as u8);
                for (label, mode) in [("cbc", Mode::Cbc), ("ctr", Mode::Ctr)] {
                    let out = run(name, &key, mode, &iv, &plaintext, false);
                    assert_eq!(run(name, &key, mode, &iv, &out, true), plaintext,
                               "{} {} round trip", name, label);

                    println!("{} {} {} {} {} {}", label, name, hex(&key), hex(&iv),
                             hex(&plaintext), hex(&out));
                    cases += 1;
                }
            }
        }
    }

    // --- Streebog, both sizes, every length around the block boundary ---
    let message = filler(600, 7);
    let mut lengths: Vec<usize> = (0..=130).collect();
    lengths.extend([191, 192, 193, 255, 256, 257, 384, 500, 600]);
    for length in lengths {
        let slice = &message[..length];
        for (size, name) in [(256usize, "streebog256"), (512, "streebog512")] {
            let mut hash = AnyHash::new(name).unwrap();
            hash.update(slice);
            let digest = hash.digest();

            // And streaming in ragged pieces must equal one call, which
            // is the check the SHA-1 padding bug in this library's own
            // history would have failed.
            for chunk in [1usize, 17, 64] {
                let mut piecewise = AnyHash::new(name).unwrap();
                for piece in slice.chunks(chunk.max(1)) {
                    piecewise.update(piece);
                }
                assert_eq!(piecewise.digest(), digest,
                           "{} length {} in chunks of {}", name, length, chunk);
            }

            println!("hash {} {} {}", size, hex(slice), hex(&digest));
            cases += 1;
        }
    }

    // --- GOST R 34.11-94, both parameter sets ---
    //
    // The lengths sweep the 32 byte block boundary closely, because
    // this hash does **not** add a padded block to a message that
    // exactly fills one - the opposite of Streebog above and of
    // everything else here. A corpus whose lengths were all multiples
    // of 32, or none of them, would miss that in either direction.
    for length in [0usize, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128,
                   129, 200, 255, 256, 257, 500, 600] {
        let slice = &message[..length];
        for name in ["gost94", "gost94_test"] {
            let mut hash = AnyHash::new(name).unwrap();
            hash.update(slice);
            let digest = hash.digest();
            for chunk in [1usize, 7, 32, 33] {
                let mut piecewise = AnyHash::new(name).unwrap();
                for piece in slice.chunks(chunk.max(1)) {
                    piecewise.update(piece);
                }
                assert_eq!(piecewise.digest(), digest,
                           "{} length {} in chunks of {}", name, length, chunk);
            }
            println!("gost94 {} {} {}", name, hex(slice), hex(&digest));
            cases += 1;
        }
    }

    eprintln!("[diff_gost] {} cases", cases);
}
