/*
XTS: IEEE 1619, and NIST SP 800-38E which adopts it by reference.

The disk encryption mode. Every other mode here turns a block cipher
into something that encrypts a *stream*; XTS turns one into something
that encrypts a *place*. A sector is encrypted under its own number, so
the same plaintext in two sectors gives different ciphertext, and the
ciphertext is exactly as long as the plaintext - which is the whole
constraint, because a disk sector has nowhere to put an IV or a tag.

## Two keys, and they are not interchangeable

The key is twice the cipher's length: the first half encrypts the data,
the second encrypts the *tweak* - the sector number - once per sector.
"aes-256-xts" therefore takes 64 bytes and is two AES-256 keys, which is
why key lengths here look wrong until you know that.

## What it does not do

**XTS is not authenticated, and cannot be.** There is no room: the
ciphertext is the same length as the plaintext. An attacker who can
write to the disk can change any 16 byte block to random bytes of their
choosing, and decryption will produce random plaintext rather than an
error. It also leaks equality: the same plaintext written to the same
sector twice gives the same ciphertext, so an observer watching a disk
over time sees which sectors changed and which reverted. Both are
accepted properties of the problem, not gaps here, and
`docs/pitfalls.md` records them.

## What is easy to get wrong

**The tweak is little endian.** Sector 1 is
`01 00 00 ... 00`, not `00 ... 00 01`. Every implementation on a disk
agrees on this; a big-endian tweak encrypts and decrypts perfectly
against itself and mounts nobody's filesystem.

**The multiply by alpha is little endian too**, with the reduction
polynomial's `0x87` going into byte *zero* after a shift left through
the whole 128 bits. Written big-endian, which is how `ghash.rs` does its
(different) field, it gives a sequence of tweaks that is self-consistent
and wrong from the second block.

**The last two blocks are swapped when stealing.** For a length that is
not a multiple of 16, the second-to-last ciphertext block is the
encryption of the *stolen* block under the *last* tweak, and the final
partial block is the truncation of what the second-to-last tweak
produced. Writing them in the obvious order round-trips against itself.

**A data unit shorter than one block cannot be done at all**, because
stealing needs a full block to steal from. That is an error, not a
special case.
*/

use crate::block_ciphers::BlockCipher;

/// The block XTS is defined over. There is no 64 bit variant.
const BLOCK: usize = 16;

/// SP 800-38E section 4: a data unit is at most 2^20 blocks.
///
/// **Enforced when encrypting and not when decrypting.** Writing
/// something outside the standard is a choice this library will not make
/// for a caller; reading something that is already on a disk is the
/// reason this library exists. The same split as everywhere else here:
/// strict about what we emit, permissive about what we read.
pub const MAX_BLOCKS: usize = 1 << 20;

/// A sector number as the 16 byte little endian tweak XTS wants.
///
/// This is the conversion everyone gets wrong once; it is a function so
/// that it is wrong in one place or in none.
pub fn sector_tweak(sector: u128) -> [u8; BLOCK] {
    sector.to_le_bytes()
}

/// Multiply the tweak by the primitive element `alpha` in
/// GF(2^128) mod `x^128 + x^7 + x^2 + x + 1`.
///
/// A shift left by one across all 128 bits in **little endian byte
/// order** - so the carry moves from byte `i` into byte `i+1` - and the
/// reduction constant `0x87` folded into byte zero when the top bit
/// falls off the end.
///
/// The fold is a mask, not an `if`: the tweak is the sector number
/// encrypted under the tweak key, so its top bit is secret, and a branch
/// on it is one bit of a secret per block.
fn multiply_by_alpha(tweak: &mut [u8; BLOCK]) {
    *tweak = double(u128::from_le_bytes(*tweak)).to_le_bytes();
}

/// The same on the tweak as a little-endian integer.
#[inline(always)]
fn double(value: u128) -> u128 {
    (value << 1) ^ (0x87 & 0u128.wrapping_sub(value >> 127))
}

fn require_128_bit(cipher: &dyn BlockCipher, what: &str) -> Result<(), String> {
    if cipher.blocksize() != BLOCK {
        return Err(format!(
            "XTS is defined for a 128 bit block; the {} cipher's block is {} \
             bytes.", what, cipher.blocksize()));
    }
    Ok(())
}

/// One block through `encrypt_blocks` or `decrypt_blocks`, so the tweak
/// key and the stolen blocks take the same constant-time path as the
/// rest. The width is checked here as well as by `require_128_bit`:
/// sixteen bytes are two blocks to a 64 bit cipher, and would not fail.
fn one_block(cipher: &mut dyn BlockCipher, input: &[u8], encrypt: bool)
             -> Result<[u8; BLOCK], String> {
    if cipher.blocksize() != BLOCK {
        return Err(format!("The cipher's block is {} bytes, not 16.", cipher.blocksize()));
    }
    let mut block = [0u8; BLOCK];
    block.copy_from_slice(&input[..BLOCK]);
    if encrypt {
        cipher.encrypt_blocks(&mut block)?;
    } else {
        cipher.decrypt_blocks(&mut block)?;
    }
    Ok(block)
}

fn xor_into(target: &mut [u8; BLOCK], other: &[u8; BLOCK]) {
    for (t, o) in target.iter_mut().zip(other.iter()) {
        *t ^= o;
    }
}

/// `E(P xor T) xor T`, in whichever direction.
fn transform(cipher: &mut dyn BlockCipher, block: &[u8], tweak: &[u8; BLOCK],
             encrypt: bool) -> Result<[u8; BLOCK], String> {
    let mut masked = [0u8; BLOCK];
    masked.copy_from_slice(block);
    xor_into(&mut masked, tweak);
    let mut out = one_block(cipher, &masked, encrypt)?;
    xor_into(&mut out, tweak);
    Ok(out)
}

/// Blocks per call to the cipher in `whole_blocks`: AES's bitsliced batch.
const BATCH: usize = 16;

/// The straightforward blocks of a data unit, `E(P xor T) xor T` with the
/// tweak doubling after each, in batches through `encrypt_blocks` or
/// `decrypt_blocks`. Leaves `running` at the tweak for the next block.
fn whole_blocks(cipher: &mut dyn BlockCipher, input: &[u8], running: &mut [u8; BLOCK],
                encrypt: bool, out: &mut Vec<u8>) -> Result<(), String> {
    // The tweak as one little-endian integer for the length of the loop:
    // doubling is a shift and a conditional XOR, and masking a block is
    // one XOR, where a byte array costs a conversion each time.
    let from = out.len();
    out.extend_from_slice(input);
    if cipher.xts_blocks(running, &mut out[from..], encrypt)? {
        return Ok(());
    }
    let mut tweak = u128::from_le_bytes(*running);
    let mut tweaks = [0u128; BATCH];
    for blocks in out[from..].chunks_mut(BATCH * BLOCK) {
        for (block, saved) in blocks.chunks_exact_mut(BLOCK).zip(tweaks.iter_mut()) {
            *saved = tweak;
            mask(block, tweak);
            tweak = double(tweak);
        }
        if encrypt {
            cipher.encrypt_blocks(blocks)?;
        } else {
            cipher.decrypt_blocks(blocks)?;
        }
        for (block, saved) in blocks.chunks_exact_mut(BLOCK).zip(tweaks.iter()) {
            mask(block, *saved);
        }
    }
    *running = tweak.to_le_bytes();
    Ok(())
}

/// A block XORed with a tweak held as an integer.
#[inline(always)]
fn mask(block: &mut [u8], tweak: u128) {
    let block: &mut [u8; BLOCK] = block.try_into().expect("a whole block");
    *block = (u128::from_le_bytes(*block) ^ tweak).to_le_bytes();
}

/// The initial tweak for a data unit: the sector number encrypted under
/// the tweak key.
fn initial_tweak(tweak_cipher: &mut dyn BlockCipher, tweak: &[u8; BLOCK])
                 -> Result<[u8; BLOCK], String> {
    one_block(tweak_cipher, tweak, true)
}

/// Encrypt one data unit.
///
/// `data` is keyed with the first half of the XTS key and `tweak_cipher`
/// with the second; `tweak` is the data unit number, which
/// [`sector_tweak`] builds from an integer.
///
/// The output is exactly as long as the input. Ciphertext stealing
/// handles a length that is not a multiple of 16.
///
/// # Errors
/// A cipher whose block is not 128 bits, an input shorter than one
/// block, or an input longer than [`MAX_BLOCKS`] blocks.
pub fn encrypt(data: &mut dyn BlockCipher, tweak_cipher: &mut dyn BlockCipher,
               tweak: &[u8; BLOCK], input: &[u8]) -> Result<Vec<u8>, String> {
    require_128_bit(data, "data")?;
    require_128_bit(tweak_cipher, "tweak")?;
    if input.len() < BLOCK {
        return Err(format!(
            "An XTS data unit is at least one 16 byte block, because a short \
             final block steals from the one before it; this is {} bytes.",
            input.len()));
    }
    if input.len().div_ceil(BLOCK) > MAX_BLOCKS {
        return Err(format!(
            "SP 800-38E limits a data unit to {} blocks; this is {}. Decryption \
             accepts a longer one, so something already written this way can \
             still be read.", MAX_BLOCKS, input.len().div_ceil(BLOCK)));
    }

    let mut running = initial_tweak(tweak_cipher, tweak)?;
    let whole = input.len() / BLOCK;
    let remainder = input.len() % BLOCK;
    // With a partial tail, the last *whole* block is held back: it is
    // what the tail steals from.
    let straightforward = if remainder == 0 { whole } else { whole - 1 };

    let mut out = Vec::with_capacity(input.len());
    whole_blocks(data, &input[..straightforward * BLOCK], &mut running, true, &mut out)?;

    if remainder == 0 {
        return Ok(out);
    }

    // Ciphertext stealing, IEEE 1619 section 5.3.2. The last two blocks
    // come out in the opposite order to the tweaks that made them.
    let penultimate = &input[straightforward * BLOCK..(straightforward + 1) * BLOCK];
    let cc = transform(data, penultimate, &running, true)?;
    multiply_by_alpha(&mut running);

    let tail = &input[(straightforward + 1) * BLOCK..];
    let mut stolen = [0u8; BLOCK];
    stolen[..remainder].copy_from_slice(tail);
    stolen[remainder..].copy_from_slice(&cc[remainder..]);

    out.extend_from_slice(&transform(data, &stolen, &running, true)?);
    out.extend_from_slice(&cc[..remainder]);
    Ok(out)
}

/// Decrypt one data unit.
///
/// # Errors
/// A cipher whose block is not 128 bits, or an input shorter than one
/// block. A length over [`MAX_BLOCKS`] is **not** an error here; see
/// that constant.
pub fn decrypt(data: &mut dyn BlockCipher, tweak_cipher: &mut dyn BlockCipher,
               tweak: &[u8; BLOCK], input: &[u8]) -> Result<Vec<u8>, String> {
    require_128_bit(data, "data")?;
    require_128_bit(tweak_cipher, "tweak")?;
    if input.len() < BLOCK {
        return Err(format!(
            "An XTS data unit is at least one 16 byte block; this is {} bytes.",
            input.len()));
    }

    let mut running = initial_tweak(tweak_cipher, tweak)?;
    let whole = input.len() / BLOCK;
    let remainder = input.len() % BLOCK;
    let straightforward = if remainder == 0 { whole } else { whole - 1 };

    let mut out = Vec::with_capacity(input.len());
    whole_blocks(data, &input[..straightforward * BLOCK], &mut running, false, &mut out)?;

    if remainder == 0 {
        return Ok(out);
    }

    // The mirror image of the stealing above: the second-to-last
    // ciphertext block was made with the *last* tweak, so decrypting it
    // needs that tweak, which is one step ahead of where the loop left
    // off.
    let mut next = running;
    multiply_by_alpha(&mut next);

    let penultimate = &input[straightforward * BLOCK..(straightforward + 1) * BLOCK];
    let pp = transform(data, penultimate, &next, false)?;

    let tail = &input[(straightforward + 1) * BLOCK..];
    let mut recovered = [0u8; BLOCK];
    recovered[..remainder].copy_from_slice(tail);
    recovered[remainder..].copy_from_slice(&pp[remainder..]);

    out.extend_from_slice(&transform(data, &recovered, &running, false)?);
    out.extend_from_slice(&pp[..remainder]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::aes::AesCrypto;

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Run a whole data unit with a key that is `key1 || key2`.
    fn run(key: &[u8], sector: u128, input: &[u8], encrypting: bool) -> Vec<u8> {
        let half = key.len() / 2;
        let mut data = AesCrypto::new(&key[..half]).unwrap();
        let mut tweak = AesCrypto::new(&key[half..]).unwrap();
        let number = sector_tweak(sector);
        if encrypting {
            encrypt(&mut data, &mut tweak, &number, input).unwrap()
        } else {
            decrypt(&mut data, &mut tweak, &number, input).unwrap()
        }
    }

    /// AES with only `encrypt_blocks` and `decrypt_blocks`: no
    /// `xts_blocks`, so `whole_blocks` takes its own three passes.
    struct BlocksOnly(AesCrypto);

    impl BlockCipher for BlocksOnly {
        fn blocksize(&self) -> usize {
            16
        }
        fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
            self.0.block_encrypt(input, result)
        }
        fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
            self.0.block_decrypt(input, result)
        }
        fn encrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
            self.0.encrypt_blocks(blocks)
        }
        fn decrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
            self.0.decrypt_blocks(blocks)
        }
    }

    /// The cipher's own one-pass XTS (AES's instructions, with the
    /// `aes-ni` feature on a processor that has them) against the mode's
    /// three passes, at every length to past two batches and from tweaks
    /// whose top bit is set, so the doubling's reduction runs from the
    /// first block. Without the hardware both sides are the same path.
    #[test]
    fn test_the_one_pass_path_agrees_with_the_three_pass_one() {
        let key: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37) ^ 0x5C).collect();
        let input: Vec<u8> = (0..40 * 16).map(|i| (i * 11 + i / 7) as u8).collect();
        for sector in [0u128, 1, 1 << 127, u128::MAX] {
            for length in 16..=input.len() {
                let mut tweak_cipher = AesCrypto::new(&key[32..]).unwrap();
                let mut fast = AesCrypto::new(&key[..32]).unwrap();
                let mut slow = BlocksOnly(AesCrypto::new(&key[..32]).unwrap());
                let number = sector_tweak(sector);
                let a = encrypt(&mut fast, &mut tweak_cipher, &number, &input[..length]).unwrap();
                let b = encrypt(&mut slow, &mut tweak_cipher, &number, &input[..length]).unwrap();
                assert_eq!(a, b, "sector {sector:x}, {length} bytes");
                let back = decrypt(&mut fast, &mut tweak_cipher, &number, &a).unwrap();
                assert_eq!(back, decrypt(&mut slow, &mut tweak_cipher, &number, &b).unwrap());
                assert_eq!(back, &input[..length]);
            }
        }
    }

    /// Known answers.
    ///
    /// IEEE 1619's own vectors are behind the standard's paywall, so
    /// these were **generated by python-cryptography** (OpenSSL's
    /// AES-XTS) with `scripts/make_xts_vectors.py` and pinned here. The
    /// re-runnable comparison is `pytests/test_xts.py`, which sweeps
    /// every length; these exist so that `cargo test` alone still fails
    /// if the mode changes.
    #[test]
    fn test_known_answers_from_openssl() {
        let cases: &[(&str, &str, u128, &str, &str)] = &[
            (
                "one block, sector 0",
                "1111111111111111111111111111111122222222222222222222222222222222",
                0,
                "00000000000000000000000000000000",
                "ca57c6fbb73cc802301a7b8a4581cb0b",
            ),
            (
                "two blocks, sector 1",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                1,
                "4444444444444444444444444444444444444444444444444444444444444444",
                "44e1fa05aec6a4464162fe53c53d17cf905f00b6a4c0203af5d73032216ddcc8",
            ),
            (
                "three blocks and one byte, sector 2",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                2,
                "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51",
                "96bc3a684bbebaaddd2df4423daede7e30d3138ce9fd4bf31cbd8802ceea8674b2df4baf184a8ca3bd70dffc4238c59147",
            ),
            (
                "aes-256-xts, four blocks, sector 0x0102030405060708",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                72623859790382856,
                "000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d606366696c6f7275787b7e8184878a8d909396999c9fa2a5a8abaeb1b4b7babd",
                "086778e10184bffe63b9e9d28204e548fd22a8b222d0784be3e646dce7be6d1ae7d409eae6051a72c46e148abcca388bdcddbc2a2f4a9acb70c1e04a48bc736f",
            ),
            (
                "aes-256-xts, two blocks, sector 2^70 + 5",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                1180591620717411303429,
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "502b405292475d87d13df5be988de271c3fb0bf232f8da0bcc0d66c7bbd76e8d",
            ),
        ];
        assert_eq!(cases.len(), 5);
        for (name, key, sector, plaintext, ciphertext) in cases {
            let key = unhex(key);
            let plaintext = unhex(plaintext);
            let expected = unhex(ciphertext);
            assert_eq!(hex(&run(&key, *sector, &plaintext, true)), hex(&expected),
                       "encrypting {}", name);
            assert_eq!(hex(&run(&key, *sector, &expected, false)), hex(&plaintext),
                       "decrypting {}", name);
        }
    }

    /// Every length from one block to five round-trips, including all
    /// fifteen partial tails.
    #[test]
    fn test_round_trip_at_every_length() {
        let key: Vec<u8> = (0..64u8).collect();
        for length in BLOCK..=(5 * BLOCK) {
            let plaintext: Vec<u8> = (0..length).map(|i| (i * 13 + 7) as u8).collect();
            let ciphertext = run(&key, 42, &plaintext, true);
            assert_eq!(ciphertext.len(), plaintext.len(), "length {}", length);
            assert_eq!(run(&key, 42, &ciphertext, false), plaintext, "length {}", length);
        }
    }

    /// **The sector number changes the ciphertext.**
    ///
    /// This is the entire reason the mode exists, and an implementation
    /// that dropped the tweak would still round-trip perfectly.
    #[test]
    fn test_the_sector_number_reaches_the_ciphertext() {
        let key = [0x5au8; 64];
        let plaintext = [0u8; 64];
        let first = run(&key, 0, &plaintext, true);
        let second = run(&key, 1, &plaintext, true);
        let far = run(&key, 1 << 70, &plaintext, true);
        assert_ne!(first, second);
        assert_ne!(first, far);
        assert_ne!(second, far);

        // And a sector's ciphertext does not decrypt under another's.
        assert_ne!(run(&key, 1, &first, false), plaintext.to_vec());
    }

    /// The tweak is **little endian**, so sector 1 is `01 00 ... 00`.
    ///
    /// A big-endian implementation agrees with itself about everything
    /// and with no disk anywhere.
    #[test]
    fn test_the_tweak_is_little_endian() {
        assert_eq!(sector_tweak(0), [0u8; 16]);
        let one = sector_tweak(1);
        assert_eq!(one[0], 1, "sector 1 did not put its 1 in byte zero");
        assert_eq!(one[15], 0);
        assert_eq!(sector_tweak(0x0102030405060708)[..8],
                   [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    /// Multiplying by alpha is a shift with a little-endian carry, and
    /// `0x87` folds into byte zero.
    #[test]
    fn test_the_alpha_multiply() {
        // 1 * alpha = 2.
        let mut tweak = [0u8; 16];
        tweak[0] = 1;
        multiply_by_alpha(&mut tweak);
        assert_eq!(tweak[0], 2);
        assert!(tweak[1..].iter().all(|b| *b == 0));

        // The carry moves *up* the array, not down.
        let mut tweak = [0u8; 16];
        tweak[0] = 0x80;
        multiply_by_alpha(&mut tweak);
        assert_eq!(tweak[0], 0, "the low byte did not shift out");
        assert_eq!(tweak[1], 1, "the carry did not land in byte one");

        // The top bit of the *last* byte is what triggers the reduction.
        let mut tweak = [0u8; 16];
        tweak[15] = 0x80;
        multiply_by_alpha(&mut tweak);
        assert_eq!(tweak[0], 0x87, "the reduction constant did not land in byte zero");
        assert!(tweak[1..].iter().all(|b| *b == 0));

        // Doubling 128 times returns to where it started, because alpha
        // generates a subgroup of order 2^128 - 1 and 1 * alpha^n only
        // returns after that many steps - so this must *not* be the
        // identity, which is the check that the reduction is a real one.
        let mut tweak = [0u8; 16];
        tweak[0] = 1;
        for _ in 0..128 {
            multiply_by_alpha(&mut tweak);
        }
        assert_ne!(tweak, {
            let mut one = [0u8; 16];
            one[0] = 1;
            one
        });
    }

    /// Anything shorter than a block is refused rather than handled.
    #[test]
    fn test_a_short_data_unit_is_refused() {
        let key = [0u8; 32];
        let mut data = AesCrypto::new(&key[..16]).unwrap();
        let mut tweak = AesCrypto::new(&key[16..]).unwrap();
        let number = sector_tweak(0);
        for length in 0..BLOCK {
            assert!(encrypt(&mut data, &mut tweak, &number, &vec![0u8; length]).is_err(),
                    "{} bytes was encrypted", length);
            assert!(decrypt(&mut data, &mut tweak, &number, &vec![0u8; length]).is_err(),
                    "{} bytes was decrypted", length);
        }
        assert!(encrypt(&mut data, &mut tweak, &number, &[0u8; BLOCK]).is_ok());
    }

    /// A 64 bit block cipher is refused on either side of the key.
    #[test]
    fn test_a_64_bit_block_cipher_is_refused() {
        let mut des = crate::block_ciphers::des::Des::new(&[1u8; 8]).unwrap();
        let mut aes = AesCrypto::new(&[0u8; 16]).unwrap();
        let number = sector_tweak(0);
        assert!(encrypt(&mut des, &mut aes, &number, &[0u8; 32]).is_err());
        assert!(encrypt(&mut aes, &mut des, &number, &[0u8; 32]).is_err());
        assert!(decrypt(&mut des, &mut aes, &number, &[0u8; 32]).is_err());
        assert!(decrypt(&mut aes, &mut des, &number, &[0u8; 32]).is_err());
    }

    /// The block size requirement is refused **by name**.
    ///
    /// Removing `require_128_bit` leaves every test passing, because a
    /// 64 bit cipher then fails in `one_block` instead - defence in
    /// depth rather than a hole, but invisible to a breakage sweep. So
    /// the error is pinned, on both sides of the key.
    #[test]
    fn test_the_block_size_error_says_which_cipher() {
        let mut des = crate::block_ciphers::des::Des::new(&[1u8; 8]).unwrap();
        let mut aes = AesCrypto::new(&[0u8; 16]).unwrap();
        let number = sector_tweak(0);

        let error = encrypt(&mut des, &mut aes, &number, &[0u8; 32]).unwrap_err();
        assert!(error.contains("128 bit block"), "{}", error);
        assert!(error.contains("data cipher"), "{}", error);

        let mut des = crate::block_ciphers::des::Des::new(&[1u8; 8]).unwrap();
        let mut aes = AesCrypto::new(&[0u8; 16]).unwrap();
        let error = encrypt(&mut aes, &mut des, &number, &[0u8; 32]).unwrap_err();
        assert!(error.contains("tweak cipher"), "{}", error);
    }

    /// The two halves of the key are not interchangeable.
    ///
    /// Swapping them gives a perfectly working XTS that no other
    /// implementation agrees with, and a round trip cannot see it.
    #[test]
    fn test_the_two_keys_are_not_interchangeable() {
        let mut key = [0u8; 64];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let plaintext = [0x77u8; 48];

        let straight = run(&key, 9, &plaintext, true);

        let mut swapped = [0u8; 64];
        swapped[..32].copy_from_slice(&key[32..]);
        swapped[32..].copy_from_slice(&key[..32]);
        assert_ne!(straight, run(&swapped, 9, &plaintext, true));
    }

    /// Ciphertext stealing puts the last two blocks in the opposite
    /// order to the tweaks that produced them.
    ///
    /// A whole-block data unit and one byte longer must differ in their
    /// *last complete block*, not merely have a byte appended - which is
    /// what an implementation without stealing would produce.
    #[test]
    fn test_stealing_rewrites_the_last_whole_block() {
        let key = [0x31u8; 32];
        let aligned = [0xaau8; 32];
        let mut longer = [0xaau8; 33];
        longer[..32].copy_from_slice(&aligned);

        let first = run(&key, 3, &aligned, true);
        let second = run(&key, 3, &longer, true);

        assert_eq!(&first[..16], &second[..16], "the first block should be untouched");
        assert_ne!(&first[16..32], &second[16..32],
                   "the last whole block was not rewritten, so nothing was stolen");
    }

    /// The length limit applies to encryption and not to decryption.
    ///
    /// A 2^20 block data unit is 16 MiB, cheap enough to build, so the
    /// limit is exercised rather than read back as a constant, which is
    /// all the earlier form of this test did: at the limit encryption
    /// is fine, one block past it is refused with the message naming
    /// the limit, and decryption accepts the same unit, so that a
    /// volume already written this way can still be read.
    #[test]
    fn test_the_length_limit_is_one_sided() {
        assert_eq!(MAX_BLOCKS, 1 << 20);
        let key = [0u8; 32];
        let mut data = AesCrypto::new(&key[..16]).unwrap();
        let mut tweak = AesCrypto::new(&key[16..]).unwrap();
        let number = sector_tweak(0);

        let mut unit = vec![0u8; BLOCK * MAX_BLOCKS];
        assert!(encrypt(&mut data, &mut tweak, &number, &unit).is_ok());

        // One byte past the limit is one block past it.
        unit.push(0);
        let refused = encrypt(&mut data, &mut tweak, &number, &unit).unwrap_err();
        assert!(refused.contains(&format!("{} blocks", MAX_BLOCKS)), "{refused}");
        assert!(decrypt(&mut data, &mut tweak, &number, &unit).is_ok(),
                "decryption must accept a unit encryption refuses");
    }
}
