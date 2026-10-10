/*
LRW: Liskov, Rivest and Wagner's tweakable block cipher mode, as IEEE
P1619 drafted it for disks before settling on XTS.

Each 16 byte block `j` of a data unit is encrypted as

    C = E_K1(P xor T) xor T,    T = K2 * (I + j)

where `I` is the index of the data unit's first block, `K2` is a second
128 bit key, and `*` is multiplication in GF(2^128). It was Linux
dm-crypt's `lrw-benbi` and `lrw-plain64` and TrueCrypt 4.1 to 4.3's
volume mode, and it is here because volumes made then still exist.

## What is easy to get wrong

**The field elements are big endian integers.** The index and the
tweak key are 128 bit numbers written most significant byte first, and
bit `k` of the number is the coefficient of `x^k` (the Linux kernel
calls this convention `bbe`). That is neither XTS's field (little
endian, `xts.rs`) nor GCM's (bit-reflected, `ghash.rs`), and all three
reduce by the same polynomial `x^128 + x^7 + x^2 + x + 1` - so a
multiplication borrowed from either works on the first block of some
vector by coincidence and on nothing else.

**The index counts blocks, not sectors.** It increases by one per 16
byte block, carrying across all 128 bits; the IEEE draft's wrap-around
vector starts at all ones.

## What it does not do

LRW is not authenticated, and leaks equality exactly as XTS does. It
was also dropped from the standard after a weakness when the tweak key
is encrypted under itself (`K2` stored in a sector it encrypts), which
is one reason XTS uses its second key differently. Kept for reading old
volumes, as everything here is.
*/

use crate::block_ciphers::BlockCipher;

const BLOCK: usize = 16;

/// `a * b` in GF(2^128), big endian bit and byte order.
pub fn gf_multiply(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let a = u128::from_be_bytes(*a);
    let b = u128::from_be_bytes(*b);
    let mut result = 0u128;
    for bit in (0..128).rev() {
        // result = result * x, reduced.
        let carry = result >> 127;
        result <<= 1;
        if carry != 0 {
            result ^= 0x87;
        }
        if (b >> bit) & 1 == 1 {
            result ^= a;
        }
    }
    result.to_be_bytes()
}

/// `value * x` in the field: a left shift, reduced.
fn double(value: u128) -> u128 {
    (value << 1) ^ if value >> 127 == 1 { 0x87 } else { 0 }
}

/// A block XORed with a tweak held as an integer.
#[inline(always)]
fn mask(block: &mut [u8], tweak: u128) {
    let block: &mut [u8; BLOCK] = block.try_into().expect("a whole block");
    *block = (u128::from_be_bytes(*block) ^ tweak).to_be_bytes();
}

/// Blocks handed to the cipher at a time, so that AES's batched path is
/// the one taken.
const BATCH: usize = 16;

fn crypt(cipher: &mut dyn BlockCipher, tweak_key: &[u8; BLOCK], index: &[u8; BLOCK],
         input: &[u8], encrypt: bool) -> Result<Vec<u8>, String> {
    if cipher.blocksize() != BLOCK {
        return Err(format!("LRW is defined for a 128 bit block; this cipher's is {} bytes.",
                           cipher.blocksize()));
    }
    if !input.len().is_multiple_of(BLOCK) {
        return Err(format!("LRW encrypts whole 16 byte blocks; {} bytes is not.",
                           input.len()));
    }
    // One multiplication for the first tweak; from there the tweak is
    // stepped. Adding one to the counter flips its trailing ones and the
    // zero above them, so `K2 * (I + j + 1)` is `K2 * (I + j)` XOR
    // `K2 * (x^(k+1) - 1)` where `k` is how many trailing zeros the
    // new counter has - and that is `inc[k]`, a table of 128 values
    // built by doubling once. A wrap to zero has 128 trailing zeros and
    // flips every bit, which is the last entry.
    let k2 = u128::from_be_bytes(*tweak_key);
    let mut inc = [0u128; 128];
    let (mut power, mut sum) = (k2, 0u128);
    for entry in inc.iter_mut() {
        sum ^= power;
        *entry = sum;
        power = double(power);
    }
    let mut counter = u128::from_be_bytes(*index);
    let mut tweak = u128::from_be_bytes(gf_multiply(tweak_key, index));

    // Masked in place, a batch through the cipher, unmasked: the batch
    // is what keeps AES on its constant-time path.
    let mut out = input.to_vec();
    let mut tweaks = [0u128; BATCH];
    for blocks in out.chunks_mut(BATCH * BLOCK) {
        for (block, saved) in blocks.chunks_exact_mut(BLOCK).zip(tweaks.iter_mut()) {
            *saved = tweak;
            mask(block, tweak);
            counter = counter.wrapping_add(1);
            tweak ^= inc[(counter.trailing_zeros() as usize).min(127)];
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
    Ok(out)
}

/// Encrypt whole blocks, the first at block index `index`.
pub fn encrypt(cipher: &mut dyn BlockCipher, tweak_key: &[u8; BLOCK], index: &[u8; BLOCK],
               input: &[u8]) -> Result<Vec<u8>, String> {
    crypt(cipher, tweak_key, index, input, true)
}

pub fn decrypt(cipher: &mut dyn BlockCipher, tweak_key: &[u8; BLOCK], index: &[u8; BLOCK],
               input: &[u8]) -> Result<Vec<u8>, String> {
    crypt(cipher, tweak_key, index, input, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AnyBlockCipher;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// IEEE P1619's LRW-AES vectors, as Linux carries them: AES-128,
    /// -192 and -256, a counter that wraps, and a 512 byte data unit.
    #[test]
    fn test_ieee_p1619_vectors() {
        let text = include_str!("../../vectors/lrw_aes.vec");
        let mut count = 0;
        for record in text.split("\nname = ").skip(1) {
            let field = |name: &str| unhex(record.lines()
                .find_map(|l| l.strip_prefix(&format!("{name} = "))).unwrap());
            let key = field("key");
            let (data_key, tweak_key) = key.split_at(key.len() - 16);
            let tweak_key: [u8; 16] = tweak_key.try_into().unwrap();
            let index: [u8; 16] = field("iv").try_into().unwrap();
            let mut cipher = AnyBlockCipher::new("aes", data_key, None).unwrap();
            let name = record.lines().next().unwrap();
            assert_eq!(encrypt(&mut cipher, &tweak_key, &index, &field("plaintext")).unwrap(),
                       field("ciphertext"), "{name}");
            assert_eq!(decrypt(&mut cipher, &tweak_key, &index, &field("ciphertext")).unwrap(),
                       field("plaintext"), "{name}");
            count += 1;
        }
        assert_eq!(count, 9);
    }

    /// The stepped tweak against a multiplication per block, over a
    /// counter that carries through several trailing ones and one that
    /// wraps from all ones to zero: the two places a stepping rule that
    /// is right for a plain increment goes wrong. The IEEE vectors above
    /// cover a wrap too, but with their own data; this one holds the
    /// cipher fixed and varies only the index.
    #[test]
    fn test_the_stepped_tweak_is_the_multiplied_one() {
        let mut cipher = AnyBlockCipher::new("aes", &[0x11; 16], None).unwrap();
        let tweak_key = [0x5cu8; 16];
        let input: Vec<u8> = (0..40 * BLOCK).map(|i| (i * 7) as u8).collect();
        for start in [0u128, 1, 0xfff, u128::MAX - 2, u128::MAX - 37, u128::MAX] {
            let got = encrypt(&mut cipher, &tweak_key, &start.to_be_bytes(), &input).unwrap();
            let mut want = Vec::new();
            for (j, block) in input.chunks(BLOCK).enumerate() {
                let tweak = gf_multiply(&tweak_key, &start.wrapping_add(j as u128).to_be_bytes());
                let mut masked = Vec::new();
                for (a, b) in block.iter().zip(&tweak) {
                    masked.push(a ^ b);
                }
                let mut enc = Vec::new();
                cipher.block_encrypt(&masked, &mut enc);
                want.extend(enc.iter().zip(&tweak).map(|(a, b)| a ^ b));
            }
            assert_eq!(got, want, "index {start:#x}");
            assert_eq!(decrypt(&mut cipher, &tweak_key, &start.to_be_bytes(), &got).unwrap(),
                       input);
        }
    }

    /// A cipher that records how its blocks arrive: through
    /// `encrypt_blocks` and `decrypt_blocks`, whose batch sizes it keeps,
    /// or one at a time through `block_encrypt`, which it counts.
    struct Counting {
        batches: Vec<usize>,
        single: usize,
    }

    impl BlockCipher for Counting {
        fn blocksize(&self) -> usize { BLOCK }
        fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
            self.single += 1;
            result.extend(input.iter().map(|b| b ^ 0x5a));
        }
        fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
            self.block_encrypt(input, result)
        }
        fn encrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
            self.batches.push(blocks.len() / BLOCK);
            for b in blocks.iter_mut() { *b ^= 0x5a; }
            Ok(())
        }
        fn decrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
            self.encrypt_blocks(blocks)
        }
    }

    /// The mode used to call `block_encrypt` once per block, which for
    /// AES without its instructions is the table route rather than the
    /// bitsliced one - a bypass of the constant-time path that the
    /// vector tests cannot see, since both routes give the same bytes.
    /// The whole blocks now go through `encrypt_blocks` in batches of
    /// `BATCH`, and a cipher that counts its calls shows it.
    #[test]
    fn test_the_blocks_go_through_the_batched_path() {
        let mut cipher = Counting { batches: Vec::new(), single: 0 };
        let input = vec![0x3cu8; 37 * BLOCK];
        let out = encrypt(&mut cipher, &[1; BLOCK], &[0; BLOCK], &input).unwrap();
        assert_eq!(cipher.batches, [BATCH, BATCH, 5]);
        assert_eq!(cipher.single, 0, "a block went through block_encrypt on its own");
        cipher.batches.clear();
        assert_eq!(decrypt(&mut cipher, &[1; BLOCK], &[0; BLOCK], &out).unwrap(), input);
        assert_eq!(cipher.batches, [BATCH, BATCH, 5]);
        assert_eq!(cipher.single, 0);
    }

    /// x * x^127 = x^128 = x^7 + x^2 + x + 1.
    #[test]
    fn test_the_reduction() {
        let x = 2u128.to_be_bytes();
        let top = (1u128 << 127).to_be_bytes();
        assert_eq!(gf_multiply(&x, &top), 0x87u128.to_be_bytes());
        assert_eq!(gf_multiply(&top, &x), 0x87u128.to_be_bytes());
        let one = 1u128.to_be_bytes();
        assert_eq!(gf_multiply(&one, &top), top);
    }
}
