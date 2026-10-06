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
    let mut counter = u128::from_be_bytes(*index);
    let mut out = Vec::with_capacity(input.len());
    let mut result = Vec::with_capacity(BLOCK);
    for block in input.chunks(BLOCK) {
        let tweak = gf_multiply(tweak_key, &counter.to_be_bytes());
        let masked: Vec<u8> = block.iter().zip(&tweak).map(|(a, b)| a ^ b).collect();
        result.clear();
        if encrypt {
            cipher.block_encrypt(&masked, &mut result);
        } else {
            cipher.block_decrypt(&masked, &mut result);
        }
        out.extend(result.iter().zip(&tweak).map(|(a, b)| a ^ b));
        counter = counter.wrapping_add(1);
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
