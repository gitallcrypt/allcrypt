//! LUKS's anti-forensic information splitter (the LUKS1 on-disk format,
//! section 2.4; LUKS2 uses it unchanged).
//!
//! Not a key derivation: a way of storing a key so that destroying any
//! part of the stored form destroys the key. The key is spread over
//! `stripes` stripes of its own length - 4000 in every LUKS volume - of
//! which all but the last are random; folding them through a hash-based
//! diffusion and XORing the last gives the key back. A keyslot holds the
//! stripes encrypted, so that overwriting even one sector of it, on a
//! disk that remaps sectors behind the operating system's back, leaves
//! nothing to recover.
//!
//! The diffusion hashes the block in digest-sized pieces, each with its
//! index as a 32-bit big-endian number in front, the last piece's hash
//! cut to that piece's length.
//!
//! Hashes are named as LUKS names them, which is the Linux kernel's way:
//! this library's names, but `rmd160` for RIPEMD-160, `wp512` for
//! Whirlpool, and `wp384` and `wp256` for Whirlpool cut short.

use crate::api::AnyHash;
use crate::hash_functions::HashFunction;

/// The library's name for a LUKS hash name, and the length it is cut to
/// if it is one of the kernel's truncated Whirlpools.
pub fn kernel_hash_name(luks: &str) -> (&str, Option<usize>) {
    match luks {
        "rmd160" => ("ripemd160", None),
        "wp512" => ("whirlpool", None),
        "wp384" => ("whirlpool", Some(48)),
        "wp256" => ("whirlpool", Some(32)),
        other => (other, None),
    }
}

fn diffuse(hash: &str, block: &mut [u8]) -> Result<(), String> {
    let (name, cut) = kernel_hash_name(hash);
    let template = AnyHash::new(name)?;
    let size = cut.unwrap_or(template.digest_len());
    for (index, piece) in block.chunks_mut(size).enumerate() {
        let mut h = template.clone();
        h.update(&(index as u32).to_be_bytes());
        h.update(piece);
        let digest = h.digest();
        let length = piece.len();
        piece.copy_from_slice(&digest[..length]);
    }
    Ok(())
}

/// The fold over all stripes but the last: XOR in, diffuse, repeat.
fn fold(material: &[u8], key_len: usize, stripes: usize, hash: &str) -> Result<Vec<u8>, String> {
    let mut d = vec![0u8; key_len];
    for stripe in material.chunks(key_len).take(stripes - 1) {
        d.iter_mut().zip(stripe).for_each(|(a, b)| *a ^= b);
        diffuse(hash, &mut d)?;
    }
    Ok(d)
}

fn check(key_len: usize, stripes: usize) -> Result<(), String> {
    if key_len == 0 || stripes == 0 {
        return Err("The AF splitter needs a key and at least one stripe.".to_string());
    }
    key_len.checked_mul(stripes).map(|_| ()).ok_or_else(|| "Too many stripes.".to_string())
}

/// AFsplit: `stripes - 1` stripes from `random`, and the last chosen so
/// that merging gives `key` back. The result is `key.len() * stripes`
/// bytes.
pub fn af_split(key: &[u8], stripes: usize, hash: &str,
                random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>)
                -> Result<Vec<u8>, String> {
    check(key.len(), stripes)?;
    let mut material = vec![0u8; key.len() * stripes];
    random(&mut material[..key.len() * (stripes - 1)])?;
    let d = fold(&material, key.len(), stripes, hash)?;
    let last = &mut material[(stripes - 1) * key.len()..];
    for ((out, a), b) in last.iter_mut().zip(&d).zip(key) {
        *out = a ^ b;
    }
    Ok(material)
}

/// AFmerge: the key from its `stripes` stripes. Bytes past
/// `key_len * stripes` - a keyslot area is whole sectors - are ignored.
pub fn af_merge(material: &[u8], key_len: usize, stripes: usize, hash: &str)
                -> Result<Vec<u8>, String> {
    check(key_len, stripes)?;
    if material.len() < key_len * stripes {
        return Err(format!("{stripes} stripes of {key_len} bytes are {} bytes; this is {}.",
                           key_len * stripes, material.len()));
    }
    let mut d = fold(material, key_len, stripes, hash)?;
    let last = &material[(stripes - 1) * key_len..stripes * key_len];
    d.iter_mut().zip(last).for_each(|(a, b)| *a ^= b);
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(mut n: u8) -> impl FnMut(&mut [u8]) -> Result<(), String> {
        move |buf: &mut [u8]| {
            for b in buf {
                *b = n;
                n = n.wrapping_mul(29).wrapping_add(7);
            }
            Ok(())
        }
    }

    #[test]
    fn test_split_and_merge_round_trip() {
        let key: Vec<u8> = (0..64).collect();
        // LUKS's own 4000 stripes once; the other hashes at fewer, since
        // the stripe count changes only how often the same fold runs.
        for (hash, stripes) in [("sha256", 4000), ("sha1", 40), ("sha512", 40), ("rmd160", 40),
                                ("wp256", 40), ("wp512", 40)] {
            let material = af_split(&key, stripes, hash, &mut counter(1)).unwrap();
            assert_eq!(material.len(), 64 * stripes);
            assert_eq!(af_merge(&material, 64, stripes, hash).unwrap(), key, "{hash}");
            // Every stripe matters: changing one byte of the first loses
            // the key.
            let mut bent = material.clone();
            bent[0] ^= 1;
            assert_ne!(af_merge(&bent, 64, stripes, hash).unwrap(), key, "{hash}");
        }
    }

    /// One stripe is the key itself; two are `r` and `H(r) XOR key`.
    #[test]
    fn test_one_and_two_stripes_by_hand() {
        let key = [0x5au8; 20];
        assert_eq!(af_split(&key, 1, "sha1", &mut counter(3)).unwrap(), key);
        let material = af_split(&key, 2, "sha1", &mut counter(3)).unwrap();
        let mut d = material[..20].to_vec();
        let mut h = AnyHash::new("sha1").unwrap();
        h.update(&0u32.to_be_bytes());
        h.update(&d);
        d = h.digest();
        let last: Vec<u8> = d.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        assert_eq!(material[20..], last[..]);
    }

    /// The diffusion's last piece is cut: 33 bytes under SHA-256 are one
    /// whole hash and one byte of the second, whose index is 1.
    #[test]
    fn test_the_last_piece_is_cut_and_indexed() {
        let mut block = [7u8; 33];
        diffuse("sha256", &mut block).unwrap();
        let mut h = AnyHash::new("sha256").unwrap();
        h.update(&1u32.to_be_bytes());
        h.update(&[7u8]);
        assert_eq!(block[32], h.digest()[0]);
        // wp256 diffuses in 32-byte pieces of Whirlpool, not 64.
        let mut block = [7u8; 64];
        diffuse("wp256", &mut block).unwrap();
        let mut h = AnyHash::new("whirlpool").unwrap();
        h.update(&1u32.to_be_bytes());
        h.update(&[7u8; 32]);
        assert_eq!(block[32..], h.digest()[..32]);
    }

    #[test]
    fn test_short_material_and_zero_stripes_are_refused() {
        assert!(af_merge(&[0; 63], 16, 4, "sha1").is_err());
        assert!(af_merge(&[0; 64], 16, 0, "sha1").is_err());
        assert!(af_split(&[], 4, "sha1", &mut counter(0)).is_err());
        assert!(af_merge(&[0; 64], 16, 4, "nosuch").is_err());
    }
}
