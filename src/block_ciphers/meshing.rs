/*
CryptoPro key meshing, RFC 4357 section 2.3.2.

GOST 28147-89 has a 64 bit block, so one key is safe for a small amount
of data - RFC 4357 puts the limit at 1024 octets. Meshing changes the
key and the initialisation vector every 1024 octets, deterministically,
with no extra material from anybody:

    K[i+1]   = decryptECB(K[i], C)
    IV0[i+1] = encryptECB(K[i+1], IVn[i])

where `C` is a fixed 32 byte string and `IVn[i]` is the initialisation
vector **as it stands after** those 1024 octets - not the one the
section started with.

That is the same idea as ACPKM (RFC 8645), which the newer suites use,
and it is not the same construction. Three differences, each silent:

  * the key step is a **decryption**, not an encryption. ACPKM encrypts
    a constant; this decrypts one, and the constant is different;
  * the IV is re-derived too, from the *evolved* IV under the *new*
    key. ACPKM leaves its counter alone and lets it run across the
    boundary;
  * the boundary is 1024 octets of data, fixed by RFC 4357 rather than
    chosen per suite.

So a section boundary here moves both halves of the state, and an
implementation that carried the counter across it - the ACPKM habit -
produces a stream that is right for the first 1024 bytes and wrong
afterwards. RFC 9189 Appendix A.2.1's second record is 2048 bytes for
exactly that reason.

## What "the initialisation vector" means

It means different things to the two things that mesh, and both are
here because RFC 9189 meshes both:

  * for the **counter mode**, it is the counter block `(N1, N2)` - the
    value that gets encrypted to make the next block of gamma, before
    that encryption;
  * for the **MAC**, it is the chaining state.

They are meshed independently, each on its own count of the bytes it
has processed, because they process different bytes: the MAC covers the
record header and the sequence number, and the cipher does not.
*/

use crate::block_ciphers::gost::GostCrypto;
use crate::block_ciphers::BlockCipher;

/// How many octets one key covers, RFC 4357 section 2.3.2.
pub const SECTION: usize = 1024;

/// `C` from RFC 4357 section 2.3.2.
///
/// Not ACPKM's `D`, and not related to it: that one is `0x80..0x9f` and
/// is *encrypted*; this one is arbitrary and is *decrypted*.
const C: [u8; 32] = [
    0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
    0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
    0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
    0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
];

/// `K[i+1] = decryptECB(K[i], C)`.
pub fn next_key(sbox: &str, key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("GOST 28147-89 takes a 32 byte key; got {}.",
                           key.len()));
    }
    let mut cipher = GostCrypto::new(key.to_vec(), sbox.to_string())?;
    let mut out = Vec::with_capacity(32);
    for block in C.chunks(8) {
        cipher.block_decrypt(block, &mut out);
    }
    if out.len() != 32 {
        return Err(format!("meshing produced {} bytes, not 32.", out.len()));
    }
    Ok(out)
}

/// `IV0[i+1] = encryptECB(K[i+1], IVn[i])`, under the **new** key.
///
/// Taking the old key here is the mistake the shape invites: the RFC
/// writes the two lines in order and the second uses `K[i+1]`, which
/// has just been computed on the line above.
pub fn next_iv(sbox: &str, new_key: &[u8], evolved_iv: &[u8])
               -> Result<Vec<u8>, String> {
    if evolved_iv.len() != 8 {
        return Err(format!("GOST 28147-89's IV is 8 bytes; got {}.",
                           evolved_iv.len()));
    }
    let mut cipher = GostCrypto::new(new_key.to_vec(), sbox.to_string())?;
    let mut out = Vec::with_capacity(8);
    cipher.block_encrypt(evolved_iv, &mut out);
    if out.len() != 8 {
        return Err(format!("meshing produced a {} byte IV.", out.len()));
    }
    Ok(out)
}

/// Both halves, which is how they are always used.
pub fn mesh(sbox: &str, key: &[u8], evolved_iv: &[u8])
            -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = next_key(sbox, key)?;
    let iv = next_iv(sbox, &key, evolved_iv)?;
    Ok((key, iv))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    const Z: &str = "id-tc26-gost-28147-param-Z";

    /// Meshing is one way: the new key is a *decryption* of a constant,
    /// so recovering it says nothing about the key that produced it -
    /// which is the whole reason for re-keying rather than counting.
    ///
    /// The keys in these tests are varied rather than constant, and
    /// that is load bearing: see
    /// `test_a_key_of_equal_words_is_its_own_inverse` below.
    #[test]
    fn test_the_key_step_is_one_way_and_deterministic() {
        let key: [u8; 32] = core::array::from_fn(
            |i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let first = next_key(Z, &key).unwrap();
        assert_eq!(first.len(), 32);
        assert_ne!(first, key);
        assert_eq!(first, next_key(Z, &key).unwrap(), "meshing is not a function");

        // Encrypting the constant instead of decrypting it is the ACPKM
        // habit, and gives a key that is equally deterministic.
        let encrypted = {
            let mut cipher = GostCrypto::new(key.to_vec(), Z.to_string()).unwrap();
            let mut out = Vec::new();
            for block in C.chunks(8) {
                cipher.block_encrypt(block, &mut out);
            }
            out
        };
        assert_ne!(first, encrypted);

        // And a second meshing is a third key, so the chain does not
        // settle into a cycle at the first step.
        let second = next_key(Z, &first).unwrap();
        assert_ne!(second, first);
        assert_ne!(second, key);
    }

    /// The IV is derived under the **new** key. The old one is the
    /// obvious mistake, because the RFC's two lines read as a pair.
    #[test]
    fn test_the_iv_uses_the_new_key() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x5a);
        let evolved = [0x33u8; 8];
        let (new_key, new_iv) = mesh(Z, &key, &evolved).unwrap();

        assert_eq!(new_iv, next_iv(Z, &new_key, &evolved).unwrap());
        assert_ne!(new_iv, next_iv(Z, &key, &evolved).unwrap(),
                   "the old and new keys give the same IV, so this proves \
                    nothing about which is used");
    }

    /// The evolved IV is what goes in, not the one the section started
    /// with - so two sections that began alike and ran differently mesh
    /// to different places.
    #[test]
    fn test_the_evolved_iv_is_the_input() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let (_, one) = mesh(Z, &key, &[0x01; 8]).unwrap();
        let (_, two) = mesh(Z, &key, &[0x02; 8]).unwrap();
        assert_ne!(one, two);
    }

    /// The S-box is part of the cipher, so it is part of the meshing.
    #[test]
    fn test_the_sbox_changes_the_meshed_key() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 3);
        assert_ne!(next_key(Z, &key).unwrap(),
                   next_key("id-Gost28147-89-CryptoPro-A-ParamSet", &key).unwrap());
    }

    #[test]
    fn test_wrong_lengths_are_refused() {
        assert!(next_key(Z, &[0u8; 31]).is_err());
        assert!(next_iv(Z, &[0u8; 32], &[0u8; 7]).is_err());
    }

    /// **A GOST key whose eight 32 bit words are all equal makes the
    /// cipher its own inverse**, and a test using one proves nothing
    /// about direction.
    ///
    /// The schedule is `K K K reverse(K)`, which is a palindrome when
    /// every word is the same - so encryption and decryption run the
    /// same subkeys in the same order. The first draft of
    /// `test_the_key_step_is_one_way_and_deterministic` used
    /// `[0x11; 32]` and asserted that decrypting the constant differs
    /// from encrypting it; it failed, and the failure was this property
    /// rather than a bug in the meshing.
    ///
    /// Written down because it is a trap for any test of any GOST
    /// direction, not only this one - and `[0x00; 32]`, the obvious
    /// choice for a test key, is exactly such a key.
    #[test]
    fn test_a_key_of_equal_words_is_its_own_inverse() {
        let block = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        for key in [[0x00u8; 32], [0x11u8; 32], [0xffu8; 32]] {
            let mut cipher = GostCrypto::new(key.to_vec(), Z.to_string()).unwrap();
            let (mut up, mut down) = (Vec::new(), Vec::new());
            cipher.block_encrypt(&block, &mut up);
            cipher.block_decrypt(&block, &mut down);
            assert_eq!(up, down,
                       "a key of equal words should make GOST its own inverse");
        }

        // A varied key does not have the property, which is what makes
        // it a usable test key.
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37));
        let mut cipher = GostCrypto::new(key.to_vec(), Z.to_string()).unwrap();
        let (mut up, mut down) = (Vec::new(), Vec::new());
        cipher.block_encrypt(&block, &mut up);
        cipher.block_decrypt(&block, &mut down);
        assert_ne!(up, down);
    }

    /// `C` is the RFC's constant, written here once. A test rather than
    /// a comment because the whole construction is deterministic under
    /// any 32 bytes, so a mistyped one produces a working cipher that
    /// nobody else can read.
    #[test]
    fn test_the_constant_is_the_rfcs() {
        assert_eq!(hex(&C),
                   "69007222 64c90423 8d3adb96 46e92ac4\
                    18feac94 00ed0712 c086dcc2 ef4ca92b".replace(' ', ""));
    }
}
