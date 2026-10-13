/*!
Noekeon, Daemen, Peeters, Van Assche and Rijmen's NESSIE submission: a
128-bit block, a 128-bit key and sixteen rounds, built entirely from
32-bit XOR, AND, NOT and rotations - bitsliced by design, so constant
time as written.

## Two key modes, two names

The specification defines the cipher once and the key two ways.

- **Direct-key mode** (`noekeon`): the key is the working key. The
  designers meant it for uses where related keys cannot occur. This is
  what libtomcrypt and Bouncy Castle implement.
- **Indirect-key mode** (`noekeon-indirect`): the working key is the key
  encrypted, in direct mode, under the all-zero key. This is what Botan
  implements and what the specification recommends where related-key
  attacks matter.

The two agree on nothing, and nothing in a ciphertext says which was
used.

## The round

The state and the working key are four 32-bit words, big endian. A round
XORs a constant into word 0, applies `Θ` (a linear mixing that also adds
the working key), XORs a second constant, and applies `Π₁` (rotations),
`Γ` (a 4-bit S-box applied bit-slice-wise across the four words) and
`Π₂` (the inverse rotations). Encryption runs sixteen rounds with the
constants in word 0 before `Θ`, then XORs the seventeenth constant and
applies `Θ` once more. Decryption runs the same rounds in reverse order
with the constants after `Θ`, under the working key passed through `Θ`
with a zero key.

The round constants are `80`, then doubled in GF(2^8) modulo
`x^8 + x^4 + x^3 + x + 1` - AES's field - seventeen of them.

## Where the vectors come from

`vectors/noekeon.vec`, written by `scripts/make_noekeon_vectors.py`:
direct mode as libtomcrypt 1.18.2 and Bouncy Castle 1.77 agree on it,
with libtomcrypt's published tests; indirect mode as Botan 1.10.17 and
Bouncy Castle's direct mode under the definition agree on it, with
Botan's published tests from the NESSIE reference code.
*/

use super::BlockCipher;

const BLOCK: usize = 16;
const ROUNDS: usize = 16;

/// The round constants: `80`, doubled modulo 0x11b, seventeen of them.
const fn round_constants() -> [u32; ROUNDS + 1] {
    let mut out = [0u32; ROUNDS + 1];
    let mut c: u32 = 0x80;
    let mut i = 0;
    while i <= ROUNDS {
        out[i] = c;
        c <<= 1;
        if c & 0x100 != 0 {
            c ^= 0x11b;
        }
        i += 1;
    }
    out
}

const RC: [u32; ROUNDS + 1] = round_constants();

type Words = [u32; 4];

/// `Θ`: mix words 0 and 2 into 1 and 3, add the key, mix 1 and 3 into 0
/// and 2.
fn theta(a: &mut Words, k: &Words) {
    let mut t = a[0] ^ a[2];
    t ^= t.rotate_right(8) ^ t.rotate_left(8);
    a[1] ^= t;
    a[3] ^= t;
    for (w, k) in a.iter_mut().zip(k) {
        *w ^= k;
    }
    let mut t = a[1] ^ a[3];
    t ^= t.rotate_right(8) ^ t.rotate_left(8);
    a[0] ^= t;
    a[2] ^= t;
}

fn pi1(a: &mut Words) {
    a[1] = a[1].rotate_left(1);
    a[2] = a[2].rotate_left(5);
    a[3] = a[3].rotate_left(2);
}

fn pi2(a: &mut Words) {
    a[1] = a[1].rotate_right(1);
    a[2] = a[2].rotate_right(5);
    a[3] = a[3].rotate_right(2);
}

/// `Γ`: the 4-bit S-box on every bit slice, as the specification writes
/// it in words. An involution.
fn gamma(a: &mut Words) {
    a[1] ^= !a[3] & !a[2];
    a[0] ^= a[2] & a[1];
    a.swap(0, 3);
    a[2] ^= a[0] ^ a[1] ^ a[3];
    a[1] ^= !a[3] & !a[2];
    a[0] ^= a[2] & a[1];
}

fn round(a: &mut Words, k: &Words, c1: u32, c2: u32) {
    a[0] ^= c1;
    theta(a, k);
    a[0] ^= c2;
    pi1(a);
    gamma(a);
    pi2(a);
}

fn load(bytes: &[u8]) -> Words {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4")))
}

/// Direct-mode encryption of one block of words.
fn encrypt_words(a: &mut Words, k: &Words) {
    for &c in &RC[..ROUNDS] {
        round(a, k, c, 0);
    }
    a[0] ^= RC[ROUNDS];
    theta(a, k);
}

#[derive(Clone)]
pub struct Noekeon {
    /// The working key, for encryption.
    enc: Words,
    /// The working key through `Θ` with a zero key, for decryption.
    dec: Words,
    indirect: bool,
}

impl Noekeon {
    /// Direct-key mode: the key is the working key.
    pub fn new(key: &[u8]) -> Result<Noekeon, String> {
        Ok(Noekeon::with_working_key(Noekeon::check(key)?, false))
    }

    /// Indirect-key mode: the working key is the key encrypted under the
    /// all-zero key.
    pub fn new_indirect(key: &[u8]) -> Result<Noekeon, String> {
        let mut working = Noekeon::check(key)?;
        encrypt_words(&mut working, &[0; 4]);
        Ok(Noekeon::with_working_key(working, true))
    }

    /// Whether the key was taken in indirect-key mode.
    pub fn is_indirect(&self) -> bool {
        self.indirect
    }

    fn check(key: &[u8]) -> Result<Words, String> {
        if key.len() != 16 {
            return Err(format!("Wrong key length {}. Noekeon takes 16 bytes.", key.len()));
        }
        Ok(load(key))
    }

    fn with_working_key(enc: Words, indirect: bool) -> Noekeon {
        let mut dec = enc;
        theta(&mut dec, &[0; 4]);
        Noekeon { enc, dec, indirect }
    }
}

impl BlockCipher for Noekeon {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut a = load(&input[..BLOCK]);
        encrypt_words(&mut a, &self.enc);
        for w in a {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut a = load(&input[..BLOCK]);
        for &c in RC[1..=ROUNDS].iter().rev() {
            round(&mut a, &self.dec, 0, c);
        }
        theta(&mut a, &self.dec);
        a[0] ^= RC[0];
        for w in a {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants the specification lists, from their rule.
    #[test]
    fn test_the_round_constants_follow_their_rule() {
        assert_eq!(RC[0], 0x80);
        assert_eq!(RC[1], 0x1b);
        for i in 1..=ROUNDS {
            let doubled = RC[i - 1] << 1;
            let reduced = if doubled & 0x100 != 0 { doubled ^ 0x11b } else { doubled };
            assert_eq!(RC[i], reduced);
        }
    }

    /// `Γ` and the composition `Π₂ Γ Π₁` are involutions, and `Θ` with a
    /// zero key is too.
    #[test]
    fn test_the_involutions() {
        let mut seed = 0x9e37_79b9u32;
        for _ in 0..500 {
            let a: Words = std::array::from_fn(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed
            });
            let mut b = a;
            gamma(&mut b);
            gamma(&mut b);
            assert_eq!(b, a);
            let mut b = a;
            theta(&mut b, &[0; 4]);
            theta(&mut b, &[0; 4]);
            assert_eq!(b, a);
        }
    }

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 15, 17, 32] {
            assert!(Noekeon::new(&vec![0u8; len]).is_err());
            assert!(Noekeon::new_indirect(&vec![0u8; len]).is_err());
        }
    }
}
