/*
RC5, Ron Rivest 1994, profiled for CBC use by RFC 2040.

Three parameters, written RC5-w/r/b: the word size `w`, the round count
`r` and the key length `b` in bytes. The block is two words. RC5-32/12/16
is the nominal cipher - 32 bit words, so a 64 bit block, twelve rounds
and a 128 bit key - and it is what "RC5" means in every deployment.

**Only w = 32 is implemented here**, deliberately. Rivest's paper allows
16 and 64 as well, but RFC 2040 profiles only 32, no published vectors
exist for the other two, and this library's rule is that an unverified
variant is worse than an absent one. The block size would change with
`w`, so adding them later is a new type rather than a parameter on this
one.

RC5 was patented (US 5,724,428, expired 2015), which is why it is
missing from a lot of software that is otherwise complete, and why
files and protocol traces encrypted with it are still out there with
nothing left to read them.

## What is unusual about it

**The rotation amount is data dependent.** `A <<< B` rotates by the low
five bits of the *other* half, which is what gives RC5 its strength with
so little code - and what makes it hard to implement in constant time.
No attempt is made here: see `docs/pitfalls.md`.

**Zero rounds is a legal cipher, not the identity.** RFC 2040's own test
vectors include `R = 0`, and the result is not the plaintext, because
the two words are still summed with `S[0]` and `S[1]` before the round
loop starts. That is the opposite of TEA, where zero rounds *is* the
identity and is refused - so the two neighbouring files disagree about
zero on purpose, and each says why.

**An empty key divides by zero** in RFC 2040's reference code: `LL`
comes out as 0 and the mixing loop does `j % LL`. Rivest's paper patches
around it by taking `c = max(1, ...)`. Refused here rather than patched,
because the RFC is what implementations followed and there is no
interoperable answer to agree with.

## Where the vectors come from

`rfcs/rfc2040.txt`, parsed at test time: 29 vectors, 27 CBC and 2
CBC-Pad, sweeping rounds 0, 1, 2, 8, 12 and 16 against key lengths of 1,
4, 5, 8 and 16 bytes. Nothing here was typed.

They are **CBC** vectors rather than raw block ones, which is better
than it sounds: CBC with an all-zero IV over a single block is ECB of
that block, so the rows with a zero IV pin the primitive, and the rest
pin the primitive and the mode wiring together.
*/

use crate::block_ciphers::BlockCipher;

/// `Odd(e - 2) * 2^32`, where `e` is the base of natural logarithms.
///
/// RFC 2040 states it as this hex constant; `test_the_magic_constants`
/// derives both from `e` and the golden ratio, so a mistyped digit fails
/// rather than quietly becoming this cipher's definition.
const P32: u32 = 0xb7e1_5163;

/// `Odd(phi - 1) * 2^32`. The same constant TEA steps its `sum` by, for
/// the same reason - both are Rivest-era choices of a "nothing up my
/// sleeve" number.
const Q32: u32 = 0x9e37_79b9;

/// RC5-32/**12**/16 is the nominal cipher, and twelve rounds is what
/// RFC 2040's security considerations call sufficient against linear
/// and differential cryptanalysis at this block size.
pub const DEFAULT_ROUNDS: usize = 12;

/// The round count RFC 2040's `R` field can hold. Rivest's paper says
/// 0..=255.
pub const MAX_ROUNDS: usize = 255;

const WORD_BYTES: usize = 4;
const BLOCK: usize = 8;

#[derive(Clone)]
pub struct Rc5 {
    /// The expanded key table, `2 * (rounds + 1)` words. Owned rather
    /// than a fixed array because the length is a parameter.
    s: Vec<u32>,
    rounds: usize,
}

impl Rc5 {
    pub fn new(key: &[u8]) -> Result<Rc5, String> {
        Rc5::with_rounds(key, DEFAULT_ROUNDS)
    }

    /// RC5-32/`rounds`/`key.len()`.
    ///
    /// Zero rounds is allowed, because RFC 2040 publishes vectors for it
    /// and it is not the identity function - the two words are still
    /// summed with `S[0]` and `S[1]`. It is of course not a cipher
    /// anybody should choose; `test_zero_rounds_is_a_legal_cipher_and_a_
    /// terrible_one` says both halves of that.
    pub fn with_rounds(key: &[u8], rounds: usize) -> Result<Rc5, String> {
        if key.is_empty() {
            return Err("RC5 needs at least one key byte. RFC 2040's key \
                        expansion divides by the number of key words, which \
                        is zero for an empty key.".to_string());
        }
        if key.len() > 255 {
            return Err(format!("Wrong key length {}. RC5 takes 1..=255 bytes.",
                               key.len()));
        }
        if rounds > MAX_ROUNDS {
            return Err(format!("RC5 takes 0..={} rounds, not {}.",
                               MAX_ROUNDS, rounds));
        }

        // RFC 2040 5.3: the key bytes go into `L` little endian, zero
        // padded on the right.
        let word_count = key.len().div_ceil(WORD_BYTES);
        let mut l = vec![0u32; word_count];
        for (i, &byte) in key.iter().enumerate() {
            l[i / WORD_BYTES] |= (byte as u32) << (8 * (i % WORD_BYTES));
        }

        // 5.4: `S[i] = P32 + i * Q32`, as a running sum so the wrap is
        // the same one the RFC's code makes.
        let table = 2 * (rounds + 1);
        let mut s = vec![0u32; table];
        s[0] = P32;
        for i in 1..table {
            s[i] = s[i - 1].wrapping_add(Q32);
        }

        // 5.5: three passes over the longer of the two arrays. `a` and
        // `b` carry across iterations, which is the part that makes this
        // a mixing function rather than a permutation of each word in
        // isolation.
        let (mut a, mut b) = (0u32, 0u32);
        let (mut i, mut j) = (0usize, 0usize);
        for _ in 0..3 * core::cmp::max(table, word_count) {
            a = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
            s[i] = a;
            // **The rotation is by `a + b`, and Rust's `rotate_left`
            // takes the amount mod 32 for a u32 already** - which is
            // what `ROT_MASK` does in the RFC. Writing `(a + b) % 32`
            // would be the same thing spelled twice.
            b = l[j].wrapping_add(a).wrapping_add(b)
                .rotate_left(a.wrapping_add(b));
            l[j] = b;
            i = (i + 1) % table;
            j = (j + 1) % word_count;
        }

        Ok(Rc5 { s, rounds })
    }

    /// The number of rounds this instance was built with, so a caller
    /// that took it from a file can check what it got.
    pub fn rounds(&self) -> usize {
        self.rounds
    }
}

/// RFC 2040 6.1: the first input byte is the least significant byte of
/// `A`. **Little endian**, which is the opposite of TEA next door and of
/// most of this library - and reading it the other way gives a cipher
/// that encrypts, decrypts and round-trips perfectly.
fn load(input: &[u8]) -> (u32, u32) {
    (u32::from_le_bytes(input[0..4].try_into().expect("four bytes")),
     u32::from_le_bytes(input[4..8].try_into().expect("four bytes")))
}

fn store(result: &mut Vec<u8>, a: u32, b: u32) {
    result.extend_from_slice(&a.to_le_bytes());
    result.extend_from_slice(&b.to_le_bytes());
}

impl BlockCipher for Rc5 {
    fn blocksize(&self) -> usize { BLOCK }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut a, mut b) = load(input);
        a = a.wrapping_add(self.s[0]);
        b = b.wrapping_add(self.s[1]);
        for i in 1..=self.rounds {
            a = (a ^ b).rotate_left(b).wrapping_add(self.s[2 * i]);
            b = (b ^ a).rotate_left(a).wrapping_add(self.s[2 * i + 1]);
        }
        store(result, a, b);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut a, mut b) = load(input);
        for i in (1..=self.rounds).rev() {
            // The inverse of `((b ^ a) <<< a) + S`: subtract, rotate
            // *right* by the other half, then XOR. The rotation amount
            // is `a`, which is the value `a` has at this point in the
            // reversed loop - so the two statements cannot be swapped.
            b = b.wrapping_sub(self.s[2 * i + 1]).rotate_right(a) ^ a;
            a = a.wrapping_sub(self.s[2 * i]).rotate_right(b) ^ b;
        }
        b = b.wrapping_sub(self.s[1]);
        a = a.wrapping_sub(self.s[0]);
        store(result, a, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_2040: &str = include_str!("../../rfcs/rfc2040.txt");

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "odd hex run {text:?}");
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                 .expect("two hex digits"))
            .collect()
    }

    struct Vector {
        padded: bool,
        rounds: usize,
        key: Vec<u8>,
        iv: Vec<u8>,
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
    }

    /// RFC 2040 section 9's vectors, read out of the document.
    ///
    /// They wrap in three different places - the key onto its own line,
    /// the IV onto its own line, the ciphertext onto its own line - and
    /// a page break sits in the middle of the list. So the lines are
    /// filtered and joined with a space and the fields are matched
    /// wherever they land, rather than the list being read positionally.
    ///
    /// **The count is asserted.** A parser that finds nothing turns
    /// every loop below into a pass, which has happened in this
    /// repository in four different documents now.
    fn published_vectors() -> Vec<Vector> {
        let start = RFC_2040.find("RC5_CBC     R =  0 Key = 00")
            .expect("RFC 2040 has no test vector section");
        let end = RFC_2040[start..].find("10. Security Considerations")
            .expect("RFC 2040 lost its security considerations") + start;

        // Page furniture. Matched by what it *is* - a running header and
        // a footer with the authors' names - because the alternative is
        // matching what the data is, and a hex run split across a page
        // would then be silently joined to the wrong field.
        let joined: String = RFC_2040[start..end].lines()
            .filter(|line| !line.contains("Baldwin & Rivest")
                        && !line.starts_with("RFC 2040"))
            .collect::<Vec<_>>()
            .join(" ");

        // One record per `RC5_CBC` tag. Split first, then read the
        // fields inside a record, so a search cannot run past the end
        // of one row into the next - which is how a wrapped row would
        // otherwise steal the following row's ciphertext.
        let mut starts: Vec<usize> = Vec::new();
        let mut from = 0;
        while let Some(at) = joined[from..].find("RC5_CBC") {
            starts.push(from + at);
            from += at + "RC5_CBC".len();
        }

        /// `name = <hex>`, where the document writes the separator with
        /// spaces around it. Matched as a whole token rather than as a
        /// substring: **`field(record, "P")` used to find the `P` in
        /// `RC5_CBC_Pad`** and read `ad` as the plaintext, which is the
        /// RFC 3394 lesson in a new document. Requiring an `=` after the
        /// name is what makes it a field rather than a letter.
        fn field(record: &str, name: &str) -> Option<String> {
            let mut from = 0;
            while let Some(at) = record[from..].find(name) {
                let after = from + at + name.len();
                let rest = &record[after..];
                let value: String = rest.chars()
                    .skip_while(|c| *c == ' ')
                    .skip_while(|c| *c == '=')
                    .skip_while(|c| *c == ' ')
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                // The `=` has to actually be there, and the value has to
                // be non-empty, or this is a letter inside a word.
                let has_equals = rest.trim_start().starts_with('=');
                if has_equals && !value.is_empty() {
                    return Some(value);
                }
                from = after;
            }
            None
        }

        let mut vectors = Vec::new();
        for (n, &at) in starts.iter().enumerate() {
            let end = starts.get(n + 1).copied().unwrap_or(joined.len());
            let record = &joined[at..end];
            let padded = record.starts_with("RC5_CBC_Pad");
            let tag = if padded { "RC5_CBC_Pad" } else { "RC5_CBC" };
            let record = &record[tag.len()..];

            let (Some(rounds), Some(key), Some(iv), Some(plaintext),
                 Some(ciphertext)) =
                (field(record, "R"), field(record, "Key"), field(record, "IV"),
                 field(record, "P"), field(record, "C"))
            else { continue };

            vectors.push(Vector {
                padded,
                rounds: rounds.parse::<usize>()
                    .expect("R is a decimal number"),
                key: unhex(&key),
                iv: unhex(&iv),
                plaintext: unhex(&plaintext),
                ciphertext: unhex(&ciphertext),
            });
        }

        assert_eq!(vectors.len(), 29,
                   "RFC 2040 section 9 publishes 29 vectors; found {}",
                   vectors.len());
        vectors
    }

    // -------------------------------------------------- the constants ---

    #[test]
    fn test_the_magic_constants() {
        // RFC 2040 defines `Pw = Odd((e - 2) * 2^w)` and
        // `Qw = Odd((phi - 1) * 2^w)`, where `Odd` rounds to the nearest
        // odd integer. Deriving them is a second opinion about sixteen
        // hex digits, and a mistyped one gives a cipher that encrypts,
        // decrypts and agrees with nobody.
        let odd = |x: f64| -> u32 {
            let n = x.round() as u64;
            (if n.is_multiple_of(2) { n + 1 } else { n }) as u32
        };
        let two32 = 2.0f64.powi(32);
        assert_eq!(P32, odd((std::f64::consts::E - 2.0) * two32));
        assert_eq!(Q32, odd(((1.0 + 5.0f64.sqrt()) / 2.0 - 1.0) * two32));

        // And Q32 is TEA's delta, which is not a coincidence but is
        // worth pinning so that a change to either file is noticed by
        // the other.
        assert_eq!(Q32, 0x9e37_79b9);
    }

    // --------------------------------------------- RFC 2040 section 9 ---

    #[test]
    fn test_the_published_vectors() {
        let vectors = published_vectors();
        let mut plain = 0;
        let mut padded = 0;

        for v in &vectors {
            let mut cipher = Rc5::with_rounds(&v.key, v.rounds).unwrap();
            let mut out = Vec::new();

            if v.padded {
                // RC5-CBC-Pad is CBC over the message with the padding
                // RFC 2040 8.2 describes, which is PKCS#7's rule: 1..=8
                // bytes, each holding the count.
                let mut padded_input = v.plaintext.clone();
                cipher.pad_pkcs7(&mut padded_input);
                cipher.cbc_encrypt(&padded_input, &mut out, &v.iv)
                    .unwrap();
                padded += 1;
            } else {
                cipher.cbc_encrypt(&v.plaintext, &mut out, &v.iv)
                    .unwrap();
                plain += 1;
            }

            assert_eq!(hex(&out), hex(&v.ciphertext),
                       "R = {} Key = {} IV = {} P = {}",
                       v.rounds, hex(&v.key), hex(&v.iv), hex(&v.plaintext));

            let mut back = Vec::new();
            let mut cipher = Rc5::with_rounds(&v.key, v.rounds).unwrap();
            cipher.cbc_decrypt(&v.ciphertext, &mut back, &v.iv).unwrap();
            let expected = if v.padded {
                let mut padded = v.plaintext.clone();
                cipher.pad_pkcs7(&mut padded);
                padded
            } else {
                v.plaintext.clone()
            };
            assert_eq!(hex(&back), hex(&expected), "decrypting back");
        }

        assert_eq!((plain, padded), (27, 2),
                   "the split between CBC and CBC-Pad rows has changed");
    }

    #[test]
    fn test_the_vectors_sweep_the_parameter_space() {
        // The value of this vector set is that it varies *two*
        // parameters, and a parser that dropped the wrapped rows would
        // still leave a plausible list. This says which ground it
        // covers, so shrinking it is a failure rather than a smaller
        // number nobody remembers.
        let vectors = published_vectors();
        let rounds: std::collections::BTreeSet<usize> =
            vectors.iter().map(|v| v.rounds).collect();
        let key_lengths: std::collections::BTreeSet<usize> =
            vectors.iter().map(|v| v.key.len()).collect();
        assert_eq!(rounds.into_iter().collect::<Vec<_>>(),
                   vec![0, 1, 2, 8, 12, 16]);
        assert_eq!(key_lengths.into_iter().collect::<Vec<_>>(),
                   vec![1, 4, 5, 8, 16]);

        // And at least one row is several blocks long, or the CBC
        // chaining is never exercised by them at all.
        assert!(vectors.iter().any(|v| v.plaintext.len() > BLOCK));
    }

    #[test]
    fn test_a_zero_iv_row_pins_the_bare_block_function() {
        // CBC with an all-zero IV over one block *is* ECB of that block,
        // by CBC's definition rather than by a trick. So the published
        // vectors reach `block_encrypt` directly, and this says so -
        // otherwise every claim above could be satisfied by a correct
        // CBC over a wrong primitive and a compensating error.
        let v = published_vectors().into_iter()
            .find(|v| !v.padded && v.iv.iter().all(|&b| b == 0)
                   && v.plaintext.len() == BLOCK)
            .expect("no single-block zero-IV row");
        let mut cipher = Rc5::with_rounds(&v.key, v.rounds).unwrap();
        let mut out = Vec::new();
        cipher.block_encrypt(&v.plaintext, &mut out);
        assert_eq!(hex(&out), hex(&v.ciphertext));
    }

    // ----------------------------------------------------- the design ---

    #[test]
    fn test_zero_rounds_is_a_legal_cipher_and_a_terrible_one() {
        // **The opposite decision from TEA next door**, and the reason
        // each file states it: TEA with zero rounds is the identity and
        // is refused, while RC5 with zero rounds still adds `S[0]` and
        // `S[1]`, so it is a key-dependent transformation that RFC 2040
        // publishes vectors for.
        let mut cipher = Rc5::with_rounds(&[0u8], 0).unwrap();
        let mut out = Vec::new();
        cipher.block_encrypt(&[0u8; 8], &mut out);
        assert_ne!(out, vec![0u8; 8], "zero rounds must not be the identity");

        // It is still trivially broken: with no rounds the ciphertext is
        // the plaintext plus two fixed words, so the difference between
        // two ciphertexts is the difference between their plaintexts.
        let mut other = Vec::new();
        cipher.block_encrypt(&[0u8, 0, 0, 0, 0, 0, 0, 1], &mut other);
        let first = u32::from_le_bytes(out[4..8].try_into().unwrap());
        let second = u32::from_le_bytes(other[4..8].try_into().unwrap());
        assert_eq!(second.wrapping_sub(first), 1 << 24,
                   "with no rounds RC5 is an addition, which is the point \
                    of the round count");
    }

    #[test]
    fn test_an_empty_key_is_refused_with_the_reason() {
        let message = Rc5::new(&[]).err().expect("an empty key is refused");
        assert!(message.contains("divides by"), "{}", message);
    }

    #[test]
    fn test_the_key_length_and_round_bounds() {
        assert!(Rc5::new(&[0u8; 1]).is_ok());
        assert!(Rc5::new(&[0u8; 255]).is_ok());
        assert!(Rc5::new(&[0u8; 256]).is_err());
        assert!(Rc5::with_rounds(&[0u8; 16], MAX_ROUNDS).is_ok());
        assert!(Rc5::with_rounds(&[0u8; 16], MAX_ROUNDS + 1).is_err());
    }

    #[test]
    fn test_the_block_is_read_little_endian() {
        // The opposite of TEA next door, and reading it the other way
        // gives a cipher that round-trips perfectly. The published
        // vectors settle it; this says which decision they settled, so a
        // reader does not have to run them to find out.
        //
        // With zero rounds the ciphertext is the plaintext plus `S[0]`
        // and `S[1]`, so a one-bit change in the *first* input byte must
        // move the *low* byte of the first output word.
        let mut cipher = Rc5::with_rounds(&[0u8], 0).unwrap();
        let mut zero = Vec::new();
        cipher.block_encrypt(&[0u8; 8], &mut zero);
        let mut one = Vec::new();
        cipher.block_encrypt(&[1, 0, 0, 0, 0, 0, 0, 0], &mut one);
        assert_eq!(one[0], zero[0].wrapping_add(1));
        assert_eq!(one[1..], zero[1..]);
    }

    #[test]
    fn test_a_different_round_count_is_a_different_cipher() {
        let key = b"sixteen byte key";
        let mut a = Rc5::with_rounds(key, 12).unwrap();
        let mut b = Rc5::with_rounds(key, 13).unwrap();
        let (mut x, mut y) = (Vec::new(), Vec::new());
        a.block_encrypt(&[0u8; 8], &mut x);
        b.block_encrypt(&[0u8; 8], &mut y);
        assert_ne!(x, y);
        assert_eq!(a.rounds(), 12);
    }

    #[test]
    fn test_the_key_schedule_mixes_the_whole_key() {
        // The mixing loop runs `3 * max(table, words)` times, so for a
        // long key and few rounds the key is longer than the table -
        // which is the branch RFC 2040 spells out as `if (LL > T)`. A
        // schedule that used `3 * T` always would drop the tail of a
        // long key, and only a vector with a long key and few rounds
        // would notice. RFC 2040 has no such row, so this is asserted
        // directly.
        let long: Vec<u8> = (0..200u8).collect();
        let mut changed = long.clone();
        changed[199] ^= 1;                       // the very last byte
        let mut a = Rc5::with_rounds(&long, 1).unwrap();
        let mut b = Rc5::with_rounds(&changed, 1).unwrap();
        let (mut x, mut y) = (Vec::new(), Vec::new());
        a.block_encrypt(&[0u8; 8], &mut x);
        b.block_encrypt(&[0u8; 8], &mut y);
        assert_ne!(x, y, "the last byte of a long key changed nothing");
    }

    #[test]
    fn test_a_short_key_is_zero_padded_and_not_repeated() {
        // RFC 2040 5.3 zero-pads the last word. Two of its own vectors
        // make the claim for us - `Key = 00` and `Key = 00000000` with
        // the same rounds give the same ciphertext, because one byte of
        // zero padded to a word is the same `L` as four - but only if
        // the padding is zeros and the word count follows the *byte*
        // length. Read out of the document rather than stated.
        let vectors = published_vectors();
        let one = vectors.iter()
            .find(|v| v.key == vec![0u8] && v.rounds == 2)
            .expect("the one-byte zero key row");
        let four = vectors.iter()
            .find(|v| v.key == vec![0u8; 4] && v.rounds == 2)
            .expect("the four-byte zero key row");
        assert_eq!(hex(&one.ciphertext), hex(&four.ciphertext),
                   "RFC 2040's own pair no longer agrees");

        // And they really do reach different key schedules, so the
        // agreement above is a fact about the padding rather than about
        // the key being ignored.
        assert_ne!(Rc5::with_rounds(&one.key, 2).unwrap().s.len(), 0);
        let mut different = Rc5::with_rounds(&[0, 0, 0, 1], 2).unwrap();
        let mut out = Vec::new();
        different.block_encrypt(&[0u8; 8], &mut out);
        assert_ne!(hex(&out), hex(&one.ciphertext));
    }

    #[test]
    fn test_round_tripping_every_mode() {
        let key = b"sixteen byte key";
        let iv = vec![7u8; 8];
        let plain: Vec<u8> = (0..64u8).collect();
        for mode in ["ecb", "cbc", "pcbc", "cfb", "ofb", "ctr"] {
            let mut cipher = Rc5::new(key).unwrap();
            let mut out = Vec::new();
            match mode {
                "ecb" => cipher.ecb_encrypt(&plain, &mut out).unwrap(),
                "cbc" => cipher.cbc_encrypt(&plain, &mut out, &iv).unwrap(),
                "pcbc" => cipher.pcbc_encrypt(&plain, &mut out, &iv).unwrap(),
                "cfb" => cipher.cfb_encrypt(&plain, &mut out, &iv).unwrap(),
                "ofb" => cipher.ofb_encrypt(&plain, &mut out, &iv).unwrap(),
                _ => cipher.ctr_encrypt(&plain, &mut out, &iv).unwrap(),
            }
            assert_ne!(out, plain, "{} did not encrypt", mode);

            let mut cipher = Rc5::new(key).unwrap();
            let mut back = Vec::new();
            match mode {
                "ecb" => cipher.ecb_decrypt(&out, &mut back).unwrap(),
                "cbc" => cipher.cbc_decrypt(&out, &mut back, &iv).unwrap(),
                "pcbc" => cipher.pcbc_decrypt(&out, &mut back, &iv).unwrap(),
                "cfb" => cipher.cfb_decrypt(&out, &mut back, &iv).unwrap(),
                "ofb" => cipher.ofb_decrypt(&out, &mut back, &iv).unwrap(),
                _ => cipher.ctr_decrypt(&out, &mut back, &iv).unwrap(),
            }
            assert_eq!(back, plain, "{} did not round-trip", mode);
        }
    }

    #[test]
    fn test_decryption_is_not_encryption_with_the_table_reversed() {
        // RC5's rotation amount is data dependent, so the inverse round
        // has to rotate *right* by the value the other half has at that
        // point - reversing the subkeys is not enough, the way it is for
        // a cipher with fixed rotations. A decryptor written that way
        // round-trips for zero rounds and nothing else, which is why
        // this checks a block whose halves differ.
        let mut cipher = Rc5::with_rounds(b"sixteen byte key", 12).unwrap();
        let block: Vec<u8> = (1..=8u8).collect();
        let mut out = Vec::new();
        cipher.block_encrypt(&block, &mut out);
        let mut back = Vec::new();
        cipher.block_decrypt(&out, &mut back);
        assert_eq!(back, block);
        assert_ne!(out, block);
    }
}
