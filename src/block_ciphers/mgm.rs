/*
MGM, Multilinear Galois Mode — RFC 9058.

An AEAD over any block cipher, and the one RFC 9367's TLS 1.3 cipher
suites are built on. Encrypt-then-MAC in one pass each way: a counter
mode for confidentiality, and a multilinear function over GF(2^n) for
authenticity.

    MGM-Encrypt(K, ICN, A, P):
        Y_1 = E_K(0 || ICN),  Y_{i+1} = incr_r(Y_i)
        C_i = P_i ^ E_K(Y_i)

        Z_1 = E_K(1 || ICN),  Z_{i+1} = incr_l(Z_i)
        H_i = E_K(Z_i)
        sum = XOR over i of  H_i (x) block_i        -- A first, then C
        T   = MSB_S( E_K( sum ^ ( H_last (x) (len(A) || len(C)) ) ) )

where `(x)` is multiplication in GF(2^n) and `n` is the cipher's block
size in bits.

## The four things that are silent when wrong

**`incr_l` and `incr_r` are different functions and both are used.**
`incr_r` steps the *right* half of the block and drives the keystream;
`incr_l` steps the *left* half and drives the authentication. RFC 9058
section 6 says plainly why: the two counter sequences must not run into
each other. Using one for both, or swapping them, produces a mode that
encrypts, authenticates, round-trips against itself perfectly, and
agrees with nobody - which is why the vectors below check `Y_i` and
`Z_i` against the document one block at a time rather than only checking
the tag.

**Each half wraps in its own width.** `incr_r` adds one modulo 2^{n/2}
to the right half and carries nothing into the left half. A `+= 1` over
the whole block as one big integer is identical for every message short
enough to test by hand and differs at the first wrap.

**The field is MSB-first**, unlike GHASH and unlike XTS. RFC 9058 §3
writes `X = (x_{n-1}, ..., x_0)` with `x_{n-1}` the leading bit of the
string, so the first byte's top bit is the highest-degree coefficient.
GHASH reverses the bits inside each byte and XTS is little endian at the
byte level as well; all three are GF(2^128) and no two of them agree.
The reduction polynomials differ too: `w^128 + w^7 + w^2 + w + 1` here
(0x87, which GHASH also uses under its own convention) and
`w^64 + w^4 + w^3 + w + 1` (0x1b) for a 64 bit block.

**The last multiplicand is the lengths, in bits, each n/2 wide.**
`len(A) || len(C)` is one block, and it is the *bit* length rather than
the byte length. A tag over byte lengths is a perfectly good tag over
the wrong number.

## Two things the mode refuses

**`|A| = 0` and `|P| = 0` together.** RFC 9058 section 6: with nothing
to authenticate, the tag no longer depends on the nonce at all, so one
captured tag forges every empty message under that key. The RFC states
this as a requirement on the caller (`0 < |A| + |P|`); here it is an
error, because a caller who does it gets no other warning.

**An ICN with its top bit set.** The nonce is `n-1` bits, and the
missing bit is the domain separator that keeps the keystream's counter
away from the authentication's: `0 || ICN` starts one and `1 || ICN`
starts the other. A caller handing over a full block would silently
have its top bit ignored, and two ICNs differing only there would
produce the same keystream - which is the one thing the mode says must
never happen. RFC 9367's TLS profile masks that bit itself, before this
code sees it, and says so at the call site.

## Whose job the nonce is

MGM has no nonce construction of its own: the ICN is supplied and must
be unique per message under a key. There is no counter in here and no
random draw, because both would be an opinion about a protocol this
module cannot see. RFC 9367 derives it from the sequence number and the
key block's IV; `src/tls/record_mgm.rs` does that.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::BlockCipher;

/// The low coefficients of the reduction polynomial, by block size.
///
/// `w^128 + w^7 + w^2 + w + 1` and `w^64 + w^4 + w^3 + w + 1`, RFC 9058
/// section 3. Returned rather than stored so a block size the standard
/// does not cover is an error at the one place that can explain it.
fn reduction_for(block_size: usize) -> Result<u8, String> {
    match block_size {
        16 => Ok(0x87),
        8 => Ok(0x1b),
        other => Err(format!(
            "MGM is defined for 64 and 128 bit blocks (RFC 9058 section 3 \
             gives a field polynomial for each); this cipher's block is {} \
             bits.", other * 8)),
    }
}

/// Multiply by `w` in GF(2^n), in place: a left shift of the whole
/// string, with the bit that leaves the top folded back in.
///
/// MSB-first, so "up in degree" is "left in the string".
fn times_w(value: &mut [u8], reduction: u8) {
    let overflow = value[0] >> 7;
    let last = value.len() - 1;
    for i in 0..last {
        value[i] = (value[i] << 1) | (value[i + 1] >> 7);
    }
    value[last] <<= 1;
    // Branchless: a conditional XOR here is a branch on a bit of a
    // value derived from the key, and this is a MAC.
    value[last] ^= reduction & overflow.wrapping_neg();
}

/// `a (x) b` in GF(2^n), RFC 9058 section 3.
///
/// Horner over the bits of `a` from the highest degree down, which is
/// left to right through the string.
pub(crate) fn gf_mul(a: &[u8], b: &[u8], reduction: u8) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len());
    let mut product = vec![0u8; a.len()];
    for byte in a {
        for bit in (0..8).rev() {
            times_w(&mut product, reduction);
            // `wrapping_neg` on 0 or 1 gives 0x00 or 0xff: the same
            // masked form the rest of this file uses, so no branch
            // depends on the multiplicand.
            let mask = ((byte >> bit) & 1).wrapping_neg();
            for (p, v) in product.iter_mut().zip(b) {
                *p ^= v & mask;
            }
        }
    }
    product
}

/// `incr_r`: add one to the **right** half, modulo 2^{n/2}.
///
/// The carry stops at the halfway point. It does not reach the left
/// half, which is a different counter.
fn incr_r(block: &mut [u8]) {
    let half = block.len() / 2;
    for i in (half..block.len()).rev() {
        let (value, carried) = block[i].overflowing_add(1);
        block[i] = value;
        if !carried {
            return;
        }
    }
}

/// `incr_l`: add one to the **left** half, modulo 2^{n/2}.
fn incr_l(block: &mut [u8]) {
    let half = block.len() / 2;
    for i in (0..half).rev() {
        let (value, carried) = block[i].overflowing_add(1);
        block[i] = value;
        if !carried {
            return;
        }
    }
}

/// One MGM operation over a named cipher.
///
/// Holds the cipher name and key rather than a built cipher, like
/// `Eax`, so one `Mgm` can serve several messages without the caller
/// rebuilding a key schedule - the schedule is built once per call
/// inside, which is where the borrow can be exclusive.
pub struct Mgm {
    cipher_name: String,
    key: Vec<u8>,
    block_size: usize,
    reduction: u8,
    tag_len: usize,
}

impl Mgm {
    /// The full-width tag, which is the block size.
    pub fn new(cipher_name: &str, key: &[u8]) -> Result<Mgm, String> {
        let block_size = AnyBlockCipher::new(cipher_name, key, None)?.blocksize();
        let reduction = reduction_for(block_size)?;
        Ok(Mgm {
            cipher_name: cipher_name.to_string(),
            key: key.to_vec(),
            block_size,
            reduction,
            tag_len: block_size,
        })
    }

    /// A shorter tag. RFC 9058 section 4 allows `32 <= S <= n` bits and
    /// requires S to be fixed by the protocol rather than chosen per
    /// message, which is why it belongs to this object and not to
    /// `encrypt`.
    pub fn with_tag_len(cipher_name: &str, key: &[u8], tag_len: usize)
                        -> Result<Mgm, String> {
        let mut mgm = Mgm::new(cipher_name, key)?;
        if !(4..=mgm.block_size).contains(&tag_len) {
            return Err(format!(
                "An MGM tag is 4..={} bytes for this cipher (RFC 9058 \
                 section 4: 32 <= S <= n); {} was asked for.",
                mgm.block_size, tag_len));
        }
        mgm.tag_len = tag_len;
        Ok(mgm)
    }

    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// The ICN this mode takes: one block wide, with the top bit clear.
    fn check_icn(&self, icn: &[u8]) -> Result<(), String> {
        if icn.len() != self.block_size {
            return Err(format!(
                "An MGM initial counter nonce is one block, {} bytes here; \
                 got {}.", self.block_size, icn.len()));
        }
        if icn[0] & 0x80 != 0 {
            return Err(
                "An MGM initial counter nonce is n-1 bits: the top bit of \
                 the first byte is the domain separator between the \
                 keystream's counter and the authentication's, and must be \
                 zero. Mask it at the point where the nonce is built, so \
                 two nonces differing only there cannot become one."
                    .to_string());
        }
        Ok(())
    }

    /// Both inputs empty makes the tag independent of the nonce.
    fn check_not_both_empty(&self, aad: &[u8], data: &[u8]) -> Result<(), String> {
        if aad.is_empty() && data.is_empty() {
            return Err(
                "MGM must not be given empty associated data and an empty \
                 message at the same time (RFC 9058 section 6): the tag then \
                 does not depend on the nonce, so one captured tag forges \
                 every such message under this key.".to_string());
        }
        Ok(())
    }

    fn cipher(&self) -> Result<AnyBlockCipher, String> {
        AnyBlockCipher::new(&self.cipher_name, &self.key, None)
    }

    /// `E_K` of one block, into a fresh vector.
    fn ek(cipher: &mut AnyBlockCipher, block: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(block.len());
        cipher.block_encrypt(block, &mut out);
        out
    }

    /// The counter-mode half, in place. Used for both directions - a
    /// counter mode is its own inverse, which is why encryption and
    /// decryption differ only in what order they do this and the tag.
    fn apply_keystream(&self, cipher: &mut AnyBlockCipher, icn: &[u8],
                       data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        // Y_1 = E_K(0 || ICN). The ICN's top bit is already zero, so
        // this is the ICN itself - written as a mask rather than left
        // implicit, because the value the *document* names is `0 || ICN`
        // and the two are only the same while `check_icn` holds.
        let mut counter = icn.to_vec();
        counter[0] &= 0x7f;
        let mut y = Self::ek(cipher, &counter);

        for chunk in data.chunks_mut(self.block_size) {
            let gamma = Self::ek(cipher, &y);
            // `zip` stops at the shorter, which is what makes the final
            // partial block MSB_u(E_K(Y_q)) without a special case.
            for (byte, mask) in chunk.iter_mut().zip(&gamma) {
                *byte ^= mask;
            }
            incr_r(&mut y);
        }
    }

    /// The multilinear half: the tag over `aad` then `ciphertext`.
    ///
    /// **The ciphertext, not the plaintext.** MGM is encrypt-then-MAC,
    /// and authenticating the plaintext here would round-trip against
    /// itself perfectly.
    fn tag_for(&self, cipher: &mut AnyBlockCipher, icn: &[u8], aad: &[u8],
               ciphertext: &[u8]) -> Vec<u8> {
        // Z_1 = E_K(1 || ICN).
        let mut separated = icn.to_vec();
        separated[0] |= 0x80;
        let mut z = Self::ek(cipher, &separated);

        let mut sum = vec![0u8; self.block_size];
        // A partial block is padded with zeros to the right, which is
        // safe here only because the lengths go into the last
        // multiplicand: without them, `A` and `A || 0x00` would have the
        // same tag.
        let mut padded = vec![0u8; self.block_size];
        for part in [aad, ciphertext] {
            for chunk in part.chunks(self.block_size) {
                let block = if chunk.len() == self.block_size {
                    chunk
                } else {
                    padded[..chunk.len()].copy_from_slice(chunk);
                    padded[chunk.len()..].fill(0);
                    &padded[..]
                };
                let h = Self::ek(cipher, &z);
                let term = gf_mul(&h, block, self.reduction);
                for (s, t) in sum.iter_mut().zip(&term) {
                    *s ^= t;
                }
                incr_l(&mut z);
            }
        }

        // len(A) || len(C), each n/2 bytes, **in bits**.
        let half = self.block_size / 2;
        let mut lengths = vec![0u8; self.block_size];
        let bits_a = (aad.len() as u128) * 8;
        let bits_c = (ciphertext.len() as u128) * 8;
        for i in 0..half {
            lengths[half - 1 - i] = (bits_a >> (8 * i)) as u8;
            lengths[self.block_size - 1 - i] = (bits_c >> (8 * i)) as u8;
        }

        let h = Self::ek(cipher, &z);
        let term = gf_mul(&h, &lengths, self.reduction);
        for (s, t) in sum.iter_mut().zip(&term) {
            *s ^= t;
        }

        let mut tag = Self::ek(cipher, &sum);
        tag.truncate(self.tag_len);
        tag
    }

    /// Encrypt, returning `(ciphertext, tag)`.
    pub fn encrypt(&self, icn: &[u8], aad: &[u8], plaintext: &[u8])
                   -> Result<(Vec<u8>, Vec<u8>), String> {
        self.check_icn(icn)?;
        self.check_not_both_empty(aad, plaintext)?;

        let mut cipher = self.cipher()?;
        let mut ciphertext = plaintext.to_vec();
        self.apply_keystream(&mut cipher, icn, &mut ciphertext);
        let tag = self.tag_for(&mut cipher, icn, aad, &ciphertext);
        Ok((ciphertext, tag))
    }

    /// Decrypt, checking the tag **before** producing any plaintext.
    pub fn decrypt(&self, icn: &[u8], aad: &[u8], ciphertext: &[u8],
                   tag: &[u8]) -> Result<Vec<u8>, String> {
        self.check_icn(icn)?;
        self.check_not_both_empty(aad, ciphertext)?;
        if tag.len() != self.tag_len {
            return Err(format!("An MGM tag is {} bytes here; got {}.",
                               self.tag_len, tag.len()));
        }

        let mut cipher = self.cipher()?;
        let expected = self.tag_for(&mut cipher, icn, aad, ciphertext);
        // Constant time and over the whole tag: a comparison that stops
        // at the first differing byte is a forgery oracle.
        if crate::bignum::ct::bytes_differ(&expected, tag) {
            return Err("The MGM tag does not match; the message was altered \
                        or was not for this key.".to_string());
        }

        // Only now. Returning plaintext before the tag is checked is
        // release-of-unverified-plaintext, which is the one thing an
        // AEAD exists to prevent.
        let mut plaintext = ciphertext.to_vec();
        self.apply_keystream(&mut cipher, icn, &mut plaintext);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9058, unmodified. Nothing below is transcribed: the four
    /// worked examples are read out of this text at test time, so a
    /// refetched document updates the vectors and a mistyped nibble is
    /// not possible.
    const RFC_9058: &str = include_str!("../../rfcs/rfc9058.txt");

    /// One labelled hex dump from the appendix.
    ///
    /// The format is a label line ending in a colon, then lines of
    /// `00000:   AA BB ...`. An **empty** value is a bare `00000:` with
    /// nothing after it, which is how the second example states its
    /// empty plaintext - so "no bytes" and "no such label" have to stay
    /// distinguishable, and `None` versus `Some(vec![])` is that.
    fn dump_after(section: &str, label: &str) -> Option<Vec<u8>> {
        let mut lines = section.lines();
        while let Some(line) = lines.next() {
            if line.trim() != label {
                continue;
            }
            let mut bytes = Vec::new();
            for following in lines.by_ref() {
                let trimmed = following.trim();
                if trimmed.is_empty() {
                    // A blank line inside a dump does not occur; a blank
                    // line after one ends it.
                    if bytes.is_empty() {
                        continue;
                    }
                    break;
                }
                let Some((offset, rest)) = trimmed.split_once(':') else {
                    break;
                };
                if offset.len() != 5 || !offset.chars().all(|c| c.is_ascii_hexdigit()) {
                    break;
                }
                for pair in rest.split_whitespace() {
                    bytes.push(u8::from_str_radix(pair, 16)
                        .unwrap_or_else(|_| panic!("{label}: {pair:?} is not a byte")));
                }
            }
            return Some(bytes);
        }
        None
    }

    struct Example {
        name: String,
        cipher: &'static str,
        section: String,
    }

    impl Example {
        fn need(&self, label: &str) -> Vec<u8> {
            dump_after(&self.section, label)
                .unwrap_or_else(|| panic!("{}: no {:?} in the document",
                                          self.name, label))
        }
    }

    /// The appendix, split into its four worked examples.
    ///
    /// The headings appear twice - once in the table of contents and
    /// once over the text - so the search starts at `Appendix A.` where
    /// it is a heading of its own, which is the same `rfind` trap the
    /// other document parsers here have already paid for.
    fn examples() -> Vec<Example> {
        let start = RFC_9058.rfind("\nAppendix A.  Test Vectors")
            .expect("RFC 9058 has an appendix A");
        let appendix = &RFC_9058[start..];

        let headings = [("A.1.1.", "kuznyechik"), ("A.1.2.", "kuznyechik"),
                        ("A.2.1.", "magma"), ("A.2.2.", "magma")];
        let mut found = Vec::new();
        for (index, (heading, cipher)) in headings.iter().enumerate() {
            let from = appendix.find(&format!("\n{heading}  Example"))
                .unwrap_or_else(|| panic!("{heading} is missing"));
            let to = headings.get(index + 1)
                .and_then(|(next, _)| appendix.find(&format!("\n{next}  Example")))
                .unwrap_or(appendix.len());
            // A.1.2 is followed by A.2's own heading before A.2.1, and
            // the ranges must not overlap; `to > from` catches a
            // heading found earlier in the text than the one before it.
            assert!(to > from, "{heading}: the sections are out of order");
            found.push(Example {
                name: heading.to_string(),
                cipher,
                section: appendix[from..to].to_string(),
            });
        }
        found
    }

    /// The count, before anything uses what was found. A parser that
    /// finds nothing turns every vector test below into an empty loop
    /// that passes.
    #[test]
    fn test_the_document_parses() {
        let found = examples();
        assert_eq!(found.len(), 4, "RFC 9058 has four worked examples");
        for example in &found {
            let key = example.need("Encryption key K:");
            let icn = example.need("ICN:");
            assert_eq!(key.len(), 32, "{}: MGM's ciphers take 256 bit keys",
                       example.name);
            assert_eq!(icn.len(), if example.cipher == "magma" { 8 } else { 16 },
                       "{}: the ICN is one block", example.name);
            assert_eq!(example.need("Tag T:").len(), icn.len());
            assert!(dump_after(&example.section, "Plaintext P:").is_some());
        }

        // The two edge cases the mode's `|A| + |P| > 0` rule stands
        // next to are each in the document exactly once, and they are
        // *different* examples: A.1.2 authenticates without encrypting
        // (q = 0) and A.2.2 encrypts without authenticating anything
        // extra (h = 0). Asserted because a parser that returned
        // nothing for every label would also make both counts zero.
        let no_plaintext = found.iter()
            .filter(|e| e.need("Plaintext P:").is_empty()).count();
        let no_aad = found.iter()
            .filter(|e| e.need("Associated authenticated data A:").is_empty())
            .count();
        assert_eq!((no_plaintext, no_aad), (1, 1),
                   "one example encrypts nothing and a different one \
                    authenticates no associated data");
        assert!(!found.iter().any(|e| e.need("Plaintext P:").is_empty()
                                   && e.need("Associated authenticated data A:")
                                        .is_empty()),
                "no example has both empty, which the mode refuses");
    }

    #[test]
    fn test_the_published_vectors() {
        for example in examples() {
            let key = example.need("Encryption key K:");
            let icn = example.need("ICN:");
            let aad = example.need("Associated authenticated data A:");
            let plaintext = example.need("Plaintext P:");
            let want_c = example.need("C:");
            let want_tag = example.need("Tag T:");

            let mgm = Mgm::new(example.cipher, &key).unwrap();
            let (ciphertext, tag) = mgm.encrypt(&icn, &aad, &plaintext)
                .unwrap_or_else(|e| panic!("{}: {e}", example.name));

            assert_eq!(ciphertext, want_c, "{}: ciphertext", example.name);
            assert_eq!(tag, want_tag, "{}: tag", example.name);

            let back = mgm.decrypt(&icn, &aad, &ciphertext, &tag).unwrap();
            assert_eq!(back, plaintext, "{}: round trip", example.name);
        }
    }

    /// The counters, one block at a time.
    ///
    /// The tag check above would fail if these were wrong, but it would
    /// fail the same way for any of a dozen mistakes. `Y_i` and `Z_i`
    /// are where `incr_r` and `incr_l` are visible separately, and the
    /// document prints both sequences.
    #[test]
    fn test_the_two_counter_sequences_match_the_document() {
        let mut checked = 0;
        for example in examples() {
            let key = example.need("Encryption key K:");
            let icn = example.need("ICN:");
            let mut cipher = AnyBlockCipher::new(example.cipher, &key, None).unwrap();

            // Y_1 = E_K(0 || ICN), then incr_r.
            let mut zero_led = icn.clone();
            zero_led[0] &= 0x7f;
            let mut y = Mgm::ek(&mut cipher, &zero_led);
            for i in 1.. {
                let Some(want) = dump_after(&example.section, &format!("Y_{i}:"))
                    else { break };
                assert_eq!(y, want, "{}: Y_{i}", example.name);
                let gamma = dump_after(&example.section, &format!("E_K(Y_{i}):"))
                    .unwrap_or_else(|| panic!("{}: Y_{i} without E_K(Y_{i})",
                                              example.name));
                assert_eq!(Mgm::ek(&mut cipher, &y), gamma,
                           "{}: E_K(Y_{i})", example.name);
                incr_r(&mut y);
                checked += 1;
            }

            // Z_1 = E_K(1 || ICN), then incr_l.
            let mut one_led = icn.clone();
            one_led[0] |= 0x80;
            let mut z = Mgm::ek(&mut cipher, &one_led);
            for i in 1.. {
                let Some(want) = dump_after(&example.section, &format!("Z_{i}:"))
                    else { break };
                assert_eq!(z, want, "{}: Z_{i}", example.name);
                let h = dump_after(&example.section, &format!("H_{i}:"))
                    .unwrap_or_else(|| panic!("{}: Z_{i} without H_{i}",
                                              example.name));
                assert_eq!(Mgm::ek(&mut cipher, &z), h, "{}: H_{i}", example.name);
                incr_l(&mut z);
                checked += 1;
            }
        }
        assert!(checked > 40, "only {checked} counter blocks were checked");
    }

    /// The field multiplication, against the document's own arithmetic.
    ///
    /// Each example prints `len(A) || len(C)` and the value of
    /// `sum ^ ( H_last (x) (len(A) || len(C)) )` just before the tag, so
    /// the last multiplication can be checked on its own - which is
    /// worth more than the tag, because the tag is `E_K` of this and a
    /// wrong product is indistinguishable from a wrong anything.
    #[test]
    fn test_the_field_multiplication_against_the_documents_own_arithmetic() {
        let mut checked = 0;
        for example in examples() {
            let key = example.need("Encryption key K:");
            let block = if example.cipher == "magma" { 8 } else { 16 };
            let reduction = reduction_for(block).unwrap();
            let mut cipher = AnyBlockCipher::new(example.cipher, &key, None).unwrap();

            // The label carries the index of the last H, which differs
            // per example, so it is searched for rather than assumed.
            let (last_index, want) = (1..40)
                .find_map(|index| {
                    let label = format!(
                        "sum (xor) ( H_{index} (x) ( len(A) || len(C) ) ):");
                    dump_after(&example.section, &label)
                        .map(|bytes| (index, bytes))
                })
                .unwrap_or_else(|| panic!("{}: no final sum", example.name));

            let aad = example.need("Associated authenticated data A:");
            let ciphertext = example.need("C:");
            // `h + q + 1` is where the lengths go in, so the index the
            // document printed says how many blocks it counted - and a
            // padding rule that dropped or added one would show here
            // before it showed in any tag.
            let blocks = |data: &[u8]| data.len().div_ceil(block);
            assert_eq!(last_index, blocks(&aad) + blocks(&ciphertext) + 1,
                       "{}: the document's H index is not h + q + 1",
                       example.name);

            // Walk the authentication half to the last H, which also
            // re-checks incr_l against the printed sequence.
            let mut one_led = example.need("ICN:");
            one_led[0] |= 0x80;
            let mut z = Mgm::ek(&mut cipher, &one_led);
            let mut sum = vec![0u8; block];
            let mut padded = vec![0u8; block];
            for part in [&aad, &ciphertext] {
                for chunk in part.chunks(block) {
                    padded[..chunk.len()].copy_from_slice(chunk);
                    padded[chunk.len()..].fill(0);
                    let term = gf_mul(&Mgm::ek(&mut cipher, &z), &padded, reduction);
                    for (s, t) in sum.iter_mut().zip(&term) {
                        *s ^= t;
                    }
                    incr_l(&mut z);
                }
            }

            let h = example.need(&format!("H_{last_index}:"));
            assert_eq!(Mgm::ek(&mut cipher, &z), h,
                       "{}: the last H", example.name);

            let lengths = example.need("len(A) || len(C):");
            let term = gf_mul(&h, &lengths, reduction);
            for (s, t) in sum.iter_mut().zip(&term) {
                *s ^= t;
            }
            assert_eq!(sum, want, "{}: the final sum", example.name);

            // The product on its own must not be the identity or zero,
            // or this comparison would hold for a multiplication that
            // did nothing.
            assert!(term.iter().any(|&b| b != 0), "{}: a zero product",
                    example.name);
            assert_ne!(term, lengths, "{}: the product is its own input",
                       example.name);
            checked += 1;
        }
        assert_eq!(checked, 4);
    }

    /// The lengths are in **bits**, and each half is n/2 wide.
    ///
    /// The document prints the block, so this is the one place the
    /// encoding is visible without arithmetic.
    #[test]
    fn test_the_length_block_is_bits() {
        for example in examples() {
            let block = if example.cipher == "magma" { 8 } else { 16 };
            let half = block / 2;
            let aad = example.need("Associated authenticated data A:");
            let ciphertext = example.need("C:");
            let printed = example.need("len(A) || len(C):");

            assert_eq!(printed.len(), block, "{}", example.name);
            let left = u64::from_str_radix(
                &printed[..half].iter().map(|b| format!("{b:02x}"))
                    .collect::<String>(), 16).unwrap();
            let right = u64::from_str_radix(
                &printed[half..].iter().map(|b| format!("{b:02x}"))
                    .collect::<String>(), 16).unwrap();
            assert_eq!(left, aad.len() as u64 * 8, "{}: len(A)", example.name);
            assert_eq!(right, ciphertext.len() as u64 * 8,
                       "{}: len(C)", example.name);
        }
    }

    /// `incr_l` and `incr_r` step different halves and neither carries
    /// into the other.
    ///
    /// The document's examples are all far too short to reach a wrap, so
    /// this is the only thing that checks the modulus. A block of `0xff`
    /// in one half and zeros in the other makes the wrap the whole
    /// observable.
    #[test]
    fn test_each_counter_wraps_in_its_own_half() {
        for block in [8usize, 16] {
            let half = block / 2;

            let mut right = vec![0u8; block];
            right[half..].fill(0xff);
            incr_r(&mut right);
            assert!(right.iter().all(|&b| b == 0),
                    "incr_r carried out of its half");

            let mut left = vec![0u8; block];
            left[..half].fill(0xff);
            incr_l(&mut left);
            assert!(left.iter().all(|&b| b == 0),
                    "incr_l carried out of its half");

            // And they are different functions: one step of each from
            // the same block lands in different places.
            let mut a = vec![0u8; block];
            let mut b = vec![0u8; block];
            incr_l(&mut a);
            incr_r(&mut b);
            assert_ne!(a, b);
        }
    }

    /// The field is MSB-first with these two polynomials, and the
    /// multiplication is a multiplication: `1` is the identity and `w`
    /// shifts.
    #[test]
    fn test_the_field_has_an_identity_and_the_stated_polynomial() {
        for (block, reduction) in [(8usize, 0x1bu8), (16, 0x87)] {
            let mut one = vec![0u8; block];
            one[block - 1] = 1;
            let value: Vec<u8> = (0..block)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(1)).collect();
            assert_eq!(gf_mul(&value, &one, reduction), value, "1 is not the identity");
            assert_eq!(gf_mul(&one, &value, reduction), value, "not commutative");

            // w * w^{n-1} = w^n = f(w) - w^n, the reduction itself.
            let mut w = vec![0u8; block];
            w[block - 1] = 2;
            let mut top = vec![0u8; block];
            top[0] = 0x80;
            let mut expected = vec![0u8; block];
            expected[block - 1] = reduction;
            assert_eq!(gf_mul(&w, &top, reduction), expected,
                       "the reduction polynomial is not the stated one");
        }
        // And the two fields are not the same field.
        let a: Vec<u8> = (0..8).map(|i| i as u8 + 3).collect();
        let b: Vec<u8> = (0..8).map(|i| i as u8 * 5 + 1).collect();
        assert_ne!(gf_mul(&a, &b, 0x1b), gf_mul(&a, &b, 0x87));
    }

    /// The tag covers the ciphertext, the associated data, **and** their
    /// lengths. Each of the four is changed on its own.
    #[test]
    fn test_every_input_reaches_the_tag() {
        let key = [0x11u8; 32];
        let icn = [0x22u8; 16];
        let mgm = Mgm::new("kuznyechik", &key).unwrap();
        let (base, tag) = mgm.encrypt(&icn, b"header", b"message").unwrap();

        // A different nonce.
        let mut other_icn = icn;
        other_icn[15] ^= 1;
        assert_ne!(mgm.encrypt(&other_icn, b"header", b"message").unwrap().1, tag);
        // Different associated data of the same length.
        assert_ne!(mgm.encrypt(&icn, b"heager", b"message").unwrap().1, tag);
        // A longer one with the same prefix: the length block is what
        // separates these, since the short one is zero padded.
        assert_ne!(mgm.encrypt(&icn, b"header\x00", b"message").unwrap().1, tag);
        // A different message.
        assert_ne!(mgm.encrypt(&icn, b"header", b"messagf").unwrap().1, tag);
        // A different key.
        let other = Mgm::new("kuznyechik", &[0x12u8; 32]).unwrap();
        assert_ne!(other.encrypt(&icn, b"header", b"message").unwrap().1, tag);

        // And every single-bit change to the ciphertext is refused.
        for byte in 0..base.len() {
            for bit in 0..8 {
                let mut altered = base.clone();
                altered[byte] ^= 1 << bit;
                assert!(mgm.decrypt(&icn, b"header", &altered, &tag).is_err(),
                        "byte {byte} bit {bit} was accepted");
            }
        }
        for byte in 0..tag.len() {
            let mut altered = tag.clone();
            altered[byte] ^= 0x80;
            assert!(mgm.decrypt(&icn, b"header", &base, &altered).is_err());
        }
    }

    /// Both empty is refused rather than answered.
    #[test]
    fn test_empty_data_and_empty_aad_together_are_refused() {
        let mgm = Mgm::new("kuznyechik", &[0x33u8; 32]).unwrap();
        let icn = [0x44u8; 16];
        assert!(mgm.encrypt(&icn, b"", b"").is_err());
        assert!(mgm.decrypt(&icn, b"", b"", &[0u8; 16]).is_err());
        // Either one alone is fine, and they give different tags.
        let only_aad = mgm.encrypt(&icn, b"a", b"").unwrap();
        let only_data = mgm.encrypt(&icn, b"", b"a").unwrap();
        assert_ne!(only_aad.1, only_data.1,
                   "a byte of header and a byte of message are the same tag");
    }

    /// An ICN with its top bit set is refused rather than masked.
    #[test]
    fn test_a_full_width_nonce_is_refused() {
        let mgm = Mgm::new("magma", &[0x55u8; 32]).unwrap();
        let mut icn = [0x01u8; 8];
        assert!(mgm.encrypt(&icn, b"a", b"b").is_ok());
        icn[0] |= 0x80;
        let refused = mgm.encrypt(&icn, b"a", b"b").unwrap_err();
        assert!(refused.contains("top bit"), "{refused}");
        // And the wrong length.
        assert!(mgm.encrypt(&[0x01u8; 7], b"a", b"b").is_err());
        assert!(mgm.encrypt(&[0x01u8; 16], b"a", b"b").is_err());
    }

    /// A block size the standard gives no polynomial for is an error at
    /// construction, not a wrong answer later.
    #[test]
    fn test_a_cipher_with_no_field_is_refused() {
        // Every 64 and 128 bit cipher here works; nothing else does.
        assert!(Mgm::new("aes", &[0u8; 16]).is_ok());
        assert!(Mgm::new("magma", &[0u8; 32]).is_ok());
        assert!(Mgm::new("des", &[0u8; 8]).is_ok());
        assert!(reduction_for(32).is_err());
    }

    /// The tag may be truncated, within the range the standard gives.
    #[test]
    fn test_a_truncated_tag_is_the_prefix_and_the_range_is_checked() {
        let key = [0x66u8; 32];
        let icn = [0x01u8; 16];
        let full = Mgm::new("kuznyechik", &key).unwrap()
            .encrypt(&icn, b"h", b"m").unwrap().1;
        for length in [4usize, 8, 12, 16] {
            let short = Mgm::with_tag_len("kuznyechik", &key, length).unwrap();
            let (ciphertext, tag) = short.encrypt(&icn, b"h", b"m").unwrap();
            assert_eq!(tag, full[..length], "a truncated tag is a prefix");
            assert_eq!(short.decrypt(&icn, b"h", &ciphertext, &tag).unwrap(),
                       b"m".to_vec());
        }
        assert!(Mgm::with_tag_len("kuznyechik", &key, 3).is_err());
        assert!(Mgm::with_tag_len("kuznyechik", &key, 17).is_err());
        assert!(Mgm::with_tag_len("magma", &key, 9).is_err());
    }

    /// Every length across two block boundaries, so a partial final
    /// block and the transition into a new counter are both swept.
    #[test]
    fn test_round_trip_at_every_length() {
        for cipher in ["kuznyechik", "magma"] {
            let mgm = Mgm::new(cipher, &[0x77u8; 32]).unwrap();
            let icn = vec![0x12u8; mgm.block_size()];
            let message: Vec<u8> = (0..=90u8).collect();
            for length in 0..message.len() {
                let (ciphertext, tag) =
                    mgm.encrypt(&icn, b"aad", &message[..length]).unwrap();
                assert_eq!(ciphertext.len(), length);
                assert_eq!(mgm.decrypt(&icn, b"aad", &ciphertext, &tag).unwrap(),
                           message[..length].to_vec());
            }
        }
    }
}
