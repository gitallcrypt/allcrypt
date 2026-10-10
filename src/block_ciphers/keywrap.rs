/*
AES Key Wrap: RFC 3394, and the padded form from RFC 5649.

Encrypting a key with a key. It looks like a mode and is not one: there
is no IV, no nonce, nothing random anywhere, and the same key data under
the same key-encryption key always produces the same bytes. That is
deliberate - a wrapped key is stored, copied and compared, and a random
IV would make two copies of one key look like two keys.

What it buys instead of randomness is **integrity without a separate
MAC**. Six passes over the data mix every 64 bit half into every other
one, and unwrapping ends with a check against a known constant; a single
wrong bit anywhere gives a value that fails it. So `unwrap` either
returns the key or returns an error, and there is no third outcome.

## Where it is used

PKCS#11 `CKM_AES_KEY_WRAP`, CMS (RFC 3394 is what `id-aes128-wrap` in a
`KEKRecipientInfo` means), JOSE's `A128KW`, Kerberos, and the
`RFC3394WRAP` in GOST's own CMS profile. Anywhere one key is stored
under another.

## The two forms, and why both are here

RFC 3394 wraps a whole number of 64 bit blocks, at least two of them, so
it cannot wrap a 20 byte HMAC key or a 57 byte Ed448 key. RFC 5649 adds
a length field to the constant and zero pads to the next multiple of
eight, which covers any length from 1 byte up - and it is a *different*
algorithm, not an option: its constant differs, and the one-block case
skips the six passes entirely and is a single ECB encryption.

## What is easy to get wrong

**The integrity check must be constant time**, or the comparison is an
oracle for the wrapped key's first eight bytes. It is a fold here, not a
`==`.

**`t` counts from 1 and runs across the passes**: `t = n*j + i`, not
`i` alone and not a counter reset per pass. Getting it wrong gives a
wrap and an unwrap that agree with each other perfectly.

**Unwrapping runs the passes backwards in both loops.** The outer one
counts down from 5 and the inner from `n` to 1. Reversing only one of
them is self-consistent for `n = 1`, which is the case the RFC's first
vector does *not* cover - its smallest is two blocks.

**RFC 5649's padding check is part of the authentication.** The message
length in the constant has to be within eight bytes of the padded
length, and the pad bytes have to be zero. Skipping either accepts a
forgery that differs from a real wrap only in bytes nobody reads.
*/

use crate::block_ciphers::BlockCipher;

/// RFC 3394 section 2.2.3.1: the default initial value.
const IV: [u8; 8] = [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6];

/// RFC 5649 section 3: the alternative initial value's constant half.
/// The other four bytes are the message length.
const AIV: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];

/// The one block the cipher must produce, and an error rather than a
/// short buffer if it does not.
fn one_block(cipher: &mut dyn BlockCipher, input: &[u8], encrypt: bool)
             -> Result<[u8; 16], String> {
    let mut out = Vec::with_capacity(16);
    if encrypt {
        cipher.block_encrypt(input, &mut out);
    } else {
        cipher.block_decrypt(input, &mut out);
    }
    if out.len() != 16 {
        return Err(format!("The cipher produced {} bytes for a 16 byte block.",
                           out.len()));
    }
    let mut block = [0u8; 16];
    block.copy_from_slice(&out);
    Ok(block)
}

fn require_128_bit(cipher: &dyn BlockCipher) -> Result<(), String> {
    if cipher.blocksize() != 16 {
        return Err(format!(
            "Key wrap is defined for a 128 bit block; this cipher's block is \
             {} bytes. There is no 64 bit variant to fall back to.",
            cipher.blocksize()));
    }
    Ok(())
}

/// `a != b` folded into one byte, so the comparison does not stop at the
/// first difference.
fn differs(a: &[u8], b: &[u8]) -> bool {
    // One implementation, in `bignum::ct`, because a second copy of a
    // constant-time comparison is a second thing to get wrong and only
    // one of them would be noticed.
    crate::bignum::ct::bytes_differ(a, b)
}

/// The six-pass core, shared by both forms.
///
/// `registers` is `n` 64 bit blocks and `a` is the initial value; the
/// result is `a` after the passes, with `registers` updated in place.
fn wrap_core(cipher: &mut dyn BlockCipher, a: &mut [u8; 8],
             registers: &mut [[u8; 8]]) -> Result<(), String> {
    let n = registers.len() as u64;
    let mut block = [0u8; 16];
    for pass in 0..6u64 {
        for (index, register) in registers.iter_mut().enumerate() {
            block[..8].copy_from_slice(a);
            block[8..].copy_from_slice(register);
            let b = one_block(cipher, &block, true)?;

            // t = n*j + i, counting the passes from 0 and the blocks
            // from 1 - so `t` never repeats across the whole wrap.
            let t = n * pass + index as u64 + 1;
            a.copy_from_slice(&b[..8]);
            for (byte, counter) in a.iter_mut().rev().zip(t.to_le_bytes()) {
                *byte ^= counter;
            }
            register.copy_from_slice(&b[8..]);
        }
    }
    Ok(())
}

/// The six-pass core run backwards.
fn unwrap_core(cipher: &mut dyn BlockCipher, a: &mut [u8; 8],
               registers: &mut [[u8; 8]]) -> Result<(), String> {
    let n = registers.len() as u64;
    let mut block = [0u8; 16];
    for pass in (0..6u64).rev() {
        for index in (0..registers.len()).rev() {
            let t = n * pass + index as u64 + 1;
            let mut masked = *a;
            for (byte, counter) in masked.iter_mut().rev().zip(t.to_le_bytes()) {
                *byte ^= counter;
            }
            block[..8].copy_from_slice(&masked);
            block[8..].copy_from_slice(&registers[index]);
            let b = one_block(cipher, &block, false)?;
            a.copy_from_slice(&b[..8]);
            registers[index].copy_from_slice(&b[8..]);
        }
    }
    Ok(())
}

fn to_registers(data: &[u8]) -> Vec<[u8; 8]> {
    data.chunks(8)
        .map(|chunk| {
            let mut block = [0u8; 8];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

/// Wrap key data, RFC 3394.
///
/// The input must be a whole number of 64 bit blocks and at least two of
/// them - 16 bytes. The output is eight bytes longer than the input.
///
/// # Errors
/// A cipher whose block is not 128 bits, or key data that is shorter
/// than 16 bytes or not a multiple of 8. Use [`wrap_with_padding`] for
/// anything else; this refuses rather than padding silently, because a
/// wrap that pads and an unwrap that does not are the same bytes with
/// different lengths.
pub fn wrap(cipher: &mut dyn BlockCipher, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    require_128_bit(cipher)?;
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(format!(
            "RFC 3394 wraps at least two 64 bit blocks, so 16 bytes or more in \
             a multiple of 8; this is {} bytes. RFC 5649 (wrap_with_padding) \
             covers the other lengths.",
            plaintext.len()));
    }

    let mut a = IV;
    let mut registers = to_registers(plaintext);
    wrap_core(cipher, &mut a, &mut registers)?;

    let mut out = Vec::with_capacity(plaintext.len() + 8);
    out.extend_from_slice(&a);
    for register in &registers {
        out.extend_from_slice(register);
    }
    Ok(out)
}

/// Unwrap key data, RFC 3394.
///
/// # Errors
/// Anything that is not a valid wrapping under this key: the wrong
/// length, or an integrity check that fails. The error does not say
/// which byte differed, and the comparison does not stop at the first
/// one.
pub fn unwrap(cipher: &mut dyn BlockCipher, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    require_128_bit(cipher)?;
    if ciphertext.len() < 24 || !ciphertext.len().is_multiple_of(8) {
        return Err(format!(
            "An RFC 3394 wrapping is at least 24 bytes in a multiple of 8; \
             this is {} bytes.",
            ciphertext.len()));
    }

    let mut a = [0u8; 8];
    a.copy_from_slice(&ciphertext[..8]);
    let mut registers = to_registers(&ciphertext[8..]);
    unwrap_core(cipher, &mut a, &mut registers)?;

    if differs(&a, &IV) {
        return Err("The wrapped key failed its integrity check: it was wrapped \
                    under a different key, or it has been altered.".to_string());
    }

    let mut out = Vec::with_capacity(ciphertext.len() - 8);
    for register in &registers {
        out.extend_from_slice(register);
    }
    Ok(out)
}

/// Wrap key data of any length, RFC 5649.
///
/// Handles 1 byte upwards. The output is the input rounded up to a
/// multiple of eight, plus eight - so a 16 byte key wraps to 24 bytes
/// and a 20 byte one to 32.
///
/// # Errors
/// A cipher whose block is not 128 bits, empty key data, or key data
/// longer than 2^32 - 1 bytes, which is what the length field holds.
pub fn wrap_with_padding(cipher: &mut dyn BlockCipher, plaintext: &[u8])
                         -> Result<Vec<u8>, String> {
    require_128_bit(cipher)?;
    if plaintext.is_empty() {
        return Err("There is no key data to wrap.".to_string());
    }
    if plaintext.len() > u32::MAX as usize {
        return Err(format!(
            "RFC 5649's length field is 32 bits, so it wraps at most {} bytes; \
             this is {}.", u32::MAX, plaintext.len()));
    }

    // The alternative initial value carries the real length, which is
    // what lets the zero padding be stripped again.
    let mut a = [0u8; 8];
    a[..4].copy_from_slice(&AIV);
    a[4..].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());

    let mut registers = to_registers(plaintext);

    // **One block skips the six passes entirely** (RFC 5649 section
    // 4.1): it is a single ECB encryption of the value and the data.
    // The six-pass core needs at least two registers to mix between, so
    // running it here would be a different algorithm that happens to
    // round-trip against itself.
    if registers.len() == 1 {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&a);
        block[8..].copy_from_slice(&registers[0]);
        return Ok(one_block(cipher, &block, true)?.to_vec());
    }

    wrap_core(cipher, &mut a, &mut registers)?;
    let mut out = Vec::with_capacity(registers.len() * 8 + 8);
    out.extend_from_slice(&a);
    for register in &registers {
        out.extend_from_slice(register);
    }
    Ok(out)
}

/// Unwrap key data wrapped with RFC 5649.
///
/// # Errors
/// Anything that is not a valid padded wrapping under this key. The
/// padding and the length field are part of what is checked: a length
/// that does not match the padded size, or a pad byte that is not zero,
/// is a forgery and is refused rather than trimmed.
pub fn unwrap_with_padding(cipher: &mut dyn BlockCipher, ciphertext: &[u8])
                           -> Result<Vec<u8>, String> {
    require_128_bit(cipher)?;
    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(8) {
        return Err(format!(
            "An RFC 5649 wrapping is at least 16 bytes in a multiple of 8; \
             this is {} bytes.", ciphertext.len()));
    }

    let (a, padded) = if ciphertext.len() == 16 {
        let block = one_block(cipher, ciphertext, false)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&block[..8]);
        (a, block[8..].to_vec())
    } else {
        let mut a = [0u8; 8];
        a.copy_from_slice(&ciphertext[..8]);
        let mut registers = to_registers(&ciphertext[8..]);
        unwrap_core(cipher, &mut a, &mut registers)?;
        let mut padded = Vec::with_capacity(registers.len() * 8);
        for register in &registers {
            padded.extend_from_slice(register);
        }
        (a, padded)
    };

    let length = u32::from_be_bytes([a[4], a[5], a[6], a[7]]) as usize;

    // Every part of this is authentication, and all of it is folded into
    // one verdict so a caller cannot learn which part failed from the
    // error it gets.
    let mut bad = differs(&a[..4], &AIV);
    bad |= length > padded.len() || padded.len().saturating_sub(length) >= 8;
    let keep = if bad { padded.len() } else { length };
    for byte in &padded[keep..] {
        bad |= *byte != 0;
    }
    if bad {
        return Err("The wrapped key failed its integrity check: it was wrapped \
                    under a different key, or it has been altered.".to_string());
    }

    Ok(padded[..length].to_vec())
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

    /// RFC 3394 section 4, read out of the vendored document rather than
    /// typed.
    ///
    /// The six sub-sections are one table each: a KEK, some key data and
    /// the expected output. Parsing them here means the vectors are the
    /// RFC's, and `test_the_vector_parser_found_them_all` turns a broken
    /// parser into a failure rather than an empty loop.
    const RFC3394: &str = include_str!("../../rfcs/rfc3394.txt");

    struct Vector {
        section: String,
        kek: Vec<u8>,
        data: Vec<u8>,
        output: Vec<u8>,
    }

    /// The hex on a line, with the grouping spaces the RFCs use
    /// removed, or `None` if it is not hex.
    fn hex_value(text: &str) -> Option<Vec<u8>> {
        let packed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if packed.is_empty() || !packed.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if !packed.len().is_multiple_of(2) {
            return None;
        }
        Some(unhex(&packed))
    }

    /// A line's value if it carries this label.
    ///
    /// **RFC 3394 writes its labels three ways**, and each spelling
    /// appears in half the sections:
    ///
    /// ```text
    /// KEK:            000102030405060708090A0B0C0D0E0F     (4.1)
    /// KEK:000102030405060708090A0B0C0D0E0F1011...          (4.3, no space)
    /// Ciphertext  031D33264E15D332 68F24EC260743EDC        (4.4, no colon)
    /// ```
    ///
    /// Each spelling left unhandled cost three of the six vectors and
    /// reported nothing wrong, which is the same trap `rfc_oids.py`
    /// documents: a document states one thing four ways and a parser
    /// that handles three drops the fourth silently. That is why
    /// `test_the_vector_parser_found_them_all` asserts the count.
    fn labelled<'a>(line: &'a str, label: &str) -> Option<&'a str> {
        let rest = line.strip_prefix(label)?;
        match rest.strip_prefix(':') {
            // With a colon the value may follow immediately.
            Some(after) => Some(after),
            // Without one, a space has to separate them, or "KEK" would
            // match "KEKsomething".
            None if rest.starts_with(' ') => Some(rest),
            None => None,
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Field {
        Kek,
        Data,
        Ciphertext,
    }

    /// RFC 3394 section 4, accumulated rather than read a line at a
    /// time.
    ///
    /// A value may sit on the label's own line, on the next line, or
    /// across several lines, and a page break can land in the middle of
    /// one. So a label opens a buffer, every hex line that follows is
    /// appended to it, and anything else closes it.
    fn parse_vectors() -> Vec<Vector> {
        let mut out: Vec<Vector> = Vec::new();
        let mut section = String::new();
        let mut kek: Option<Vec<u8>> = None;
        let mut data: Option<Vec<u8>> = None;
        let mut output: Option<Vec<u8>> = None;
        let mut current: Option<Field> = None;
        let mut buffer: Vec<u8> = Vec::new();

        macro_rules! commit {
            () => {
                if let Some(field) = current.take() {
                    if !buffer.is_empty() {
                        // **Only the first of each label in a section.**
                        // Every section states its vector twice, once
                        // wrapping and once unwrapping, so "Ciphertext"
                        // and "Key Data" each appear as an input and as
                        // an output.
                        let slot = match field {
                            Field::Kek => &mut kek,
                            Field::Data => &mut data,
                            Field::Ciphertext => &mut output,
                        };
                        if slot.is_none() {
                            *slot = Some(core::mem::take(&mut buffer));
                        }
                    }
                    buffer.clear();
                }
            };
        }

        for raw in RFC3394.lines() {
            let line = raw.replace('\u{c}', "");
            let line = line.trim();

            // A blank line or page furniture does not end a value: a
            // page break can fall inside one.
            if line.is_empty()
                || line.starts_with("RFC 3394")
                || line.starts_with("Schaad & Housley")
            {
                continue;
            }

            if line.starts_with("4.") && line.contains("Wrap ") {
                commit!();
                if let (Some(k), Some(d), Some(o)) = (&kek, &data, &output) {
                    out.push(Vector {
                        section: section.clone(),
                        kek: k.clone(),
                        data: d.clone(),
                        output: o.clone(),
                    });
                }
                section = line.to_string();
                kek = None;
                data = None;
                output = None;
                continue;
            }

            let label = [("Key Data", Field::Data), ("KEK", Field::Kek),
                         ("Ciphertext", Field::Ciphertext)]
                .into_iter()
                .find_map(|(text, field)| labelled(line, text).map(|rest| (field, rest)));

            if let Some((field, value)) = label {
                commit!();
                current = Some(field);
                buffer = hex_value(value).unwrap_or_default();
                continue;
            }

            match hex_value(line) {
                Some(more) if current.is_some() => buffer.extend_from_slice(&more),
                _ => commit!(),
            }
        }
        commit!();
        if let (Some(k), Some(d), Some(o)) = (&kek, &data, &output) {
            out.push(Vector {
                section,
                kek: k.clone(),
                data: d.clone(),
                output: o.clone(),
            });
        }
        out
    }

    #[test]
    fn test_the_vector_parser_found_them_all() {
        let vectors = parse_vectors();
        assert_eq!(vectors.len(), 6,
                   "RFC 3394 section 4 has six vectors; the parser found {}",
                   vectors.len());
        for vector in &vectors {
            assert!([16, 24, 32].contains(&vector.kek.len()),
                    "{}: a {} byte KEK", vector.section, vector.kek.len());
            assert_eq!(vector.output.len(), vector.data.len() + 8,
                       "{}: the output is not eight bytes longer", vector.section);
        }
    }

    #[test]
    fn test_rfc3394_vectors() {
        for vector in parse_vectors() {
            let mut cipher = AesCrypto::new(&vector.kek).unwrap();
            let wrapped = wrap(&mut cipher, &vector.data).unwrap();
            assert_eq!(hex(&wrapped), hex(&vector.output), "{}", vector.section);

            let mut cipher = AesCrypto::new(&vector.kek).unwrap();
            let back = unwrap(&mut cipher, &vector.output).unwrap();
            assert_eq!(hex(&back), hex(&vector.data), "{}", vector.section);
        }
    }

    /// RFC 5649 section 6, both of its examples.
    ///
    /// The second is 20 bytes, which is the one-block case after
    /// padding... no: 20 bytes pads to 24, which is three registers. The
    /// first is 20 bytes and the second is 7, and *that* is the single
    /// block case - the one that skips the six passes entirely.
    #[test]
    fn test_rfc5649_vectors() {
        let cases = parse_5649();
        assert_eq!(cases.len(), 2, "RFC 5649 section 6 has two examples");
        let mut saw_single_block = false;
        for (kek, data, output) in cases {
            let mut cipher = AesCrypto::new(&kek).unwrap();
            let wrapped = wrap_with_padding(&mut cipher, &data).unwrap();
            assert_eq!(hex(&wrapped), hex(&output));

            let mut cipher = AesCrypto::new(&kek).unwrap();
            assert_eq!(hex(&unwrap_with_padding(&mut cipher, &output).unwrap()),
                       hex(&data));
            if output.len() == 16 {
                saw_single_block = true;
            }
        }
        assert!(saw_single_block,
                "neither example exercised the single block path, which is a \
                 different algorithm from the six-pass one");
    }

    /// RFC 5649 section 6 states its examples as prose with hex on the
    /// same line, so they are picked out by the labels rather than by a
    /// table.
    fn parse_5649() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        const RFC5649: &str = include_str!("../../rfcs/rfc5649.txt");
        let mut out = Vec::new();
        let mut kek: Option<Vec<u8>> = None;
        let mut key: Option<Vec<u8>> = None;
        let mut wrap: Option<Vec<u8>> = None;

        fn flush(out: &mut Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
                 kek: &Option<Vec<u8>>, key: &Option<Vec<u8>>,
                 wrap: &Option<Vec<u8>>) {
            if let (Some(a), Some(b), Some(c)) = (kek, key, wrap) {
                out.push((a.clone(), b.clone(), c.clone()));
            }
        }

        for raw in RFC5649.lines() {
            let line = raw.trim();
            let Some((label, value)) = line.split_once(':') else { continue };
            let label = label.trim();
            let Some(bytes) = hex_value(value) else { continue };
            match label {
                // A second KEK means a second example has begun.
                "KEK" => {
                    flush(&mut out, &kek, &key, &wrap);
                    kek = Some(bytes);
                    key = None;
                    wrap = None;
                }
                "Key" => key = Some(bytes),
                "Wrap" => wrap = Some(bytes),
                // **A continuation line has an empty label.** The first
                // example's ciphertext runs onto a second line reading
                // `:  5f54f373fa543b6a`, and a parser that ignores it
                // gets a short wrapping that still parses.
                "" => {
                    if let Some(existing) = wrap.as_mut() {
                        existing.extend_from_slice(&bytes);
                    }
                }
                _ => {}
            }
        }
        flush(&mut out, &kek, &key, &wrap);
        out
    }

    /// Every length RFC 5649 covers round-trips, including the ones RFC
    /// 3394 cannot wrap at all.
    #[test]
    fn test_padded_wrap_round_trips_at_every_length() {
        let kek = [0x42u8; 32];
        for length in 1..=64usize {
            let data: Vec<u8> = (0..length).map(|i| (i * 7 + length) as u8).collect();
            let mut cipher = AesCrypto::new(&kek).unwrap();
            let wrapped = wrap_with_padding(&mut cipher, &data).unwrap();
            assert_eq!(wrapped.len(), length.div_ceil(8) * 8 + 8,
                       "length {}", length);

            let mut cipher = AesCrypto::new(&kek).unwrap();
            assert_eq!(unwrap_with_padding(&mut cipher, &wrapped).unwrap(), data,
                       "length {}", length);
        }
    }

    /// A single changed bit anywhere is refused, at every position.
    ///
    /// This is the property that replaces a separate MAC, so it is
    /// checked rather than assumed.
    #[test]
    fn test_every_altered_bit_is_refused() {
        let kek = [0x11u8; 16];
        let data = [0x22u8; 32];
        let mut cipher = AesCrypto::new(&kek).unwrap();
        let wrapped = wrap(&mut cipher, &data).unwrap();

        for index in 0..wrapped.len() {
            let mut broken = wrapped.clone();
            broken[index] ^= 1 << (index % 8);
            let mut cipher = AesCrypto::new(&kek).unwrap();
            assert!(unwrap(&mut cipher, &broken).is_err(),
                    "byte {} altered and the wrapping still unwrapped", index);
        }

        // And the wrong key.
        let mut cipher = AesCrypto::new(&[0x12u8; 16]).unwrap();
        assert!(unwrap(&mut cipher, &wrapped).is_err());
    }

    #[test]
    fn test_padded_wrap_refuses_an_altered_wrapping() {
        let kek = [0x33u8; 24];
        for length in [1usize, 7, 8, 9, 20, 33] {
            let data: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let mut cipher = AesCrypto::new(&kek).unwrap();
            let wrapped = wrap_with_padding(&mut cipher, &data).unwrap();
            for index in 0..wrapped.len() {
                let mut broken = wrapped.clone();
                broken[index] ^= 0x80;
                let mut cipher = AesCrypto::new(&kek).unwrap();
                assert!(unwrap_with_padding(&mut cipher, &broken).is_err(),
                        "length {}, byte {} altered and it still unwrapped",
                        length, index);
            }
        }
    }

    /// RFC 3394 refuses what it cannot wrap rather than padding.
    #[test]
    fn test_the_unpadded_form_refuses_lengths_it_cannot_represent() {
        let mut cipher = AesCrypto::new(&[0u8; 16]).unwrap();
        for length in [0usize, 1, 7, 8, 9, 15, 17, 20] {
            assert!(wrap(&mut cipher, &vec![0u8; length]).is_err(),
                    "{} bytes was wrapped by the unpadded form", length);
        }
        assert!(wrap(&mut cipher, &[0u8; 16]).is_ok());
        assert!(wrap(&mut cipher, &[0u8; 24]).is_ok());
    }

    /// A 64 bit block cipher is refused, rather than producing something
    /// that looks like a wrapping.
    #[test]
    fn test_a_64_bit_block_cipher_is_refused() {
        let mut des = crate::block_ciphers::des::Des::new(&[0x01u8; 8]).unwrap();
        assert!(wrap(&mut des, &[0u8; 16]).is_err());
        assert!(unwrap(&mut des, &[0u8; 24]).is_err());
        assert!(wrap_with_padding(&mut des, &[0u8; 5]).is_err());
        assert!(unwrap_with_padding(&mut des, &[0u8; 16]).is_err());
    }

    /// Wrapping is deterministic, which is the point: two copies of one
    /// key must look like two copies.
    #[test]
    fn test_wrapping_is_deterministic() {
        let kek = [0x55u8; 32];
        let data = [0x66u8; 40];
        let mut first = AesCrypto::new(&kek).unwrap();
        let mut second = AesCrypto::new(&kek).unwrap();
        assert_eq!(wrap(&mut first, &data).unwrap(), wrap(&mut second, &data).unwrap());
    }

    /// The single-block padded form and the six-pass one are different
    /// algorithms, and the boundary between them is exercised.
    ///
    /// Eight bytes or fewer is one block; nine is two. A wrap that ran
    /// the six passes for one register would round-trip against itself
    /// and disagree with everybody.
    #[test]
    fn test_the_single_block_boundary() {
        let kek = [0x77u8; 16];
        for length in [1usize, 7, 8, 9] {
            let data = vec![0xabu8; length];
            let mut cipher = AesCrypto::new(&kek).unwrap();
            let wrapped = wrap_with_padding(&mut cipher, &data).unwrap();
            assert_eq!(wrapped.len(), if length <= 8 { 16 } else { 24 },
                       "length {}", length);
            let mut cipher = AesCrypto::new(&kek).unwrap();
            assert_eq!(unwrap_with_padding(&mut cipher, &wrapped).unwrap(), data);
        }
    }

    /// A padded wrapping whose length field claims more than the padding
    /// holds is refused.
    ///
    /// Unreachable by altering a wrapping at random - the integrity
    /// check catches those first - so it is built by wrapping a forged
    /// value directly.
    #[test]
    fn test_a_length_field_that_does_not_match_the_padding_is_refused() {
        let kek = [0x99u8; 16];
        let mut cipher = AesCrypto::new(&kek).unwrap();

        // Two registers of data, but a length field claiming one byte:
        // the padded length would then be 15 bytes too long.
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(&AIV);
        a[4..].copy_from_slice(&1u32.to_be_bytes());
        let mut registers = vec![[0xccu8; 8], [0xccu8; 8]];
        wrap_core(&mut cipher, &mut a, &mut registers).unwrap();
        let mut forged = a.to_vec();
        for register in &registers {
            forged.extend_from_slice(register);
        }

        let mut cipher = AesCrypto::new(&kek).unwrap();
        assert!(unwrap_with_padding(&mut cipher, &forged).is_err(),
                "a length field 15 bytes short of the padding was accepted");

        // And one where the length is right but a pad byte is not zero.
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(&AIV);
        a[4..].copy_from_slice(&9u32.to_be_bytes());
        let mut registers = vec![[0xccu8; 8], [0xcc, 1, 0, 0, 0, 0, 0, 0]];
        let mut cipher = AesCrypto::new(&kek).unwrap();
        wrap_core(&mut cipher, &mut a, &mut registers).unwrap();
        let mut forged = a.to_vec();
        for register in &registers {
            forged.extend_from_slice(register);
        }
        let mut cipher = AesCrypto::new(&kek).unwrap();
        assert!(unwrap_with_padding(&mut cipher, &forged).is_err(),
                "a non-zero pad byte was accepted");

        // A length field far short of the padding, with the padding
        // genuinely zero. **Only the range check sees this one** - the
        // pad bytes are what they should be, and the initial value is
        // correct - so without it the unwrap returns one byte where the
        // wrapping holds sixteen.
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(&AIV);
        a[4..].copy_from_slice(&1u32.to_be_bytes());
        let mut registers = vec![[0u8; 8], [0u8; 8]];
        let mut cipher = AesCrypto::new(&kek).unwrap();
        wrap_core(&mut cipher, &mut a, &mut registers).unwrap();
        let mut forged = a.to_vec();
        for register in &registers {
            forged.extend_from_slice(register);
        }
        let mut cipher = AesCrypto::new(&kek).unwrap();
        assert!(unwrap_with_padding(&mut cipher, &forged).is_err(),
                "a length field 15 bytes short of a validly padded wrapping \
                 was accepted");

        // A correct length and correct padding under the *wrong*
        // initial value. **Only the AIV check sees this one.** Without
        // it, RFC 3394's own wrappings would also unwrap here, since
        // they differ from RFC 5649's in nothing else.
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        a[4..].copy_from_slice(&16u32.to_be_bytes());
        let mut registers = vec![[0xddu8; 8], [0xddu8; 8]];
        let mut cipher = AesCrypto::new(&kek).unwrap();
        wrap_core(&mut cipher, &mut a, &mut registers).unwrap();
        let mut forged = a.to_vec();
        for register in &registers {
            forged.extend_from_slice(register);
        }
        let mut cipher = AesCrypto::new(&kek).unwrap();
        assert!(unwrap_with_padding(&mut cipher, &forged).is_err(),
                "a wrapping with the wrong initial value was accepted");

        // And the two forms do not unwrap each other's output, which is
        // the same property seen from the outside.
        let mut cipher = AesCrypto::new(&kek).unwrap();
        let plain = wrap(&mut cipher, &[0x5au8; 16]).unwrap();
        let mut cipher = AesCrypto::new(&kek).unwrap();
        assert!(unwrap_with_padding(&mut cipher, &plain).is_err(),
                "an RFC 3394 wrapping unwrapped as an RFC 5649 one");
        let mut cipher = AesCrypto::new(&kek).unwrap();
        let padded = wrap_with_padding(&mut cipher, &[0x5au8; 16]).unwrap();
        let mut cipher = AesCrypto::new(&kek).unwrap();
        assert!(unwrap(&mut cipher, &padded).is_err(),
                "an RFC 5649 wrapping unwrapped as an RFC 3394 one");
    }

    /// **The integrity comparison looks at every byte.**
    ///
    /// A `==` that stops at the first difference is an oracle for the
    /// wrapped key's leading bytes, and no functional test can tell the
    /// two apart: after six inverse passes a wrong value differs in its
    /// first byte 255 times out of 256, so a first-byte comparison
    /// passes a bit-flipping sweep about four times in five. That is
    /// exactly the shape of test that looks like coverage and is not -
    /// so the property is asserted on the function itself.
    #[test]
    fn test_the_comparison_looks_at_every_byte() {
        let reference = [0xa6u8; 8];
        for index in 0..reference.len() {
            let mut altered = reference;
            altered[index] ^= 0x01;
            assert!(differs(&altered, &reference),
                    "a difference in byte {} was not seen", index);
        }
        assert!(!differs(&reference, &reference));
        assert!(differs(&reference, &reference[..7]), "a length difference was not seen");
    }

    /// The block size requirement is refused **by name**, not by a
    /// downstream length check.
    ///
    /// Removing `require_128_bit` leaves every test passing, because a
    /// 64 bit cipher then fails in `one_block` instead. That is defence
    /// in depth rather than a hole - but it means the sweep cannot see
    /// the check, so the error it produces is pinned here.
    #[test]
    fn test_the_block_size_error_says_what_is_wrong() {
        let mut des = crate::block_ciphers::des::Des::new(&[0x01u8; 8]).unwrap();
        let error = wrap(&mut des, &[0u8; 16]).unwrap_err();
        assert!(error.contains("128 bit block"), "{}", error);
        assert!(error.contains("8 bytes"), "{}", error);
    }

    /// The counter runs across the passes rather than restarting.
    ///
    /// `t = n*j + i` takes 6n distinct values; a counter reset each pass
    /// takes n. Both wrap and unwrap consistently, so only the RFC's
    /// vectors distinguish them. The earlier form of this test recomputed
    /// the sequence locally and never called `wrap_core`, so a change to
    /// `t` there could not fail it. Under a cipher that is the identity,
    /// the core reduces to `A ^= t` at every step, so the `A` it leaves
    /// behind is the XOR of every `t` it used - and that is compared
    /// with the sequence the document specifies, and shown to differ
    /// from a counter that restarts each pass.
    #[test]
    fn test_the_counter_does_not_repeat_across_the_passes() {
        struct Identity;
        impl BlockCipher for Identity {
            fn blocksize(&self) -> usize { 16 }
            fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
                result.extend_from_slice(&input[..16]);
            }
            fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
                result.extend_from_slice(&input[..16]);
            }
        }
        let n = 4u64;
        let mut a = [0xa6u8; 8];
        let mut registers = [[0u8; 8]; 4];
        wrap_core(&mut Identity, &mut a, &mut registers).unwrap();

        let mut seen = Vec::new();
        for pass in 0..6u64 {
            for index in 0..n {
                seen.push(n * pass + index + 1);
            }
        }
        let fold = |values: &[u64]| {
            let mut value = u64::from_be_bytes([0xa6; 8]);
            for t in values {
                value ^= t;
            }
            value.to_be_bytes()
        };
        assert_eq!(a, fold(&seen), "wrap_core did not use t = n*j + i");
        let restarting: Vec<u64> = (0..6).flat_map(|_| 1..=n).collect();
        assert_ne!(fold(&restarting), fold(&seen),
                   "the two counters are not told apart by this input");

        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), seen.len(), "a value of t repeated");
        assert_eq!(*seen.first().unwrap(), 1, "t counts from zero");
        assert_eq!(*seen.last().unwrap(), 6 * n);
    }
}
