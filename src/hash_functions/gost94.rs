/*
GOST R 34.11-94, the hash Streebog replaced.

It is here for one reason: **TLS_GOSTR341001_WITH_28147_CNT_IMIT**, the
0x0081 suite. That suite predates Streebog by a decade, and a box that
speaks it uses this hash for the handshake transcript, for the PRF, for
the certificate's signature and inside the key exchange. Nothing about
it is recommended - collisions were published in 2008 and the standard
was withdrawn in 2013 - and a box installed in 2009 speaks nothing
else.

The construction is a 256 bit Merkle-Damgard with GOST 28147-89 as its
compression function, and three things after the message that no other
hash here does: the padded final block, then the **bit length**, then
the **sum of every block as a 256 bit integer**, each fed through the
same compression. Streebog kept the last two ideas.

## Where an implementation goes wrong

  * **Everything is little endian, including the 256 bit words.** The
    standard reads its words right to left and numbers their bits from
    the right, so what it prints as `73657479 ...` is the byte string
    `...79 74 65 73` - the reverse. Every array here is in *byte stream
    order*: index 0 is the first byte of the message and the least
    significant byte of the 256 bit number. The document's own worked
    example is the message "This is message, length=32 bytes", and
    printed as a number it looks like the message backwards.

  * **The final partial block is padded at the high end**, which in
    stream order means zeros *after* the message bytes. The document
    writes `M' := 0^(256-|M|)||M`, zeros on the left, and the left is
    the high end.

  * **A message that exactly fills a block gets no extra block.** This
    is the opposite of SHA-2 and of Streebog, where a full final block
    is always followed by a padded one, and it is why this file does
    not use `BlockBuffer` like every other hash here: that type
    compresses a block the moment it is full, which is right for
    everything else and wrong for this. The standard's step 2 takes the
    *remaining* part when it is 256 bits **or fewer**, so a 32 byte
    message is one block and not two. Compressing eagerly adds a block
    of zeros to the hash, to the checksum and to nothing else, and the
    digest of every message whose length is a multiple of 32 bytes
    comes out wrong - which is exactly what the first draft of this
    file did, with RFC 5831's own 32 byte example as the thing that
    caught it.

  * **An empty message still gets three compressions**, not none. Zero
    is also "256 bits or fewer", so `M'` is a block of zeros and the
    length and checksum steps follow it as usual.

  * **The S-box is a parameter, and the two in use give different
    hashes.** `id-GostR3411-94-TestParamSet` is what the standard's
    examples use; `id-GostR3411-94-CryptoProParamSet` is what every
    certificate and every TLS connection uses. Getting this wrong
    produces a hash that is a perfectly good hash and agrees with
    nobody. The default here is CryptoPro, because that is what the
    wire carries; the tests use both and say which.

  * **The empty message has two answers in the wild.** This file, the
    second reading in `scripts/diff_check.py` and today's gost-engine
    compress a zero block for it, since the standard's step 2 runs for
    any remainder of 256 bits or fewer and zero is one. Bouncy Castle,
    gost89 and the gost engine that shipped with OpenSSL 1.0 compress
    nothing when nothing is left, and their `981e5f3c...` (CryptoPro)
    is the value usually published. Every non-empty message gets the
    same digest from all of them. GOST 34.311-95 here follows the same
    rule as the other two parameter sets, and `docs/pitfalls.md` says
    so.

  * **`A` and `psi` shift in opposite directions.** `A` moves the low
    64 bit word out and a fresh one in at the top; `psi` moves the low
    16 bit word out and a fresh one in at the top. They look alike and
    they are not interchangeable, and getting one backwards still
    produces a hash.

## What it is checked against

RFC 5831 appendix 7.3 prints both of its examples *with every
intermediate*: the four keys of every compression, the four cipher
outputs, and the running hash. So the key schedule, the encryption
stage and the mixing stage are each pinned separately rather than only
their composition - which matters, because two compensating errors in
the key schedule and the mixer would round trip.

Nothing on this machine implements it, so `scripts/diff_check.py`
carries a second reading of RFC 5831 as the differential reference.
*/

use super::HashFunction;
use crate::block_ciphers::gost::GostCrypto;

/// The standard, for the constant and the vectors.
const RFC_5831: &str = include_str!("../../rfcs/rfc5831.txt");

/// The compression function's block, in bytes.
const BLOCK: usize = 32;

/// The parameter set every GOST TLS connection and certificate uses.
pub const CRYPTOPRO_PARAM_SET: &str = "id-GostR3411-94-CryptoProParamSet";
/// The one the standard's own examples use, and nothing else.
pub const TEST_PARAM_SET: &str = "id-GostR3411-94-TestParamSet";
/// Ukraine's: GOST 34.311-95 is this hash under the DSTU 4145 default
/// DKE, and is what Ukrainian signatures and key containers hash with.
pub const DSTU_PARAM_SET: &str = crate::block_ciphers::gost::DSTU_PARAM_SET;

#[derive(Clone)]
pub struct Gost94 {
    /// The running hash, in byte stream order.
    h: [u8; BLOCK],
    /// The sum of every block so far, modulo 2^256.
    sigma: [u8; BLOCK],
    /// The message length in *bits*, modulo 2^256.
    length: [u8; BLOCK],
    /// Bytes taken in and not yet compressed: the first `pending_len`
    /// of this array.
    ///
    /// **Between one and thirty-two of them**, once anything has been
    /// fed: a full block is held back rather than compressed, because
    /// whether it is the last one decides whether it is padded. See
    /// the note at the top of the file. A fixed array rather than a
    /// `Vec`, so that `update` holds at most one block however much it
    /// is given: the earlier `Vec` took a copy of the whole input
    /// before compressing any of it, which for a large buffer was a
    /// second copy of the message.
    pending: [u8; BLOCK],
    pending_len: usize,
    /// The block cipher under the parameter set's S-box, built once:
    /// each compression re-keys it four times with `set_key`, which
    /// leaves the substitution tables alone.
    cipher: GostCrypto,
    name: &'static str,
}

impl Default for Gost94 {
    fn default() -> Self {
        Gost94::new(&[])
    }
}

impl Gost94 {
    /// With the CryptoPro parameter set, which is what certificates and
    /// TLS carry.
    pub fn new(data: &[u8]) -> Gost94 {
        Gost94::with_param_set(data, CRYPTOPRO_PARAM_SET)
            .expect("the CryptoPro parameter set is built in")
    }

    /// With a named parameter set.
    ///
    /// An unknown name is an error rather than a default. The two sets
    /// give different hashes of the same message, so quietly
    /// substituting one for the other would produce a digest that is
    /// wrong in a way nothing downstream can see.
    pub fn with_param_set(data: &[u8], name: &str) -> Result<Gost94, String> {
        let (sbox, canonical) = match name {
            CRYPTOPRO_PARAM_SET => (GostCrypto::sbox_named(CRYPTOPRO_PARAM_SET)?,
                                    CRYPTOPRO_PARAM_SET),
            TEST_PARAM_SET => (GostCrypto::sbox_named(TEST_PARAM_SET)?,
                               TEST_PARAM_SET),
            DSTU_PARAM_SET => (GostCrypto::sbox_named(DSTU_PARAM_SET)?,
                               DSTU_PARAM_SET),
            other => return Err(format!(
                "GOST R 34.11-94 has three parameter sets here, {:?}, {:?} \
                 and {:?} (GOST 34.311-95); {:?} is none of them.",
                CRYPTOPRO_PARAM_SET, TEST_PARAM_SET, DSTU_PARAM_SET, other)),
        };
        let mut hash = Gost94 {
            h: [0; BLOCK],
            sigma: [0; BLOCK],
            length: [0; BLOCK],
            pending: [0; BLOCK],
            pending_len: 0,
            cipher: GostCrypto::new_with_sbox(&[0; 32], &sbox)?,
            name: canonical,
        };
        hash.update(data);
        Ok(hash)
    }

    /// One 256 bit block into the state: the hash step, the length and
    /// the checksum.
    fn absorb(h: &mut [u8; BLOCK], sigma: &mut [u8; BLOCK],
              length: &mut [u8; BLOCK], cipher: &mut GostCrypto, block: &[u8],
              bits: u64) {
        let mut m = [0u8; BLOCK];
        m.copy_from_slice(block);
        *h = chi(&m, h, cipher);
        add_into(length, &bits_as_word(bits));
        add_into(sigma, &m);
    }

    /// The final three steps over copies of the three state words, so
    /// the hash itself is untouched and can go on being fed.
    ///
    /// The cipher is borrowed rather than copied: it carries the
    /// parameter set's 4 KiB table, and nothing about it survives a
    /// step - every `chi` sets all four keys before using them - so
    /// finishing through it leaves it as good as new for the next
    /// `update`. Cloning the whole hash for each `digest`, as before,
    /// copied that table every time, and HMAC-GOST digests twice per
    /// MAC.
    fn finish(&mut self) -> Vec<u8> {
        let (mut h, mut sigma, mut length) = (self.h, self.sigma, self.length);
        // The tail, zero padded at the high end - which is after the
        // message bytes, since index 0 is the first byte.
        let mut last = [0u8; BLOCK];
        last[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        // **Even when there is nothing left.** An empty final block is
        // still a block: the standard's step 2 runs for any remaining
        // length of 256 bits or fewer, and a message that ended on a
        // block boundary has zero left over. Skipping it here would
        // make every message whose length is a multiple of 32 bytes -
        // including the empty one - hash to something else.
        Gost94::absorb(&mut h, &mut sigma, &mut length, &mut self.cipher, &last,
                       self.pending_len as u64 * 8);

        // Then the length, then the checksum, through the same step.
        h = chi(&length, &h, &mut self.cipher);
        h = chi(&sigma, &h, &mut self.cipher);
        h.to_vec()
    }
}

impl HashFunction for Gost94 {
    fn name(&self) -> String {
        if self.name == TEST_PARAM_SET {
            "gost94_test".to_string()
        } else if self.name == DSTU_PARAM_SET {
            "gost34311".to_string()
        } else {
            // CRYPTOPRO_PARAM_SET, the only other one `with_param_set`
            // accepts.
            "gost94".to_string()
        }
    }

    fn digest_len(&self) -> usize {
        32
    }

    /// The compression function takes 256 bits, and that is what HMAC
    /// wants - RFC 4357 section 3 builds HMAC_GOSTR3411 on a 32 byte
    /// block for exactly this reason.
    fn block_size(&self) -> usize {
        BLOCK
    }

    fn update(&mut self, mut input: &[u8]) {
        // **A block is compressed only once something has arrived
        // after it**, because the last block of the message is the
        // padded one and a block that fills the buffer exactly may
        // still be the last. So: everything fits beside what is held
        // when the total is a block or less, and nothing is compressed.
        if self.pending_len + input.len() <= BLOCK {
            self.pending[self.pending_len..self.pending_len + input.len()]
                .copy_from_slice(input);
            self.pending_len += input.len();
            return;
        }
        let Gost94 { h, sigma, length, cipher, pending, pending_len, .. } = self;
        // More than a block in all, so the held block is not the last:
        // top it up from the input and compress it.
        let take = BLOCK - *pending_len;
        pending[*pending_len..].copy_from_slice(&input[..take]);
        input = &input[take..];
        Gost94::absorb(h, sigma, length, cipher, pending, BLOCK as u64 * 8);
        // Whole blocks straight out of the input while at least one
        // byte follows them - strictly greater, for the reason above.
        while input.len() > BLOCK {
            Gost94::absorb(h, sigma, length, cipher, &input[..BLOCK], BLOCK as u64 * 8);
            input = &input[BLOCK..];
        }
        // One to thirty-two bytes remain, and they are held.
        pending[..input.len()].copy_from_slice(input);
        *pending_len = input.len();
    }

    /// Of everything so far, on copies of the state words: `finish`
    /// pads and absorbs, so finishing in place would leave the hash
    /// unable to give the same digest twice or to go on after one.
    fn digest(&mut self) -> Vec<u8> {
        self.finish()
    }
}

// ------------------------------------------------------- the step function ---

/// `chi(M, H)`, RFC 5831 section 5: generate four keys, encrypt the
/// four 64 bit parts of H under them, and mix.
fn chi(m: &[u8; BLOCK], h: &[u8; BLOCK], cipher: &mut GostCrypto) -> [u8; BLOCK] {
    let keys = keys_for(m, h);

    let mut s = [0u8; BLOCK];
    for (i, key) in keys.iter().enumerate() {
        cipher.set_key(key);
        s[i * 8..(i + 1) * 8]
            .copy_from_slice(&cipher.encrypt_block(h[i * 8..(i + 1) * 8].try_into().unwrap()));
    }

    // chi(M, H) = psi^61( H xor psi( M xor psi^12(S) ) )
    let mut inner = psi_times(&s, 12);
    xor_into(&mut inner, m);
    let mut outer = psi_times(&inner, 1);
    xor_into(&mut outer, h);
    psi_times(&outer, 61)
}

/// The four keys of one step, RFC 5831 section 5.1.
fn keys_for(m: &[u8; BLOCK], h: &[u8; BLOCK]) -> [[u8; BLOCK]; 4] {
    static C3: std::sync::OnceLock<[u8; BLOCK]> = std::sync::OnceLock::new();
    // Read out of the RFC once, not once per block.
    let c3 = *C3.get_or_init(c3);
    let mut keys = [[0u8; BLOCK]; 4];
    let mut u = *h;
    let mut v = *m;

    let mut w = u;
    xor_into(&mut w, &v);
    keys[0] = p(&w);

    for (index, key) in keys.iter_mut().enumerate().skip(1) {
        // C[2] and C[4] are zero; only C[3] is not, and `index` is one
        // less than the document's `i`.
        u = a(&u);
        if index == 2 {
            xor_into(&mut u, &c3);
        }
        v = a(&a(&v));
        let mut w = u;
        xor_into(&mut w, &v);
        *key = p(&w);
    }
    keys
}

/// `A(X) = (x1 xor x2) || x4 || x3 || x2`, over four 64 bit parts.
///
/// In stream order the parts run low to high, so this moves everything
/// down by eight bytes and puts `x1 xor x2` on top.
fn a(x: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out[..24].copy_from_slice(&x[8..]);
    for i in 0..8 {
        out[24 + i] = x[i] ^ x[8 + i];
    }
    out
}

/// `P`, the byte transposition of RFC 5831 section 5.1.
///
/// `phi(i + 1 + 4(k - 1)) = 8i + k` for `i = 0..3`, `k = 1..8`, with
/// both sides one-based. Written with the document's own indices and
/// the conversion made once, because doing the arithmetic in the head
/// is how the two ends of a transposition get swapped.
fn p(w: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    for i in 0..4usize {
        for k in 1..=8usize {
            out[i + 4 * (k - 1)] = w[8 * i + (k - 1)];
        }
    }
    out
}

/// `psi`, applied `times` times.
///
/// One application moves each 16 bit word down one place and puts
/// `eta1 xor eta2 xor eta3 xor eta4 xor eta13 xor eta16` in the top.
/// The document's words are one-based from the low end, so those are
/// indices 0, 1, 2, 3, 12 and 15 here.
fn psi_times(x: &[u8; BLOCK], times: usize) -> [u8; BLOCK] {
    let mut words = [0u16; 16];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u16::from_le_bytes([x[index * 2], x[index * 2 + 1]]);
    }
    for _ in 0..times {
        let fresh = words[0] ^ words[1] ^ words[2] ^ words[3]
                  ^ words[12] ^ words[15];
        words.copy_within(1.., 0);
        words[15] = fresh;
    }
    let mut out = [0u8; BLOCK];
    for (index, word) in words.iter().enumerate() {
        out[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// ------------------------------------------------------------- arithmetic ---

fn xor_into(target: &mut [u8; BLOCK], other: &[u8; BLOCK]) {
    for (byte, value) in target.iter_mut().zip(other.iter()) {
        *byte ^= value;
    }
}

/// `A (+)' B`, addition modulo 2^256 with the low byte first.
fn add_into(target: &mut [u8; BLOCK], other: &[u8; BLOCK]) {
    let mut carry = 0u16;
    for (byte, value) in target.iter_mut().zip(other.iter()) {
        let sum = *byte as u16 + *value as u16 + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
}

fn bits_as_word(bits: u64) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out[..8].copy_from_slice(&bits.to_le_bytes());
    out
}

// --------------------------------------------------------------- C[3] ---

/// The one non-zero key generation constant, **read out of RFC 5831
/// rather than typed**.
///
/// The document writes it as an expression rather than as hex:
///
/// ```text
/// C[3] = 1^8||0^8||1^16||0^24||1^16||0^8||(0^8||1^8)^2||1^8||0^8
///        ||(0^8||1^8)^4||(1^8||0^8 )^4.
/// ```
///
/// That is 32 bytes written as eleven pieces, and a transcription of
/// it into hex is 64 digits with nothing to check them against. So the
/// expression itself is parsed: `bit^count` for a run, `(...)^k` for a
/// repeat, `||` between. The result is asserted to be 256 bits, and
/// the whole thing is pinned by the document's own key schedules -
/// `K[2]` of the first example differs from `K[1]` only where C[3]
/// does not, so a wrong constant shows up immediately.
///
/// Note the stray space in `(1^8||0^8 )^4`. The parser skips
/// whitespace everywhere for that one character.
fn c3() -> [u8; BLOCK] {
    let expression = c3_expression();
    let bits = expand_bits(&expression);
    assert_eq!(bits.len(), 256,
               "RFC 5831's C[3] expands to {} bits, not 256", bits.len());

    // The expression is written most significant first, and every array
    // here is least significant first.
    let mut out = [0u8; BLOCK];
    for (index, chunk) in bits.chunks(8).enumerate() {
        let mut byte = 0u8;
        for bit in chunk {
            byte = (byte << 1) | u8::from(*bit);
        }
        out[BLOCK - 1 - index] = byte;
    }
    out
}

/// The text of the assignment, from `C[3] =` to the full stop.
fn c3_expression() -> String {
    let start = RFC_5831.find("C[3] = ")
        .expect("RFC 5831 assigns C[3]") + "C[3] = ".len();
    let rest = &RFC_5831[start..];
    let end = rest.find('.').expect("the assignment ends in a full stop");
    rest[..end].split_whitespace().collect::<Vec<_>>().join("")
}

/// `1^8`, `0^24`, `(0^8||1^8)^4`, joined by `||`.
fn expand_bits(text: &str) -> Vec<bool> {
    let bytes: Vec<char> = text.chars().collect();
    let mut at = 0;
    let mut bits = Vec::new();
    while at < bytes.len() {
        match bytes[at] {
            '|' => at += 1,
            '(' => {
                let close = matching_paren(&bytes, at);
                let inner: String = bytes[at + 1..close].iter().collect();
                let (count, next) = read_power(&bytes, close + 1);
                let once = expand_bits(&inner);
                for _ in 0..count {
                    bits.extend_from_slice(&once);
                }
                at = next;
            }
            symbol @ ('0' | '1') => {
                let (count, next) = read_power(&bytes, at + 1);
                bits.extend(std::iter::repeat_n(symbol == '1', count));
                at = next;
            }
            other => panic!("unexpected {:?} in RFC 5831's C[3]", other),
        }
    }
    bits
}

fn matching_paren(text: &[char], open: usize) -> usize {
    let mut depth = 0;
    for (offset, character) in text.iter().enumerate().skip(open) {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return offset;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced parentheses in RFC 5831's C[3]");
}

/// `^n` at `at`, returning the exponent and where it ended.
fn read_power(text: &[char], at: usize) -> (usize, usize) {
    assert_eq!(text.get(at), Some(&'^'), "a run needs a length");
    let mut end = at + 1;
    while end < text.len() && text[end].is_ascii_digit() {
        end += 1;
    }
    let digits: String = text[at + 1..end].iter().collect();
    (digits.parse().expect("a decimal length"), end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::BlockCipher;

    /// `NAME = XXXXXXXX XXXXXXXX ...`, as RFC 5831 appendix 7.3 prints
    /// every value, with continuation lines indented under it.
    ///
    /// Returned in order and by name, because the names repeat: each
    /// compression prints its own `K[1]`, and which `K[1]` is meant is
    /// decided by position.
    fn assignments(section: &str, until: &str) -> Vec<(String, Vec<u8>)> {
        // **The last occurrence, not the first.** Every heading in
        // this document appears twice, once in the table of contents
        // and once over the section itself, and the table of contents
        // version is followed by the next heading rather than by any
        // values - so a parser that took the first match found an
        // empty section and every vector silently disappeared.
        let start = RFC_5831.rfind(section)
            .unwrap_or_else(|| panic!("{} is in the document", section));
        let body = &RFC_5831[start..];
        let body = match body.find(until) {
            Some(end) => &body[..end],
            None => body,
        };

        let mut found: Vec<(String, Vec<u8>)> = Vec::new();
        let mut current: Option<(String, String)> = None;
        for line in body.lines() {
            // The running header and footer sit in the middle of
            // continued values.
            if line.contains("Dolmatov") || line.contains("RFC 5831") {
                continue;
            }
            let trimmed = line.trim();
            if let Some((name, rest)) = trimmed.rsplit_once('=') {
                // **The last `=`, and a known name from the left of
                // it.** The document writes one line as `KSI = chi(M,
                // H) = CF9A8C65 ...` and another as `So S = ...`, so
                // neither "split at the first equals" nor "the last
                // word before it" finds both. Two values went missing
                // that way, and each test that wanted one silently
                // compared against the next occurrence instead -
                // which is a test that passes while checking the
                // wrong thing.
                const NAMES: &[&str] = &["M", "_M_", "M_s", "H", "SIGMA", "L",
                                         "K[1]", "K[2]", "K[3]", "K[4]",
                                         "S", "KSI"];
                let name = name.split_whitespace()
                    .find(|word| NAMES.contains(word))
                    .unwrap_or("");
                let rest = rest.trim();
                if !name.is_empty() && is_hex_words(rest) {
                    if let Some((name, digits)) = current.take() {
                        found.push((name, unhex(&digits)));
                    }
                    current = Some((name.to_string(), squash(rest)));
                    continue;
                }
            }
            if current.is_some() && is_hex_words(trimmed) && !trimmed.is_empty() {
                if let Some((_, digits)) = current.as_mut() {
                    digits.push_str(&squash(trimmed));
                }
                continue;
            }
            if let Some((name, digits)) = current.take() {
                found.push((name, unhex(&digits)));
            }
        }
        if let Some((name, digits)) = current {
            found.push((name, unhex(&digits)));
        }
        found
    }

    fn is_hex_words(text: &str) -> bool {
        !text.is_empty() && text.split_whitespace().all(
            |word| !word.is_empty() && word.len() <= 8
                && word.chars().all(|c| c.is_ascii_hexdigit()
                                     && !c.is_ascii_lowercase()))
    }

    fn squash(text: &str) -> String {
        text.split_whitespace().collect()
    }

    fn unhex(digits: &str) -> Vec<u8> {
        assert!(digits.len().is_multiple_of(2), "{:?} is not whole bytes", digits);
        (0..digits.len() / 2)
            .map(|i| u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16)
                 .expect("hex"))
            .collect()
    }

    /// The document prints every 256 bit value as a number, most
    /// significant byte first; this library works on byte strings.
    /// **The two are reverses of each other**, which is the trap
    /// described at the top of this file and the reason every vector
    /// below goes through here.
    fn as_stream(number: &[u8]) -> [u8; BLOCK] {
        assert_eq!(number.len(), BLOCK);
        let mut out = [0u8; BLOCK];
        for (index, byte) in number.iter().rev().enumerate() {
            out[index] = *byte;
        }
        out
    }

    fn named(values: &[(String, Vec<u8>)], name: &str, occurrence: usize)
             -> [u8; BLOCK] {
        let matches: Vec<&(String, Vec<u8>)> = values.iter()
            .filter(|(found, _)| found == name).collect();
        assert!(matches.len() > occurrence,
                "the document prints {} {} times, not {}",
                name, matches.len(), occurrence + 1);
        as_stream(&matches[occurrence].1)
    }

    /// The S-box of RFC 5831 section 7.1, which the examples use.
    ///
    /// **Printed transposed, and with the columns backwards.** The
    /// header row reads `8 7 6 5 4 3 2 1`, so the leftmost column is
    /// `pi[8]` and the rightmost is `pi[1]`, while the rows are the
    /// input values 0 to 15. A parser that took the columns left to
    /// right would produce the eight substitutions in reverse order -
    /// a working S-box, a different cipher, and a hash that agrees
    /// with nobody.
    fn test_sbox_from_the_document() -> Vec<Vec<u8>> {
        let start = RFC_5831.find("7.1.  Usage of the Algorithm")
            .expect("section 7.1");
        let body = &RFC_5831[start..];
        let end = body.find("7.2.").expect("section 7.2");
        let body = &body[..end];

        let mut rows: Vec<Vec<u8>> = Vec::new();
        for line in body.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            // A row of the table is an index and eight hex digits.
            if words.len() != 9 {
                continue;
            }
            if words[0].parse::<usize>() != Ok(rows.len()) {
                continue;
            }
            let row: Option<Vec<u8>> = words[1..].iter()
                .map(|word| if word.len() == 1 {
                    u8::from_str_radix(word, 16).ok()
                } else {
                    None
                })
                .collect();
            match row {
                Some(row) => rows.push(row),
                None => continue,
            }
        }
        assert_eq!(rows.len(), 16,
                   "section 7.1's table has sixteen rows, one per input value");

        // Columns to substitutions, right to left: the last column is
        // pi[1].
        (0..8).map(|which| {
            (0..16).map(|value| rows[value][7 - which]).collect()
        }).collect()
    }

    /// RFC 4357 section 11.2, where both parameter sets are printed as
    /// a packed 64 byte OCTET STRING rather than as a table.
    ///
    /// **This is the one that matters.** Section 7.1 of RFC 5831 gives
    /// the *test* S-box, which nothing outside that appendix uses;
    /// every GOST certificate and every GOST TLS connection uses
    /// `id-GostR3411-94-CryptoProParamSet`, and until this test there
    /// was nothing behind those 128 numbers but somebody having typed
    /// them correctly. A single wrong nibble gives a hash that is a
    /// perfectly good hash and agrees with no peer on earth.
    ///
    /// The packing is two substitutions to a byte, high nibble first,
    /// stepping across the eight substitutions for each input value in
    /// turn: byte `4i + j` is `pi[2j](i) << 4 | pi[2j+1](i)`. The
    /// document's own annotated copy of the test set - it prints the
    /// columns beside the bytes - is what settles which nibble is
    /// which.
    fn packed_sbox_from_rfc_4357(marker: &str) -> Vec<u8> {
        const RFC_4357: &str = include_str!("../../rfcs/rfc4357.txt");
        let lines: Vec<&str> = RFC_4357.lines().collect();
        let start = lines.iter().rposition(|line| {
            let trimmed = line.trim();
            trimmed.starts_with(':') && trimmed.ends_with(marker)
        }).unwrap_or_else(|| panic!("{} is not in RFC 4357's dump", marker));

        let mut bytes = Vec::new();
        for line in &lines[start + 1..] {
            if line.contains("Popov,") || line.contains("RFC 4357") {
                continue;
            }
            let trimmed = line.trim();
            // The annotated copy of the test set has its table in
            // comment lines above the bytes.
            if trimmed.starts_with("--") || trimmed.is_empty() {
                continue;
            }
            let rest = match trimmed.strip_prefix(':') {
                Some(rest) => rest.trim(),
                None => continue,
            };
            let words: Vec<&str> = rest.split_whitespace().collect();
            if words.is_empty() || !words.iter().all(
                |word| word.len() == 2 && word.chars().all(
                    |c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())) {
                continue;
            }
            for word in words {
                bytes.push(u8::from_str_radix(word, 16).expect("hex"));
            }
            if bytes.len() >= 64 {
                break;
            }
        }
        assert_eq!(bytes.len(), 64,
                   "{}: the parameters are a 64 byte OCTET STRING", marker);
        bytes
    }

    fn pack(sbox: &[Vec<u8>]) -> Vec<u8> {
        let mut packed = vec![0u8; 64];
        for value in 0..16usize {
            for pair in 0..4usize {
                packed[4 * value + pair] =
                    (sbox[2 * pair][value] << 4) | sbox[2 * pair + 1][value];
            }
        }
        packed
    }

    #[test]
    fn test_the_cryptopro_sbox_is_rfc_4357s() {
        for name in [CRYPTOPRO_PARAM_SET, TEST_PARAM_SET] {
            let carried = GostCrypto::sbox_named(name).unwrap();
            assert_eq!(pack(&carried), packed_sbox_from_rfc_4357(name),
                       "{} disagrees with RFC 4357 section 11.2", name);
        }
        // And the two are different tables, so a test that read the
        // same bytes twice would not pass.
        assert_ne!(GostCrypto::sbox_named(CRYPTOPRO_PARAM_SET).unwrap(),
                   GostCrypto::sbox_named(TEST_PARAM_SET).unwrap());
    }

    #[test]
    fn test_the_documents_sbox_is_the_one_we_carry() {
        let parsed = test_sbox_from_the_document();
        let carried = GostCrypto::sbox_named(TEST_PARAM_SET).unwrap();
        assert_eq!(parsed, carried,
                   "the table in RFC 5831 section 7.1 and the one in \
                    block_ciphers/gost.rs disagree");
        // Each substitution is a permutation of 0..16, which is what
        // makes a transposition mistake survivable and therefore worth
        // checking separately: eight permutations in the wrong order
        // are still eight permutations.
        for row in &parsed {
            let mut sorted = row.clone();
            sorted.sort();
            assert_eq!(sorted, (0..16u8).collect::<Vec<u8>>());
        }
    }

    fn with_test_sbox(data: &[u8]) -> Vec<u8> {
        let mut hash = Gost94::with_param_set(data, TEST_PARAM_SET).unwrap();
        hash.digest()
    }

    /// The first compression of the first example, key by key.
    ///
    /// This is the point of using a document that prints its
    /// intermediates: `keys_for` is pinned on its own, so a mistake in
    /// it cannot be cancelled out by a compensating mistake in the
    /// mixing transformation. The two together are one function and
    /// would round trip against themselves perfectly.
    ///
    /// **And RFC 5831 misprints one of them.** `K[1]` of this first
    /// step is printed with two of its eight 32 bit words transposed -
    /// the second and the fifth. Everything else in both examples
    /// agrees to the digit: `K[2]`, `K[3]` and `K[4]` here, all four
    /// keys of every other step, the `S` these four keys produce, the
    /// `KSI` that follows it, and both final hashes - one of which is
    /// the widely published vector for this message. A `P` that
    /// produced the printed `K[1]` would produce a different `S` two
    /// lines below it, so the document disagrees with itself and the
    /// rest of it wins.
    ///
    /// Asserted rather than skipped, and asserted as *exactly* two
    /// transposed words: if a future reading of the standard changes
    /// `P`, this fails whichever way it moves.
    #[test]
    fn test_the_key_schedule_of_the_first_example() {
        let values = assignments("7.3.1.  Hash", "\n7.3.2.");
        let m = named(&values, "M", 0);
        let h = [0u8; BLOCK];

        let keys = keys_for(&m, &h);
        for (index, key) in keys.iter().enumerate().skip(1) {
            let expected = named(&values, &format!("K[{}]", index + 1), 0);
            assert_eq!(key, &expected, "K[{}] of the first step", index + 1);
        }

        let printed = named(&values, "K[1]", 0);
        let ours = keys[0];
        let word = |value: &[u8; BLOCK], index: usize| -> [u8; 4] {
            value[index * 4..index * 4 + 4].try_into().expect("four bytes")
        };
        let differ: Vec<usize> = (0..8)
            .filter(|index| word(&printed, *index) != word(&ours, *index))
            .collect();
        assert_eq!(differ, vec![1, 4],
                   "the printed K[1] differs from ours in words {:?}; the \
                    known misprint is words 1 and 4 transposed", differ);
        assert_eq!(word(&printed, 1), word(&ours, 4));
        assert_eq!(word(&printed, 4), word(&ours, 1));
    }

    /// And the encryption stage: the four cipher outputs, which the
    /// document prints as S.
    #[test]
    fn test_the_cipher_outputs_of_the_first_example() {
        let values = assignments("7.3.1.  Hash", "\n7.3.2.");
        let m = named(&values, "M", 0);
        let h = [0u8; BLOCK];
        let sbox = GostCrypto::sbox_named(TEST_PARAM_SET).unwrap();

        let keys = keys_for(&m, &h);
        let mut s = [0u8; BLOCK];
        for (i, key) in keys.iter().enumerate() {
            let mut cipher = GostCrypto::new_with_sbox(key,
                                                       &sbox).unwrap();
            let mut out = Vec::new();
            cipher.block_encrypt(&h[i * 8..(i + 1) * 8], &mut out);
            s[i * 8..(i + 1) * 8].copy_from_slice(&out);
        }
        // The document prints S for the *second* compression onwards
        // and spells the first one out as four separate s[i] lines, so
        // the whole word is assembled from those.
        let printed = assignments("7.3.1.  Hash", "\n7.3.2.");
        let expected = printed.iter().find(|(name, _)| name == "S")
            .map(|(_, value)| as_stream(value))
            .expect("the document prints S");
        assert_eq!(s, expected, "the four encryptions of the first step");
    }

    /// And the step function's output, which pins the mixing.
    #[test]
    fn test_the_first_step_of_the_first_example() {
        let values = assignments("7.3.1.  Hash", "\n7.3.2.");
        let m = named(&values, "M", 0);
        let sbox = GostCrypto::sbox_named(TEST_PARAM_SET).unwrap();
        let mut cipher = GostCrypto::new_with_sbox(&[0; 32], &sbox).unwrap();
        let result = chi(&m, &[0u8; BLOCK], &mut cipher);
        assert_eq!(result, named(&values, "KSI", 0),
                   "chi(M, 0) of the first example");
    }

    /// RFC 5831 appendix 7.3.1: "This is message, length=32 bytes".
    #[test]
    fn test_the_first_documented_message() {
        let values = assignments("7.3.1.  Hash", "\n7.3.2.");
        let message = named(&values, "M", 0);
        // The document's M read as a byte string is the message, and
        // it is ASCII - which is the check that `as_stream` is the
        // right way round rather than a hope.
        assert_eq!(std::str::from_utf8(&message).unwrap(),
                   "This is message, length=32 bytes");

        let expected = named(&values, "H", 1);
        assert_eq!(with_test_sbox(&message), expected.to_vec());
    }

    /// RFC 5831 appendix 7.3.2, which is 50 bytes - so it has a padded
    /// final block, where the first example has none.
    #[test]
    fn test_the_second_documented_message() {
        let text = "Suppose the original message has length = 50 bytes";
        assert_eq!(text.len(), 50);
        let values = assignments("7.3.2.  Hash", "\n8.  Security");
        // The last H printed in the section is the answer.
        let hashes: Vec<&(String, Vec<u8>)> = values.iter()
            .filter(|(name, _)| name == "H").collect();
        let expected = as_stream(&hashes.last().expect("an H").1);
        assert_eq!(with_test_sbox(text.as_bytes()), expected.to_vec());
    }

    /// The two parameter sets are two different hashes.
    ///
    /// Worth stating, because the only sign of using the wrong one is
    /// that a signature does not verify - against a peer, days later.
    #[test]
    fn test_the_parameter_sets_disagree() {
        let message = b"This is message, length=32 bytes";
        let test = with_test_sbox(message);
        let mut cryptopro = Gost94::new(message);
        assert_ne!(test, cryptopro.digest());
        assert!(Gost94::with_param_set(&[], "id-Gost28147-89-TestParamSet")
                .is_err(),
                "a 28147 parameter set is not a 34.11 one");
        assert!(Gost94::with_param_set(&[], "Default").is_err());
    }

    /// `update` copied its whole input into a `Vec` before compressing
    /// a block of it, so hashing a large buffer needed a second copy of
    /// it, and `digest` cloned the hash - with its boxed 4 KiB table -
    /// every call. The streaming test below fed at most 137 bytes, for
    /// which a `Vec` and a block-sized array behave alike. The pending
    /// store is now a block-sized array, which the first assertion
    /// checks by type, and the rest pins the hold-back rule on piece
    /// sizes that cross the block boundary every way: several blocks in
    /// one call, exactly a block, a block and one, and byte by byte.
    #[test]
    fn test_update_holds_at_most_one_block() {
        let message: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let one_shot = Gost94::new(&message).digest();
        let mut hash = Gost94::new(&[]);
        hash.update(&message);
        let held: &[u8; BLOCK] = &hash.pending;
        assert_eq!(held.len(), BLOCK);
        assert!(hash.pending_len >= 1 && hash.pending_len <= BLOCK);
        assert_eq!(hash.digest(), one_shot);
        for piece in [1usize, 31, 32, 33, 63, 64, 65, 100, 999] {
            let mut hash = Gost94::new(&[]);
            for chunk in message.chunks(piece) {
                hash.update(chunk);
                assert!(hash.pending_len >= 1 && hash.pending_len <= BLOCK,
                        "{} held after a piece of {}", hash.pending_len, piece);
            }
            assert_eq!(hash.digest(), one_shot, "pieces of {}", piece);
            // And `digest` twice, then more input, still agrees.
            assert_eq!(hash.digest(), one_shot, "second digest, pieces of {}", piece);
            hash.update(b"tail");
            let mut whole = message.clone();
            whole.extend_from_slice(b"tail");
            assert_eq!(hash.digest(), Gost94::new(&whole).digest(), "after digest");
        }
    }

    /// Feeding the same message in pieces is the same hash.
    #[test]
    fn test_streaming_matches_one_shot() {
        let message: Vec<u8> = (0..137u8).collect();
        let one_shot = Gost94::new(&message).digest();
        for split in [0, 1, 31, 32, 33, 64, 100, 137] {
            let mut hash = Gost94::new(&message[..split]);
            hash.update(&message[split..]);
            assert_eq!(hash.digest(), one_shot, "split at {}", split);
            // And a zero length call in the middle changes nothing -
            // the mistake `BlockBuffer` exists to prevent.
            let mut hash = Gost94::new(&message[..split]);
            hash.update(&[]);
            hash.update(&message[split..]);
            assert_eq!(hash.digest(), one_shot, "empty update at {}", split);
        }
    }

    /// An empty message is three compressions, not zero.
    ///
    /// The final block is fed even when it is empty, so the digest of
    /// nothing is not the initial value. An implementation that skips
    /// the tail when there is no tail returns `h0` - thirty-two zero
    /// bytes here - and fails every message whose length is a multiple
    /// of 32 bytes in the same way.
    #[test]
    fn test_the_empty_message_is_not_the_initial_value() {
        let empty = Gost94::new(&[]).digest();
        assert_ne!(empty, vec![0u8; 32]);
        // And a 32 byte message is not the same as its first block
        // being the whole story either.
        let exact = Gost94::new(&[0u8; 32]).digest();
        assert_ne!(exact, empty);
    }

    /// C[3] is 256 bits and is not all zeros, and the pieces of the
    /// expression it is parsed from are the pieces the document wrote.
    #[test]
    fn test_the_constant_comes_out_of_the_document() {
        let expression = c3_expression();
        assert!(expression.starts_with("1^8||0^8||1^16"), "{}", expression);
        assert!(expression.ends_with("(1^8||0^8)^4"), "{}", expression);
        let value = c3();
        assert_ne!(value, [0u8; BLOCK]);
        // Every byte is 0x00 or 0xff, since the expression is written
        // in runs of eight or more bits.
        for byte in value {
            assert!(byte == 0 || byte == 0xff, "byte {:#04x}", byte);
        }
        assert_eq!(value.iter().filter(|b| **b == 0xff).count(), 16,
                   "half the bytes are set");
    }
}
