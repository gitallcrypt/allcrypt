/*
OCB, Krovetz and Rogaway's authenticated mode, as RFC 7253 specifies it
(OCB3).

One block cipher call per block of message - half of what EAX, CCM or
GCM-without-a-multiplier need - and the authentication is a plain XOR
checksum of the plaintext, encrypted once at the end:

    Offset_0 from the nonce (below)
    Offset_i = Offset_{i-1} ^ L_{ntz(i)}
    C_i      = Offset_i ^ E(P_i ^ Offset_i)
    Checksum = P_1 ^ P_2 ^ ... (^ P_* || 1 || 0...)
    Tag      = E(Checksum ^ Offset_m(*) ^ L_$) ^ HASH(A)

with `L_* = E(0)`, `L_$ = double(L_*)`, `L_0 = double(L_$)` and each
further `L_i` the doubling of the one before. OpenPGP uses it: RFC 9580's
version 2 encrypted data packets and LibrePGP's (GnuPG's) OCB packets
take OCB as their default AEAD.

It is defined for 128 bit blocks only. RFC 7253 section 3 makes the
block cipher a parameter, so any 128 bit cipher here gets it - OpenPGP
names AES, Camellia and Twofish - and a 64 bit one is refused rather
than run with a doubling polynomial nobody wrote down.

## What is silent when wrong

**`double` is big endian.** `S[1]` is the most significant bit of the
first byte, the shift is left across the whole block, and the reduction
`0x87` goes into the *last* byte. That is LRW's field and MGM's, and
the opposite of XTS's and GHASH's.

**The nonce block carries the tag length.** Its top seven bits are
`TAGLEN mod 128`, so a 128 bit tag writes zero there and a 96 bit one
writes 96: a truncated tag is not a prefix of the full one, unlike EAX's.
A single `1` bit sits immediately above the nonce, which is what makes a
short nonce differ from a long one with leading zeros.

**`Offset_0` is a 128 bit window into a 192 bit string.** `Ktop` is the
cipher of the nonce block with its low six bits cleared, `Stretch` is
`Ktop || (Ktop[1..64] ^ Ktop[9..72])`, and the low six bits of the
nonce (`bottom`) say how far into `Stretch` the window starts. Every
nonce in a counter sequence shares `Ktop` with sixty-three neighbours,
which is the point of it (one cipher call per sixty-four messages), and
the window arithmetic is exercised by the RFC's internal values at
`bottom = 15` and by the long iterated vector at every other value.

**The offsets index `L` by the trailing zeros of the block number, from
one.** `ntz(1) = 0`, `ntz(2) = 1`, `ntz(4) = 2`. Starting the count at
zero, or using the block number itself, is right for the first block and
wrong from the second.

**The final partial block is padded `1 || 0...` in the checksum and in
HASH**, and its keystream is `E(Offset_*)` with nothing XORed in. The
three branches - no partial block, a partial block, no blocks at all -
each have their own vectors in appendix A.

**The checksum is over the plaintext.** Decryption must recompute it from
what it decrypted, and returns nothing until the tag matches.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::BlockCipher;

const BLOCK: usize = 16;

/// Blocks handed to the cipher at a time. OCB's blocks are independent
/// of each other - the offsets depend only on the block number - so a
/// batch goes through `encrypt_blocks`, which is what keeps AES on its
/// constant-time path.
const BATCH: usize = 16;

fn double(value: u128) -> u128 {
    (value << 1) ^ if value >> 127 == 1 { 0x87 } else { 0 }
}

/// One OCB key, over a named 128 bit block cipher, serving any number
/// of messages: the cipher and the `L` values are built once, which is
/// what `encrypt` and `decrypt` take `&mut self` for.
pub struct Ocb {
    keyed: Keyed,
    tag_len: usize,
}

impl core::fmt::Debug for Ocb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ocb {{ {}, keys redacted }}", self.keyed.cipher.name())
    }
}

/// The keyed state: the cipher, `L_*`, `L_$` and the `L_i` computed
/// so far, and the scratch a batch of blocks goes through the cipher in.
struct Keyed {
    cipher: AnyBlockCipher,
    l_star: u128,
    l_dollar: u128,
    l: Vec<u128>,
    batch: Vec<u8>,
}

impl Keyed {
    fn new(cipher_name: &str, key: &[u8]) -> Result<Keyed, String> {
        let cipher = AnyBlockCipher::new(cipher_name, key, None)?;
        if cipher.blocksize() != BLOCK {
            return Err(format!(
                "OCB is defined for a 128 bit block; {cipher_name}'s is {} bits.",
                cipher.blocksize() * 8));
        }
        let mut keyed = Keyed { cipher, l_star: 0, l_dollar: 0, l: Vec::new(),
                                batch: Vec::with_capacity(BATCH * BLOCK) };
        keyed.l_star = keyed.encipher(0)?;
        keyed.l_dollar = double(keyed.l_star);
        keyed.l.push(double(keyed.l_dollar));
        Ok(keyed)
    }

    /// One block, through `encrypt_blocks` like the batches: every single
    /// block here - `L_*`, `Ktop`, a final partial block's pad, the tag -
    /// is under the secret key and most are secret too, and AES's
    /// one-block `block_encrypt` is its table path.
    fn encipher(&mut self, block: u128) -> Result<u128, String> {
        let mut one = block.to_be_bytes();
        self.cipher.encrypt_blocks(&mut one)?;
        Ok(u128::from_be_bytes(one))
    }

    /// The whole blocks of `input`, numbered from `first`, each
    /// `Offset_i ^ E(X_i ^ Offset_i)` (or `D` for decryption) appended to
    /// `out`, a batch at a time; `offset` is left at the last block's.
    /// `sum` collects the XOR of the blocks on the plaintext side - the
    /// input when encrypting, the output when decrypting - which is
    /// OCB's checksum.
    fn crypt_blocks(&mut self, input: &[u8], first: u64, offset: &mut u128, encrypt: bool,
                    sum: &mut u128, out: &mut Vec<u8>) -> Result<(), String> {
        let mut number = first;
        let mut offsets = [0u128; BATCH];
        for chunk in input.chunks(BATCH * BLOCK) {
            self.batch.clear();
            for (block, saved) in chunk.chunks_exact(BLOCK).zip(offsets.iter_mut()) {
                *offset ^= self.l_for(number);
                number += 1;
                *saved = *offset;
                let x = u128::from_be_bytes(block.try_into().unwrap());
                if encrypt {
                    *sum ^= x;
                }
                self.batch.extend_from_slice(&(x ^ *offset).to_be_bytes());
            }
            if encrypt {
                self.cipher.encrypt_blocks(&mut self.batch)?;
            } else {
                self.cipher.decrypt_blocks(&mut self.batch)?;
            }
            for (block, saved) in self.batch.chunks_exact(BLOCK).zip(offsets.iter()) {
                let y = u128::from_be_bytes(block.try_into().unwrap()) ^ *saved;
                if !encrypt {
                    *sum ^= y;
                }
                out.extend_from_slice(&y.to_be_bytes());
            }
        }
        Ok(())
    }

    /// `L_{ntz(i)}` for block number `i`, counted from one.
    fn l_for(&mut self, i: u64) -> u128 {
        let index = i.trailing_zeros() as usize;
        while self.l.len() <= index {
            let next = double(*self.l.last().unwrap());
            self.l.push(next);
        }
        self.l[index]
    }

    /// RFC 7253 section 4.1, HASH(K, A): the XOR of `E(A_i ^ Offset_i)`
    /// over the blocks, a batch at a time.
    fn hash(&mut self, aad: &[u8]) -> Result<u128, String> {
        let (mut sum, mut offset) = (0u128, 0u128);
        let whole = aad.len() / BLOCK * BLOCK;
        let mut number = 1u64;
        for chunk in aad[..whole].chunks(BATCH * BLOCK) {
            self.batch.clear();
            for block in chunk.chunks_exact(BLOCK) {
                offset ^= self.l_for(number);
                number += 1;
                let a = u128::from_be_bytes(block.try_into().unwrap());
                self.batch.extend_from_slice(&(a ^ offset).to_be_bytes());
            }
            self.cipher.encrypt_blocks(&mut self.batch)?;
            for block in self.batch.chunks_exact(BLOCK) {
                sum ^= u128::from_be_bytes(block.try_into().unwrap());
            }
        }
        let rest = &aad[whole..];
        if !rest.is_empty() {
            offset ^= self.l_star;
            sum ^= self.encipher(padded(rest) ^ offset)?;
        }
        Ok(sum)
    }

    /// `Offset_0` from the nonce, section 4.2.
    fn initial_offset(&mut self, nonce: &[u8], tag_len: usize) -> Result<u128, String> {
        let mut n = 0u128;
        for &byte in nonce {
            n = n << 8 | u128::from(byte);
        }
        // num2str(TAGLEN mod 128, 7) || zeros || 1 || N
        let block = ((tag_len as u128 * 8) % 128) << 121 | 1u128 << (8 * nonce.len()) | n;
        let bottom = (block & 0x3f) as u32;
        let ktop = self.encipher(block & !0x3f)?;
        // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]): the low 64
        // bits of a 192 bit string whose top 128 are Ktop.
        let tail = ((ktop >> 64) ^ (ktop >> 56)) as u64;
        Ok(if bottom == 0 {
            ktop
        } else {
            ktop << bottom | u128::from(tail >> (64 - bottom))
        })
    }
}

/// `A_* || 1 || zeros`, a partial block padded to a whole one.
fn padded(rest: &[u8]) -> u128 {
    let mut block = [0u8; BLOCK];
    block[..rest.len()].copy_from_slice(rest);
    block[rest.len()] = 0x80;
    u128::from_be_bytes(block)
}

impl Ocb {
    /// OCB with a 128 bit tag.
    pub fn new(cipher_name: &str, key: &[u8]) -> Result<Ocb, String> {
        Ocb::with_tag_len(cipher_name, key, BLOCK)
    }

    /// A shorter tag, in bytes. Not a prefix of the 16 byte one: the
    /// length is written into the nonce block, so each tag length is its
    /// own mode.
    pub fn with_tag_len(cipher_name: &str, key: &[u8], tag_len: usize) -> Result<Ocb, String> {
        if tag_len == 0 || tag_len > BLOCK {
            return Err(format!("An OCB tag is 1..=16 bytes; {tag_len} was asked for."));
        }
        Ok(Ocb { keyed: Keyed::new(cipher_name, key)?, tag_len })
    }

    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// RFC 7253 section 2: a nonce of 1 to 15 bytes. The construction
    /// would keep an empty one distinct - the `1` marker above the
    /// nonce moves - but it is outside the parameter set the document
    /// defines and its vectors cover.
    fn check_nonce(nonce: &[u8]) -> Result<(), String> {
        if nonce.is_empty() || nonce.len() > 15 {
            return Err(format!("An OCB nonce is 1 to 15 bytes (RFC 7253 section 2); \
                                got {}.", nonce.len()));
        }
        Ok(())
    }

    /// Encrypt, returning `(ciphertext, tag)`.
    pub fn encrypt(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8])
                   -> Result<(Vec<u8>, Vec<u8>), String> {
        Ocb::check_nonce(nonce)?;
        let keyed = &mut self.keyed;
        let mut offset = keyed.initial_offset(nonce, self.tag_len)?;
        let mut checksum = 0u128;
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        let whole = plaintext.len() / BLOCK * BLOCK;
        keyed.crypt_blocks(&plaintext[..whole], 1, &mut offset, true, &mut checksum,
                           &mut ciphertext)?;
        let rest = &plaintext[whole..];
        if !rest.is_empty() {
            offset ^= keyed.l_star;
            let pad = keyed.encipher(offset)?.to_be_bytes();
            ciphertext.extend(rest.iter().zip(pad).map(|(p, k)| p ^ k));
            checksum ^= padded(rest);
        }
        let hash = keyed.hash(aad)?;
        let tag = keyed.encipher(checksum ^ offset ^ keyed.l_dollar)? ^ hash;
        Ok((ciphertext, tag.to_be_bytes()[..self.tag_len].to_vec()))
    }

    /// Decrypt, checking the tag before returning any plaintext.
    pub fn decrypt(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8])
                   -> Result<Vec<u8>, String> {
        Ocb::check_nonce(nonce)?;
        if tag.len() != self.tag_len {
            return Err(format!("An OCB tag is {} bytes here; got {}.", self.tag_len, tag.len()));
        }
        let keyed = &mut self.keyed;
        let mut offset = keyed.initial_offset(nonce, self.tag_len)?;
        let mut checksum = 0u128;
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        let whole = ciphertext.len() / BLOCK * BLOCK;
        keyed.crypt_blocks(&ciphertext[..whole], 1, &mut offset, false, &mut checksum,
                           &mut plaintext)?;
        let rest = &ciphertext[whole..];
        if !rest.is_empty() {
            offset ^= keyed.l_star;
            let pad = keyed.encipher(offset)?.to_be_bytes();
            let start = plaintext.len();
            plaintext.extend(rest.iter().zip(pad).map(|(c, k)| c ^ k));
            checksum ^= padded(&plaintext[start..]);
        }
        let hash = keyed.hash(aad)?;
        let expected = keyed.encipher(checksum ^ offset ^ keyed.l_dollar)? ^ hash;
        if crate::bignum::ct::bytes_differ(&expected.to_be_bytes()[..self.tag_len], tag) {
            return Err("The OCB tag does not match; the message was altered or was not \
                        for this key.".to_string());
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC: &str = include_str!("../../rfcs/rfc7253.txt");

    fn unhex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits.chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// Appendix A's text with the page furniture removed: the running
    /// footer and header lines and the form feeds between them.
    fn appendix() -> Vec<&'static str> {
        let start = RFC.find("Appendix A.  Sample Results\n").unwrap();
        RFC[start..].lines()
            .filter(|l| !l.starts_with("Krovetz & Rogaway") && !l.starts_with("RFC 7253")
                        && !l.starts_with('\x0c'))
            .collect()
    }

    struct Sample {
        key: Vec<u8>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        plaintext: Vec<u8>,
        output: Vec<u8>,
    }

    /// The `K:`, `N:`, `A:`, `P:`, `C:` tuples. A value continues on the
    /// following indented lines that carry no label.
    fn samples() -> Vec<Sample> {
        let lines = appendix();
        let mut out = Vec::new();
        let mut key = Vec::new();
        let mut current: Vec<(String, Vec<u8>)> = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();
            if let Some((label, value)) = line.split_once(':') {
                let label = label.trim();
                if ["K", "N", "A", "P", "C"].contains(&label) {
                    let mut text = value.to_string();
                    while i + 1 < lines.len() {
                        let next = lines[i + 1].trim();
                        if next.is_empty() || next.contains(':')
                            || !next.bytes().all(|b| b.is_ascii_hexdigit()) {
                            break;
                        }
                        text.push_str(next);
                        i += 1;
                    }
                    let value = unhex(&text);
                    if label == "K" {
                        key = value;
                    } else {
                        current.push((label.to_string(), value));
                        if label == "C" {
                            let get = |name: &str| current.iter().find(|(n, _)| n == name)
                                .map(|(_, v)| v.clone()).unwrap();
                            out.push(Sample { key: key.clone(), nonce: get("N"), aad: get("A"),
                                              plaintext: get("P"), output: get("C") });
                            current.clear();
                        }
                    }
                }
            }
            i += 1;
        }
        out
    }

    #[test]
    fn test_the_sample_results() {
        let samples = samples();
        // Sixteen with the first key and a 128 bit tag, one with the
        // second key and a 96 bit tag.
        assert_eq!(samples.len(), 17);
        assert!(samples.iter().any(|s| s.plaintext.is_empty() && s.aad.is_empty()));
        for (index, s) in samples.iter().enumerate() {
            let tag_len = s.output.len() - s.plaintext.len();
            let mut ocb = Ocb::with_tag_len("aes", &s.key, tag_len).unwrap();
            let (ciphertext, tag) = ocb.encrypt(&s.nonce, &s.aad, &s.plaintext).unwrap();
            let mut combined = ciphertext.clone();
            combined.extend_from_slice(&tag);
            assert_eq!(combined, s.output, "sample {index}");
            assert_eq!(ocb.decrypt(&s.nonce, &s.aad, &ciphertext, &tag).unwrap(), s.plaintext,
                       "sample {index}");
        }
        assert_eq!(samples.last().unwrap().output.len() - samples.last().unwrap().plaintext.len(),
                   12);
    }

    /// The internal values the appendix prints for the sixteenth
    /// sample: `L_*`, `L_$`, `L_0`, `L_1`, `bottom`, `Ktop` and the
    /// offsets, so that a wrong window into `Stretch` is reported as
    /// that rather than as a wrong tag.
    #[test]
    fn test_the_internal_values() {
        let lines = appendix();
        let value = |label: &str| -> Vec<u8> {
            let line = lines.iter()
                .find(|l| l.trim_start().starts_with(label)
                          && l.trim_start()[label.len()..].trim_start().starts_with(':'))
                .unwrap_or_else(|| panic!("{label} not in the appendix"));
            unhex(line.split_once(':').unwrap().1.split('(').next().unwrap())
        };
        let as_u128 = |v: Vec<u8>| u128::from_be_bytes(v.try_into().unwrap());
        let key = unhex("000102030405060708090A0B0C0D0E0F");
        let nonce = unhex("BBAA9988776655443322110F");
        let mut keyed = Keyed::new("aes", &key).unwrap();
        assert_eq!(keyed.l_star, as_u128(value("L_*")));
        assert_eq!(keyed.l_dollar, as_u128(value("L_$")));
        assert_eq!(keyed.l_for(1), as_u128(value("L_0")));
        assert_eq!(keyed.l_for(2), as_u128(value("L_1")));

        let offset0 = keyed.initial_offset(&nonce, 16).unwrap();
        assert_eq!(offset0, as_u128(value("Offset_0")));
        let offset1 = offset0 ^ keyed.l_for(1);
        assert_eq!(offset1, as_u128(value("Offset_1")));
        let offset2 = offset1 ^ keyed.l_for(2);
        assert_eq!(offset2, as_u128(value("Offset_2")));
        assert_eq!(offset2 ^ keyed.l_star, as_u128(value("Offset_*")));
        // bottom is printed in decimal.
        let bottom = lines.iter().find(|l| l.trim_start().starts_with("bottom")).unwrap();
        assert!(bottom.contains(": 15 (decimal)"));
    }

    /// The iterated test at the end of appendix A, for all nine
    /// parameter sets: 385 encryptions per set, with every nonce bottom
    /// from 0 to 63 and every message length from 0 to 127 bytes.
    #[test]
    fn test_the_iterated_vectors() {
        let lines = appendix();
        let mut count = 0;
        for line in &lines {
            let Some(rest) = line.trim().strip_prefix("AEAD_AES_") else { continue };
            let (name, output) = rest.split_once("Output").unwrap();
            let expected = unhex(output.split_once(':').unwrap().1);
            let mut parts = name.trim().split('_');
            let key_bits: usize = parts.next().unwrap().parse().unwrap();
            assert_eq!(parts.next(), Some("OCB"));
            let tag_bits: usize = parts.next().unwrap().strip_prefix("TAGLEN").unwrap()
                .parse().unwrap();

            let mut key = vec![0u8; key_bits / 8];
            *key.last_mut().unwrap() = tag_bits as u8;
            let mut ocb = Ocb::with_tag_len("aes", &key, tag_bits / 8).unwrap();
            let nonce = |n: u64| { let mut v = vec![0u8; 4]; v.extend(n.to_be_bytes()); v };
            let mut c = Vec::new();
            let mut seal = |n: u64, a: &[u8], p: &[u8], c: &mut Vec<u8>| {
                let (ciphertext, tag) = ocb.encrypt(&nonce(n), a, p).unwrap();
                c.extend(ciphertext);
                c.extend(tag);
            };
            for i in 0..128u64 {
                let s = vec![0u8; i as usize];
                seal(3 * i + 1, &s, &s, &mut c);
                seal(3 * i + 2, &[], &s, &mut c);
                seal(3 * i + 3, &s, &[], &mut c);
            }
            let (empty, tag) = ocb.encrypt(&nonce(385), &c, &[]).unwrap();
            assert!(empty.is_empty());
            assert_eq!(tag, expected, "AEAD_AES_{}", name.trim());
            count += 1;
        }
        assert_eq!(count, 9);
    }

    #[test]
    fn test_altering_anything_is_refused() {
        let mut ocb = Ocb::new("aes", &[0x33; 16]).unwrap();
        let (nonce, aad) = (b"twelve bytes", b"associated data");
        for length in [0usize, 1, 15, 16, 17, 33] {
            let message = vec![0x5a; length];
            let (ciphertext, tag) = ocb.encrypt(nonce, aad, &message).unwrap();
            assert_eq!(ocb.decrypt(nonce, aad, &ciphertext, &tag).unwrap(), message);
            for i in 0..ciphertext.len() {
                let mut altered = ciphertext.clone();
                altered[i] ^= 1;
                assert!(ocb.decrypt(nonce, aad, &altered, &tag).is_err());
            }
            for i in 0..tag.len() {
                let mut altered = tag.clone();
                altered[i] ^= 0x80;
                assert!(ocb.decrypt(nonce, aad, &ciphertext, &altered).is_err());
            }
            assert!(ocb.decrypt(b"twelve bytez", aad, &ciphertext, &tag).is_err());
            assert!(ocb.decrypt(nonce, b"associated datA", &ciphertext, &tag).is_err());
        }
    }

    /// The tag length is in the nonce block, so a truncated tag is not
    /// the full tag cut short - the opposite of EAX.
    #[test]
    fn test_a_shorter_tag_is_a_different_mode() {
        let mut full = Ocb::new("aes", &[7; 16]).unwrap();
        let mut short = Ocb::with_tag_len("aes", &[7; 16], 8).unwrap();
        let (c1, t1) = full.encrypt(b"nonce", b"", b"message").unwrap();
        let (c2, t2) = short.encrypt(b"nonce", b"", b"message").unwrap();
        assert_ne!(c1, c2);
        assert_ne!(&t1[..8], &t2[..]);
        assert!(short.decrypt(b"nonce", b"", &c2, &t1[..8]).is_err());
    }

    /// A short nonce is not a long one with leading zeros: the `1`
    /// above it moves. And the lengths are RFC 7253's, 1 to 15: the
    /// empty nonce was accepted, outside the document's parameter set,
    /// and this test used it.
    #[test]
    fn test_the_nonce_length_matters() {
        let mut ocb = Ocb::new("aes", &[9; 16]).unwrap();
        let mut seen = std::collections::HashSet::new();
        for length in 1..=15 {
            let (c, t) = ocb.encrypt(&vec![0u8; length], b"", b"m").unwrap();
            assert!(seen.insert((c, t)), "nonce length {length} collided");
        }
        assert!(ocb.encrypt(&[], b"", b"m").is_err());
        assert!(ocb.encrypt(&[0u8; 16], b"", b"m").is_err());
        assert!(ocb.decrypt(&[], b"", b"", &[0u8; 16]).is_err());
    }

    #[test]
    fn test_other_128_bit_ciphers_and_refusals() {
        for name in ["camellia", "twofish", "serpent", "aria", "sm4", "seed", "kuznyechik"] {
            let key = vec![0x42u8; if name == "kuznyechik" { 32 } else { 16 }];
            let mut ocb = Ocb::new(name, &key).unwrap();
            let (c, t) = ocb.encrypt(b"n", b"a", &[1u8; 40]).unwrap();
            assert_eq!(ocb.decrypt(b"n", b"a", &c, &t).unwrap(), vec![1u8; 40], "{name}");
        }
        assert!(Ocb::new("des", &[0u8; 8]).is_err());
        assert!(Ocb::new("blowfish", &[0u8; 16]).is_err());
        assert!(Ocb::with_tag_len("aes", &[0u8; 16], 0).is_err());
        assert!(Ocb::with_tag_len("aes", &[0u8; 16], 17).is_err());
    }

    /// One `Ocb` holds its cipher and `L` values, where each call used
    /// to build them again. What the saving changes is that state can
    /// now leak from one message into the next - the `L_i` table grows
    /// with the longest message seen - so this runs messages of several
    /// lengths, decryptions, and a decryption that fails, through one
    /// object and checks each against a fresh one.
    #[test]
    fn test_one_object_serves_many_messages() {
        let mut shared = Ocb::new("aes", &[0x77; 16]).unwrap();
        let (nonce, aad) = (b"nonce", b"aad");
        for length in [100usize, 0, 1, 15, 16, 17, 32, 33, 1000] {
            let message = vec![length as u8; length];
            let (ciphertext, tag) = shared.encrypt(nonce, aad, &message).unwrap();
            let mut fresh = Ocb::new("aes", &[0x77; 16]).unwrap();
            assert_eq!(fresh.encrypt(nonce, aad, &message).unwrap(), (ciphertext.clone(), tag.clone()),
                       "length {length}");
            let mut wrong = tag.clone();
            wrong[0] ^= 1;
            assert!(shared.decrypt(nonce, aad, &ciphertext, &wrong).is_err());
            assert_eq!(shared.decrypt(nonce, aad, &ciphertext, &tag).unwrap(), message);
        }
    }
}
