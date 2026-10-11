/*!
DSTU 7624:2014's authenticated modes over Kalyna - its GCM and GMAC
("selective gamma with accelerated authentication") and its CCM
("authentication and gamma") - and its XTS ("indexed substitution").
None of the four is NIST's mode of the same name run over another
cipher: the field, the byte order, the counter, the length block and the
header all differ.

## The field

`GF(2^n)` for `n` the block size in bits, with a block read as a
**little-endian** integer, bit `i` the coefficient of `x^i`. The
reduction polynomials are `x^128 + x^7 + x^2 + x + 1`,
`x^256 + x^10 + x^5 + x^2 + 1` and `x^512 + x^8 + x^5 + x^2 + 1`. GCM
multiplies in it and XTS doubles in it.

## GCM and GMAC

`H = E(0)`. The message is encrypted with Kalyna's own counter mode
under the IV (`E(IV) + 1` first, little endian). The tag is
`E(B ⊕ L)`, cut to `q` bytes, where `B` is the polynomial hash of the
associated data's blocks and then the ciphertext's - `B ← (B ⊕ X)·H` -
and `L` is the associated data's length in bits at byte 0 and the
ciphertext's at the middle of the block, each 64 bits little endian.
There is no multiplication after the length block. GMAC is the tag of
GCM with the data as associated data and no message, so the IV does not
enter it.

**A last block that is not whole is padded with zeros**, as Bouncy
Castle pads it. cryptonite pads a short last block of the message with
`80 00 ... 00` instead, and its reading of a short block of associated
data depends on memory it never wrote, so the two implementations agree
only on whole blocks and no published example has a short one. This is
the reading of one implementation, not of the standard's text; see
`docs/pitfalls.md`.

## CCM

A CBC-MAC over a header, the associated data and the message, then the
message and the MAC encrypted with Kalyna's counter mode under the
nonce, the MAC by the keystream that follows the message's. The header
is two parts:

- `G1`: the nonce's first `B − Nb − 1` bytes, the message's length in
  bytes as `Nb` bytes little endian, and a flag byte - bit 7 set when
  there is a message, the tag length's code in bits 6 to 4 (8, 16, 32,
  48 and 64 bytes are 2 to 6), and `Nb − 1` in bits 3 to 0;
- `G2`: the associated data's length, little endian, **cut short so
  that the associated data after it ends on a block boundary** - the
  whole block when the data is whole blocks.

A message that is not whole blocks is padded with `80 00 ... 00` for
the MAC. Bouncy Castle takes whole blocks only, at least one of them of
associated data, so for everything else - a short block, no associated
data, no message - this is cryptonite's reading, which its own tests
pin with a short-block example.

## XTS

One key. The tweak starts at `E(IV)` and is doubled in the field
before each block, so the first block uses `2·E(IV)`; each block is
`E(P ⊕ T) ⊕ T`. A last block that is not whole is handled by ciphertext
stealing as IEEE 1619 does it: the last whole block's ciphertext lends
its tail, the combined block is encrypted under the next tweak, and the
two trade places. Bouncy Castle takes whole blocks only; the stealing is
cryptonite's, and its tests carry five examples of it.

## Where the vectors come from

`vectors/kalyna_aead.vec`, written by `scripts/make_kalyna_aead_vectors.py`:
the standard's examples as Bouncy Castle's `DSTU7624Test.java` carries
them and cryptonite's acceptance tests, which every row's witness must
reproduce first, then rows on which Bouncy Castle 1.77 and cryptonite
agree, and each alone where the other stops.
*/

use crate::bignum::ct::bytes_differ;
use crate::block_ciphers::kalyna::Kalyna;
use crate::block_ciphers::BlockCipher;

/// The reduction polynomial's terms below `x^n`, for a block of `bytes`.
fn reduction(bytes: usize) -> u64 {
    match bytes {
        16 => 0x87,
        32 => 0x425,
        _ => 0x125,
    }
}

fn limbs(block: &[u8]) -> Vec<u64> {
    block.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes"))).collect()
}

fn bytes(limbs: &[u64]) -> Vec<u8> {
    limbs.iter().flat_map(|l| l.to_le_bytes()).collect()
}

/// `z · x` in place.
pub(crate) fn double(z: &mut [u64], poly: u64) {
    let mut carry = 0u64;
    for limb in z.iter_mut() {
        let top = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = top;
    }
    z[0] ^= poly & carry.wrapping_neg();
}

/// `a · b` in the field of `a.len()` limbs, by shift and add with masks:
/// no branch and no index depends on either value.
fn multiply(a: &[u64], b: &[u64], poly: u64) -> Vec<u64> {
    let mut z = vec![0u64; a.len()];
    let mut y = b.to_vec();
    for limb in a {
        for bit in 0..64 {
            let mask = ((limb >> bit) & 1).wrapping_neg();
            for (zi, yi) in z.iter_mut().zip(&y) {
                *zi ^= yi & mask;
            }
            double(&mut y, poly);
        }
    }
    z
}

fn encrypt(cipher: &mut Kalyna, block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(block.len());
    cipher.block_encrypt(block, &mut out);
    out
}

/// Kalyna's counter-mode keystream under `iv`, `len` bytes.
fn keystream(cipher: &mut Kalyna, iv: &[u8], len: usize) -> Result<Vec<u8>, String> {
    let mut counter = Vec::new();
    cipher.ctr_init(iv, &mut counter)?;
    let mut out = Vec::with_capacity(len + counter.len());
    while out.len() < len {
        cipher.block_encrypt(&counter, &mut out);
        cipher.ctr_next(&mut counter);
    }
    out.truncate(len);
    Ok(out)
}

fn xor_into(out: &mut [u8], with: &[u8]) {
    for (o, w) in out.iter_mut().zip(with) {
        *o ^= w;
    }
}

fn require_one_block(what: &str, value: &[u8], block: usize) -> Result<(), String> {
    if value.len() != block {
        return Err(format!("Kalyna's {what} is one block, {block} bytes, not {}.", value.len()));
    }
    Ok(())
}

// --------------------------------------------------------------- GCM ----

/// The tag of DSTU 7624's GCM over associated data and ciphertext,
/// `q` bytes.
fn gcm_tag(cipher: &mut Kalyna, aad: &[u8], ciphertext: &[u8], q: usize) -> Vec<u8> {
    let block = cipher.blocksize();
    let poly = reduction(block);
    let h = limbs(&encrypt(cipher, &vec![0u8; block]));
    let mut b = vec![0u64; block / 8];
    for data in [aad, ciphertext] {
        for chunk in data.chunks(block) {
            let mut padded = chunk.to_vec();
            padded.resize(block, 0);
            for (bi, x) in b.iter_mut().zip(limbs(&padded)) {
                *bi ^= x;
            }
            b = multiply(&b, &h, poly);
        }
    }
    b[0] ^= (aad.len() as u64).wrapping_mul(8);
    b[block / 16] ^= (ciphertext.len() as u64).wrapping_mul(8);
    let mut tag = encrypt(cipher, &bytes(&b));
    tag.truncate(q);
    tag
}

/// Whether `q` is a GCM tag length for a block of `block` bytes.
pub(crate) fn check_gcm_tag_len(q: usize, block: usize) -> Result<(), String> {
    if q < 8 || q > block {
        return Err(format!("A Kalyna GCM tag is 8 to {block} bytes, not {q}."));
    }
    Ok(())
}

/// DSTU 7624's GCM: the ciphertext and a tag of `q` bytes, 8 to the
/// block. The IV is one block.
///
/// # Errors
/// An IV that is not one block, or a tag length out of range.
pub fn gcm_encrypt(cipher: &mut Kalyna, iv: &[u8], aad: &[u8], message: &[u8], q: usize)
                   -> Result<(Vec<u8>, Vec<u8>), String> {
    let block = cipher.blocksize();
    require_one_block("GCM IV", iv, block)?;
    check_gcm_tag_len(q, block)?;
    let mut ciphertext = message.to_vec();
    xor_into(&mut ciphertext, &keystream(cipher, iv, message.len())?);
    let tag = gcm_tag(cipher, aad, &ciphertext, q);
    Ok((ciphertext, tag))
}

/// The inverse of `gcm_encrypt`. Nothing is decrypted unless the tag,
/// of exactly `q` bytes, checks.
///
/// # Errors
/// A tag that does not match, or the errors of `gcm_encrypt`.
pub fn gcm_decrypt(cipher: &mut Kalyna, iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8],
                   q: usize) -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    require_one_block("GCM IV", iv, block)?;
    check_gcm_tag_len(q, block)?;
    if tag.len() != q {
        return Err(format!("This Kalyna GCM tag is {q} bytes; got {}.", tag.len()));
    }
    if bytes_differ(&gcm_tag(cipher, aad, ciphertext, q), tag) {
        return Err("The Kalyna GCM tag does not match: the data or the associated data \
                    was altered, or the key or IV is wrong.".to_string());
    }
    let mut message = ciphertext.to_vec();
    xor_into(&mut message, &keystream(cipher, iv, ciphertext.len())?);
    Ok(message)
}

/// DSTU 7624's GMAC: GCM's tag over `data` as associated data, with no
/// message, `q` bytes from 8 to the block.
///
/// # Errors
/// A tag length out of range.
pub fn gmac(cipher: &mut Kalyna, data: &[u8], q: usize) -> Result<Vec<u8>, String> {
    check_gcm_tag_len(q, cipher.blocksize())?;
    Ok(gcm_tag(cipher, data, &[], q))
}

// --------------------------------------------------------------- CCM ----

/// The tag lengths CCM's flag byte has a code for, and the codes.
const CCM_TAG_CODES: [(usize, u8); 5] = [(8, 2), (16, 3), (32, 4), (48, 5), (64, 6)];

/// Whether `q` and `nb` are a CCM tag length and length field for a
/// block of `block` bytes.
pub(crate) fn check_ccm_params(q: usize, nb: usize, block: usize) -> Result<(), String> {
    ccm_flag(q, nb, false, block).map(|_| ())
}

fn ccm_flag(q: usize, nb: usize, has_message: bool, block: usize) -> Result<u8, String> {
    let code = CCM_TAG_CODES.iter().find(|(len, _)| *len == q && q <= block)
        .map(|(_, code)| *code)
        .ok_or_else(|| format!("A Kalyna CCM tag is 8, 16, 32, 48 or 64 bytes and no more \
                                than the block, {block}; not {q}."))?;
    // Eight at most, so the length and the flag always leave room for
    // nonce bytes in G1: the smallest block is sixteen.
    if nb == 0 || nb > 8 {
        return Err(format!("Kalyna CCM's length field is 1 to 8 bytes, not {nb}."));
    }
    Ok((u8::from(has_message) << 7) | (code << 4) | (nb as u8 - 1))
}

/// CCM's MAC, `q` bytes, before it is encrypted.
fn ccm_mac(cipher: &mut Kalyna, nonce: &[u8], aad: &[u8], message: &[u8], q: usize, nb: usize)
           -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    let flag = ccm_flag(q, nb, !message.is_empty(), block)?;
    if nb < 8 && (message.len() as u64) >> (8 * nb) != 0 {
        return Err(format!("A {nb}-byte length field cannot hold a message of {} bytes.",
                           message.len()));
    }
    let mut input = Vec::with_capacity(3 * block + aad.len() + message.len());
    // G1.
    input.extend_from_slice(&nonce[..block - nb - 1]);
    input.extend_from_slice(&(message.len() as u64).to_le_bytes()[..nb]);
    input.push(flag);
    // G2, cut so the associated data ends on a block boundary.
    let mut g2 = (aad.len() as u64).to_le_bytes().to_vec();
    g2.resize(block, 0);
    input.extend_from_slice(&g2[..block - aad.len() % block]);
    input.extend_from_slice(aad);
    input.extend_from_slice(message);
    if !message.len().is_multiple_of(block) {
        input.push(0x80);
        input.resize(input.len().next_multiple_of(block), 0);
    }
    let mut state = vec![0u8; block];
    for chunk in input.chunks_exact(block) {
        xor_into(&mut state, chunk);
        state = encrypt(cipher, &state);
    }
    state.truncate(q);
    Ok(state)
}

/// DSTU 7624's CCM: the ciphertext followed by the encrypted MAC of `q`
/// bytes (8, 16, 32, 48 or 64, no more than the block), with a length
/// field of `nb` bytes. The nonce is one block.
///
/// # Errors
/// A nonce that is not one block, a tag length or `nb` out of range, or
/// a message too long for `nb`.
pub fn ccm_encrypt(cipher: &mut Kalyna, nonce: &[u8], aad: &[u8], message: &[u8], q: usize,
                   nb: usize) -> Result<Vec<u8>, String> {
    require_one_block("CCM nonce", nonce, cipher.blocksize())?;
    let mac = ccm_mac(cipher, nonce, aad, message, q, nb)?;
    let mut out = message.to_vec();
    out.extend_from_slice(&mac);
    xor_into(&mut out, &keystream(cipher, nonce, message.len() + q)?);
    Ok(out)
}

/// The inverse of `ccm_encrypt`, from the ciphertext with its encrypted
/// MAC. Nothing is returned unless the MAC checks.
///
/// # Errors
/// A MAC that does not match, input shorter than the MAC, or the errors
/// of `ccm_encrypt`.
pub fn ccm_decrypt(cipher: &mut Kalyna, nonce: &[u8], aad: &[u8], sealed: &[u8], q: usize,
                   nb: usize) -> Result<Vec<u8>, String> {
    require_one_block("CCM nonce", nonce, cipher.blocksize())?;
    check_ccm_params(q, nb, cipher.blocksize())?;
    if sealed.len() < q {
        return Err(format!("A Kalyna CCM ciphertext ends in its {q}-byte MAC; this is {} \
                            bytes.", sealed.len()));
    }
    let mut opened = sealed.to_vec();
    xor_into(&mut opened, &keystream(cipher, nonce, sealed.len())?);
    let (message, mac) = opened.split_at(sealed.len() - q);
    if bytes_differ(&ccm_mac(cipher, nonce, aad, message, q, nb)?, mac) {
        return Err("The Kalyna CCM MAC does not match: the data or the associated data \
                    was altered, or the key or nonce is wrong.".to_string());
    }
    Ok(message.to_vec())
}

// --------------------------------------------------------------- XTS ----

/// The tweaks for `count` blocks: `2·E(IV)`, `4·E(IV)`, ...
fn tweaks(cipher: &mut Kalyna, iv: &[u8], count: usize) -> Vec<Vec<u8>> {
    let poly = reduction(cipher.blocksize());
    let mut t = limbs(&encrypt(cipher, iv));
    (0..count).map(|_| {
        double(&mut t, poly);
        bytes(&t)
    }).collect()
}

fn xts_block(cipher: &mut Kalyna, block: &[u8], tweak: &[u8], decrypting: bool) -> Vec<u8> {
    let mut x = block.to_vec();
    xor_into(&mut x, tweak);
    let mut out = Vec::with_capacity(x.len());
    if decrypting { cipher.block_decrypt(&x, &mut out) } else { cipher.block_encrypt(&x, &mut out) }
    xor_into(&mut out, tweak);
    out
}

fn xts(cipher: &mut Kalyna, iv: &[u8], data: &[u8], decrypting: bool) -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    require_one_block("XTS IV", iv, block)?;
    if data.len() < block {
        return Err(format!("Kalyna's XTS needs at least one whole block, {block} bytes; got {}.",
                           data.len()));
    }
    let whole = data.len() / block;
    let tail = data.len() % block;
    let t = tweaks(cipher, iv, whole + 1);
    let mut out = Vec::with_capacity(data.len());
    let plain_blocks = if tail == 0 { whole } else { whole - 1 };
    for (i, chunk) in data.chunks_exact(block).take(plain_blocks).enumerate() {
        out.extend_from_slice(&xts_block(cipher, chunk, &t[i], decrypting));
    }
    if tail != 0 {
        // The last whole block and the short one. Encrypting, the whole
        // block takes the earlier tweak and the combined block the later;
        // decrypting meets them in the other order.
        let last = &data[(whole - 1) * block..whole * block];
        let short = &data[whole * block..];
        let (first_tweak, second_tweak) = if decrypting {
            (&t[whole], &t[whole - 1])
        } else {
            (&t[whole - 1], &t[whole])
        };
        let lent = xts_block(cipher, last, first_tweak, decrypting);
        let mut combined = short.to_vec();
        combined.extend_from_slice(&lent[tail..]);
        out.extend_from_slice(&xts_block(cipher, &combined, second_tweak, decrypting));
        out.extend_from_slice(&lent[..tail]);
    }
    Ok(out)
}

/// DSTU 7624's XTS, encrypting. The IV is one block and the data at
/// least one block; a short last block is handled by ciphertext stealing.
///
/// # Errors
/// An IV that is not one block, or data shorter than one block.
pub fn xts_encrypt(cipher: &mut Kalyna, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    xts(cipher, iv, data, false)
}

/// The inverse of `xts_encrypt`.
///
/// # Errors
/// As `xts_encrypt`.
pub fn xts_decrypt(cipher: &mut Kalyna, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    xts(cipher, iv, data, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `multiply` against repeated doubling: `a · x^k` both ways, and
    /// the product commutes, in all three fields.
    #[test]
    fn test_the_field() {
        for bytes_len in [16usize, 32, 64] {
            let poly = reduction(bytes_len);
            let a: Vec<u64> = (0..bytes_len / 8).map(|i| 0x9e37_79b9_7f4a_7c15u64
                                                          .wrapping_mul(i as u64 + 1)).collect();
            let b: Vec<u64> = (0..bytes_len / 8).map(|i| 0xc2b2_ae3d_27d4_eb4fu64
                                                          .rotate_left(i as u32 * 7)).collect();
            assert_eq!(multiply(&a, &b, poly), multiply(&b, &a, poly));
            for k in [0usize, 1, 63, 64, 65, 8 * bytes_len - 1] {
                let mut xk = vec![0u64; bytes_len / 8];
                xk[k / 64] = 1 << (k % 64);
                let mut doubled = a.clone();
                for _ in 0..k {
                    double(&mut doubled, poly);
                }
                assert_eq!(multiply(&a, &xk, poly), doubled, "{bytes_len} {k}");
            }
            // x^n reduces to the polynomial's low terms.
            let mut top = vec![0u64; bytes_len / 8];
            top[bytes_len / 8 - 1] = 1 << 63;
            double(&mut top, poly);
            let mut low = vec![0u64; bytes_len / 8];
            low[0] = poly;
            assert_eq!(top, low);
        }
    }

    #[test]
    fn test_ccm_refuses_tag_lengths_without_a_code() {
        let mut c = Kalyna::new(16, &[1u8; 16]).unwrap();
        for q in [0usize, 4, 12, 15, 17, 24, 32] {
            assert!(ccm_encrypt(&mut c, &[0u8; 16], b"a", b"m", q, 4).is_err(), "{q}");
        }
        assert!(ccm_encrypt(&mut c, &[0u8; 16], b"a", b"m", 8, 4).is_ok());
        assert!(ccm_encrypt(&mut c, &[0u8; 16], b"a", b"m", 16, 4).is_ok());
        // Nb + 1 bytes of G1 are length and flag; the rest is nonce.
        assert!(ccm_encrypt(&mut c, &[0u8; 16], b"a", b"m", 16, 0).is_err());
        assert!(ccm_encrypt(&mut c, &[0u8; 16], b"a", b"m", 16, 9).is_err());
        // A one-byte length field holds lengths below 256.
        assert!(ccm_encrypt(&mut c, &[0u8; 16], b"a", &[0u8; 255], 16, 1).is_ok());
        assert!(ccm_encrypt(&mut c, &[0u8; 16], b"a", &[0u8; 256], 16, 1).is_err());
    }

    /// Input shorter than the MAC is refused, not split at a negative
    /// offset.
    #[test]
    fn test_ccm_refuses_input_shorter_than_its_mac() {
        let mut c = Kalyna::new(32, &[1u8; 32]).unwrap();
        let sealed = ccm_encrypt(&mut c, &[2u8; 32], b"", b"", 16, 4).unwrap();
        assert_eq!(sealed.len(), 16);
        assert_eq!(ccm_decrypt(&mut c, &[2u8; 32], b"", &sealed, 16, 4).unwrap(), b"");
        for len in 0..16 {
            let refusal = ccm_decrypt(&mut c, &[2u8; 32], b"", &sealed[..len], 16, 4).unwrap_err();
            assert!(refusal.contains("ends in its 16-byte MAC"), "{len}: {refusal}");
        }
    }

    #[test]
    fn test_xts_refuses_less_than_a_block() {
        let mut c = Kalyna::new(32, &[1u8; 32]).unwrap();
        for len in 0..32 {
            assert!(xts_encrypt(&mut c, &[0u8; 32], &vec![0u8; len]).is_err(), "{len}");
            assert!(xts_decrypt(&mut c, &[0u8; 32], &vec![0u8; len]).is_err(), "{len}");
        }
        assert!(xts_encrypt(&mut c, &[0u8; 16], &[0u8; 32]).is_err());
    }
}
