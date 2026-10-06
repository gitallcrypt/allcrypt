/*
scrypt, RFC 7914.

PBKDF2's cost is time and nothing else, which is why it loses so badly to
an attacker with hardware: each guess needs a few hundred bytes of state,
so a GPU runs thousands in parallel for the price of one. scrypt's answer
is to make each guess need **memory** - `128 * N * r` bytes of it, held
for the whole computation - so parallelism costs silicon area rather than
being free.

The construction, outside in:

    scrypt(P, S, N, r, p, dkLen)
      B        = PBKDF2-HMAC-SHA256(P, S, 1, p * 128 * r)
      B[i]     = ROMix(B[i], N)           for each of the p blocks
      DK       = PBKDF2-HMAC-SHA256(P, B, 1, dkLen)

    ROMix(B, N)                            -- the memory-hard part
      V[i]     = X;  X = BlockMix(X)       for i in 0..N     (fill)
      j        = Integerify(X) mod N
      X        = BlockMix(X xor V[j])      N times            (walk)

    BlockMix(B)                            -- 2r blocks of 64 bytes
      X        = B[2r - 1]
      X        = Salsa20/8_core(X xor B[i]) for each i, output interleaved

The two PBKDF2 calls use **one iteration**. That is not a mistake and not
a weak parameter: all of scrypt's cost is in ROMix, and the PBKDF2 calls
are there to spread the password over the buffer and to squeeze the
result back down. Raising the iteration count there would add cost an
attacker pays once per guess *and* that parallelises freely, which is
precisely what scrypt exists to avoid.

## The two places this goes quietly wrong

**BlockMix's output is interleaved, not concatenated.** The 2r outputs
come out as `Y[0], Y[2], .., Y[2r-2], Y[1], Y[3], .., Y[2r-1]` - the even
ones then the odd ones. For `r = 1` there are two blocks and the
interleave is the identity, so an implementation that concatenates is
correct for `r = 1` and wrong for every other `r`. RFC 7914's own first
test vector uses `r = 1`.

**Integerify reads the last 64 byte block, little endian.** Not the first,
not the whole buffer, and not big endian. A wrong reading gives a
different but perfectly deterministic walk through V, so the result is
stable, reproducible, and matches nobody.

Both are pinned below against the RFC's intermediate vectors rather than
only against the final answer, because a final-answer test tells you that
something is wrong without telling you which of the two it is.
*/

use crate::hash_functions::sha2;
use crate::kdf::password::pbkdf2;
use crate::stream_ciphers::salsa20;

/// scrypt, RFC 7914 section 6.
///
/// `n` is the CPU/memory cost and **must be a power of two greater than
/// one**; `r` is the block size factor and `p` the parallelisation
/// factor. Memory used is `128 * n * r` bytes, plus `128 * r * p` for
/// the working buffer.
///
/// # Errors
/// A non-power-of-two `n`, a zero parameter, a `p` past the RFC's
/// ceiling, or a request whose memory would not fit in `usize`.
pub fn scrypt(password: &[u8], salt: &[u8], n: u64, r: u32, p: u32, length: usize)
              -> Result<Vec<u8>, String> {
    if n <= 1 || !n.is_power_of_two() {
        return Err(format!("scrypt's N is a power of two greater than 1; \
                            {} is not.", n));
    }
    if r == 0 || p == 0 {
        return Err("scrypt's r and p must both be at least 1.".to_string());
    }
    // RFC 7914 section 6: p <= ((2^32 - 1) * 32) / (128 * r). Checked
    // because past it the final PBKDF2 call would be asked for more
    // than its counter can address, which is a silent repeat rather
    // than an error.
    let ceiling = ((u32::MAX as u64) * 32) / (128 * r as u64);
    if p as u64 > ceiling {
        return Err(format!("scrypt with r={} allows p up to {}; {} is too large.",
                           r, ceiling, p));
    }

    let block_bytes = 128usize
        .checked_mul(r as usize)
        .ok_or_else(|| format!("scrypt with r={} needs more memory than this \
                                machine can address.", r))?;
    let buffer_bytes = block_bytes
        .checked_mul(p as usize)
        .ok_or_else(|| format!("scrypt with r={} and p={} needs more memory than \
                                this machine can address.", r, p))?;
    let n_usize = usize::try_from(n)
        .map_err(|_| format!("scrypt with N={} needs more memory than this \
                              machine can address.", n))?;
    block_bytes.checked_mul(n_usize)
        .ok_or_else(|| format!("scrypt with N={} and r={} needs more memory than \
                                this machine can address.", n, r))?;

    // One iteration, deliberately - see the note above.
    let mut b = pbkdf2(sha2::SHA256::new(&[]), password, salt, 1, buffer_bytes)?;

    for chunk in b.chunks_mut(block_bytes) {
        romix(chunk, n_usize, r as usize);
    }

    pbkdf2(sha2::SHA256::new(&[]), password, &b, 1, length)
}

/// ROMix, RFC 7914 section 5. In place, over one `128 * r` byte block.
///
/// The memory-hard core: fill `V` with `N` successive BlockMix states,
/// then take `N` more steps, each XORing in a element of `V` chosen by
/// the current state. An attacker who keeps less than the whole of `V`
/// has to recompute, and the recomputation is serial.
fn romix(block: &mut [u8], n: usize, r: usize) {
    let block_bytes = 128 * r;
    let mut x = block.to_vec();
    let mut scratch = vec![0u8; block_bytes];

    // Fill. `V` is the whole memory cost, and it is why scrypt is
    // scrypt.
    let mut v = vec![0u8; block_bytes * n];
    for index in 0..n {
        v[index * block_bytes..(index + 1) * block_bytes].copy_from_slice(&x);
        block_mix(&x, &mut scratch, r);
        x.copy_from_slice(&scratch);
    }

    // Walk.
    for _ in 0..n {
        // `n` is a power of two, so `mod n` is a mask - which is also
        // why `n` has to be one.
        let j = integerify(&x, r) as usize & (n - 1);
        let at = j * block_bytes;
        for (byte, chosen) in x.iter_mut().zip(&v[at..at + block_bytes]) {
            *byte ^= chosen;
        }
        block_mix(&x, &mut scratch, r);
        x.copy_from_slice(&scratch);
    }

    block.copy_from_slice(&x);
}

/// BlockMix, RFC 7914 section 4.
///
/// **The output is interleaved**: the even numbered results first, then
/// the odd numbered ones. With `r = 1` that is the identity, so an
/// implementation that concatenates passes the RFC's first test vector
/// and fails every other `r`.
fn block_mix(input: &[u8], output: &mut [u8], r: usize) {
    let blocks = 2 * r;
    let mut x = [0u8; 64];
    x.copy_from_slice(&input[(blocks - 1) * 64..blocks * 64]);

    for index in 0..blocks {
        for (byte, next) in x.iter_mut().zip(&input[index * 64..(index + 1) * 64]) {
            *byte ^= next;
        }
        x = salsa20::core(&x, 8);
        // Even results go to the front half, odd ones to the back.
        let at = if index.is_multiple_of(2) {
            (index / 2) * 64
        } else {
            (r + index / 2) * 64
        };
        output[at..at + 64].copy_from_slice(&x);
    }
}

/// Integerify, RFC 7914 section 5: the **last** 64 byte block read as a
/// little endian integer.
///
/// Only the low 64 bits are taken, which is all that `mod N` can ever
/// use - N is a power of two no larger than a `usize`. Reading the
/// first block instead, or reading big endian, gives a different walk
/// through V that is every bit as deterministic and matches nothing.
fn integerify(block: &[u8], r: usize) -> u64 {
    let at = (2 * r - 1) * 64;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&block[at..at + 8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 7914 section 9: scryptBlockMix with r=1.
    ///
    /// The RFC gives the input as two 64 byte blocks and the output as
    /// two more. r=1 here, so this does **not** exercise the
    /// interleave - see the test below for that.
    #[test]
    fn test_rfc7914_block_mix() {
        let input = unhex(BLOCK_MIX_INPUT);
        let expected = unhex(BLOCK_MIX_OUTPUT);
        let mut output = vec![0u8; input.len()];
        block_mix(&input, &mut output, 1);
        assert_eq!(hex(&output), hex(&expected));
    }

    /// RFC 7914 section 10: scryptROMix with N=16, r=1.
    #[test]
    fn test_rfc7914_romix() {
        let mut block = unhex(ROMIX_INPUT);
        let expected = unhex(ROMIX_OUTPUT);
        romix(&mut block, 16, 1);
        assert_eq!(hex(&block), hex(&expected));
    }

    /// RFC 7914 section 12, the whole function.
    ///
    /// The last vector (N=1048576) is deliberately left out: it wants a
    /// gigabyte of memory and two minutes, and exercises no path the
    /// others do not - N only changes how many times the same two
    /// loops run.
    #[test]
    fn test_rfc7914_scrypt() {
        assert_eq!(hex(&scrypt(b"", b"", 16, 1, 1, 64).unwrap()), SCRYPT_EMPTY);
        assert_eq!(hex(&scrypt(b"password", b"NaCl", 1024, 8, 16, 64).unwrap()),
                   SCRYPT_NACL);
        assert_eq!(hex(&scrypt(b"pleaseletmein", b"SodiumChloride",
                               16384, 8, 1, 64).unwrap()),
                   SCRYPT_SODIUM);
    }

    /// **The interleave, which r=1 cannot see.**
    ///
    /// With r=1 BlockMix has two outputs and "evens then odds" is the
    /// identity, so every RFC vector above passes against an
    /// implementation that concatenates. This pins the property
    /// directly at r=2: the second output block must be the *fourth*
    /// Salsa call's result, not the second's.
    #[test]
    fn test_the_block_mix_output_is_interleaved() {
        let r = 2;
        let input: Vec<u8> = (0..128 * r).map(|i| (i % 251) as u8).collect();
        let mut output = vec![0u8; 128 * r];
        block_mix(&input, &mut output, r);

        // Recompute the four Salsa outputs in order, by hand.
        let mut x = [0u8; 64];
        x.copy_from_slice(&input[(2 * r - 1) * 64..]);
        let mut sequence = Vec::new();
        for index in 0..2 * r {
            for (byte, next) in x.iter_mut()
                    .zip(&input[index * 64..(index + 1) * 64]) {
                *byte ^= next;
            }
            x = salsa20::core(&x, 8);
            sequence.push(x.to_vec());
        }

        // Interleaved: Y0, Y2 | Y1, Y3.
        let mut want = Vec::new();
        want.extend_from_slice(&sequence[0]);
        want.extend_from_slice(&sequence[2]);
        want.extend_from_slice(&sequence[1]);
        want.extend_from_slice(&sequence[3]);
        assert_eq!(hex(&output), hex(&want),
                   "BlockMix did not interleave its output");

        // And the concatenated version must differ, or the assertion
        // above proves nothing.
        let mut concatenated = Vec::new();
        for block in &sequence {
            concatenated.extend_from_slice(block);
        }
        assert_ne!(hex(&output), hex(&concatenated));
    }

    /// Integerify reads the last block, little endian.
    ///
    /// Three wrong readings - the first block, big endian, the whole
    /// buffer - each give a deterministic walk through V and a stable
    /// wrong answer. This pins the right one directly.
    #[test]
    fn test_integerify_reads_the_last_block_little_endian() {
        let r = 2;
        let mut block = vec![0u8; 128 * r];
        // Put a recognisable value at the start of the last 64 byte
        // block and something different at the front.
        block[..8].copy_from_slice(&0x1111_1111_1111_1111u64.to_le_bytes());
        let at = (2 * r - 1) * 64;
        block[at..at + 8].copy_from_slice(&0x0807_0605_0403_0201u64.to_le_bytes());

        assert_eq!(integerify(&block, r), 0x0807_0605_0403_0201,
                   "integerify did not read the last block little endian");
        assert_ne!(integerify(&block, r), 0x0102_0304_0506_0708,
                   "integerify read big endian");
        assert_ne!(integerify(&block, r), 0x1111_1111_1111_1111,
                   "integerify read the first block");
    }

    /// Every parameter changes the answer.
    #[test]
    fn test_every_parameter_reaches_the_result() {
        let base = scrypt(b"pw", b"salt", 16, 2, 2, 32).unwrap();
        assert_ne!(base, scrypt(b"PW", b"salt", 16, 2, 2, 32).unwrap());
        assert_ne!(base, scrypt(b"pw", b"pepper", 16, 2, 2, 32).unwrap());
        assert_ne!(base, scrypt(b"pw", b"salt", 32, 2, 2, 32).unwrap(), "N ignored");
        assert_ne!(base, scrypt(b"pw", b"salt", 16, 3, 2, 32).unwrap(), "r ignored");
        assert_ne!(base, scrypt(b"pw", b"salt", 16, 2, 3, 32).unwrap(), "p ignored");
    }

    /// Asking for more bytes extends what was there, since the final
    /// step is one PBKDF2 call.
    #[test]
    fn test_a_longer_request_extends_a_shorter_one() {
        let long = scrypt(b"pw", b"salt", 16, 1, 1, 100).unwrap();
        for length in [1usize, 31, 32, 33, 64, 99] {
            let short = scrypt(b"pw", b"salt", 16, 1, 1, length).unwrap();
            assert_eq!(&long[..length], &short[..]);
        }
    }

    #[test]
    fn test_bad_parameters_are_errors() {
        assert!(scrypt(b"", b"", 0, 1, 1, 32).is_err(), "N=0");
        assert!(scrypt(b"", b"", 1, 1, 1, 32).is_err(), "N=1");
        assert!(scrypt(b"", b"", 3, 1, 1, 32).is_err(), "N not a power of two");
        assert!(scrypt(b"", b"", 1000, 1, 1, 32).is_err(), "N not a power of two");
        assert!(scrypt(b"", b"", 16, 0, 1, 32).is_err(), "r=0");
        assert!(scrypt(b"", b"", 16, 1, 0, 32).is_err(), "p=0");
        assert!(scrypt(b"", b"", 16, 1, u32::MAX, 32).is_err(), "p past the ceiling");
    }

    // The vectors, read out of RFC 7914 rather than typed.
    const BLOCK_MIX_INPUT: &str = "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89";
    const BLOCK_MIX_OUTPUT: &str = "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f8120edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b77d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425";
    const ROMIX_INPUT: &str = "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89";
    const ROMIX_OUTPUT: &str = "79ccc193629debca047f0b70604bf6b62ce3dd4a9626e355fafc6198e6ea2b46d58413673b99b029d665c357601fb426a0b2f4bba200ee9f0a43d19b571a9c71ef1142e65d5a266fddca832ce59faa7cac0b9cf1be2bffca300d01ee387619c4ae12fd4438f203a0e4e1c47ec314861f4e9087cb33396a6873e8f9d2539a4b8e";
    const SCRYPT_EMPTY: &str = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
    const SCRYPT_NACL: &str = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";
    const SCRYPT_SODIUM: &str = "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887";
}
