/*
Keccak: SHA-3, SHAKE, and the pre-standard Keccak-256 that Ethereum uses.

FIPS 202. One permutation, `Keccak-f[1600]`, wrapped in a sponge: absorb
the message `rate` bytes at a time, permuting between blocks; then squeeze
output the same way. The `capacity` - the part of the state the message
never touches directly - is what the security level rests on, and it is
always twice the digest length.

    SHA3-224   rate 144   capacity 56    SHAKE128   rate 168   capacity 32
    SHA3-256   rate 136   capacity 64    SHAKE256   rate 136   capacity 64
    SHA3-384   rate 104   capacity 96
    SHA3-512   rate  72   capacity 128

## The padding byte is the whole difference between three functions

The sponge is identical; the *domain separation* is not. Keccak pads with
`0x01`, SHA-3 with `0x06`, and the SHAKEs with `0x1f`:

  * **Keccak**, the 2012 submission: `0x01`. This is what Ethereum
    calls `keccak256` and what every Ethereum address, transaction hash
    and Solidity `keccak256()` is built on.
  * **SHA-3**, FIPS 202 as standardised in 2015: `0x06`, which is
    Keccak's `0x01` with the two bits `01` appended for domain
    separation.
  * **SHAKE**, the extendable output functions: `0x1f`.

**One byte.** `SHA3-256("")` and `Keccak-256("")` differ in every bit of
their output and in nothing else about how they are computed, and almost
no library ships both - which is exactly the gap this library exists to
fill. Anyone who has ever fed a SHA-3 library to an Ethereum address and
got a wrong answer has met this byte.

## What the sponge is not

It is not Merkle-Damgard. There is no length field, no block counter and
no initialisation vector - the state starts at zero and the only thing
appended to the message is the padding. So the length-extension attacks
that SHA-2 needs HMAC to avoid do not apply here, and `KMAC` (SP 800-185)
exists because a keyed SHAKE is already a MAC.
*/

use crate::hash_functions::HashFunction;

/// The round constants of iota, FIPS 202 section 3.2.5.
///
/// Generated from the linear feedback shift register the standard
/// defines rather than transcribed: twenty-four 64 bit constants is
/// twenty-four chances to mistype one, and the definition is eight
/// lines.
const fn round_constants() -> [u64; 24] {
    let mut rc = [0u64; 24];
    // The LFSR of FIPS 202 Algorithm 5, `rc(t)`, which is the low bit
    // of a byte-wide register stepped with the polynomial
    // x^8 + x^6 + x^5 + x^4 + 1.
    let mut lfsr: u8 = 0x01;
    let mut round = 0;
    while round < 24 {
        let mut constant = 0u64;
        let mut j = 0;
        while j < 7 {
            // Bit 2^j - 1 of the constant takes the LFSR's output.
            let bit = (lfsr & 1) as u64;
            constant |= bit << ((1usize << j) - 1);
            // Step: the feedback is the outgoing bit.
            let feedback = lfsr & 0x80;
            lfsr <<= 1;
            if feedback != 0 {
                lfsr ^= 0x71;
            }
            j += 1;
        }
        rc[round] = constant;
        round += 1;
    }
    rc
}

const ROUND_CONSTANTS: [u64; 24] = round_constants();

/// The rho rotation offsets, by (x, y) lane.
///
/// Also generated: the standard defines them by walking the lanes in a
/// fixed spiral and taking triangular numbers, which is short enough to
/// write and much easier to check than twenty-five numbers.
const fn rho_offsets() -> [u32; 25] {
    let mut offsets = [0u32; 25];
    let (mut x, mut y) = (1usize, 0usize);
    let mut t = 0usize;
    while t < 24 {
        offsets[x + 5 * y] = (((t + 1) * (t + 2) / 2) % 64) as u32;
        // (x, y) = (y, 2x + 3y) mod 5, the spiral of FIPS 202
        // Algorithm 2.
        let next_x = y;
        let next_y = (2 * x + 3 * y) % 5;
        x = next_x;
        y = next_y;
        t += 1;
    }
    offsets
}

const RHO: [u32; 25] = rho_offsets();

/// `Keccak-f[1600]`: twenty-four rounds of theta, rho, pi, chi, iota.
fn permute(state: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        // theta: each lane takes the parity of two neighbouring
        // columns, one of them rotated by one bit.
        let mut parity = [0u64; 5];
        for x in 0..5 {
            parity[x] = state[x] ^ state[x + 5] ^ state[x + 10]
                ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        // rho and pi together: rotate each lane and move it.
        let mut moved = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                // pi: (x, y) -> (y, 2x + 3y).
                moved[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }

        // chi: the only non-linear step, one row at a time.
        for y in 0..5 {
            let row: [u64; 5] = core::array::from_fn(|x| moved[x + 5 * y]);
            for x in 0..5 {
                state[x + 5 * y] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }

        // iota: one lane, one constant, which is what breaks the
        // symmetry the other four steps preserve.
        state[0] ^= round_constant;
    }
}

/// A Keccak sponge.
///
/// One type for all of SHA-3, SHAKE and raw Keccak, because they differ
/// only in `rate` and in one padding byte.
#[derive(Clone)]
pub struct Keccak {
    state: [u64; 25],
    /// Bytes absorbed into the current block.
    filled: usize,
    /// The sponge's rate in bytes: `200 - capacity`.
    rate: usize,
    /// `0x01` for Keccak, `0x06` for SHA-3, `0x1f` for SHAKE.
    padding: u8,
    /// Default output length in bytes. For the SHAKEs this is only a
    /// default - they will produce any length.
    digest_len: usize,
    name: &'static str,
}

impl Keccak {
    /// The most bytes one `squeeze` will produce: 1 GiB.
    ///
    /// A sponge has no maximum of its own, so this is the documented
    /// cap. The output is allocated before the first permutation, and
    /// a length that came from a caller - `api::shake` from Python
    /// takes one - would otherwise reach the allocator unchecked, where
    /// failure is an abort rather than an error.
    pub const MAX_SQUEEZE: usize = 1 << 30;

    /// SHA3-224/256/384/512, by output length in bytes.
    pub fn sha3(digest_len: usize) -> Result<Keccak, String> {
        let name = match digest_len {
            28 => "sha3_224",
            32 => "sha3_256",
            48 => "sha3_384",
            64 => "sha3_512",
            other => return Err(format!(
                "SHA-3 comes in 28, 32, 48 and 64 byte outputs; {} is not one.",
                other)),
        };
        // The capacity is always twice the digest length, which is what
        // fixes the rate.
        Ok(Keccak::with(200 - 2 * digest_len, 0x06, digest_len, name))
    }

    /// SHAKE128 or SHAKE256, at any output length.
    ///
    /// The number names the *security level*, not the output: SHAKE128
    /// will give you a thousand bytes and they are all as good as 128
    /// bits of security allows.
    pub fn shake(security_bits: usize, digest_len: usize) -> Result<Keccak, String> {
        let (rate, name) = match security_bits {
            128 => (168, "shake_128"),
            256 => (136, "shake_256"),
            other => return Err(format!(
                "SHAKE comes at 128 and 256 bit security; {} is not one.", other)),
        };
        if digest_len > Keccak::MAX_SQUEEZE {
            return Err(format!(
                "A SHAKE output is at most {} bytes here; asked for {}.",
                Keccak::MAX_SQUEEZE, digest_len));
        }
        Ok(Keccak::with(rate, 0x1f, digest_len, name))
    }

    /// The **pre-standard** Keccak, with the original `0x01` padding.
    ///
    /// This is what Ethereum calls `keccak256`: every address, every
    /// transaction hash and Solidity's `keccak256()` are this and not
    /// SHA-3. The two differ in one byte of padding and in every bit of
    /// their output, and almost no library ships both.
    #[allow(clippy::self_named_constructors)]
    pub fn keccak(digest_len: usize) -> Result<Keccak, String> {
        if digest_len == 0 || digest_len > 64 {
            return Err(format!("A Keccak digest is 1 to 64 bytes; {} is not.",
                               digest_len));
        }
        let name = match digest_len {
            28 => "keccak_224",
            32 => "keccak_256",
            48 => "keccak_384",
            64 => "keccak_512",
            _ => "keccak",
        };
        Ok(Keccak::with(200 - 2 * digest_len, 0x01, digest_len, name))
    }

    fn with(rate: usize, padding: u8, digest_len: usize, name: &'static str) -> Keccak {
        Keccak { state: [0u64; 25], filled: 0, rate, padding, digest_len, name }
    }

    /// Absorb one byte, permuting when the block fills.
    #[inline]
    fn absorb(&mut self, byte: u8) {
        let lane = self.filled / 8;
        let shift = 8 * (self.filled % 8);
        self.state[lane] ^= (byte as u64) << shift;
        self.filled += 1;
        if self.filled == self.rate {
            permute(&mut self.state);
            self.filled = 0;
        }
    }

    /// Squeeze `length` bytes, which is the whole of SHAKE and the tail
    /// of every SHA-3.
    ///
    /// Repeatable and non-destructive, like `digest`: it works on a
    /// copy, so a caller may keep updating afterwards.
    ///
    /// # Panics
    /// `length` above `MAX_SQUEEZE`, or an output buffer the allocator
    /// refuses. Every caller in this library passes a length fixed by
    /// its algorithm or already checked by `shake`; a length from
    /// outside goes through `try_squeeze`.
    pub fn squeeze(&self, length: usize) -> Vec<u8> {
        match self.try_squeeze(length) {
            Ok(out) => out,
            Err(reason) => panic!("{reason}"),
        }
    }

    /// `squeeze`, with the cap and the allocation reported as an error.
    pub fn try_squeeze(&self, length: usize) -> Result<Vec<u8>, String> {
        if length > Keccak::MAX_SQUEEZE {
            return Err(format!(
                "A sponge output is at most {} bytes here; asked for {}.",
                Keccak::MAX_SQUEEZE, length));
        }
        let mut out = Vec::new();
        out.try_reserve_exact(length).map_err(|_| format!(
            "Could not allocate {} bytes for the sponge output.", length))?;
        let mut sponge = self.clone();

        // Pad: the domain byte at the start of the padding and `0x80`
        // at the end of the block. When the two land on the same byte
        // they are ORed together, which is the case nothing else
        // covers.
        let mut padded = vec![0u8; sponge.rate - sponge.filled];
        padded[0] = sponge.padding;
        let last = padded.len() - 1;
        padded[last] |= 0x80;
        for byte in padded {
            sponge.absorb(byte);
        }

        while out.len() < length {
            let take = core::cmp::min(sponge.rate, length - out.len());
            for index in 0..take {
                out.push((sponge.state[index / 8] >> (8 * (index % 8))) as u8);
            }
            if out.len() < length {
                permute(&mut sponge.state);
            }
        }
        Ok(out)
    }
}

impl HashFunction for Keccak {
    /// The catalogue name, with the length spelled out where it is not
    /// the one the bare name means, so `AnyHash::new` reads it back as
    /// this same function.
    fn name(&self) -> String {
        let bits = self.digest_len * 8;
        match self.name {
            "keccak" => format!("keccak_{bits}"),
            "shake_128" if self.digest_len != 16 => format!("shake_128_{bits}"),
            "shake_256" if self.digest_len != 32 => format!("shake_256_{bits}"),
            other => other.to_string(),
        }
    }

    fn digest_len(&self) -> usize { self.digest_len }

    /// The sponge's rate, which is what HMAC would need.
    ///
    /// HMAC over SHA-3 is defined and legal, and also unnecessary: the
    /// sponge is not vulnerable to length extension, so a keyed SHAKE
    /// is already a MAC. `KMAC` (SP 800-185) is the standard way.
    fn block_size(&self) -> usize { self.rate }

    /// Bytes one at a time up to a lane boundary, then whole 64 bit lanes,
    /// then bytes again. Byte `i` of the block is byte `i % 8` of lane
    /// `i / 8`, little endian, either way.
    ///
    /// Only when the rate is a whole number of lanes, which every SHA-3
    /// and SHAKE rate is. `keccak(n)` takes any digest length, and for one
    /// that is not a multiple of four the rate ends mid-lane: a lane step
    /// would run past it without permuting.
    fn update(&mut self, mut input: &[u8]) {
        if !self.rate.is_multiple_of(8) {
            for byte in input {
                self.absorb(*byte);
            }
            return;
        }
        while !input.is_empty() && !self.filled.is_multiple_of(8) {
            self.absorb(input[0]);
            input = &input[1..];
        }
        let mut lanes = input.chunks_exact(8);
        for lane in &mut lanes {
            self.state[self.filled / 8] ^= u64::from_le_bytes(lane.try_into().unwrap());
            self.filled += 8;
            if self.filled == self.rate {
                permute(&mut self.state);
                self.filled = 0;
            }
        }
        for byte in lanes.remainder() {
            self.absorb(*byte);
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        self.squeeze(self.digest_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Input fed whole, a byte at a time and in ragged pieces gives one
    /// digest, for rates that are and are not whole lanes.
    #[test]
    fn test_every_way_of_feeding_agrees() {
        let message: Vec<u8> = (0..1000u32).map(|i| (i * 31 + 7) as u8).collect();
        for digest_len in [1usize, 3, 28, 31, 32, 48, 64] {
            let mut whole = Keccak::keccak(digest_len).unwrap();
            whole.update(&message);
            let want = whole.digest();
            let mut bytes = Keccak::keccak(digest_len).unwrap();
            for b in &message {
                bytes.absorb(*b);
            }
            assert_eq!(bytes.digest(), want, "byte at a time, {digest_len}");
            for piece in [1usize, 5, 8, 13, 64, 199, 200] {
                let mut ragged = Keccak::keccak(digest_len).unwrap();
                for chunk in message.chunks(piece) {
                    ragged.update(chunk);
                }
                assert_eq!(ragged.digest(), want, "{digest_len} in pieces of {piece}");
            }
        }
    }

    /// FIPS 202's published digests of the empty string, all four
    /// sizes.
    #[test]
    fn test_sha3_of_the_empty_string() {
        let cases = [
            (28, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
            (32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (48, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a\
                  c3713831264adb47fb6bd1e058d5f004"),
            (64, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
                  15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
        ];
        for (length, expected) in cases {
            let mut hash = Keccak::sha3(length).unwrap();
            assert_eq!(hex(&hash.digest()), expected, "SHA3-{}", length * 8);
        }
    }

    /// SHA3-256 of "abc", the other vector everybody quotes.
    #[test]
    fn test_sha3_256_of_abc() {
        let mut hash = Keccak::sha3(32).unwrap();
        hash.update(b"abc");
        assert_eq!(hex(&hash.digest()),
                   "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    /// **The padding byte, which is the whole difference.**
    ///
    /// SHA3-256 and Keccak-256 of the same input differ in every bit
    /// and in nothing else about how they are computed. This is the
    /// case that almost no library covers, and the reason an Ethereum
    /// address fed through a SHA-3 library comes out wrong.
    #[test]
    fn test_keccak_256_is_not_sha3_256() {
        let mut keccak = Keccak::keccak(32).unwrap();
        // The pre-standard Keccak-256 of the empty string, which is the
        // hash of an empty Ethereum account's code.
        assert_eq!(hex(&keccak.digest()),
                   "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

        let mut sha3 = Keccak::sha3(32).unwrap();
        assert_ne!(hex(&keccak.digest()), hex(&sha3.digest()));

        // And the difference really is one byte of padding.
        assert_eq!(keccak.padding, 0x01);
        assert_eq!(sha3.padding, 0x06);
        assert_eq!(keccak.rate, sha3.rate);
    }

    /// Keccak-256 of "abc", which every Ethereum library agrees on.
    #[test]
    fn test_keccak_256_of_abc() {
        let mut hash = Keccak::keccak(32).unwrap();
        hash.update(b"abc");
        assert_eq!(hex(&hash.digest()),
                   "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    }

    /// **An external check on the padding that comes from outside any
    /// library on this machine.**
    ///
    /// An Ethereum function selector is the first four bytes of
    /// `keccak256` of the function's signature, and they are published
    /// everywhere: `transfer(address,uint256)` is `a9059cbb`, which is
    /// in the ERC-20 standard, in every block explorer and in the
    /// bytecode of several million deployed contracts.
    ///
    /// SHA-3 of the same string gives something else entirely. So this
    /// pins the `0x01` padding against a number that was fixed by
    /// consensus years ago and that nothing here could have influenced
    /// — which is stronger evidence than a vector copied from a
    /// document.
    #[test]
    fn test_an_ethereum_function_selector() {
        let mut hash = Keccak::keccak(32).unwrap();
        hash.update(b"transfer(address,uint256)");
        assert_eq!(&hex(&hash.digest())[..8], "a9059cbb");

        let mut hash = Keccak::keccak(32).unwrap();
        hash.update(b"balanceOf(address)");
        assert_eq!(&hex(&hash.digest())[..8], "70a08231");

        // And SHA-3 of the same string is not the selector, which is
        // the mistake this whole distinction exists to prevent.
        let mut sha3 = Keccak::sha3(32).unwrap();
        sha3.update(b"transfer(address,uint256)");
        assert_ne!(&hex(&sha3.digest())[..8], "a9059cbb");
    }

    /// SHAKE's published outputs, and the property that makes it an
    /// extendable output function: a longer request **extends** a
    /// shorter one rather than replacing it.
    #[test]
    fn test_shake_extends_rather_than_replaces() {
        let shake = Keccak::shake(128, 32).unwrap();
        assert_eq!(hex(&shake.squeeze(32)),
                   "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");

        let long = shake.squeeze(1000);
        for length in [1usize, 16, 32, 167, 168, 169, 500, 999] {
            assert_eq!(&shake.squeeze(length)[..], &long[..length],
                       "squeezing {} bytes was not a prefix of squeezing 1000",
                       length);
        }

        let shake256 = Keccak::shake(256, 32).unwrap();
        assert_eq!(hex(&shake256.squeeze(32)),
                   "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
        assert_ne!(hex(&shake256.squeeze(32)), hex(&shake.squeeze(32)),
                   "SHAKE128 and SHAKE256 agreed, so the rate is not being used");
    }

    /// **The rate boundary, in both directions.**
    ///
    /// Absorbing: an input that exactly fills a block must be padded
    /// into a whole extra block. Squeezing: an output longer than the
    /// rate needs another permutation. Both are off-by-one territory,
    /// and both are right for every length but the boundary itself.
    #[test]
    fn test_the_rate_boundary_absorbing_and_squeezing() {
        for digest_len in [28usize, 32, 48, 64] {
            let rate = 200 - 2 * digest_len;
            for length in [rate - 2, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 1] {
                let input: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
                let mut one_shot = Keccak::sha3(digest_len).unwrap();
                one_shot.update(&input);
                let expected = hex(&one_shot.digest());

                for chunk in [1usize, 7, rate - 1, rate, rate + 1] {
                    let mut streamed = Keccak::sha3(digest_len).unwrap();
                    for piece in input.chunks(chunk) {
                        streamed.update(piece);
                    }
                    assert_eq!(hex(&streamed.digest()), expected,
                               "SHA3-{} disagreed with itself at {} bytes in {} \
                                byte pieces", digest_len * 8, length, chunk);
                }
            }
        }
    }

    /// **The padding that fits in one byte**, at `rate - 1`.
    ///
    /// The domain byte and the closing `0x80` normally land on
    /// different bytes; at exactly one byte short of the rate they land
    /// on the same one and must be ORed together. Writing `=` instead
    /// of `|=` is wrong for that single length and right for every
    /// other - and wrong *consistently*, so streamed and one-shot still
    /// agree and every other vector passes.
    ///
    /// Two pinned answers from `hashlib`, at two different rates, since
    /// only a pinned answer can see this.
    #[test]
    fn test_the_padding_fits_in_one_byte_at_the_boundary() {
        // SHA3-256, rate 136.
        let input: Vec<u8> = (0..135).map(|i| (i % 251) as u8).collect();
        let mut hash = Keccak::sha3(32).unwrap();
        hash.update(&input);
        assert_eq!(hex(&hash.digest()),
                   "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2");

        // SHA3-512, rate 72 - a different boundary, so a fix that
        // happened to work for one rate is not enough.
        let input: Vec<u8> = (0..71).map(|i| (i % 251) as u8).collect();
        let mut hash = Keccak::sha3(64).unwrap();
        hash.update(&input);
        assert_eq!(hex(&hash.digest()),
                   "3ccc850d53a1287af7b4560b2ef0d43eb5d9a80d62a0e9cf1dbc040135921104\
                   d4395168e90bfc871773ebb34bca1bd67056e1cc7dc7a48ff7c3167d389f117c");
    }

    /// **Squeezing past the rate**, where the sponge must permute
    /// again.
    ///
    /// Every SHA-3 digest is shorter than its rate, so nothing else
    /// here reaches the second squeeze block. And a SHAKE compared only
    /// against prefixes of itself is wrong the same way at both
    /// lengths, so the prefix property holds while the bytes are wrong.
    /// Pinned against `hashlib`, at both rates.
    #[test]
    fn test_squeezing_past_the_rate() {
        let mut shake = Keccak::shake(128, 400).unwrap();
        shake.update(b"abc");
        // 400 bytes, against a rate of 168: three squeeze blocks.
        assert_eq!(hex(&shake.squeeze(400)),
                   "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8\
                   44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378\
                   9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232\
                   a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4\
                   a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a\
                   cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd\
                   4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b4\
                   75375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e50732f5cfc904b1\
                   319795000d7361d9e5e1b77b4b8f5774aa1482cfa58f83096bdb2e06a3eed543\
                   a38919b57ecbec737f4086be007f8ef80094ceea8807193d46e9be540b6e99b4\
                   c1c71507095028a024e8d39aa8f4c5854cedd50d30a223e7d54e9a24f0a2526b\
                   31002afbd1b4ebea69c8400c3deb4c1c35d6dbb75651b284076f5fde47b4a058\
                   6ee173e30bd4d08f2bc59c6114bdd745");

        let mut shake = Keccak::shake(256, 300).unwrap();
        shake.update(b"abc");
        // 300 bytes, against a rate of 136.
        assert_eq!(hex(&shake.squeeze(300)),
                   "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
                   d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4\
                   1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78\
                   dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334\
                   e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3\
                   3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67\
                   7513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195\
                   bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412\
                   fc346b1bb39b878330e026b12ddf384af3334560ea1d363966caa7d8ddcbec7d\
                   a52b42215c11d5f8ee57f341");
    }

    /// The round constants match FIPS 202's published table.
    #[test]
    fn test_the_round_constants_match_the_published_table() {
        const PUBLISHED: [u64; 24] = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ];
        assert_eq!(ROUND_CONSTANTS, PUBLISHED,
                   "the LFSR does not reproduce the standard's constants");
    }

    /// The rho offsets match FIPS 202's published table.
    #[test]
    fn test_the_rho_offsets_match_the_published_table() {
        // FIPS 202 Table 2, laid out as [x + 5y].
        const PUBLISHED: [u32; 25] = [
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
        ];
        assert_eq!(RHO, PUBLISHED, "the spiral does not reproduce Table 2");
    }

    /// `digest()` is repeatable and does not end the hash.
    #[test]
    fn test_digest_is_repeatable() {
        let mut hash = Keccak::sha3(32).unwrap();
        hash.update(b"first");
        let once = hash.digest();
        assert_eq!(once, hash.digest());
        hash.update(b"second");
        let mut whole = Keccak::sha3(32).unwrap();
        whole.update(b"firstsecond");
        assert_eq!(hex(&hash.digest()), hex(&whole.digest()));
    }

    #[test]
    fn test_bad_sizes_are_errors() {
        assert!(Keccak::sha3(20).is_err());
        assert!(Keccak::sha3(0).is_err());
        assert!(Keccak::shake(192, 32).is_err());
        assert!(Keccak::keccak(0).is_err());
        assert!(Keccak::keccak(65).is_err());
    }

    /// `squeeze` reserved its whole output before the first permutation
    /// with `Vec::with_capacity`, which on failure aborts the process
    /// rather than returning, and nothing bounded the length - a sponge
    /// has no maximum of its own. `api::shake` takes the length from a
    /// caller. The existing tests squeezed at most a thousand bytes.
    /// The length below is refused by the cap before any allocation;
    /// `usize::MAX` would have aborted the old code, so it is the only
    /// kind of value that can be offered here.
    #[test]
    fn test_an_oversized_squeeze_is_an_error_not_an_abort() {
        let shake = Keccak::shake(128, 32).unwrap();
        let reason = shake.try_squeeze(Keccak::MAX_SQUEEZE + 1).unwrap_err();
        assert!(reason.contains("at most"), "{reason}");
        assert!(shake.try_squeeze(usize::MAX).is_err());
        assert!(Keccak::shake(128, usize::MAX).is_err());
        assert!(Keccak::shake(256, Keccak::MAX_SQUEEZE + 1).is_err());
        // The two squeezes agree inside the cap.
        assert_eq!(shake.try_squeeze(200).unwrap(), shake.squeeze(200));
    }
}
