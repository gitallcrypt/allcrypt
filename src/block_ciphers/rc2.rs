/*
RC2 (RFC 2268), a 64 bit block cipher from 1989.

Here because TLS's export ciphersuites use it, and because it is the
clearest surviving artefact of a specific piece of history: the cipher has
a parameter, `effective_bits`, whose entire purpose is to make the key
*weaker* than the key you supplied. A 128 bit key with `effective_bits`
set to 40 has 40 bits of entropy, spread across 128 bits of schedule, so
that the export paperwork could say forty and the wire format could stay
the same.

## The parameter is not optional and not cosmetic

`effective_bits` changes the key schedule, not a length check. Two
implementations that agree on the key and disagree on this produce
completely different ciphertext. TLS's `RC2_CBC_40` means a 16 byte
expanded key with `effective_bits = 40`, which is not the same as a 5 byte
key, and not the same as a 16 byte key either.

Most library interfaces hide the parameter and default it to `8 *
key_len`, which is the no-weakening case. That default is what
`RC2::new` uses, so that the ordinary use agrees with everyone else, and
`RC2::with_effective_bits` is what TLS needs.

## The shape of the cipher

Sixteen rounds in two kinds: eighteen "mixing" rounds and two "mashing"
rounds, arranged 5 mix, 1 mash, 6 mix, 1 mash, 5 mix. A mash round indexes
the key schedule with the low bits of the previous word, which is the only
data-dependent step and is what makes RC2 awkward to implement in constant
time - one of several reasons it is not a cipher to choose today.

Everything is **little endian** 16 bit words, in a library where almost
nothing else is. `PITABLE` is a fixed permutation of 0..255, published in
the RFC with no explanation of where it came from.
*/

use super::BlockCipher;

/// The permutation from RFC 2268 section 2. A fixed table with no
/// derivation given; transcribed rather than computed, which is why the
/// test that checks it against the specification's own vectors matters.
const PITABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79,
    0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
    0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5,
    0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22,
    0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
    0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f,
    0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b,
    0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
    0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde,
    0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e,
    0x04, 0x18, 0xa4, 0xec, 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
    0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85,
    0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10,
    0x67, 0x6c, 0xba, 0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
    0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b,
    0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68,
    0xfe, 0x7f, 0xc1, 0xad,
];

/// RC2 with an expanded key schedule.
#[derive(Clone)]
pub struct RC2 {
    /// 64 sixteen bit words, which is the whole schedule.
    k: [u16; 64],
}

impl RC2 {
    /// A key with no deliberate weakening: `effective_bits = 8 * key.len()`.
    ///
    /// This is what every library's plain `RC2(key)` means, so it is what
    /// this one means too. TLS's export suites do not want it.
    pub fn new(key: &[u8]) -> Result<RC2, String> {
        let bits = key.len() * 8;
        RC2::with_effective_bits(key, bits)
    }

    /// A key deliberately reduced to `effective_bits` of entropy.
    ///
    /// TLS's `RC2_CBC_40` is a 16 byte key with 40 effective bits - not a
    /// 5 byte key, and not an unweakened 16 byte one. Getting this wrong
    /// produces an implementation that round-trips against itself and
    /// agrees with nothing.
    pub fn with_effective_bits(key: &[u8], effective_bits: usize)
                               -> Result<RC2, String> {
        if key.is_empty() || key.len() > 128 {
            return Err(format!(
                "An RC2 key is 1 to 128 bytes; this one is {}.", key.len()));
        }
        if effective_bits == 0 || effective_bits > 1024 {
            return Err(format!(
                "RC2's effective key length is 1 to 1024 bits; {} is not.",
                effective_bits));
        }

        // Step 1: fill 128 bytes by running the permutation forward.
        let mut l = [0u8; 128];
        l[..key.len()].copy_from_slice(key);
        for i in key.len()..128 {
            let index = l[i - 1].wrapping_add(l[i - key.len()]) as usize;
            l[i] = PITABLE[index];
        }

        // Step 2: the weakening. `t8` bytes survive; the top bits of the
        // last surviving byte are masked off by `tm`, so the entropy is
        // exactly `effective_bits` however long the key was.
        let t8 = effective_bits.div_ceil(8);
        let tm = (255u16 >> ((8 * t8) - effective_bits)) as u8;
        l[128 - t8] = PITABLE[(l[128 - t8] & tm) as usize];
        for i in (0..128 - t8).rev() {
            let index = (l[i + 1] ^ l[i + t8]) as usize;
            l[i] = PITABLE[index];
        }

        // Step 3: read the 128 bytes back as 64 little-endian words.
        let mut k = [0u16; 64];
        for (i, word) in k.iter_mut().enumerate() {
            *word = u16::from(l[2 * i]) | (u16::from(l[2 * i + 1]) << 8);
        }
        Ok(RC2 { k })
    }

    fn encrypt_block(&self, input: &[u8]) -> [u8; 8] {
        let mut r = [
            u16::from(input[0]) | (u16::from(input[1]) << 8),
            u16::from(input[2]) | (u16::from(input[3]) << 8),
            u16::from(input[4]) | (u16::from(input[5]) << 8),
            u16::from(input[6]) | (u16::from(input[7]) << 8),
        ];

        let mut j = 0usize;
        // 5 mixing, 1 mashing, 6 mixing, 1 mashing, 5 mixing.
        for round in 0..16 {
            self.mix(&mut r, &mut j);
            if round == 4 || round == 10 {
                self.mash(&mut r);
            }
        }

        let mut out = [0u8; 8];
        for (i, word) in r.iter().enumerate() {
            out[2 * i] = (*word & 0xff) as u8;
            out[2 * i + 1] = (*word >> 8) as u8;
        }
        out
    }

    fn decrypt_block(&self, input: &[u8]) -> [u8; 8] {
        let mut r = [
            u16::from(input[0]) | (u16::from(input[1]) << 8),
            u16::from(input[2]) | (u16::from(input[3]) << 8),
            u16::from(input[4]) | (u16::from(input[5]) << 8),
            u16::from(input[6]) | (u16::from(input[7]) << 8),
        ];

        let mut j = 63usize;
        for round in (0..16).rev() {
            self.unmix(&mut r, &mut j);
            if round == 5 || round == 11 {
                self.unmash(&mut r);
            }
        }

        let mut out = [0u8; 8];
        for (i, word) in r.iter().enumerate() {
            out[2 * i] = (*word & 0xff) as u8;
            out[2 * i + 1] = (*word >> 8) as u8;
        }
        out
    }

    /// One mixing round: four steps, rotating by 1, 2, 3 and 5.
    fn mix(&self, r: &mut [u16; 4], j: &mut usize) {
        const ROTATIONS: [u32; 4] = [1, 2, 3, 5];
        for i in 0..4 {
            let sum = r[i]
                .wrapping_add(self.k[*j])
                .wrapping_add(r[(i + 3) % 4] & r[(i + 2) % 4])
                .wrapping_add(!r[(i + 3) % 4] & r[(i + 1) % 4]);
            r[i] = sum.rotate_left(ROTATIONS[i]);
            *j += 1;
        }
    }

    fn unmix(&self, r: &mut [u16; 4], j: &mut usize) {
        const ROTATIONS: [u32; 4] = [1, 2, 3, 5];
        for i in (0..4).rev() {
            let rotated = r[i].rotate_right(ROTATIONS[i]);
            r[i] = rotated
                .wrapping_sub(self.k[*j])
                .wrapping_sub(r[(i + 3) % 4] & r[(i + 2) % 4])
                .wrapping_sub(!r[(i + 3) % 4] & r[(i + 1) % 4]);
            *j = j.wrapping_sub(1);
        }
    }

    /// One mashing round. The key word is chosen by the low six bits of
    /// the previous word - the only data-dependent index in the cipher,
    /// and the reason a constant-time RC2 is awkward.
    fn mash(&self, r: &mut [u16; 4]) {
        for i in 0..4 {
            let index = (r[(i + 3) % 4] & 63) as usize;
            r[i] = r[i].wrapping_add(self.k[index]);
        }
    }

    fn unmash(&self, r: &mut [u16; 4]) {
        for i in (0..4).rev() {
            let index = (r[(i + 3) % 4] & 63) as usize;
            r[i] = r[i].wrapping_sub(self.k[index]);
        }
    }
}

impl BlockCipher for RC2 {
    fn blocksize(&self) -> usize {
        8
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&self.encrypt_block(input));
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&self.decrypt_block(input));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 2268 section 5, all eight vectors.
    ///
    /// Note what they vary: the same 8 byte key appears with 63, 64 and
    /// 128 effective bits and gives three different ciphertexts. That is
    /// the parameter this cipher exists to demonstrate, and a test suite
    /// without those rows would pass with it ignored entirely.
    #[test]
    fn test_the_rfc_2268_vectors() {
        for (key, effective_bits, plaintext, want) in [
            ("0000000000000000", 63, "0000000000000000", "ebb773f993278eff"),
            ("ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"),
            ("3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"),
            ("88", 64, "0000000000000000", "61a8a244adacccf0"),
            ("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"),
            ("88bca90e90875a7f0f79c384627bafb2", 64,
             "0000000000000000", "1a807d272bbe5db1"),
            ("88bca90e90875a7f0f79c384627bafb2", 128,
             "0000000000000000", "2269552ab0f85ca6"),
            ("88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
             129, "0000000000000000", "5b78d3a43dfff1f1"),
        ] {
            let mut cipher = RC2::with_effective_bits(&unhex(key), effective_bits)
                .unwrap();
            let plaintext = unhex(plaintext);
            let mut out = Vec::new();
            cipher.block_encrypt(&plaintext, &mut out);
            assert_eq!(hex(&out), want,
                       "key {} with {} effective bits", key, effective_bits);

            let mut back = Vec::new();
            cipher.block_decrypt(&out, &mut back);
            assert_eq!(back, plaintext, "decryption did not undo encryption");
        }
    }

    /// The whole point of the parameter: the same key, weakened, is a
    /// different cipher. An implementation that ignored `effective_bits`
    /// would pass every round-trip test ever written.
    #[test]
    fn test_effective_bits_changes_the_cipher() {
        let key = unhex("88bca90e90875a7f0f79c384627bafb2");
        let plaintext = [0u8; 8];
        let mut seen = Vec::new();
        for bits in [40usize, 56, 64, 128] {
            let mut cipher = RC2::with_effective_bits(&key, bits).unwrap();
            let mut out = Vec::new();
            cipher.block_encrypt(&plaintext, &mut out);
            assert!(!seen.contains(&out),
                    "{} effective bits gave a ciphertext already seen", bits);
            seen.push(out);
        }

        // And the default is the unweakened case, so an ordinary caller
        // agrees with every other library.
        let mut default = RC2::new(&key).unwrap();
        let mut plain_out = Vec::new();
        default.block_encrypt(&plaintext, &mut plain_out);
        assert_eq!(plain_out, seen[3], "RC2::new must mean 8 * key length");
    }

    #[test]
    fn test_round_trips_at_every_key_length() {
        for key_len in [1usize, 5, 8, 16, 40, 128] {
            let key: Vec<u8> = (0..key_len).map(|i| (i * 37 + 11) as u8).collect();
            let mut cipher = RC2::new(&key).unwrap();
            for block in 0..4u8 {
                let plaintext: Vec<u8> = (0..8).map(|i| i * 31 + block).collect();
                let mut out = Vec::new();
                cipher.block_encrypt(&plaintext, &mut out);
                assert_eq!(out.len(), 8);
                let mut back = Vec::new();
                cipher.block_decrypt(&out, &mut back);
                assert_eq!(back, plaintext, "key length {}", key_len);
            }
        }
    }

    #[test]
    fn test_impossible_parameters_are_refused() {
        assert!(RC2::new(&[]).is_err(), "an empty key was accepted");
        assert!(RC2::new(&[0; 129]).is_err(), "a 129 byte key was accepted");
        assert!(RC2::with_effective_bits(&[1], 0).is_err());
        assert!(RC2::with_effective_bits(&[1], 1025).is_err());
        // The two ends of the legal range work.
        assert!(RC2::with_effective_bits(&[1], 1).is_ok());
        assert!(RC2::with_effective_bits(&[0; 128], 1024).is_ok());
    }
}
