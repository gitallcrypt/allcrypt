//! Rabbit (Boesgaard, Vesterager, Pedersen, Christiansen and Scavenius,
//! FSE 2003; RFC 4503): an eSTREAM software-profile stream cipher.
//!
//! A 128 bit key, an optional 64 bit IV, and 128 bits of keystream per
//! step.
//!
//! ## The state
//!
//! Eight 32 bit state words `X0..X7`, eight 32 bit counters `C0..C7`
//! and one carry bit `b`. A step adds the constants `A0..A7` to the
//! counters as one 256 bit addition, carrying from `C0` up through `C7`
//! and **out of `C7` into the next step's `C0`** through `b`; then
//!
//! ```text
//! Gj = g(Xj, Cj),  g(u, v) = LSW((u+v)^2) ^ MSW((u+v)^2)   (64 bit square)
//! X0 = G0 + (G7 <<< 16) + (G6 <<< 16)    X1 = G1 + (G0 <<< 8) + G7
//! ```
//!
//! and so on, the even words with two 16 bit rotations and the odd ones
//! with one 8 bit rotation and an unrotated word. The output takes 16
//! bits from each of two words for each 16 bits of the block.
//!
//! ## Key and IV setup
//!
//! The key's eight 16 bit words fill `X` and `C` in an arrangement that
//! differs for even and odd `j`; four steps follow, and then `Cj ^=
//! X(j+4 mod 8)`. The IV, if any, is XORed into the counters, split in
//! four 32 bit ways, and four more steps follow. The carry bit is part
//! of the state throughout: it is not reset between the key and IV
//! setups or before the first keystream block.
//!
//! ## Byte order
//!
//! RFC 4503 prints keys, IVs and keystream as **big-endian numbers**
//! (I2OSP): its key `[00 .. 00]` gives an `S[0]` printed `B1 57 54 F0 ..
//! F7 02`. As bytes, here, the key, the IV and each keystream block are
//! **little endian** - the first byte is bits 7..0 - which is how the
//! eSTREAM reference, Crypto++, libtomcrypt and RustCrypto all read and
//! write them, so the RFC's values are read here reversed. Both
//! readings give a cipher that agrees with itself.
//!
//! The appendix's debugging vectors print the key as `91 28 13 29 2E ED
//! ..` where the key that produces them is `.. 2E 3D ..`, as in
//! Appendix A; that is the RFC's verified erratum 2504, which the tests
//! apply to that one printed line.
//!
//! ## Constant time
//!
//! Additions, a 32 by 32 bit multiplication, rotations and XORs, with
//! the counter's carry computed from the wide sum rather than compared.

use crate::stream_ciphers::StreamCipher;

const A: [u32; 8] = [0x4D34_D34D, 0xD34D_34D3, 0x34D3_4D34, 0x4D34_D34D, 0xD34D_34D3,
                     0x34D3_4D34, 0x4D34_D34D, 0xD34D_34D3];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    x: [u32; 8],
    c: [u32; 8],
    b: u32,
}

fn g(u: u32, v: u32) -> u32 {
    let s = u64::from(u.wrapping_add(v));
    let square = s * s;
    square as u32 ^ (square >> 32) as u32
}

impl State {
    /// The key's 16 bit words placed into `X` and `C`, before any step.
    fn expand(key: &[u8; 16]) -> State {
        let k: [u32; 8] = core::array::from_fn(|i| u32::from(u16::from_le_bytes([key[2 * i],
                                                                                  key[2 * i + 1]])));
        let mut s = State { x: [0; 8], c: [0; 8], b: 0 };
        for j in 0..8 {
            if j % 2 == 0 {
                s.x[j] = k[(j + 1) % 8] << 16 | k[j];
                s.c[j] = k[(j + 4) % 8] << 16 | k[(j + 5) % 8];
            } else {
                s.x[j] = k[(j + 5) % 8] << 16 | k[(j + 4) % 8];
                s.c[j] = k[j] << 16 | k[(j + 1) % 8];
            }
        }
        s
    }

    /// The counter update and the next-state function.
    fn step(&mut self) {
        for (c, a) in self.c.iter_mut().zip(A) {
            let t = u64::from(*c) + u64::from(a) + u64::from(self.b);
            self.b = (t >> 32) as u32;
            *c = t as u32;
        }
        let g: [u32; 8] = core::array::from_fn(|j| g(self.x[j], self.c[j]));
        for j in 0..8 {
            self.x[j] = if j % 2 == 0 {
                g[j].wrapping_add(g[(j + 7) % 8].rotate_left(16))
                    .wrapping_add(g[(j + 6) % 8].rotate_left(16))
            } else {
                g[j].wrapping_add(g[(j + 7) % 8].rotate_left(8)).wrapping_add(g[(j + 6) % 8])
            };
        }
    }

    /// Key setup: the expansion, four steps, and the counters mixed with
    /// the state.
    fn keyed(key: &[u8; 16]) -> State {
        let mut s = State::expand(key);
        for _ in 0..4 {
            s.step();
        }
        for j in 0..8 {
            s.c[j] ^= s.x[(j + 4) % 8];
        }
        s
    }

    /// The IV into the counters, before the IV setup's four steps.
    fn add_iv(&mut self, iv: &[u8; 8]) {
        let low = u32::from_le_bytes(iv[..4].try_into().expect("4 bytes"));
        let high = u32::from_le_bytes(iv[4..].try_into().expect("4 bytes"));
        // IV[63..48] || IV[31..16], and IV[47..32] || IV[15..0].
        let odd = [(high & 0xffff_0000) | low >> 16, high << 16 | (low & 0xffff)];
        let words = [low, odd[0], high, odd[1]];
        for j in 0..8 {
            self.c[j] ^= words[j % 4];
        }
    }

    fn block(&self) -> [u8; 16] {
        let x = &self.x;
        let words = [x[0] ^ x[5] >> 16 ^ x[3] << 16, x[2] ^ x[7] >> 16 ^ x[5] << 16,
                     x[4] ^ x[1] >> 16 ^ x[7] << 16, x[6] ^ x[3] >> 16 ^ x[1] << 16];
        let mut out = [0u8; 16];
        for (chunk, w) in out.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Rabbit under one key and IV.
#[derive(Clone)]
pub struct Rabbit {
    state: State,
    /// The current keystream block, and how many of its bytes are used.
    block: [u8; 16],
    used: usize,
}

impl core::fmt::Debug for Rabbit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rabbit").finish_non_exhaustive()
    }
}

impl Rabbit {
    /// Rabbit under a 16 byte key and an IV of 8 bytes, or none: an empty
    /// IV skips the IV setup, as RFC 4503 2.4 allows. A key used without
    /// an IV must never be used again.
    ///
    /// # Errors
    /// A key of another length, or an IV that is neither empty nor 8
    /// bytes.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Rabbit, String> {
        let key: &[u8; 16] = key.try_into()
            .map_err(|_| format!("A Rabbit key is 16 bytes, not {}.", key.len()))?;
        let mut state = State::keyed(key);
        match iv.len() {
            0 => {}
            8 => {
                state.add_iv(iv.try_into().expect("8 bytes"));
                for _ in 0..4 {
                    state.step();
                }
            }
            n => return Err(format!("A Rabbit IV is 8 bytes, or empty for none, not {n}.")),
        }
        Ok(Rabbit { state, block: [0; 16], used: 16 })
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == 16 {
                self.state.step();
                self.block = self.state.block();
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

impl StreamCipher for Rabbit {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC: &str = include_str!("../../rfcs/rfc4503.txt");

    /// An RFC octet string, `name = [B1 57 .. 02]`, as this module's
    /// bytes: reversed. The bracket after the `=`, since `S[0]` has one of
    /// its own.
    fn octets(line: &str) -> Vec<u8> {
        let open = line.find("= [").expect("= [") + 3;
        let inside = &line[open..open + line[open..].find(']').expect("]")];
        let mut bytes: Vec<u8> = inside.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).expect("hex")).collect();
        bytes.reverse();
        bytes
    }

    fn keystream(key: &[u8], iv: &[u8], n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        Rabbit::new(key, iv).expect("key").apply_keystream(&mut out);
        out
    }

    /// Appendix A, both parts: three keys without an IV, then three IVs
    /// under the zero key (erratum 5341: A.2's `mkey` is the key).
    #[test]
    fn test_rfc_4503_appendix_a() {
        // Anchored at the headings' own lines: the table of contents
        // names both appendices first.
        let start = RFC.find("\nA.1.  Testing without IV Setup\n").expect("A.1");
        let end = RFC.find("\nAppendix B: Debugging Vectors\n").expect("Appendix B");
        let (mut key, mut iv) = (Vec::new(), Vec::new());
        let mut expected: Vec<u8> = Vec::new();
        let mut checked = (0, 0);
        let mut check = |key: &[u8], iv: &[u8], expected: &mut Vec<u8>| {
            if expected.len() == 48 {
                assert_eq!(keystream(key, iv, 48), *expected, "{key:02x?} {iv:02x?}");
                if iv.is_empty() { checked.0 += 1 } else { checked.1 += 1 }
                expected.clear();
            }
        };
        for line in RFC[start..end].lines().map(str::trim) {
            if line.starts_with("key  = [") || line.starts_with("mkey = [") {
                key = octets(line);
                iv.clear();
            } else if line.starts_with("iv   = [") {
                iv = octets(line);
            } else if line.starts_with("S[") {
                expected.extend(octets(line));
                check(&key, &iv, &mut expected);
            }
        }
        assert_eq!(checked, (3, 3));
    }

    /// One state block of Appendix B: `b`, `X0..X7` and `C0..C7`.
    fn parse_state(text: &str) -> State {
        let mut s = State { x: [0; 8], c: [0; 8], b: u32::MAX };
        let mut seen = 0;
        for item in text.split([',', '\n']).map(str::trim).filter(|t| !t.is_empty()) {
            let (name, value) = item.split_once('=').expect("name = value");
            let (name, value) = (name.trim(), value.trim());
            if name == "b" {
                s.b = value.parse().expect("b");
            } else {
                let v = u32::from_str_radix(value.trim_start_matches("0x"), 16).expect("hex");
                let i: usize = name[1..].parse().expect("index");
                if name.starts_with('X') { s.x[i] = v } else { s.c[i] = v }
            }
            seen += 1;
        }
        assert_eq!(seen, 17, "{text}");
        s
    }

    /// Appendix B's states in order, by their heading.
    fn states() -> Vec<(String, State)> {
        let start = RFC.find("\nAppendix B: Debugging Vectors\n").expect("Appendix B");
        let text = &RFC[start..];
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(found) = text[at..].find("Inner state after ") {
            let head = at + found;
            let colon = head + text[head..].find(":\n").expect("heading");
            let body_start = colon + 2;
            let body_end = body_start + text[body_start..].find("\n\n").expect("block end");
            out.push((text[head..colon].to_string(), parse_state(&text[body_start..body_end])));
            at = body_end;
        }
        out
    }

    /// The debugging vectors' key, with erratum 2504 applied to the one
    /// printed line it names, which must still read as printed.
    fn debugging_key() -> [u8; 16] {
        let printed = "key  = [91 28 13 29 2E ED 36 FE 3B FC 62 F1 DC 51 C3 AC]";
        let b1 = RFC.find("B.1.  Testing Round Function and Key Setup").expect("B.1");
        assert!(RFC[b1..b1 + 200].contains(printed), "the B.1 key line has changed");
        let corrected = printed.replace("2E ED", "2E 3D");
        octets(&corrected).try_into().expect("16 bytes")
    }

    #[test]
    fn test_rfc_4503_appendix_b_states() {
        let states = states();
        let names: Vec<&str> = states.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, [
            "Inner state after key expansion",
            "Inner state after first key setup iteration",
            "Inner state after fourth key setup iteration",
            "Inner state after final key setup xor",
            "Inner state after generation of 48 bytes of output",
            "Inner state after IV expansion",
            "Inner state after first IV setup iteration",
            "Inner state after fourth IV setup iteration",
        ]);
        let key = debugging_key();
        let mut s = State::expand(&key);
        assert_eq!(s, states[0].1, "key expansion");
        s.step();
        assert_eq!(s, states[1].1, "first key setup step");
        for _ in 1..4 {
            s.step();
        }
        assert_eq!(s, states[2].1, "fourth key setup step");
        let keyed = State::keyed(&key);
        assert_eq!(keyed, states[3].1, "after the key setup's XOR");
        let mut out = keyed;
        for _ in 0..3 {
            out.step();
        }
        assert_eq!(out, states[4].1, "after 48 bytes");

        let iv_line = RFC[RFC.find("B.2.  Testing the IV Setup").expect("B.2")..]
            .lines().find(|l| l.trim().starts_with("iv   = [")).expect("B.2 iv");
        let iv: [u8; 8] = octets(iv_line).try_into().expect("8 bytes");
        let mut s = keyed;
        s.add_iv(&iv);
        assert_eq!(s, states[5].1, "IV expansion");
        s.step();
        assert_eq!(s, states[6].1, "first IV setup step");
        for _ in 1..4 {
            s.step();
        }
        assert_eq!(s, states[7].1, "fourth IV setup step");
    }

    /// The printed key itself is not the one the debugging vectors use.
    #[test]
    fn test_the_misprinted_key_does_not_give_the_states() {
        let mut misprinted = debugging_key();
        misprinted[10] = 0xED;
        assert_ne!(State::keyed(&misprinted), states()[3].1);
    }

    /// The carry out of `C7` reaches the next step: a state whose
    /// counters are all ones carries into every word.
    #[test]
    fn test_the_carry_persists_across_steps() {
        let mut s = State { x: [0; 8], c: [u32::MAX; 8], b: 0 };
        s.step();
        assert_eq!(s.b, 1);
        let mut without = s;
        without.b = 0;
        s.step();
        without.step();
        assert_ne!(s.c, without.c);
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let key: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(29) ^ 0x5c).collect();
        for iv in [Vec::new(), vec![1, 2, 3, 4, 5, 6, 7, 8]] {
            let whole = keystream(&key, &iv, 200);
            for piece in [1, 3, 15, 16, 17, 33] {
                let mut c = Rabbit::new(&key, &iv).expect("key");
                let mut got = vec![0u8; 200];
                for chunk in got.chunks_mut(piece) {
                    c.apply_keystream(chunk);
                }
                assert_eq!(got, whole, "pieces of {piece}");
            }
        }
    }

    #[test]
    fn test_other_lengths_are_refused() {
        for n in [0, 8, 15, 17, 32] {
            assert_eq!(Rabbit::new(&vec![0; n], &[]).unwrap_err(),
                       format!("A Rabbit key is 16 bytes, not {n}."));
        }
        for n in [1, 4, 7, 9, 16] {
            assert_eq!(Rabbit::new(&[0; 16], &vec![0; n]).unwrap_err(),
                       format!("A Rabbit IV is 8 bytes, or empty for none, not {n}."));
        }
    }
}
