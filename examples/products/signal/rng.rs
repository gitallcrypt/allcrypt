//! Where the randomness comes from.
//!
//! Normally the system generator. For a test, a stream anybody can
//! recompute: `SHA-256(seed || 0) || SHA-256(seed || 1) || ...`, the
//! counter eight bytes big endian. `scripts/witness/signalwitness` gives
//! libsignal-protocol-c the same stream, so the two produce the same
//! bytes exactly when they draw the same amounts in the same order -
//! which is most of what a byte-for-byte replay checks.

use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::HashFunction;

pub enum Random {
    System,
    Stream { seed: Vec<u8>, counter: u64, block: [u8; 32], used: usize },
}

impl Random {
    pub fn system() -> Random {
        Random::System
    }

    pub fn seeded(seed: &[u8]) -> Random {
        Random::Stream { seed: seed.to_vec(), counter: 0, block: [0; 32], used: 32 }
    }

    pub fn fill(&mut self, out: &mut [u8]) -> Result<(), String> {
        match self {
            Random::System => allcrypt::random::fill(out),
            Random::Stream { seed, counter, block, used } => {
                for byte in out.iter_mut() {
                    if *used == block.len() {
                        let mut hash = SHA256::new(&[]);
                        hash.update(seed);
                        hash.update(&counter.to_be_bytes());
                        block.copy_from_slice(&hash.digest());
                        *counter += 1;
                        *used = 0;
                    }
                    *byte = block[*used];
                    *used += 1;
                }
                Ok(())
            }
        }
    }

    /// libsignal's `get_random_sequence(max = INT32_MAX)`: four bytes
    /// read as a native (little endian) `int32`, masked to 31 bits and
    /// reduced modulo `2^31 - 1`. Sender key ids are drawn this way.
    pub fn sequence(&mut self) -> Result<u32, String> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes)?;
        Ok((u32::from_le_bytes(bytes) & 0x7fff_ffff) % 0x7fff_ffff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stream is SHA-256 blocks, consumed across calls without
    /// regard to where one call ended - libsignal's generator is asked
    /// for 32 bytes, then 64, then 4, and a stream that restarted a
    /// block per call would agree on the first draw only.
    #[test]
    fn test_the_stream_runs_across_calls() {
        let mut whole = Random::seeded(b"s");
        let mut all = [0u8; 100];
        whole.fill(&mut all).unwrap();

        let mut pieces = Random::seeded(b"s");
        let mut joined = Vec::new();
        for size in [32, 64, 4] {
            let mut part = vec![0u8; size];
            pieces.fill(&mut part).unwrap();
            joined.extend_from_slice(&part);
        }
        assert_eq!(joined, all);

        let mut first = SHA256::new(&[]);
        first.update(b"s");
        first.update(&0u64.to_be_bytes());
        assert_eq!(all[..32], first.digest()[..]);
    }

    #[test]
    fn test_the_sequence_is_31_bits_modulo_2_to_31_minus_1() {
        let mut ones = Random::Stream { seed: vec![], counter: 0, block: [0xff; 32], used: 0 };
        assert_eq!(ones.sequence().unwrap(), 0);
        let mut block = [0u8; 32];
        block[..4].copy_from_slice(&[1, 0, 0, 0x80]);
        let mut low = Random::Stream { seed: vec![], counter: 0, block, used: 0 };
        assert_eq!(low.sequence().unwrap(), 1);
    }
}
