//! The rand_isaac crate as a witness for ISAAC and ISAAC-64, in the
//! request format of `../driver.h`.
//!
//! `IsaacRng::from_rng` and `Isaac64Rng::from_rng` read the whole seed
//! array, 1024 or 2048 bytes, as little-endian words from the RNG they are
//! given; here that RNG yields the key and then zeros. The crate computes
//! randinit's block first and returns each block's words from the last to
//! the first, the order the reference's `rand()` macro reads them in; this
//! driver puts each block back in index order.

use std::io::{self, BufRead, Write};

use rand_core::{Error, RngCore, SeedableRng};
use rand_isaac::{Isaac64Rng, IsaacRng};

/// The key, then zeros.
struct KeyBytes {
    key: Vec<u8>,
    at: usize,
}

impl RngCore for KeyBytes {
    fn next_u32(&mut self) -> u32 {
        unreachable!("from_rng fills bytes")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("from_rng fills bytes")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.key.get(self.at).copied().unwrap_or(0);
            self.at += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s == "-" {
        return Some(Vec::new());
    }
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn answer(line: &str) -> String {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 5 || f[0] != "isaac" {
        return "error request".to_string();
    }
    let (Some(key), Ok(first), Ok(count)) = (unhex(f[2]), f[3].parse::<usize>(),
                                             f[4].parse::<usize>()) else {
        return "error request".to_string();
    };
    if count == 0 || count > 64 || first > 1024 {
        return "error request".to_string();
    }
    let seed = KeyBytes { key: key.clone(), at: 0 };
    let mut out = Vec::new();
    match f[1] {
        "32" if key.len() <= 1024 => {
            let mut rng = IsaacRng::from_rng(seed).unwrap();
            for b in 0..first + count {
                let mut block: Vec<u32> = (0..256).map(|_| rng.next_u32()).collect();
                block.reverse();
                if b >= first {
                    out.extend(block.iter().flat_map(|w| w.to_le_bytes()));
                }
            }
        }
        "64" if key.len() <= 2048 => {
            let mut rng = Isaac64Rng::from_rng(seed).unwrap();
            for b in 0..first + count {
                let mut block: Vec<u64> = (0..256).map(|_| rng.next_u64()).collect();
                block.reverse();
                if b >= first {
                    out.extend(block.iter().flat_map(|w| w.to_le_bytes()));
                }
            }
        }
        "32" | "64" => return "error key".to_string(),
        _ => return "error request".to_string(),
    }
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        writeln!(stdout, "{}", answer(&line.unwrap())).unwrap();
        stdout.flush().unwrap();
    }
}
