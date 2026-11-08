//! The request loop of scripts/witness/snow3g_zuc/driver.h, for the two
//! Rust witnesses: one request per line on stdin, one answer per line.

use std::io::{BufRead, Write};

/// What a witness implements. Each returns the answer's bytes, or an
/// error string that is printed after "error ".
pub trait Witness {
    fn stream(&self, cipher: &str, key: &[u8], iv: &[u8], n: usize) -> Result<Vec<u8>, String>;
    fn f8(&self, alg: &str, key: &[u8; 16], count: u32, bearer: u32, dir: u32, data: &mut [u8],
          bits: u32) -> Result<(), String>;
    fn f9(&self, alg: &str, key: &[u8; 16], count: u32, fresh: u32, dir: u32, data: &[u8],
          bits: u32) -> Result<[u8; 4], String>;
    fn zucmac(&self, tagbits: u32, key: &[u8], iv: &[u8], data: &[u8], bits: u32)
        -> Result<Vec<u8>, String>;
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn answer(w: &dyn Witness, line: &str) -> Result<String, String> {
    let f: Vec<&str> = line.split_whitespace().collect();
    match (f.first().copied(), f.len()) {
        (Some("stream"), 5) => {
            Ok(hex(&w.stream(f[1], &unhex(f[2]), &unhex(f[3]), f[4].parse().unwrap())?))
        }
        (Some(op @ ("f8" | "f9")), 8) => {
            let key: [u8; 16] = unhex(f[2]).try_into().map_err(|_| "key or data length")?;
            let count = u32::from_str_radix(f[3], 16).unwrap();
            let (dir, bits): (u32, u32) = (f[5].parse().unwrap(), f[6].parse().unwrap());
            let mut data = unhex(f[7]);
            if data.len() != bits.div_ceil(8) as usize {
                return Err("key or data length".into());
            }
            if op == "f8" {
                w.f8(f[1], &key, count, f[4].parse().unwrap(), dir, &mut data, bits)?;
                if bits % 8 != 0 {
                    data[bits as usize / 8] &= 0xffu8 << (8 - bits % 8);
                }
                Ok(hex(&data))
            } else {
                let fresh = if f[1] == "uia2" {
                    u32::from_str_radix(f[4], 16).unwrap()
                } else {
                    f[4].parse().unwrap()
                };
                Ok(hex(&w.f9(f[1], &key, count, fresh, dir, &data, bits)?))
            }
        }
        (Some("zucmac"), 6) => {
            let tagbits: u32 = f[1].parse().unwrap();
            let bits: u32 = f[4].parse().unwrap();
            let data = unhex(f[5]);
            if data.len() != bits.div_ceil(8) as usize || ![32, 64, 128].contains(&tagbits) {
                return Err("data length or tag size".into());
            }
            Ok(hex(&w.zucmac(tagbits, &unhex(f[2]), &unhex(f[3]), &data, bits)?))
        }
        _ => Err("request".into()),
    }
}

/// Answers requests until stdin ends. A panic in the implementation is
/// reported as an error for that request.
pub fn serve(w: &dyn Witness) {
    std::panic::set_hook(Box::new(|_| {}));
    let stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let out = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| answer(w, &line))) {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => format!("error {e}"),
            Err(_) => "error panic".into(),
        };
        let mut lock = stdout.lock();
        writeln!(lock, "{out}").unwrap();
        lock.flush().unwrap();
    }
}

/// A ZUC-256 IV as the specification writes it - 25 bytes, the last eight
/// holding six bits each - packed into the 23 bytes the crates take, first
/// value highest.
pub fn pack_iv(iv: &[u8]) -> Result<[u8; 23], String> {
    if iv.len() != 25 || iv[17..].iter().any(|b| b & 0xc0 != 0) {
        return Err("key or iv length".into());
    }
    let mut out = [0u8; 23];
    out[..17].copy_from_slice(&iv[..17]);
    let bits = iv[17..].iter().fold(0u64, |acc, b| acc << 6 | u64::from(*b));
    for i in 0..6 {
        out[17 + i] = (bits >> (40 - 8 * i)) as u8;
    }
    Ok(out)
}

/// Keystream words written big endian, cut to `n` bytes.
pub fn words_to_bytes(mut next: impl FnMut() -> u32, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 4);
    while out.len() < n {
        out.extend_from_slice(&next().to_be_bytes());
    }
    out.truncate(n);
    out
}
