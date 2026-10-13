//! Strumok (DSTU 8845:2019) through uacrypt's `hazmat::strumok`, with
//! uapki_driver.c's request format: `<key hex> <iv hex> <n>[,<n>...]`
//! per line, the keystream of zero bytes in pieces of those lengths,
//! one `apply_keystream` call each, back as hex; "error ..." for a key
//! or IV of the wrong length.
#[allow(dead_code)]
mod strumok;

use std::io::{BufRead, Write};

enum Cipher {
    S256(strumok::Strumok256),
    S512(strumok::Strumok512),
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn answer(line: &str) -> Result<String, String> {
    let mut words = line.split_whitespace();
    let (key, iv, pieces) = match (words.next(), words.next(), words.next()) {
        (Some(k), Some(v), Some(p)) => (k, v, p),
        _ => return Err("request".into()),
    };
    let key = unhex(key).ok_or("key hex")?;
    let iv: [u8; 32] = unhex(iv).ok_or("iv hex")?.try_into().map_err(|_| "iv length")?;
    let mut cipher = match key.len() {
        32 => Cipher::S256(strumok::Strumok256::new(&key.try_into().unwrap(), &iv)),
        64 => Cipher::S512(strumok::Strumok512::new(&key.try_into().unwrap(), &iv)),
        _ => return Err("key length".into()),
    };
    let mut out = String::new();
    for p in pieces.split(',') {
        let n: usize = p.parse().map_err(|_| "piece")?;
        let mut z = vec![0u8; n];
        match &mut cipher {
            Cipher::S256(c) => c.apply_keystream(&mut z),
            Cipher::S512(c) => c.apply_keystream(&mut z),
        }
        for b in z {
            out.push_str(&format!("{b:02x}"));
        }
    }
    Ok(out)
}

fn main() {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        match answer(&line) {
            Ok(s) => writeln!(out, "{s}").unwrap(),
            Err(e) => writeln!(out, "error {e}").unwrap(),
        }
        out.flush().unwrap();
    }
}
