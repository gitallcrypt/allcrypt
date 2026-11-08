//! The grain-128aeadv2 0.1.2 crate as a witness, under the request lines
//! `../rweather_grain.c` describes: `encrypt_aead`, then `decrypt_aead` of
//! the result, which must give the plaintext back.

use std::io::{self, BufRead, Write};

use grain_128aeadv2::{Grain128, KeyInit};

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
    if f.len() != 5 || f[0] != "seal" {
        return "error request".to_string();
    }
    let Some(v) = f[1..].iter().map(|s| unhex(s)).collect::<Option<Vec<_>>>() else {
        return "error request".to_string();
    };
    let (key, nonce, ad, pt) = (&v[0], &v[1], &v[2], &v[3]);
    let (Ok(key), Ok(nonce)) = (<[u8; 16]>::try_from(key.as_slice()),
                                <[u8; 12]>::try_from(nonce.as_slice())) else {
        return "error key or nonce".to_string();
    };
    let cipher = Grain128::new(&key.into());
    let (ct, tag) = cipher.encrypt_aead(&nonce.into(), ad, pt);
    match cipher.decrypt_aead(&nonce.into(), ad, &ct, &tag) {
        Ok(back) if back == *pt => {}
        _ => return "error decrypt".to_string(),
    }
    ct.iter().chain(tag.iter()).map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        writeln!(stdout, "{}", answer(&line.unwrap())).unwrap();
        stdout.flush().unwrap();
    }
}
