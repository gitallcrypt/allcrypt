// RustCrypto's pmac 0.7.1 as a witness: one request per line on stdin,
// `pmac <cipher> <key hex> <message hex>` ("-" for empty), the tag in
// hex on stdout, or "error unsupported".
use std::io::{self, BufRead, Write};
use digest::{KeyInit, Mac};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return Vec::new(); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn tag<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> String {
    match <M as KeyInit>::new_from_slice(key) {
        Ok(mut m) => {
            m.update(msg);
            m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
        }
        Err(_) => "error key length".to_string(),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        let answer = if f.len() == 4 && f[0] == "pmac" {
            let (key, msg) = (unhex(f[2]), unhex(f[3]));
            match f[1] {
                "aes" => match key.len() {
                    16 => tag::<pmac::Pmac<aes::Aes128>>(&key, &msg),
                    24 => tag::<pmac::Pmac<aes::Aes192>>(&key, &msg),
                    32 => tag::<pmac::Pmac<aes::Aes256>>(&key, &msg),
                    _ => "error key length".to_string(),
                },
                "des" => tag::<pmac::Pmac<des::Des>>(&key, &msg),
                "3des" => tag::<pmac::Pmac<des::TdesEde3>>(&key, &msg),
                "blowfish" => tag::<pmac::Pmac<blowfish::Blowfish>>(&key, &msg),
                _ => "error unsupported".to_string(),
            }
        } else {
            "error request".to_string()
        };
        writeln!(out, "{answer}").unwrap();
        out.flush().unwrap();
    }
}
