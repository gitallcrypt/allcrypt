// RustCrypto's rabbit 0.5.0 and hc-256 0.6.0 as a witness: `stream
// <cipher> <key hex> <iv hex> <length>` per line, "-" for an empty IV;
// the first <length> bytes of keystream in hex, or "error ...". Ciphers:
// rabbit (no IV), rabbit-iv (8 byte IV) and hc256. The keystream is
// applied in pieces of 1, 2, 3 .. bytes.
use std::io::{self, BufRead, Write};
use cipher::{KeyInit, KeyIvInit, StreamCipher};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return Vec::new(); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn pieces(c: &mut dyn StreamCipher, n: usize) -> String {
    let mut out = vec![0u8; n];
    let (mut at, mut piece) = (0, 1);
    while at < n {
        let end = (at + piece).min(n);
        c.apply_keystream(&mut out[at..end]);
        at = end;
        piece += 1;
    }
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        let answer = if f.len() == 5 && f[0] == "stream" {
            let (key, iv, n) = (unhex(f[2]), unhex(f[3]), f[4].parse::<usize>().unwrap());
            match f[1] {
                "rabbit" if iv.is_empty() => match rabbit::RabbitKeyOnly::new_from_slice(&key) {
                    Ok(mut c) => pieces(&mut c, n),
                    Err(_) => "error key".to_string(),
                },
                "rabbit-iv" => match rabbit::Rabbit::new_from_slices(&key, &iv) {
                    Ok(mut c) => pieces(&mut c, n),
                    Err(_) => "error key or iv".to_string(),
                },
                "hc256" => match hc_256::Hc256::new_from_slices(&key, &iv) {
                    Ok(mut c) => pieces(&mut c, n),
                    Err(_) => "error key or iv".to_string(),
                },
                _ => "error unsupported".to_string(),
            }
        } else {
            "error request".to_string()
        };
        writeln!(out, "{answer}").unwrap();
        out.flush().unwrap();
    }
}
