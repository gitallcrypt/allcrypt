// The trivium 0.1.0 and grain128 0.1.0 crates as a witness: `stream
// <cipher> <key hex> <iv hex> <length>` per line, ciphers trivium and
// grain128; the first <length> bytes of keystream in hex, or "error ...".
//
// The trivium crate loads s_1.. from the key's bits in the order the
// Trivium specification writes them. The eSTREAM submission, its test
// vectors and allcrypt load s_1 from the key's last bit, reading each byte
// least significant bit first; the same bits arrive in the crate's order
// when the key's bytes are reversed and read most significant bit first,
// which is what this passes it, and the same for the IV. Its keystream is
// packed least significant bit first, as the submission's is.
//
// grain128 is a port of the Grain-128 reference implementation and takes
// the key, IV and keystream as that does; its keystream is taken in pieces
// of 1, 2, 3 .. bytes.
use std::io::{self, BufRead, Write};

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn trivium(key: &[u8], iv: &[u8], n: usize) -> String {
    if key.len() != 10 || iv.len() != 10 {
        return "error key or iv length".to_string();
    }
    let key: Vec<u8> = key.iter().rev().copied().collect();
    let iv: Vec<u8> = iv.iter().rev().copied().collect();
    let t = trivium::Trivium::new(&key, &iv, trivium::BitOrder::Msb, trivium::PackOrder::Lsb);
    hex(&t.xor_bytes(&vec![0u8; n]))
}

fn grain128(key: &[u8], iv: &[u8], n: usize) -> String {
    if key.len() != 16 || iv.len() != 12 {
        return "error key or iv length".to_string();
    }
    let mut g = grain128::Grain128::keysetup(key, 128, 96);
    g.ivsetup(iv);
    let mut out = vec![0u8; n];
    let (mut at, mut piece) = (0, 1);
    while at < n {
        let end = (at + piece).min(n);
        g.keystream_bytes(&mut out[at..end]);
        at = end;
        piece += 1;
    }
    hex(&out)
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        let answer = if f.len() == 5 && f[0] == "stream" {
            match (unhex(f[2]), unhex(f[3]), f[4].parse::<usize>()) {
                (Some(key), Some(iv), Ok(n)) => match f[1] {
                    "trivium" => trivium(&key, &iv, n),
                    "grain128" => grain128(&key, &iv, n),
                    _ => "error unsupported".to_string(),
                },
                _ => "error request".to_string(),
            }
        } else {
            "error request".to_string()
        };
        writeln!(out, "{answer}").unwrap();
        out.flush().unwrap();
    }
}
