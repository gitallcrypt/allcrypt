// sacundim/chaskey as a witness. Requests, one per line, "-" for empty:
//
//   chaskey <rounds> <key hex> <msg hex>   the 16 byte tag, rounds 8, 12
//                                          or 16 (Chaskey-LTS), the
//                                          message written in pieces of
//                                          1, 2, 3 .. bytes
//   cipher <rounds> <key hex> <block hex>  its Even-Mansour block cipher,
//                                          pi(x ^ K) ^ K
//
// The answer is hex, or "error ...".
use std::io::{self, BufRead, Write};
use chaskey::cipher::{encrypt, Permutation};
use chaskey::{Chaskey, Chaskey12, ChaskeyLTS, Digester};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return Vec::new(); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn words(b: &[u8]) -> [u32; 4] {
    [0, 1, 2, 3].map(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
}

fn hex(words: &[u32; 4]) -> String {
    words.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

fn mac<P: Permutation>(key: [u32; 4], msg: &[u8]) -> String {
    let mut d: Digester<P> = Digester::new(key);
    let (mut at, mut piece) = (0, 1);
    while at < msg.len() {
        let end = (at + piece).min(msg.len());
        d.write(&msg[at..end]);
        at = end;
        piece += 1;
    }
    hex(d.finish().raw_words())
}

fn block<P: Permutation>(key: [u32; 4], x: &[u8]) -> String {
    let mut v = words(x);
    encrypt::<P>(&mut v, &key);
    hex(&v)
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        let answer = if f.len() == 4 && f[2].len() == 32 {
            let key = words(&unhex(f[2]));
            let data = unhex(f[3]);
            match (f[0], f[1]) {
                ("chaskey", "8") => mac::<Chaskey>(key, &data),
                ("chaskey", "12") => mac::<Chaskey12>(key, &data),
                ("chaskey", "16") => mac::<ChaskeyLTS>(key, &data),
                ("cipher", _) if data.len() != 16 => "error request".to_string(),
                ("cipher", "8") => block::<Chaskey>(key, &data),
                ("cipher", "12") => block::<Chaskey12>(key, &data),
                ("cipher", "16") => block::<ChaskeyLTS>(key, &data),
                ("chaskey" | "cipher", _) => "error unsupported".to_string(),
                _ => "error request".to_string(),
            }
        } else {
            "error request".to_string()
        };
        writeln!(out, "{answer}").unwrap();
        out.flush().unwrap();
    }
}
